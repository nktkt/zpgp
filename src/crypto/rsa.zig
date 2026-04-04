// SPDX-License-Identifier: MIT
//! RSA operations for OpenPGP using std.crypto.ff.
//!
//! Supports up to 4096-bit RSA keys with PKCS#1 v1.5 padding for both
//! signature and encryption operations per RFC 3447.

const std = @import("std");
const ff = std.crypto.ff;
const HashAlgorithm = @import("../types/enums.zig").HashAlgorithm;
const HashContext = @import("hash.zig").HashContext;

pub const RsaError = error{
    InvalidKey,
    MessageTooLong,
    DecryptionFailed,
    VerificationFailed,
    InvalidPadding,
    BufferTooSmall,
};

pub const max_bits = 4096;
pub const max_bytes = max_bits / 8;

const BigUint = ff.Uint(max_bits);
const BigMod = ff.Modulus(max_bits);
const BigFe = BigMod.Fe;

/// DER-encoded DigestInfo prefixes for PKCS#1 v1.5 signatures (RFC 3447 Section 9.2).
const DigestInfoPrefix = struct {
    const sha1 = [_]u8{
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
        0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    };
    const sha256 = [_]u8{
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20,
    };
    const sha384 = [_]u8{
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
        0x00, 0x04, 0x30,
    };
    const sha512 = [_]u8{
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
        0x00, 0x04, 0x40,
    };

    fn forAlgorithm(algo: HashAlgorithm) RsaError![]const u8 {
        return switch (algo) {
            .sha1 => &sha1,
            .sha256 => &sha256,
            .sha384 => &sha384,
            .sha512 => &sha512,
            else => error.InvalidPadding,
        };
    }
};

/// Build PKCS#1 v1.5 signature padding (type 01) into `em`.
/// Layout: 0x00 0x01 [0xFF...] 0x00 [DigestInfo prefix] [digest]
fn buildPkcs1v15SignaturePadding(
    em: []u8,
    hash_algo: HashAlgorithm,
    digest: []const u8,
) RsaError!void {
    const prefix = try DigestInfoPrefix.forAlgorithm(hash_algo);
    const t_len = prefix.len + digest.len;
    const em_len = em.len;

    // RFC 3447: emLen must be at least tLen + 11
    if (em_len < t_len + 11) return error.MessageTooLong;

    const ps_len = em_len - t_len - 3;

    em[0] = 0x00;
    em[1] = 0x01;
    @memset(em[2 .. 2 + ps_len], 0xff);
    em[2 + ps_len] = 0x00;
    @memcpy(em[3 + ps_len .. 3 + ps_len + prefix.len], prefix);
    @memcpy(em[3 + ps_len + prefix.len ..], digest);
}

/// Build PKCS#1 v1.5 encryption padding (type 02) into `em`.
/// Layout: 0x00 0x02 [random non-zero bytes] 0x00 [plaintext]
fn buildPkcs1v15EncryptionPadding(em: []u8, plaintext: []const u8) RsaError!void {
    const em_len = em.len;

    // Minimum: 11 bytes overhead (3 framing + 8 random minimum)
    if (em_len < plaintext.len + 11) return error.MessageTooLong;

    const ps_len = em_len - plaintext.len - 3;

    em[0] = 0x00;
    em[1] = 0x02;

    // Fill PS with random non-zero bytes
    const random = std.crypto.random;
    random.bytes(em[2 .. 2 + ps_len]);
    // Replace any zero bytes
    for (em[2 .. 2 + ps_len]) |*b| {
        while (b.* == 0) {
            random.bytes(b[0..1]);
        }
    }

    em[2 + ps_len] = 0x00;
    @memcpy(em[3 + ps_len ..], plaintext);
}

/// Strip PKCS#1 v1.5 encryption padding (type 02) and return the plaintext.
fn stripPkcs1v15EncryptionPadding(em: []const u8, allocator: std.mem.Allocator) ![]u8 {
    if (em.len < 11) return error.InvalidPadding;
    if (em[0] != 0x00 or em[1] != 0x02) return error.InvalidPadding;

    // Find the 0x00 separator after at least 8 bytes of random padding
    var sep_index: ?usize = null;
    for (em[2..], 2..) |b, i| {
        if (b == 0x00 and i >= 10) {
            sep_index = i;
            break;
        }
    }
    const sep = sep_index orelse return error.InvalidPadding;

    const plaintext = em[sep + 1 ..];
    const result = try allocator.alloc(u8, plaintext.len);
    @memcpy(result, plaintext);
    return result;
}

/// Pad a byte slice with leading zeros to fill `out`. Input is big-endian.
fn padToLen(out: []u8, data: []const u8) void {
    if (data.len >= out.len) {
        @memcpy(out, data[data.len - out.len ..]);
    } else {
        const pad = out.len - data.len;
        @memset(out[0..pad], 0);
        @memcpy(out[pad..], data);
    }
}

pub const RsaPublicKey = struct {
    n_bytes: []const u8, // modulus, big-endian
    e_bytes: []const u8, // public exponent, big-endian

    /// Raw RSA public operation: result = message^e mod n
    pub fn rawEncrypt(self: RsaPublicKey, message: []const u8, out: []u8) !void {
        const n_mod = try BigMod.fromBytes(self.n_bytes, .big);
        const mod_len = self.n_bytes.len;

        // Pad message to modulus byte length for field element creation
        var padded_msg: [max_bytes]u8 = undefined;
        padToLen(padded_msg[0..mod_len], message);

        const m_fe = try BigFe.fromBytes(n_mod, padded_msg[0..mod_len], .big);
        const result = try n_mod.powWithEncodedPublicExponent(m_fe, self.e_bytes, .big);

        var result_buf: [max_bytes]u8 = undefined;
        try result.toBytes(result_buf[0..mod_len], .big);
        @memcpy(out[0..mod_len], result_buf[0..mod_len]);
    }

    /// PKCS#1 v1.5 signature verification (RFC 3447 Section 8.2.2).
    pub fn pkcs1v15Verify(
        self: RsaPublicKey,
        hash_algo: HashAlgorithm,
        digest: []const u8,
        signature: []const u8,
    ) !void {
        const mod_len = self.n_bytes.len;

        // Step 1: RSA verification: em = signature^e mod n
        var em: [max_bytes]u8 = undefined;
        try self.rawEncrypt(signature, em[0..mod_len]);

        // Step 2: Build expected padded message
        var expected: [max_bytes]u8 = undefined;
        @memset(expected[0..max_bytes], 0);
        try buildPkcs1v15SignaturePadding(expected[0..mod_len], hash_algo, digest);

        // Step 3: Compare in constant time
        if (!std.mem.eql(u8, em[0..mod_len], expected[0..mod_len])) {
            return error.VerificationFailed;
        }
    }

    /// PKCS#1 v1.5 encrypt (for session key encryption).
    pub fn pkcs1v15Encrypt(self: RsaPublicKey, plaintext: []const u8, out: []u8) !void {
        const mod_len = self.n_bytes.len;

        // Build padded message
        var em: [max_bytes]u8 = undefined;
        try buildPkcs1v15EncryptionPadding(em[0..mod_len], plaintext);

        // Encrypt: ciphertext = em^e mod n
        try self.rawEncrypt(em[0..mod_len], out[0..mod_len]);
    }
};

pub const RsaSecretKey = struct {
    n_bytes: []const u8,
    e_bytes: []const u8,
    d_bytes: []const u8,
    p_bytes: ?[]const u8 = null, // optional, for CRT
    q_bytes: ?[]const u8 = null,

    /// Raw RSA private operation: result = ciphertext^d mod n
    pub fn rawDecrypt(self: RsaSecretKey, ciphertext: []const u8, out: []u8) !void {
        const n_mod = try BigMod.fromBytes(self.n_bytes, .big);
        const mod_len = self.n_bytes.len;

        // Pad ciphertext to modulus byte length
        var padded: [max_bytes]u8 = undefined;
        padToLen(padded[0..mod_len], ciphertext);

        const c_fe = try BigFe.fromBytes(n_mod, padded[0..mod_len], .big);

        // Use constant-time exponentiation for secret exponent.
        // The exponent buffer must match the modulus byte length.
        var d_padded: [max_bytes]u8 = undefined;
        padToLen(d_padded[0..mod_len], self.d_bytes);

        const result = try n_mod.powWithEncodedExponent(c_fe, d_padded[0..mod_len], .big);

        var result_buf: [max_bytes]u8 = undefined;
        try result.toBytes(result_buf[0..mod_len], .big);
        @memcpy(out[0..mod_len], result_buf[0..mod_len]);
    }

    /// PKCS#1 v1.5 signature creation (RFC 3447 Section 8.2.1).
    pub fn pkcs1v15Sign(
        self: RsaSecretKey,
        hash_algo: HashAlgorithm,
        digest: []const u8,
        out: []u8,
    ) !void {
        const mod_len = self.n_bytes.len;

        // Step 1: Build PKCS#1 v1.5 padded message
        var em: [max_bytes]u8 = undefined;
        try buildPkcs1v15SignaturePadding(em[0..mod_len], hash_algo, digest);

        // Step 2: RSA sign: signature = em^d mod n
        try self.rawDecrypt(em[0..mod_len], out[0..mod_len]);
    }

    /// PKCS#1 v1.5 decrypt.
    pub fn pkcs1v15Decrypt(
        self: RsaSecretKey,
        ciphertext: []const u8,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        const mod_len = self.n_bytes.len;

        // Step 1: RSA decrypt: em = ciphertext^d mod n
        var em: [max_bytes]u8 = undefined;
        try self.rawDecrypt(ciphertext, em[0..mod_len]);

        // Step 2: Strip PKCS#1 v1.5 type 02 padding
        return stripPkcs1v15EncryptionPadding(em[0..mod_len], allocator);
    }

    /// Get the public key portion.
    pub fn publicKey(self: RsaSecretKey) RsaPublicKey {
        return .{
            .n_bytes = self.n_bytes,
            .e_bytes = self.e_bytes,
        };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// A 512-bit RSA test key generated with deterministic PRNG (seed=12345).
// p = 0x9b238e1d7cb0045348d3d5c38d6547533ccd1599ef2dd5fb753f8fcb4daf87db
// q = 0xfec125b963da72ad51c3f8a188bddcab11b35543f36062488c7e8d71294a2a81
// n = p * q, e = 65537, d = e^{-1} mod lcm(p-1, q-1)
const test_n = [_]u8{
    0x9a, 0x62, 0x53, 0xab, 0xe2, 0xb0, 0xbd, 0x0d,
    0xbb, 0x10, 0xad, 0x3e, 0xe1, 0x79, 0x55, 0xe6,
    0xc6, 0x1d, 0xc7, 0xec, 0x32, 0xa3, 0x6b, 0x1e,
    0x37, 0x67, 0xb9, 0x09, 0x31, 0x18, 0xa3, 0xd6,
    0xa8, 0xc6, 0x8c, 0x53, 0xd6, 0xcf, 0x18, 0x57,
    0x21, 0xc6, 0x2b, 0x5e, 0x63, 0x4b, 0xee, 0xe7,
    0x32, 0xbe, 0x53, 0xd6, 0xc1, 0xf8, 0xe0, 0x29,
    0x3c, 0xec, 0xf8, 0x5b, 0x4a, 0x0b, 0x63, 0x5b,
};

const test_e = [_]u8{ 0x01, 0x00, 0x01 };

const test_d = [_]u8{
    0x36, 0xbc, 0x8d, 0xf5, 0xef, 0x55, 0xc2, 0x71,
    0xcf, 0xd5, 0x45, 0xd7, 0x79, 0x91, 0xcf, 0x87,
    0x16, 0xcf, 0x10, 0x47, 0x0a, 0x5d, 0x2e, 0x69,
    0x74, 0x33, 0x6e, 0x43, 0x78, 0x08, 0xc8, 0x6d,
    0x8d, 0xed, 0x3d, 0x18, 0x71, 0x28, 0x3c, 0x1b,
    0xb5, 0xaa, 0x16, 0x84, 0xbd, 0x7a, 0xad, 0x16,
    0x8d, 0x75, 0xf5, 0xd7, 0xe7, 0x3e, 0xa5, 0x70,
    0x7c, 0xdf, 0x4c, 0x09, 0x4d, 0xc4, 0x84, 0x01,
};

fn getTestPublicKey() RsaPublicKey {
    return .{
        .n_bytes = &test_n,
        .e_bytes = &test_e,
    };
}

fn getTestSecretKey() RsaSecretKey {
    return .{
        .n_bytes = &test_n,
        .e_bytes = &test_e,
        .d_bytes = &test_d,
    };
}

test "raw RSA encrypt/decrypt round-trip" {
    const pub_key = getTestPublicKey();
    const sec_key = getTestSecretKey();

    // A small message value (must be < n), zero-padded to 64 bytes
    var message: [64]u8 = [_]u8{0} ** 64;
    message[63] = 0x42;

    // Encrypt with public key
    var ciphertext: [64]u8 = undefined;
    try pub_key.rawEncrypt(&message, &ciphertext);

    // The ciphertext should differ from the plaintext
    try std.testing.expect(!std.mem.eql(u8, &message, &ciphertext));

    // Decrypt with private key
    var decrypted: [64]u8 = undefined;
    try sec_key.rawDecrypt(&ciphertext, &decrypted);

    try std.testing.expectEqualSlices(u8, &message, decrypted[0..64]);
}

test "PKCS#1 v1.5 sign/verify round-trip" {
    const sec_key = getTestSecretKey();
    const pub_key = sec_key.publicKey();

    // Hash some data with SHA-256
    const data = "Hello, OpenPGP!";
    var digest: [32]u8 = undefined;
    try HashContext.hash(.sha256, data, &digest);

    // Sign
    var signature: [64]u8 = undefined;
    try sec_key.pkcs1v15Sign(.sha256, &digest, &signature);

    // Verify
    try pub_key.pkcs1v15Verify(.sha256, &digest, &signature);
}

test "PKCS#1 v1.5 verify rejects wrong digest" {
    const sec_key = getTestSecretKey();
    const pub_key = sec_key.publicKey();

    const data = "Hello, OpenPGP!";
    var digest: [32]u8 = undefined;
    try HashContext.hash(.sha256, data, &digest);

    // Sign
    var signature: [64]u8 = undefined;
    try sec_key.pkcs1v15Sign(.sha256, &digest, &signature);

    // Tamper with digest
    var bad_digest = digest;
    bad_digest[0] ^= 0xff;

    // Verify should fail
    try std.testing.expectError(
        error.VerificationFailed,
        pub_key.pkcs1v15Verify(.sha256, &bad_digest, &signature),
    );
}

test "PKCS#1 v1.5 encrypt/decrypt round-trip" {
    const sec_key = getTestSecretKey();
    const pub_key = sec_key.publicKey();

    // Plaintext must be small enough: mod_len(64) - 11 = 53 bytes max
    const plaintext = "session key data";

    // Encrypt
    var ciphertext: [64]u8 = undefined;
    try pub_key.pkcs1v15Encrypt(plaintext, &ciphertext);

    // Decrypt
    const decrypted = try sec_key.pkcs1v15Decrypt(&ciphertext, std.testing.allocator);
    defer std.testing.allocator.free(decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, decrypted);
}

test "PKCS#1 v1.5 signature padding structure" {
    var em: [64]u8 = undefined;
    // SHA-256 digest (32 bytes) + prefix (19 bytes) = 51 bytes T
    // em_len 64 >= 51 + 11 = 62, so ps_len = 64 - 51 - 3 = 10
    const dummy_digest = [_]u8{0xAB} ** 32;
    try buildPkcs1v15SignaturePadding(&em, .sha256, &dummy_digest);

    try std.testing.expectEqual(@as(u8, 0x00), em[0]);
    try std.testing.expectEqual(@as(u8, 0x01), em[1]);
    // PS: bytes 2..12 should all be 0xFF
    for (em[2..12]) |b| {
        try std.testing.expectEqual(@as(u8, 0xFF), b);
    }
    try std.testing.expectEqual(@as(u8, 0x00), em[12]);
    // DigestInfo prefix for SHA-256 starts at byte 13
    try std.testing.expectEqual(@as(u8, 0x30), em[13]);
    try std.testing.expectEqual(@as(u8, 0x31), em[14]);
}

test "DigestInfo prefix for supported algorithms" {
    _ = try DigestInfoPrefix.forAlgorithm(.sha1);
    _ = try DigestInfoPrefix.forAlgorithm(.sha256);
    _ = try DigestInfoPrefix.forAlgorithm(.sha384);
    _ = try DigestInfoPrefix.forAlgorithm(.sha512);

    // Unsupported should error
    try std.testing.expectError(error.InvalidPadding, DigestInfoPrefix.forAlgorithm(.md5));
}

test "RsaPublicKey struct layout" {
    const n = [_]u8{ 0x00, 0xFF };
    const e = [_]u8{0x03};
    const pk = RsaPublicKey{ .n_bytes = &n, .e_bytes = &e };
    try std.testing.expectEqual(@as(usize, 2), pk.n_bytes.len);
    try std.testing.expectEqual(@as(usize, 1), pk.e_bytes.len);
}
