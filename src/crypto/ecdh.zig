// SPDX-License-Identifier: MIT
//! ECDH key agreement for OpenPGP (RFC 6637) using Curve25519.
//!
//! This module implements the ECDH encrypt/decrypt operations used when
//! processing OpenPGP PKESK (Tag 1) packets with ECDH public keys.
//!
//! Key derivation uses the KDF specified in RFC 6637 Section 8:
//!   Hash(0x00000001 || shared_secret || param)
//! where param encodes the curve OID, algorithm identifiers, and a tag
//! "Anonymous Sender    " plus the recipient key fingerprint.

const std = @import("std");
const Allocator = std.mem.Allocator;
const X25519 = std.crypto.dh.X25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const SymmetricAlgorithm = @import("../types/enums.zig").SymmetricAlgorithm;
const aes_keywrap = @import("aes_keywrap.zig");

pub const EcdhError = error{
    InvalidPublicKey,
    KeyAgreementFailed,
    UnwrapFailed,
    UnsupportedAlgorithm,
    OutOfMemory,
};

pub const EcdhResult = struct {
    ephemeral_public: [32]u8,
    wrapped_key: []u8,
    allocator: Allocator,

    pub fn deinit(self: EcdhResult) void {
        self.allocator.free(self.wrapped_key);
    }
};

/// Curve25519 OID: 1.3.6.1.4.1.3029.1.5.1
/// Encoded as: length byte + OID bytes
const cv25519_oid = [_]u8{ 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01 };

/// Build the KDF parameter block per RFC 6637 Section 8.
///
/// Format:
///   curve_oid_len (1) || curve_oid || public_algo (1) ||
///   03 (length of following KDF params) ||
///   01 (reserved) || kdf_hash_algo (1) || wrap_algo (1) ||
///   "Anonymous Sender    " (20 bytes) || fingerprint (20 bytes)
/// KDF param size: OID(11) + algo(1) + kdf_len(1) + reserved(1) + hash(1) + sym(1) +
/// anon_sender(20) + fingerprint(20) = 56 bytes.
const kdf_param_size = cv25519_oid.len + 1 + 1 + 1 + 1 + 1 + 20 + 20;

fn buildKdfParam(
    sym_algo: SymmetricAlgorithm,
    fingerprint: [20]u8,
) [kdf_param_size]u8 {
    var param: [kdf_param_size]u8 = undefined;
    var pos: usize = 0;

    // Curve OID (including the length prefix)
    @memcpy(param[pos..][0..cv25519_oid.len], &cv25519_oid);
    pos += cv25519_oid.len;

    // Public key algorithm: ECDH = 18
    param[pos] = 18;
    pos += 1;

    // KDF parameters: 03 || 01 || SHA256(8) || sym_algo
    param[pos] = 0x03;
    pos += 1;
    param[pos] = 0x01; // reserved
    pos += 1;
    param[pos] = 0x08; // SHA256
    pos += 1;
    param[pos] = @intFromEnum(sym_algo);
    pos += 1;

    // "Anonymous Sender    " (20 bytes, padded with spaces)
    const anon_sender = "Anonymous Sender    ";
    @memcpy(param[pos..][0..20], anon_sender);
    pos += 20;

    // Recipient key fingerprint
    @memcpy(param[pos..][0..20], &fingerprint);
    pos += 20;

    std.debug.assert(pos == kdf_param_size);
    return param;
}

/// Derive the key-encryption key (KEK) from the shared secret using
/// the KDF specified in RFC 6637 Section 8.
///
/// kek = Hash(0x00000001 || shared_secret || param), truncated to key_len.
fn deriveKek(
    shared_secret: [32]u8,
    sym_algo: SymmetricAlgorithm,
    fingerprint: [20]u8,
    kek_out: []u8,
) void {
    const param = buildKdfParam(sym_algo, fingerprint);

    var h = Sha256.init(.{});
    h.update(&[_]u8{ 0x00, 0x00, 0x00, 0x01 }); // counter = 1
    h.update(&shared_secret);
    h.update(&param);
    const digest = h.finalResult();

    @memcpy(kek_out, digest[0..kek_out.len]);
}

/// Perform ECDH encryption: generate an ephemeral key pair, compute the
/// shared secret, derive a KEK, and wrap the session key.
pub fn ecdhEncrypt(
    recipient_public: [32]u8,
    session_key: []const u8,
    sym_algo: SymmetricAlgorithm,
    fingerprint: [20]u8,
    allocator: Allocator,
) EcdhError!EcdhResult {
    // Generate ephemeral key pair
    const ephemeral = X25519.KeyPair.generate();

    // Compute shared secret
    const shared_secret = X25519.scalarmult(
        ephemeral.secret_key,
        recipient_public,
    ) catch return EcdhError.KeyAgreementFailed;

    // Derive the KEK
    const kek_len = sym_algo.keySize() orelse return EcdhError.UnsupportedAlgorithm;
    var kek: [32]u8 = undefined;
    deriveKek(shared_secret, sym_algo, fingerprint, kek[0..kek_len]);

    // Wrap the session key
    // RFC 6637: session key is prefixed with a length byte and padded with
    // PKCS5 to a multiple of 8 bytes before wrapping.
    const padded = padSessionKey(session_key, allocator) catch return EcdhError.OutOfMemory;
    defer allocator.free(padded);

    const wrapped = aes_keywrap.wrap(
        kek[0..kek_len],
        padded,
        allocator,
    ) catch return EcdhError.OutOfMemory;

    return EcdhResult{
        .ephemeral_public = ephemeral.public_key,
        .wrapped_key = wrapped,
        .allocator = allocator,
    };
}

/// Perform ECDH decryption: recover the session key from wrapped key data.
pub fn ecdhDecrypt(
    recipient_secret: [32]u8,
    ephemeral_public: [32]u8,
    wrapped_key: []const u8,
    sym_algo: SymmetricAlgorithm,
    fingerprint: [20]u8,
    allocator: Allocator,
) EcdhError![]u8 {
    // Compute shared secret
    const shared_secret = X25519.scalarmult(
        recipient_secret,
        ephemeral_public,
    ) catch return EcdhError.KeyAgreementFailed;

    // Derive the KEK
    const kek_len = sym_algo.keySize() orelse return EcdhError.UnsupportedAlgorithm;
    var kek: [32]u8 = undefined;
    deriveKek(shared_secret, sym_algo, fingerprint, kek[0..kek_len]);

    // Unwrap
    const padded = aes_keywrap.unwrap(
        kek[0..kek_len],
        wrapped_key,
        allocator,
    ) catch return EcdhError.UnwrapFailed;
    defer allocator.free(padded);

    // Unpad: first byte is the length of the session key
    if (padded.len == 0) return EcdhError.UnwrapFailed;
    const sk_len = padded[0];
    if (sk_len == 0 or @as(usize, sk_len) + 1 > padded.len) return EcdhError.UnwrapFailed;

    const session_key = allocator.alloc(u8, sk_len) catch return EcdhError.OutOfMemory;
    @memcpy(session_key, padded[1..][0..sk_len]);
    return session_key;
}

/// Pad a session key for AES Key Wrap per RFC 6637:
/// [length_byte] [session_key...] [PKCS5 padding to multiple of 8]
fn padSessionKey(session_key: []const u8, allocator: Allocator) ![]u8 {
    const total_unpadded = 1 + session_key.len; // 1 byte for length prefix
    const padded_len = ((total_unpadded + 7) / 8) * 8;
    // Minimum 16 bytes for AES Key Wrap
    const final_len = @max(padded_len, 16);

    const buf = try allocator.alloc(u8, final_len);
    buf[0] = @intCast(session_key.len);
    @memcpy(buf[1..][0..session_key.len], session_key);

    // PKCS5-style padding
    const pad_byte: u8 = @intCast(final_len - total_unpadded);
    @memset(buf[total_unpadded..], pad_byte);

    return buf;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ECDH encrypt/decrypt round-trip with AES-128" {
    const allocator = std.testing.allocator;

    // Generate a recipient key pair
    const recipient = X25519.KeyPair.generate();
    const fingerprint = [_]u8{0x42} ** 20;

    // A 16-byte session key for AES-128
    const session_key = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    };

    const result = try ecdhEncrypt(
        recipient.public_key,
        &session_key,
        .aes128,
        fingerprint,
        allocator,
    );
    defer result.deinit();

    const recovered = try ecdhDecrypt(
        recipient.secret_key,
        result.ephemeral_public,
        result.wrapped_key,
        .aes128,
        fingerprint,
        allocator,
    );
    defer allocator.free(recovered);

    try std.testing.expectEqualSlices(u8, &session_key, recovered);
}

test "ECDH encrypt/decrypt round-trip with AES-256" {
    const allocator = std.testing.allocator;

    const recipient = X25519.KeyPair.generate();
    const fingerprint = [_]u8{0xAB} ** 20;

    const session_key = [_]u8{
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81,
        0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x82,
        0x13, 0x23, 0x33, 0x43, 0x53, 0x63, 0x73, 0x83,
    };

    const result = try ecdhEncrypt(
        recipient.public_key,
        &session_key,
        .aes256,
        fingerprint,
        allocator,
    );
    defer result.deinit();

    const recovered = try ecdhDecrypt(
        recipient.secret_key,
        result.ephemeral_public,
        result.wrapped_key,
        .aes256,
        fingerprint,
        allocator,
    );
    defer allocator.free(recovered);

    try std.testing.expectEqualSlices(u8, &session_key, recovered);
}

test "ECDH decrypt with wrong key fails" {
    const allocator = std.testing.allocator;

    const recipient = X25519.KeyPair.generate();
    const wrong_recipient = X25519.KeyPair.generate();
    const fingerprint = [_]u8{0x00} ** 20;

    const session_key = [_]u8{0xFF} ** 16;

    const result = try ecdhEncrypt(
        recipient.public_key,
        &session_key,
        .aes128,
        fingerprint,
        allocator,
    );
    defer result.deinit();

    // Trying to decrypt with the wrong secret key should fail
    try std.testing.expectError(
        EcdhError.UnwrapFailed,
        ecdhDecrypt(
            wrong_recipient.secret_key,
            result.ephemeral_public,
            result.wrapped_key,
            .aes128,
            fingerprint,
            allocator,
        ),
    );
}

test "padSessionKey produces correct format" {
    const allocator = std.testing.allocator;

    const sk = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };
    const padded = try padSessionKey(&sk, allocator);
    defer allocator.free(padded);

    // Minimum 16 bytes, multiple of 8
    try std.testing.expect(padded.len >= 16);
    try std.testing.expect(padded.len % 8 == 0);
    try std.testing.expectEqual(@as(u8, 5), padded[0]); // length prefix
    try std.testing.expectEqualSlices(u8, &sk, padded[1..6]);
}
