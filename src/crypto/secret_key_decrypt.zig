// SPDX-License-Identifier: MIT
//! Passphrase-protected secret key decryption per RFC 4880 Section 5.5.3.
//!
//! OpenPGP secret keys may be encrypted with a passphrase. The passphrase
//! is converted to a symmetric key using an S2K (String-to-Key) specifier,
//! then the secret key material is decrypted using the specified symmetric
//! algorithm in CFB mode.
//!
//! Protection modes (s2k_usage byte):
//!   0   — unprotected (cleartext MPIs)
//!   254 — SHA-1 hash integrity check
//!   255 — two-octet checksum integrity check
//!   other — value is the symmetric algorithm ID (simple checksum)
//!
//! After decryption, the integrity is verified using either:
//!   - A SHA-1 hash of the decrypted data (usage 254), or
//!   - A two-octet checksum sum of the decrypted bytes (usage 255 or other)

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const S2K = @import("../types/s2k.zig").S2K;
const SymmetricAlgorithm = @import("../types/enums.zig").SymmetricAlgorithm;
const cfb_mod = @import("cfb.zig");
const Aes128Cfb = cfb_mod.Aes128Cfb;
const Aes192Cfb = cfb_mod.Aes192Cfb;
const Aes256Cfb = cfb_mod.Aes256Cfb;
const Cast5Cfb = cfb_mod.Cast5Cfb;
const TwofishCfb = cfb_mod.TwofishCfb;
const TripleDesCfb = cfb_mod.TripleDesCfb;
const BlowfishCfb = cfb_mod.BlowfishCfb;
const Camellia128Cfb = cfb_mod.Camellia128Cfb;
const Camellia192Cfb = cfb_mod.Camellia192Cfb;
const Camellia256Cfb = cfb_mod.Camellia256Cfb;

pub const SecretKeyDecryptError = error{
    /// The S2K specifier type is not supported.
    UnsupportedS2kType,
    /// The symmetric algorithm is not supported for decryption.
    UnsupportedAlgorithm,
    /// The data is too short to contain valid encrypted key material.
    InvalidData,
    /// The IV is missing or has incorrect length.
    InvalidIV,
    /// The SHA-1 hash of the decrypted data does not match (usage 254).
    Sha1Mismatch,
    /// The two-octet checksum does not match (usage 255 or other).
    ChecksumMismatch,
    /// The S2K specifier could not be parsed.
    InvalidS2k,
    /// Memory allocation failed.
    OutOfMemory,
    /// Key derivation failed.
    KeyDerivationFailed,
    /// S2K output too large.
    OutputTooLarge,
    /// End of stream while parsing S2K.
    EndOfStream,
    /// Weak S2K parameters.
    WeakParameters,
};

/// Decrypt passphrase-protected secret key material.
///
/// This function takes the encrypted secret key data (as stored in a
/// Secret-Key Packet after the public key portion), derives a symmetric
/// key from the passphrase using the embedded S2K specifier, decrypts
/// the data using CFB mode, and verifies the integrity check.
///
/// Parameters:
///   - allocator: used for temporary allocations
///   - encrypted_data: the encrypted portion of the secret key
///     (everything after the IV, as parsed by SecretKeyPacket)
///   - passphrase: the user's passphrase
///   - sym_algo: the symmetric algorithm to use for decryption
///   - iv: the initialization vector (block_size bytes)
///   - s2k_data: the raw S2K specifier bytes
///   - s2k_usage: the s2k_usage byte (254, 255, or algorithm ID)
///
/// Returns the decrypted MPI data (without the integrity check bytes).
pub fn decryptSecretKey(
    allocator: Allocator,
    encrypted_data: []const u8,
    passphrase: []const u8,
    sym_algo: SymmetricAlgorithm,
    iv: []const u8,
    s2k_data: []const u8,
    s2k_usage: u8,
) SecretKeyDecryptError![]u8 {
    // 1. Determine the key size for the algorithm
    const key_size = sym_algo.keySize() orelse return SecretKeyDecryptError.UnsupportedAlgorithm;
    const block_size = sym_algo.blockSize() orelse return SecretKeyDecryptError.UnsupportedAlgorithm;

    // 2. Validate IV length
    if (iv.len != block_size) return SecretKeyDecryptError.InvalidIV;

    // 3. Parse the S2K specifier
    var s2k_fbs = std.io.fixedBufferStream(s2k_data);
    const s2k = S2K.readFrom(s2k_fbs.reader()) catch return SecretKeyDecryptError.InvalidS2k;

    // 4. Derive the key from the passphrase
    var derived_key: [32]u8 = undefined; // max key size (AES-256 = 32 bytes)
    if (key_size > derived_key.len) return SecretKeyDecryptError.UnsupportedAlgorithm;

    s2k.deriveKeyAlloc(allocator, passphrase, derived_key[0..key_size]) catch |err| {
        return switch (err) {
            error.OutOfMemory => SecretKeyDecryptError.OutOfMemory,
            error.OutputTooLarge => SecretKeyDecryptError.OutputTooLarge,
            error.OutputTooLong => SecretKeyDecryptError.OutputTooLarge,
            error.UnsupportedS2kType => SecretKeyDecryptError.UnsupportedS2kType,
            error.UnsupportedAlgorithm => SecretKeyDecryptError.KeyDerivationFailed,
            error.OutputTooShort => SecretKeyDecryptError.KeyDerivationFailed,
            error.EndOfStream => SecretKeyDecryptError.EndOfStream,
            error.WeakParameters => SecretKeyDecryptError.WeakParameters,
        };
    };

    // 5. Decrypt the data using CFB mode with the derived key and IV
    const decrypted = allocator.alloc(u8, encrypted_data.len) catch
        return SecretKeyDecryptError.OutOfMemory;
    errdefer allocator.free(decrypted);
    @memcpy(decrypted, encrypted_data);

    cfbDecryptWithIv(sym_algo, derived_key[0..key_size], iv, decrypted) catch
        return SecretKeyDecryptError.UnsupportedAlgorithm;

    // 6. Verify integrity
    if (s2k_usage == 254) {
        // SHA-1 hash check: last 20 bytes are the hash
        const sha1_len = 20;
        if (decrypted.len < sha1_len) {
            allocator.free(decrypted);
            return SecretKeyDecryptError.InvalidData;
        }

        const data_end = decrypted.len - sha1_len;
        const stored_hash = decrypted[data_end..];

        var sha1 = std.crypto.hash.Sha1.init(.{});
        sha1.update(decrypted[0..data_end]);
        const computed_hash = sha1.finalResult();

        if (!mem.eql(u8, stored_hash, &computed_hash)) {
            allocator.free(decrypted);
            return SecretKeyDecryptError.Sha1Mismatch;
        }

        // Return only the MPI data (without the SHA-1 hash)
        const result = allocator.alloc(u8, data_end) catch {
            allocator.free(decrypted);
            return SecretKeyDecryptError.OutOfMemory;
        };
        @memcpy(result, decrypted[0..data_end]);
        allocator.free(decrypted);
        return result;
    } else {
        // Two-octet checksum: last 2 bytes are the sum of all preceding bytes mod 65536
        if (decrypted.len < 2) {
            allocator.free(decrypted);
            return SecretKeyDecryptError.InvalidData;
        }

        const data_end = decrypted.len - 2;
        const stored_checksum = mem.readInt(u16, decrypted[data_end..][0..2], .big);

        var checksum: u16 = 0;
        for (decrypted[0..data_end]) |b| {
            checksum = checksum +% b;
        }

        if (stored_checksum != checksum) {
            allocator.free(decrypted);
            return SecretKeyDecryptError.ChecksumMismatch;
        }

        // Return only the MPI data (without the 2-byte checksum)
        const result = allocator.alloc(u8, data_end) catch {
            allocator.free(decrypted);
            return SecretKeyDecryptError.OutOfMemory;
        };
        @memcpy(result, decrypted[0..data_end]);
        allocator.free(decrypted);
        return result;
    }
}

/// Decrypt data in-place using CFB mode with the specified IV.
///
/// Unlike the standard OpenPGP CFB (which starts with FR=zeros and
/// generates its own prefix), secret key decryption uses CFB with
/// the IV as the initial feedback register value.
fn cfbDecryptWithIv(
    sym_algo: SymmetricAlgorithm,
    key: []const u8,
    iv: []const u8,
    data: []u8,
) !void {
    switch (sym_algo) {
        .aes128 => {
            var c = Aes128Cfb.init(key[0..16].*);
            @memcpy(&c.fr, iv[0..16]);
            c.decrypt(data);
        },
        .aes192 => {
            var c = Aes192Cfb.init(key[0..24].*);
            @memcpy(&c.fr, iv[0..16]);
            c.decrypt(data);
        },
        .aes256 => {
            var c = Aes256Cfb.init(key[0..32].*);
            @memcpy(&c.fr, iv[0..16]);
            c.decrypt(data);
        },
        .cast5 => {
            var c = Cast5Cfb.init(key[0..16].*);
            @memcpy(&c.fr, iv[0..8]);
            c.decrypt(data);
        },
        .twofish => {
            var c = TwofishCfb.init(key[0..32].*);
            @memcpy(&c.fr, iv[0..16]);
            c.decrypt(data);
        },
        .triple_des => {
            var c = TripleDesCfb.init(key[0..24].*);
            @memcpy(&c.fr, iv[0..8]);
            c.decrypt(data);
        },
        .blowfish => {
            var c = BlowfishCfb.init(key[0..16].*);
            @memcpy(&c.fr, iv[0..8]);
            c.decrypt(data);
        },
        .camellia128 => {
            var c = Camellia128Cfb.init(key[0..16].*);
            @memcpy(&c.fr, iv[0..16]);
            c.decrypt(data);
        },
        .camellia192 => {
            var c = Camellia192Cfb.init(key[0..24].*);
            @memcpy(&c.fr, iv[0..16]);
            c.decrypt(data);
        },
        .camellia256 => {
            var c = Camellia256Cfb.init(key[0..32].*);
            @memcpy(&c.fr, iv[0..16]);
            c.decrypt(data);
        },
        else => return error.UnsupportedAlgorithm,
    }
}

/// Encrypt data in-place using CFB mode with the specified IV.
///
/// Used for creating passphrase-protected secret keys.
fn cfbEncryptWithIv(
    sym_algo: SymmetricAlgorithm,
    key: []const u8,
    iv: []const u8,
    data: []u8,
) !void {
    switch (sym_algo) {
        .aes128 => {
            var c = Aes128Cfb.init(key[0..16].*);
            @memcpy(&c.fr, iv[0..16]);
            c.encrypt(data);
        },
        .aes192 => {
            var c = Aes192Cfb.init(key[0..24].*);
            @memcpy(&c.fr, iv[0..16]);
            c.encryptData(data);
        },
        .aes256 => {
            var c = Aes256Cfb.init(key[0..32].*);
            @memcpy(&c.fr, iv[0..16]);
            c.encrypt(data);
        },
        .cast5 => {
            var c = Cast5Cfb.init(key[0..16].*);
            @memcpy(&c.fr, iv[0..8]);
            c.encryptData(data);
        },
        .twofish => {
            var c = TwofishCfb.init(key[0..32].*);
            @memcpy(&c.fr, iv[0..16]);
            c.encryptData(data);
        },
        .triple_des => {
            var c = TripleDesCfb.init(key[0..24].*);
            @memcpy(&c.fr, iv[0..8]);
            c.encryptData(data);
        },
        .blowfish => {
            var c = BlowfishCfb.init(key[0..16].*);
            @memcpy(&c.fr, iv[0..8]);
            c.encryptData(data);
        },
        .camellia128 => {
            var c = Camellia128Cfb.init(key[0..16].*);
            @memcpy(&c.fr, iv[0..16]);
            c.encryptData(data);
        },
        .camellia192 => {
            var c = Camellia192Cfb.init(key[0..24].*);
            @memcpy(&c.fr, iv[0..16]);
            c.encryptData(data);
        },
        .camellia256 => {
            var c = Camellia256Cfb.init(key[0..32].*);
            @memcpy(&c.fr, iv[0..16]);
            c.encryptData(data);
        },
        else => return error.UnsupportedAlgorithm,
    }
}

/// Encrypt secret key material with a passphrase (for creating protected keys).
///
/// This is the inverse of decryptSecretKey: it takes plaintext MPI data,
/// derives a key from the passphrase, computes the integrity check, and
/// encrypts everything.
///
/// Returns the encrypted data (MPI data + integrity check, all encrypted).
pub fn encryptSecretKey(
    allocator: Allocator,
    plaintext_mpis: []const u8,
    passphrase: []const u8,
    sym_algo: SymmetricAlgorithm,
    iv: []const u8,
    s2k_data: []const u8,
    s2k_usage: u8,
) SecretKeyDecryptError![]u8 {
    const key_size = sym_algo.keySize() orelse return SecretKeyDecryptError.UnsupportedAlgorithm;
    const block_size = sym_algo.blockSize() orelse return SecretKeyDecryptError.UnsupportedAlgorithm;

    if (iv.len != block_size) return SecretKeyDecryptError.InvalidIV;

    // Parse S2K and derive key
    var s2k_fbs = std.io.fixedBufferStream(s2k_data);
    const s2k = S2K.readFrom(s2k_fbs.reader()) catch return SecretKeyDecryptError.InvalidS2k;

    var derived_key: [32]u8 = undefined;
    if (key_size > derived_key.len) return SecretKeyDecryptError.UnsupportedAlgorithm;

    s2k.deriveKeyAlloc(allocator, passphrase, derived_key[0..key_size]) catch |err| {
        return switch (err) {
            error.OutOfMemory => SecretKeyDecryptError.OutOfMemory,
            error.OutputTooLarge => SecretKeyDecryptError.OutputTooLarge,
            error.OutputTooLong => SecretKeyDecryptError.OutputTooLarge,
            error.UnsupportedS2kType => SecretKeyDecryptError.UnsupportedS2kType,
            error.UnsupportedAlgorithm => SecretKeyDecryptError.KeyDerivationFailed,
            error.OutputTooShort => SecretKeyDecryptError.KeyDerivationFailed,
            error.EndOfStream => SecretKeyDecryptError.EndOfStream,
            error.WeakParameters => SecretKeyDecryptError.WeakParameters,
        };
    };

    // Build plaintext + integrity check
    const integrity_len: usize = if (s2k_usage == 254) 20 else 2;
    const total_len = plaintext_mpis.len + integrity_len;

    const buf = allocator.alloc(u8, total_len) catch
        return SecretKeyDecryptError.OutOfMemory;
    errdefer allocator.free(buf);

    @memcpy(buf[0..plaintext_mpis.len], plaintext_mpis);

    if (s2k_usage == 254) {
        // SHA-1 hash
        var sha1 = std.crypto.hash.Sha1.init(.{});
        sha1.update(plaintext_mpis);
        const hash = sha1.finalResult();
        @memcpy(buf[plaintext_mpis.len..][0..20], &hash);
    } else {
        // Two-octet checksum
        var checksum: u16 = 0;
        for (plaintext_mpis) |b| {
            checksum = checksum +% b;
        }
        mem.writeInt(u16, buf[plaintext_mpis.len..][0..2], checksum, .big);
    }

    // Encrypt
    cfbEncryptWithIv(sym_algo, derived_key[0..key_size], iv, buf) catch
        return SecretKeyDecryptError.UnsupportedAlgorithm;

    return buf;
}

/// Parse the S2K usage byte and determine the protection mode.
pub const ProtectionMode = enum {
    /// s2k_usage == 0: unprotected
    unprotected,
    /// s2k_usage == 254: SHA-1 integrity check
    sha1_check,
    /// s2k_usage == 255: two-octet checksum with S2K
    checksum_with_s2k,
    /// s2k_usage is an algorithm ID: simple checksum, no S2K specifier
    legacy_algorithm,
};

pub fn protectionMode(s2k_usage: u8) ProtectionMode {
    return switch (s2k_usage) {
        0 => .unprotected,
        254 => .sha1_check,
        255 => .checksum_with_s2k,
        else => .legacy_algorithm,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "secret key decrypt/encrypt round-trip with SHA-1 check (usage 254)" {
    const allocator = std.testing.allocator;

    // Build test S2K (type 3, SHA-256, salt, count)
    const s2k_bytes = [_]u8{
        3, // iterated
        8, // SHA-256
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, // salt
        96, // coded_count -> 65536
    };

    // AES-128 IV (16 bytes)
    const iv = [_]u8{0x42} ** 16;

    // Plaintext MPI data (simulated)
    const plaintext_mpis = [_]u8{
        0x00, 0x08, // bit count
        0xAB, // MPI data
        0x00, 0x10, // bit count
        0xDE, 0xAD, // MPI data
    };

    // Encrypt
    const encrypted = try encryptSecretKey(
        allocator,
        &plaintext_mpis,
        "test-passphrase",
        .aes128,
        &iv,
        &s2k_bytes,
        254,
    );
    defer allocator.free(encrypted);

    // Encrypted should differ from plaintext
    try std.testing.expect(encrypted.len > plaintext_mpis.len);

    // Decrypt
    const decrypted = try decryptSecretKey(
        allocator,
        encrypted,
        "test-passphrase",
        .aes128,
        &iv,
        &s2k_bytes,
        254,
    );
    defer allocator.free(decrypted);

    try std.testing.expectEqualSlices(u8, &plaintext_mpis, decrypted);
}

test "secret key decrypt/encrypt round-trip with checksum (usage 255)" {
    const allocator = std.testing.allocator;

    const s2k_bytes = [_]u8{
        1, // salted
        2, // SHA-1
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // salt
    };

    const iv = [_]u8{0x55} ** 16;

    const plaintext_mpis = [_]u8{
        0x00, 0x20, // 32 bits
        0xDE, 0xAD, 0xBE, 0xEF,
    };

    const encrypted = try encryptSecretKey(
        allocator,
        &plaintext_mpis,
        "my-password",
        .aes256,
        &iv,
        &s2k_bytes,
        255,
    );
    defer allocator.free(encrypted);

    const decrypted = try decryptSecretKey(
        allocator,
        encrypted,
        "my-password",
        .aes256,
        &iv,
        &s2k_bytes,
        255,
    );
    defer allocator.free(decrypted);

    try std.testing.expectEqualSlices(u8, &plaintext_mpis, decrypted);
}

test "secret key decrypt wrong passphrase fails" {
    const allocator = std.testing.allocator;

    const s2k_bytes = [_]u8{
        3, 8,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
        96,
    };
    const iv = [_]u8{0x42} ** 16;
    const plaintext_mpis = [_]u8{ 0x00, 0x08, 0xAB };

    const encrypted = try encryptSecretKey(
        allocator,
        &plaintext_mpis,
        "correct-password",
        .aes128,
        &iv,
        &s2k_bytes,
        254,
    );
    defer allocator.free(encrypted);

    // Try wrong passphrase
    const result = decryptSecretKey(
        allocator,
        encrypted,
        "wrong-password",
        .aes128,
        &iv,
        &s2k_bytes,
        254,
    );
    try std.testing.expectError(SecretKeyDecryptError.Sha1Mismatch, result);
}

test "secret key decrypt with AES-192" {
    const allocator = std.testing.allocator;

    const s2k_bytes = [_]u8{
        3, 8,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        96,
    };
    const iv = [_]u8{0x77} ** 16;
    const plaintext_mpis = [_]u8{
        0x00, 0x10,
        0xCA, 0xFE,
        0x00, 0x08,
        0xBE,
    };

    const encrypted = try encryptSecretKey(
        allocator,
        &plaintext_mpis,
        "aes192-passphrase",
        .aes192,
        &iv,
        &s2k_bytes,
        254,
    );
    defer allocator.free(encrypted);

    const decrypted = try decryptSecretKey(
        allocator,
        encrypted,
        "aes192-passphrase",
        .aes192,
        &iv,
        &s2k_bytes,
        254,
    );
    defer allocator.free(decrypted);

    try std.testing.expectEqualSlices(u8, &plaintext_mpis, decrypted);
}

test "secret key decrypt with CAST5" {
    const allocator = std.testing.allocator;

    const s2k_bytes = [_]u8{
        0, // simple
        2, // SHA-1
    };
    const iv = [_]u8{0xDD} ** 8; // CAST5 block size = 8

    const plaintext_mpis = [_]u8{ 0x00, 0x08, 0xFF };

    const encrypted = try encryptSecretKey(
        allocator,
        &plaintext_mpis,
        "cast5-test",
        .cast5,
        &iv,
        &s2k_bytes,
        254,
    );
    defer allocator.free(encrypted);

    const decrypted = try decryptSecretKey(
        allocator,
        encrypted,
        "cast5-test",
        .cast5,
        &iv,
        &s2k_bytes,
        254,
    );
    defer allocator.free(decrypted);

    try std.testing.expectEqualSlices(u8, &plaintext_mpis, decrypted);
}

test "secret key decrypt empty MPI data" {
    const allocator = std.testing.allocator;

    const s2k_bytes = [_]u8{
        0, 8, // simple, SHA-256
    };
    const iv = [_]u8{0x00} ** 16;

    const encrypted = try encryptSecretKey(
        allocator,
        &[_]u8{},
        "empty-test",
        .aes128,
        &iv,
        &s2k_bytes,
        254,
    );
    defer allocator.free(encrypted);

    const decrypted = try decryptSecretKey(
        allocator,
        encrypted,
        "empty-test",
        .aes128,
        &iv,
        &s2k_bytes,
        254,
    );
    defer allocator.free(decrypted);

    try std.testing.expectEqual(@as(usize, 0), decrypted.len);
    allocator.free(decrypted);
}

test "protection mode classification" {
    try std.testing.expectEqual(ProtectionMode.unprotected, protectionMode(0));
    try std.testing.expectEqual(ProtectionMode.sha1_check, protectionMode(254));
    try std.testing.expectEqual(ProtectionMode.checksum_with_s2k, protectionMode(255));
    try std.testing.expectEqual(ProtectionMode.legacy_algorithm, protectionMode(7));
    try std.testing.expectEqual(ProtectionMode.legacy_algorithm, protectionMode(9));
}

test "secret key decrypt invalid IV length fails" {
    const allocator = std.testing.allocator;

    const s2k_bytes = [_]u8{ 0, 8 };
    const bad_iv = [_]u8{0x42} ** 8; // wrong for AES (should be 16)

    const result = decryptSecretKey(
        allocator,
        &[_]u8{0xAA} ** 30,
        "test",
        .aes128,
        &bad_iv,
        &s2k_bytes,
        254,
    );
    try std.testing.expectError(SecretKeyDecryptError.InvalidIV, result);
}

test "secret key decrypt with Twofish" {
    const allocator = std.testing.allocator;

    const s2k_bytes = [_]u8{
        1, 8,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
    };
    const iv = [_]u8{0x33} ** 16;

    const plaintext_mpis = [_]u8{
        0x00, 0x20,
        0x01, 0x02, 0x03, 0x04,
    };

    const encrypted = try encryptSecretKey(
        allocator,
        &plaintext_mpis,
        "twofish-pass",
        .twofish,
        &iv,
        &s2k_bytes,
        254,
    );
    defer allocator.free(encrypted);

    const decrypted = try decryptSecretKey(
        allocator,
        encrypted,
        "twofish-pass",
        .twofish,
        &iv,
        &s2k_bytes,
        254,
    );
    defer allocator.free(decrypted);

    try std.testing.expectEqualSlices(u8, &plaintext_mpis, decrypted);
}

test "secret key decrypt larger MPI data" {
    const allocator = std.testing.allocator;

    const s2k_bytes = [_]u8{
        3, 8,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        200,
    };
    const iv = [_]u8{0xAA} ** 16;

    // Simulate RSA secret key MPIs (d, p, q, u) - 128 bytes
    var plaintext_mpis: [128]u8 = undefined;
    for (&plaintext_mpis, 0..) |*b, i| {
        b.* = @truncate(i *% 37 +% 17);
    }

    const encrypted = try encryptSecretKey(
        allocator,
        &plaintext_mpis,
        "long-key-test",
        .aes256,
        &iv,
        &s2k_bytes,
        254,
    );
    defer allocator.free(encrypted);

    const decrypted = try decryptSecretKey(
        allocator,
        encrypted,
        "long-key-test",
        .aes256,
        &iv,
        &s2k_bytes,
        254,
    );
    defer allocator.free(decrypted);

    try std.testing.expectEqualSlices(u8, &plaintext_mpis, decrypted);
}
