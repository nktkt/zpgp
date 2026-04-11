// SPDX-License-Identifier: MIT
//! SEIPD (Symmetrically Encrypted Integrity Protected Data) encryption
//! and decryption per RFC 4880 Section 5.13.
//!
//! SEIPD v1 (Tag 18) protects the data with a Modification Detection Code
//! (MDC), which is a SHA-1 hash of the entire plaintext including the random
//! prefix and the MDC header bytes (0xD3, 0x14).
//!
//! The encryption uses OpenPGP CFB in non-resyncing mode.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const SymmetricAlgorithm = @import("../types/enums.zig").SymmetricAlgorithm;
const cfb_mod = @import("cfb.zig");
const Aes128Cfb = cfb_mod.Aes128Cfb;
const Aes192Cfb = cfb_mod.Aes192Cfb;
const Aes256Cfb = cfb_mod.Aes256Cfb;
const Cast5Cfb = cfb_mod.Cast5Cfb;
const TwofishCfb = cfb_mod.TwofishCfb;

pub const SeipdError = error{
    UnsupportedAlgorithm,
    InvalidVersion,
    InvalidData,
    QuickCheckFailed,
    MdcMismatch,
    MdcMissing,
    OutOfMemory,
    KeySizeMismatch,
};

/// MDC packet header bytes: tag 19 (0xD3 in new-format) + length 20 (0x14).
const MDC_HEADER = [2]u8{ 0xD3, 0x14 };

/// SHA-1 digest size.
const SHA1_DIGEST_LEN = 20;

/// Encrypt plaintext using SEIPD v1 (Tag 18).
///
/// Returns the complete SEIPD packet body including the version byte,
/// encrypted prefix, encrypted data, and encrypted MDC.
///
/// The plaintext should already be a serialized packet sequence (e.g.,
/// a literal data packet, optionally wrapped in a compressed data packet).
pub fn seipdEncrypt(
    allocator: Allocator,
    plaintext: []const u8,
    session_key: []const u8,
    sym_algo: SymmetricAlgorithm,
) SeipdError![]u8 {
    const block_size = sym_algo.blockSize() orelse return SeipdError.UnsupportedAlgorithm;
    const key_size = sym_algo.keySize() orelse return SeipdError.UnsupportedAlgorithm;

    if (session_key.len != key_size) return SeipdError.KeySizeMismatch;

    // 1. Generate random prefix: block_size bytes + 2 repeat bytes
    var prefix: [18]u8 = undefined; // max block_size (16) + 2
    const prefix_len = block_size + 2;
    std.crypto.random.bytes(prefix[0..block_size]);
    // Copy last two bytes of the random block as the quick-check bytes
    prefix[block_size] = prefix[block_size - 2];
    prefix[block_size + 1] = prefix[block_size - 1];

    // 2. Build the plaintext to be encrypted:
    //    prefix + plaintext + MDC_header(0xD3, 0x14) + SHA1(prefix + plaintext + 0xD3 + 0x14)
    //
    // The MDC hash covers: prefix + plaintext + MDC_HEADER
    const mdc_input_len = prefix_len + plaintext.len + 2; // +2 for MDC_HEADER
    const total_plaintext_len = prefix_len + plaintext.len + 2 + SHA1_DIGEST_LEN;

    // Allocate buffer for the data to encrypt
    const encrypt_buf = allocator.alloc(u8, total_plaintext_len) catch
        return SeipdError.OutOfMemory;
    errdefer allocator.free(encrypt_buf);

    // Fill in: prefix | plaintext | MDC_HEADER
    @memcpy(encrypt_buf[0..prefix_len], prefix[0..prefix_len]);
    if (plaintext.len > 0) {
        @memcpy(encrypt_buf[prefix_len .. prefix_len + plaintext.len], plaintext);
    }
    encrypt_buf[prefix_len + plaintext.len] = MDC_HEADER[0];
    encrypt_buf[prefix_len + plaintext.len + 1] = MDC_HEADER[1];

    // Compute SHA-1 of everything up to (and including) the MDC header
    var sha1 = std.crypto.hash.Sha1.init(.{});
    sha1.update(encrypt_buf[0..mdc_input_len]);
    const mdc_hash = sha1.finalResult();

    // Append the MDC hash
    @memcpy(encrypt_buf[mdc_input_len .. mdc_input_len + SHA1_DIGEST_LEN], &mdc_hash);

    // 3. Encrypt everything with OpenPGP CFB (non-resyncing)
    encryptCfb(sym_algo, session_key, encrypt_buf) catch return SeipdError.UnsupportedAlgorithm;

    // 4. Build the SEIPD packet body: version byte (1) + encrypted data
    const result = allocator.alloc(u8, 1 + encrypt_buf.len) catch
        return SeipdError.OutOfMemory;
    result[0] = 1; // version
    @memcpy(result[1..], encrypt_buf);

    allocator.free(encrypt_buf);
    return result;
}

/// Decrypt SEIPD v1 data.
///
/// `encrypted_data` is the SEIPD packet body (including the version byte).
/// Returns the decrypted plaintext (without prefix and MDC).
pub fn seipdDecrypt(
    allocator: Allocator,
    encrypted_data: []const u8,
    session_key: []const u8,
    sym_algo: SymmetricAlgorithm,
) SeipdError![]u8 {
    const block_size = sym_algo.blockSize() orelse return SeipdError.UnsupportedAlgorithm;
    const key_size = sym_algo.keySize() orelse return SeipdError.UnsupportedAlgorithm;

    if (session_key.len != key_size) return SeipdError.KeySizeMismatch;

    // 1. Check version == 1
    if (encrypted_data.len < 1) return SeipdError.InvalidData;
    if (encrypted_data[0] != 1) return SeipdError.InvalidVersion;

    const cipher_data = encrypted_data[1..];
    const prefix_len = block_size + 2;

    // Minimum data: prefix + MDC_HEADER(2) + SHA1(20)
    if (cipher_data.len < prefix_len + 2 + SHA1_DIGEST_LEN) return SeipdError.InvalidData;

    // 2. Decrypt with OpenPGP CFB (non-resyncing)
    const decrypted = allocator.alloc(u8, cipher_data.len) catch
        return SeipdError.OutOfMemory;
    defer allocator.free(decrypted);
    @memcpy(decrypted, cipher_data);

    decryptCfb(sym_algo, session_key, decrypted) catch return SeipdError.UnsupportedAlgorithm;

    // 3. Verify quick-check bytes
    if (decrypted[block_size] != decrypted[block_size - 2] or
        decrypted[block_size + 1] != decrypted[block_size - 1])
    {
        return SeipdError.QuickCheckFailed;
    }

    // 4. Verify MDC
    // The last 22 bytes should be: MDC_HEADER (2) + SHA-1 hash (20)
    const mdc_start = decrypted.len - SHA1_DIGEST_LEN - 2;

    // Check MDC header bytes
    if (decrypted[mdc_start] != MDC_HEADER[0] or decrypted[mdc_start + 1] != MDC_HEADER[1]) {
        return SeipdError.MdcMissing;
    }

    // Extract the stored MDC hash
    const stored_mdc = decrypted[mdc_start + 2 .. mdc_start + 2 + SHA1_DIGEST_LEN];

    // Compute expected MDC: SHA-1 of everything before the MDC hash
    var sha1 = std.crypto.hash.Sha1.init(.{});
    sha1.update(decrypted[0 .. mdc_start + 2]); // prefix + plaintext + MDC_HEADER
    const expected_mdc = sha1.finalResult();

    if (!mem.eql(u8, stored_mdc, &expected_mdc)) {
        return SeipdError.MdcMismatch;
    }

    // 5. Extract plaintext: between prefix and MDC
    const plaintext_start = prefix_len;
    const plaintext_end = mdc_start;

    if (plaintext_end < plaintext_start) {
        return SeipdError.InvalidData;
    }

    const plaintext_len = plaintext_end - plaintext_start;
    const result = allocator.alloc(u8, plaintext_len) catch
        return SeipdError.OutOfMemory;

    @memcpy(result, decrypted[plaintext_start..plaintext_end]);
    return result;
}

/// Encrypt data in-place using the appropriate CFB cipher for the algorithm.
fn encryptCfb(sym_algo: SymmetricAlgorithm, key: []const u8, data: []u8) !void {
    switch (sym_algo) {
        .aes128 => {
            var c = Aes128Cfb.init(key[0..16].*);
            c.encrypt(data);
        },
        .aes192 => {
            var c = Aes192Cfb.init(key[0..24].*);
            c.encryptData(data);
        },
        .aes256 => {
            var c = Aes256Cfb.init(key[0..32].*);
            c.encrypt(data);
        },
        .cast5 => {
            var c = Cast5Cfb.init(key[0..16].*);
            c.encryptData(data);
        },
        .twofish => {
            var c = TwofishCfb.init(key[0..32].*);
            c.encryptData(data);
        },
        else => return error.UnsupportedAlgorithm,
    }
}

/// Decrypt data in-place using the appropriate CFB cipher for the algorithm.
fn decryptCfb(sym_algo: SymmetricAlgorithm, key: []const u8, data: []u8) !void {
    switch (sym_algo) {
        .aes128 => {
            var c = Aes128Cfb.init(key[0..16].*);
            c.decrypt(data);
        },
        .aes192 => {
            var c = Aes192Cfb.init(key[0..24].*);
            c.decrypt(data);
        },
        .aes256 => {
            var c = Aes256Cfb.init(key[0..32].*);
            c.decrypt(data);
        },
        .cast5 => {
            var c = Cast5Cfb.init(key[0..16].*);
            c.decrypt(data);
        },
        .twofish => {
            var c = TwofishCfb.init(key[0..32].*);
            c.decrypt(data);
        },
        else => return error.UnsupportedAlgorithm,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "SEIPD AES-128 encrypt/decrypt round-trip" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const plaintext = "Hello, SEIPD v1 with AES-128!";

    const encrypted = try seipdEncrypt(allocator, plaintext, &key, .aes128);
    defer allocator.free(encrypted);

    // Must start with version 1
    try std.testing.expectEqual(@as(u8, 1), encrypted[0]);

    // Decrypt
    const decrypted = try seipdDecrypt(allocator, encrypted, &key, .aes128);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "SEIPD AES-256 encrypt/decrypt round-trip" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0xAB} ** 32;
    const plaintext = "AES-256 SEIPD encryption test with longer message data for multiple blocks";

    const encrypted = try seipdEncrypt(allocator, plaintext, &key, .aes256);
    defer allocator.free(encrypted);

    try std.testing.expectEqual(@as(u8, 1), encrypted[0]);

    const decrypted = try seipdDecrypt(allocator, encrypted, &key, .aes256);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "SEIPD CAST5 encrypt/decrypt round-trip" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0xDE} ** 16;
    const plaintext = "CAST5 SEIPD test data";

    const encrypted = try seipdEncrypt(allocator, plaintext, &key, .cast5);
    defer allocator.free(encrypted);

    const decrypted = try seipdDecrypt(allocator, encrypted, &key, .cast5);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "SEIPD Twofish encrypt/decrypt round-trip" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x77} ** 32;
    const plaintext = "Twofish SEIPD encryption test message";

    const encrypted = try seipdEncrypt(allocator, plaintext, &key, .twofish);
    defer allocator.free(encrypted);

    const decrypted = try seipdDecrypt(allocator, encrypted, &key, .twofish);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "SEIPD empty plaintext" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x01} ** 16;

    const encrypted = try seipdEncrypt(allocator, "", &key, .aes128);
    defer allocator.free(encrypted);

    const decrypted = try seipdDecrypt(allocator, encrypted, &key, .aes128);
    defer allocator.free(decrypted);

    try std.testing.expectEqual(@as(usize, 0), decrypted.len);
}

test "SEIPD decrypt wrong key fails" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const wrong_key = [_]u8{0x99} ** 16;
    const plaintext = "Sensitive data";

    const encrypted = try seipdEncrypt(allocator, plaintext, &key, .aes128);
    defer allocator.free(encrypted);

    // Decrypting with the wrong key should fail (either quick-check or MDC)
    if (seipdDecrypt(allocator, encrypted, &wrong_key, .aes128)) |decrypted| {
        allocator.free(decrypted);
        try std.testing.expect(false); // should not succeed
    } else |err| {
        try std.testing.expect(err == SeipdError.QuickCheckFailed or
            err == SeipdError.MdcMismatch or
            err == SeipdError.MdcMissing);
    }
}

test "SEIPD decrypt tampered data fails" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const plaintext = "Integrity-protected data";

    const encrypted = try seipdEncrypt(allocator, plaintext, &key, .aes128);
    defer allocator.free(encrypted);

    // Tamper with the encrypted data (flip a byte in the middle)
    const mid = encrypted.len / 2;
    encrypted[mid] ^= 0xFF;

    // Decryption should fail integrity check
    if (seipdDecrypt(allocator, encrypted, &key, .aes128)) |decrypted| {
        allocator.free(decrypted);
        try std.testing.expect(false);
    } else |err| {
        try std.testing.expect(err == SeipdError.QuickCheckFailed or
            err == SeipdError.MdcMismatch or
            err == SeipdError.MdcMissing);
    }
}

test "SEIPD decrypt invalid version fails" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x42} ** 16;

    // Version 2 (invalid)
    var data: [50]u8 = undefined;
    data[0] = 2;
    @memset(data[1..], 0xAA);

    const result = seipdDecrypt(allocator, &data, &key, .aes128);
    try std.testing.expectError(SeipdError.InvalidVersion, result);
}

test "SEIPD decrypt data too short fails" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x42} ** 16;

    // Version byte + too little data
    const data = [_]u8{ 1, 0xAA, 0xBB };
    const result = seipdDecrypt(allocator, &data, &key, .aes128);
    try std.testing.expectError(SeipdError.InvalidData, result);
}

test "SEIPD unsupported algorithm" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x42} ** 16;

    const result = seipdEncrypt(allocator, "test", &key, .plaintext);
    try std.testing.expectError(SeipdError.UnsupportedAlgorithm, result);
}

test "SEIPD key size mismatch" {
    const allocator = std.testing.allocator;
    const short_key = [_]u8{0x42} ** 8; // too short for AES-128

    const result = seipdEncrypt(allocator, "test", &short_key, .aes128);
    try std.testing.expectError(SeipdError.KeySizeMismatch, result);
}

test "SEIPD large plaintext" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x55} ** 32;

    // 4KB plaintext
    const plaintext = try allocator.alloc(u8, 4096);
    defer allocator.free(plaintext);
    @memset(plaintext, 0x42);

    const encrypted = try seipdEncrypt(allocator, plaintext, &key, .aes256);
    defer allocator.free(encrypted);

    const decrypted = try seipdDecrypt(allocator, encrypted, &key, .aes256);
    defer allocator.free(decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, decrypted);
}

test "SEIPD encrypted data differs from plaintext" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x01} ** 16;
    const plaintext = "This should be encrypted";

    const encrypted = try seipdEncrypt(allocator, plaintext, &key, .aes128);
    defer allocator.free(encrypted);

    // The encrypted portion (after version byte) should not contain the plaintext
    try std.testing.expect(mem.indexOf(u8, encrypted[1..], plaintext) == null);
}

test "SEIPD two encryptions produce different ciphertext" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const plaintext = "Same plaintext";

    const enc1 = try seipdEncrypt(allocator, plaintext, &key, .aes128);
    defer allocator.free(enc1);

    const enc2 = try seipdEncrypt(allocator, plaintext, &key, .aes128);
    defer allocator.free(enc2);

    // Different random prefix means different ciphertext
    try std.testing.expect(!mem.eql(u8, enc1, enc2));

    // But both decrypt to the same plaintext
    const dec1 = try seipdDecrypt(allocator, enc1, &key, .aes128);
    defer allocator.free(dec1);
    const dec2 = try seipdDecrypt(allocator, enc2, &key, .aes128);
    defer allocator.free(dec2);

    try std.testing.expectEqualStrings(plaintext, dec1);
    try std.testing.expectEqualStrings(plaintext, dec2);
}
