// SPDX-License-Identifier: MIT
//! Unified symmetric cipher dispatch for OpenPGP.
//!
//! Consolidates symmetric cipher operations into a single dispatch interface.
//! Given a runtime SymmetricAlgorithm value, routes operations to the
//! appropriate cipher implementation from the standard library or custom
//! implementations (CAST5, Twofish, Triple DES).
//!
//! Supports:
//!   - AES-128 (algo 7): 16-byte key, 16-byte block
//!   - AES-256 (algo 9): 32-byte key, 16-byte block
//!   - CAST5   (algo 3): 16-byte key, 8-byte block
//!   - Twofish (algo 10): 32-byte key, 16-byte block
//!   - Triple DES (algo 2): 24-byte key, 8-byte block
//!
//! Note: AES-192 is listed in the OpenPGP spec but is not available in
//! the Zig standard library on all platforms. It is reported via
//! getCipherInfo but not supported for block/CFB operations.

const std = @import("std");
const aes = std.crypto.core.aes;
const SymmetricAlgorithm = @import("../types/enums.zig").SymmetricAlgorithm;
const Cast5 = @import("cast5.zig").Cast5;
const Twofish = @import("twofish.zig").Twofish;
const TripleDes = @import("triple_des.zig").TripleDes;
const cfb_mod = @import("cfb.zig");

/// Security level classification for symmetric algorithms.
pub const SecurityLevel = enum {
    /// Algorithm provides adequate security (>= 128-bit equivalent).
    secure,
    /// Algorithm is deprecated but may still be encountered.
    deprecated,
    /// Algorithm is insecure and should not be used.
    insecure,
    /// Algorithm is not recognized.
    unknown,
};

/// Information about a symmetric cipher.
pub const CipherInfo = struct {
    /// Key size in bytes.
    key_size: usize,
    /// Block size in bytes.
    block_size: usize,
    /// Human-readable algorithm name.
    name: []const u8,
    /// Security assessment.
    security_level: SecurityLevel,
};

/// Get cipher properties for a symmetric algorithm.
///
/// Returns null for unsupported or unknown algorithms.
pub fn getCipherInfo(algo: SymmetricAlgorithm) ?CipherInfo {
    return switch (algo) {
        .aes128 => .{
            .key_size = 16,
            .block_size = 16,
            .name = "AES-128",
            .security_level = .secure,
        },
        .aes192 => .{
            .key_size = 24,
            .block_size = 16,
            .name = "AES-192",
            .security_level = .secure,
        },
        .aes256 => .{
            .key_size = 32,
            .block_size = 16,
            .name = "AES-256",
            .security_level = .secure,
        },
        .cast5 => .{
            .key_size = 16,
            .block_size = 8,
            .name = "CAST5",
            .security_level = .deprecated,
        },
        .twofish => .{
            .key_size = 32,
            .block_size = 16,
            .name = "Twofish-256",
            .security_level = .secure,
        },
        .triple_des => .{
            .key_size = 24,
            .block_size = 8,
            .name = "3DES",
            .security_level = .deprecated,
        },
        .idea => .{
            .key_size = 16,
            .block_size = 8,
            .name = "IDEA",
            .security_level = .deprecated,
        },
        .blowfish => .{
            .key_size = 16,
            .block_size = 8,
            .name = "Blowfish",
            .security_level = .deprecated,
        },
        .plaintext => null,
        _ => null,
    };
}

/// Encrypt a single block with the specified algorithm.
///
/// `key` must be exactly the key size for the algorithm.
/// `dst` and `src` must be exactly the block size for the algorithm.
pub fn encryptBlock(algo: SymmetricAlgorithm, key: []const u8, dst: []u8, src: []const u8) !void {
    switch (algo) {
        .aes128 => {
            if (key.len != 16) return error.InvalidKeyLength;
            const ctx = aes.Aes128.initEnc(key[0..16].*);
            ctx.encrypt(dst[0..16], src[0..16]);
        },
        .aes256 => {
            if (key.len != 32) return error.InvalidKeyLength;
            const ctx = aes.Aes256.initEnc(key[0..32].*);
            ctx.encrypt(dst[0..16], src[0..16]);
        },
        .cast5 => {
            if (key.len != 16) return error.InvalidKeyLength;
            const ctx = Cast5.initEnc(key[0..16].*);
            ctx.encrypt(dst[0..8], src[0..8]);
        },
        .twofish => {
            if (key.len != 32) return error.InvalidKeyLength;
            const ctx = Twofish.initEnc(key[0..32].*);
            ctx.encrypt(dst[0..16], src[0..16]);
        },
        .triple_des => {
            if (key.len != 24) return error.InvalidKeyLength;
            const ctx = TripleDes.initEnc(key[0..24].*);
            ctx.encrypt(dst[0..8], src[0..8]);
        },
        else => return error.UnsupportedAlgorithm,
    }
}

/// Decrypt a single block with the specified algorithm.
///
/// `key` must be exactly the key size for the algorithm.
/// `dst` and `src` must be exactly the block size for the algorithm.
pub fn decryptBlock(algo: SymmetricAlgorithm, key: []const u8, dst: []u8, src: []const u8) !void {
    switch (algo) {
        .aes128 => {
            if (key.len != 16) return error.InvalidKeyLength;
            const ctx = aes.Aes128.initDec(key[0..16].*);
            ctx.decrypt(dst[0..16], src[0..16]);
        },
        .aes256 => {
            if (key.len != 32) return error.InvalidKeyLength;
            const ctx = aes.Aes256.initDec(key[0..32].*);
            ctx.decrypt(dst[0..16], src[0..16]);
        },
        .cast5 => {
            if (key.len != 16) return error.InvalidKeyLength;
            const ctx = Cast5.initEnc(key[0..16].*);
            ctx.decrypt(dst[0..8], src[0..8]);
        },
        .twofish => {
            if (key.len != 32) return error.InvalidKeyLength;
            const ctx = Twofish.initEnc(key[0..32].*);
            ctx.decrypt(dst[0..16], src[0..16]);
        },
        .triple_des => {
            if (key.len != 24) return error.InvalidKeyLength;
            const ctx = TripleDes.initEnc(key[0..24].*);
            ctx.decrypt(dst[0..8], src[0..8]);
        },
        else => return error.UnsupportedAlgorithm,
    }
}

/// Create an OpenPGP CFB encryptor for any supported algorithm.
///
/// Returns a CfbEncryptor that wraps the appropriate CFB implementation.
pub fn createCfbEncryptor(algo: SymmetricAlgorithm, key: []const u8) !CfbEncryptor {
    return switch (algo) {
        .aes128 => {
            if (key.len != 16) return error.InvalidKeyLength;
            return CfbEncryptor{ .state = .{ .aes128 = cfb_mod.OpenPgpCfb(aes.Aes128).init(key[0..16].*) } };
        },
        .aes256 => {
            if (key.len != 32) return error.InvalidKeyLength;
            return CfbEncryptor{ .state = .{ .aes256 = cfb_mod.OpenPgpCfb(aes.Aes256).init(key[0..32].*) } };
        },
        .cast5 => {
            if (key.len != 16) return error.InvalidKeyLength;
            return CfbEncryptor{ .state = .{ .cast5 = cfb_mod.Cast5Cfb.init(key[0..16].*) } };
        },
        .twofish => {
            if (key.len != 32) return error.InvalidKeyLength;
            return CfbEncryptor{ .state = .{ .twofish = cfb_mod.TwofishCfb.init(key[0..32].*) } };
        },
        .triple_des => {
            if (key.len != 24) return error.InvalidKeyLength;
            return CfbEncryptor{ .state = .{ .triple_des = cfb_mod.TripleDesCfb.init(key[0..24].*) } };
        },
        else => error.UnsupportedAlgorithm,
    };
}

/// Type alias for the CFB modes.
/// AES ciphers use the AES-specific CFB mode; other ciphers use the direct variant.
const Aes128Cfb = cfb_mod.Aes128Cfb;
const Aes256Cfb = cfb_mod.Aes256Cfb;
const Cast5Cfb = cfb_mod.Cast5Cfb;
const TwofishCfb = cfb_mod.TwofishCfb;
const TripleDesCfb = cfb_mod.TripleDesCfb;

/// Unified CFB encryptor/decryptor that dispatches to the correct implementation.
pub const CfbEncryptor = struct {
    state: union(enum) {
        aes128: Aes128Cfb,
        aes256: Aes256Cfb,
        cast5: Cast5Cfb,
        twofish: TwofishCfb,
        triple_des: TripleDesCfb,
    },

    /// Encrypt data in-place using non-resyncing CFB.
    pub fn encrypt(self: *CfbEncryptor, data: []u8) void {
        switch (self.state) {
            .aes128 => |*s| s.encrypt(data),
            .aes256 => |*s| s.encrypt(data),
            // Direct CFB types use encryptData instead of encrypt
            .cast5 => |*s| s.encryptData(data),
            .twofish => |*s| s.encryptData(data),
            .triple_des => |*s| s.encryptData(data),
        }
    }

    /// Decrypt data in-place using non-resyncing CFB.
    pub fn decrypt(self: *CfbEncryptor, data: []u8) void {
        switch (self.state) {
            .aes128 => |*s| s.decrypt(data),
            .aes256 => |*s| s.decrypt(data),
            .cast5 => |*s| s.decrypt(data),
            .twofish => |*s| s.decrypt(data),
            .triple_des => |*s| s.decrypt(data),
        }
    }

    /// Get the block size of the underlying cipher.
    pub fn blockSize(self: *const CfbEncryptor) usize {
        return switch (self.state) {
            .aes128 => Aes128Cfb.block_size,
            .aes256 => Aes256Cfb.block_size,
            .cast5 => Cast5Cfb.block_size,
            .twofish => TwofishCfb.block_size,
            .triple_des => TripleDesCfb.block_size,
        };
    }
};

/// Check whether a symmetric algorithm is supported for block operations.
pub fn isSupported(algo: SymmetricAlgorithm) bool {
    return getCipherInfo(algo) != null;
}

/// Check whether a symmetric algorithm has adequate security for new messages.
///
/// Returns true only for algorithms with at least 128-bit security.
pub fn isSecureForNew(algo: SymmetricAlgorithm) bool {
    const info = getCipherInfo(algo) orelse return false;
    return info.security_level == .secure;
}

/// Validate that a key has the correct length for the given algorithm.
pub fn validateKeyLength(algo: SymmetricAlgorithm, key_len: usize) bool {
    const info = getCipherInfo(algo) orelse return false;
    return key_len == info.key_size;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "getCipherInfo returns correct values" {
    const aes128_info = getCipherInfo(.aes128).?;
    try std.testing.expectEqual(@as(usize, 16), aes128_info.key_size);
    try std.testing.expectEqual(@as(usize, 16), aes128_info.block_size);
    try std.testing.expectEqualStrings("AES-128", aes128_info.name);
    try std.testing.expectEqual(SecurityLevel.secure, aes128_info.security_level);

    const aes256_info = getCipherInfo(.aes256).?;
    try std.testing.expectEqual(@as(usize, 32), aes256_info.key_size);
    try std.testing.expectEqual(@as(usize, 16), aes256_info.block_size);
    try std.testing.expectEqualStrings("AES-256", aes256_info.name);
    try std.testing.expectEqual(SecurityLevel.secure, aes256_info.security_level);

    const cast5_info = getCipherInfo(.cast5).?;
    try std.testing.expectEqual(@as(usize, 16), cast5_info.key_size);
    try std.testing.expectEqual(@as(usize, 8), cast5_info.block_size);
    try std.testing.expectEqual(SecurityLevel.deprecated, cast5_info.security_level);

    const twofish_info = getCipherInfo(.twofish).?;
    try std.testing.expectEqual(@as(usize, 32), twofish_info.key_size);
    try std.testing.expectEqual(@as(usize, 16), twofish_info.block_size);
    try std.testing.expectEqual(SecurityLevel.secure, twofish_info.security_level);

    const tdes_info = getCipherInfo(.triple_des).?;
    try std.testing.expectEqual(@as(usize, 24), tdes_info.key_size);
    try std.testing.expectEqual(@as(usize, 8), tdes_info.block_size);
    try std.testing.expectEqual(SecurityLevel.deprecated, tdes_info.security_level);
}

test "getCipherInfo returns null for unsupported" {
    try std.testing.expect(getCipherInfo(.plaintext) == null);
    const unknown: SymmetricAlgorithm = @enumFromInt(200);
    try std.testing.expect(getCipherInfo(unknown) == null);
}

test "encryptBlock AES-128 round-trip" {
    const key = [_]u8{0x42} ** 16;
    const plaintext = [_]u8{0xAA} ** 16;
    var ciphertext: [16]u8 = undefined;
    var decrypted: [16]u8 = undefined;

    try encryptBlock(.aes128, &key, &ciphertext, &plaintext);
    try std.testing.expect(!std.mem.eql(u8, &plaintext, &ciphertext));

    try decryptBlock(.aes128, &key, &decrypted, &ciphertext);
    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "encryptBlock AES-256 round-trip" {
    const key = [_]u8{0x42} ** 32;
    const plaintext = [_]u8{0xBB} ** 16;
    var ciphertext: [16]u8 = undefined;
    var decrypted: [16]u8 = undefined;

    try encryptBlock(.aes256, &key, &ciphertext, &plaintext);
    try decryptBlock(.aes256, &key, &decrypted, &ciphertext);
    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "encryptBlock CAST5 round-trip" {
    const key = [_]u8{0x42} ** 16;
    const plaintext = [_]u8{0xCC} ** 8;
    var ciphertext: [8]u8 = undefined;
    var decrypted: [8]u8 = undefined;

    try encryptBlock(.cast5, &key, &ciphertext, &plaintext);
    try decryptBlock(.cast5, &key, &decrypted, &ciphertext);
    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "encryptBlock Twofish round-trip" {
    const key = [_]u8{0x42} ** 32;
    const plaintext = [_]u8{0xDD} ** 16;
    var ciphertext: [16]u8 = undefined;
    var decrypted: [16]u8 = undefined;

    try encryptBlock(.twofish, &key, &ciphertext, &plaintext);
    try decryptBlock(.twofish, &key, &decrypted, &ciphertext);
    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "encryptBlock Triple DES round-trip" {
    const key = [_]u8{0x42} ** 24;
    const plaintext = [_]u8{0xEE} ** 8;
    var ciphertext: [8]u8 = undefined;
    var decrypted: [8]u8 = undefined;

    try encryptBlock(.triple_des, &key, &ciphertext, &plaintext);
    try decryptBlock(.triple_des, &key, &decrypted, &ciphertext);
    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "encryptBlock rejects wrong key length" {
    const key = [_]u8{0} ** 10; // Wrong length
    var dst: [16]u8 = undefined;
    const src = [_]u8{0} ** 16;

    try std.testing.expectError(error.InvalidKeyLength, encryptBlock(.aes128, &key, &dst, &src));
}

test "encryptBlock rejects unsupported algorithm" {
    const key = [_]u8{0} ** 16;
    var dst: [16]u8 = undefined;
    const src = [_]u8{0} ** 16;

    try std.testing.expectError(error.UnsupportedAlgorithm, encryptBlock(.plaintext, &key, &dst, &src));
}

test "createCfbEncryptor AES-128 encrypt/decrypt" {
    const key = [_]u8{0x42} ** 16;
    const original: [16]u8 = "Hello, OpenPGP!X".*;

    var enc = try createCfbEncryptor(.aes128, &key);
    var data = original;
    enc.encrypt(&data);

    // Encrypted data should differ from original
    try std.testing.expect(!std.mem.eql(u8, &original, &data));

    // Create a fresh decryptor
    var dec = try createCfbEncryptor(.aes128, &key);
    dec.decrypt(&data);

    try std.testing.expectEqualSlices(u8, &original, &data);
}

test "createCfbEncryptor AES-256 encrypt/decrypt" {
    const key = [_]u8{0x42} ** 32;
    const original: [16]u8 = "AES-256 test!!!!".*;

    var enc = try createCfbEncryptor(.aes256, &key);
    var data = original;
    enc.encrypt(&data);

    var dec = try createCfbEncryptor(.aes256, &key);
    dec.decrypt(&data);

    try std.testing.expectEqualSlices(u8, &original, &data);
}

test "createCfbEncryptor CAST5 encrypt/decrypt" {
    const key = [_]u8{0x42} ** 16;
    const original: [8]u8 = "CAST5!!!".*;

    var enc = try createCfbEncryptor(.cast5, &key);
    var data = original;
    enc.encrypt(&data);

    var dec = try createCfbEncryptor(.cast5, &key);
    dec.decrypt(&data);

    try std.testing.expectEqualSlices(u8, &original, &data);
}

test "createCfbEncryptor rejects wrong key length" {
    const key = [_]u8{0} ** 10;
    try std.testing.expectError(error.InvalidKeyLength, createCfbEncryptor(.aes128, &key));
}

test "createCfbEncryptor rejects unsupported algorithm" {
    const key = [_]u8{0} ** 16;
    try std.testing.expectError(error.UnsupportedAlgorithm, createCfbEncryptor(.plaintext, &key));
}

test "CfbEncryptor blockSize" {
    const key128 = [_]u8{0x42} ** 16;
    const enc128 = try createCfbEncryptor(.aes128, &key128);
    try std.testing.expectEqual(@as(usize, 16), enc128.blockSize());

    const key_cast = [_]u8{0x42} ** 16;
    const enc_cast = try createCfbEncryptor(.cast5, &key_cast);
    try std.testing.expectEqual(@as(usize, 8), enc_cast.blockSize());
}

test "isSupported" {
    try std.testing.expect(isSupported(.aes128));
    try std.testing.expect(isSupported(.aes256));
    try std.testing.expect(isSupported(.cast5));
    try std.testing.expect(isSupported(.twofish));
    try std.testing.expect(isSupported(.triple_des));
    try std.testing.expect(!isSupported(.plaintext));
}

test "isSecureForNew" {
    try std.testing.expect(isSecureForNew(.aes128));
    try std.testing.expect(isSecureForNew(.aes256));
    try std.testing.expect(isSecureForNew(.twofish));
    try std.testing.expect(!isSecureForNew(.cast5));
    try std.testing.expect(!isSecureForNew(.triple_des));
    try std.testing.expect(!isSecureForNew(.plaintext));
}

test "validateKeyLength" {
    try std.testing.expect(validateKeyLength(.aes128, 16));
    try std.testing.expect(!validateKeyLength(.aes128, 32));
    try std.testing.expect(validateKeyLength(.aes256, 32));
    try std.testing.expect(!validateKeyLength(.aes256, 16));
    try std.testing.expect(validateKeyLength(.cast5, 16));
    try std.testing.expect(validateKeyLength(.twofish, 32));
    try std.testing.expect(validateKeyLength(.triple_des, 24));
    try std.testing.expect(!validateKeyLength(.plaintext, 0));
}
