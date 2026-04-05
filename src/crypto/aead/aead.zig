// SPDX-License-Identifier: MIT
//! Unified AEAD interface for OpenPGP (RFC 9580).
//!
//! Dispatches to the correct AEAD algorithm (EAX, OCB, GCM) based on
//! the algorithm identifiers from the packet headers.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const SymmetricAlgorithm = @import("../../types/enums.zig").SymmetricAlgorithm;
const eax_mod = @import("eax.zig");
const ocb_mod = @import("ocb.zig");
const gcm_mod = @import("gcm.zig");

/// RFC 9580 Section 9.6 - AEAD Algorithms
pub const AeadAlgorithm = enum(u8) {
    eax = 1,
    ocb = 2,
    gcm = 3,
    _,

    pub fn name(self: AeadAlgorithm) []const u8 {
        return switch (self) {
            .eax => "EAX",
            .ocb => "OCB",
            .gcm => "GCM",
            _ => "Unknown",
        };
    }

    /// Authentication tag size in bytes. All OpenPGP AEAD modes use 16.
    pub fn tagSize(self: AeadAlgorithm) ?usize {
        return switch (self) {
            .eax => 16,
            .ocb => 16,
            .gcm => 16,
            _ => null,
        };
    }

    /// Nonce (IV) size in bytes.
    pub fn nonceSize(self: AeadAlgorithm) ?usize {
        return switch (self) {
            .eax => 16,
            .ocb => 15,
            .gcm => 12,
            _ => null,
        };
    }
};

pub const AeadError = error{
    UnsupportedAlgorithm,
    UnsupportedSymmetricAlgorithm,
    AuthenticationFailed,
    OutOfMemory,
    KeySizeMismatch,
    NonceSizeMismatch,
};

pub const AeadResult = struct {
    ciphertext: []u8,
    tag: [16]u8,

    pub fn deinit(self: AeadResult, allocator: Allocator) void {
        allocator.free(self.ciphertext);
    }
};

/// Encrypt with AEAD, dispatching to the correct algorithm.
pub fn aeadEncrypt(
    allocator: Allocator,
    sym_algo: SymmetricAlgorithm,
    aead_algo: AeadAlgorithm,
    key: []const u8,
    nonce: []const u8,
    plaintext: []const u8,
    ad: []const u8,
) AeadError!AeadResult {
    const expected_nonce_size = aead_algo.nonceSize() orelse return AeadError.UnsupportedAlgorithm;
    if (nonce.len != expected_nonce_size) return AeadError.NonceSizeMismatch;

    const ciphertext = allocator.alloc(u8, plaintext.len) catch return AeadError.OutOfMemory;
    errdefer allocator.free(ciphertext);

    var tag: [16]u8 = undefined;

    switch (aead_algo) {
        .eax => {
            switch (sym_algo) {
                .aes128 => {
                    if (key.len != 16) return AeadError.KeySizeMismatch;
                    const ctx = eax_mod.AesEax128.init(key[0..16].*);
                    ctx.encrypt(ciphertext, &tag, plaintext, nonce, ad);
                },
                .aes256 => {
                    if (key.len != 32) return AeadError.KeySizeMismatch;
                    const ctx = eax_mod.AesEax256.init(key[0..32].*);
                    ctx.encrypt(ciphertext, &tag, plaintext, nonce, ad);
                },
                else => return AeadError.UnsupportedSymmetricAlgorithm,
            }
        },
        .ocb => {
            switch (sym_algo) {
                .aes128 => {
                    if (key.len != 16) return AeadError.KeySizeMismatch;
                    const ctx = ocb_mod.AesOcb128.init(key[0..16].*);
                    ctx.encrypt(ciphertext, &tag, plaintext, nonce, ad);
                },
                .aes256 => {
                    if (key.len != 32) return AeadError.KeySizeMismatch;
                    const ctx = ocb_mod.AesOcb256.init(key[0..32].*);
                    ctx.encrypt(ciphertext, &tag, plaintext, nonce, ad);
                },
                else => return AeadError.UnsupportedSymmetricAlgorithm,
            }
        },
        .gcm => {
            switch (sym_algo) {
                .aes128 => {
                    if (key.len != 16) return AeadError.KeySizeMismatch;
                    const ctx = gcm_mod.AesGcm128.init(key[0..16].*);
                    ctx.encrypt(ciphertext, &tag, plaintext, nonce, ad);
                },
                .aes256 => {
                    if (key.len != 32) return AeadError.KeySizeMismatch;
                    const ctx = gcm_mod.AesGcm256.init(key[0..32].*);
                    ctx.encrypt(ciphertext, &tag, plaintext, nonce, ad);
                },
                else => return AeadError.UnsupportedSymmetricAlgorithm,
            }
        },
        _ => return AeadError.UnsupportedAlgorithm,
    }

    return .{ .ciphertext = ciphertext, .tag = tag };
}

/// Decrypt with AEAD, dispatching to the correct algorithm.
pub fn aeadDecrypt(
    allocator: Allocator,
    sym_algo: SymmetricAlgorithm,
    aead_algo: AeadAlgorithm,
    key: []const u8,
    nonce: []const u8,
    ciphertext: []const u8,
    tag: []const u8,
    ad: []const u8,
) AeadError![]u8 {
    const expected_nonce_size = aead_algo.nonceSize() orelse return AeadError.UnsupportedAlgorithm;
    if (nonce.len != expected_nonce_size) return AeadError.NonceSizeMismatch;
    if (tag.len != 16) return AeadError.AuthenticationFailed;

    const plaintext = allocator.alloc(u8, ciphertext.len) catch return AeadError.OutOfMemory;

    var tag_arr: [16]u8 = undefined;
    @memcpy(&tag_arr, tag[0..16]);

    const decrypt_err: ?AeadError = switch (aead_algo) {
        .eax => switch (sym_algo) {
            .aes128 => blk: {
                if (key.len != 16) break :blk AeadError.KeySizeMismatch;
                const ctx = eax_mod.AesEax128.init(key[0..16].*);
                break :blk if (ctx.decrypt(plaintext, ciphertext, tag_arr, nonce, ad)) null else |_| AeadError.AuthenticationFailed;
            },
            .aes256 => blk: {
                if (key.len != 32) break :blk AeadError.KeySizeMismatch;
                const ctx = eax_mod.AesEax256.init(key[0..32].*);
                break :blk if (ctx.decrypt(plaintext, ciphertext, tag_arr, nonce, ad)) null else |_| AeadError.AuthenticationFailed;
            },
            else => AeadError.UnsupportedSymmetricAlgorithm,
        },
        .ocb => switch (sym_algo) {
            .aes128 => blk: {
                if (key.len != 16) break :blk AeadError.KeySizeMismatch;
                const ctx = ocb_mod.AesOcb128.init(key[0..16].*);
                break :blk if (ctx.decrypt(plaintext, ciphertext, tag_arr, nonce, ad)) null else |_| AeadError.AuthenticationFailed;
            },
            .aes256 => blk: {
                if (key.len != 32) break :blk AeadError.KeySizeMismatch;
                const ctx = ocb_mod.AesOcb256.init(key[0..32].*);
                break :blk if (ctx.decrypt(plaintext, ciphertext, tag_arr, nonce, ad)) null else |_| AeadError.AuthenticationFailed;
            },
            else => AeadError.UnsupportedSymmetricAlgorithm,
        },
        .gcm => switch (sym_algo) {
            .aes128 => blk: {
                if (key.len != 16) break :blk AeadError.KeySizeMismatch;
                const ctx = gcm_mod.AesGcm128.init(key[0..16].*);
                break :blk if (ctx.decrypt(plaintext, ciphertext, tag_arr, nonce, ad)) null else |_| AeadError.AuthenticationFailed;
            },
            .aes256 => blk: {
                if (key.len != 32) break :blk AeadError.KeySizeMismatch;
                const ctx = gcm_mod.AesGcm256.init(key[0..32].*);
                break :blk if (ctx.decrypt(plaintext, ciphertext, tag_arr, nonce, ad)) null else |_| AeadError.AuthenticationFailed;
            },
            else => AeadError.UnsupportedSymmetricAlgorithm,
        },
        _ => AeadError.UnsupportedAlgorithm,
    };

    if (decrypt_err) |err| {
        allocator.free(plaintext);
        return err;
    }

    return plaintext;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "AeadAlgorithm properties" {
    try std.testing.expectEqualStrings("EAX", AeadAlgorithm.eax.name());
    try std.testing.expectEqualStrings("OCB", AeadAlgorithm.ocb.name());
    try std.testing.expectEqualStrings("GCM", AeadAlgorithm.gcm.name());

    try std.testing.expectEqual(@as(usize, 16), AeadAlgorithm.eax.tagSize().?);
    try std.testing.expectEqual(@as(usize, 16), AeadAlgorithm.ocb.tagSize().?);
    try std.testing.expectEqual(@as(usize, 16), AeadAlgorithm.gcm.tagSize().?);

    try std.testing.expectEqual(@as(usize, 16), AeadAlgorithm.eax.nonceSize().?);
    try std.testing.expectEqual(@as(usize, 15), AeadAlgorithm.ocb.nonceSize().?);
    try std.testing.expectEqual(@as(usize, 12), AeadAlgorithm.gcm.nonceSize().?);
}

test "AeadAlgorithm unknown" {
    const unknown: AeadAlgorithm = @enumFromInt(99);
    try std.testing.expectEqualStrings("Unknown", unknown.name());
    try std.testing.expect(unknown.tagSize() == null);
    try std.testing.expect(unknown.nonceSize() == null);
}

test "AeadAlgorithm integer round-trip" {
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(AeadAlgorithm.eax));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(AeadAlgorithm.ocb));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(AeadAlgorithm.gcm));
    try std.testing.expectEqual(AeadAlgorithm.eax, @as(AeadAlgorithm, @enumFromInt(1)));
}

test "aeadEncrypt/aeadDecrypt EAX AES-128 round-trip" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const nonce = [_]u8{0x33} ** 16;
    const plaintext = "Hello, AEAD dispatch!";
    const ad = "associated data";

    const result = try aeadEncrypt(allocator, .aes128, .eax, &key, &nonce, plaintext, ad);
    defer result.deinit(allocator);

    const decrypted = try aeadDecrypt(allocator, .aes128, .eax, &key, &nonce, result.ciphertext, &result.tag, ad);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "aeadEncrypt/aeadDecrypt GCM AES-256 round-trip" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0xAB} ** 32;
    const nonce = [_]u8{0xCD} ** 12;
    const plaintext = "GCM dispatch test";
    const ad = "";

    const result = try aeadEncrypt(allocator, .aes256, .gcm, &key, &nonce, plaintext, ad);
    defer result.deinit(allocator);

    const decrypted = try aeadDecrypt(allocator, .aes256, .gcm, &key, &nonce, result.ciphertext, &result.tag, ad);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "aeadEncrypt/aeadDecrypt OCB AES-128 round-trip" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x77} ** 16;
    const nonce = [_]u8{0x88} ** 15;
    const plaintext = "OCB dispatch test data";
    const ad = "header info";

    const result = try aeadEncrypt(allocator, .aes128, .ocb, &key, &nonce, plaintext, ad);
    defer result.deinit(allocator);

    const decrypted = try aeadDecrypt(allocator, .aes128, .ocb, &key, &nonce, result.ciphertext, &result.tag, ad);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "aeadDecrypt wrong key fails" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const wrong_key = [_]u8{0x99} ** 16;
    const nonce = [_]u8{0x33} ** 16;
    const plaintext = "secret";
    const ad = "";

    const result = try aeadEncrypt(allocator, .aes128, .eax, &key, &nonce, plaintext, ad);
    defer result.deinit(allocator);

    const decrypt_result = aeadDecrypt(allocator, .aes128, .eax, &wrong_key, &nonce, result.ciphertext, &result.tag, ad);
    try std.testing.expectError(AeadError.AuthenticationFailed, decrypt_result);
}

test "aeadEncrypt unsupported algorithm" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const nonce = [_]u8{0x33} ** 16;

    const unknown_aead: AeadAlgorithm = @enumFromInt(99);
    const result = aeadEncrypt(allocator, .aes128, unknown_aead, &key, &nonce, "test", "");
    try std.testing.expectError(AeadError.UnsupportedAlgorithm, result);
}

test "aeadEncrypt unsupported symmetric algorithm" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const nonce = [_]u8{0x33} ** 16;

    const result = aeadEncrypt(allocator, .cast5, .eax, &key, &nonce, "test", "");
    try std.testing.expectError(AeadError.UnsupportedSymmetricAlgorithm, result);
}

test "aeadEncrypt key size mismatch" {
    const allocator = std.testing.allocator;
    const short_key = [_]u8{0x42} ** 8;
    const nonce = [_]u8{0x33} ** 16;

    const result = aeadEncrypt(allocator, .aes128, .eax, &short_key, &nonce, "test", "");
    try std.testing.expectError(AeadError.KeySizeMismatch, result);
}

test "aeadEncrypt nonce size mismatch" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const wrong_nonce = [_]u8{0x33} ** 8;

    const result = aeadEncrypt(allocator, .aes128, .eax, &key, &wrong_nonce, "test", "");
    try std.testing.expectError(AeadError.NonceSizeMismatch, result);
}
