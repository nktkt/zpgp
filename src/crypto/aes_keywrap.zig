// SPDX-License-Identifier: MIT
//! AES Key Wrap per RFC 3394.
//!
//! Used in OpenPGP ECDH to wrap/unwrap session keys.
//!
//! The algorithm wraps `n` 64-bit blocks of key data using an AES key
//! encryption key (KEK). The output is `(n+1)` 64-bit blocks.

const std = @import("std");
const aes = std.crypto.core.aes;
const Allocator = std.mem.Allocator;

pub const KeyWrapError = error{
    InvalidInputLength,
    IntegrityCheckFailed,
    OutOfMemory,
};

/// Default IV per RFC 3394 Section 2.2.3.1
const default_iv: [8]u8 = [_]u8{ 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };

/// Wrap key data using AES Key Wrap (RFC 3394).
///
/// `kek` must be 16 or 32 bytes (AES-128 or AES-256).
/// `plaintext` must be a multiple of 8 bytes and at least 16 bytes.
/// Returns the wrapped key (8 bytes longer than the input).
pub fn wrap(kek: []const u8, plaintext: []const u8, allocator: Allocator) ![]u8 {
    if (plaintext.len < 16 or plaintext.len % 8 != 0)
        return KeyWrapError.InvalidInputLength;

    const n = plaintext.len / 8;
    const output = try allocator.alloc(u8, (n + 1) * 8);
    errdefer allocator.free(output);

    // Initialise: A = IV, R[1..n] = plaintext blocks
    var a: [8]u8 = default_iv;
    // R is stored in output[8..] (n blocks of 8 bytes each)
    @memcpy(output[8..][0..plaintext.len], plaintext);

    // Wrap
    if (kek.len == 16) {
        wrapInner(aes.AesEncryptCtx(aes.Aes128), aes.Aes128.initEnc(kek[0..16].*), &a, output[8..], n);
    } else if (kek.len == 32) {
        wrapInner(aes.AesEncryptCtx(aes.Aes256), aes.Aes256.initEnc(kek[0..32].*), &a, output[8..], n);
    } else {
        return KeyWrapError.InvalidInputLength;
    }

    @memcpy(output[0..8], &a);
    return output;
}

fn wrapInner(comptime Ctx: type, ctx: Ctx, a: *[8]u8, r: []u8, n: usize) void {
    var block_in: [16]u8 = undefined;
    var block_out: [16]u8 = undefined;

    var j: usize = 0;
    while (j < 6) : (j += 1) {
        var i: usize = 0;
        while (i < n) : (i += 1) {
            // B = AES(K, A || R[i])
            @memcpy(block_in[0..8], a);
            @memcpy(block_in[8..16], r[i * 8 ..][0..8]);
            ctx.encrypt(&block_out, &block_in);

            // A = MSB(64, B) XOR t, where t = (n*j)+i+1
            const t: u64 = @as(u64, n) * @as(u64, j) + @as(u64, i) + 1;
            const t_bytes = std.mem.toBytes(std.mem.nativeToBig(u64, t));
            @memcpy(a, block_out[0..8]);
            for (a, t_bytes) |*ab, tb| ab.* ^= tb;

            // R[i] = LSB(64, B)
            @memcpy(r[i * 8 ..][0..8], block_out[8..16]);
        }
    }
}

/// Unwrap key data using AES Key Wrap (RFC 3394).
///
/// `kek` must be 16 or 32 bytes (AES-128 or AES-256).
/// `ciphertext` must be a multiple of 8 bytes and at least 24 bytes.
/// Returns the unwrapped key (8 bytes shorter than the input).
pub fn unwrap(kek: []const u8, ciphertext: []const u8, allocator: Allocator) ![]u8 {
    if (ciphertext.len < 24 or ciphertext.len % 8 != 0)
        return KeyWrapError.InvalidInputLength;

    const n = ciphertext.len / 8 - 1;
    const output = try allocator.alloc(u8, n * 8);

    // Initialise: A = C[0], R[i] = C[i]
    var a: [8]u8 = undefined;
    @memcpy(&a, ciphertext[0..8]);
    @memcpy(output[0 .. n * 8], ciphertext[8..][0 .. n * 8]);

    // Unwrap
    if (kek.len == 16) {
        unwrapInner(aes.AesDecryptCtx(aes.Aes128), aes.Aes128.initDec(kek[0..16].*), &a, output, n);
    } else if (kek.len == 32) {
        unwrapInner(aes.AesDecryptCtx(aes.Aes256), aes.Aes256.initDec(kek[0..32].*), &a, output, n);
    } else {
        allocator.free(output);
        return KeyWrapError.InvalidInputLength;
    }

    // Integrity check: A must equal the default IV
    if (!std.mem.eql(u8, &a, &default_iv)) {
        allocator.free(output);
        return KeyWrapError.IntegrityCheckFailed;
    }

    return output;
}

fn unwrapInner(comptime Ctx: type, ctx: Ctx, a: *[8]u8, r: []u8, n: usize) void {
    var block_in: [16]u8 = undefined;
    var block_out: [16]u8 = undefined;

    var j: usize = 6;
    while (j > 0) {
        j -= 1;
        var i: usize = n;
        while (i > 0) {
            i -= 1;
            // t = (n*j)+i+1
            const t: u64 = @as(u64, n) * @as(u64, j) + @as(u64, i) + 1;
            const t_bytes = std.mem.toBytes(std.mem.nativeToBig(u64, t));

            // A = MSB(64, B) XOR t  ->  undo by XOR-ing t first
            var a_xor: [8]u8 = undefined;
            @memcpy(&a_xor, a);
            for (&a_xor, t_bytes) |*ab, tb| ab.* ^= tb;

            // B = AES-1(K, (A XOR t) || R[i])
            @memcpy(block_in[0..8], &a_xor);
            @memcpy(block_in[8..16], r[i * 8 ..][0..8]);
            ctx.decrypt(&block_out, &block_in);

            // A = MSB(64, B)
            @memcpy(a, block_out[0..8]);
            // R[i] = LSB(64, B)
            @memcpy(r[i * 8 ..][0..8], block_out[8..16]);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "AES-128 Key Wrap round-trip" {
    const allocator = std.testing.allocator;

    // KEK from RFC 3394 Section 4.1
    const kek = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };
    const plaintext = [_]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    };

    const wrapped = try wrap(&kek, &plaintext, allocator);
    defer allocator.free(wrapped);

    try std.testing.expectEqual(@as(usize, 24), wrapped.len);

    // RFC 3394 Section 4.1 expected ciphertext
    const expected = [_]u8{
        0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
        0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
        0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
    };
    try std.testing.expectEqualSlices(u8, &expected, wrapped);

    const unwrapped = try unwrap(&kek, wrapped, allocator);
    defer allocator.free(unwrapped);

    try std.testing.expectEqualSlices(u8, &plaintext, unwrapped);
}

test "AES-256 Key Wrap round-trip" {
    const allocator = std.testing.allocator;

    // RFC 3394 Section 4.6: AES-256 KEK wrapping 256-bit key data
    const kek = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    };
    const plaintext = [_]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };

    const wrapped = try wrap(&kek, &plaintext, allocator);
    defer allocator.free(wrapped);

    try std.testing.expectEqual(@as(usize, 40), wrapped.len);

    // RFC 3394 Section 4.6 expected ciphertext
    const expected = [_]u8{
        0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4,
        0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87, 0xF8, 0x26,
        0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26,
        0xCB, 0xC7, 0xF0, 0xE7, 0x1A, 0x99, 0xF4, 0x3B,
        0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21,
    };
    try std.testing.expectEqualSlices(u8, &expected, wrapped);

    const unwrapped = try unwrap(&kek, wrapped, allocator);
    defer allocator.free(unwrapped);

    try std.testing.expectEqualSlices(u8, &plaintext, unwrapped);
}

test "Key Wrap unwrap integrity check" {
    const allocator = std.testing.allocator;

    const kek = [_]u8{0x42} ** 16;
    const plaintext = [_]u8{0xAA} ** 16;

    const wrapped = try wrap(&kek, &plaintext, allocator);
    defer allocator.free(wrapped);

    // Corrupt the wrapped data
    var corrupted: [24]u8 = undefined;
    @memcpy(&corrupted, wrapped);
    corrupted[12] ^= 0xFF;

    try std.testing.expectError(
        KeyWrapError.IntegrityCheckFailed,
        unwrap(&kek, &corrupted, allocator),
    );
}

test "Key Wrap rejects invalid input lengths" {
    const allocator = std.testing.allocator;
    const kek = [_]u8{0} ** 16;

    // Too short
    try std.testing.expectError(KeyWrapError.InvalidInputLength, wrap(&kek, &[_]u8{0} ** 8, allocator));
    // Not a multiple of 8
    try std.testing.expectError(KeyWrapError.InvalidInputLength, wrap(&kek, &[_]u8{0} ** 17, allocator));
    // Invalid KEK length
    try std.testing.expectError(KeyWrapError.InvalidInputLength, wrap(&[_]u8{0} ** 24, &[_]u8{0} ** 16, allocator));
}
