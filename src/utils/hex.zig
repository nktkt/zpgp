// SPDX-License-Identifier: MIT
//! Hex encoding and decoding utilities for OpenPGP.
//!
//! Provides functions for converting between binary data and hexadecimal
//! string representations. Used throughout the library for formatting
//! key IDs, fingerprints, and other binary identifiers.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Lowercase hex alphabet.
const hex_lower = "0123456789abcdef";
/// Uppercase hex alphabet.
const hex_upper = "0123456789ABCDEF";

pub const HexError = error{
    InvalidHexCharacter,
    InvalidHexLength,
    OutOfMemory,
    BufferTooSmall,
};

/// Encode binary data to a lowercase hex string.
///
/// Returns a newly allocated slice. Caller owns the memory.
///
/// Example: "\xde\xad" -> "dead"
pub fn hexEncode(allocator: Allocator, data: []const u8) HexError![]u8 {
    const buf = allocator.alloc(u8, data.len * 2) catch return error.OutOfMemory;
    formatHexLower(data, buf);
    return buf;
}

/// Encode binary data to an uppercase hex string.
///
/// Returns a newly allocated slice. Caller owns the memory.
///
/// Example: "\xde\xad" -> "DEAD"
pub fn hexEncodeUpper(allocator: Allocator, data: []const u8) HexError![]u8 {
    const buf = allocator.alloc(u8, data.len * 2) catch return error.OutOfMemory;
    formatHexUpper(data, buf);
    return buf;
}

/// Decode a hex string to binary data.
///
/// The input must have an even number of characters and contain only
/// valid hex digits (0-9, a-f, A-F). Whitespace is NOT accepted;
/// use `hexDecodeIgnoringWhitespace` if whitespace may be present.
///
/// Returns a newly allocated slice. Caller owns the memory.
pub fn hexDecode(allocator: Allocator, hex: []const u8) HexError![]u8 {
    if (hex.len % 2 != 0) return error.InvalidHexLength;

    const buf = allocator.alloc(u8, hex.len / 2) catch return error.OutOfMemory;
    errdefer allocator.free(buf);

    for (buf, 0..) |*byte, i| {
        const hi = hexDigitValue(hex[i * 2]) orelse return error.InvalidHexCharacter;
        const lo = hexDigitValue(hex[i * 2 + 1]) orelse return error.InvalidHexCharacter;
        byte.* = (@as(u8, hi) << 4) | @as(u8, lo);
    }

    return buf;
}

/// Decode a hex string, ignoring any whitespace characters.
///
/// Strips spaces, tabs, newlines, and carriage returns before decoding.
/// Useful for parsing user-pasted fingerprints like "DEAD BEEF 1234".
pub fn hexDecodeIgnoringWhitespace(allocator: Allocator, hex: []const u8) HexError![]u8 {
    // First pass: count non-whitespace hex chars
    var count: usize = 0;
    for (hex) |c| {
        if (isWhitespace(c)) continue;
        if (hexDigitValue(c) == null) return error.InvalidHexCharacter;
        count += 1;
    }
    if (count % 2 != 0) return error.InvalidHexLength;

    const buf = allocator.alloc(u8, count / 2) catch return error.OutOfMemory;
    errdefer allocator.free(buf);

    var idx: usize = 0;
    var hi_set = false;
    var hi_val: u4 = 0;
    for (hex) |c| {
        if (isWhitespace(c)) continue;
        const val = hexDigitValue(c).?;
        if (!hi_set) {
            hi_val = val;
            hi_set = true;
        } else {
            buf[idx] = (@as(u8, hi_val) << 4) | @as(u8, val);
            idx += 1;
            hi_set = false;
        }
    }

    return buf;
}

/// Format binary data as lowercase hex into a pre-allocated buffer.
///
/// `buf` must be at least `data.len * 2` bytes long.
/// No allocation is performed.
pub fn formatHexLower(data: []const u8, buf: []u8) void {
    std.debug.assert(buf.len >= data.len * 2);
    for (data, 0..) |byte, i| {
        buf[i * 2] = hex_lower[byte >> 4];
        buf[i * 2 + 1] = hex_lower[byte & 0x0F];
    }
}

/// Format binary data as uppercase hex into a pre-allocated buffer.
///
/// `buf` must be at least `data.len * 2` bytes long.
/// No allocation is performed.
pub fn formatHexUpper(data: []const u8, buf: []u8) void {
    std.debug.assert(buf.len >= data.len * 2);
    for (data, 0..) |byte, i| {
        buf[i * 2] = hex_upper[byte >> 4];
        buf[i * 2 + 1] = hex_upper[byte & 0x0F];
    }
}

/// Legacy alias for formatHexLower, matching the original spec name.
pub fn formatHex(data: []const u8, buf: []u8) void {
    formatHexLower(data, buf);
}

/// Format a fingerprint as a colon-separated hex string.
///
/// Example: {0xDE, 0xAD, 0xBE, 0xEF} -> "DE:AD:BE:EF"
///
/// Returns a newly allocated string. Caller owns the memory.
pub fn formatFingerprint(allocator: Allocator, fp: []const u8) HexError![]u8 {
    if (fp.len == 0) {
        const empty = allocator.alloc(u8, 0) catch return error.OutOfMemory;
        return empty;
    }

    // Each byte becomes "XX:" except the last which is "XX"
    const len = fp.len * 3 - 1;
    const buf = allocator.alloc(u8, len) catch return error.OutOfMemory;

    for (fp, 0..) |byte, i| {
        const offset = i * 3;
        buf[offset] = hex_upper[byte >> 4];
        buf[offset + 1] = hex_upper[byte & 0x0F];
        if (i + 1 < fp.len) {
            buf[offset + 2] = ':';
        }
    }

    return buf;
}

/// Format a fingerprint in the GPG-style grouped format.
///
/// For a 20-byte V4 fingerprint: "XXXX XXXX XXXX XXXX XXXX  XXXX XXXX XXXX XXXX XXXX"
/// (groups of 4, double space in the middle).
///
/// Returns a newly allocated string. Caller owns the memory.
pub fn formatFingerprintGrouped(allocator: Allocator, fp: []const u8) HexError![]u8 {
    if (fp.len == 0) {
        const empty = allocator.alloc(u8, 0) catch return error.OutOfMemory;
        return empty;
    }

    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    for (fp, 0..) |byte, i| {
        output.append(allocator, hex_upper[byte >> 4]) catch return error.OutOfMemory;
        output.append(allocator, hex_upper[byte & 0x0F]) catch return error.OutOfMemory;

        // Add spacing between groups of 2 bytes (4 hex chars)
        if (i + 1 < fp.len and (i + 1) % 2 == 0) {
            if (fp.len == 20 and i + 1 == 10) {
                // Double space in the middle of a V4 fingerprint
                output.appendSlice(allocator, "  ") catch return error.OutOfMemory;
            } else {
                output.append(allocator, ' ') catch return error.OutOfMemory;
            }
        }
    }

    return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Convert a single hex character to its 4-bit value.
/// Returns null for non-hex characters.
fn hexDigitValue(c: u8) ?u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => null,
    };
}

fn isWhitespace(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\n' or c == '\r';
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "hexEncode basic" {
    const allocator = std.testing.allocator;
    const result = try hexEncode(allocator, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF });
    defer allocator.free(result);
    try std.testing.expectEqualStrings("deadbeef", result);
}

test "hexEncodeUpper basic" {
    const allocator = std.testing.allocator;
    const result = try hexEncodeUpper(allocator, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF });
    defer allocator.free(result);
    try std.testing.expectEqualStrings("DEADBEEF", result);
}

test "hexEncode empty" {
    const allocator = std.testing.allocator;
    const result = try hexEncode(allocator, &[_]u8{});
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "hexDecode basic" {
    const allocator = std.testing.allocator;
    const result = try hexDecode(allocator, "deadBEEF");
    defer allocator.free(result);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, result);
}

test "hexDecode empty" {
    const allocator = std.testing.allocator;
    const result = try hexDecode(allocator, "");
    defer allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "hexDecode odd length" {
    const allocator = std.testing.allocator;
    const result = hexDecode(allocator, "abc");
    try std.testing.expectError(error.InvalidHexLength, result);
}

test "hexDecode invalid character" {
    const allocator = std.testing.allocator;
    const result = hexDecode(allocator, "zz");
    try std.testing.expectError(error.InvalidHexCharacter, result);
}

test "hexDecodeIgnoringWhitespace" {
    const allocator = std.testing.allocator;
    const result = try hexDecodeIgnoringWhitespace(allocator, "DE AD\nBE\tEF");
    defer allocator.free(result);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, result);
}

test "formatHex no allocation" {
    var buf: [8]u8 = undefined;
    formatHex(&[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, &buf);
    try std.testing.expectEqualStrings("deadbeef", &buf);
}

test "formatFingerprint" {
    const allocator = std.testing.allocator;
    const result = try formatFingerprint(allocator, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF });
    defer allocator.free(result);
    try std.testing.expectEqualStrings("DE:AD:BE:EF", result);
}

test "formatFingerprintGrouped V4" {
    const allocator = std.testing.allocator;
    var fp: [20]u8 = undefined;
    for (&fp, 0..) |*b, i| b.* = @intCast(i);
    const result = try formatFingerprintGrouped(allocator, &fp);
    defer allocator.free(result);
    // Should have double space in the middle
    try std.testing.expect(mem.indexOf(u8, result, "  ") != null);
}

test "hexEncode/hexDecode round-trip" {
    const allocator = std.testing.allocator;
    const original = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    const encoded = try hexEncode(allocator, &original);
    defer allocator.free(encoded);
    const decoded = try hexDecode(allocator, encoded);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, &original, decoded);
}
