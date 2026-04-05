// SPDX-License-Identifier: MIT
//! Base64 utilities beyond the standard library.
//!
//! The standard `std.base64` module provides basic encode/decode operations.
//! This module adds OpenPGP-specific helpers:
//!   - Multi-line encoding (76-character lines as per RFC 4880 Section 6.3)
//!   - Decoding that ignores embedded whitespace
//!   - Size estimation helpers for pre-allocation

const std = @import("std");
const mem = std.mem;
const base64 = std.base64;
const Allocator = mem.Allocator;

pub const Base64Error = error{
    InvalidBase64,
    OutOfMemory,
};

/// Encode binary data to base64 with line breaks every `line_width` characters.
///
/// The default line width for OpenPGP ASCII Armor is 76 (per RFC 4880 Section
/// 6.3). The output does NOT include a trailing newline after the last line.
///
/// Returns a newly allocated slice. Caller owns the memory.
pub fn encodeMultiLine(allocator: Allocator, data: []const u8, line_width: usize) Base64Error![]u8 {
    if (data.len == 0) {
        const empty = allocator.alloc(u8, 0) catch return error.OutOfMemory;
        return empty;
    }
    if (line_width == 0) return error.InvalidBase64;

    const encoder = base64.standard.Encoder;
    const b64_len = encoder.calcSize(data.len);
    const b64_buf = allocator.alloc(u8, b64_len) catch return error.OutOfMemory;
    defer allocator.free(b64_buf);
    const b64_data = encoder.encode(b64_buf, data);

    // Count how many newlines we need
    const num_full_lines = b64_data.len / line_width;
    const has_remainder = (b64_data.len % line_width) != 0;
    const num_newlines = if (has_remainder) num_full_lines else if (num_full_lines > 0) num_full_lines - 1 else 0;

    const result_len = b64_data.len + num_newlines;
    const result = allocator.alloc(u8, result_len) catch return error.OutOfMemory;
    errdefer allocator.free(result);

    var src_offset: usize = 0;
    var dst_offset: usize = 0;

    while (src_offset < b64_data.len) {
        const remaining = b64_data.len - src_offset;
        const chunk = @min(remaining, line_width);

        @memcpy(result[dst_offset .. dst_offset + chunk], b64_data[src_offset .. src_offset + chunk]);
        dst_offset += chunk;
        src_offset += chunk;

        // Add newline between lines (not after the last line)
        if (src_offset < b64_data.len) {
            result[dst_offset] = '\n';
            dst_offset += 1;
        }
    }

    return result;
}

/// Decode base64 data, ignoring any whitespace characters.
///
/// Strips spaces, tabs, newlines, and carriage returns before decoding.
/// This is useful for parsing ASCII-armored PGP data where the base64
/// content is split across multiple lines.
///
/// Returns a newly allocated slice. Caller owns the memory.
pub fn decodeIgnoringWhitespace(allocator: Allocator, encoded: []const u8) Base64Error![]u8 {
    // First pass: strip whitespace
    var stripped: std.ArrayList(u8) = .empty;
    defer stripped.deinit(allocator);

    for (encoded) |c| {
        if (c == ' ' or c == '\t' or c == '\n' or c == '\r') continue;
        stripped.append(allocator, c) catch return error.OutOfMemory;
    }

    const stripped_slice = stripped.items;
    if (stripped_slice.len == 0) {
        const empty = allocator.alloc(u8, 0) catch return error.OutOfMemory;
        return empty;
    }

    // Decode
    const decoder = base64.standard.Decoder;
    const decoded_len = decoder.calcSizeForSlice(stripped_slice) catch return error.InvalidBase64;
    const result = allocator.alloc(u8, decoded_len) catch return error.OutOfMemory;
    errdefer allocator.free(result);

    decoder.decode(result, stripped_slice) catch return error.InvalidBase64;

    return result;
}

/// Estimate the decoded size from the encoded length.
///
/// This is an upper bound; the actual size may be slightly smaller due to
/// padding. Useful for pre-allocating buffers.
///
/// Formula: decoded_size <= encoded_len * 3 / 4
pub fn estimateDecodedSize(encoded_len: usize) usize {
    if (encoded_len == 0) return 0;
    return (encoded_len * 3) / 4;
}

/// Estimate the encoded size from the raw data length.
///
/// Returns the exact size of the base64 output (including padding).
///
/// Formula: encoded_size = ceil(data_len / 3) * 4
pub fn estimateEncodedSize(data_len: usize) usize {
    if (data_len == 0) return 0;
    return ((data_len + 2) / 3) * 4;
}

/// Estimate the multi-line encoded size including newlines.
///
/// The result includes one newline per line boundary (but not a trailing
/// newline). The `line_width` is the max number of base64 characters per
/// line (typically 76 for OpenPGP).
pub fn estimateMultiLineSize(data_len: usize, line_width: usize) usize {
    if (data_len == 0 or line_width == 0) return 0;
    const b64_len = estimateEncodedSize(data_len);
    const num_full_lines = b64_len / line_width;
    const has_remainder = (b64_len % line_width) != 0;
    const num_newlines = if (has_remainder) num_full_lines else if (num_full_lines > 0) num_full_lines - 1 else 0;
    return b64_len + num_newlines;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "encodeMultiLine basic" {
    const allocator = std.testing.allocator;
    // Short data that fits on one line
    const result = try encodeMultiLine(allocator, "Hello", 76);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("SGVsbG8=", result);
}

test "encodeMultiLine with wrapping" {
    const allocator = std.testing.allocator;
    // Use a very short line width to force wrapping
    const result = try encodeMultiLine(allocator, "Hello, World!", 8);
    defer allocator.free(result);
    // "SGVsbG8s" + "\n" + "IFdvcmxk" + "\n" + "IQ=="
    try std.testing.expect(mem.indexOf(u8, result, "\n") != null);
    // Verify no line exceeds 8 chars
    var iter = mem.splitScalar(u8, result, '\n');
    while (iter.next()) |line| {
        try std.testing.expect(line.len <= 8);
    }
}

test "encodeMultiLine empty" {
    const allocator = std.testing.allocator;
    const result = try encodeMultiLine(allocator, "", 76);
    defer allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "decodeIgnoringWhitespace basic" {
    const allocator = std.testing.allocator;
    const result = try decodeIgnoringWhitespace(allocator, "SGVs\nbG8=\n");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello", result);
}

test "decodeIgnoringWhitespace with tabs and spaces" {
    const allocator = std.testing.allocator;
    const result = try decodeIgnoringWhitespace(allocator, "SG Vs\tbG 8=");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello", result);
}

test "decodeIgnoringWhitespace empty" {
    const allocator = std.testing.allocator;
    const result = try decodeIgnoringWhitespace(allocator, "   \n\t  ");
    defer allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "decodeIgnoringWhitespace invalid" {
    const allocator = std.testing.allocator;
    const result = decodeIgnoringWhitespace(allocator, "!!!!");
    try std.testing.expectError(error.InvalidBase64, result);
}

test "estimateDecodedSize" {
    try std.testing.expectEqual(@as(usize, 0), estimateDecodedSize(0));
    try std.testing.expectEqual(@as(usize, 3), estimateDecodedSize(4));
    try std.testing.expectEqual(@as(usize, 6), estimateDecodedSize(8));
}

test "estimateEncodedSize" {
    try std.testing.expectEqual(@as(usize, 0), estimateEncodedSize(0));
    try std.testing.expectEqual(@as(usize, 4), estimateEncodedSize(1));
    try std.testing.expectEqual(@as(usize, 4), estimateEncodedSize(3));
    try std.testing.expectEqual(@as(usize, 8), estimateEncodedSize(4));
}

test "encode/decode round-trip" {
    const allocator = std.testing.allocator;
    const original = "The quick brown fox jumps over the lazy dog";
    const encoded = try encodeMultiLine(allocator, original, 20);
    defer allocator.free(encoded);
    const decoded = try decodeIgnoringWhitespace(allocator, encoded);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(original, decoded);
}
