// SPDX-License-Identifier: MIT
//! PEM-like format utilities (generalization of ASCII Armor).
//!
//! PEM (Privacy Enhanced Mail) encoding wraps binary data in a text format
//! delimited by header/footer lines. While OpenPGP ASCII Armor is the
//! primary format (see armor.zig), this module provides a more general
//! PEM block parser that can handle arbitrary labels and optional headers.
//!
//! PEM format:
//!   -----BEGIN <label>-----
//!   [Header: Value]
//!   [Header: Value]
//!                           <- blank line separates headers from body
//!   <base64 encoded data>
//!   -----END <label>-----
//!
//! This is useful for interoperating with systems that use X.509/PKCS
//! formats or other PEM-encoded data alongside OpenPGP.

const std = @import("std");
const mem = std.mem;
const base64 = std.base64;
const Allocator = mem.Allocator;

pub const PemError = error{
    InvalidPem,
    MismatchedLabels,
    InvalidBase64,
    OutOfMemory,
};

/// A key-value header within a PEM block.
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// A single parsed PEM block.
pub const PemBlock = struct {
    /// The label from the BEGIN/END lines (e.g., "RSA PRIVATE KEY").
    label: []const u8,
    /// Optional headers between the BEGIN line and the base64 body.
    headers: []Header,
    /// The decoded binary data.
    data: []u8,

    /// Free all memory owned by this PemBlock.
    pub fn deinit(self: PemBlock, allocator: Allocator) void {
        allocator.free(self.label);
        for (self.headers) |hdr| {
            allocator.free(hdr.name);
            allocator.free(hdr.value);
        }
        allocator.free(self.headers);
        allocator.free(self.data);
    }
};

/// Parse all PEM blocks from the input text.
///
/// Returns a slice of PemBlock structures. Multiple blocks may be present
/// in a single input (e.g., a certificate chain). Caller must call
/// `deinit` on each PemBlock and free the returned slice.
pub fn parsePemBlocks(allocator: Allocator, text: []const u8) PemError![]PemBlock {
    var blocks: std.ArrayList(PemBlock) = .empty;
    errdefer {
        for (blocks.items) |blk| blk.deinit(allocator);
        blocks.deinit(allocator);
    }

    var pos: usize = 0;
    while (pos < text.len) {
        // Find the next BEGIN line
        const begin_marker = "-----BEGIN ";
        const begin_idx = mem.indexOfPos(u8, text, pos, begin_marker) orelse break;
        const label_start = begin_idx + begin_marker.len;
        const label_end_marker = "-----";

        const label_end = mem.indexOfPos(u8, text, label_start, label_end_marker) orelse
            return error.InvalidPem;
        const label = allocator.dupe(u8, text[label_start..label_end]) catch
            return error.OutOfMemory;
        errdefer allocator.free(label);

        // Move past the BEGIN line
        const line_end = mem.indexOfPos(u8, text, label_end + label_end_marker.len, "\n") orelse text.len;
        var cursor = line_end + 1;

        // Parse optional headers (key: value lines before the blank line)
        var headers: std.ArrayList(Header) = .empty;
        errdefer {
            for (headers.items) |hdr| {
                allocator.free(hdr.name);
                allocator.free(hdr.value);
            }
            headers.deinit(allocator);
        }

        while (cursor < text.len) {
            const next_newline = mem.indexOfPos(u8, text, cursor, "\n") orelse text.len;
            const line = mem.trimRight(u8, text[cursor..next_newline], "\r");

            if (line.len == 0) {
                // Blank line separates headers from body
                cursor = next_newline + 1;
                break;
            }

            // Check if this is a header (contains ": ")
            if (mem.indexOf(u8, line, ": ")) |colon_pos| {
                // Could also be base64 data that happens to contain ": " -
                // but per PEM convention, headers come before the blank line.
                // If the line starts with "-----END", it's not a header.
                if (mem.startsWith(u8, line, "-----END")) break;

                const hdr_name = allocator.dupe(u8, line[0..colon_pos]) catch
                    return error.OutOfMemory;
                errdefer allocator.free(hdr_name);
                const hdr_value = allocator.dupe(u8, line[colon_pos + 2 ..]) catch
                    return error.OutOfMemory;

                headers.append(allocator, .{ .name = hdr_name, .value = hdr_value }) catch
                    return error.OutOfMemory;
                cursor = next_newline + 1;
            } else {
                // Not a header line - this is the start of the base64 body
                // (no blank line separator before the body)
                break;
            }
        }

        // Collect base64 body lines until END marker
        const end_marker_full = buildEndMarker(allocator, text[label_start..label_end]) catch
            return error.OutOfMemory;
        defer allocator.free(end_marker_full);

        var b64_data: std.ArrayList(u8) = .empty;
        defer b64_data.deinit(allocator);

        while (cursor < text.len) {
            const next_newline = mem.indexOfPos(u8, text, cursor, "\n") orelse text.len;
            const line = mem.trimRight(u8, text[cursor..next_newline], "\r");
            cursor = next_newline + 1;

            if (mem.startsWith(u8, line, "-----END ")) {
                // Verify the label matches
                const end_label_start = "-----END ".len;
                const end_label_end = mem.indexOf(u8, line[end_label_start..], "-----");
                if (end_label_end) |el_end| {
                    const end_label = line[end_label_start .. end_label_start + el_end];
                    if (!mem.eql(u8, end_label, text[label_start..label_end])) {
                        return error.MismatchedLabels;
                    }
                }
                break;
            }

            // Skip empty lines in the body
            if (line.len == 0) continue;

            // Accumulate base64 characters (skip whitespace)
            for (line) |c| {
                if (c != ' ' and c != '\t') {
                    b64_data.append(allocator, c) catch return error.OutOfMemory;
                }
            }
        }

        // Decode the base64 data
        const decoded = decodeBase64(allocator, b64_data.items) catch
            return error.InvalidBase64;

        const owned_headers = headers.toOwnedSlice(allocator) catch return error.OutOfMemory;
        // Prevent the errdefer from freeing these since we transferred ownership
        headers = .empty;

        blocks.append(allocator, .{
            .label = label,
            .headers = owned_headers,
            .data = decoded,
        }) catch return error.OutOfMemory;

        pos = cursor;
    }

    return blocks.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Encode binary data into a PEM block.
///
/// Creates a PEM block with the given label and data, using 76-character
/// base64 lines. No headers are included.
///
/// Returns a newly allocated string. Caller owns the memory.
pub fn encodePemBlock(allocator: Allocator, label: []const u8, data: []const u8) PemError![]u8 {
    return encodePemBlockWithHeaders(allocator, label, data, &[_]Header{});
}

/// Encode binary data into a PEM block with optional headers.
///
/// Returns a newly allocated string. Caller owns the memory.
pub fn encodePemBlockWithHeaders(
    allocator: Allocator,
    label: []const u8,
    data: []const u8,
    headers: []const Header,
) PemError![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // BEGIN line
    output.appendSlice(allocator, "-----BEGIN ") catch return error.OutOfMemory;
    output.appendSlice(allocator, label) catch return error.OutOfMemory;
    output.appendSlice(allocator, "-----\n") catch return error.OutOfMemory;

    // Headers
    for (headers) |hdr| {
        output.appendSlice(allocator, hdr.name) catch return error.OutOfMemory;
        output.appendSlice(allocator, ": ") catch return error.OutOfMemory;
        output.appendSlice(allocator, hdr.value) catch return error.OutOfMemory;
        output.append(allocator, '\n') catch return error.OutOfMemory;
    }

    // Blank line if headers were present
    if (headers.len > 0) {
        output.append(allocator, '\n') catch return error.OutOfMemory;
    }

    // Base64-encoded body (76-char lines)
    if (data.len > 0) {
        const encoder = base64.standard.Encoder;
        const b64_len = encoder.calcSize(data.len);
        const b64_buf = allocator.alloc(u8, b64_len) catch return error.OutOfMemory;
        defer allocator.free(b64_buf);
        const b64_data = encoder.encode(b64_buf, data);

        const line_width: usize = 76;
        var offset: usize = 0;
        while (offset < b64_data.len) {
            const remaining = b64_data.len - offset;
            const chunk = @min(remaining, line_width);
            output.appendSlice(allocator, b64_data[offset .. offset + chunk]) catch
                return error.OutOfMemory;
            output.append(allocator, '\n') catch return error.OutOfMemory;
            offset += chunk;
        }
    }

    // END line
    output.appendSlice(allocator, "-----END ") catch return error.OutOfMemory;
    output.appendSlice(allocator, label) catch return error.OutOfMemory;
    output.appendSlice(allocator, "-----\n") catch return error.OutOfMemory;

    return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn buildEndMarker(allocator: Allocator, label: []const u8) ![]u8 {
    const total = "-----END ".len + label.len + "-----".len;
    const buf = try allocator.alloc(u8, total);
    var offset: usize = 0;
    @memcpy(buf[offset .. offset + "-----END ".len], "-----END ");
    offset += "-----END ".len;
    @memcpy(buf[offset .. offset + label.len], label);
    offset += label.len;
    @memcpy(buf[offset .. offset + "-----".len], "-----");
    return buf;
}

fn decodeBase64(allocator: Allocator, b64: []const u8) ![]u8 {
    if (b64.len == 0) {
        return try allocator.alloc(u8, 0);
    }
    const decoder = base64.standard.Decoder;
    const decoded_len = decoder.calcSizeForSlice(b64) catch return error.InvalidBase64;
    const result = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(result);
    decoder.decode(result, b64) catch return error.InvalidBase64;
    return result;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "encodePemBlock and parsePemBlocks round-trip" {
    const allocator = std.testing.allocator;
    const data = "Hello, PEM world!";
    const encoded = try encodePemBlock(allocator, "TEST DATA", data);
    defer allocator.free(encoded);

    // Verify the BEGIN/END markers are present
    try std.testing.expect(mem.startsWith(u8, encoded, "-----BEGIN TEST DATA-----\n"));
    try std.testing.expect(mem.endsWith(u8, encoded, "-----END TEST DATA-----\n"));

    // Parse it back
    const blocks = try parsePemBlocks(allocator, encoded);
    defer {
        for (blocks) |blk| blk.deinit(allocator);
        allocator.free(blocks);
    }

    try std.testing.expectEqual(@as(usize, 1), blocks.len);
    try std.testing.expectEqualStrings("TEST DATA", blocks[0].label);
    try std.testing.expectEqualStrings(data, blocks[0].data);
}

test "parsePemBlocks with headers" {
    const allocator = std.testing.allocator;
    const pem_text =
        \\-----BEGIN CERTIFICATE-----
        \\Version: 1
        \\Comment: test
        \\
        \\SGVsbG8=
        \\-----END CERTIFICATE-----
        \\
    ;

    const blocks = try parsePemBlocks(allocator, pem_text);
    defer {
        for (blocks) |blk| blk.deinit(allocator);
        allocator.free(blocks);
    }

    try std.testing.expectEqual(@as(usize, 1), blocks.len);
    try std.testing.expectEqualStrings("CERTIFICATE", blocks[0].label);
    try std.testing.expectEqual(@as(usize, 2), blocks[0].headers.len);
    try std.testing.expectEqualStrings("Version", blocks[0].headers[0].name);
    try std.testing.expectEqualStrings("1", blocks[0].headers[0].value);
    try std.testing.expectEqualStrings("Hello", blocks[0].data);
}

test "parsePemBlocks multiple blocks" {
    const allocator = std.testing.allocator;
    const pem_text =
        \\-----BEGIN BLOCK A-----
        \\AQID
        \\-----END BLOCK A-----
        \\-----BEGIN BLOCK B-----
        \\BAUG
        \\-----END BLOCK B-----
        \\
    ;

    const blocks = try parsePemBlocks(allocator, pem_text);
    defer {
        for (blocks) |blk| blk.deinit(allocator);
        allocator.free(blocks);
    }

    try std.testing.expectEqual(@as(usize, 2), blocks.len);
    try std.testing.expectEqualStrings("BLOCK A", blocks[0].label);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3 }, blocks[0].data);
    try std.testing.expectEqualStrings("BLOCK B", blocks[1].label);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 4, 5, 6 }, blocks[1].data);
}

test "parsePemBlocks empty input" {
    const allocator = std.testing.allocator;
    const blocks = try parsePemBlocks(allocator, "no PEM data here");
    defer allocator.free(blocks);
    try std.testing.expectEqual(@as(usize, 0), blocks.len);
}

test "encodePemBlockWithHeaders" {
    const allocator = std.testing.allocator;
    const hdrs = [_]Header{
        .{ .name = "Version", .value = "zpgp 0.1" },
    };
    const encoded = try encodePemBlockWithHeaders(allocator, "PGP MESSAGE", "test", &hdrs);
    defer allocator.free(encoded);
    try std.testing.expect(mem.indexOf(u8, encoded, "Version: zpgp 0.1\n") != null);
}
