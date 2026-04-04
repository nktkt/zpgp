//! ASCII Armor encoding and decoding per RFC 4880 Section 6.
//!
//! This module implements the OpenPGP ASCII Armor format, which wraps binary
//! PGP data in a base64-encoded text format with header/footer lines and a
//! CRC-24 checksum.

const std = @import("std");
const mem = std.mem;
const base64 = std.base64;
const Allocator = mem.Allocator;
const crc24 = @import("crc24.zig");

/// Maximum number of base64 characters per line in armored output.
const LINE_WIDTH: usize = 76;

/// An armor header key-value pair (e.g., "Version: GnuPG v2").
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// The type of PGP armor block.
pub const ArmorType = enum {
    message,
    public_key,
    private_key,
    signature,

    /// Return the human-readable label for the armor boundary lines.
    pub fn label(self: ArmorType) []const u8 {
        return switch (self) {
            .message => "PGP MESSAGE",
            .public_key => "PGP PUBLIC KEY BLOCK",
            .private_key => "PGP PRIVATE KEY BLOCK",
            .signature => "PGP SIGNATURE",
        };
    }

    /// Parse an armor type from its label string.
    pub fn fromLabel(s: []const u8) ?ArmorType {
        if (mem.eql(u8, s, "PGP MESSAGE")) return .message;
        if (mem.eql(u8, s, "PGP PUBLIC KEY BLOCK")) return .public_key;
        if (mem.eql(u8, s, "PGP PRIVATE KEY BLOCK")) return .private_key;
        if (mem.eql(u8, s, "PGP SIGNATURE")) return .signature;
        return null;
    }
};

/// Result of decoding an armored PGP block.
pub const DecodeResult = struct {
    data: []u8,
    armor_type: ArmorType,
    headers: []Header,
    allocator: Allocator,

    pub fn deinit(self: *DecodeResult) void {
        self.allocator.free(self.data);
        // Free the duplicated header name/value strings.
        for (self.headers) |hdr| {
            self.allocator.free(hdr.name);
            self.allocator.free(hdr.value);
        }
        self.allocator.free(self.headers);
    }
};

pub const ArmorError = error{
    InvalidArmor,
    InvalidCrc,
    MissingCrc,
    InvalidBase64,
    UnsupportedArmorType,
};

/// Encode binary data into ASCII-armored format.
///
/// The output follows RFC 4880 Section 6.2:
///   - Header line: `-----BEGIN <label>-----`
///   - Optional headers (e.g., `Version: zpgp 0.1`)
///   - Blank line separating headers from body
///   - Base64-encoded data in lines of at most 76 characters
///   - CRC-24 checksum line: `=<4 base64 chars>`
///   - Footer line: `-----END <label>-----`
pub fn encode(
    allocator: Allocator,
    data: []const u8,
    armor_type: ArmorType,
    headers: ?[]const Header,
) ![]u8 {
    const lbl = armor_type.label();

    // Compute CRC-24 over the raw binary data.
    const checksum = crc24.compute(data);

    // Base64-encode the data.
    const encoder = base64.standard.Encoder;
    const b64_len = encoder.calcSize(data.len);
    const b64_buf = try allocator.alloc(u8, b64_len);
    defer allocator.free(b64_buf);
    const b64_data = encoder.encode(b64_buf, data);

    // Base64-encode the 3-byte CRC.
    const crc_bytes = [3]u8{
        @intCast((checksum >> 16) & 0xFF),
        @intCast((checksum >> 8) & 0xFF),
        @intCast(checksum & 0xFF),
    };
    var crc_b64: [4]u8 = undefined;
    _ = encoder.encode(&crc_b64, &crc_bytes);

    // Build the output using an ArrayList.
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);

    // Header line.
    try output.appendSlice(allocator, "-----BEGIN ");
    try output.appendSlice(allocator, lbl);
    try output.appendSlice(allocator, "-----\n");

    // Optional headers.
    if (headers) |hdrs| {
        for (hdrs) |hdr| {
            try output.appendSlice(allocator, hdr.name);
            try output.appendSlice(allocator, ": ");
            try output.appendSlice(allocator, hdr.value);
            try output.append(allocator, '\n');
        }
    }

    // Blank line (separates headers from body).
    try output.append(allocator, '\n');

    // Base64 body in lines of at most LINE_WIDTH characters.
    var offset: usize = 0;
    while (offset < b64_data.len) {
        const end = @min(offset + LINE_WIDTH, b64_data.len);
        try output.appendSlice(allocator, b64_data[offset..end]);
        try output.append(allocator, '\n');
        offset = end;
    }

    // CRC line.
    try output.append(allocator, '=');
    try output.appendSlice(allocator, &crc_b64);
    try output.append(allocator, '\n');

    // Footer line.
    try output.appendSlice(allocator, "-----END ");
    try output.appendSlice(allocator, lbl);
    try output.appendSlice(allocator, "-----\n");

    return try output.toOwnedSlice(allocator);
}

/// Decode an ASCII-armored PGP block back to binary data.
///
/// Parses the header/footer boundary lines, extracts optional headers,
/// decodes the base64 body, and validates the CRC-24 checksum.
pub fn decode(allocator: Allocator, armored: []const u8) !DecodeResult {
    // Split the input into lines, stripping \r\n or \n.
    var lines: std.ArrayList([]const u8) = .empty;
    defer lines.deinit(allocator);

    var line_iter = mem.splitSequence(u8, armored, "\n");
    while (line_iter.next()) |raw_line| {
        // Strip trailing \r if present (for \r\n line endings).
        const line = if (raw_line.len > 0 and raw_line[raw_line.len - 1] == '\r')
            raw_line[0 .. raw_line.len - 1]
        else
            raw_line;
        try lines.append(allocator, line);
    }

    const all_lines = lines.items;
    if (all_lines.len < 3) return ArmorError.InvalidArmor;

    // Find the BEGIN line.
    var begin_idx: ?usize = null;
    for (all_lines, 0..) |line, i| {
        if (mem.startsWith(u8, line, "-----BEGIN ") and mem.endsWith(u8, line, "-----")) {
            begin_idx = i;
            break;
        }
    }
    const begin = begin_idx orelse return ArmorError.InvalidArmor;

    // Extract armor type from the BEGIN line.
    const begin_line = all_lines[begin];
    const label_start = "-----BEGIN ".len;
    const label_end = begin_line.len - "-----".len;
    if (label_start >= label_end) return ArmorError.InvalidArmor;
    const label_str = begin_line[label_start..label_end];
    const armor_type = ArmorType.fromLabel(label_str) orelse return ArmorError.UnsupportedArmorType;

    // Find the END line.
    var end_idx: ?usize = null;
    const expected_end_prefix = "-----END ";
    for (all_lines[begin + 1 ..], begin + 1..) |line, i| {
        if (mem.startsWith(u8, line, expected_end_prefix) and mem.endsWith(u8, line, "-----")) {
            end_idx = i;
            break;
        }
    }
    const end = end_idx orelse return ArmorError.InvalidArmor;

    // The content is between begin+1 and end-1 (inclusive).
    if (end <= begin + 1) return ArmorError.InvalidArmor;
    const content_lines = all_lines[begin + 1 .. end];

    // Parse optional headers: lines before the first blank line.
    var header_list: std.ArrayList(Header) = .empty;
    defer {
        // Only free on error path -- on success, ownership is transferred.
        // We use errdefer-like logic by checking if we already returned.
    }
    var body_start: usize = 0;
    for (content_lines, 0..) |line, i| {
        if (line.len == 0) {
            // Blank line: end of headers.
            body_start = i + 1;
            break;
        }
        // Parse "Name: Value" header.
        if (mem.indexOf(u8, line, ": ")) |colon_pos| {
            const name = try allocator.dupe(u8, line[0..colon_pos]);
            errdefer allocator.free(name);
            const value = try allocator.dupe(u8, line[colon_pos + 2 ..]);
            errdefer allocator.free(value);
            try header_list.append(allocator, .{ .name = name, .value = value });
        } else {
            // No colon found and not blank -- might be start of body (no headers).
            body_start = 0;
            break;
        }
    } else {
        // No blank line found -- treat everything as body with no headers.
        body_start = 0;
    }

    // Error cleanup for headers on failure.
    errdefer {
        for (header_list.items) |hdr| {
            allocator.free(hdr.name);
            allocator.free(hdr.value);
        }
        header_list.deinit(allocator);
    }

    const body_lines = content_lines[body_start..];

    // The last body line before the END should be the CRC line (=XXXX).
    if (body_lines.len == 0) return ArmorError.InvalidArmor;

    // Find the CRC line -- it starts with '=' and is exactly 5 characters.
    var crc_line_idx: ?usize = null;
    for (0..body_lines.len) |i| {
        const ri = body_lines.len - 1 - i;
        const line = body_lines[ri];
        if (line.len == 0) continue; // skip trailing empty lines
        if (line.len == 5 and line[0] == '=') {
            crc_line_idx = ri;
            break;
        }
        // If we hit a non-empty, non-CRC line, CRC might be missing.
        // Some implementations omit CRC; for now we require it per spec.
        return ArmorError.MissingCrc;
    }
    const crc_idx = crc_line_idx orelse return ArmorError.MissingCrc;

    // Decode the CRC value.
    const crc_b64 = body_lines[crc_idx][1..5];
    var crc_raw: [3]u8 = undefined;
    base64.standard.Decoder.decode(&crc_raw, crc_b64) catch return ArmorError.InvalidCrc;
    const expected_crc: u24 = @as(u24, crc_raw[0]) << 16 | @as(u24, crc_raw[1]) << 8 | @as(u24, crc_raw[2]);

    // Concatenate all base64 body lines (excluding the CRC line).
    var b64_body: std.ArrayList(u8) = .empty;
    defer b64_body.deinit(allocator);

    for (body_lines[0..crc_idx]) |line| {
        if (line.len == 0) continue;
        try b64_body.appendSlice(allocator, line);
    }

    // Decode base64.
    const b64_slice = b64_body.items;
    const decoded_size = base64.standard.Decoder.calcSizeForSlice(b64_slice) catch return ArmorError.InvalidBase64;
    const decoded_buf = try allocator.alloc(u8, decoded_size);
    errdefer allocator.free(decoded_buf);
    base64.standard.Decoder.decode(decoded_buf, b64_slice) catch return ArmorError.InvalidBase64;

    // Validate CRC-24.
    const actual_crc = crc24.compute(decoded_buf);
    if (actual_crc != expected_crc) return ArmorError.InvalidCrc;

    const owned_headers = try header_list.toOwnedSlice(allocator);

    return DecodeResult{
        .data = decoded_buf,
        .armor_type = armor_type,
        .headers = owned_headers,
        .allocator = allocator,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ArmorType label round-trip" {
    const types = [_]ArmorType{ .message, .public_key, .private_key, .signature };
    for (types) |at| {
        const lbl = at.label();
        const parsed = ArmorType.fromLabel(lbl);
        try std.testing.expectEqual(at, parsed.?);
    }
}

test "ArmorType fromLabel returns null for unknown" {
    try std.testing.expect(ArmorType.fromLabel("UNKNOWN") == null);
}

test "encode then decode round-trip" {
    const allocator = std.testing.allocator;

    // Arbitrary binary test data.
    const data = "Hello, OpenPGP world! This is a test of ASCII Armor encoding.\x00\x01\x02\xFF";

    const armored = try encode(allocator, data, .public_key, null);
    defer allocator.free(armored);

    var result = try decode(allocator, armored);
    defer result.deinit();

    try std.testing.expectEqualSlices(u8, data, result.data);
    try std.testing.expectEqual(ArmorType.public_key, result.armor_type);
    try std.testing.expectEqual(@as(usize, 0), result.headers.len);
}

test "encode then decode round-trip with headers" {
    const allocator = std.testing.allocator;

    const data = "Test message data for armor encoding";
    const headers = [_]Header{
        .{ .name = "Version", .value = "zpgp 0.1" },
        .{ .name = "Comment", .value = "Test key" },
    };

    const armored = try encode(allocator, data, .message, &headers);
    defer allocator.free(armored);

    // Verify the armored text contains expected elements.
    try std.testing.expect(mem.indexOf(u8, armored, "-----BEGIN PGP MESSAGE-----") != null);
    try std.testing.expect(mem.indexOf(u8, armored, "-----END PGP MESSAGE-----") != null);
    try std.testing.expect(mem.indexOf(u8, armored, "Version: zpgp 0.1") != null);
    try std.testing.expect(mem.indexOf(u8, armored, "Comment: Test key") != null);

    var result = try decode(allocator, armored);
    defer result.deinit();

    try std.testing.expectEqualSlices(u8, data, result.data);
    try std.testing.expectEqual(ArmorType.message, result.armor_type);
    try std.testing.expectEqual(@as(usize, 2), result.headers.len);
    try std.testing.expectEqualSlices(u8, "Version", result.headers[0].name);
    try std.testing.expectEqualSlices(u8, "zpgp 0.1", result.headers[0].value);
    try std.testing.expectEqualSlices(u8, "Comment", result.headers[1].name);
    try std.testing.expectEqualSlices(u8, "Test key", result.headers[1].value);
}

test "CRC-24 validation detects corruption" {
    const allocator = std.testing.allocator;

    const data = "Integrity check test data";
    const armored_buf = try encode(allocator, data, .signature, null);
    defer allocator.free(armored_buf);

    // Corrupt one character in the base64 body (not the header/footer/CRC).
    // Find the blank line that separates headers from body, then corrupt body.
    const armored = try allocator.dupe(u8, armored_buf);
    defer allocator.free(armored);

    // Find the base64 body start (after double newline).
    if (mem.indexOf(u8, armored, "\n\n")) |blank_pos| {
        const body_start = blank_pos + 2;
        // Flip a character in the body if it's a valid base64 char.
        if (body_start < armored.len - 20) {
            // Change character to a different valid base64 character.
            armored[body_start] = if (armored[body_start] == 'A') 'B' else 'A';
        }
    }

    const result = decode(allocator, armored);
    // Should fail with CRC error or base64 error.
    try std.testing.expect(result == ArmorError.InvalidCrc or
        result == ArmorError.InvalidBase64 or
        result == ArmorError.MissingCrc);
}

test "encode produces correct line width" {
    const allocator = std.testing.allocator;

    // Use enough data to produce multiple base64 lines.
    const data = "A" ** 200;

    const armored = try encode(allocator, data, .public_key, null);
    defer allocator.free(armored);

    // Check that no base64 body line exceeds LINE_WIDTH characters.
    var in_body = false;
    var line_iter = mem.splitSequence(u8, armored, "\n");
    while (line_iter.next()) |line| {
        if (line.len == 0 and !in_body) {
            in_body = true;
            continue;
        }
        if (in_body) {
            if (mem.startsWith(u8, line, "=") or mem.startsWith(u8, line, "-----END")) break;
            try std.testing.expect(line.len <= LINE_WIDTH);
        }
    }
}

test "decode all armor types" {
    const allocator = std.testing.allocator;
    const data = "test";

    const types = [_]ArmorType{ .message, .public_key, .private_key, .signature };
    for (types) |at| {
        const armored = try encode(allocator, data, at, null);
        defer allocator.free(armored);

        var result = try decode(allocator, armored);
        defer result.deinit();

        try std.testing.expectEqual(at, result.armor_type);
        try std.testing.expectEqualSlices(u8, data, result.data);
    }
}

test "decode with Version header" {
    const allocator = std.testing.allocator;

    // Manually construct an armored block with a Version header.
    const data = "Hello PGP";
    const headers = [_]Header{
        .{ .name = "Version", .value = "zpgp 0.1" },
    };

    const armored = try encode(allocator, data, .public_key, &headers);
    defer allocator.free(armored);

    var result = try decode(allocator, armored);
    defer result.deinit();

    try std.testing.expectEqualSlices(u8, data, result.data);
    try std.testing.expectEqual(@as(usize, 1), result.headers.len);
    try std.testing.expectEqualSlices(u8, "Version", result.headers[0].name);
    try std.testing.expectEqualSlices(u8, "zpgp 0.1", result.headers[0].value);
}

test "encode empty data" {
    const allocator = std.testing.allocator;

    const armored = try encode(allocator, "", .message, null);
    defer allocator.free(armored);

    var result = try decode(allocator, armored);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.data.len);
    try std.testing.expectEqual(ArmorType.message, result.armor_type);
}
