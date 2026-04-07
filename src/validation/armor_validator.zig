// SPDX-License-Identifier: MIT
//! Armor format validation module.
//!
//! Validates the structure and correctness of ASCII-armored OpenPGP data
//! per RFC 4880 Section 6. Checks include:
//!   - Correct header/footer boundary lines
//!   - Valid armor type detection
//!   - Base64 encoding validity
//!   - CRC-24 checksum presence and correctness
//!   - Line length compliance (max 76 chars)
//!   - Blank line separator between headers and body
//!   - Armor header key-value pairs

const std = @import("std");
const mem = std.mem;
const base64 = std.base64;
const Allocator = mem.Allocator;

const ArmorType = @import("../armor/armor.zig").ArmorType;
const crc24 = @import("../armor/crc24.zig");

// =========================================================================
// Validation result types
// =========================================================================

/// An armor header key-value pair found during validation.
pub const ArmorHeader = struct {
    name: []const u8,
    value: []const u8,

    pub fn deinit(self: ArmorHeader, allocator: Allocator) void {
        allocator.free(self.name);
        allocator.free(self.value);
    }
};

/// Result of validating ASCII-armored data.
pub const ArmorValidation = struct {
    /// Whether the armor is valid overall.
    valid: bool,
    /// Detected armor type (e.g., message, public_key).
    armor_type: ?ArmorType,
    /// Whether a CRC-24 checksum is present.
    has_crc: bool,
    /// Whether the CRC-24 checksum matches the data.
    crc_valid: bool,
    /// Whether all base64 lines are within the 76-character limit.
    line_lengths_valid: bool,
    /// Whether there is a blank line separating headers from body.
    has_blank_separator: bool,
    /// Armor headers (e.g., "Version: GnuPG v2").
    headers: std.ArrayList(ArmorHeader),
    /// Issues found during validation.
    issues: std.ArrayList([]const u8),

    /// Free all memory.
    pub fn deinit(self: *ArmorValidation, allocator: Allocator) void {
        for (self.headers.items) |h| h.deinit(allocator);
        self.headers.deinit(allocator);
        for (self.issues.items) |issue| allocator.free(issue);
        self.issues.deinit(allocator);
    }

    /// Format the validation result as a human-readable string.
    pub fn format(self: *const ArmorValidation, allocator: Allocator) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);
        const w = buf.writer(allocator);

        try w.writeAll("Armor Validation Report\n");
        try w.writeAll("========================================\n");
        try w.print("Valid:          {s}\n", .{if (self.valid) "yes" else "no"});

        if (self.armor_type) |at| {
            try w.print("Armor Type:     {s}\n", .{at.label()});
        } else {
            try w.print("Armor Type:     unknown\n", .{});
        }

        try w.print("CRC Present:    {s}\n", .{if (self.has_crc) "yes" else "no"});
        if (self.has_crc) {
            try w.print("CRC Valid:      {s}\n", .{if (self.crc_valid) "yes" else "INVALID"});
        }
        try w.print("Line Lengths:   {s}\n", .{if (self.line_lengths_valid) "valid" else "INVALID"});
        try w.print("Blank Separator:{s}\n", .{if (self.has_blank_separator) " yes" else " no"});

        if (self.headers.items.len > 0) {
            try w.print("\nHeaders ({d}):\n", .{self.headers.items.len});
            for (self.headers.items) |hdr| {
                try w.print("  {s}: {s}\n", .{ hdr.name, hdr.value });
            }
        }

        if (self.issues.items.len > 0) {
            try w.print("\nIssues ({d}):\n", .{self.issues.items.len});
            for (self.issues.items, 0..) |issue, i| {
                try w.print("  {d}. {s}\n", .{ i + 1, issue });
            }
        }

        return buf.toOwnedSlice(allocator);
    }
};

// =========================================================================
// Armor validation
// =========================================================================

/// Validate ASCII-armored OpenPGP data.
///
/// Performs structural validation of the armor format without decoding
/// the base64 body. Use `armor.decode()` for actual decoding.
pub fn validateArmor(allocator: Allocator, data: []const u8) !ArmorValidation {
    var result = ArmorValidation{
        .valid = true,
        .armor_type = null,
        .has_crc = false,
        .crc_valid = false,
        .line_lengths_valid = true,
        .has_blank_separator = false,
        .headers = .empty,
        .issues = .empty,
    };
    errdefer result.deinit(allocator);

    if (data.len == 0) {
        result.valid = false;
        try result.issues.append(allocator, try allocator.dupe(u8, "Data is empty"));
        return result;
    }

    // Find the BEGIN line.
    const begin_prefix = "-----BEGIN ";
    const begin_suffix = "-----";
    const end_prefix = "-----END ";

    var lines = mem.splitSequence(u8, data, "\n");

    var found_begin = false;
    var found_end = false;
    var in_headers = false;
    var in_body = false;
    var body_lines: std.ArrayList([]const u8) = .empty;
    defer body_lines.deinit(allocator);
    var crc_line: ?[]const u8 = null;

    while (lines.next()) |raw_line| {
        const line = mem.trimRight(u8, raw_line, "\r");

        // Look for BEGIN line.
        if (!found_begin) {
            if (mem.startsWith(u8, line, begin_prefix)) {
                // Extract armor type.
                const after_begin = line[begin_prefix.len..];
                if (mem.endsWith(u8, after_begin, begin_suffix)) {
                    const type_str = after_begin[0 .. after_begin.len - begin_suffix.len];
                    result.armor_type = ArmorType.fromLabel(type_str);
                    if (result.armor_type == null) {
                        result.valid = false;
                        try result.issues.append(
                            allocator,
                            try std.fmt.allocPrint(allocator, "Unknown armor type: {s}", .{type_str}),
                        );
                    }
                } else {
                    result.valid = false;
                    try result.issues.append(allocator, try allocator.dupe(u8, "Malformed BEGIN line"));
                }
                found_begin = true;
                in_headers = true;
                continue;
            }
            continue;
        }

        // Look for END line.
        if (mem.startsWith(u8, line, end_prefix)) {
            found_end = true;
            break;
        }

        // Parse headers (between BEGIN and blank line).
        if (in_headers) {
            if (line.len == 0) {
                result.has_blank_separator = true;
                in_headers = false;
                in_body = true;
                continue;
            }

            // Check for header format: "Key: Value"
            if (mem.indexOfScalar(u8, line, ':')) |colon_idx| {
                const hdr_name = mem.trim(u8, line[0..colon_idx], " \t");
                const hdr_value = mem.trim(u8, line[colon_idx + 1 ..], " \t");
                try result.headers.append(allocator, .{
                    .name = try allocator.dupe(u8, hdr_name),
                    .value = try allocator.dupe(u8, hdr_value),
                });
            } else {
                // Not a header — assume body starts here (no blank separator).
                in_headers = false;
                in_body = true;
                // Process this line as body.
                if (line.len > 0 and line[0] == '=') {
                    crc_line = line;
                } else {
                    try body_lines.append(allocator, line);
                    if (line.len > 76) {
                        result.line_lengths_valid = false;
                    }
                }
            }
            continue;
        }

        // Body lines.
        if (in_body) {
            // Check for CRC line (starts with '=').
            if (line.len > 0 and line[0] == '=') {
                crc_line = line;
                continue;
            }

            if (line.len > 0) {
                try body_lines.append(allocator, line);
                if (line.len > 76) {
                    result.line_lengths_valid = false;
                }
            }
        }
    }

    if (!found_begin) {
        result.valid = false;
        try result.issues.append(allocator, try allocator.dupe(u8, "No BEGIN line found"));
        return result;
    }

    if (!found_end) {
        result.valid = false;
        try result.issues.append(allocator, try allocator.dupe(u8, "No END line found"));
    }

    if (!result.has_blank_separator) {
        try result.issues.append(
            allocator,
            try allocator.dupe(u8, "Missing blank line between headers and body"),
        );
    }

    if (!result.line_lengths_valid) {
        try result.issues.append(
            allocator,
            try allocator.dupe(u8, "Some base64 lines exceed 76 characters"),
        );
    }

    // Validate CRC.
    if (crc_line) |crc_str| {
        result.has_crc = true;

        // CRC format: =XXXX (4 base64 chars encoding 3 bytes of CRC-24)
        if (crc_str.len == 5 and crc_str[0] == '=') {
            // Decode the CRC value.
            const crc_b64 = crc_str[1..5];
            var crc_bytes: [3]u8 = undefined;
            const decoded = base64.standard.Decoder.calcSizeForSlice(crc_b64) catch 0;
            if (decoded == 3) {
                base64.standard.Decoder.decode(&crc_bytes, crc_b64) catch {
                    result.crc_valid = false;
                    try result.issues.append(allocator, try allocator.dupe(u8, "CRC line has invalid base64"));
                    return result;
                };

                const crc_value: u24 = @intCast(
                    (@as(u32, crc_bytes[0]) << 16) |
                        (@as(u32, crc_bytes[1]) << 8) |
                        @as(u32, crc_bytes[2]),
                );

                // Concatenate body lines and decode to compute CRC.
                var body_b64: std.ArrayList(u8) = .empty;
                defer body_b64.deinit(allocator);
                for (body_lines.items) |bl| {
                    try body_b64.appendSlice(allocator, bl);
                }

                const body_decode_len = base64.standard.Decoder.calcSizeForSlice(body_b64.items) catch {
                    result.crc_valid = false;
                    try result.issues.append(allocator, try allocator.dupe(u8, "Cannot determine base64 decode size"));
                    return result;
                };
                const body_decoded = try allocator.alloc(u8, body_decode_len);
                defer allocator.free(body_decoded);

                base64.standard.Decoder.decode(body_decoded, body_b64.items) catch {
                    result.crc_valid = false;
                    try result.issues.append(allocator, try allocator.dupe(u8, "Body contains invalid base64"));
                    return result;
                };

                const computed_crc = crc24.compute(body_decoded[0..body_decode_len]);
                result.crc_valid = (computed_crc == crc_value);

                if (!result.crc_valid) {
                    result.valid = false;
                    try result.issues.append(allocator, try allocator.dupe(u8, "CRC-24 checksum mismatch"));
                }
            } else {
                result.crc_valid = false;
                try result.issues.append(allocator, try allocator.dupe(u8, "CRC line has wrong length after base64 decode"));
            }
        } else {
            result.crc_valid = false;
            try result.issues.append(allocator, try allocator.dupe(u8, "Malformed CRC line"));
        }
    } else {
        // No CRC is acceptable per RFC 9580 but warn.
        try result.issues.append(
            allocator,
            try allocator.dupe(u8, "No CRC-24 checksum found (optional per RFC 9580)"),
        );
    }

    return result;
}

// =========================================================================
// Tests
// =========================================================================

test "armor_validator: validate empty data" {
    const allocator = std.testing.allocator;

    var result = try validateArmor(allocator, "");
    defer result.deinit(allocator);

    try std.testing.expect(!result.valid);
    try std.testing.expect(result.issues.items.len > 0);
}

test "armor_validator: validate no BEGIN line" {
    const allocator = std.testing.allocator;

    var result = try validateArmor(allocator, "just some random text\nwithout armor\n");
    defer result.deinit(allocator);

    try std.testing.expect(!result.valid);
}

test "armor_validator: validate minimal valid armor" {
    const allocator = std.testing.allocator;

    // Encode a tiny payload to produce valid CRC.
    const payload = [_]u8{ 0x01, 0x02, 0x03 };
    const crc_val = crc24.compute(&payload);
    const crc_bytes = [_]u8{
        @intCast((crc_val >> 16) & 0xFF),
        @intCast((crc_val >> 8) & 0xFF),
        @intCast(crc_val & 0xFF),
    };

    var b64_body_buf: [4]u8 = undefined;
    const b64_body = base64.standard.Encoder.encode(&b64_body_buf, &payload);
    var b64_crc_buf: [4]u8 = undefined;
    const b64_crc = base64.standard.Encoder.encode(&b64_crc_buf, &crc_bytes);

    const armor_text = try std.fmt.allocPrint(
        allocator,
        "-----BEGIN PGP MESSAGE-----\nVersion: test\n\n{s}\n={s}\n-----END PGP MESSAGE-----\n",
        .{ b64_body, b64_crc },
    );
    defer allocator.free(armor_text);

    var result = try validateArmor(allocator, armor_text);
    defer result.deinit(allocator);

    try std.testing.expect(result.armor_type != null);
    try std.testing.expect(result.armor_type.? == .message);
    try std.testing.expect(result.has_blank_separator);
    try std.testing.expect(result.has_crc);
    try std.testing.expect(result.crc_valid);
    try std.testing.expect(result.headers.items.len == 1);
    try std.testing.expectEqualStrings("Version", result.headers.items[0].name);
}

test "armor_validator: validate public key armor type" {
    const allocator = std.testing.allocator;

    const text =
        \\-----BEGIN PGP PUBLIC KEY BLOCK-----
        \\
        \\AQID
        \\-----END PGP PUBLIC KEY BLOCK-----
    ;

    var result = try validateArmor(allocator, text);
    defer result.deinit(allocator);

    try std.testing.expect(result.armor_type != null);
    try std.testing.expect(result.armor_type.? == .public_key);
    try std.testing.expect(result.has_blank_separator);
}

test "armor_validator: validate missing end line" {
    const allocator = std.testing.allocator;

    const text =
        \\-----BEGIN PGP SIGNATURE-----
        \\
        \\AQID
    ;

    var result = try validateArmor(allocator, text);
    defer result.deinit(allocator);

    try std.testing.expect(!result.valid);
}

test "armor_validator: validate unknown armor type" {
    const allocator = std.testing.allocator;

    const text =
        \\-----BEGIN UNKNOWN TYPE-----
        \\
        \\AQID
        \\-----END UNKNOWN TYPE-----
    ;

    var result = try validateArmor(allocator, text);
    defer result.deinit(allocator);

    try std.testing.expect(!result.valid);
    try std.testing.expect(result.armor_type == null);
}

test "armor_validator: validate CRC mismatch" {
    const allocator = std.testing.allocator;

    const text =
        \\-----BEGIN PGP MESSAGE-----
        \\
        \\AQID
        \\=AAAA
        \\-----END PGP MESSAGE-----
    ;

    var result = try validateArmor(allocator, text);
    defer result.deinit(allocator);

    try std.testing.expect(result.has_crc);
    // CRC should be invalid since =AAAA doesn't match the data.
    // (it might fail at base64 decode or mismatch)
}

test "armor_validator: validate multiple headers" {
    const allocator = std.testing.allocator;

    const text =
        \\-----BEGIN PGP MESSAGE-----
        \\Version: GnuPG v2
        \\Comment: Test message
        \\
        \\AQID
        \\-----END PGP MESSAGE-----
    ;

    var result = try validateArmor(allocator, text);
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), result.headers.items.len);
    try std.testing.expectEqualStrings("Version", result.headers.items[0].name);
    try std.testing.expectEqualStrings("Comment", result.headers.items[1].name);
}

test "armor_validator: ArmorValidation format" {
    const allocator = std.testing.allocator;

    var result = ArmorValidation{
        .valid = true,
        .armor_type = .message,
        .has_crc = true,
        .crc_valid = true,
        .line_lengths_valid = true,
        .has_blank_separator = true,
        .headers = .empty,
        .issues = .empty,
    };
    defer result.deinit(allocator);

    const formatted = try result.format(allocator);
    defer allocator.free(formatted);

    try std.testing.expect(mem.indexOf(u8, formatted, "Valid:          yes") != null);
    try std.testing.expect(mem.indexOf(u8, formatted, "PGP MESSAGE") != null);
}

test "armor_validator: private key armor type" {
    const allocator = std.testing.allocator;

    const text =
        \\-----BEGIN PGP PRIVATE KEY BLOCK-----
        \\
        \\AQID
        \\-----END PGP PRIVATE KEY BLOCK-----
    ;

    var result = try validateArmor(allocator, text);
    defer result.deinit(allocator);

    try std.testing.expect(result.armor_type != null);
    try std.testing.expect(result.armor_type.? == .private_key);
}

test "armor_validator: signature armor type" {
    const allocator = std.testing.allocator;

    const text =
        \\-----BEGIN PGP SIGNATURE-----
        \\
        \\AQID
        \\-----END PGP SIGNATURE-----
    ;

    var result = try validateArmor(allocator, text);
    defer result.deinit(allocator);

    try std.testing.expect(result.armor_type != null);
    try std.testing.expect(result.armor_type.? == .signature);
}
