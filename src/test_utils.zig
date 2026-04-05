// SPDX-License-Identifier: MIT
//! Tests for utility modules (hex, base64, pem, email, time_fmt).
//!
//! These tests exercise the utility functions with a variety of inputs
//! including edge cases, round-trip verification, and error handling.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

// Import utility modules
const hex = @import("utils/hex.zig");
const base64_extra = @import("utils/base64.zig");
const pem = @import("utils/pem.zig");
const email_util = @import("utils/email.zig");
const time_fmt = @import("utils/time_fmt.zig");

// =========================================================================
// Hex module tests
// =========================================================================

test "hex: encode all byte values" {
    const allocator = testing.allocator;
    var data: [256]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i);

    const encoded = try hex.hexEncode(allocator, &data);
    defer allocator.free(encoded);
    try testing.expectEqual(@as(usize, 512), encoded.len);

    // Verify first few bytes
    try testing.expectEqualStrings("00", encoded[0..2]);
    try testing.expectEqualStrings("0a", encoded[20..22]);
    try testing.expectEqualStrings("ff", encoded[510..512]);
}

test "hex: decode case insensitive" {
    const allocator = testing.allocator;
    const lower = try hex.hexDecode(allocator, "abcdef");
    defer allocator.free(lower);
    const upper = try hex.hexDecode(allocator, "ABCDEF");
    defer allocator.free(upper);
    const mixed = try hex.hexDecode(allocator, "AbCdEf");
    defer allocator.free(mixed);

    try testing.expectEqualSlices(u8, lower, upper);
    try testing.expectEqualSlices(u8, lower, mixed);
}

test "hex: encode/decode round-trip large data" {
    const allocator = testing.allocator;
    var data: [1024]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i % 256);

    const encoded = try hex.hexEncode(allocator, &data);
    defer allocator.free(encoded);
    const decoded = try hex.hexDecode(allocator, encoded);
    defer allocator.free(decoded);

    try testing.expectEqualSlices(u8, &data, decoded);
}

test "hex: formatFingerprint empty" {
    const allocator = testing.allocator;
    const result = try hex.formatFingerprint(allocator, &[_]u8{});
    defer allocator.free(result);
    try testing.expectEqual(@as(usize, 0), result.len);
}

test "hex: formatFingerprintGrouped single byte" {
    const allocator = testing.allocator;
    const result = try hex.formatFingerprintGrouped(allocator, &[_]u8{0xFF});
    defer allocator.free(result);
    try testing.expectEqualStrings("FF", result);
}

test "hex: decodeIgnoringWhitespace all whitespace types" {
    const allocator = testing.allocator;
    const result = try hex.hexDecodeIgnoringWhitespace(allocator, " DE \t AD \r\n BE \n EF ");
    defer allocator.free(result);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, result);
}

test "hex: decodeIgnoringWhitespace rejects invalid chars" {
    const allocator = testing.allocator;
    try testing.expectError(error.InvalidHexCharacter, hex.hexDecodeIgnoringWhitespace(allocator, "GG"));
}

// =========================================================================
// Base64 module tests
// =========================================================================

test "base64: encodeMultiLine standard width" {
    const allocator = testing.allocator;
    // Create data that will produce more than 76 base64 chars
    var data: [100]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i % 256);

    const encoded = try base64_extra.encodeMultiLine(allocator, &data, 76);
    defer allocator.free(encoded);

    // Verify no line exceeds 76 characters
    var iter = mem.splitScalar(u8, encoded, '\n');
    while (iter.next()) |line| {
        try testing.expect(line.len <= 76);
    }
}

test "base64: encodeMultiLine narrow width" {
    const allocator = testing.allocator;
    const encoded = try base64_extra.encodeMultiLine(allocator, "Hello, World!", 4);
    defer allocator.free(encoded);

    var iter = mem.splitScalar(u8, encoded, '\n');
    while (iter.next()) |line| {
        try testing.expect(line.len <= 4);
    }
}

test "base64: decode with complex whitespace" {
    const allocator = testing.allocator;
    const input = "\r\n  SGVs\r\n  bG8s\r\n  IFdv\r\ncmxk\r\nIQ==\r\n";
    const decoded = try base64_extra.decodeIgnoringWhitespace(allocator, input);
    defer allocator.free(decoded);
    try testing.expectEqualStrings("Hello, World!", decoded);
}

test "base64: estimateDecodedSize boundaries" {
    try testing.expectEqual(@as(usize, 0), base64_extra.estimateDecodedSize(0));
    try testing.expectEqual(@as(usize, 3), base64_extra.estimateDecodedSize(4));
    try testing.expectEqual(@as(usize, 6), base64_extra.estimateDecodedSize(8));
    try testing.expectEqual(@as(usize, 75), base64_extra.estimateDecodedSize(100));
}

test "base64: estimateEncodedSize boundaries" {
    try testing.expectEqual(@as(usize, 0), base64_extra.estimateEncodedSize(0));
    try testing.expectEqual(@as(usize, 4), base64_extra.estimateEncodedSize(1));
    try testing.expectEqual(@as(usize, 4), base64_extra.estimateEncodedSize(2));
    try testing.expectEqual(@as(usize, 4), base64_extra.estimateEncodedSize(3));
    try testing.expectEqual(@as(usize, 8), base64_extra.estimateEncodedSize(4));
}

test "base64: round-trip binary data" {
    const allocator = testing.allocator;
    var data: [256]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i);

    const encoded = try base64_extra.encodeMultiLine(allocator, &data, 76);
    defer allocator.free(encoded);
    const decoded = try base64_extra.decodeIgnoringWhitespace(allocator, encoded);
    defer allocator.free(decoded);

    try testing.expectEqualSlices(u8, &data, decoded);
}

// =========================================================================
// PEM module tests
// =========================================================================

test "pem: encode/decode empty data" {
    const allocator = testing.allocator;
    const encoded = try pem.encodePemBlock(allocator, "EMPTY", "");
    defer allocator.free(encoded);

    try testing.expect(mem.startsWith(u8, encoded, "-----BEGIN EMPTY-----\n"));
    try testing.expect(mem.endsWith(u8, encoded, "-----END EMPTY-----\n"));

    const blocks = try pem.parsePemBlocks(allocator, encoded);
    defer {
        for (blocks) |blk| blk.deinit(allocator);
        allocator.free(blocks);
    }
    try testing.expectEqual(@as(usize, 1), blocks.len);
    try testing.expectEqual(@as(usize, 0), blocks[0].data.len);
}

test "pem: round-trip binary data" {
    const allocator = testing.allocator;
    var data: [128]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i);

    const encoded = try pem.encodePemBlock(allocator, "BINARY DATA", &data);
    defer allocator.free(encoded);

    const blocks = try pem.parsePemBlocks(allocator, encoded);
    defer {
        for (blocks) |blk| blk.deinit(allocator);
        allocator.free(blocks);
    }

    try testing.expectEqual(@as(usize, 1), blocks.len);
    try testing.expectEqualSlices(u8, &data, blocks[0].data);
}

test "pem: parse with surrounding text" {
    const allocator = testing.allocator;
    const input =
        \\Some text before the PEM block.
        \\-----BEGIN TEST-----
        \\AQID
        \\-----END TEST-----
        \\Some text after the PEM block.
        \\
    ;

    const blocks = try pem.parsePemBlocks(allocator, input);
    defer {
        for (blocks) |blk| blk.deinit(allocator);
        allocator.free(blocks);
    }

    try testing.expectEqual(@as(usize, 1), blocks.len);
    try testing.expectEqualStrings("TEST", blocks[0].label);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3 }, blocks[0].data);
}

// =========================================================================
// Email module tests
// =========================================================================

test "email: parseUserId complex formats" {
    // Name with special characters
    const parts1 = email_util.parseUserId("O'Brien, Alice (Security Team) <alice@big-corp.example.com>");
    try testing.expectEqualStrings("O'Brien, Alice", parts1.name.?);
    try testing.expectEqualStrings("Security Team", parts1.comment.?);
    try testing.expectEqualStrings("alice@big-corp.example.com", parts1.email.?);

    // Just comment and email
    const parts2 = email_util.parseUserId("(main key) <user@example.com>");
    try testing.expect(parts2.comment != null);
    try testing.expectEqualStrings("user@example.com", parts2.email.?);
}

test "email: formatUserId all combinations" {
    const allocator = testing.allocator;

    // All fields
    const full = try email_util.formatUserId(.{
        .name = "Alice",
        .comment = "work",
        .email = "alice@example.com",
    }, allocator);
    defer allocator.free(full);
    try testing.expectEqualStrings("Alice (work) <alice@example.com>", full);

    // Name only
    const name_only = try email_util.formatUserId(.{
        .name = "Bob",
        .comment = null,
        .email = null,
    }, allocator);
    defer allocator.free(name_only);
    try testing.expectEqualStrings("Bob", name_only);

    // Name and email
    const name_email = try email_util.formatUserId(.{
        .name = "Carol",
        .comment = null,
        .email = "carol@example.com",
    }, allocator);
    defer allocator.free(name_email);
    try testing.expectEqualStrings("Carol <carol@example.com>", name_email);
}

test "email: isValidEmail edge cases" {
    // Valid
    try testing.expect(email_util.isValidEmail("a@b.c"));
    try testing.expect(email_util.isValidEmail("user+tag@sub.domain.com"));
    try testing.expect(email_util.isValidEmail("user.name@domain.org"));

    // Invalid
    try testing.expect(!email_util.isValidEmail("")); // empty
    try testing.expect(!email_util.isValidEmail("@domain.com")); // no local
    try testing.expect(!email_util.isValidEmail("user@")); // no domain
    try testing.expect(!email_util.isValidEmail("user@domain")); // no dot in domain
    try testing.expect(!email_util.isValidEmail("user@.domain.com")); // leading dot
    try testing.expect(!email_util.isValidEmail("user@domain.com.")); // trailing dot
    try testing.expect(!email_util.isValidEmail("user@domain..com")); // consecutive dots
}

test "email: normalizeEmail preserves structure" {
    const allocator = testing.allocator;
    const result = try email_util.normalizeEmail(allocator, "  Alice.Smith@Example.COM  ");
    defer allocator.free(result);
    try testing.expectEqualStrings("alice.smith@example.com", result);
}

test "email: emailsEqual various cases" {
    try testing.expect(email_util.emailsEqual("USER@EXAMPLE.COM", "user@example.com"));
    try testing.expect(email_util.emailsEqual("  user@example.com  ", "user@example.com"));
    try testing.expect(!email_util.emailsEqual("alice@example.com", "bob@example.com"));
    try testing.expect(!email_util.emailsEqual("user@a.com", "user@b.com"));
}

// =========================================================================
// Time formatting module tests
// =========================================================================

test "time_fmt: formatTimestamp known dates" {
    var buf: [32]u8 = undefined;

    // Unix epoch
    const epoch = try time_fmt.formatTimestamp(0, &buf);
    try testing.expectEqualStrings("1970-01-01 00:00:00 UTC", epoch);

    // Known date: 2009-02-13 23:31:30 UTC (Unix timestamp 1234567890)
    const known = try time_fmt.formatTimestamp(1234567890, &buf);
    try testing.expectEqualStrings("2009-02-13 23:31:30 UTC", known);
}

test "time_fmt: formatDuration various scales" {
    var buf: [64]u8 = undefined;

    try testing.expectEqualStrings("0 seconds", try time_fmt.formatDuration(0, &buf));
    try testing.expectEqualStrings("1 second", try time_fmt.formatDuration(1, &buf));
    try testing.expectEqualStrings("59 seconds", try time_fmt.formatDuration(59, &buf));
    try testing.expectEqualStrings("1 minute", try time_fmt.formatDuration(60, &buf));
    try testing.expectEqualStrings("59 minutes", try time_fmt.formatDuration(3540, &buf));
    try testing.expectEqualStrings("1 hour", try time_fmt.formatDuration(3600, &buf));
    try testing.expectEqualStrings("23 hours", try time_fmt.formatDuration(82800, &buf));
    try testing.expectEqualStrings("1 day", try time_fmt.formatDuration(86400, &buf));
    try testing.expectEqualStrings("365 days", try time_fmt.formatDuration(365 * 86400, &buf));
}

test "time_fmt: parseIsoDate various dates" {
    // Known dates
    try testing.expectEqual(@as(u32, 0), try time_fmt.parseIsoDate("1970-01-01"));
    try testing.expectEqual(@as(u32, 86400), try time_fmt.parseIsoDate("1970-01-02"));

    // 2000-01-01 = 10957 days * 86400 = 946684800
    try testing.expectEqual(@as(u32, 946684800), try time_fmt.parseIsoDate("2000-01-01"));

    // Leap year validation
    _ = try time_fmt.parseIsoDate("2000-02-29"); // 2000 is a leap year
    _ = try time_fmt.parseIsoDate("2024-02-29"); // 2024 is a leap year
    try testing.expectError(error.InvalidDate, time_fmt.parseIsoDate("1900-02-29")); // 1900 is NOT
    try testing.expectError(error.InvalidDate, time_fmt.parseIsoDate("2023-02-29")); // 2023 is NOT
}

test "time_fmt: daysUntilExpiry calculations" {
    // No expiration
    try testing.expect(time_fmt.daysUntilExpiry(0, 0, 0) == null);

    // Exactly at expiration
    const at_expiry = time_fmt.daysUntilExpiry(0, 86400, 86400);
    try testing.expect(at_expiry != null);
    try testing.expectEqual(@as(i64, 0), at_expiry.?);

    // One day before expiration
    const before = time_fmt.daysUntilExpiry(0, 86400 * 10, 86400 * 9);
    try testing.expect(before != null);
    try testing.expectEqual(@as(i64, 1), before.?);

    // One day after expiration
    const after = time_fmt.daysUntilExpiry(0, 86400 * 10, 86400 * 11);
    try testing.expect(after != null);
    try testing.expectEqual(@as(i64, -1), after.?);
}
