// SPDX-License-Identifier: MIT
//! Email address utilities for OpenPGP User IDs.
//!
//! OpenPGP User IDs conventionally follow the format:
//!   "Real Name (Comment) <email@example.com>"
//!
//! This module provides parsing, formatting, and validation utilities
//! for this format, as well as email address normalization for WKD
//! and key lookups.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

pub const EmailError = error{
    InvalidUserId,
    InvalidEmail,
    OutOfMemory,
};

/// Parsed components of an OpenPGP User ID string.
///
/// A User ID has the conventional format:
///   "Real Name (Comment) <email@example.com>"
///
/// All fields are optional slices into the original string (not copies).
pub const UserIdParts = struct {
    /// The display name portion, or null if not present.
    name: ?[]const u8,
    /// The email address (without angle brackets), or null if not present.
    email: ?[]const u8,
    /// The comment (without parentheses), or null if not present.
    comment: ?[]const u8,
};

/// Parse a User ID string into its component parts.
///
/// Handles the standard format "Name (Comment) <email>" as well as
/// bare email addresses and bare names.
///
/// The returned slices point into the input string and do not allocate.
pub fn parseUserId(user_id: []const u8) UserIdParts {
    var result = UserIdParts{
        .name = null,
        .email = null,
        .comment = null,
    };

    if (user_id.len == 0) return result;

    // Extract email: look for <...>
    if (mem.indexOf(u8, user_id, "<")) |lt_pos| {
        if (mem.indexOfPos(u8, user_id, lt_pos, ">")) |gt_pos| {
            if (gt_pos > lt_pos + 1) {
                result.email = user_id[lt_pos + 1 .. gt_pos];
            }
        }
    }

    // Extract comment: look for (...)
    if (mem.indexOf(u8, user_id, "(")) |lp_pos| {
        if (mem.indexOfPos(u8, user_id, lp_pos, ")")) |rp_pos| {
            if (rp_pos > lp_pos + 1) {
                result.comment = user_id[lp_pos + 1 .. rp_pos];
            }
        }
    }

    // Extract name: everything before the first ( or < that isn't whitespace
    var name_end = user_id.len;
    if (mem.indexOf(u8, user_id, "(")) |pos| {
        if (pos < name_end) name_end = pos;
    }
    if (mem.indexOf(u8, user_id, "<")) |pos| {
        if (pos < name_end) name_end = pos;
    }

    const name_candidate = mem.trim(u8, user_id[0..name_end], " \t");
    if (name_candidate.len > 0) {
        // If no angle-bracketed email was found and the candidate looks
        // like a bare email (contains @), treat it as an email, not a name.
        if (result.email == null and result.comment == null and
            mem.indexOf(u8, name_candidate, "@") != null)
        {
            result.email = name_candidate;
        } else {
            result.name = name_candidate;
        }
    }

    // If still nothing was found, try treating the whole string as bare text
    if (result.email == null and result.name == null and result.comment == null) {
        const trimmed = mem.trim(u8, user_id, " \t");
        if (trimmed.len > 0) {
            if (mem.indexOf(u8, trimmed, "@") != null) {
                result.email = trimmed;
            } else {
                result.name = trimmed;
            }
        }
    }

    return result;
}

/// Format User ID parts back into the conventional string format.
///
/// Produces "Name (Comment) <email>" with appropriate parts omitted
/// when null.
///
/// Returns a newly allocated string. Caller owns the memory.
pub fn formatUserId(parts: UserIdParts, allocator: Allocator) EmailError![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    if (parts.name) |name| {
        output.appendSlice(allocator, name) catch return error.OutOfMemory;
    }

    if (parts.comment) |comment| {
        if (output.items.len > 0) {
            output.append(allocator, ' ') catch return error.OutOfMemory;
        }
        output.append(allocator, '(') catch return error.OutOfMemory;
        output.appendSlice(allocator, comment) catch return error.OutOfMemory;
        output.append(allocator, ')') catch return error.OutOfMemory;
    }

    if (parts.email) |email| {
        if (output.items.len > 0) {
            output.append(allocator, ' ') catch return error.OutOfMemory;
        }
        output.append(allocator, '<') catch return error.OutOfMemory;
        output.appendSlice(allocator, email) catch return error.OutOfMemory;
        output.append(allocator, '>') catch return error.OutOfMemory;
    }

    return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Extract just the email address from a User ID string.
///
/// Returns the email address without angle brackets, or null if no
/// email address is found.
///
/// This does NOT allocate; the returned slice points into the input.
pub fn extractEmail(user_id: []const u8) ?[]const u8 {
    const parts = parseUserId(user_id);
    return parts.email;
}

/// Check if a string is a valid email address.
///
/// This performs a basic structural validation:
///   - Contains exactly one '@'
///   - Local part is non-empty
///   - Domain part is non-empty and contains a dot
///   - No spaces or control characters
///
/// This is NOT a full RFC 5321 validator; it covers the common case
/// for OpenPGP User IDs.
pub fn isValidEmail(email: []const u8) bool {
    if (email.len == 0) return false;
    if (email.len > 254) return false; // RFC 5321 max

    // Find exactly one '@'
    var at_count: usize = 0;
    var at_pos: usize = 0;
    for (email, 0..) |c, i| {
        if (c == '@') {
            at_count += 1;
            at_pos = i;
        }
        // No spaces or control chars
        if (c <= 0x20 or c >= 0x7F) return false;
    }

    if (at_count != 1) return false;

    const local = email[0..at_pos];
    const domain = email[at_pos + 1 ..];

    // Local part checks
    if (local.len == 0 or local.len > 64) return false;

    // Domain checks
    if (domain.len == 0 or domain.len > 253) return false;
    if (mem.indexOf(u8, domain, ".") == null) return false;
    if (domain[0] == '.' or domain[domain.len - 1] == '.') return false;
    // No consecutive dots
    if (mem.indexOf(u8, domain, "..") != null) return false;

    return true;
}

/// Normalize an email address for comparison and WKD lookups.
///
/// Normalization:
///   - Converts the entire address to lowercase
///   - Trims surrounding whitespace
///
/// Returns a newly allocated string. Caller owns the memory.
pub fn normalizeEmail(allocator: Allocator, email: []const u8) EmailError![]u8 {
    const trimmed = mem.trim(u8, email, " \t\r\n");
    const buf = allocator.alloc(u8, trimmed.len) catch return error.OutOfMemory;

    for (trimmed, 0..) |c, i| {
        buf[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
    }

    return buf;
}

/// Check if two email addresses are equivalent after normalization.
///
/// Case-insensitive comparison with whitespace trimming.
pub fn emailsEqual(a: []const u8, b: []const u8) bool {
    const ta = mem.trim(u8, a, " \t\r\n");
    const tb = mem.trim(u8, b, " \t\r\n");
    if (ta.len != tb.len) return false;
    for (ta, tb) |ca, cb| {
        const la: u8 = if (ca >= 'A' and ca <= 'Z') ca + 32 else ca;
        const lb: u8 = if (cb >= 'A' and cb <= 'Z') cb + 32 else cb;
        if (la != lb) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseUserId full format" {
    const parts = parseUserId("Alice Smith (work) <alice@example.com>");
    try std.testing.expectEqualStrings("Alice Smith", parts.name.?);
    try std.testing.expectEqualStrings("work", parts.comment.?);
    try std.testing.expectEqualStrings("alice@example.com", parts.email.?);
}

test "parseUserId name and email only" {
    const parts = parseUserId("Bob <bob@example.com>");
    try std.testing.expectEqualStrings("Bob", parts.name.?);
    try std.testing.expect(parts.comment == null);
    try std.testing.expectEqualStrings("bob@example.com", parts.email.?);
}

test "parseUserId email only with brackets" {
    const parts = parseUserId("<user@example.com>");
    try std.testing.expect(parts.name == null);
    try std.testing.expectEqualStrings("user@example.com", parts.email.?);
}

test "parseUserId bare email" {
    const parts = parseUserId("user@example.com");
    try std.testing.expect(parts.name == null);
    try std.testing.expectEqualStrings("user@example.com", parts.email.?);
}

test "parseUserId bare name" {
    const parts = parseUserId("Just A Name");
    try std.testing.expectEqualStrings("Just A Name", parts.name.?);
    try std.testing.expect(parts.email == null);
}

test "parseUserId empty" {
    const parts = parseUserId("");
    try std.testing.expect(parts.name == null);
    try std.testing.expect(parts.email == null);
    try std.testing.expect(parts.comment == null);
}

test "formatUserId round-trip" {
    const allocator = std.testing.allocator;
    const parts = UserIdParts{
        .name = "Alice",
        .comment = "work",
        .email = "alice@example.com",
    };
    const formatted = try formatUserId(parts, allocator);
    defer allocator.free(formatted);
    try std.testing.expectEqualStrings("Alice (work) <alice@example.com>", formatted);
}

test "formatUserId email only" {
    const allocator = std.testing.allocator;
    const parts = UserIdParts{
        .name = null,
        .comment = null,
        .email = "user@example.com",
    };
    const formatted = try formatUserId(parts, allocator);
    defer allocator.free(formatted);
    try std.testing.expectEqualStrings("<user@example.com>", formatted);
}

test "extractEmail from user id" {
    const email = extractEmail("Alice <alice@example.com>");
    try std.testing.expectEqualStrings("alice@example.com", email.?);
}

test "extractEmail no email" {
    const email = extractEmail("Just A Name");
    try std.testing.expect(email == null);
}

test "isValidEmail valid" {
    try std.testing.expect(isValidEmail("user@example.com"));
    try std.testing.expect(isValidEmail("a@b.co"));
    try std.testing.expect(isValidEmail("user+tag@domain.org"));
}

test "isValidEmail invalid" {
    try std.testing.expect(!isValidEmail(""));
    try std.testing.expect(!isValidEmail("noatsign"));
    try std.testing.expect(!isValidEmail("@domain.com"));
    try std.testing.expect(!isValidEmail("user@"));
    try std.testing.expect(!isValidEmail("user@nodot"));
    try std.testing.expect(!isValidEmail("user@@double.com"));
    try std.testing.expect(!isValidEmail("user @space.com"));
}

test "normalizeEmail" {
    const allocator = std.testing.allocator;
    const result = try normalizeEmail(allocator, "  User@Example.COM  ");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("user@example.com", result);
}

test "emailsEqual" {
    try std.testing.expect(emailsEqual("user@example.com", "USER@EXAMPLE.COM"));
    try std.testing.expect(emailsEqual("  user@example.com ", "user@example.com"));
    try std.testing.expect(!emailsEqual("alice@example.com", "bob@example.com"));
}
