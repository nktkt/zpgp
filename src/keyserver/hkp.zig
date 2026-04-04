// SPDX-License-Identifier: MIT
//! HKP (HTTP Keyserver Protocol) client per the HKP specification.
//!
//! HKP defines a simple HTTP-based protocol for keyserver operations:
//!   - GET /pks/lookup?op=get&search={query}&options=mr — retrieve a key
//!   - GET /pks/lookup?op=index&search={query}&options=mr — search for keys
//!   - POST /pks/add — submit a key (body: keytext={url-encoded armored key})
//!
//! This module implements URL building, request formatting, and URL encoding.
//! The actual HTTP transport is separated to allow testing without network access.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// HKP client for interacting with OpenPGP keyservers.
pub const HkpClient = struct {
    allocator: Allocator,
    /// Base server URL, e.g. "https://keys.openpgp.org"
    server_url: []const u8,

    /// Initialize an HKP client with the given server URL.
    ///
    /// The server_url should not have a trailing slash.
    /// The caller retains ownership of the server_url string.
    pub fn init(allocator: Allocator, server_url: []const u8) HkpClient {
        return .{
            .allocator = allocator,
            .server_url = server_url,
        };
    }

    /// Build a URL for looking up a key by ID, fingerprint, or email.
    ///
    /// Returns a URL like:
    ///   {server}/pks/lookup?op=get&search={query}&options=mr
    pub fn buildLookupUrl(self: *const HkpClient, allocator: Allocator, query: []const u8) ![]u8 {
        return formatLookupUrl(allocator, self.server_url, "get", query);
    }

    /// Build a URL for searching keys by name or email.
    ///
    /// Returns a URL like:
    ///   {server}/pks/lookup?op=index&search={query}&options=mr
    pub fn buildSearchUrl(self: *const HkpClient, allocator: Allocator, query: []const u8) ![]u8 {
        return formatLookupUrl(allocator, self.server_url, "index", query);
    }

    /// Build the POST body for submitting a key.
    ///
    /// Returns a URL-encoded body like:
    ///   keytext={url-encoded armored key}
    pub fn buildSubmitBody(self: *const HkpClient, allocator: Allocator, armored_key: []const u8) ![]u8 {
        _ = self;
        return formatSubmitBody(allocator, armored_key);
    }
};

/// Format an HKP lookup URL.
///
/// Builds: {server}/pks/lookup?op={op}&search={url-encoded search}&options=mr
pub fn formatLookupUrl(
    allocator: Allocator,
    server: []const u8,
    op: []const u8,
    search: []const u8,
) ![]u8 {
    const encoded_search = try urlEncode(allocator, search);
    defer allocator.free(encoded_search);

    // Calculate total length
    // server + "/pks/lookup?op=" + op + "&search=" + encoded_search + "&options=mr"
    const total = server.len + "/pks/lookup?op=".len + op.len +
        "&search=".len + encoded_search.len + "&options=mr".len;

    const buf = try allocator.alloc(u8, total);
    var offset: usize = 0;

    @memcpy(buf[offset .. offset + server.len], server);
    offset += server.len;

    const path = "/pks/lookup?op=";
    @memcpy(buf[offset .. offset + path.len], path);
    offset += path.len;

    @memcpy(buf[offset .. offset + op.len], op);
    offset += op.len;

    const search_param = "&search=";
    @memcpy(buf[offset .. offset + search_param.len], search_param);
    offset += search_param.len;

    @memcpy(buf[offset .. offset + encoded_search.len], encoded_search);
    offset += encoded_search.len;

    const options = "&options=mr";
    @memcpy(buf[offset .. offset + options.len], options);
    offset += options.len;

    return buf;
}

/// Format an HKP submit body.
///
/// Builds: keytext={url-encoded armored key}
pub fn formatSubmitBody(allocator: Allocator, armored_key: []const u8) ![]u8 {
    const encoded = try urlEncode(allocator, armored_key);
    defer allocator.free(encoded);

    const prefix = "keytext=";
    const total = prefix.len + encoded.len;
    const buf = try allocator.alloc(u8, total);

    @memcpy(buf[0..prefix.len], prefix);
    @memcpy(buf[prefix.len..], encoded);

    return buf;
}

/// URL-encode a string per RFC 3986.
///
/// Unreserved characters (A-Z, a-z, 0-9, '-', '.', '_', '~') are passed
/// through unchanged. All other bytes are encoded as %XX where XX is the
/// uppercase hexadecimal representation.
pub fn urlEncode(allocator: Allocator, input: []const u8) ![]u8 {
    // Count the output size first
    var size: usize = 0;
    for (input) |c| {
        if (isUnreserved(c)) {
            size += 1;
        } else {
            size += 3; // %XX
        }
    }

    const buf = try allocator.alloc(u8, size);
    var offset: usize = 0;

    for (input) |c| {
        if (isUnreserved(c)) {
            buf[offset] = c;
            offset += 1;
        } else {
            buf[offset] = '%';
            buf[offset + 1] = hexDigit(c >> 4);
            buf[offset + 2] = hexDigit(c & 0x0F);
            offset += 3;
        }
    }

    return buf;
}

/// Check if a byte is an unreserved character per RFC 3986.
fn isUnreserved(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => true,
        else => false,
    };
}

/// Convert a 4-bit value to an uppercase hex digit.
fn hexDigit(v: u8) u8 {
    return if (v < 10) ('0' + v) else ('A' + v - 10);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "urlEncode simple string" {
    const allocator = std.testing.allocator;

    const result = try urlEncode(allocator, "hello");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hello", result);
}

test "urlEncode with spaces" {
    const allocator = std.testing.allocator;

    const result = try urlEncode(allocator, "hello world");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hello%20world", result);
}

test "urlEncode email address" {
    const allocator = std.testing.allocator;

    const result = try urlEncode(allocator, "user@example.com");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("user%40example.com", result);
}

test "urlEncode special characters" {
    const allocator = std.testing.allocator;

    const result = try urlEncode(allocator, "a=b&c=d");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("a%3Db%26c%3Dd", result);
}

test "urlEncode preserves unreserved characters" {
    const allocator = std.testing.allocator;

    const result = try urlEncode(allocator, "ABCxyz012-._~");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("ABCxyz012-._~", result);
}

test "urlEncode empty string" {
    const allocator = std.testing.allocator;

    const result = try urlEncode(allocator, "");
    defer allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "urlEncode newline and tab" {
    const allocator = std.testing.allocator;

    const result = try urlEncode(allocator, "a\nb\tc");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("a%0Ab%09c", result);
}

test "formatLookupUrl get operation" {
    const allocator = std.testing.allocator;

    const url = try formatLookupUrl(allocator, "https://keys.openpgp.org", "get", "0xDEADBEEF");
    defer allocator.free(url);

    try std.testing.expectEqualStrings(
        "https://keys.openpgp.org/pks/lookup?op=get&search=0xDEADBEEF&options=mr",
        url,
    );
}

test "formatLookupUrl index operation" {
    const allocator = std.testing.allocator;

    const url = try formatLookupUrl(allocator, "https://keys.openpgp.org", "index", "alice@example.com");
    defer allocator.free(url);

    try std.testing.expectEqualStrings(
        "https://keys.openpgp.org/pks/lookup?op=index&search=alice%40example.com&options=mr",
        url,
    );
}

test "formatLookupUrl with spaces in search" {
    const allocator = std.testing.allocator;

    const url = try formatLookupUrl(allocator, "http://localhost:11371", "index", "Alice Smith");
    defer allocator.free(url);

    try std.testing.expectEqualStrings(
        "http://localhost:11371/pks/lookup?op=index&search=Alice%20Smith&options=mr",
        url,
    );
}

test "formatSubmitBody" {
    const allocator = std.testing.allocator;

    const armored = "-----BEGIN PGP PUBLIC KEY BLOCK-----\ndata\n-----END PGP PUBLIC KEY BLOCK-----\n";
    const body = try formatSubmitBody(allocator, armored);
    defer allocator.free(body);

    // Should start with "keytext="
    try std.testing.expect(mem.startsWith(u8, body, "keytext="));
    // The armored text should be URL-encoded
    try std.testing.expect(mem.indexOf(u8, body, "%0A") != null); // newlines encoded
}

test "HkpClient buildLookupUrl" {
    const allocator = std.testing.allocator;

    const client = HkpClient.init(allocator, "https://keys.openpgp.org");

    const url = try client.buildLookupUrl(allocator, "0xABCD1234");
    defer allocator.free(url);

    try std.testing.expectEqualStrings(
        "https://keys.openpgp.org/pks/lookup?op=get&search=0xABCD1234&options=mr",
        url,
    );
}

test "HkpClient buildSearchUrl" {
    const allocator = std.testing.allocator;

    const client = HkpClient.init(allocator, "https://keys.openpgp.org");

    const url = try client.buildSearchUrl(allocator, "test@test.com");
    defer allocator.free(url);

    try std.testing.expectEqualStrings(
        "https://keys.openpgp.org/pks/lookup?op=index&search=test%40test.com&options=mr",
        url,
    );
}

test "HkpClient buildSubmitBody" {
    const allocator = std.testing.allocator;

    const client = HkpClient.init(allocator, "https://keys.openpgp.org");

    const body = try client.buildSubmitBody(allocator, "KEY DATA");
    defer allocator.free(body);

    try std.testing.expectEqualStrings("keytext=KEY%20DATA", body);
}

test "hexDigit" {
    try std.testing.expectEqual(@as(u8, '0'), hexDigit(0));
    try std.testing.expectEqual(@as(u8, '9'), hexDigit(9));
    try std.testing.expectEqual(@as(u8, 'A'), hexDigit(10));
    try std.testing.expectEqual(@as(u8, 'F'), hexDigit(15));
}

test "isUnreserved" {
    // Letters
    try std.testing.expect(isUnreserved('A'));
    try std.testing.expect(isUnreserved('Z'));
    try std.testing.expect(isUnreserved('a'));
    try std.testing.expect(isUnreserved('z'));
    // Digits
    try std.testing.expect(isUnreserved('0'));
    try std.testing.expect(isUnreserved('9'));
    // Special unreserved
    try std.testing.expect(isUnreserved('-'));
    try std.testing.expect(isUnreserved('.'));
    try std.testing.expect(isUnreserved('_'));
    try std.testing.expect(isUnreserved('~'));
    // Reserved
    try std.testing.expect(!isUnreserved(' '));
    try std.testing.expect(!isUnreserved('@'));
    try std.testing.expect(!isUnreserved('='));
    try std.testing.expect(!isUnreserved('&'));
    try std.testing.expect(!isUnreserved('/'));
    try std.testing.expect(!isUnreserved('?'));
}
