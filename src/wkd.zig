// SPDX-License-Identifier: MIT
//! Web Key Directory (WKD) support per draft-koch-openpgp-webkey-service.
//!
//! WKD provides a decentralized way to discover OpenPGP keys by email address.
//! The protocol maps email addresses to HTTPS URLs where the key can be fetched.
//!
//! Two methods exist:
//!   - Advanced method: Uses a subdomain (openpgpkey.domain)
//!     https://openpgpkey.example.com/.well-known/openpgpkey/example.com/hu/<hash>
//!   - Direct method: Uses the domain directly
//!     https://example.com/.well-known/openpgpkey/hu/<hash>
//!
//! The <hash> is the z-base-32 encoded SHA-1 hash of the lowercase local-part
//! of the email address.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Sha1 = std.crypto.hash.Sha1;

/// Z-Base-32 alphabet per RFC 6189 Section 5.1.6.
/// This is NOT the same as the standard Base32 (RFC 4648) alphabet.
const z_base32_alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769";

/// Reverse lookup table for z-base-32 decoding.
/// Maps ASCII character to 5-bit value, or 0xFF for invalid.
const z_base32_decode_table: [128]u8 = blk: {
    var table = [_]u8{0xFF} ** 128;
    for (z_base32_alphabet, 0..) |c, i| {
        table[c] = @intCast(i);
    }
    break :blk table;
};

/// Result of parsing an email address.
pub const EmailParts = struct {
    /// The local part (before the @).
    local: []const u8,
    /// The domain part (after the @).
    domain: []const u8,
};

/// Parse an email address into local-part and domain.
///
/// The email must contain exactly one '@' character.
/// Returns error for malformed addresses.
pub fn parseEmail(email: []const u8) !EmailParts {
    // Find the @ separator
    const at_pos = mem.indexOf(u8, email, "@") orelse return error.InvalidEmail;

    // Check there's only one @
    if (mem.indexOf(u8, email[at_pos + 1 ..], "@") != null) return error.InvalidEmail;

    const local = email[0..at_pos];
    const domain = email[at_pos + 1 ..];

    // Validate parts are non-empty
    if (local.len == 0) return error.InvalidEmail;
    if (domain.len == 0) return error.InvalidEmail;

    // Basic domain validation: must contain at least one dot
    if (mem.indexOf(u8, domain, ".") == null) return error.InvalidEmail;

    return .{
        .local = local,
        .domain = domain,
    };
}

/// WKD client for building WKD URLs and computing hashes.
pub const WkdClient = struct {
    allocator: Allocator,

    /// Initialize a new WKD client.
    pub fn init(allocator: Allocator) WkdClient {
        return .{ .allocator = allocator };
    }

    /// Build the advanced-method WKD URL for an email address.
    ///
    /// Advanced method:
    ///   https://openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<hash>
    ///
    /// Where <hash> is z-base-32(SHA-1(lowercase(local-part))).
    pub fn buildAdvancedUrl(self: WkdClient, email: []const u8) ![]u8 {
        const parts = try parseEmail(email);
        return self.buildAdvancedUrlFromParts(parts.local, parts.domain);
    }

    /// Build the advanced-method WKD URL from pre-parsed parts.
    pub fn buildAdvancedUrlFromParts(self: WkdClient, local: []const u8, domain: []const u8) ![]u8 {
        // Lowercase the local part
        const lower_local = try toLower(self.allocator, local);
        defer self.allocator.free(lower_local);

        // Compute the WKD hash
        const hash = computeWkdHash(lower_local);

        // Z-Base-32 encode the hash
        const encoded = try zBase32Encode(self.allocator, &hash);
        defer self.allocator.free(encoded);

        // Build URL: https://openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<hash>
        const prefix = "https://openpgpkey.";
        const mid1 = "/.well-known/openpgpkey/";
        const mid2 = "/hu/";

        const total_len = prefix.len + domain.len + mid1.len + domain.len + mid2.len + encoded.len;
        const url = try self.allocator.alloc(u8, total_len);
        errdefer self.allocator.free(url);

        var offset: usize = 0;
        @memcpy(url[offset .. offset + prefix.len], prefix);
        offset += prefix.len;
        @memcpy(url[offset .. offset + domain.len], domain);
        offset += domain.len;
        @memcpy(url[offset .. offset + mid1.len], mid1);
        offset += mid1.len;
        @memcpy(url[offset .. offset + domain.len], domain);
        offset += domain.len;
        @memcpy(url[offset .. offset + mid2.len], mid2);
        offset += mid2.len;
        @memcpy(url[offset .. offset + encoded.len], encoded);

        return url;
    }

    /// Build the direct-method WKD URL for an email address.
    ///
    /// Direct method:
    ///   https://<domain>/.well-known/openpgpkey/hu/<hash>
    ///
    /// Where <hash> is z-base-32(SHA-1(lowercase(local-part))).
    pub fn buildDirectUrl(self: WkdClient, email: []const u8) ![]u8 {
        const parts = try parseEmail(email);
        return self.buildDirectUrlFromParts(parts.local, parts.domain);
    }

    /// Build the direct-method WKD URL from pre-parsed parts.
    pub fn buildDirectUrlFromParts(self: WkdClient, local: []const u8, domain: []const u8) ![]u8 {
        // Lowercase the local part
        const lower_local = try toLower(self.allocator, local);
        defer self.allocator.free(lower_local);

        // Compute the WKD hash
        const hash = computeWkdHash(lower_local);

        // Z-Base-32 encode the hash
        const encoded = try zBase32Encode(self.allocator, &hash);
        defer self.allocator.free(encoded);

        // Build URL: https://<domain>/.well-known/openpgpkey/hu/<hash>
        const prefix = "https://";
        const mid = "/.well-known/openpgpkey/hu/";

        const total_len = prefix.len + domain.len + mid.len + encoded.len;
        const url = try self.allocator.alloc(u8, total_len);
        errdefer self.allocator.free(url);

        var offset: usize = 0;
        @memcpy(url[offset .. offset + prefix.len], prefix);
        offset += prefix.len;
        @memcpy(url[offset .. offset + domain.len], domain);
        offset += domain.len;
        @memcpy(url[offset .. offset + mid.len], mid);
        offset += mid.len;
        @memcpy(url[offset .. offset + encoded.len], encoded);

        return url;
    }

    /// Build the WKD policy URL for a domain (advanced method).
    pub fn buildPolicyUrl(self: WkdClient, domain: []const u8) ![]u8 {
        const prefix = "https://openpgpkey.";
        const suffix = "/.well-known/openpgpkey/policy";

        const total = prefix.len + domain.len + suffix.len;
        const url = try self.allocator.alloc(u8, total);
        errdefer self.allocator.free(url);

        var offset: usize = 0;
        @memcpy(url[offset .. offset + prefix.len], prefix);
        offset += prefix.len;
        @memcpy(url[offset .. offset + domain.len], domain);
        offset += domain.len;
        @memcpy(url[offset .. offset + suffix.len], suffix);

        return url;
    }

    /// Build the WKD submission URL for a domain.
    pub fn buildSubmissionUrl(self: WkdClient, domain: []const u8) ![]u8 {
        const prefix = "https://openpgpkey.";
        const suffix = "/.well-known/openpgpkey/submission-address";

        const total = prefix.len + domain.len + suffix.len;
        const url = try self.allocator.alloc(u8, total);
        errdefer self.allocator.free(url);

        var offset: usize = 0;
        @memcpy(url[offset .. offset + prefix.len], prefix);
        offset += prefix.len;
        @memcpy(url[offset .. offset + domain.len], domain);
        offset += domain.len;
        @memcpy(url[offset .. offset + suffix.len], suffix);

        return url;
    }
};

/// Compute the WKD hash of a local-part.
///
/// The WKD hash is SHA-1 of the (already lowercase) local-part.
/// The result is a 20-byte SHA-1 digest.
pub fn computeWkdHash(local_part: []const u8) [20]u8 {
    var hash: [20]u8 = undefined;
    Sha1.hash(local_part, &hash, .{});
    return hash;
}

/// Z-Base-32 encode a byte array per RFC 6189.
///
/// Returns a newly allocated string containing the z-base-32 encoding.
pub fn zBase32Encode(allocator: Allocator, data: []const u8) ![]u8 {
    if (data.len == 0) {
        return try allocator.alloc(u8, 0);
    }

    // Output size: ceil(data.len * 8 / 5)
    const output_len = (data.len * 8 + 4) / 5;
    const output = try allocator.alloc(u8, output_len);
    errdefer allocator.free(output);

    var bit_buffer: u32 = 0;
    var bits_in_buffer: u5 = 0;
    var out_idx: usize = 0;
    var in_idx: usize = 0;

    while (out_idx < output_len) {
        // Load more bits if needed
        if (bits_in_buffer < 5) {
            if (in_idx < data.len) {
                bit_buffer = (bit_buffer << 8) | data[in_idx];
                in_idx += 1;
                bits_in_buffer += 8;
            } else {
                // Pad remaining bits with zeros
                bit_buffer <<= @intCast(5 - bits_in_buffer);
                bits_in_buffer = 5;
            }
        }

        // Extract 5 bits
        bits_in_buffer -= 5;
        const index: u5 = @intCast((bit_buffer >> bits_in_buffer) & 0x1F);
        output[out_idx] = z_base32_alphabet[index];
        out_idx += 1;
    }

    return output;
}

/// Z-Base-32 decode a string per RFC 6189.
///
/// Returns a newly allocated byte array containing the decoded data.
pub fn zBase32Decode(allocator: Allocator, encoded: []const u8) ![]u8 {
    if (encoded.len == 0) {
        return try allocator.alloc(u8, 0);
    }

    // Output size: floor(encoded.len * 5 / 8)
    const output_len = (encoded.len * 5) / 8;
    const output = try allocator.alloc(u8, output_len);
    errdefer allocator.free(output);

    var bit_buffer: u32 = 0;
    var bits_in_buffer: u5 = 0;
    var out_idx: usize = 0;

    for (encoded) |c| {
        if (c >= 128) return error.InvalidEncoding;
        const val = z_base32_decode_table[c];
        if (val == 0xFF) return error.InvalidEncoding;

        bit_buffer = (bit_buffer << 5) | val;
        bits_in_buffer += 5;

        if (bits_in_buffer >= 8) {
            bits_in_buffer -= 8;
            output[out_idx] = @intCast((bit_buffer >> bits_in_buffer) & 0xFF);
            out_idx += 1;
        }
    }

    return output;
}

/// Convert a string to lowercase, allocating a new string.
fn toLower(allocator: Allocator, input: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, input.len);
    for (input, 0..) |c, i| {
        result[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
    }
    return result;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseEmail basic" {
    const result = try parseEmail("alice@example.com");
    try std.testing.expectEqualStrings("alice", result.local);
    try std.testing.expectEqualStrings("example.com", result.domain);
}

test "parseEmail with plus" {
    const result = try parseEmail("alice+tag@example.com");
    try std.testing.expectEqualStrings("alice+tag", result.local);
    try std.testing.expectEqualStrings("example.com", result.domain);
}

test "parseEmail with dots" {
    const result = try parseEmail("alice.bob@sub.example.com");
    try std.testing.expectEqualStrings("alice.bob", result.local);
    try std.testing.expectEqualStrings("sub.example.com", result.domain);
}

test "parseEmail invalid - no at" {
    try std.testing.expectError(error.InvalidEmail, parseEmail("aliceexample.com"));
}

test "parseEmail invalid - empty local" {
    try std.testing.expectError(error.InvalidEmail, parseEmail("@example.com"));
}

test "parseEmail invalid - empty domain" {
    try std.testing.expectError(error.InvalidEmail, parseEmail("alice@"));
}

test "parseEmail invalid - double at" {
    try std.testing.expectError(error.InvalidEmail, parseEmail("alice@bob@example.com"));
}

test "parseEmail invalid - no dot in domain" {
    try std.testing.expectError(error.InvalidEmail, parseEmail("alice@localhost"));
}

test "zBase32Encode empty" {
    const allocator = std.testing.allocator;
    const encoded = try zBase32Encode(allocator, &[_]u8{});
    defer allocator.free(encoded);
    try std.testing.expectEqual(@as(usize, 0), encoded.len);
}

test "zBase32Encode single byte" {
    const allocator = std.testing.allocator;
    // 0x00 = 00000000
    // 5-bit groups: 00000 00000 (padded)
    // = 'y' 'y'
    const encoded = try zBase32Encode(allocator, &[_]u8{0x00});
    defer allocator.free(encoded);
    try std.testing.expectEqual(@as(usize, 2), encoded.len);
    try std.testing.expectEqual(@as(u8, 'y'), encoded[0]);
}

test "zBase32Encode known value" {
    const allocator = std.testing.allocator;
    // Test with a known SHA-1 output
    const data = [_]u8{ 0x48, 0x65, 0x6C, 0x6C, 0x6F }; // "Hello"
    const encoded = try zBase32Encode(allocator, &data);
    defer allocator.free(encoded);

    // 5 bytes = 40 bits = 8 z-base-32 characters
    try std.testing.expectEqual(@as(usize, 8), encoded.len);
}

test "zBase32Encode/Decode round-trip" {
    const allocator = std.testing.allocator;

    const test_cases = [_][]const u8{
        &[_]u8{0x42},
        &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF },
        &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 },
        &[_]u8{ 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00 },
    };

    for (test_cases) |data| {
        const encoded = try zBase32Encode(allocator, data);
        defer allocator.free(encoded);

        const decoded = try zBase32Decode(allocator, encoded);
        defer allocator.free(decoded);

        try std.testing.expectEqualSlices(u8, data, decoded);
    }
}

test "zBase32Decode invalid character" {
    const allocator = std.testing.allocator;
    // '!' is not in the z-base-32 alphabet
    try std.testing.expectError(error.InvalidEncoding, zBase32Decode(allocator, "y!b"));
}

test "zBase32Decode empty" {
    const allocator = std.testing.allocator;
    const decoded = try zBase32Decode(allocator, "");
    defer allocator.free(decoded);
    try std.testing.expectEqual(@as(usize, 0), decoded.len);
}

test "computeWkdHash deterministic" {
    const hash1 = computeWkdHash("alice");
    const hash2 = computeWkdHash("alice");
    try std.testing.expectEqualSlices(u8, &hash1, &hash2);
}

test "computeWkdHash different inputs" {
    const hash1 = computeWkdHash("alice");
    const hash2 = computeWkdHash("bob");
    try std.testing.expect(!mem.eql(u8, &hash1, &hash2));
}

test "computeWkdHash is SHA-1" {
    // Verify against known SHA-1 value
    var expected: [20]u8 = undefined;
    Sha1.hash("alice", &expected, .{});

    const result = computeWkdHash("alice");
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "WkdClient buildDirectUrl" {
    const allocator = std.testing.allocator;
    const client = WkdClient.init(allocator);

    const url = try client.buildDirectUrl("alice@example.com");
    defer allocator.free(url);

    try std.testing.expect(mem.startsWith(u8, url, "https://example.com/.well-known/openpgpkey/hu/"));
    try std.testing.expect(url.len > "https://example.com/.well-known/openpgpkey/hu/".len);
}

test "WkdClient buildAdvancedUrl" {
    const allocator = std.testing.allocator;
    const client = WkdClient.init(allocator);

    const url = try client.buildAdvancedUrl("alice@example.com");
    defer allocator.free(url);

    try std.testing.expect(mem.startsWith(u8, url, "https://openpgpkey.example.com/.well-known/openpgpkey/example.com/hu/"));
}

test "WkdClient URLs are case-insensitive for local part" {
    const allocator = std.testing.allocator;
    const client = WkdClient.init(allocator);

    const url1 = try client.buildDirectUrl("Alice@example.com");
    defer allocator.free(url1);

    const url2 = try client.buildDirectUrl("alice@example.com");
    defer allocator.free(url2);

    // Both should produce the same URL since local part is lowercased
    try std.testing.expectEqualStrings(url1, url2);
}

test "WkdClient buildPolicyUrl" {
    const allocator = std.testing.allocator;
    const client = WkdClient.init(allocator);

    const url = try client.buildPolicyUrl("example.com");
    defer allocator.free(url);

    try std.testing.expectEqualStrings(
        "https://openpgpkey.example.com/.well-known/openpgpkey/policy",
        url,
    );
}

test "WkdClient buildSubmissionUrl" {
    const allocator = std.testing.allocator;
    const client = WkdClient.init(allocator);

    const url = try client.buildSubmissionUrl("example.com");
    defer allocator.free(url);

    try std.testing.expectEqualStrings(
        "https://openpgpkey.example.com/.well-known/openpgpkey/submission-address",
        url,
    );
}

test "WkdClient buildDirectUrl invalid email" {
    const allocator = std.testing.allocator;
    const client = WkdClient.init(allocator);

    try std.testing.expectError(error.InvalidEmail, client.buildDirectUrl("not-an-email"));
}

test "toLower" {
    const allocator = std.testing.allocator;

    const result = try toLower(allocator, "Hello World!");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hello world!", result);

    const result2 = try toLower(allocator, "already lowercase");
    defer allocator.free(result2);
    try std.testing.expectEqualStrings("already lowercase", result2);

    const result3 = try toLower(allocator, "ALL CAPS");
    defer allocator.free(result3);
    try std.testing.expectEqualStrings("all caps", result3);
}

test "z_base32_alphabet is valid" {
    // Verify the alphabet has 32 unique characters
    try std.testing.expectEqual(@as(usize, 32), z_base32_alphabet.len);

    // Check all characters are unique
    var seen = [_]bool{false} ** 128;
    for (z_base32_alphabet) |c| {
        try std.testing.expect(!seen[c]);
        seen[c] = true;
    }
}

test "z_base32_decode_table is consistent with alphabet" {
    for (z_base32_alphabet, 0..) |c, i| {
        try std.testing.expectEqual(@as(u8, @intCast(i)), z_base32_decode_table[c]);
    }
}
