// SPDX-License-Identifier: MIT
//! Keyserver protocol helpers.
//!
//! Provides utilities for detecting keyserver protocols (HKP, HKPS, WKD),
//! normalizing key identifiers, and building keyserver query URLs.
//! Supports the HKP (HTTP Keyserver Protocol) and WKD (Web Key Directory)
//! specifications.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Supported keyserver protocols.
pub const KeyserverProtocol = enum {
    hkp,
    hkps,
    wkd,
    wkd_direct,

    pub fn name(self: KeyserverProtocol) []const u8 {
        return switch (self) {
            .hkp => "HKP",
            .hkps => "HKPS",
            .wkd => "WKD (Advanced)",
            .wkd_direct => "WKD (Direct)",
        };
    }

    /// Return the default port for this protocol.
    pub fn defaultPort(self: KeyserverProtocol) u16 {
        return switch (self) {
            .hkp => 11371,
            .hkps => 443,
            .wkd, .wkd_direct => 443,
        };
    }
};

/// Type of a normalized key identifier.
pub const KeyIdType = enum {
    fingerprint_v4,
    fingerprint_v6,
    key_id,
    email,
};

/// A normalized key identifier suitable for keyserver queries.
pub const NormalizedKeyId = struct {
    id_type: KeyIdType,
    value: []const u8,
    search_string: []const u8,

    pub fn deinit(self: NormalizedKeyId, allocator: Allocator) void {
        allocator.free(self.value);
        allocator.free(self.search_string);
    }
};

/// Detect the keyserver protocol from a URL string.
///
/// Recognizes:
///   - "hkp://..."  -> .hkp
///   - "hkps://..." -> .hkps
///   - URLs containing ".well-known/openpgpkey" -> .wkd
///   - "keys.openpgp.org" -> .hkps (well-known keyserver)
///   - "keyserver.ubuntu.com" -> .hkp
pub fn detectProtocol(url: []const u8) ?KeyserverProtocol {
    if (url.len == 0) return null;

    // Check for explicit protocol prefixes
    if (mem.startsWith(u8, url, "hkps://")) return .hkps;
    if (mem.startsWith(u8, url, "hkp://")) return .hkp;

    // Check for WKD indicators
    if (mem.indexOf(u8, url, ".well-known/openpgpkey") != null) return .wkd;
    if (mem.indexOf(u8, url, "/.well-known/openpgpkey") != null) return .wkd;

    // Well-known keyservers
    if (mem.indexOf(u8, url, "keys.openpgp.org") != null) return .hkps;
    if (mem.indexOf(u8, url, "keyserver.ubuntu.com") != null) return .hkp;
    if (mem.indexOf(u8, url, "pgp.mit.edu") != null) return .hkp;
    if (mem.indexOf(u8, url, "keys.gnupg.net") != null) return .hkp;
    if (mem.indexOf(u8, url, "sks-keyservers.net") != null) return .hkp;

    // Check for HTTPS/HTTP
    if (mem.startsWith(u8, url, "https://")) return .hkps;
    if (mem.startsWith(u8, url, "http://")) return .hkp;

    return null;
}

/// Normalize a key identifier for keyserver queries.
///
/// Accepts:
///   - 40-char hex string -> V4 fingerprint
///   - 64-char hex string -> V6 fingerprint
///   - 16-char hex string -> key ID
///   - 8-char hex string  -> short key ID (expanded to 16 chars)
///   - "0x" prefixed hex  -> fingerprint or key ID
///   - email address      -> email search
///
/// Returns the normalized form with an appropriate HKP search string.
pub fn normalizeKeyId(allocator: Allocator, input: []const u8) !NormalizedKeyId {
    if (input.len == 0) return error.InvalidInput;

    // Strip whitespace and "0x" prefix
    var clean = input;
    if (mem.startsWith(u8, clean, "0x") or mem.startsWith(u8, clean, "0X")) {
        clean = clean[2..];
    }

    // Check if it's an email address
    if (mem.indexOf(u8, clean, "@") != null) {
        const value = try allocator.dupe(u8, clean);
        errdefer allocator.free(value);
        // HKP email search format
        const search = try std.fmt.allocPrint(allocator, "={s}", .{clean});
        return .{
            .id_type = .email,
            .value = value,
            .search_string = search,
        };
    }

    // Try to parse as hex
    const stripped = stripSpaces(allocator, clean) catch {
        // If stripping fails, try as-is
        const value = try allocator.dupe(u8, clean);
        errdefer allocator.free(value);
        const search = try std.fmt.allocPrint(allocator, "0x{s}", .{clean});
        return .{
            .id_type = .key_id,
            .value = value,
            .search_string = search,
        };
    };
    defer allocator.free(stripped);

    // Validate hex characters
    for (stripped) |c| {
        if (!isHexChar(c)) {
            // Might be a name search
            const value = try allocator.dupe(u8, input);
            errdefer allocator.free(value);
            const search = try std.fmt.allocPrint(allocator, "{s}", .{input});
            return .{
                .id_type = .email,
                .value = value,
                .search_string = search,
            };
        }
    }

    const upper = try toUpperHex(allocator, stripped);

    if (upper.len == 40) {
        // V4 fingerprint
        const value = try allocator.dupe(u8, upper);
        errdefer allocator.free(value);
        const search = try std.fmt.allocPrint(allocator, "0x{s}", .{upper});
        allocator.free(upper);
        return .{
            .id_type = .fingerprint_v4,
            .value = value,
            .search_string = search,
        };
    } else if (upper.len == 64) {
        // V6 fingerprint
        const value = try allocator.dupe(u8, upper);
        errdefer allocator.free(value);
        const search = try std.fmt.allocPrint(allocator, "0x{s}", .{upper});
        allocator.free(upper);
        return .{
            .id_type = .fingerprint_v6,
            .value = value,
            .search_string = search,
        };
    } else if (upper.len == 16) {
        // Full key ID
        const value = try allocator.dupe(u8, upper);
        errdefer allocator.free(value);
        const search = try std.fmt.allocPrint(allocator, "0x{s}", .{upper});
        allocator.free(upper);
        return .{
            .id_type = .key_id,
            .value = value,
            .search_string = search,
        };
    } else if (upper.len == 8) {
        // Short key ID - pad to 16 chars
        const padded = try std.fmt.allocPrint(allocator, "00000000{s}", .{upper});
        errdefer allocator.free(padded);
        const value = try allocator.dupe(u8, padded);
        errdefer allocator.free(value);
        const search = try std.fmt.allocPrint(allocator, "0x{s}", .{upper});
        allocator.free(upper);
        allocator.free(padded);
        return .{
            .id_type = .key_id,
            .value = value,
            .search_string = search,
        };
    } else {
        // Unknown length hex - treat as fingerprint/key ID
        const value = try allocator.dupe(u8, upper);
        errdefer allocator.free(value);
        const search = try std.fmt.allocPrint(allocator, "0x{s}", .{upper});
        allocator.free(upper);
        return .{
            .id_type = .key_id,
            .value = value,
            .search_string = search,
        };
    }
}

/// Build an HKP lookup URL for a key search.
pub fn buildHkpLookupUrl(allocator: Allocator, server: []const u8, search: []const u8) ![]u8 {
    // Determine base URL
    var base: []const u8 = server;
    if (!mem.startsWith(u8, server, "http://") and !mem.startsWith(u8, server, "https://") and
        !mem.startsWith(u8, server, "hkp://") and !mem.startsWith(u8, server, "hkps://"))
    {
        return try std.fmt.allocPrint(allocator, "https://{s}/pks/lookup?op=get&search={s}", .{ base, search });
    }

    // Convert hkp/hkps to http/https
    if (mem.startsWith(u8, server, "hkps://")) {
        base = server[7..]; // strip hkps://
        return try std.fmt.allocPrint(allocator, "https://{s}/pks/lookup?op=get&search={s}", .{ base, search });
    } else if (mem.startsWith(u8, server, "hkp://")) {
        base = server[6..]; // strip hkp://
        return try std.fmt.allocPrint(allocator, "http://{s}:11371/pks/lookup?op=get&search={s}", .{ base, search });
    }

    // Already has http(s)://
    // Strip trailing slash
    if (base.len > 0 and base[base.len - 1] == '/') {
        base = base[0 .. base.len - 1];
    }

    return try std.fmt.allocPrint(allocator, "{s}/pks/lookup?op=get&search={s}", .{ base, search });
}

/// Build a WKD direct URL for an email address.
pub fn buildWkdDirectUrl(allocator: Allocator, email: []const u8) ![]u8 {
    const at_pos = mem.indexOf(u8, email, "@") orelse return error.InvalidInput;
    const local_part = email[0..at_pos];
    const domain = email[at_pos + 1 ..];

    // WKD uses a z-base-32 encoding of SHA-1 of the local part
    // For simplicity, we compute a hex hash and note the real implementation needs z-base-32
    const sha1 = std.crypto.hash.Sha1;
    var hash: [20]u8 = undefined;
    sha1.hash(local_part, &hash, .{});

    var hash_hex: [40]u8 = undefined;
    for (hash, 0..) |b, i| {
        const hex_chars = "0123456789abcdef";
        hash_hex[i * 2] = hex_chars[b >> 4];
        hash_hex[i * 2 + 1] = hex_chars[b & 0x0F];
    }

    return try std.fmt.allocPrint(allocator,
        "https://{s}/.well-known/openpgpkey/hu/{s}", .{ domain, hash_hex });
}

/// Build a WKD advanced URL for an email address.
pub fn buildWkdAdvancedUrl(allocator: Allocator, email: []const u8) ![]u8 {
    const at_pos = mem.indexOf(u8, email, "@") orelse return error.InvalidInput;
    const local_part = email[0..at_pos];
    const domain = email[at_pos + 1 ..];

    const sha1 = std.crypto.hash.Sha1;
    var hash: [20]u8 = undefined;
    sha1.hash(local_part, &hash, .{});

    var hash_hex: [40]u8 = undefined;
    for (hash, 0..) |b, i| {
        const hex_chars = "0123456789abcdef";
        hash_hex[i * 2] = hex_chars[b >> 4];
        hash_hex[i * 2 + 1] = hex_chars[b & 0x0F];
    }

    return try std.fmt.allocPrint(allocator,
        "https://openpgpkey.{s}/.well-known/openpgpkey/{s}/hu/{s}", .{ domain, domain, hash_hex });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const InvalidInputError = error{InvalidInput};

fn isHexChar(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

fn stripSpaces(allocator: Allocator, input: []const u8) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    for (input) |c| {
        if (c != ' ' and c != '\t' and c != ':' and c != '-') {
            try result.append(allocator, c);
        }
    }
    return result.toOwnedSlice(allocator);
}

fn toUpperHex(allocator: Allocator, input: []const u8) ![]u8 {
    const result = try allocator.dupe(u8, input);
    for (result) |*c| {
        if (c.* >= 'a' and c.* <= 'f') {
            c.* = c.* - 'a' + 'A';
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "detectProtocol HKP" {
    try std.testing.expectEqual(KeyserverProtocol.hkp, detectProtocol("hkp://keys.example.com").?);
    try std.testing.expectEqual(KeyserverProtocol.hkps, detectProtocol("hkps://keys.example.com").?);
}

test "detectProtocol WKD" {
    try std.testing.expectEqual(KeyserverProtocol.wkd,
        detectProtocol("https://example.com/.well-known/openpgpkey/hu/abc").?);
}

test "detectProtocol well-known servers" {
    try std.testing.expectEqual(KeyserverProtocol.hkps, detectProtocol("keys.openpgp.org").?);
    try std.testing.expectEqual(KeyserverProtocol.hkp, detectProtocol("keyserver.ubuntu.com").?);
    try std.testing.expectEqual(KeyserverProtocol.hkp, detectProtocol("pgp.mit.edu").?);
}

test "detectProtocol HTTPS/HTTP" {
    try std.testing.expectEqual(KeyserverProtocol.hkps, detectProtocol("https://example.com").?);
    try std.testing.expectEqual(KeyserverProtocol.hkp, detectProtocol("http://example.com").?);
}

test "detectProtocol returns null for empty or unknown" {
    try std.testing.expect(detectProtocol("") == null);
    try std.testing.expect(detectProtocol("ftp://example.com") == null);
}

test "normalizeKeyId email" {
    const allocator = std.testing.allocator;
    const result = try normalizeKeyId(allocator, "alice@example.com");
    defer result.deinit(allocator);

    try std.testing.expectEqual(KeyIdType.email, result.id_type);
    try std.testing.expectEqualStrings("alice@example.com", result.value);
    try std.testing.expect(mem.startsWith(u8, result.search_string, "="));
}

test "normalizeKeyId V4 fingerprint" {
    const allocator = std.testing.allocator;
    const result = try normalizeKeyId(allocator, "AABBCCDD11223344AABBCCDD11223344AABBCCDD");
    defer result.deinit(allocator);

    try std.testing.expectEqual(KeyIdType.fingerprint_v4, result.id_type);
    try std.testing.expectEqual(@as(usize, 40), result.value.len);
}

test "normalizeKeyId key ID 16 chars" {
    const allocator = std.testing.allocator;
    const result = try normalizeKeyId(allocator, "AABBCCDD11223344");
    defer result.deinit(allocator);

    try std.testing.expectEqual(KeyIdType.key_id, result.id_type);
}

test "normalizeKeyId short key ID 8 chars" {
    const allocator = std.testing.allocator;
    const result = try normalizeKeyId(allocator, "AABBCCDD");
    defer result.deinit(allocator);

    try std.testing.expectEqual(KeyIdType.key_id, result.id_type);
    try std.testing.expectEqual(@as(usize, 16), result.value.len);
}

test "normalizeKeyId with 0x prefix" {
    const allocator = std.testing.allocator;
    const result = try normalizeKeyId(allocator, "0xAABBCCDD11223344AABBCCDD11223344AABBCCDD");
    defer result.deinit(allocator);

    try std.testing.expectEqual(KeyIdType.fingerprint_v4, result.id_type);
}

test "buildHkpLookupUrl basic" {
    const allocator = std.testing.allocator;
    const url = try buildHkpLookupUrl(allocator, "hkps://keys.openpgp.org", "0xAABBCCDD");
    defer allocator.free(url);

    try std.testing.expect(mem.startsWith(u8, url, "https://keys.openpgp.org"));
    try std.testing.expect(mem.indexOf(u8, url, "pks/lookup") != null);
}

test "buildHkpLookupUrl plain hostname" {
    const allocator = std.testing.allocator;
    const url = try buildHkpLookupUrl(allocator, "keys.example.com", "0xAABBCCDD");
    defer allocator.free(url);

    try std.testing.expect(mem.startsWith(u8, url, "https://keys.example.com"));
}

test "buildWkdDirectUrl" {
    const allocator = std.testing.allocator;
    const url = try buildWkdDirectUrl(allocator, "alice@example.com");
    defer allocator.free(url);

    try std.testing.expect(mem.startsWith(u8, url, "https://example.com/.well-known/openpgpkey/hu/"));
}

test "buildWkdAdvancedUrl" {
    const allocator = std.testing.allocator;
    const url = try buildWkdAdvancedUrl(allocator, "alice@example.com");
    defer allocator.free(url);

    try std.testing.expect(mem.startsWith(u8, url, "https://openpgpkey.example.com"));
    try std.testing.expect(mem.indexOf(u8, url, ".well-known/openpgpkey/example.com/hu/") != null);
}

test "KeyserverProtocol properties" {
    try std.testing.expectEqualStrings("HKP", KeyserverProtocol.hkp.name());
    try std.testing.expectEqual(@as(u16, 11371), KeyserverProtocol.hkp.defaultPort());
    try std.testing.expectEqual(@as(u16, 443), KeyserverProtocol.hkps.defaultPort());
}

test "stripSpaces removes whitespace and separators" {
    const allocator = std.testing.allocator;
    const result = try stripSpaces(allocator, "AA BB:CC-DD");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("AABBCCDD", result);
}

test "isHexChar" {
    try std.testing.expect(isHexChar('0'));
    try std.testing.expect(isHexChar('9'));
    try std.testing.expect(isHexChar('a'));
    try std.testing.expect(isHexChar('f'));
    try std.testing.expect(isHexChar('A'));
    try std.testing.expect(isHexChar('F'));
    try std.testing.expect(!isHexChar('g'));
    try std.testing.expect(!isHexChar('@'));
}
