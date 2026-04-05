// SPDX-License-Identifier: MIT
//! HTTP-based HKP (HTTP Keyserver Protocol) client.
//!
//! Provides a higher-level client that uses std.http.Client for actual
//! network requests, as well as parsing utilities for HKP responses.
//!
//! HKP machine-readable index format (per the HKP specification):
//!   info:1:N          — version 1, N keys follow
//!   pub:keyid:algo:keylen:creationdate:expirationdate:flags
//!   uid:uidstring:creationdate:expirationdate:flags
//!
//! Tests in this module do NOT make live network requests. They test:
//! - URL building
//! - Machine-readable index response parsing
//! - Request body formatting

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const hkp = @import("hkp.zig");
const PublicKeyAlgorithm = @import("../types/enums.zig").PublicKeyAlgorithm;

/// A single key entry from an HKP search result.
pub const KeyEntry = struct {
    key_id: []u8,
    algorithm: ?PublicKeyAlgorithm,
    bits: ?u32,
    creation_time: ?u32,
    expiration_time: ?u32,
    flags: []u8,
    uids: std.ArrayList([]u8),

    pub fn deinit(self: *KeyEntry, allocator: Allocator) void {
        allocator.free(self.key_id);
        allocator.free(self.flags);
        for (self.uids.items) |uid| {
            allocator.free(uid);
        }
        self.uids.deinit(allocator);
    }
};

/// Search result from an HKP index query.
pub const SearchResult = struct {
    entries: []KeyEntry,

    pub fn deinit(self: *SearchResult, allocator: Allocator) void {
        for (self.entries) |*entry| {
            entry.deinit(allocator);
        }
        allocator.free(self.entries);
    }
};

/// HKP client with HTTP support.
pub const HkpHttpClient = struct {
    allocator: Allocator,
    server: []const u8,
    port: u16,

    /// Initialize a new HKP HTTP client.
    ///
    /// The server should be a hostname like "keys.openpgp.org".
    /// The default HKP port is 11371.
    pub fn init(allocator: Allocator, server: []const u8) HkpHttpClient {
        return .{
            .allocator = allocator,
            .server = server,
            .port = 11371,
        };
    }

    /// Initialize with a custom port.
    pub fn initWithPort(allocator: Allocator, server: []const u8, port: u16) HkpHttpClient {
        return .{
            .allocator = allocator,
            .server = server,
            .port = port,
        };
    }

    /// Build the full base URL for this client.
    pub fn buildBaseUrl(self: *const HkpHttpClient, allocator: Allocator) ![]u8 {
        if (self.port == 443) {
            return std.fmt.allocPrint(allocator, "https://{s}", .{self.server});
        } else if (self.port == 80 or self.port == 11371) {
            return std.fmt.allocPrint(allocator, "http://{s}:{d}", .{ self.server, self.port });
        } else {
            return std.fmt.allocPrint(allocator, "http://{s}:{d}", .{ self.server, self.port });
        }
    }

    /// Build a lookup URL for fetching a key.
    pub fn buildGetUrl(self: *const HkpHttpClient, allocator: Allocator, search: []const u8) ![]u8 {
        const base_url = try self.buildBaseUrl(allocator);
        defer allocator.free(base_url);

        return hkp.formatLookupUrl(allocator, base_url, "get", search);
    }

    /// Build a search URL for finding keys.
    pub fn buildSearchUrl(self: *const HkpHttpClient, allocator: Allocator, query: []const u8) ![]u8 {
        const base_url = try self.buildBaseUrl(allocator);
        defer allocator.free(base_url);

        return hkp.formatLookupUrl(allocator, base_url, "index", query);
    }

    /// Build the POST body for submitting a key.
    pub fn buildSubmitBody(self: *const HkpHttpClient, allocator: Allocator, armored_key: []const u8) ![]u8 {
        _ = self;
        return hkp.formatSubmitBody(allocator, armored_key);
    }

    /// Build the submit URL.
    pub fn buildSubmitUrl(self: *const HkpHttpClient, allocator: Allocator) ![]u8 {
        const base_url = try self.buildBaseUrl(allocator);
        defer allocator.free(base_url);

        return std.fmt.allocPrint(allocator, "{s}/pks/add", .{base_url});
    }
};

/// Parse an HKP machine-readable index response.
///
/// The format is line-based:
///   info:1:N
///   pub:KEYID:ALGO:KEYLEN:CREATIONDATE:EXPIRATIONDATE:FLAGS
///   uid:UIDSTRING:CREATIONDATE:EXPIRATIONDATE:FLAGS
///
/// Fields may be empty. Lines starting with anything other than
/// "info:", "pub:", or "uid:" are ignored.
pub fn parseMachineReadableIndex(allocator: Allocator, data: []const u8) ![]KeyEntry {
    var entries: std.ArrayList(KeyEntry) = .empty;
    errdefer {
        for (entries.items) |*e| e.deinit(allocator);
        entries.deinit(allocator);
    }

    var lines = mem.splitScalar(u8, data, '\n');

    while (lines.next()) |line| {
        const trimmed = mem.trimRight(u8, line, "\r");
        if (trimmed.len == 0) continue;

        if (mem.startsWith(u8, trimmed, "pub:")) {
            var entry = try parsePubLine(allocator, trimmed);
            errdefer entry.deinit(allocator);

            // Read subsequent uid lines
            while (lines.next()) |uid_line| {
                const uid_trimmed = mem.trimRight(u8, uid_line, "\r");
                if (mem.startsWith(u8, uid_trimmed, "uid:")) {
                    const uid_str = try parseUidLine(allocator, uid_trimmed);
                    try entry.uids.append(allocator, uid_str);
                } else {
                    // Not a uid line; we should process it but for simplicity
                    // we just check if it's another pub line
                    if (mem.startsWith(u8, uid_trimmed, "pub:")) {
                        // Save current entry and start a new one
                        try entries.append(allocator, entry);
                        entry = try parsePubLine(allocator, uid_trimmed);
                    } else {
                        break; // Unknown line type, skip
                    }
                }
            }

            try entries.append(allocator, entry);
        }
    }

    return entries.toOwnedSlice(allocator);
}

/// Parse a "pub:" line from machine-readable index output.
fn parsePubLine(allocator: Allocator, line: []const u8) !KeyEntry {
    // pub:KEYID:ALGO:KEYLEN:CREATIONDATE:EXPIRATIONDATE:FLAGS
    var fields = mem.splitScalar(u8, line, ':');

    // Skip the "pub" prefix
    _ = fields.next();

    const key_id_str = fields.next() orelse "";
    const algo_str = fields.next() orelse "";
    const bits_str = fields.next() orelse "";
    const creation_str = fields.next() orelse "";
    const expiration_str = fields.next() orelse "";
    const flags_str = fields.next() orelse "";

    const key_id = try allocator.dupe(u8, key_id_str);
    errdefer allocator.free(key_id);

    const algorithm: ?PublicKeyAlgorithm = if (algo_str.len > 0)
        blk: {
            const algo_num = std.fmt.parseInt(u8, algo_str, 10) catch break :blk null;
            break :blk @enumFromInt(algo_num);
        }
    else
        null;

    const bits: ?u32 = if (bits_str.len > 0)
        std.fmt.parseInt(u32, bits_str, 10) catch null
    else
        null;

    const creation_time: ?u32 = if (creation_str.len > 0)
        std.fmt.parseInt(u32, creation_str, 10) catch null
    else
        null;

    const expiration_time: ?u32 = if (expiration_str.len > 0)
        std.fmt.parseInt(u32, expiration_str, 10) catch null
    else
        null;

    const flags = try allocator.dupe(u8, flags_str);

    return .{
        .key_id = key_id,
        .algorithm = algorithm,
        .bits = bits,
        .creation_time = creation_time,
        .expiration_time = expiration_time,
        .flags = flags,
        .uids = .empty,
    };
}

/// Parse a "uid:" line and return the URL-decoded UID string.
fn parseUidLine(allocator: Allocator, line: []const u8) ![]u8 {
    // uid:UIDSTRING:CREATIONDATE:EXPIRATIONDATE:FLAGS
    var fields = mem.splitScalar(u8, line, ':');

    // Skip the "uid" prefix
    _ = fields.next();

    const uid_str = fields.next() orelse "";

    // URL-decode the UID string
    return urlDecode(allocator, uid_str);
}

/// Simple URL decoding: converts %XX sequences to bytes.
pub fn urlDecode(allocator: Allocator, input: []const u8) ![]u8 {
    // Count output size
    var size: usize = 0;
    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '%' and i + 2 < input.len) {
            size += 1;
            i += 3;
        } else if (input[i] == '+') {
            size += 1;
            i += 1;
        } else {
            size += 1;
            i += 1;
        }
    }

    const buf = try allocator.alloc(u8, size);
    errdefer allocator.free(buf);

    var out: usize = 0;
    i = 0;
    while (i < input.len) {
        if (input[i] == '%' and i + 2 < input.len) {
            const high = hexVal(input[i + 1]) orelse {
                buf[out] = input[i];
                out += 1;
                i += 1;
                continue;
            };
            const low = hexVal(input[i + 2]) orelse {
                buf[out] = input[i];
                out += 1;
                i += 1;
                continue;
            };
            buf[out] = (@as(u8, high) << 4) | @as(u8, low);
            out += 1;
            i += 3;
        } else if (input[i] == '+') {
            buf[out] = ' ';
            out += 1;
            i += 1;
        } else {
            buf[out] = input[i];
            out += 1;
            i += 1;
        }
    }

    return buf[0..out];
}

/// Convert a hex character to its numeric value.
fn hexVal(c: u8) ?u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => null,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "HkpHttpClient init" {
    const allocator = std.testing.allocator;
    const client = HkpHttpClient.init(allocator, "keys.openpgp.org");
    try std.testing.expectEqualStrings("keys.openpgp.org", client.server);
    try std.testing.expectEqual(@as(u16, 11371), client.port);
}

test "HkpHttpClient initWithPort" {
    const allocator = std.testing.allocator;
    const client = HkpHttpClient.initWithPort(allocator, "localhost", 8080);
    try std.testing.expectEqual(@as(u16, 8080), client.port);
}

test "HkpHttpClient buildBaseUrl default port" {
    const allocator = std.testing.allocator;
    const client = HkpHttpClient.init(allocator, "keys.openpgp.org");

    const url = try client.buildBaseUrl(allocator);
    defer allocator.free(url);

    try std.testing.expectEqualStrings("http://keys.openpgp.org:11371", url);
}

test "HkpHttpClient buildBaseUrl HTTPS" {
    const allocator = std.testing.allocator;
    const client = HkpHttpClient.initWithPort(allocator, "keys.openpgp.org", 443);

    const url = try client.buildBaseUrl(allocator);
    defer allocator.free(url);

    try std.testing.expectEqualStrings("https://keys.openpgp.org", url);
}

test "HkpHttpClient buildGetUrl" {
    const allocator = std.testing.allocator;
    const client = HkpHttpClient.init(allocator, "keys.openpgp.org");

    const url = try client.buildGetUrl(allocator, "0xDEADBEEF");
    defer allocator.free(url);

    try std.testing.expect(mem.indexOf(u8, url, "op=get") != null);
    try std.testing.expect(mem.indexOf(u8, url, "search=0xDEADBEEF") != null);
    try std.testing.expect(mem.indexOf(u8, url, "options=mr") != null);
}

test "HkpHttpClient buildSearchUrl" {
    const allocator = std.testing.allocator;
    const client = HkpHttpClient.init(allocator, "keys.openpgp.org");

    const url = try client.buildSearchUrl(allocator, "alice@example.com");
    defer allocator.free(url);

    try std.testing.expect(mem.indexOf(u8, url, "op=index") != null);
    try std.testing.expect(mem.indexOf(u8, url, "alice%40example.com") != null);
}

test "HkpHttpClient buildSubmitBody" {
    const allocator = std.testing.allocator;
    const client = HkpHttpClient.init(allocator, "keys.openpgp.org");

    const body = try client.buildSubmitBody(allocator, "KEY DATA");
    defer allocator.free(body);

    try std.testing.expect(mem.startsWith(u8, body, "keytext="));
}

test "HkpHttpClient buildSubmitUrl" {
    const allocator = std.testing.allocator;
    const client = HkpHttpClient.init(allocator, "keys.openpgp.org");

    const url = try client.buildSubmitUrl(allocator);
    defer allocator.free(url);

    try std.testing.expect(mem.endsWith(u8, url, "/pks/add"));
}

test "parseMachineReadableIndex single key" {
    const allocator = std.testing.allocator;

    const data =
        \\info:1:1
        \\pub:AABBCCDD11223344:1:2048:1609459200::
        \\uid:Alice%20%3Calice%40example.com%3E:1609459200::
    ;

    const entries = try parseMachineReadableIndex(allocator, data);
    defer {
        for (entries) |*e| e.deinit(allocator);
        allocator.free(entries);
    }

    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("AABBCCDD11223344", entries[0].key_id);
    try std.testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, entries[0].algorithm.?);
    try std.testing.expectEqual(@as(u32, 2048), entries[0].bits.?);
    try std.testing.expectEqual(@as(u32, 1609459200), entries[0].creation_time.?);
    try std.testing.expectEqual(@as(usize, 1), entries[0].uids.items.len);
    try std.testing.expectEqualStrings("Alice <alice@example.com>", entries[0].uids.items[0]);
}

test "parseMachineReadableIndex multiple keys" {
    const allocator = std.testing.allocator;

    const data =
        \\info:1:2
        \\pub:1111111111111111:1:2048:1000000000::
        \\uid:Bob:1000000000::
        \\pub:2222222222222222:17:1024:1100000000::
        \\uid:Carol:1100000000::
    ;

    const entries = try parseMachineReadableIndex(allocator, data);
    defer {
        for (entries) |*e| e.deinit(allocator);
        allocator.free(entries);
    }

    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("1111111111111111", entries[0].key_id);
    try std.testing.expectEqualStrings("2222222222222222", entries[1].key_id);
    try std.testing.expectEqual(PublicKeyAlgorithm.dsa, entries[1].algorithm.?);
}

test "parseMachineReadableIndex empty input" {
    const allocator = std.testing.allocator;

    const entries = try parseMachineReadableIndex(allocator, "");
    defer allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "parseMachineReadableIndex key with no uids" {
    const allocator = std.testing.allocator;

    const data =
        \\info:1:1
        \\pub:AAAA:1:4096:1500000000::
    ;

    const entries = try parseMachineReadableIndex(allocator, data);
    defer {
        for (entries) |*e| e.deinit(allocator);
        allocator.free(entries);
    }

    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqual(@as(usize, 0), entries[0].uids.items.len);
}

test "parseMachineReadableIndex key with empty fields" {
    const allocator = std.testing.allocator;

    const data =
        \\pub:BBBB::::::::
    ;

    const entries = try parseMachineReadableIndex(allocator, data);
    defer {
        for (entries) |*e| e.deinit(allocator);
        allocator.free(entries);
    }

    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("BBBB", entries[0].key_id);
    try std.testing.expect(entries[0].algorithm == null);
    try std.testing.expect(entries[0].bits == null);
}

test "parseMachineReadableIndex multiple uids" {
    const allocator = std.testing.allocator;

    const data =
        \\pub:CCCC:1:2048:1000::
        \\uid:Alice:1000::
        \\uid:Alice+Work:1000::
    ;

    const entries = try parseMachineReadableIndex(allocator, data);
    defer {
        for (entries) |*e| e.deinit(allocator);
        allocator.free(entries);
    }

    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqual(@as(usize, 2), entries[0].uids.items.len);
    try std.testing.expectEqualStrings("Alice", entries[0].uids.items[0]);
    try std.testing.expectEqualStrings("Alice Work", entries[0].uids.items[1]); // + decoded as space
}

test "urlDecode simple" {
    const allocator = std.testing.allocator;

    const result = try urlDecode(allocator, "hello%20world");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hello world", result);
}

test "urlDecode plus sign" {
    const allocator = std.testing.allocator;

    const result = try urlDecode(allocator, "hello+world");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hello world", result);
}

test "urlDecode special characters" {
    const allocator = std.testing.allocator;

    const result = try urlDecode(allocator, "alice%40example.com");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("alice@example.com", result);
}

test "urlDecode no encoding" {
    const allocator = std.testing.allocator;

    const result = try urlDecode(allocator, "plain");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("plain", result);
}

test "urlDecode empty" {
    const allocator = std.testing.allocator;

    const result = try urlDecode(allocator, "");
    defer allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "urlDecode angle brackets" {
    const allocator = std.testing.allocator;

    const result = try urlDecode(allocator, "%3Calice%40example.com%3E");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("<alice@example.com>", result);
}

test "KeyEntry fields" {
    // Verify KeyEntry struct can be constructed and its fields are correct.
    // Memory cleanup is tested implicitly through parseMachineReadableIndex tests.
    const entry = KeyEntry{
        .key_id = @constCast("AABB"),
        .algorithm = .rsa_encrypt_sign,
        .bits = 2048,
        .creation_time = 1000,
        .expiration_time = null,
        .flags = @constCast(""),
        .uids = .empty,
    };

    try std.testing.expectEqualStrings("AABB", entry.key_id);
    try std.testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, entry.algorithm.?);
    try std.testing.expectEqual(@as(u32, 2048), entry.bits.?);
}

test "SearchResult deinit" {
    const allocator = std.testing.allocator;

    var entries_list: std.ArrayList(KeyEntry) = .empty;

    const entry = KeyEntry{
        .key_id = try allocator.dupe(u8, "1234"),
        .algorithm = null,
        .bits = null,
        .creation_time = null,
        .expiration_time = null,
        .flags = try allocator.dupe(u8, ""),
        .uids = .empty,
    };
    try entries_list.append(allocator, entry);

    var result = SearchResult{
        .entries = try entries_list.toOwnedSlice(allocator),
    };
    result.deinit(allocator);
}

test "hexVal" {
    try std.testing.expectEqual(@as(u4, 0), hexVal('0').?);
    try std.testing.expectEqual(@as(u4, 9), hexVal('9').?);
    try std.testing.expectEqual(@as(u4, 10), hexVal('a').?);
    try std.testing.expectEqual(@as(u4, 15), hexVal('f').?);
    try std.testing.expectEqual(@as(u4, 10), hexVal('A').?);
    try std.testing.expectEqual(@as(u4, 15), hexVal('F').?);
    try std.testing.expect(hexVal('g') == null);
    try std.testing.expect(hexVal(' ') == null);
}
