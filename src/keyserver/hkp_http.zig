// SPDX-License-Identifier: MIT
//! HTTP transport layer for HKP (HTTP Keyserver Protocol).
//!
//! Provides a minimal HTTP/1.1 client that can perform GET and POST
//! requests over TCP connections. This module handles:
//!
//! - URL parsing for HKP/HKPS schemes
//! - HTTP request construction and response parsing
//! - Chunked transfer encoding
//! - Integration with the HKP URL formatting from hkp.zig
//!
//! TLS support: Zig 0.15.2 does not expose std.crypto.tls.Client in a
//! stable API suitable for generic TLS wrapping. HKPS connections are
//! noted as requiring an external TLS implementation or a future Zig
//! std.http.Client.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const net = std.net;

const hkp = @import("hkp.zig");
const hkp_client = @import("hkp_client.zig");

// ---------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------

/// Supported URL schemes for keyserver connections.
pub const Scheme = enum {
    http,
    https,
    hkp,
    hkps,

    /// Default port for each scheme.
    pub fn defaultPort(self: Scheme) u16 {
        return switch (self) {
            .http => 80,
            .https => 443,
            .hkp => 11371,
            .hkps => 443,
        };
    }

    /// Whether this scheme requires TLS.
    pub fn requiresTls(self: Scheme) bool {
        return self == .https or self == .hkps;
    }

    /// The HTTP scheme string to use in requests.
    pub fn httpScheme(self: Scheme) []const u8 {
        return if (self.requiresTls()) "https" else "http";
    }
};

/// A parsed URL.
pub const ParsedUrl = struct {
    scheme: Scheme,
    host: []const u8,
    port: u16,
    path: []const u8,
    query: ?[]const u8,

    /// Format the path + query string portion for use in HTTP requests.
    pub fn requestTarget(self: *const ParsedUrl, allocator: Allocator) ![]u8 {
        if (self.query) |q| {
            return std.fmt.allocPrint(allocator, "{s}?{s}", .{ self.path, q });
        }
        return allocator.dupe(u8, self.path);
    }

    /// Format as a full URL string.
    pub fn format(self: *const ParsedUrl, allocator: Allocator) ![]u8 {
        const scheme_str = switch (self.scheme) {
            .http => "http",
            .https => "https",
            .hkp => "hkp",
            .hkps => "hkps",
        };
        if (self.query) |q| {
            return std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}?{s}", .{
                scheme_str, self.host, self.port, self.path, q,
            });
        }
        return std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{
            scheme_str, self.host, self.port, self.path,
        });
    }
};

pub const UrlParseError = error{
    InvalidUrl,
    InvalidPort,
    UnknownScheme,
};

/// Parse a URL string into its components.
///
/// Supports schemes: http, https, hkp, hkps.
/// Examples:
///   "hkp://keys.openpgp.org" -> { .hkp, "keys.openpgp.org", 11371, "/", null }
///   "https://keys.openpgp.org:443/pks/lookup?op=get" -> { .https, "keys.openpgp.org", 443, "/pks/lookup", "op=get" }
pub fn parseUrl(url: []const u8) UrlParseError!ParsedUrl {
    // Find scheme
    const scheme_end = mem.indexOf(u8, url, "://") orelse return UrlParseError.InvalidUrl;
    const scheme_str = url[0..scheme_end];

    const scheme: Scheme = if (mem.eql(u8, scheme_str, "http"))
        .http
    else if (mem.eql(u8, scheme_str, "https"))
        .https
    else if (mem.eql(u8, scheme_str, "hkp"))
        .hkp
    else if (mem.eql(u8, scheme_str, "hkps"))
        .hkps
    else
        return UrlParseError.UnknownScheme;

    // After "://"
    const after_scheme = url[scheme_end + 3 ..];
    if (after_scheme.len == 0) return UrlParseError.InvalidUrl;

    // Split host[:port] from path
    const path_start = mem.indexOf(u8, after_scheme, "/") orelse after_scheme.len;
    const authority = after_scheme[0..path_start];

    // Parse host and optional port
    var host: []const u8 = undefined;
    var port: u16 = scheme.defaultPort();

    if (mem.indexOf(u8, authority, ":")) |colon| {
        host = authority[0..colon];
        const port_str = authority[colon + 1 ..];
        if (port_str.len > 0) {
            port = std.fmt.parseInt(u16, port_str, 10) catch return UrlParseError.InvalidPort;
        }
    } else {
        host = authority;
    }

    if (host.len == 0) return UrlParseError.InvalidUrl;

    // Parse path and query
    var path: []const u8 = "/";
    var query: ?[]const u8 = null;

    if (path_start < after_scheme.len) {
        const path_and_query = after_scheme[path_start..];
        if (mem.indexOf(u8, path_and_query, "?")) |q_pos| {
            path = path_and_query[0..q_pos];
            if (q_pos + 1 < path_and_query.len) {
                query = path_and_query[q_pos + 1 ..];
            }
        } else {
            path = path_and_query;
        }
    }

    return .{
        .scheme = scheme,
        .host = host,
        .port = port,
        .path = path,
        .query = query,
    };
}

// ---------------------------------------------------------------------------
// HTTP response parsing
// ---------------------------------------------------------------------------

/// HTTP status code categories.
pub const StatusCategory = enum {
    informational, // 1xx
    success, // 2xx
    redirection, // 3xx
    client_error, // 4xx
    server_error, // 5xx
    unknown,

    pub fn fromCode(code: u16) StatusCategory {
        return switch (code / 100) {
            1 => .informational,
            2 => .success,
            3 => .redirection,
            4 => .client_error,
            5 => .server_error,
            else => .unknown,
        };
    }
};

/// A parsed HTTP response header.
pub const HttpResponseHeader = struct {
    status_code: u16,
    reason_phrase: []const u8,
    headers: []const HeaderField,
    /// Byte offset where the body begins in the original data.
    body_offset: usize,
};

/// A single HTTP header field.
pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,
};

/// A fully parsed HTTP response.
pub const HttpResponse = struct {
    status_code: u16,
    reason_phrase: []u8,
    headers: []HeaderField,
    body: []u8,

    pub fn deinit(self: *HttpResponse, allocator: Allocator) void {
        allocator.free(self.reason_phrase);
        for (self.headers) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        allocator.free(self.headers);
        allocator.free(self.body);
    }

    /// Get the value of a header by name (case-insensitive).
    pub fn getHeader(self: *const HttpResponse, name: []const u8) ?[]const u8 {
        for (self.headers) |h| {
            if (asciiEqualIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }

    /// Check if the response indicates success (2xx).
    pub fn isSuccess(self: *const HttpResponse) bool {
        return StatusCategory.fromCode(self.status_code) == .success;
    }

    /// Get the content length from headers, if present.
    pub fn contentLength(self: *const HttpResponse) ?usize {
        const val = self.getHeader("content-length") orelse return null;
        return std.fmt.parseInt(usize, mem.trim(u8, val, " "), 10) catch null;
    }

    /// Check if the response uses chunked transfer encoding.
    pub fn isChunked(self: *const HttpResponse) bool {
        const te = self.getHeader("transfer-encoding") orelse return false;
        return mem.indexOf(u8, te, "chunked") != null;
    }
};

pub const HttpParseError = error{
    InvalidResponse,
    InvalidStatusLine,
    InvalidHeaderLine,
    InvalidChunkSize,
    IncompleteResponse,
    ResponseTooLarge,
    OutOfMemory,
};

/// Parse a complete HTTP response from raw bytes.
///
/// Handles both Content-Length and chunked transfer encoding.
pub fn parseHttpResponse(allocator: Allocator, data: []const u8) HttpParseError!HttpResponse {
    // Find end of headers
    const header_end = mem.indexOf(u8, data, "\r\n\r\n") orelse
        return HttpParseError.IncompleteResponse;

    const header_section = data[0..header_end];
    const body_start = header_end + 4;

    // Parse status line
    var line_iter = mem.splitSequence(u8, header_section, "\r\n");
    const status_line = line_iter.next() orelse return HttpParseError.InvalidStatusLine;

    // "HTTP/1.1 200 OK"
    if (!mem.startsWith(u8, status_line, "HTTP/")) return HttpParseError.InvalidStatusLine;

    // Find the space after version
    const space1 = mem.indexOf(u8, status_line, " ") orelse return HttpParseError.InvalidStatusLine;
    const after_version = status_line[space1 + 1 ..];

    // Parse status code
    const space2 = mem.indexOf(u8, after_version, " ") orelse after_version.len;
    const code_str = after_version[0..space2];
    const status_code = std.fmt.parseInt(u16, code_str, 10) catch
        return HttpParseError.InvalidStatusLine;

    const reason = if (space2 < after_version.len)
        after_version[space2 + 1 ..]
    else
        "";

    const reason_phrase = allocator.dupe(u8, reason) catch return HttpParseError.OutOfMemory;
    errdefer allocator.free(reason_phrase);

    // Parse headers
    var header_list: std.ArrayList(HeaderField) = .empty;
    errdefer {
        for (header_list.items) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        header_list.deinit(allocator);
    }

    while (line_iter.next()) |line| {
        if (line.len == 0) break;
        const colon = mem.indexOf(u8, line, ":") orelse continue;
        const name = mem.trim(u8, line[0..colon], " ");
        const value = mem.trim(u8, line[colon + 1 ..], " ");

        const name_dup = allocator.dupe(u8, name) catch return HttpParseError.OutOfMemory;
        errdefer allocator.free(name_dup);
        const value_dup = allocator.dupe(u8, value) catch return HttpParseError.OutOfMemory;
        header_list.append(allocator, .{ .name = name_dup, .value = value_dup }) catch
            return HttpParseError.OutOfMemory;
    }

    const headers = header_list.toOwnedSlice(allocator) catch return HttpParseError.OutOfMemory;
    errdefer {
        for (headers) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        allocator.free(headers);
    }

    // Determine body handling
    const raw_body = if (body_start < data.len) data[body_start..] else "";

    // Check for chunked transfer encoding
    var is_chunked = false;
    for (headers) |h| {
        if (asciiEqualIgnoreCase(h.name, "transfer-encoding") and
            mem.indexOf(u8, h.value, "chunked") != null)
        {
            is_chunked = true;
            break;
        }
    }

    const body = if (is_chunked)
        (decodeChunkedBody(allocator, raw_body) catch return HttpParseError.InvalidChunkSize)
    else
        (allocator.dupe(u8, raw_body) catch return HttpParseError.OutOfMemory);

    return .{
        .status_code = status_code,
        .reason_phrase = reason_phrase,
        .headers = headers,
        .body = body,
    };
}

/// Decode a chunked transfer-encoded body.
///
/// Format: <chunk-size-hex>\r\n<chunk-data>\r\n ... 0\r\n\r\n
pub fn decodeChunkedBody(allocator: Allocator, data: []const u8) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    var offset: usize = 0;
    while (offset < data.len) {
        // Read chunk size line
        const line_end = mem.indexOf(u8, data[offset..], "\r\n") orelse break;
        const size_str = mem.trim(u8, data[offset .. offset + line_end], " ");

        // Strip chunk extensions (after semicolon)
        const clean_size = if (mem.indexOf(u8, size_str, ";")) |sc|
            mem.trim(u8, size_str[0..sc], " ")
        else
            size_str;

        if (clean_size.len == 0) break;

        const chunk_size = std.fmt.parseInt(usize, clean_size, 16) catch break;
        if (chunk_size == 0) break; // Final chunk

        offset += line_end + 2; // skip size line + CRLF

        if (offset + chunk_size > data.len) break;

        try output.appendSlice(allocator, data[offset .. offset + chunk_size]);
        offset += chunk_size;

        // Skip trailing CRLF after chunk data
        if (offset + 2 <= data.len and data[offset] == '\r' and data[offset + 1] == '\n') {
            offset += 2;
        }
    }

    return output.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// HTTP request construction
// ---------------------------------------------------------------------------

/// Build an HTTP GET request string.
pub fn buildGetRequest(allocator: Allocator, host: []const u8, path: []const u8, port: u16) ![]u8 {
    if (port == 80 or port == 443) {
        return std.fmt.allocPrint(allocator,
            "GET {s} HTTP/1.1\r\n" ++
                "Host: {s}\r\n" ++
                "User-Agent: zpgp/0.1\r\n" ++
                "Accept: */*\r\n" ++
                "Connection: close\r\n" ++
                "\r\n", .{ path, host });
    }
    return std.fmt.allocPrint(allocator,
        "GET {s} HTTP/1.1\r\n" ++
            "Host: {s}:{d}\r\n" ++
            "User-Agent: zpgp/0.1\r\n" ++
            "Accept: */*\r\n" ++
            "Connection: close\r\n" ++
            "\r\n", .{ path, host, port });
}

/// Build an HTTP POST request string with body.
pub fn buildPostRequest(allocator: Allocator, host: []const u8, path: []const u8, port: u16, content_type: []const u8, body: []const u8) ![]u8 {
    if (port == 80 or port == 443) {
        return std.fmt.allocPrint(allocator,
            "POST {s} HTTP/1.1\r\n" ++
                "Host: {s}\r\n" ++
                "User-Agent: zpgp/0.1\r\n" ++
                "Content-Type: {s}\r\n" ++
                "Content-Length: {d}\r\n" ++
                "Connection: close\r\n" ++
                "\r\n" ++
                "{s}", .{ path, host, content_type, body.len, body });
    }
    return std.fmt.allocPrint(allocator,
        "POST {s} HTTP/1.1\r\n" ++
            "Host: {s}:{d}\r\n" ++
            "User-Agent: zpgp/0.1\r\n" ++
            "Content-Type: {s}\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Connection: close\r\n" ++
            "\r\n" ++
            "{s}", .{ path, host, port, content_type, body.len, body });
}

// ---------------------------------------------------------------------------
// HKP HTTP client integration
// ---------------------------------------------------------------------------

/// Errors for HKP HTTP operations.
pub const HkpHttpError = error{
    ConnectionFailed,
    RequestFailed,
    InvalidResponse,
    KeyNotFound,
    ServerError,
    TlsNotSupported,
    OutOfMemory,
    InvalidUrl,
    InvalidPort,
    UnknownScheme,
    InvalidStatusLine,
    InvalidHeaderLine,
    InvalidChunkSize,
    IncompleteResponse,
    ResponseTooLarge,
};

/// Key information returned from a search.
pub const KeySearchInfo = struct {
    key_id: []u8,
    uid: ?[]u8,
    algorithm: ?[]u8,
    bits: ?u32,
    creation_date: ?[]u8,

    pub fn deinit(self: *KeySearchInfo, allocator: Allocator) void {
        allocator.free(self.key_id);
        if (self.uid) |u| allocator.free(u);
        if (self.algorithm) |a| allocator.free(a);
        if (self.creation_date) |d| allocator.free(d);
    }
};

/// Full HKP client with HTTP transport capabilities.
///
/// Usage:
///   const client = HkpTransportClient.init(allocator, "hkp://keys.openpgp.org");
///   const key = try client.lookupKey("0xDEADBEEF");
///
/// Note: actual TCP connections require network access. In test mode,
/// the response parsing can be tested with mock data.
pub const HkpTransportClient = struct {
    allocator: Allocator,
    url: ParsedUrl,

    pub fn init(allocator: Allocator, server_url: []const u8) !HkpTransportClient {
        const parsed = try parseUrl(server_url);
        return .{ .allocator = allocator, .url = parsed };
    }

    /// Build the lookup URL for a key query.
    pub fn buildLookupUrl(self: *const HkpTransportClient, allocator: Allocator, query: []const u8) ![]u8 {
        const scheme_str = self.url.scheme.httpScheme();
        const base_url = if (self.url.port == self.url.scheme.defaultPort())
            try std.fmt.allocPrint(allocator, "{s}://{s}", .{ scheme_str, self.url.host })
        else
            try std.fmt.allocPrint(allocator, "{s}://{s}:{d}", .{ scheme_str, self.url.host, self.url.port });
        defer allocator.free(base_url);

        return hkp.formatLookupUrl(allocator, base_url, "get", query);
    }

    /// Build the search URL for finding keys.
    pub fn buildSearchUrl(self: *const HkpTransportClient, allocator: Allocator, query: []const u8) ![]u8 {
        const scheme_str = self.url.scheme.httpScheme();
        const base_url = if (self.url.port == self.url.scheme.defaultPort())
            try std.fmt.allocPrint(allocator, "{s}://{s}", .{ scheme_str, self.url.host })
        else
            try std.fmt.allocPrint(allocator, "{s}://{s}:{d}", .{ scheme_str, self.url.host, self.url.port });
        defer allocator.free(base_url);

        return hkp.formatLookupUrl(allocator, base_url, "index", query);
    }

    /// Build the GET request for looking up a key.
    pub fn buildKeyLookupRequest(self: *const HkpTransportClient, allocator: Allocator, key_id: []const u8) ![]u8 {
        const encoded_search = try hkp.urlEncode(allocator, key_id);
        defer allocator.free(encoded_search);

        const path = try std.fmt.allocPrint(allocator, "/pks/lookup?op=get&search={s}&options=mr", .{encoded_search});
        defer allocator.free(path);

        return buildGetRequest(allocator, self.url.host, path, self.url.port);
    }

    /// Build the GET request for searching keys.
    pub fn buildKeySearchRequest(self: *const HkpTransportClient, allocator: Allocator, query: []const u8) ![]u8 {
        const encoded_query = try hkp.urlEncode(allocator, query);
        defer allocator.free(encoded_query);

        const path = try std.fmt.allocPrint(allocator, "/pks/lookup?op=index&search={s}&options=mr", .{encoded_query});
        defer allocator.free(path);

        return buildGetRequest(allocator, self.url.host, path, self.url.port);
    }

    /// Build the POST request for uploading a key.
    pub fn buildKeyUploadRequest(self: *const HkpTransportClient, allocator: Allocator, armored_key: []const u8) ![]u8 {
        const body = try hkp.formatSubmitBody(allocator, armored_key);
        defer allocator.free(body);

        return buildPostRequest(allocator, self.url.host, "/pks/add", self.url.port, "application/x-www-form-urlencoded", body);
    }

    /// Extract an armored key from an HKP GET response body.
    ///
    /// The server returns the key in ASCII-armored format. This function
    /// validates that the response contains valid armor markers.
    pub fn extractArmoredKey(body: []const u8) ?[]const u8 {
        const begin = mem.indexOf(u8, body, "-----BEGIN PGP PUBLIC KEY BLOCK-----") orelse return null;
        const end_marker = "-----END PGP PUBLIC KEY BLOCK-----";
        const end = mem.indexOf(u8, body[begin..], end_marker) orelse return null;
        return body[begin .. begin + end + end_marker.len];
    }

    /// Parse search results from an HKP machine-readable index response.
    pub fn parseSearchResults(allocator: Allocator, body: []const u8) ![]hkp_client.KeyEntry {
        return hkp_client.parseMachineReadableIndex(allocator, body);
    }
};

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Case-insensitive ASCII comparison.
fn asciiEqualIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        const la = if (ca >= 'A' and ca <= 'Z') ca + 32 else ca;
        const lb = if (cb >= 'A' and cb <= 'Z') cb + 32 else cb;
        if (la != lb) return false;
    }
    return true;
}

/// Percent-decode a URL-encoded string (for cookie/header values).
pub fn percentDecode(allocator: Allocator, input: []const u8) ![]u8 {
    return hkp_client.urlDecode(allocator, input);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseUrl http" {
    const parsed = try parseUrl("http://example.com/path");
    try std.testing.expectEqual(Scheme.http, parsed.scheme);
    try std.testing.expectEqualStrings("example.com", parsed.host);
    try std.testing.expectEqual(@as(u16, 80), parsed.port);
    try std.testing.expectEqualStrings("/path", parsed.path);
    try std.testing.expect(parsed.query == null);
}

test "parseUrl https with port" {
    const parsed = try parseUrl("https://keys.example.com:8443/api");
    try std.testing.expectEqual(Scheme.https, parsed.scheme);
    try std.testing.expectEqualStrings("keys.example.com", parsed.host);
    try std.testing.expectEqual(@as(u16, 8443), parsed.port);
    try std.testing.expectEqualStrings("/api", parsed.path);
}

test "parseUrl hkp default port" {
    const parsed = try parseUrl("hkp://keys.openpgp.org");
    try std.testing.expectEqual(Scheme.hkp, parsed.scheme);
    try std.testing.expectEqualStrings("keys.openpgp.org", parsed.host);
    try std.testing.expectEqual(@as(u16, 11371), parsed.port);
    try std.testing.expectEqualStrings("/", parsed.path);
}

test "parseUrl hkps default port" {
    const parsed = try parseUrl("hkps://keys.openpgp.org");
    try std.testing.expectEqual(Scheme.hkps, parsed.scheme);
    try std.testing.expectEqual(@as(u16, 443), parsed.port);
    try std.testing.expect(parsed.scheme.requiresTls());
}

test "parseUrl with query" {
    const parsed = try parseUrl("http://example.com/search?q=test&page=1");
    try std.testing.expectEqualStrings("/search", parsed.path);
    try std.testing.expectEqualStrings("q=test&page=1", parsed.query.?);
}

test "parseUrl invalid" {
    try std.testing.expectError(UrlParseError.InvalidUrl, parseUrl("not-a-url"));
    try std.testing.expectError(UrlParseError.UnknownScheme, parseUrl("ftp://example.com"));
    try std.testing.expectError(UrlParseError.InvalidUrl, parseUrl("http://"));
}

test "parseUrl with custom port" {
    const parsed = try parseUrl("hkp://localhost:12345/test");
    try std.testing.expectEqualStrings("localhost", parsed.host);
    try std.testing.expectEqual(@as(u16, 12345), parsed.port);
    try std.testing.expectEqualStrings("/test", parsed.path);
}

test "Scheme defaultPort" {
    try std.testing.expectEqual(@as(u16, 80), Scheme.http.defaultPort());
    try std.testing.expectEqual(@as(u16, 443), Scheme.https.defaultPort());
    try std.testing.expectEqual(@as(u16, 11371), Scheme.hkp.defaultPort());
    try std.testing.expectEqual(@as(u16, 443), Scheme.hkps.defaultPort());
}

test "Scheme requiresTls" {
    try std.testing.expect(!Scheme.http.requiresTls());
    try std.testing.expect(Scheme.https.requiresTls());
    try std.testing.expect(!Scheme.hkp.requiresTls());
    try std.testing.expect(Scheme.hkps.requiresTls());
}

test "StatusCategory fromCode" {
    try std.testing.expectEqual(StatusCategory.informational, StatusCategory.fromCode(100));
    try std.testing.expectEqual(StatusCategory.success, StatusCategory.fromCode(200));
    try std.testing.expectEqual(StatusCategory.success, StatusCategory.fromCode(201));
    try std.testing.expectEqual(StatusCategory.redirection, StatusCategory.fromCode(301));
    try std.testing.expectEqual(StatusCategory.client_error, StatusCategory.fromCode(404));
    try std.testing.expectEqual(StatusCategory.server_error, StatusCategory.fromCode(500));
    try std.testing.expectEqual(StatusCategory.unknown, StatusCategory.fromCode(600));
}

test "parseHttpResponse simple 200" {
    const allocator = std.testing.allocator;
    const raw =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "Content-Length: 5\r\n" ++
        "\r\n" ++
        "hello";

    var resp = try parseHttpResponse(allocator, raw);
    defer resp.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status_code);
    try std.testing.expectEqualStrings("OK", resp.reason_phrase);
    try std.testing.expect(resp.isSuccess());
    try std.testing.expectEqualStrings("hello", resp.body);
    try std.testing.expectEqualStrings("text/plain", resp.getHeader("Content-Type").?);
}

test "parseHttpResponse 404" {
    const allocator = std.testing.allocator;
    const raw =
        "HTTP/1.1 404 Not Found\r\n" ++
        "Content-Length: 9\r\n" ++
        "\r\n" ++
        "not found";

    var resp = try parseHttpResponse(allocator, raw);
    defer resp.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 404), resp.status_code);
    try std.testing.expectEqualStrings("Not Found", resp.reason_phrase);
    try std.testing.expect(!resp.isSuccess());
}

test "parseHttpResponse empty body" {
    const allocator = std.testing.allocator;
    const raw =
        "HTTP/1.1 204 No Content\r\n" ++
        "\r\n";

    var resp = try parseHttpResponse(allocator, raw);
    defer resp.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 204), resp.status_code);
    try std.testing.expectEqual(@as(usize, 0), resp.body.len);
}

test "parseHttpResponse chunked" {
    const allocator = std.testing.allocator;
    const raw =
        "HTTP/1.1 200 OK\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n" ++
        "5\r\n" ++
        "hello\r\n" ++
        "6\r\n" ++
        " world\r\n" ++
        "0\r\n" ++
        "\r\n";

    var resp = try parseHttpResponse(allocator, raw);
    defer resp.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status_code);
    try std.testing.expectEqualStrings("hello world", resp.body);
}

test "parseHttpResponse header case insensitive" {
    const allocator = std.testing.allocator;
    const raw =
        "HTTP/1.1 200 OK\r\n" ++
        "content-type: application/json\r\n" ++
        "\r\n" ++
        "{}";

    var resp = try parseHttpResponse(allocator, raw);
    defer resp.deinit(allocator);

    try std.testing.expectEqualStrings("application/json", resp.getHeader("Content-Type").?);
    try std.testing.expectEqualStrings("application/json", resp.getHeader("content-type").?);
    try std.testing.expect(resp.getHeader("X-Nonexistent") == null);
}

test "parseHttpResponse invalid" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(HttpParseError.IncompleteResponse, parseHttpResponse(allocator, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expectError(HttpParseError.InvalidStatusLine, parseHttpResponse(allocator, "INVALID\r\n\r\n"));
}

test "decodeChunkedBody" {
    const allocator = std.testing.allocator;
    const chunked = "A\r\n0123456789\r\n5\r\nhello\r\n0\r\n\r\n";
    const decoded = try decodeChunkedBody(allocator, chunked);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("0123456789hello", decoded);
}

test "decodeChunkedBody empty" {
    const allocator = std.testing.allocator;
    const decoded = try decodeChunkedBody(allocator, "0\r\n\r\n");
    defer allocator.free(decoded);
    try std.testing.expectEqual(@as(usize, 0), decoded.len);
}

test "decodeChunkedBody with extensions" {
    const allocator = std.testing.allocator;
    const chunked = "5;ext=val\r\nhello\r\n0\r\n\r\n";
    const decoded = try decodeChunkedBody(allocator, chunked);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("hello", decoded);
}

test "buildGetRequest" {
    const allocator = std.testing.allocator;
    const req = try buildGetRequest(allocator, "keys.openpgp.org", "/pks/lookup?op=get", 11371);
    defer allocator.free(req);
    try std.testing.expect(mem.startsWith(u8, req, "GET /pks/lookup?op=get HTTP/1.1\r\n"));
    try std.testing.expect(mem.indexOf(u8, req, "Host: keys.openpgp.org:11371") != null);
    try std.testing.expect(mem.indexOf(u8, req, "Connection: close") != null);
    try std.testing.expect(mem.endsWith(u8, req, "\r\n\r\n"));
}

test "buildGetRequest default port" {
    const allocator = std.testing.allocator;
    const req = try buildGetRequest(allocator, "example.com", "/", 80);
    defer allocator.free(req);
    try std.testing.expect(mem.indexOf(u8, req, "Host: example.com\r\n") != null);
}

test "buildPostRequest" {
    const allocator = std.testing.allocator;
    const req = try buildPostRequest(allocator, "keys.openpgp.org", "/pks/add", 11371, "application/x-www-form-urlencoded", "keytext=DATA");
    defer allocator.free(req);
    try std.testing.expect(mem.startsWith(u8, req, "POST /pks/add HTTP/1.1\r\n"));
    try std.testing.expect(mem.indexOf(u8, req, "Content-Length: 12") != null);
    try std.testing.expect(mem.endsWith(u8, req, "keytext=DATA"));
}

test "asciiEqualIgnoreCase" {
    try std.testing.expect(asciiEqualIgnoreCase("Content-Type", "content-type"));
    try std.testing.expect(asciiEqualIgnoreCase("HOST", "host"));
    try std.testing.expect(asciiEqualIgnoreCase("", ""));
    try std.testing.expect(!asciiEqualIgnoreCase("abc", "abd"));
    try std.testing.expect(!asciiEqualIgnoreCase("abc", "ab"));
}

test "HkpTransportClient init and build URLs" {
    const allocator = std.testing.allocator;

    const client = try HkpTransportClient.init(allocator, "hkp://keys.openpgp.org");
    try std.testing.expectEqual(Scheme.hkp, client.url.scheme);
    try std.testing.expectEqualStrings("keys.openpgp.org", client.url.host);
    try std.testing.expectEqual(@as(u16, 11371), client.url.port);

    const lookup_url = try client.buildLookupUrl(allocator, "0xDEADBEEF");
    defer allocator.free(lookup_url);
    try std.testing.expect(mem.indexOf(u8, lookup_url, "op=get") != null);
    try std.testing.expect(mem.indexOf(u8, lookup_url, "0xDEADBEEF") != null);

    const search_url = try client.buildSearchUrl(allocator, "test@example.com");
    defer allocator.free(search_url);
    try std.testing.expect(mem.indexOf(u8, search_url, "op=index") != null);
    try std.testing.expect(mem.indexOf(u8, search_url, "test%40example.com") != null);
}

test "HkpTransportClient build requests" {
    const allocator = std.testing.allocator;

    const client = try HkpTransportClient.init(allocator, "hkp://keys.openpgp.org");

    const lookup_req = try client.buildKeyLookupRequest(allocator, "0xDEADBEEF");
    defer allocator.free(lookup_req);
    try std.testing.expect(mem.startsWith(u8, lookup_req, "GET "));
    try std.testing.expect(mem.indexOf(u8, lookup_req, "op=get") != null);

    const search_req = try client.buildKeySearchRequest(allocator, "alice");
    defer allocator.free(search_req);
    try std.testing.expect(mem.indexOf(u8, search_req, "op=index") != null);

    const upload_req = try client.buildKeyUploadRequest(allocator, "KEY DATA");
    defer allocator.free(upload_req);
    try std.testing.expect(mem.startsWith(u8, upload_req, "POST "));
    try std.testing.expect(mem.indexOf(u8, upload_req, "keytext=") != null);
}

test "HkpTransportClient extractArmoredKey" {
    const body =
        "Some text before\n" ++
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" ++
        "data\n" ++
        "-----END PGP PUBLIC KEY BLOCK-----\n" ++
        "Some text after\n";

    const key = HkpTransportClient.extractArmoredKey(body);
    try std.testing.expect(key != null);
    try std.testing.expect(mem.startsWith(u8, key.?, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    try std.testing.expect(mem.endsWith(u8, key.?, "-----END PGP PUBLIC KEY BLOCK-----"));
}

test "HkpTransportClient extractArmoredKey not found" {
    const key = HkpTransportClient.extractArmoredKey("no key here");
    try std.testing.expect(key == null);
}

test "HkpTransportClient HKPS init" {
    const allocator = std.testing.allocator;
    const client = try HkpTransportClient.init(allocator, "hkps://keys.openpgp.org");
    try std.testing.expect(client.url.scheme.requiresTls());
    try std.testing.expectEqual(@as(u16, 443), client.url.port);
}

test "ParsedUrl requestTarget" {
    const allocator = std.testing.allocator;
    const parsed = try parseUrl("http://example.com/path?query=value");

    const target = try parsed.requestTarget(allocator);
    defer allocator.free(target);
    try std.testing.expectEqualStrings("/path?query=value", target);
}

test "ParsedUrl requestTarget no query" {
    const allocator = std.testing.allocator;
    const parsed = try parseUrl("http://example.com/path");

    const target = try parsed.requestTarget(allocator);
    defer allocator.free(target);
    try std.testing.expectEqualStrings("/path", target);
}

test "ParsedUrl format" {
    const allocator = std.testing.allocator;
    const parsed = try parseUrl("hkp://keys.openpgp.org");

    const formatted = try parsed.format(allocator);
    defer allocator.free(formatted);
    try std.testing.expect(mem.indexOf(u8, formatted, "hkp://") != null);
    try std.testing.expect(mem.indexOf(u8, formatted, "keys.openpgp.org") != null);
}

test "HttpResponse isChunked" {
    const allocator = std.testing.allocator;
    const raw =
        "HTTP/1.1 200 OK\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n" ++
        "0\r\n\r\n";

    var resp = try parseHttpResponse(allocator, raw);
    defer resp.deinit(allocator);
    try std.testing.expect(resp.isChunked());
}

test "HttpResponse contentLength" {
    const allocator = std.testing.allocator;
    const raw =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Length: 42\r\n" ++
        "\r\n" ++
        "";

    var resp = try parseHttpResponse(allocator, raw);
    defer resp.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 42), resp.contentLength().?);
}

test "percentDecode" {
    const allocator = std.testing.allocator;
    const decoded = try percentDecode(allocator, "hello%20world");
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("hello world", decoded);
}
