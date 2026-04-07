// SPDX-License-Identifier: MIT
//! PGP/MIME support per RFC 3156.
//!
//! RFC 3156 defines three MIME content types for OpenPGP:
//!
//!   1. `multipart/encrypted` — An encrypted message consisting of a
//!      control part (application/pgp-encrypted) and the encrypted body
//!      (application/octet-stream).
//!
//!   2. `multipart/signed` — A signed message consisting of the original
//!      text part and a detached signature (application/pgp-signature).
//!
//!   3. `application/pgp-keys` — A MIME entity containing OpenPGP key
//!      material.
//!
//! This module provides functions to create and parse PGP/MIME structures.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const HashAlgorithm = @import("../types/enums.zig").HashAlgorithm;

/// The type of PGP/MIME message.
pub const PgpMimeType = enum {
    /// multipart/encrypted (RFC 3156 Section 4)
    encrypted,
    /// multipart/signed (RFC 3156 Section 5)
    signed,
    /// application/pgp-keys (RFC 3156 Section 7)
    keys,

    /// Return the MIME content type string (without boundary parameter).
    pub fn contentType(self: PgpMimeType) []const u8 {
        return switch (self) {
            .encrypted => "multipart/encrypted",
            .signed => "multipart/signed",
            .keys => "application/pgp-keys",
        };
    }

    /// Return the protocol parameter value for this type.
    pub fn protocol(self: PgpMimeType) ?[]const u8 {
        return switch (self) {
            .encrypted => "application/pgp-encrypted",
            .signed => "application/pgp-signature",
            .keys => null,
        };
    }
};

/// Errors specific to PGP/MIME operations.
pub const PgpMimeError = error{
    InvalidMimeFormat,
    MissingBoundary,
    MissingPgpData,
    InvalidContentType,
    OutOfMemory,
};

/// A parsed PGP/MIME message.
pub const PgpMimeMessage = struct {
    /// The detected PGP/MIME type.
    msg_type: PgpMimeType,
    /// The body part (plaintext part for signed, control part for encrypted).
    body_part: []u8,
    /// The PGP data (signature for signed, encrypted data for encrypted, key data for keys).
    pgp_data: []u8,
    /// The MIME boundary string.
    boundary: []u8,

    pub fn deinit(self: PgpMimeMessage, allocator: Allocator) void {
        allocator.free(self.body_part);
        allocator.free(self.pgp_data);
        allocator.free(self.boundary);
    }
};

// ===========================================================================
// Message creation
// ===========================================================================

/// Create a PGP/MIME encrypted message (multipart/encrypted).
///
/// The resulting MIME structure is:
///
///   Content-Type: multipart/encrypted;
///     protocol="application/pgp-encrypted";
///     boundary="<boundary>"
///
///   --<boundary>
///   Content-Type: application/pgp-encrypted
///   Content-Description: PGP/MIME version identification
///
///   Version: 1
///
///   --<boundary>
///   Content-Type: application/octet-stream; name="encrypted.asc"
///   Content-Description: OpenPGP encrypted message
///   Content-Disposition: inline; filename="encrypted.asc"
///
///   <encrypted_body>
///
///   --<boundary>--
pub fn createPgpMimeEncrypted(
    allocator: Allocator,
    encrypted_body: []const u8,
    boundary: []const u8,
) PgpMimeError![]u8 {
    if (boundary.len == 0) return PgpMimeError.MissingBoundary;
    if (encrypted_body.len == 0) return PgpMimeError.MissingPgpData;

    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // MIME headers
    try appendStr(allocator, &output, "Content-Type: multipart/encrypted;\r\n");
    try appendStr(allocator, &output, "  protocol=\"application/pgp-encrypted\";\r\n");
    try appendStr(allocator, &output, "  boundary=\"");
    try appendStr(allocator, &output, boundary);
    try appendStr(allocator, &output, "\"\r\n");
    try appendStr(allocator, &output, "\r\n");

    // Part 1: PGP/MIME version identification
    try appendStr(allocator, &output, "--");
    try appendStr(allocator, &output, boundary);
    try appendStr(allocator, &output, "\r\n");
    try appendStr(allocator, &output, "Content-Type: application/pgp-encrypted\r\n");
    try appendStr(allocator, &output, "Content-Description: PGP/MIME version identification\r\n");
    try appendStr(allocator, &output, "\r\n");
    try appendStr(allocator, &output, "Version: 1\r\n");
    try appendStr(allocator, &output, "\r\n");

    // Part 2: Encrypted data
    try appendStr(allocator, &output, "--");
    try appendStr(allocator, &output, boundary);
    try appendStr(allocator, &output, "\r\n");
    try appendStr(allocator, &output, "Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n");
    try appendStr(allocator, &output, "Content-Description: OpenPGP encrypted message\r\n");
    try appendStr(allocator, &output, "Content-Disposition: inline; filename=\"encrypted.asc\"\r\n");
    try appendStr(allocator, &output, "\r\n");
    try appendStr(allocator, &output, encrypted_body);
    try appendStr(allocator, &output, "\r\n");

    // Closing boundary
    try appendStr(allocator, &output, "--");
    try appendStr(allocator, &output, boundary);
    try appendStr(allocator, &output, "--\r\n");

    return output.toOwnedSlice(allocator) catch return PgpMimeError.OutOfMemory;
}

/// Create a PGP/MIME signed message (multipart/signed).
///
/// The resulting MIME structure is:
///
///   Content-Type: multipart/signed;
///     micalg=pgp-sha256;
///     protocol="application/pgp-signature";
///     boundary="<boundary>"
///
///   --<boundary>
///   <text_body>
///
///   --<boundary>
///   Content-Type: application/pgp-signature; name="signature.asc"
///   Content-Description: OpenPGP digital signature
///   Content-Disposition: attachment; filename="signature.asc"
///
///   <signature>
///
///   --<boundary>--
pub fn createPgpMimeSigned(
    allocator: Allocator,
    text_body: []const u8,
    signature: []const u8,
    hash_algo: HashAlgorithm,
    boundary: []const u8,
) PgpMimeError![]u8 {
    if (boundary.len == 0) return PgpMimeError.MissingBoundary;
    if (signature.len == 0) return PgpMimeError.MissingPgpData;

    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // MIME headers
    try appendStr(allocator, &output, "Content-Type: multipart/signed;\r\n");
    try appendStr(allocator, &output, "  micalg=pgp-");
    try appendStr(allocator, &output, micalgName(hash_algo));
    try appendStr(allocator, &output, ";\r\n");
    try appendStr(allocator, &output, "  protocol=\"application/pgp-signature\";\r\n");
    try appendStr(allocator, &output, "  boundary=\"");
    try appendStr(allocator, &output, boundary);
    try appendStr(allocator, &output, "\"\r\n");
    try appendStr(allocator, &output, "\r\n");

    // Part 1: Text body
    try appendStr(allocator, &output, "--");
    try appendStr(allocator, &output, boundary);
    try appendStr(allocator, &output, "\r\n");
    try appendStr(allocator, &output, text_body);
    try appendStr(allocator, &output, "\r\n");

    // Part 2: Signature
    try appendStr(allocator, &output, "--");
    try appendStr(allocator, &output, boundary);
    try appendStr(allocator, &output, "\r\n");
    try appendStr(allocator, &output, "Content-Type: application/pgp-signature; name=\"signature.asc\"\r\n");
    try appendStr(allocator, &output, "Content-Description: OpenPGP digital signature\r\n");
    try appendStr(allocator, &output, "Content-Disposition: attachment; filename=\"signature.asc\"\r\n");
    try appendStr(allocator, &output, "\r\n");
    try appendStr(allocator, &output, signature);
    try appendStr(allocator, &output, "\r\n");

    // Closing boundary
    try appendStr(allocator, &output, "--");
    try appendStr(allocator, &output, boundary);
    try appendStr(allocator, &output, "--\r\n");

    return output.toOwnedSlice(allocator) catch return PgpMimeError.OutOfMemory;
}

/// Create a PGP/MIME keys attachment.
///
/// Wraps OpenPGP key material in a MIME entity with the appropriate
/// content type (application/pgp-keys).
pub fn createPgpMimeKeys(
    allocator: Allocator,
    key_data: []const u8,
) PgpMimeError![]u8 {
    if (key_data.len == 0) return PgpMimeError.MissingPgpData;

    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    try appendStr(allocator, &output, "Content-Type: application/pgp-keys\r\n");
    try appendStr(allocator, &output, "Content-Description: OpenPGP public key\r\n");
    try appendStr(allocator, &output, "Content-Disposition: attachment; filename=\"key.asc\"\r\n");
    try appendStr(allocator, &output, "\r\n");
    try appendStr(allocator, &output, key_data);

    return output.toOwnedSlice(allocator) catch return PgpMimeError.OutOfMemory;
}

// ===========================================================================
// Message parsing
// ===========================================================================

/// Parse a PGP/MIME message.
///
/// Detects the message type from the Content-Type header and extracts
/// the body part and PGP data from the MIME structure.
pub fn parsePgpMime(allocator: Allocator, mime_data: []const u8) PgpMimeError!PgpMimeMessage {
    if (mime_data.len == 0) return PgpMimeError.InvalidMimeFormat;

    // Detect message type from Content-Type header
    const msg_type = detectMimeType(mime_data) orelse return PgpMimeError.InvalidContentType;

    // Extract boundary
    const boundary = try extractBoundary(allocator, mime_data);
    errdefer allocator.free(boundary);

    // Find MIME parts
    const parts = try extractMimeParts(allocator, mime_data, boundary);

    return .{
        .msg_type = msg_type,
        .body_part = parts.body,
        .pgp_data = parts.pgp_data,
        .boundary = boundary,
    };
}

// ===========================================================================
// Utility functions
// ===========================================================================

/// Generate a random MIME boundary string.
///
/// Produces a boundary string of the form "----zpgp-XXXXXXXXXXXXXXXX"
/// using cryptographically random bytes encoded as hex.
pub fn generateBoundary(allocator: Allocator) PgpMimeError![]u8 {
    const prefix = "----zpgp-";
    var random_bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);

    const hex_len = random_bytes.len * 2;
    const total_len = prefix.len + hex_len;
    const result = allocator.alloc(u8, total_len) catch return PgpMimeError.OutOfMemory;

    @memcpy(result[0..prefix.len], prefix);

    const hex_chars = "0123456789abcdef";
    for (random_bytes, 0..) |byte, i| {
        result[prefix.len + i * 2] = hex_chars[byte >> 4];
        result[prefix.len + i * 2 + 1] = hex_chars[byte & 0x0F];
    }

    return result;
}

/// Build the Content-Type header value for a PGP/MIME message.
///
/// Returns a string like:
///   multipart/encrypted; protocol="application/pgp-encrypted"; boundary="..."
pub fn pgpMimeContentType(msg_type: PgpMimeType, boundary: []const u8, allocator: Allocator) PgpMimeError![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    try appendStr(allocator, &output, msg_type.contentType());

    if (msg_type.protocol()) |proto| {
        try appendStr(allocator, &output, "; protocol=\"");
        try appendStr(allocator, &output, proto);
        try appendStr(allocator, &output, "\"");
    }

    try appendStr(allocator, &output, "; boundary=\"");
    try appendStr(allocator, &output, boundary);
    try appendStr(allocator, &output, "\"");

    return output.toOwnedSlice(allocator) catch return PgpMimeError.OutOfMemory;
}

/// Return the micalg parameter value for the given hash algorithm.
///
/// Per RFC 3156 Section 5, the micalg value is "pgp-<hash-name>" in
/// lowercase.
pub fn micalgName(algo: HashAlgorithm) []const u8 {
    return switch (algo) {
        .sha1 => "sha1",
        .sha256 => "sha256",
        .sha384 => "sha384",
        .sha512 => "sha512",
        .sha224 => "sha224",
        .md5 => "md5",
        .ripemd160 => "ripemd160",
        _ => "unknown",
    };
}

/// Parse a micalg parameter value into a hash algorithm.
pub fn parseMicalg(value: []const u8) ?HashAlgorithm {
    // Strip "pgp-" prefix if present
    const name = if (mem.startsWith(u8, value, "pgp-")) value[4..] else value;

    if (mem.eql(u8, name, "sha1")) return .sha1;
    if (mem.eql(u8, name, "sha256")) return .sha256;
    if (mem.eql(u8, name, "sha384")) return .sha384;
    if (mem.eql(u8, name, "sha512")) return .sha512;
    if (mem.eql(u8, name, "sha224")) return .sha224;
    if (mem.eql(u8, name, "md5")) return .md5;
    if (mem.eql(u8, name, "ripemd160")) return .ripemd160;
    return null;
}

// ===========================================================================
// Internal helpers
// ===========================================================================

fn appendStr(allocator: Allocator, list: *std.ArrayList(u8), data: []const u8) PgpMimeError!void {
    list.appendSlice(allocator, data) catch return PgpMimeError.OutOfMemory;
}

/// Detect the PGP/MIME type from the Content-Type header.
fn detectMimeType(data: []const u8) ?PgpMimeType {
    if (mem.indexOf(u8, data, "multipart/encrypted") != null) return .encrypted;
    if (mem.indexOf(u8, data, "multipart/signed") != null) return .signed;
    if (mem.indexOf(u8, data, "application/pgp-keys") != null) return .keys;
    return null;
}

/// Extract the boundary parameter from MIME headers.
fn extractBoundary(allocator: Allocator, data: []const u8) PgpMimeError![]u8 {
    // Look for boundary="..." or boundary=...
    const boundary_key = "boundary=\"";
    if (mem.indexOf(u8, data, boundary_key)) |pos| {
        const start = pos + boundary_key.len;
        const end = mem.indexOfPos(u8, data, start, "\"") orelse return PgpMimeError.MissingBoundary;
        return allocator.dupe(u8, data[start..end]) catch return PgpMimeError.OutOfMemory;
    }

    // Try without quotes
    const boundary_key2 = "boundary=";
    if (mem.indexOf(u8, data, boundary_key2)) |pos| {
        const start = pos + boundary_key2.len;
        // Find end of boundary (whitespace, semicolon, or newline)
        var end = start;
        while (end < data.len and data[end] != ' ' and data[end] != ';' and
            data[end] != '\r' and data[end] != '\n')
        {
            end += 1;
        }
        if (end == start) return PgpMimeError.MissingBoundary;
        return allocator.dupe(u8, data[start..end]) catch return PgpMimeError.OutOfMemory;
    }

    return PgpMimeError.MissingBoundary;
}

/// MIME parts extracted from parsing.
const MimeParts = struct {
    body: []u8,
    pgp_data: []u8,
};

/// Extract MIME parts separated by the boundary.
fn extractMimeParts(allocator: Allocator, data: []const u8, boundary: []const u8) PgpMimeError!MimeParts {
    // Build the boundary delimiter (--<boundary>)
    const delim_len = 2 + boundary.len;
    const delim = allocator.alloc(u8, delim_len) catch return PgpMimeError.OutOfMemory;
    defer allocator.free(delim);
    delim[0] = '-';
    delim[1] = '-';
    @memcpy(delim[2..][0..boundary.len], boundary);

    // Find the first boundary
    const first_boundary = mem.indexOf(u8, data, delim) orelse return PgpMimeError.InvalidMimeFormat;

    // Find start of first part (after boundary + newline)
    var part1_start = first_boundary + delim.len;
    // Skip CRLF or LF
    if (part1_start < data.len and data[part1_start] == '\r') part1_start += 1;
    if (part1_start < data.len and data[part1_start] == '\n') part1_start += 1;

    // Find second boundary
    const second_boundary = mem.indexOfPos(u8, data, part1_start, delim) orelse
        return PgpMimeError.InvalidMimeFormat;

    // First part content (strip trailing CRLF before boundary)
    var part1_end = second_boundary;
    if (part1_end > 0 and data[part1_end - 1] == '\n') part1_end -= 1;
    if (part1_end > 0 and data[part1_end - 1] == '\r') part1_end -= 1;

    const body = allocator.dupe(u8, data[part1_start..part1_end]) catch return PgpMimeError.OutOfMemory;
    errdefer allocator.free(body);

    // Find start of second part
    var part2_start = second_boundary + delim.len;
    if (part2_start < data.len and data[part2_start] == '\r') part2_start += 1;
    if (part2_start < data.len and data[part2_start] == '\n') part2_start += 1;

    // Find closing boundary (--<boundary>--)
    const closing_delim_len = delim_len + 2;
    const closing_delim = allocator.alloc(u8, closing_delim_len) catch {
        allocator.free(body);
        return PgpMimeError.OutOfMemory;
    };
    defer allocator.free(closing_delim);
    @memcpy(closing_delim[0..delim_len], delim);
    closing_delim[delim_len] = '-';
    closing_delim[delim_len + 1] = '-';

    const closing_pos = mem.indexOfPos(u8, data, part2_start, closing_delim) orelse data.len;

    var part2_end = closing_pos;
    if (part2_end > 0 and data[part2_end - 1] == '\n') part2_end -= 1;
    if (part2_end > 0 and data[part2_end - 1] == '\r') part2_end -= 1;

    if (part2_start > part2_end) part2_start = part2_end;

    const pgp_data = allocator.dupe(u8, data[part2_start..part2_end]) catch {
        allocator.free(body);
        return PgpMimeError.OutOfMemory;
    };

    return .{
        .body = body,
        .pgp_data = pgp_data,
    };
}

// ===========================================================================
// Tests
// ===========================================================================

test "PgpMimeType contentType" {
    try std.testing.expectEqualStrings("multipart/encrypted", PgpMimeType.encrypted.contentType());
    try std.testing.expectEqualStrings("multipart/signed", PgpMimeType.signed.contentType());
    try std.testing.expectEqualStrings("application/pgp-keys", PgpMimeType.keys.contentType());
}

test "PgpMimeType protocol" {
    try std.testing.expectEqualStrings("application/pgp-encrypted", PgpMimeType.encrypted.protocol().?);
    try std.testing.expectEqualStrings("application/pgp-signature", PgpMimeType.signed.protocol().?);
    try std.testing.expect(PgpMimeType.keys.protocol() == null);
}

test "micalgName" {
    try std.testing.expectEqualStrings("sha256", micalgName(.sha256));
    try std.testing.expectEqualStrings("sha1", micalgName(.sha1));
    try std.testing.expectEqualStrings("sha512", micalgName(.sha512));
    try std.testing.expectEqualStrings("sha384", micalgName(.sha384));
    try std.testing.expectEqualStrings("sha224", micalgName(.sha224));
}

test "parseMicalg" {
    try std.testing.expectEqual(HashAlgorithm.sha256, parseMicalg("pgp-sha256").?);
    try std.testing.expectEqual(HashAlgorithm.sha256, parseMicalg("sha256").?);
    try std.testing.expectEqual(HashAlgorithm.sha1, parseMicalg("pgp-sha1").?);
    try std.testing.expectEqual(HashAlgorithm.sha512, parseMicalg("sha512").?);
    try std.testing.expect(parseMicalg("unknown") == null);
}

test "generateBoundary" {
    const allocator = std.testing.allocator;
    const b1 = try generateBoundary(allocator);
    defer allocator.free(b1);
    const b2 = try generateBoundary(allocator);
    defer allocator.free(b2);

    // Should start with the prefix
    try std.testing.expect(mem.startsWith(u8, b1, "----zpgp-"));
    try std.testing.expect(mem.startsWith(u8, b2, "----zpgp-"));

    // Should be the right length: prefix(9) + hex(32) = 41
    try std.testing.expectEqual(@as(usize, 41), b1.len);

    // Two random boundaries should (almost certainly) differ
    try std.testing.expect(!mem.eql(u8, b1, b2));
}

test "pgpMimeContentType encrypted" {
    const allocator = std.testing.allocator;
    const ct = try pgpMimeContentType(.encrypted, "test-boundary", allocator);
    defer allocator.free(ct);

    try std.testing.expect(mem.indexOf(u8, ct, "multipart/encrypted") != null);
    try std.testing.expect(mem.indexOf(u8, ct, "application/pgp-encrypted") != null);
    try std.testing.expect(mem.indexOf(u8, ct, "test-boundary") != null);
}

test "pgpMimeContentType signed" {
    const allocator = std.testing.allocator;
    const ct = try pgpMimeContentType(.signed, "sig-bound", allocator);
    defer allocator.free(ct);

    try std.testing.expect(mem.indexOf(u8, ct, "multipart/signed") != null);
    try std.testing.expect(mem.indexOf(u8, ct, "application/pgp-signature") != null);
    try std.testing.expect(mem.indexOf(u8, ct, "sig-bound") != null);
}

test "pgpMimeContentType keys" {
    const allocator = std.testing.allocator;
    const ct = try pgpMimeContentType(.keys, "key-bound", allocator);
    defer allocator.free(ct);

    try std.testing.expect(mem.indexOf(u8, ct, "application/pgp-keys") != null);
    try std.testing.expect(mem.indexOf(u8, ct, "key-bound") != null);
}

test "createPgpMimeEncrypted structure" {
    const allocator = std.testing.allocator;
    const encrypted_body = "-----BEGIN PGP MESSAGE-----\r\nABCDEF\r\n-----END PGP MESSAGE-----\r\n";
    const boundary = "test-boundary-123";

    const result = try createPgpMimeEncrypted(allocator, encrypted_body, boundary);
    defer allocator.free(result);

    try std.testing.expect(mem.indexOf(u8, result, "multipart/encrypted") != null);
    try std.testing.expect(mem.indexOf(u8, result, "application/pgp-encrypted") != null);
    try std.testing.expect(mem.indexOf(u8, result, "Version: 1") != null);
    try std.testing.expect(mem.indexOf(u8, result, "application/octet-stream") != null);
    try std.testing.expect(mem.indexOf(u8, result, encrypted_body) != null);
    try std.testing.expect(mem.indexOf(u8, result, "--test-boundary-123--") != null);
}

test "createPgpMimeEncrypted empty boundary" {
    const allocator = std.testing.allocator;
    const result = createPgpMimeEncrypted(allocator, "data", "");
    try std.testing.expectError(PgpMimeError.MissingBoundary, result);
}

test "createPgpMimeEncrypted empty body" {
    const allocator = std.testing.allocator;
    const result = createPgpMimeEncrypted(allocator, "", "boundary");
    try std.testing.expectError(PgpMimeError.MissingPgpData, result);
}

test "createPgpMimeSigned structure" {
    const allocator = std.testing.allocator;
    const text_body = "Content-Type: text/plain\r\n\r\nHello, World!";
    const signature = "-----BEGIN PGP SIGNATURE-----\r\nXYZ\r\n-----END PGP SIGNATURE-----\r\n";
    const boundary = "sig-boundary";

    const result = try createPgpMimeSigned(allocator, text_body, signature, .sha256, boundary);
    defer allocator.free(result);

    try std.testing.expect(mem.indexOf(u8, result, "multipart/signed") != null);
    try std.testing.expect(mem.indexOf(u8, result, "micalg=pgp-sha256") != null);
    try std.testing.expect(mem.indexOf(u8, result, "application/pgp-signature") != null);
    try std.testing.expect(mem.indexOf(u8, result, text_body) != null);
    try std.testing.expect(mem.indexOf(u8, result, signature) != null);
    try std.testing.expect(mem.indexOf(u8, result, "--sig-boundary--") != null);
}

test "createPgpMimeSigned empty signature" {
    const allocator = std.testing.allocator;
    const result = createPgpMimeSigned(allocator, "body", "", .sha256, "boundary");
    try std.testing.expectError(PgpMimeError.MissingPgpData, result);
}

test "createPgpMimeKeys" {
    const allocator = std.testing.allocator;
    const key_data = "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\nKEYDATA\r\n-----END PGP PUBLIC KEY BLOCK-----\r\n";

    const result = try createPgpMimeKeys(allocator, key_data);
    defer allocator.free(result);

    try std.testing.expect(mem.indexOf(u8, result, "application/pgp-keys") != null);
    try std.testing.expect(mem.indexOf(u8, result, key_data) != null);
}

test "createPgpMimeKeys empty" {
    const allocator = std.testing.allocator;
    const result = createPgpMimeKeys(allocator, "");
    try std.testing.expectError(PgpMimeError.MissingPgpData, result);
}

test "parsePgpMime encrypted" {
    const allocator = std.testing.allocator;
    const boundary = "test-bound";
    const encrypted_body = "ENCRYPTED DATA HERE";

    const msg = try createPgpMimeEncrypted(allocator, encrypted_body, boundary);
    defer allocator.free(msg);

    var parsed = try parsePgpMime(allocator, msg);
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(PgpMimeType.encrypted, parsed.msg_type);
    try std.testing.expectEqualStrings(boundary, parsed.boundary);
}

test "parsePgpMime signed" {
    const allocator = std.testing.allocator;
    const boundary = "sig-bound";
    const text_body = "Hello, signed world!";
    const signature = "SIGNATURE_DATA";

    const msg = try createPgpMimeSigned(allocator, text_body, signature, .sha256, boundary);
    defer allocator.free(msg);

    var parsed = try parsePgpMime(allocator, msg);
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(PgpMimeType.signed, parsed.msg_type);
    try std.testing.expectEqualStrings(boundary, parsed.boundary);
}

test "parsePgpMime empty input" {
    const allocator = std.testing.allocator;
    const result = parsePgpMime(allocator, "");
    try std.testing.expectError(PgpMimeError.InvalidMimeFormat, result);
}

test "parsePgpMime invalid content type" {
    const allocator = std.testing.allocator;
    const result = parsePgpMime(allocator, "Content-Type: text/plain\r\n\r\nHello");
    try std.testing.expectError(PgpMimeError.InvalidContentType, result);
}

test "detectMimeType" {
    try std.testing.expectEqual(PgpMimeType.encrypted, detectMimeType("Content-Type: multipart/encrypted; ...").?);
    try std.testing.expectEqual(PgpMimeType.signed, detectMimeType("Content-Type: multipart/signed; ...").?);
    try std.testing.expectEqual(PgpMimeType.keys, detectMimeType("Content-Type: application/pgp-keys").?);
    try std.testing.expect(detectMimeType("Content-Type: text/plain") == null);
}

test "extractBoundary with quotes" {
    const allocator = std.testing.allocator;
    const header = "Content-Type: multipart/signed; boundary=\"my-boundary\"";
    const b = try extractBoundary(allocator, header);
    defer allocator.free(b);
    try std.testing.expectEqualStrings("my-boundary", b);
}

test "extractBoundary without quotes" {
    const allocator = std.testing.allocator;
    const header = "Content-Type: multipart/signed; boundary=my-boundary\r\n";
    const b = try extractBoundary(allocator, header);
    defer allocator.free(b);
    try std.testing.expectEqualStrings("my-boundary", b);
}

test "extractBoundary missing" {
    const allocator = std.testing.allocator;
    const result = extractBoundary(allocator, "Content-Type: multipart/signed");
    try std.testing.expectError(PgpMimeError.MissingBoundary, result);
}

test "PgpMimeMessage deinit" {
    const allocator = std.testing.allocator;
    const body = try allocator.dupe(u8, "body");
    const pgp = try allocator.dupe(u8, "pgp-data");
    const bound = try allocator.dupe(u8, "boundary");

    const msg = PgpMimeMessage{
        .msg_type = .signed,
        .body_part = body,
        .pgp_data = pgp,
        .boundary = bound,
    };
    msg.deinit(allocator);
}
