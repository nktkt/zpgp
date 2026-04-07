// SPDX-License-Identifier: MIT
//! Enhanced cleartext signature handling with multi-hash support.
//!
//! Extends the basic cleartext signature framework (RFC 4880 Section 7)
//! with support for multiple hash algorithms in a single message and
//! enhanced format validation.
//!
//! RFC 4880 Section 7 allows multiple "Hash:" header lines, each declaring
//! a hash algorithm used by one of the signatures in the message.
//! This module supports creating and validating such messages.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const HashAlgorithm = @import("../types/enums.zig").HashAlgorithm;
const armor = @import("../armor/armor.zig");

/// Result of cleartext format validation.
pub const CleartextValidation = struct {
    /// Whether the format is structurally valid.
    valid: bool,
    /// Hash algorithms declared in Hash: header lines.
    hash_headers: [][]u8,
    /// Diagnostic messages for format issues found.
    issues: [][]u8,

    pub fn deinit(self: CleartextValidation, allocator: Allocator) void {
        for (self.hash_headers) |h| allocator.free(h);
        allocator.free(self.hash_headers);
        for (self.issues) |i| allocator.free(i);
        allocator.free(self.issues);
    }
};

/// A parsed multi-hash cleartext signed message.
pub const MultiHashCleartextMessage = struct {
    /// The cleartext body (dash-unescaped).
    text: []u8,
    /// The raw binary signature data (decoded from the armor block).
    signature_data: []u8,
    /// All hash algorithms declared in the Hash: headers.
    hash_algos: []HashAlgorithm,

    pub fn deinit(self: MultiHashCleartextMessage, allocator: Allocator) void {
        allocator.free(self.text);
        allocator.free(self.signature_data);
        allocator.free(self.hash_algos);
    }
};

// ===========================================================================
// Creation
// ===========================================================================

/// Create a cleartext signature with multiple hash algorithm declarations.
///
/// Multiple "Hash:" headers are emitted, one per algorithm, as allowed
/// by RFC 4880 Section 7.  Each hash corresponds to a signature over
/// the canonicalized text.
///
/// The `signature_packet_bytes` should contain all signature packets
/// (concatenated).
pub fn createMultiHashCleartextSig(
    allocator: Allocator,
    text: []const u8,
    signature_packet_bytes: []const u8,
    hash_algos: []const HashAlgorithm,
) ![]u8 {
    if (hash_algos.len == 0) return error.MissingHashAlgorithm;

    // Dash-escape the text
    const escaped = try dashEscape(allocator, text);
    defer allocator.free(escaped);

    // Armor the signature
    const armored_sig = try armor.encode(allocator, signature_packet_bytes, .signature, null);
    defer allocator.free(armored_sig);

    // Assemble the cleartext signed message
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // Header
    try output.appendSlice(allocator, "-----BEGIN PGP SIGNED MESSAGE-----\n");

    // Hash headers — one per algorithm
    for (hash_algos) |algo| {
        try output.appendSlice(allocator, "Hash: ");
        try output.appendSlice(allocator, hashAlgorithmName(algo));
        try output.appendSlice(allocator, "\n");
    }

    // Blank line after headers
    try output.append(allocator, '\n');

    // Dash-escaped cleartext
    try output.appendSlice(allocator, escaped);

    // Ensure newline before signature
    if (escaped.len > 0 and escaped[escaped.len - 1] != '\n') {
        try output.append(allocator, '\n');
    }

    // Armored signature block
    try output.appendSlice(allocator, armored_sig);

    return try output.toOwnedSlice(allocator);
}

/// Create a cleartext signature with a combined Hash: header line.
///
/// Multiple hash algorithms are listed comma-separated on a single
/// Hash: line (e.g., "Hash: SHA256, SHA512").
pub fn createCombinedHashCleartextSig(
    allocator: Allocator,
    text: []const u8,
    signature_packet_bytes: []const u8,
    hash_algos: []const HashAlgorithm,
) ![]u8 {
    if (hash_algos.len == 0) return error.MissingHashAlgorithm;

    const escaped = try dashEscape(allocator, text);
    defer allocator.free(escaped);

    const armored_sig = try armor.encode(allocator, signature_packet_bytes, .signature, null);
    defer allocator.free(armored_sig);

    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    try output.appendSlice(allocator, "-----BEGIN PGP SIGNED MESSAGE-----\n");
    try output.appendSlice(allocator, "Hash: ");

    for (hash_algos, 0..) |algo, i| {
        if (i > 0) try output.appendSlice(allocator, ", ");
        try output.appendSlice(allocator, hashAlgorithmName(algo));
    }
    try output.append(allocator, '\n');
    try output.append(allocator, '\n');

    try output.appendSlice(allocator, escaped);
    if (escaped.len > 0 and escaped[escaped.len - 1] != '\n') {
        try output.append(allocator, '\n');
    }
    try output.appendSlice(allocator, armored_sig);

    return try output.toOwnedSlice(allocator);
}

// ===========================================================================
// Canonicalization
// ===========================================================================

/// Canonicalize text for cleartext signature signing per RFC 4880 Section 7.1.
///
/// Applies the following transformations:
///   - Trailing whitespace (spaces and tabs) on each line is stripped.
///   - Line endings are converted to CR LF.
///   - The trailing CR LF on the final line is NOT included.
///
/// This is used to produce the canonical form for hash computation.
pub fn canonicalizeForSigning(allocator: Allocator, text: []const u8) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    var iter = mem.splitSequence(u8, text, "\n");
    var first = true;

    while (iter.next()) |raw_line| {
        var line = raw_line;
        // Strip trailing CR
        if (line.len > 0 and line[line.len - 1] == '\r') {
            line = line[0 .. line.len - 1];
        }
        // Strip trailing whitespace (spaces and tabs)
        line = mem.trimRight(u8, line, " \t");

        if (!first) {
            try output.appendSlice(allocator, "\r\n");
        }
        first = false;

        try output.appendSlice(allocator, line);
    }

    return try output.toOwnedSlice(allocator);
}

// ===========================================================================
// Validation
// ===========================================================================

/// Validate the format of a cleartext signed message.
///
/// Checks for structural correctness including:
///   - Presence of BEGIN PGP SIGNED MESSAGE header
///   - Valid Hash: header lines
///   - Proper separation between headers and cleartext
///   - Presence of signature block
///   - Proper closing markers
///
/// Returns a CleartextValidation with the results.
pub fn validateCleartextFormat(allocator: Allocator, data: []const u8) !CleartextValidation {
    var hash_headers: std.ArrayList([]u8) = .empty;
    errdefer {
        for (hash_headers.items) |h| allocator.free(h);
        hash_headers.deinit(allocator);
    }

    var issues: std.ArrayList([]u8) = .empty;
    errdefer {
        for (issues.items) |i| allocator.free(i);
        issues.deinit(allocator);
    }

    var valid = true;

    // Check for BEGIN marker
    const begin_marker = "-----BEGIN PGP SIGNED MESSAGE-----";
    if (mem.indexOf(u8, data, begin_marker) == null) {
        valid = false;
        const issue = try allocator.dupe(u8, "Missing BEGIN PGP SIGNED MESSAGE marker");
        try issues.append(allocator, issue);
    } else {
        // Find headers section
        const header_pos = mem.indexOf(u8, data, begin_marker).?;
        const after_header = header_pos + begin_marker.len;
        const header_end = mem.indexOfPos(u8, data, after_header, "\n") orelse data.len;

        // Parse Hash: headers
        var pos = header_end + 1;
        while (pos < data.len) {
            const line_end = mem.indexOfPos(u8, data, pos, "\n") orelse data.len;
            var line = data[pos..line_end];

            // Strip trailing CR
            if (line.len > 0 and line[line.len - 1] == '\r') {
                line = line[0 .. line.len - 1];
            }

            if (line.len == 0) break; // Blank line ends headers

            if (mem.startsWith(u8, line, "Hash: ")) {
                const hash_value = line["Hash: ".len..];
                // May be comma-separated
                var hash_iter = mem.splitSequence(u8, hash_value, ",");
                while (hash_iter.next()) |hash_name| {
                    const trimmed = mem.trim(u8, hash_name, " \t");
                    if (trimmed.len > 0) {
                        const duped = try allocator.dupe(u8, trimmed);
                        try hash_headers.append(allocator, duped);

                        // Validate the hash name
                        if (parseHashName(trimmed) == null) {
                            const issue = try std.fmt.allocPrint(allocator, "Unknown hash algorithm: {s}", .{trimmed});
                            try issues.append(allocator, issue);
                        }
                    }
                }
            } else {
                // Unknown header
                const issue = try std.fmt.allocPrint(allocator, "Unknown header line: {s}", .{line});
                try issues.append(allocator, issue);
            }

            pos = line_end + 1;
        }

        if (hash_headers.items.len == 0) {
            const issue = try allocator.dupe(u8, "No Hash: header found");
            try issues.append(allocator, issue);
        }
    }

    // Check for signature block
    const sig_begin = "-----BEGIN PGP SIGNATURE-----";
    const sig_end = "-----END PGP SIGNATURE-----";

    if (mem.indexOf(u8, data, sig_begin) == null) {
        valid = false;
        const issue = try allocator.dupe(u8, "Missing BEGIN PGP SIGNATURE marker");
        try issues.append(allocator, issue);
    }

    if (mem.indexOf(u8, data, sig_end) == null) {
        valid = false;
        const issue = try allocator.dupe(u8, "Missing END PGP SIGNATURE marker");
        try issues.append(allocator, issue);
    }

    // Check that signature block comes after signed message header
    if (mem.indexOf(u8, data, begin_marker)) |begin_pos| {
        if (mem.indexOf(u8, data, sig_begin)) |sig_pos| {
            if (sig_pos < begin_pos) {
                valid = false;
                const issue = try allocator.dupe(u8, "Signature block appears before signed message header");
                try issues.append(allocator, issue);
            }
        }
    }

    return .{
        .valid = valid,
        .hash_headers = try hash_headers.toOwnedSlice(allocator),
        .issues = try issues.toOwnedSlice(allocator),
    };
}

// ===========================================================================
// Helper functions
// ===========================================================================

/// Hash algorithm name as used in the "Hash:" armor header.
fn hashAlgorithmName(algo: HashAlgorithm) []const u8 {
    return switch (algo) {
        .sha1 => "SHA1",
        .sha256 => "SHA256",
        .sha384 => "SHA384",
        .sha512 => "SHA512",
        .sha224 => "SHA224",
        .md5 => "MD5",
        .ripemd160 => "RIPEMD160",
        _ => "Unknown",
    };
}

/// Parse a hash algorithm name from the "Hash:" armor header value.
fn parseHashName(name: []const u8) ?HashAlgorithm {
    if (mem.eql(u8, name, "SHA1")) return .sha1;
    if (mem.eql(u8, name, "SHA256")) return .sha256;
    if (mem.eql(u8, name, "SHA384")) return .sha384;
    if (mem.eql(u8, name, "SHA512")) return .sha512;
    if (mem.eql(u8, name, "SHA224")) return .sha224;
    if (mem.eql(u8, name, "MD5")) return .md5;
    if (mem.eql(u8, name, "RIPEMD160")) return .ripemd160;
    return null;
}

/// Dash-escape text per RFC 4880 Section 7.1.
///
/// Lines starting with "-" are prefixed with "- ".
fn dashEscape(allocator: Allocator, text: []const u8) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    var iter = mem.splitSequence(u8, text, "\n");
    var first = true;

    while (iter.next()) |line| {
        if (!first) {
            try output.append(allocator, '\n');
        }
        first = false;

        if (line.len > 0 and line[0] == '-') {
            try output.appendSlice(allocator, "- ");
        }
        try output.appendSlice(allocator, line);
    }

    return try output.toOwnedSlice(allocator);
}

/// Remove dash-escaping from text.
///
/// Lines starting with "- " have the "- " prefix removed.
fn dashUnescape(allocator: Allocator, text: []const u8) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    var iter = mem.splitSequence(u8, text, "\n");
    var first = true;

    while (iter.next()) |line| {
        if (!first) {
            try output.append(allocator, '\n');
        }
        first = false;

        var actual_line = line;
        if (actual_line.len > 0 and actual_line[actual_line.len - 1] == '\r') {
            actual_line = actual_line[0 .. actual_line.len - 1];
        }

        if (mem.startsWith(u8, actual_line, "- ")) {
            try output.appendSlice(allocator, actual_line[2..]);
        } else {
            try output.appendSlice(allocator, actual_line);
        }
    }

    return try output.toOwnedSlice(allocator);
}

// ===========================================================================
// Tests
// ===========================================================================

test "createMultiHashCleartextSig single hash" {
    const allocator = std.testing.allocator;
    const text = "Hello, World!";
    const fake_sig = "fake signature data for multi-hash test";

    const result = try createMultiHashCleartextSig(
        allocator,
        text,
        fake_sig,
        &[_]HashAlgorithm{.sha256},
    );
    defer allocator.free(result);

    try std.testing.expect(mem.indexOf(u8, result, "-----BEGIN PGP SIGNED MESSAGE-----") != null);
    try std.testing.expect(mem.indexOf(u8, result, "Hash: SHA256") != null);
    try std.testing.expect(mem.indexOf(u8, result, "-----BEGIN PGP SIGNATURE-----") != null);
    try std.testing.expect(mem.indexOf(u8, result, "-----END PGP SIGNATURE-----") != null);
}

test "createMultiHashCleartextSig multiple hashes" {
    const allocator = std.testing.allocator;
    const text = "Multi-hash signed message";
    const fake_sig = "multi sig data";

    const result = try createMultiHashCleartextSig(
        allocator,
        text,
        fake_sig,
        &[_]HashAlgorithm{ .sha256, .sha512 },
    );
    defer allocator.free(result);

    try std.testing.expect(mem.indexOf(u8, result, "Hash: SHA256") != null);
    try std.testing.expect(mem.indexOf(u8, result, "Hash: SHA512") != null);
}

test "createMultiHashCleartextSig empty algos" {
    const allocator = std.testing.allocator;
    const empty_algos: []const HashAlgorithm = &.{};
    const result = createMultiHashCleartextSig(allocator, "text", "sig", empty_algos);
    try std.testing.expectError(error.MissingHashAlgorithm, result);
}

test "createCombinedHashCleartextSig" {
    const allocator = std.testing.allocator;
    const text = "Combined hash message";
    const fake_sig = "sig data for combined";

    const result = try createCombinedHashCleartextSig(
        allocator,
        text,
        fake_sig,
        &[_]HashAlgorithm{ .sha256, .sha512 },
    );
    defer allocator.free(result);

    // Should have a single Hash: line with comma-separated values
    try std.testing.expect(mem.indexOf(u8, result, "Hash: SHA256, SHA512") != null);
}

test "createCombinedHashCleartextSig empty algos" {
    const allocator = std.testing.allocator;
    const empty_algos: []const HashAlgorithm = &.{};
    const result = createCombinedHashCleartextSig(allocator, "text", "sig", empty_algos);
    try std.testing.expectError(error.MissingHashAlgorithm, result);
}

test "canonicalizeForSigning basic" {
    const allocator = std.testing.allocator;
    const input = "Hello   \nWorld\t\t\nFoo";
    const expected = "Hello\r\nWorld\r\nFoo";
    const result = try canonicalizeForSigning(allocator, input);
    defer allocator.free(result);
    try std.testing.expectEqualStrings(expected, result);
}

test "canonicalizeForSigning preserves content" {
    const allocator = std.testing.allocator;
    const input = "No trailing spaces\nSame here";
    const expected = "No trailing spaces\r\nSame here";
    const result = try canonicalizeForSigning(allocator, input);
    defer allocator.free(result);
    try std.testing.expectEqualStrings(expected, result);
}

test "canonicalizeForSigning empty" {
    const allocator = std.testing.allocator;
    const result = try canonicalizeForSigning(allocator, "");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "canonicalizeForSigning single line" {
    const allocator = std.testing.allocator;
    const result = try canonicalizeForSigning(allocator, "Hello  ");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello", result);
}

test "canonicalizeForSigning CRLF input" {
    const allocator = std.testing.allocator;
    const input = "Line1\r\nLine2  \r\nLine3";
    const expected = "Line1\r\nLine2\r\nLine3";
    const result = try canonicalizeForSigning(allocator, input);
    defer allocator.free(result);
    try std.testing.expectEqualStrings(expected, result);
}

test "validateCleartextFormat valid message" {
    const allocator = std.testing.allocator;
    const msg =
        "-----BEGIN PGP SIGNED MESSAGE-----\n" ++
        "Hash: SHA256\n" ++
        "\n" ++
        "Hello, World!\n" ++
        "-----BEGIN PGP SIGNATURE-----\n" ++
        "\n" ++
        "aWdub3JlIHRoaXM=\n" ++
        "=ABCD\n" ++
        "-----END PGP SIGNATURE-----\n";

    var result = try validateCleartextFormat(allocator, msg);
    defer result.deinit(allocator);

    try std.testing.expect(result.valid);
    try std.testing.expectEqual(@as(usize, 1), result.hash_headers.len);
    try std.testing.expectEqualStrings("SHA256", result.hash_headers[0]);
}

test "validateCleartextFormat multiple hashes" {
    const allocator = std.testing.allocator;
    const msg =
        "-----BEGIN PGP SIGNED MESSAGE-----\n" ++
        "Hash: SHA256\n" ++
        "Hash: SHA512\n" ++
        "\n" ++
        "Multi-hash message\n" ++
        "-----BEGIN PGP SIGNATURE-----\n" ++
        "\n" ++
        "aWdub3JlIHRoaXM=\n" ++
        "=ABCD\n" ++
        "-----END PGP SIGNATURE-----\n";

    var result = try validateCleartextFormat(allocator, msg);
    defer result.deinit(allocator);

    try std.testing.expect(result.valid);
    try std.testing.expectEqual(@as(usize, 2), result.hash_headers.len);
    try std.testing.expectEqualStrings("SHA256", result.hash_headers[0]);
    try std.testing.expectEqualStrings("SHA512", result.hash_headers[1]);
}

test "validateCleartextFormat comma-separated hashes" {
    const allocator = std.testing.allocator;
    const msg =
        "-----BEGIN PGP SIGNED MESSAGE-----\n" ++
        "Hash: SHA256, SHA384\n" ++
        "\n" ++
        "Text\n" ++
        "-----BEGIN PGP SIGNATURE-----\n" ++
        "\n" ++
        "aWdub3JlIHRoaXM=\n" ++
        "=ABCD\n" ++
        "-----END PGP SIGNATURE-----\n";

    var result = try validateCleartextFormat(allocator, msg);
    defer result.deinit(allocator);

    try std.testing.expect(result.valid);
    try std.testing.expectEqual(@as(usize, 2), result.hash_headers.len);
}

test "validateCleartextFormat missing begin marker" {
    const allocator = std.testing.allocator;
    const msg = "Hash: SHA256\nHello\n-----BEGIN PGP SIGNATURE-----\n-----END PGP SIGNATURE-----\n";

    var result = try validateCleartextFormat(allocator, msg);
    defer result.deinit(allocator);

    try std.testing.expect(!result.valid);
    try std.testing.expect(result.issues.len > 0);
}

test "validateCleartextFormat missing signature block" {
    const allocator = std.testing.allocator;
    const msg = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nHello\n";

    var result = try validateCleartextFormat(allocator, msg);
    defer result.deinit(allocator);

    try std.testing.expect(!result.valid);
}

test "validateCleartextFormat unknown hash" {
    const allocator = std.testing.allocator;
    const msg =
        "-----BEGIN PGP SIGNED MESSAGE-----\n" ++
        "Hash: BOGUS_HASH\n" ++
        "\n" ++
        "Text\n" ++
        "-----BEGIN PGP SIGNATURE-----\n" ++
        "\n" ++
        "aWdub3JlIHRoaXM=\n" ++
        "=ABCD\n" ++
        "-----END PGP SIGNATURE-----\n";

    var result = try validateCleartextFormat(allocator, msg);
    defer result.deinit(allocator);

    // Structurally valid but with warnings about unknown hash
    try std.testing.expect(result.valid);
    try std.testing.expect(result.issues.len > 0);
}

test "CleartextValidation deinit" {
    const allocator = std.testing.allocator;
    const h_val = try allocator.dupe(u8, "SHA256");
    const issue_val = try allocator.dupe(u8, "some issue");

    const hashes = try allocator.alloc([]u8, 1);
    hashes[0] = h_val;
    const issue_arr = try allocator.alloc([]u8, 1);
    issue_arr[0] = issue_val;

    const val = CleartextValidation{
        .valid = true,
        .hash_headers = hashes,
        .issues = issue_arr,
    };
    val.deinit(allocator);
}

test "dashEscape preserves non-dash lines" {
    const allocator = std.testing.allocator;
    const input = "Hello\nWorld";
    const result = try dashEscape(allocator, input);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello\nWorld", result);
}

test "dashEscape escapes dash lines" {
    const allocator = std.testing.allocator;
    const input = "-Dashed line\n--Double";
    const result = try dashEscape(allocator, input);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("- -Dashed line\n- --Double", result);
}

test "dashUnescape round-trip" {
    const allocator = std.testing.allocator;
    const original = "-Dashed\nNormal\n--Double";
    const escaped = try dashEscape(allocator, original);
    defer allocator.free(escaped);
    const unescaped = try dashUnescape(allocator, escaped);
    defer allocator.free(unescaped);
    try std.testing.expectEqualStrings(original, unescaped);
}

test "hashAlgorithmName round-trip" {
    const algos = [_]HashAlgorithm{ .sha1, .sha256, .sha384, .sha512, .sha224 };
    for (algos) |algo| {
        const name = hashAlgorithmName(algo);
        const parsed = parseHashName(name);
        try std.testing.expectEqual(algo, parsed.?);
    }
}

test "parseHashName unknown" {
    try std.testing.expect(parseHashName("BOGUS") == null);
}

test "MultiHashCleartextMessage deinit" {
    const allocator = std.testing.allocator;
    const text_data = try allocator.dupe(u8, "test text");
    const sig_data = try allocator.dupe(u8, "sig");
    const algos = try allocator.alloc(HashAlgorithm, 1);
    algos[0] = .sha256;

    const msg = MultiHashCleartextMessage{
        .text = text_data,
        .signature_data = sig_data,
        .hash_algos = algos,
    };
    msg.deinit(allocator);
}
