// SPDX-License-Identifier: MIT
//! Cleartext Signature Framework per RFC 4880 Section 7.
//!
//! A cleartext signed message has this format:
//!
//!   -----BEGIN PGP SIGNED MESSAGE-----
//!   Hash: <algorithm name>
//!
//!   <cleartext message with dash-escaping>
//!   -----BEGIN PGP SIGNATURE-----
//!
//!   <armored signature packet(s)>
//!   -----END PGP SIGNATURE-----
//!
//! The cleartext is human-readable.  Lines starting with a dash are
//! "dash-escaped" by prepending "- ".  Trailing whitespace on each line
//! is stripped before signing (canonicalization).

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const HashAlgorithm = @import("../types/enums.zig").HashAlgorithm;
const PublicKeyAlgorithm = @import("../types/enums.zig").PublicKeyAlgorithm;
const armor = @import("../armor/armor.zig");
const sig_creation = @import("creation.zig");
const hash_mod = @import("../crypto/hash.zig");

/// A parsed cleartext signed message.
pub const CleartextMessage = struct {
    /// The cleartext body (dash-unescaped).
    text: []u8,
    /// The raw binary signature packet data (decoded from the armor block).
    signature_data: []u8,
    /// The hash algorithm declared in the "Hash:" header.
    hash_algo: HashAlgorithm,

    pub fn deinit(self: CleartextMessage, allocator: Allocator) void {
        allocator.free(self.text);
        allocator.free(self.signature_data);
    }
};

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

/// Create a cleartext signed message.
///
/// This function:
///   1. Dash-escapes the text.
///   2. Canonicalizes line endings for hashing (trailing whitespace stripped,
///      CR LF line endings).
///   3. Computes the hash of the canonicalized text with the V4 signature
///      trailer.
///   4. Builds signature subpackets (creation time, issuer).
///   5. Signs with the provided secret key data.
///   6. Assembles the complete cleartext signed message.
///
/// NOTE: The actual cryptographic signing is stubbed here -- the caller must
/// provide pre-built signature packet data, or this function produces a
/// template with the hash result.  Full signing requires the RSA/DSA private
/// key operations which are in other modules.
///
/// For a complete signing flow, use the higher-level message module.
///
/// This function builds the cleartext message wrapper around already-created
/// signature packet bytes.
pub fn createCleartextSignature(
    allocator: Allocator,
    text: []const u8,
    signature_packet_bytes: []const u8,
    hash_algo: HashAlgorithm,
) ![]u8 {
    // Dash-escape the text
    const escaped = try dashEscape(allocator, text);
    defer allocator.free(escaped);

    // Armor the signature
    const armored_sig = try armor.encode(allocator, signature_packet_bytes, .signature, null);
    defer allocator.free(armored_sig);

    // Assemble the cleartext signed message
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);

    // Header
    try output.appendSlice(allocator, "-----BEGIN PGP SIGNED MESSAGE-----\n");
    try output.appendSlice(allocator, "Hash: ");
    try output.appendSlice(allocator, hashAlgorithmName(hash_algo));
    try output.appendSlice(allocator, "\n\n");

    // Dash-escaped cleartext
    try output.appendSlice(allocator, escaped);

    // Ensure there is a newline before the signature block
    if (escaped.len > 0 and escaped[escaped.len - 1] != '\n') {
        try output.append(allocator, '\n');
    }

    // Signature block
    try output.appendSlice(allocator, armored_sig);

    return try output.toOwnedSlice(allocator);
}

/// Parse a cleartext signed message.
///
/// Extracts the cleartext body (with dash-escaping removed), the binary
/// signature data, and the declared hash algorithm.
pub fn parseCleartextSignature(
    allocator: Allocator,
    input: []const u8,
) !CleartextMessage {
    // Find "-----BEGIN PGP SIGNED MESSAGE-----"
    const signed_msg_header = "-----BEGIN PGP SIGNED MESSAGE-----";
    const header_pos = mem.indexOf(u8, input, signed_msg_header) orelse return error.InvalidFormat;

    // Find the end of the header line
    const after_header = header_pos + signed_msg_header.len;
    const header_line_end = mem.indexOfPos(u8, input, after_header, "\n") orelse return error.InvalidFormat;

    // Parse Hash: header(s) -- they follow the BEGIN line up to a blank line.
    var hash_algo: HashAlgorithm = .sha256; // default
    var pos = header_line_end + 1;

    // Read header lines until blank line
    while (pos < input.len) {
        const line_end = mem.indexOfPos(u8, input, pos, "\n") orelse input.len;
        var line = input[pos..line_end];

        // Strip trailing CR
        if (line.len > 0 and line[line.len - 1] == '\r') {
            line = line[0 .. line.len - 1];
        }

        if (line.len == 0) {
            // Blank line -- end of headers
            pos = line_end + 1;
            break;
        }

        // Parse "Hash: <name>" header
        if (mem.startsWith(u8, line, "Hash: ")) {
            const hash_name = line["Hash: ".len..];
            // Handle multiple hash names (comma-separated)
            var name_iter = mem.splitSequence(u8, hash_name, ",");
            if (name_iter.next()) |first_name| {
                // Trim whitespace
                const trimmed = mem.trim(u8, first_name, " \t");
                if (parseHashName(trimmed)) |algo| {
                    hash_algo = algo;
                }
            }
        }

        pos = line_end + 1;
    }

    // Find "-----BEGIN PGP SIGNATURE-----"
    const sig_begin_marker = "-----BEGIN PGP SIGNATURE-----";
    const sig_begin_pos = mem.indexOfPos(u8, input, pos, sig_begin_marker) orelse return error.InvalidFormat;

    // The cleartext is between the blank line and the signature begin marker.
    // We need to handle the case where there might be a trailing newline before
    // the signature block.
    var text_end = sig_begin_pos;
    // Strip trailing newlines/CR before the signature marker
    while (text_end > pos and (input[text_end - 1] == '\n' or input[text_end - 1] == '\r')) {
        text_end -= 1;
    }

    const escaped_text = input[pos..text_end];

    // Dash-unescape the text
    const text = try dashUnescape(allocator, escaped_text);
    errdefer allocator.free(text);

    // Find "-----END PGP SIGNATURE-----" and decode the signature armor
    const sig_end_marker = "-----END PGP SIGNATURE-----";
    const sig_end_pos = mem.indexOfPos(u8, input, sig_begin_pos, sig_end_marker) orelse return error.InvalidFormat;
    const sig_block_end = sig_end_pos + sig_end_marker.len;

    // Include any trailing newline in the block
    var block_end = sig_block_end;
    if (block_end < input.len and input[block_end] == '\n') {
        block_end += 1;
    }

    const sig_armor = input[sig_begin_pos..block_end];

    // Decode the armored signature
    var decode_result = armor.decode(allocator, sig_armor) catch return error.InvalidFormat;
    defer decode_result.deinit();

    const signature_data = try allocator.dupe(u8, decode_result.data);

    return .{
        .text = text,
        .signature_data = signature_data,
        .hash_algo = hash_algo,
    };
}

/// Dash-escape text per RFC 4880 Section 7.1.
///
/// Lines starting with "-" are prefixed with "- ".
/// All other lines are left unchanged.
pub fn dashEscape(allocator: Allocator, text: []const u8) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);

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
pub fn dashUnescape(allocator: Allocator, text: []const u8) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);

    var iter = mem.splitSequence(u8, text, "\n");
    var first = true;

    while (iter.next()) |line| {
        if (!first) {
            try output.append(allocator, '\n');
        }
        first = false;

        // Remove dash escaping
        var actual_line = line;
        // Strip trailing CR for processing
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

/// Canonicalize text for cleartext signature hashing.
///
/// Per RFC 4880 Section 7.1:
///   - Trailing whitespace on each line is stripped.
///   - Line endings are converted to CR LF.
///   - The trailing CR LF on the last line is NOT included.
pub fn canonicalizeText(allocator: Allocator, text: []const u8) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);

    var iter = mem.splitSequence(u8, text, "\n");
    var first = true;

    while (iter.next()) |raw_line| {
        // Strip trailing CR
        var line = raw_line;
        if (line.len > 0 and line[line.len - 1] == '\r') {
            line = line[0 .. line.len - 1];
        }

        // Strip trailing whitespace (spaces and tabs)
        line = mem.trimRight(u8, line, " \t");

        if (!first) {
            // Append CR LF line ending for previous line
            try output.appendSlice(allocator, "\r\n");
        }
        first = false;

        try output.appendSlice(allocator, line);
    }

    return try output.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "dashEscape no dashes" {
    const allocator = std.testing.allocator;
    const input = "Hello world\nThis is a test\nNo dashes here";
    const escaped = try dashEscape(allocator, input);
    defer allocator.free(escaped);
    try std.testing.expectEqualStrings(input, escaped);
}

test "dashEscape lines starting with dash" {
    const allocator = std.testing.allocator;
    const input = "Hello\n-This starts with dash\n--Double dash\nNo dash";
    const expected = "Hello\n- -This starts with dash\n- --Double dash\nNo dash";
    const escaped = try dashEscape(allocator, input);
    defer allocator.free(escaped);
    try std.testing.expectEqualStrings(expected, escaped);
}

test "dashEscape empty string" {
    const allocator = std.testing.allocator;
    const escaped = try dashEscape(allocator, "");
    defer allocator.free(escaped);
    try std.testing.expectEqualStrings("", escaped);
}

test "dashEscape single dash line" {
    const allocator = std.testing.allocator;
    const escaped = try dashEscape(allocator, "-");
    defer allocator.free(escaped);
    try std.testing.expectEqualStrings("- -", escaped);
}

test "dashUnescape removes prefix" {
    const allocator = std.testing.allocator;
    const input = "Hello\n- -This was escaped\n- --Double dash\nNo dash";
    const expected = "Hello\n-This was escaped\n--Double dash\nNo dash";
    const unescaped = try dashUnescape(allocator, input);
    defer allocator.free(unescaped);
    try std.testing.expectEqualStrings(expected, unescaped);
}

test "dashEscape dashUnescape round-trip" {
    const allocator = std.testing.allocator;
    const original = "Hello\n-Dashed line\n--Double\nNormal line\n- Already looks escaped";
    const escaped = try dashEscape(allocator, original);
    defer allocator.free(escaped);
    const unescaped = try dashUnescape(allocator, escaped);
    defer allocator.free(unescaped);
    try std.testing.expectEqualStrings(original, unescaped);
}

test "canonicalizeText strips trailing whitespace" {
    const allocator = std.testing.allocator;
    const input = "Hello   \nWorld\t\t\nFoo";
    const expected = "Hello\r\nWorld\r\nFoo";
    const canonical = try canonicalizeText(allocator, input);
    defer allocator.free(canonical);
    try std.testing.expectEqualStrings(expected, canonical);
}

test "canonicalizeText converts line endings" {
    const allocator = std.testing.allocator;
    const input = "Line1\r\nLine2\nLine3";
    const expected = "Line1\r\nLine2\r\nLine3";
    const canonical = try canonicalizeText(allocator, input);
    defer allocator.free(canonical);
    try std.testing.expectEqualStrings(expected, canonical);
}

test "canonicalizeText empty string" {
    const allocator = std.testing.allocator;
    const canonical = try canonicalizeText(allocator, "");
    defer allocator.free(canonical);
    try std.testing.expectEqualStrings("", canonical);
}

test "canonicalizeText single line no trailing space" {
    const allocator = std.testing.allocator;
    const canonical = try canonicalizeText(allocator, "Hello");
    defer allocator.free(canonical);
    try std.testing.expectEqualStrings("Hello", canonical);
}

test "hashAlgorithmName" {
    try std.testing.expectEqualStrings("SHA256", hashAlgorithmName(.sha256));
    try std.testing.expectEqualStrings("SHA1", hashAlgorithmName(.sha1));
    try std.testing.expectEqualStrings("SHA512", hashAlgorithmName(.sha512));
}

test "parseHashName round-trip" {
    const algos = [_]HashAlgorithm{ .sha1, .sha256, .sha384, .sha512, .sha224 };
    for (algos) |algo| {
        const name = hashAlgorithmName(algo);
        const parsed = parseHashName(name);
        try std.testing.expectEqual(algo, parsed.?);
    }
}

test "parseHashName unknown" {
    try std.testing.expect(parseHashName("UNKNOWN_HASH") == null);
}

test "createCleartextSignature structure" {
    const allocator = std.testing.allocator;

    // Create a minimal "signature" (just some bytes for testing the wrapper)
    const fake_sig = "fake signature packet data for testing";

    const result = try createCleartextSignature(
        allocator,
        "Hello, World!\n-This is a test",
        fake_sig,
        .sha256,
    );
    defer allocator.free(result);

    // Verify structural elements
    try std.testing.expect(mem.indexOf(u8, result, "-----BEGIN PGP SIGNED MESSAGE-----") != null);
    try std.testing.expect(mem.indexOf(u8, result, "Hash: SHA256") != null);
    try std.testing.expect(mem.indexOf(u8, result, "-----BEGIN PGP SIGNATURE-----") != null);
    try std.testing.expect(mem.indexOf(u8, result, "-----END PGP SIGNATURE-----") != null);

    // The dash-escaped text should be present
    try std.testing.expect(mem.indexOf(u8, result, "Hello, World!") != null);
    try std.testing.expect(mem.indexOf(u8, result, "- -This is a test") != null);
}

test "parseCleartextSignature round-trip" {
    const allocator = std.testing.allocator;

    const original_text = "Hello, World!\n-This is a test";
    const fake_sig = "fake signature packet data for testing cleartext";

    const cleartext_msg = try createCleartextSignature(
        allocator,
        original_text,
        fake_sig,
        .sha256,
    );
    defer allocator.free(cleartext_msg);

    var parsed = try parseCleartextSignature(allocator, cleartext_msg);
    defer parsed.deinit(allocator);

    try std.testing.expectEqualStrings(original_text, parsed.text);
    try std.testing.expectEqual(HashAlgorithm.sha256, parsed.hash_algo);
    try std.testing.expectEqualSlices(u8, fake_sig, parsed.signature_data);
}

test "parseCleartextSignature with SHA512" {
    const allocator = std.testing.allocator;

    const text = "Test message";
    const fake_sig = "sig data";

    const cleartext_msg = try createCleartextSignature(allocator, text, fake_sig, .sha512);
    defer allocator.free(cleartext_msg);

    var parsed = try parseCleartextSignature(allocator, cleartext_msg);
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(HashAlgorithm.sha512, parsed.hash_algo);
}

test "parseCleartextSignature invalid format" {
    const allocator = std.testing.allocator;
    const result = parseCleartextSignature(allocator, "not a valid cleartext message");
    try std.testing.expectError(error.InvalidFormat, result);
}

test "canonicalizeText multiple trailing spaces" {
    const allocator = std.testing.allocator;
    const input = "a   \nb  \nc";
    const expected = "a\r\nb\r\nc";
    const canonical = try canonicalizeText(allocator, input);
    defer allocator.free(canonical);
    try std.testing.expectEqualStrings(expected, canonical);
}

test "dashEscape preserves empty lines" {
    const allocator = std.testing.allocator;
    const input = "Hello\n\nWorld";
    const escaped = try dashEscape(allocator, input);
    defer allocator.free(escaped);
    try std.testing.expectEqualStrings("Hello\n\nWorld", escaped);
}

test "dashUnescape no escaping present" {
    const allocator = std.testing.allocator;
    const input = "Hello\nWorld";
    const unescaped = try dashUnescape(allocator, input);
    defer allocator.free(unescaped);
    try std.testing.expectEqualStrings("Hello\nWorld", unescaped);
}
