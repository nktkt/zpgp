// SPDX-License-Identifier: MIT
//! GPG agent protocol (Assuan) support.
//!
//! The Assuan protocol is a simple line-based protocol used for communication
//! between GnuPG components (gpg, gpg-agent, scdaemon, etc.).
//!
//! Protocol overview:
//!   - Client sends commands as single lines terminated by LF.
//!   - Server responds with "OK", "ERR <code> <description>", or
//!     "D <data>" lines, followed by "OK" or "ERR".
//!   - The server may also send "S <keyword> <status>" lines for
//!     progress and status updates.
//!   - "INQUIRE <keyword>" requests data from the client.
//!
//! Special characters in data are percent-encoded: %XX where XX is the
//! hex value of the byte. Specifically, CR, LF, and '%' must be encoded.
//!
//! Reference: https://www.gnupg.org/documentation/manuals/assuan/

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// An Assuan protocol command.
pub const AssuanCommand = struct {
    /// The command verb (e.g., "GETINFO", "HAVEKEY", "SIGKEY").
    command: []const u8,
    /// Optional argument string (percent-encoded if necessary).
    args: ?[]const u8,

    /// Serialize the command to a protocol line (terminated by LF).
    pub fn serialize(self: AssuanCommand, allocator: Allocator) ![]u8 {
        if (self.args) |a| {
            const total_len = self.command.len + 1 + a.len + 1; // "CMD args\n"
            const result = try allocator.alloc(u8, total_len);
            var offset: usize = 0;
            @memcpy(result[0..self.command.len], self.command);
            offset += self.command.len;
            result[offset] = ' ';
            offset += 1;
            @memcpy(result[offset..][0..a.len], a);
            offset += a.len;
            result[offset] = '\n';
            return result;
        } else {
            const result = try allocator.alloc(u8, self.command.len + 1);
            @memcpy(result[0..self.command.len], self.command);
            result[self.command.len] = '\n';
            return result;
        }
    }
};

/// Server response status.
pub const ResponseStatus = enum {
    /// Command succeeded.
    ok,
    /// Command failed with an error.
    err,
    /// Data line (part of a multi-line response).
    data_line,
    /// Server is requesting data from the client.
    inquire,
    /// Status/progress information.
    status,
    /// Comment line (begins with #).
    comment,
    /// Unknown response type.
    unknown,
};

/// A parsed Assuan protocol response line.
pub const AssuanResponse = struct {
    /// The response status.
    status: ResponseStatus,
    /// Optional data payload (decoded from percent-encoding for D lines).
    data: ?[]u8,
    /// Error code (only meaningful when status == .err).
    error_code: u32,
    /// Status keyword (only meaningful when status == .status).
    keyword: ?[]const u8,

    pub fn deinit(self: AssuanResponse, allocator: Allocator) void {
        if (self.data) |d| allocator.free(d);
    }

    /// Parse a single Assuan response line.
    ///
    /// Does NOT consume the trailing LF; the caller should strip it first.
    pub fn parse(allocator: Allocator, line: []const u8) !AssuanResponse {
        // Strip trailing CR/LF
        var trimmed = line;
        if (trimmed.len > 0 and trimmed[trimmed.len - 1] == '\n') trimmed = trimmed[0 .. trimmed.len - 1];
        if (trimmed.len > 0 and trimmed[trimmed.len - 1] == '\r') trimmed = trimmed[0 .. trimmed.len - 1];

        if (trimmed.len == 0) {
            return .{ .status = .unknown, .data = null, .error_code = 0, .keyword = null };
        }

        // OK [optional text]
        if (mem.eql(u8, trimmed, "OK") or mem.startsWith(u8, trimmed, "OK ")) {
            const text = if (trimmed.len > 3) trimmed[3..] else null;
            const data = if (text) |t|
                try allocator.dupe(u8, t)
            else
                null;
            return .{ .status = .ok, .data = data, .error_code = 0, .keyword = null };
        }

        // ERR <code> [description]
        if (mem.startsWith(u8, trimmed, "ERR ")) {
            const after_err = trimmed[4..];
            const space_pos = mem.indexOf(u8, after_err, " ") orelse after_err.len;
            const code_str = after_err[0..space_pos];
            const code = std.fmt.parseInt(u32, code_str, 10) catch 0;
            const desc = if (space_pos < after_err.len)
                try allocator.dupe(u8, after_err[space_pos + 1 ..])
            else
                null;
            return .{ .status = .err, .data = desc, .error_code = code, .keyword = null };
        }

        // D <data>
        if (mem.startsWith(u8, trimmed, "D ")) {
            const encoded = trimmed[2..];
            const decoded = try assuanDecode(allocator, encoded);
            return .{ .status = .data_line, .data = decoded, .error_code = 0, .keyword = null };
        }

        // S <keyword> [args]
        if (mem.startsWith(u8, trimmed, "S ")) {
            const after_s = trimmed[2..];
            const space_pos = mem.indexOf(u8, after_s, " ");
            const kw = if (space_pos) |sp| after_s[0..sp] else after_s;
            const data = if (space_pos) |sp|
                (if (sp + 1 < after_s.len) try allocator.dupe(u8, after_s[sp + 1 ..]) else null)
            else
                null;
            return .{ .status = .status, .data = data, .error_code = 0, .keyword = kw };
        }

        // INQUIRE <keyword>
        if (mem.startsWith(u8, trimmed, "INQUIRE ")) {
            const kw = trimmed[8..];
            return .{ .status = .inquire, .data = null, .error_code = 0, .keyword = kw };
        }

        // Comment
        if (trimmed[0] == '#') {
            const data = try allocator.dupe(u8, trimmed[1..]);
            return .{ .status = .comment, .data = data, .error_code = 0, .keyword = null };
        }

        // Unknown
        const data = try allocator.dupe(u8, trimmed);
        return .{ .status = .unknown, .data = data, .error_code = 0, .keyword = null };
    }
};

// ===========================================================================
// Common gpg-agent command builders
// ===========================================================================

/// Build a GET_PASSPHRASE command.
///
/// Requests a passphrase from the agent, optionally caching it under
/// `cache_id`. The `prompt` and `description` are shown to the user.
pub fn getPassphrase(
    allocator: Allocator,
    cache_id: []const u8,
    error_msg: []const u8,
    prompt: []const u8,
    description: []const u8,
) !AssuanCommand {
    // Format: GET_PASSPHRASE <cache_id> <error_msg> <prompt> <description>
    // Each component is percent-encoded
    const enc_cache = try assuanEncode(allocator, cache_id);
    defer allocator.free(enc_cache);
    const enc_error = try assuanEncode(allocator, error_msg);
    defer allocator.free(enc_error);
    const enc_prompt = try assuanEncode(allocator, prompt);
    defer allocator.free(enc_prompt);
    const enc_desc = try assuanEncode(allocator, description);
    defer allocator.free(enc_desc);

    const args = try std.fmt.allocPrint(
        allocator,
        "{s} {s} {s} {s}",
        .{ enc_cache, enc_error, enc_prompt, enc_desc },
    );

    return .{ .command = "GET_PASSPHRASE", .args = args };
}

/// Build a CLEAR_PASSPHRASE command to remove a cached passphrase.
pub fn clearPassphrase(cache_id: []const u8) AssuanCommand {
    return .{ .command = "CLEAR_PASSPHRASE", .args = cache_id };
}

/// Build a SIGKEY command to select a key for signing.
pub fn signKey(key_grip: []const u8) AssuanCommand {
    return .{ .command = "SIGKEY", .args = key_grip };
}

/// Build a SETHASH command to set the hash for signing.
///
/// `algo` is the hash algorithm number, `hash_hex` is the hex-encoded digest.
pub fn setHash(allocator: Allocator, algo: u8, hash_hex: []const u8) !AssuanCommand {
    const args = try std.fmt.allocPrint(allocator, "{d} {s}", .{ algo, hash_hex });
    return .{ .command = "SETHASH", .args = args };
}

/// Build a PKSIGN command to perform the actual signing.
pub fn pkSign() AssuanCommand {
    return .{ .command = "PKSIGN", .args = null };
}

/// Build a PKDECRYPT command to decrypt data.
pub fn pkDecrypt() AssuanCommand {
    return .{ .command = "PKDECRYPT", .args = null };
}

/// Build a SETKEY command to select a key for decryption.
pub fn setKey(key_grip: []const u8) AssuanCommand {
    return .{ .command = "SETKEY", .args = key_grip };
}

/// Build a HAVEKEY command to check if the agent has a specific secret key.
pub fn haveSecretKey(key_grip: []const u8) AssuanCommand {
    return .{ .command = "HAVEKEY", .args = key_grip };
}

/// Build a GETINFO command to query agent information.
pub fn getInfo(what: []const u8) AssuanCommand {
    return .{ .command = "GETINFO", .args = what };
}

/// Build a KEYINFO command to get information about a key.
pub fn keyInfo(key_grip: []const u8) AssuanCommand {
    return .{ .command = "KEYINFO", .args = key_grip };
}

/// Build a RESET command.
pub fn reset() AssuanCommand {
    return .{ .command = "RESET", .args = null };
}

/// Build a BYE command to close the connection.
pub fn bye() AssuanCommand {
    return .{ .command = "BYE", .args = null };
}

/// Build an OPTION command to set an agent option.
pub fn option(allocator: Allocator, name: []const u8, value: []const u8) !AssuanCommand {
    const args = try std.fmt.allocPrint(allocator, "{s}={s}", .{ name, value });
    return .{ .command = "OPTION", .args = args };
}

// ===========================================================================
// Assuan percent-encoding
// ===========================================================================

/// Percent-encode data for the Assuan protocol.
///
/// Characters that must be encoded: LF (0x0A), CR (0x0D), and '%' (0x25).
/// All other characters with value < 0x20 are also encoded for safety.
pub fn assuanEncode(allocator: Allocator, data: []const u8) ![]u8 {
    // Count bytes that need encoding
    var encoded_len: usize = 0;
    for (data) |byte| {
        if (needsEncoding(byte)) {
            encoded_len += 3; // %XX
        } else {
            encoded_len += 1;
        }
    }

    const result = try allocator.alloc(u8, encoded_len);
    var offset: usize = 0;

    const hex_chars = "0123456789ABCDEF";
    for (data) |byte| {
        if (needsEncoding(byte)) {
            result[offset] = '%';
            result[offset + 1] = hex_chars[byte >> 4];
            result[offset + 2] = hex_chars[byte & 0x0F];
            offset += 3;
        } else {
            result[offset] = byte;
            offset += 1;
        }
    }

    return result;
}

/// Decode percent-encoded Assuan data.
pub fn assuanDecode(allocator: Allocator, data: []const u8) ![]u8 {
    // Count output bytes
    var decoded_len: usize = 0;
    var i: usize = 0;
    while (i < data.len) {
        if (data[i] == '%' and i + 2 < data.len) {
            decoded_len += 1;
            i += 3;
        } else {
            decoded_len += 1;
            i += 1;
        }
    }

    const result = try allocator.alloc(u8, decoded_len);
    var out_idx: usize = 0;
    i = 0;

    while (i < data.len) {
        if (data[i] == '%' and i + 2 < data.len) {
            const high = hexDigitValue(data[i + 1]) orelse {
                result[out_idx] = data[i];
                out_idx += 1;
                i += 1;
                continue;
            };
            const low = hexDigitValue(data[i + 2]) orelse {
                result[out_idx] = data[i];
                out_idx += 1;
                i += 1;
                continue;
            };
            result[out_idx] = (@as(u8, high) << 4) | @as(u8, low);
            out_idx += 1;
            i += 3;
        } else {
            result[out_idx] = data[i];
            out_idx += 1;
            i += 1;
        }
    }

    // If decoded length differs from pre-calculated (shouldn't happen),
    // shrink the result
    if (out_idx < result.len) {
        const shrunk = allocator.realloc(result, out_idx) catch return result[0..out_idx];
        return shrunk;
    }

    return result;
}

/// Check if a byte needs Assuan percent-encoding.
fn needsEncoding(byte: u8) bool {
    return byte < 0x20 or byte == '%';
}

/// Convert a hex digit character to its numeric value.
fn hexDigitValue(c: u8) ?u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'A'...'F' => @intCast(c - 'A' + 10),
        'a'...'f' => @intCast(c - 'a' + 10),
        else => null,
    };
}

// ===========================================================================
// Key grip calculation
// ===========================================================================

/// Calculate the key grip for an RSA key.
///
/// The key grip is the SHA-1 hash of the public key parameters encoded
/// in a GnuPG-specific S-expression format:
///
///   (public-key (rsa (n #<hex-n>#) (e #<hex-e>#)))
///
/// For Ed25519 keys:
///   (public-key (ecc (curve Ed25519) (q #<hex-q>#)))
///
/// The key grip uniquely identifies a key in the gpg-agent storage.
pub fn calculateRsaKeyGrip(rsa_n: []const u8) [20]u8 {
    // The key grip for RSA is SHA-1 of the modulus n with leading zero stripped.
    // GnuPG computes it as SHA-1 of:
    //   "(20:)" + n-bytes
    // But the simplified version that GnuPG actually uses is just SHA-1 of the
    // canonical S-expression encoding of the key parameters.
    //
    // For compatibility, we compute SHA-1 of the raw modulus bytes.
    var sha1 = std.crypto.hash.Sha1.init(.{});

    // Strip leading zeros from the modulus
    var n = rsa_n;
    while (n.len > 1 and n[0] == 0) {
        n = n[1..];
    }

    sha1.update(n);
    return sha1.finalResult();
}

/// Calculate the key grip for an Ed25519 key.
pub fn calculateEd25519KeyGrip(pubkey: []const u8) [20]u8 {
    var sha1 = std.crypto.hash.Sha1.init(.{});
    sha1.update(pubkey);
    return sha1.finalResult();
}

/// Format a key grip as a hex string (uppercase, 40 characters).
pub fn formatKeyGrip(allocator: Allocator, grip: [20]u8) ![]u8 {
    const hex_chars = "0123456789ABCDEF";
    const result = try allocator.alloc(u8, 40);
    for (grip, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0F];
    }
    return result;
}

/// Parse a key grip from a hex string.
pub fn parseKeyGrip(hex: []const u8) !?[20]u8 {
    if (hex.len != 40) return null;

    var result: [20]u8 = undefined;
    for (0..20) |i| {
        const high = hexDigitValue(hex[i * 2]) orelse return null;
        const low = hexDigitValue(hex[i * 2 + 1]) orelse return null;
        result[i] = (@as(u8, high) << 4) | @as(u8, low);
    }
    return result;
}

// ===========================================================================
// GPG agent socket path detection
// ===========================================================================

/// Well-known environment variable for the GPG agent socket path.
pub const GPG_AGENT_INFO_ENV = "GPG_AGENT_INFO";

/// Standard socket name within the GnuPG home directory.
pub const AGENT_SOCKET_NAME = "S.gpg-agent";

/// Determine the GPG home directory.
///
/// Checks GNUPGHOME environment variable first, then falls back to
/// ~/.gnupg.
pub fn gpgHomeDir(allocator: Allocator) ![]u8 {
    // Check GNUPGHOME first
    if (std.posix.getenv("GNUPGHOME")) |home| {
        return try allocator.dupe(u8, home);
    }

    // Fall back to ~/.gnupg
    if (std.posix.getenv("HOME")) |home| {
        return try std.fmt.allocPrint(allocator, "{s}/.gnupg", .{home});
    }

    return error.HomeNotFound;
}

/// Build the expected gpg-agent socket path.
pub fn agentSocketPath(allocator: Allocator) ![]u8 {
    const home = try gpgHomeDir(allocator);
    defer allocator.free(home);
    return try std.fmt.allocPrint(allocator, "{s}/{s}", .{ home, AGENT_SOCKET_NAME });
}

// ===========================================================================
// Tests
// ===========================================================================

test "AssuanCommand serialize with args" {
    const allocator = std.testing.allocator;
    const cmd = AssuanCommand{ .command = "GETINFO", .args = "version" };
    const serialized = try cmd.serialize(allocator);
    defer allocator.free(serialized);
    try std.testing.expectEqualStrings("GETINFO version\n", serialized);
}

test "AssuanCommand serialize without args" {
    const allocator = std.testing.allocator;
    const cmd = AssuanCommand{ .command = "RESET", .args = null };
    const serialized = try cmd.serialize(allocator);
    defer allocator.free(serialized);
    try std.testing.expectEqualStrings("RESET\n", serialized);
}

test "AssuanResponse parse OK" {
    const allocator = std.testing.allocator;
    var resp = try AssuanResponse.parse(allocator, "OK");
    defer resp.deinit(allocator);
    try std.testing.expectEqual(ResponseStatus.ok, resp.status);
    try std.testing.expect(resp.data == null);
}

test "AssuanResponse parse OK with text" {
    const allocator = std.testing.allocator;
    var resp = try AssuanResponse.parse(allocator, "OK Pleased to meet you");
    defer resp.deinit(allocator);
    try std.testing.expectEqual(ResponseStatus.ok, resp.status);
    try std.testing.expectEqualStrings("Pleased to meet you", resp.data.?);
}

test "AssuanResponse parse ERR" {
    const allocator = std.testing.allocator;
    var resp = try AssuanResponse.parse(allocator, "ERR 100 Not found");
    defer resp.deinit(allocator);
    try std.testing.expectEqual(ResponseStatus.err, resp.status);
    try std.testing.expectEqual(@as(u32, 100), resp.error_code);
    try std.testing.expectEqualStrings("Not found", resp.data.?);
}

test "AssuanResponse parse ERR no description" {
    const allocator = std.testing.allocator;
    var resp = try AssuanResponse.parse(allocator, "ERR 67108922");
    defer resp.deinit(allocator);
    try std.testing.expectEqual(ResponseStatus.err, resp.status);
    try std.testing.expectEqual(@as(u32, 67108922), resp.error_code);
    try std.testing.expect(resp.data == null);
}

test "AssuanResponse parse D (data)" {
    const allocator = std.testing.allocator;
    var resp = try AssuanResponse.parse(allocator, "D hello%20world");
    defer resp.deinit(allocator);
    try std.testing.expectEqual(ResponseStatus.data_line, resp.status);
    // %20 is space (0x20), but since 0x20 >= 0x20, it's not encoded by needsEncoding.
    // In percent-decoding, %20 should decode to space.
    try std.testing.expectEqualStrings("hello world", resp.data.?);
}

test "AssuanResponse parse S (status)" {
    const allocator = std.testing.allocator;
    var resp = try AssuanResponse.parse(allocator, "S PROGRESS 50/100");
    defer resp.deinit(allocator);
    try std.testing.expectEqual(ResponseStatus.status, resp.status);
    try std.testing.expectEqualStrings("PROGRESS", resp.keyword.?);
    try std.testing.expectEqualStrings("50/100", resp.data.?);
}

test "AssuanResponse parse INQUIRE" {
    const allocator = std.testing.allocator;
    var resp = try AssuanResponse.parse(allocator, "INQUIRE CIPHERTEXT");
    defer resp.deinit(allocator);
    try std.testing.expectEqual(ResponseStatus.inquire, resp.status);
    try std.testing.expectEqualStrings("CIPHERTEXT", resp.keyword.?);
}

test "AssuanResponse parse comment" {
    const allocator = std.testing.allocator;
    var resp = try AssuanResponse.parse(allocator, "# This is a comment");
    defer resp.deinit(allocator);
    try std.testing.expectEqual(ResponseStatus.comment, resp.status);
    try std.testing.expectEqualStrings(" This is a comment", resp.data.?);
}

test "AssuanResponse parse empty line" {
    const allocator = std.testing.allocator;
    var resp = try AssuanResponse.parse(allocator, "");
    defer resp.deinit(allocator);
    try std.testing.expectEqual(ResponseStatus.unknown, resp.status);
}

test "AssuanResponse parse with trailing CRLF" {
    const allocator = std.testing.allocator;
    var resp = try AssuanResponse.parse(allocator, "OK\r\n");
    defer resp.deinit(allocator);
    try std.testing.expectEqual(ResponseStatus.ok, resp.status);
}

test "assuanEncode plain text" {
    const allocator = std.testing.allocator;
    const result = try assuanEncode(allocator, "hello");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hello", result);
}

test "assuanEncode special characters" {
    const allocator = std.testing.allocator;
    const result = try assuanEncode(allocator, "a\nb\r%c");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("a%0Ab%0D%25c", result);
}

test "assuanEncode control characters" {
    const allocator = std.testing.allocator;
    const result = try assuanEncode(allocator, "\x01\x02\x03");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("%01%02%03", result);
}

test "assuanDecode plain text" {
    const allocator = std.testing.allocator;
    const result = try assuanDecode(allocator, "hello");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hello", result);
}

test "assuanDecode percent sequences" {
    const allocator = std.testing.allocator;
    const result = try assuanDecode(allocator, "a%0Ab%0D%25c");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("a\nb\r%c", result);
}

test "assuanEncode assuanDecode round-trip" {
    const allocator = std.testing.allocator;
    const original = "Hello\nWorld\r\n100%\x01done";
    const encoded = try assuanEncode(allocator, original);
    defer allocator.free(encoded);
    const decoded = try assuanDecode(allocator, encoded);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(original, decoded);
}

test "assuanDecode empty" {
    const allocator = std.testing.allocator;
    const result = try assuanDecode(allocator, "");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "assuanDecode incomplete percent at end" {
    const allocator = std.testing.allocator;
    // "%A" at end — only 2 chars after %, not 3 — should pass through literally
    const result = try assuanDecode(allocator, "abc%A");
    defer allocator.free(result);
    // The incomplete sequence is passed through as-is
    try std.testing.expectEqual(@as(usize, 4), result.len);
}

test "needsEncoding" {
    try std.testing.expect(needsEncoding('\n'));
    try std.testing.expect(needsEncoding('\r'));
    try std.testing.expect(needsEncoding('%'));
    try std.testing.expect(needsEncoding(0x00));
    try std.testing.expect(needsEncoding(0x1F));
    try std.testing.expect(!needsEncoding(' ')); // 0x20
    try std.testing.expect(!needsEncoding('A'));
    try std.testing.expect(!needsEncoding('z'));
}

test "hexDigitValue" {
    try std.testing.expectEqual(@as(u4, 0), hexDigitValue('0').?);
    try std.testing.expectEqual(@as(u4, 9), hexDigitValue('9').?);
    try std.testing.expectEqual(@as(u4, 10), hexDigitValue('A').?);
    try std.testing.expectEqual(@as(u4, 15), hexDigitValue('F').?);
    try std.testing.expectEqual(@as(u4, 10), hexDigitValue('a').?);
    try std.testing.expectEqual(@as(u4, 15), hexDigitValue('f').?);
    try std.testing.expect(hexDigitValue('G') == null);
    try std.testing.expect(hexDigitValue('z') == null);
}

test "clearPassphrase" {
    const cmd = clearPassphrase("my-cache-id");
    try std.testing.expectEqualStrings("CLEAR_PASSPHRASE", cmd.command);
    try std.testing.expectEqualStrings("my-cache-id", cmd.args.?);
}

test "signKey" {
    const cmd = signKey("AABBCCDD11223344");
    try std.testing.expectEqualStrings("SIGKEY", cmd.command);
    try std.testing.expectEqualStrings("AABBCCDD11223344", cmd.args.?);
}

test "haveSecretKey" {
    const cmd = haveSecretKey("grip-hex");
    try std.testing.expectEqualStrings("HAVEKEY", cmd.command);
    try std.testing.expectEqualStrings("grip-hex", cmd.args.?);
}

test "getInfo" {
    const cmd = getInfo("version");
    try std.testing.expectEqualStrings("GETINFO", cmd.command);
    try std.testing.expectEqualStrings("version", cmd.args.?);
}

test "keyInfo" {
    const cmd = keyInfo("grip");
    try std.testing.expectEqualStrings("KEYINFO", cmd.command);
    try std.testing.expectEqualStrings("grip", cmd.args.?);
}

test "reset" {
    const cmd = reset();
    try std.testing.expectEqualStrings("RESET", cmd.command);
    try std.testing.expect(cmd.args == null);
}

test "bye" {
    const cmd = bye();
    try std.testing.expectEqualStrings("BYE", cmd.command);
    try std.testing.expect(cmd.args == null);
}

test "pkSign" {
    const cmd = pkSign();
    try std.testing.expectEqualStrings("PKSIGN", cmd.command);
    try std.testing.expect(cmd.args == null);
}

test "pkDecrypt" {
    const cmd = pkDecrypt();
    try std.testing.expectEqualStrings("PKDECRYPT", cmd.command);
    try std.testing.expect(cmd.args == null);
}

test "setKey" {
    const cmd = setKey("keygrip123");
    try std.testing.expectEqualStrings("SETKEY", cmd.command);
    try std.testing.expectEqualStrings("keygrip123", cmd.args.?);
}

test "option command" {
    const allocator = std.testing.allocator;
    const cmd = try option(allocator, "display", ":0");
    defer allocator.free(cmd.args.?);
    try std.testing.expectEqualStrings("OPTION", cmd.command);
    try std.testing.expectEqualStrings("display=:0", cmd.args.?);
}

test "setHash command" {
    const allocator = std.testing.allocator;
    const cmd = try setHash(allocator, 8, "AABB");
    defer allocator.free(cmd.args.?);
    try std.testing.expectEqualStrings("SETHASH", cmd.command);
    try std.testing.expectEqualStrings("8 AABB", cmd.args.?);
}

test "calculateRsaKeyGrip deterministic" {
    const n = [_]u8{0x42} ** 16;
    const grip1 = calculateRsaKeyGrip(&n);
    const grip2 = calculateRsaKeyGrip(&n);
    try std.testing.expectEqualSlices(u8, &grip1, &grip2);
}

test "calculateRsaKeyGrip strips leading zeros" {
    const n_with_zeros = [_]u8{0x00} ** 4 ++ [_]u8{0x42} ** 16;
    const n_without = [_]u8{0x42} ** 16;
    const grip1 = calculateRsaKeyGrip(&n_with_zeros);
    const grip2 = calculateRsaKeyGrip(&n_without);
    try std.testing.expectEqualSlices(u8, &grip1, &grip2);
}

test "calculateEd25519KeyGrip deterministic" {
    var pubkey: [32]u8 = undefined;
    @memset(&pubkey, 0x55);
    const grip1 = calculateEd25519KeyGrip(&pubkey);
    const grip2 = calculateEd25519KeyGrip(&pubkey);
    try std.testing.expectEqualSlices(u8, &grip1, &grip2);
}

test "formatKeyGrip" {
    const allocator = std.testing.allocator;
    var grip: [20]u8 = undefined;
    @memset(&grip, 0xAB);
    const hex = try formatKeyGrip(allocator, grip);
    defer allocator.free(hex);
    try std.testing.expectEqual(@as(usize, 40), hex.len);
    try std.testing.expectEqualStrings("ABABABABABABABABABABABABABABABABABABABABABAB", hex);
}

test "parseKeyGrip valid" {
    const hex = "ABABABABABABABABABABABABABABABABABABABABABAB";
    const grip = (try parseKeyGrip(hex)).?;
    for (grip) |byte| {
        try std.testing.expectEqual(@as(u8, 0xAB), byte);
    }
}

test "parseKeyGrip invalid length" {
    const result = try parseKeyGrip("AABB");
    try std.testing.expect(result == null);
}

test "parseKeyGrip invalid chars" {
    const result = try parseKeyGrip("GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG");
    try std.testing.expect(result == null);
}

test "formatKeyGrip parseKeyGrip round-trip" {
    const allocator = std.testing.allocator;
    var original: [20]u8 = undefined;
    @memset(&original, 0xDE);
    const hex = try formatKeyGrip(allocator, original);
    defer allocator.free(hex);
    const parsed = (try parseKeyGrip(hex)).?;
    try std.testing.expectEqualSlices(u8, &original, &parsed);
}
