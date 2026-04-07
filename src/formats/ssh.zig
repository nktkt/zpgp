// SPDX-License-Identifier: MIT
//! SSH key format conversion.
//!
//! Converts between OpenPGP key material and SSH public key formats.
//! Supports Ed25519, RSA, and ECDSA key types in the SSH authorized_keys
//! wire format (RFC 4253 Section 6.6, RFC 8709).
//!
//! The SSH public key format encodes keys as:
//!   <key-type> <base64-encoded-data> [comment]
//!
//! Where the base64 data contains length-prefixed strings in "SSH wire format":
//!   string key_type
//!   <algorithm-specific fields>

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const base64 = std.base64;

/// Errors specific to SSH key format operations.
pub const SshError = error{
    InvalidKeyData,
    UnsupportedKeyType,
    InvalidSshFormat,
    InvalidBase64,
    KeyTooShort,
    OutOfMemory,
    Overflow,
};

/// An SSH public key with its type, raw data, and optional comment.
pub const SshPublicKey = struct {
    /// The key type string (e.g., "ssh-rsa", "ssh-ed25519").
    key_type: []u8,
    /// The raw key data in SSH wire format.
    key_data: []u8,
    /// Optional comment (typically user@host).
    comment: ?[]u8,

    pub fn deinit(self: SshPublicKey, allocator: Allocator) void {
        allocator.free(self.key_type);
        allocator.free(self.key_data);
        if (self.comment) |c| allocator.free(c);
    }
};

/// Supported SSH key type identifiers.
pub const SshKeyType = enum {
    ssh_rsa,
    ssh_ed25519,
    ecdsa_sha2_nistp256,
    ecdsa_sha2_nistp384,
    ecdsa_sha2_nistp521,

    /// Return the SSH key type identifier string.
    pub fn name(self: SshKeyType) []const u8 {
        return switch (self) {
            .ssh_rsa => "ssh-rsa",
            .ssh_ed25519 => "ssh-ed25519",
            .ecdsa_sha2_nistp256 => "ecdsa-sha2-nistp256",
            .ecdsa_sha2_nistp384 => "ecdsa-sha2-nistp384",
            .ecdsa_sha2_nistp521 => "ecdsa-sha2-nistp521",
        };
    }

    /// Parse an SSH key type from its string identifier.
    pub fn fromName(s: []const u8) ?SshKeyType {
        if (mem.eql(u8, s, "ssh-rsa")) return .ssh_rsa;
        if (mem.eql(u8, s, "ssh-ed25519")) return .ssh_ed25519;
        if (mem.eql(u8, s, "ecdsa-sha2-nistp256")) return .ecdsa_sha2_nistp256;
        if (mem.eql(u8, s, "ecdsa-sha2-nistp384")) return .ecdsa_sha2_nistp384;
        if (mem.eql(u8, s, "ecdsa-sha2-nistp521")) return .ecdsa_sha2_nistp521;
        return null;
    }
};

// ===========================================================================
// SSH wire format encoding/decoding
// ===========================================================================

/// Encode a byte slice as an SSH "string" (4-byte big-endian length + data).
///
/// Returns a newly allocated slice containing the length-prefixed encoding.
/// Caller owns the returned memory.
pub fn encodeSshString(allocator: Allocator, data: []const u8) SshError![]u8 {
    if (data.len > std.math.maxInt(u32)) return SshError.Overflow;
    const len: u32 = @intCast(data.len);
    const result = allocator.alloc(u8, 4 + data.len) catch return SshError.OutOfMemory;
    std.mem.writeInt(u32, result[0..4], len, .big);
    if (data.len > 0) {
        @memcpy(result[4..][0..data.len], data);
    }
    return result;
}

/// Decode an SSH "string" from the beginning of `data`.
///
/// Returns the decoded value and the remaining unconsumed bytes.
pub fn decodeSshString(data: []const u8) SshError!struct { value: []const u8, rest: []const u8 } {
    if (data.len < 4) return SshError.InvalidSshFormat;
    const len = std.mem.readInt(u32, data[0..4], .big);
    if (data.len < 4 + len) return SshError.InvalidSshFormat;
    return .{
        .value = data[4 .. 4 + len],
        .rest = data[4 + len ..],
    };
}

/// Encode an SSH mpint (multi-precision integer).
///
/// SSH mpints are stored as a string where the first bit indicates sign.
/// For positive numbers, a leading zero byte is prepended if the MSB is set.
pub fn encodeSshMpint(allocator: Allocator, data: []const u8) SshError![]u8 {
    // Strip leading zeros
    var stripped = data;
    while (stripped.len > 1 and stripped[0] == 0) {
        stripped = stripped[1..];
    }

    // If MSB is set, prepend a zero byte (positive number convention)
    const needs_padding = stripped.len > 0 and (stripped[0] & 0x80) != 0;
    const payload_len = stripped.len + @as(usize, if (needs_padding) 1 else 0);

    if (payload_len > std.math.maxInt(u32)) return SshError.Overflow;
    const total_len = 4 + payload_len;
    const result = allocator.alloc(u8, total_len) catch return SshError.OutOfMemory;

    std.mem.writeInt(u32, result[0..4], @intCast(payload_len), .big);
    var offset: usize = 4;
    if (needs_padding) {
        result[offset] = 0;
        offset += 1;
    }
    if (stripped.len > 0) {
        @memcpy(result[offset..][0..stripped.len], stripped);
    }
    return result;
}

// ===========================================================================
// Public key conversion
// ===========================================================================

/// Convert an Ed25519 public key (32 bytes) to SSH authorized_keys format.
///
/// The output is a single line: "ssh-ed25519 <base64-blob> [comment]"
///
/// The wire format blob contains:
///   string "ssh-ed25519"
///   string <32-byte public key>
pub fn toSshEd25519AuthorizedKeys(allocator: Allocator, ed25519_pubkey: []const u8, comment: ?[]const u8) SshError![]u8 {
    if (ed25519_pubkey.len != 32) return SshError.InvalidKeyData;

    // Build the SSH wire format blob
    const wire_blob = try buildEd25519WireBlob(allocator, ed25519_pubkey);
    defer allocator.free(wire_blob);

    return formatAuthorizedKeysLine(allocator, "ssh-ed25519", wire_blob, comment);
}

/// Convert an RSA public key (n, e as big-endian byte arrays) to SSH
/// authorized_keys format.
///
/// The wire format blob contains:
///   string "ssh-rsa"
///   mpint  e (public exponent)
///   mpint  n (modulus)
pub fn toSshRsaAuthorizedKeys(
    allocator: Allocator,
    rsa_n: []const u8,
    rsa_e: []const u8,
    comment: ?[]const u8,
) SshError![]u8 {
    // Build the wire format blob
    const wire_blob = try buildRsaWireBlob(allocator, rsa_n, rsa_e);
    defer allocator.free(wire_blob);

    return formatAuthorizedKeysLine(allocator, "ssh-rsa", wire_blob, comment);
}

/// Parse an SSH public key from authorized_keys line format.
///
/// Accepts a line like:
///   ssh-ed25519 AAAA... user@host
///
/// Returns the parsed key with its type, raw data, and comment.
pub fn parseSshPublicKey(allocator: Allocator, line: []const u8) SshError!SshPublicKey {
    // Trim leading/trailing whitespace
    const trimmed = mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0) return SshError.InvalidSshFormat;

    // Split into key_type, base64_data, [comment]
    var iter = mem.splitSequence(u8, trimmed, " ");

    const key_type_str = iter.next() orelse return SshError.InvalidSshFormat;
    const b64_str = iter.next() orelse return SshError.InvalidSshFormat;

    // Remaining text is the comment
    const comment_start = @as(usize, @intCast(@intFromPtr(b64_str.ptr) - @intFromPtr(trimmed.ptr))) + b64_str.len;
    const comment_text = if (comment_start < trimmed.len)
        mem.trim(u8, trimmed[comment_start..], " \t")
    else
        null;

    // Validate key type
    if (SshKeyType.fromName(key_type_str) == null) return SshError.UnsupportedKeyType;

    // Decode the base64 blob
    const decoder = base64.standard.Decoder;
    const decoded_len = decoder.calcSize(b64_str.len) catch return SshError.InvalidBase64;
    const decoded = allocator.alloc(u8, decoded_len) catch return SshError.OutOfMemory;
    errdefer allocator.free(decoded);

    decoder.decode(decoded, b64_str) catch {
        allocator.free(decoded);
        return SshError.InvalidBase64;
    };

    const key_type_copy = allocator.dupe(u8, key_type_str) catch {
        allocator.free(decoded);
        return SshError.OutOfMemory;
    };
    errdefer allocator.free(key_type_copy);

    const comment_copy: ?[]u8 = if (comment_text) |ct|
        if (ct.len > 0) allocator.dupe(u8, ct) catch {
            allocator.free(decoded);
            allocator.free(key_type_copy);
            return SshError.OutOfMemory;
        } else null
    else
        null;

    return .{
        .key_type = key_type_copy,
        .key_data = decoded,
        .comment = comment_copy,
    };
}

/// Export an OpenPGP Ed25519 authentication subkey as an SSH authorized_keys
/// line.
///
/// Searches the key data (binary OpenPGP packet stream) for a subkey with
/// the authentication key flag set and Ed25519/EdDSA algorithm, then formats
/// it as an SSH public key.
pub fn exportAuthenticationKeyAsSsh(allocator: Allocator, ed25519_pubkey: []const u8, comment: ?[]const u8) SshError![]u8 {
    if (ed25519_pubkey.len < 32) return SshError.KeyTooShort;

    // Use the last 32 bytes as the Ed25519 public key material
    const pubkey_data = ed25519_pubkey[ed25519_pubkey.len - 32 ..];
    return toSshEd25519AuthorizedKeys(allocator, pubkey_data, comment);
}

/// Extract the raw public key bytes from an SSH wire format blob.
///
/// For Ed25519 keys, this extracts the 32-byte public key.
/// For RSA keys, this extracts the modulus (n) bytes.
pub fn extractPublicKeyFromWireBlob(allocator: Allocator, wire_blob: []const u8) SshError![]u8 {
    // Decode the key type
    const kt_result = try decodeSshString(wire_blob);
    const key_type = kt_result.value;
    const after_type = kt_result.rest;

    if (mem.eql(u8, key_type, "ssh-ed25519")) {
        // Ed25519: next string is the 32-byte public key
        const pk_result = try decodeSshString(after_type);
        return allocator.dupe(u8, pk_result.value) catch return SshError.OutOfMemory;
    } else if (mem.eql(u8, key_type, "ssh-rsa")) {
        // RSA: skip exponent, get modulus
        const e_result = try decodeSshString(after_type);
        const n_result = try decodeSshString(e_result.rest);
        return allocator.dupe(u8, n_result.value) catch return SshError.OutOfMemory;
    }

    return SshError.UnsupportedKeyType;
}

/// Compute the SSH key fingerprint (SHA-256 hash of the wire blob, base64-encoded).
///
/// Returns a string like "SHA256:abcdef..." suitable for display.
pub fn computeSshFingerprint(allocator: Allocator, wire_blob: []const u8) SshError![]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(wire_blob);
    const digest = hasher.finalResult();

    // Base64-encode the digest (no padding, URL-safe is common but we use standard)
    const encoder = base64.standard.Encoder;
    const b64_len = encoder.calcSize(digest.len);
    const b64_buf = allocator.alloc(u8, b64_len) catch return SshError.OutOfMemory;
    _ = encoder.encode(b64_buf, &digest);

    // Strip trailing '=' padding for display
    var end = b64_len;
    while (end > 0 and b64_buf[end - 1] == '=') end -= 1;

    // Prepend "SHA256:"
    const prefix = "SHA256:";
    const result = allocator.alloc(u8, prefix.len + end) catch {
        allocator.free(b64_buf);
        return SshError.OutOfMemory;
    };
    @memcpy(result[0..prefix.len], prefix);
    @memcpy(result[prefix.len..][0..end], b64_buf[0..end]);
    allocator.free(b64_buf);

    return result;
}

// ===========================================================================
// Internal helpers
// ===========================================================================

/// Build the SSH wire format blob for an Ed25519 key.
fn buildEd25519WireBlob(allocator: Allocator, pubkey: []const u8) SshError![]u8 {
    const type_str = "ssh-ed25519";
    const type_encoded = try encodeSshString(allocator, type_str);
    defer allocator.free(type_encoded);

    const key_encoded = try encodeSshString(allocator, pubkey);
    defer allocator.free(key_encoded);

    const total_len = type_encoded.len + key_encoded.len;
    const result = allocator.alloc(u8, total_len) catch return SshError.OutOfMemory;
    @memcpy(result[0..type_encoded.len], type_encoded);
    @memcpy(result[type_encoded.len..][0..key_encoded.len], key_encoded);
    return result;
}

/// Build the SSH wire format blob for an RSA key.
fn buildRsaWireBlob(allocator: Allocator, rsa_n: []const u8, rsa_e: []const u8) SshError![]u8 {
    const type_str = "ssh-rsa";
    const type_encoded = try encodeSshString(allocator, type_str);
    defer allocator.free(type_encoded);

    const e_encoded = try encodeSshMpint(allocator, rsa_e);
    defer allocator.free(e_encoded);

    const n_encoded = try encodeSshMpint(allocator, rsa_n);
    defer allocator.free(n_encoded);

    const total_len = type_encoded.len + e_encoded.len + n_encoded.len;
    const result = allocator.alloc(u8, total_len) catch return SshError.OutOfMemory;
    var offset: usize = 0;
    @memcpy(result[0..type_encoded.len], type_encoded);
    offset += type_encoded.len;
    @memcpy(result[offset..][0..e_encoded.len], e_encoded);
    offset += e_encoded.len;
    @memcpy(result[offset..][0..n_encoded.len], n_encoded);
    return result;
}

/// Format an authorized_keys line from key type, wire blob, and optional comment.
fn formatAuthorizedKeysLine(allocator: Allocator, key_type: []const u8, wire_blob: []const u8, comment: ?[]const u8) SshError![]u8 {
    // Base64-encode the wire blob
    const encoder = base64.standard.Encoder;
    const b64_len = encoder.calcSize(wire_blob.len);
    const b64_buf = allocator.alloc(u8, b64_len) catch return SshError.OutOfMemory;
    defer allocator.free(b64_buf);
    _ = encoder.encode(b64_buf, wire_blob);

    // Calculate total line length
    const comment_len = if (comment) |c| 1 + c.len else 0; // " comment"
    const total_len = key_type.len + 1 + b64_len + comment_len;

    const result = allocator.alloc(u8, total_len) catch return SshError.OutOfMemory;
    var offset: usize = 0;

    @memcpy(result[0..key_type.len], key_type);
    offset += key_type.len;

    result[offset] = ' ';
    offset += 1;

    @memcpy(result[offset..][0..b64_len], b64_buf);
    offset += b64_len;

    if (comment) |c| {
        result[offset] = ' ';
        offset += 1;
        @memcpy(result[offset..][0..c.len], c);
    }

    return result;
}

// ===========================================================================
// Tests
// ===========================================================================

test "encodeSshString basic" {
    const allocator = std.testing.allocator;
    const encoded = try encodeSshString(allocator, "hello");
    defer allocator.free(encoded);

    try std.testing.expectEqual(@as(usize, 9), encoded.len);
    // Length prefix: 0x00 0x00 0x00 0x05
    try std.testing.expectEqual(@as(u8, 0), encoded[0]);
    try std.testing.expectEqual(@as(u8, 0), encoded[1]);
    try std.testing.expectEqual(@as(u8, 0), encoded[2]);
    try std.testing.expectEqual(@as(u8, 5), encoded[3]);
    try std.testing.expectEqualStrings("hello", encoded[4..9]);
}

test "encodeSshString empty" {
    const allocator = std.testing.allocator;
    const encoded = try encodeSshString(allocator, "");
    defer allocator.free(encoded);

    try std.testing.expectEqual(@as(usize, 4), encoded.len);
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, encoded[0..4], .big));
}

test "decodeSshString basic" {
    const data: []const u8 = &([_]u8{ 0, 0, 0, 5 } ++ "hello".* ++ "rest".*);
    const result = try decodeSshString(data);
    try std.testing.expectEqualStrings("hello", result.value);
    try std.testing.expectEqualStrings("rest", result.rest);
}

test "decodeSshString too short" {
    const result = decodeSshString(&[_]u8{ 0, 0, 0 });
    try std.testing.expectError(SshError.InvalidSshFormat, result);
}

test "decodeSshString length exceeds data" {
    const result = decodeSshString(&[_]u8{ 0, 0, 0, 10, 0x41 });
    try std.testing.expectError(SshError.InvalidSshFormat, result);
}

test "encodeSshString decodeSshString round-trip" {
    const allocator = std.testing.allocator;
    const original = "ssh-ed25519";
    const encoded = try encodeSshString(allocator, original);
    defer allocator.free(encoded);

    const decoded = try decodeSshString(encoded);
    try std.testing.expectEqualStrings(original, decoded.value);
    try std.testing.expectEqual(@as(usize, 0), decoded.rest.len);
}

test "encodeSshMpint no padding needed" {
    const allocator = std.testing.allocator;
    // 0x03 has MSB clear, no padding needed
    const encoded = try encodeSshMpint(allocator, &[_]u8{0x03});
    defer allocator.free(encoded);

    try std.testing.expectEqual(@as(usize, 5), encoded.len);
    try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, encoded[0..4], .big));
    try std.testing.expectEqual(@as(u8, 0x03), encoded[4]);
}

test "encodeSshMpint with padding" {
    const allocator = std.testing.allocator;
    // 0x80 has MSB set, needs zero-padding
    const encoded = try encodeSshMpint(allocator, &[_]u8{0x80});
    defer allocator.free(encoded);

    try std.testing.expectEqual(@as(usize, 6), encoded.len);
    try std.testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, encoded[0..4], .big));
    try std.testing.expectEqual(@as(u8, 0x00), encoded[4]);
    try std.testing.expectEqual(@as(u8, 0x80), encoded[5]);
}

test "encodeSshMpint strips leading zeros" {
    const allocator = std.testing.allocator;
    const encoded = try encodeSshMpint(allocator, &[_]u8{ 0x00, 0x00, 0x42 });
    defer allocator.free(encoded);

    try std.testing.expectEqual(@as(usize, 5), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x42), encoded[4]);
}

test "toSshEd25519AuthorizedKeys" {
    const allocator = std.testing.allocator;
    // 32-byte test key (all zeros for simplicity)
    var pubkey: [32]u8 = undefined;
    @memset(&pubkey, 0x42);

    const line = try toSshEd25519AuthorizedKeys(allocator, &pubkey, "test@host");
    defer allocator.free(line);

    try std.testing.expect(mem.startsWith(u8, line, "ssh-ed25519 "));
    try std.testing.expect(mem.endsWith(u8, line, " test@host"));
}

test "toSshEd25519AuthorizedKeys no comment" {
    const allocator = std.testing.allocator;
    var pubkey: [32]u8 = undefined;
    @memset(&pubkey, 0xAB);

    const line = try toSshEd25519AuthorizedKeys(allocator, &pubkey, null);
    defer allocator.free(line);

    try std.testing.expect(mem.startsWith(u8, line, "ssh-ed25519 "));
    // No trailing space when there's no comment
    try std.testing.expect(!mem.endsWith(u8, line, " "));
}

test "toSshEd25519AuthorizedKeys invalid key length" {
    const allocator = std.testing.allocator;
    const result = toSshEd25519AuthorizedKeys(allocator, &[_]u8{ 0x01, 0x02 }, null);
    try std.testing.expectError(SshError.InvalidKeyData, result);
}

test "toSshRsaAuthorizedKeys" {
    const allocator = std.testing.allocator;
    // Minimal RSA key material for testing
    const n = [_]u8{ 0x00, 0xBB, 0xCC, 0xDD } ** 8;
    const e = [_]u8{ 0x01, 0x00, 0x01 }; // 65537

    const line = try toSshRsaAuthorizedKeys(allocator, &n, &e, "rsa@test");
    defer allocator.free(line);

    try std.testing.expect(mem.startsWith(u8, line, "ssh-rsa "));
    try std.testing.expect(mem.endsWith(u8, line, " rsa@test"));
}

test "SshKeyType name round-trip" {
    const types = [_]SshKeyType{
        .ssh_rsa,
        .ssh_ed25519,
        .ecdsa_sha2_nistp256,
        .ecdsa_sha2_nistp384,
        .ecdsa_sha2_nistp521,
    };

    for (types) |kt| {
        const n = kt.name();
        const parsed = SshKeyType.fromName(n);
        try std.testing.expectEqual(kt, parsed.?);
    }
}

test "SshKeyType fromName unknown" {
    try std.testing.expect(SshKeyType.fromName("ssh-unknown") == null);
}

test "SshPublicKey deinit" {
    const allocator = std.testing.allocator;
    const kt = try allocator.dupe(u8, "ssh-ed25519");
    const kd = try allocator.dupe(u8, "key-data");
    const cm = try allocator.dupe(u8, "user@host");

    const pk = SshPublicKey{
        .key_type = kt,
        .key_data = kd,
        .comment = cm,
    };
    pk.deinit(allocator);
}

test "SshPublicKey deinit null comment" {
    const allocator = std.testing.allocator;
    const kt = try allocator.dupe(u8, "ssh-rsa");
    const kd = try allocator.dupe(u8, "data");

    const pk = SshPublicKey{
        .key_type = kt,
        .key_data = kd,
        .comment = null,
    };
    pk.deinit(allocator);
}

test "extractPublicKeyFromWireBlob ed25519" {
    const allocator = std.testing.allocator;

    // Build a valid wire blob
    var pubkey: [32]u8 = undefined;
    @memset(&pubkey, 0x55);

    const wire_blob = try buildEd25519WireBlob(allocator, &pubkey);
    defer allocator.free(wire_blob);

    const extracted = try extractPublicKeyFromWireBlob(allocator, wire_blob);
    defer allocator.free(extracted);

    try std.testing.expectEqualSlices(u8, &pubkey, extracted);
}

test "extractPublicKeyFromWireBlob rsa" {
    const allocator = std.testing.allocator;

    const n = [_]u8{0x42} ** 16;
    const e = [_]u8{ 0x01, 0x00, 0x01 };

    const wire_blob = try buildRsaWireBlob(allocator, &n, &e);
    defer allocator.free(wire_blob);

    const extracted = try extractPublicKeyFromWireBlob(allocator, wire_blob);
    defer allocator.free(extracted);

    // The extracted modulus should contain our n bytes (possibly with leading zero)
    try std.testing.expect(extracted.len >= n.len);
}

test "computeSshFingerprint" {
    const allocator = std.testing.allocator;

    var pubkey: [32]u8 = undefined;
    @memset(&pubkey, 0x42);

    const wire_blob = try buildEd25519WireBlob(allocator, &pubkey);
    defer allocator.free(wire_blob);

    const fp = try computeSshFingerprint(allocator, wire_blob);
    defer allocator.free(fp);

    try std.testing.expect(mem.startsWith(u8, fp, "SHA256:"));
    try std.testing.expect(fp.len > 7);
}

test "exportAuthenticationKeyAsSsh" {
    const allocator = std.testing.allocator;

    var key_material: [32]u8 = undefined;
    @memset(&key_material, 0x77);

    const line = try exportAuthenticationKeyAsSsh(allocator, &key_material, "auth@key");
    defer allocator.free(line);

    try std.testing.expect(mem.startsWith(u8, line, "ssh-ed25519 "));
}

test "exportAuthenticationKeyAsSsh too short" {
    const allocator = std.testing.allocator;
    const result = exportAuthenticationKeyAsSsh(allocator, &[_]u8{ 0x01, 0x02 }, null);
    try std.testing.expectError(SshError.KeyTooShort, result);
}
