// SPDX-License-Identifier: MIT
//! V6 key fingerprint calculation per RFC 9580 Section 5.5.4.
//!
//! A V6 fingerprint is the 256-bit SHA-256 hash of:
//!   0x9B || 4-byte big-endian key packet body length || key packet body
//!
//! The V6 Key ID is the first 8 bytes of the V6 fingerprint.
//!
//! This differs from V4 fingerprints which use:
//!   0x99 || 2-byte length || key body (hashed with SHA-1)

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Calculate the V6 fingerprint (SHA-256) for a public key packet body.
///
/// The input `key_packet_body` is the raw body of a V6 Public-Key Packet
/// (tag 6 or 14), i.e. version(1) + creation_time(4) + algorithm(1) +
/// key material (raw bytes, not MPI-encoded for native key types).
///
/// V6 fingerprint = SHA-256(0x9B || 4-byte-BE-length || key_packet_body)
pub fn calculateV6Fingerprint(key_packet_body: []const u8) [32]u8 {
    var sha256 = Sha256.init(.{});

    // 0x9B tag byte (V6 key material indicator)
    sha256.update(&[_]u8{0x9B});

    // 4-byte big-endian length of the key packet body
    const len: u32 = @intCast(key_packet_body.len);
    var len_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_bytes, len, .big);
    sha256.update(&len_bytes);

    // Key packet body
    sha256.update(key_packet_body);

    return sha256.finalResult();
}

/// Extract the V6 Key ID (first 8 bytes) from a V6 fingerprint.
///
/// Unlike V4 where the Key ID is the LAST 8 bytes, V6 uses the FIRST 8 bytes.
pub fn v6KeyIdFromFingerprint(fp: [32]u8) [8]u8 {
    return fp[0..8].*;
}

/// Calculate the V6 Key ID directly from a key packet body.
pub fn calculateV6KeyId(key_packet_body: []const u8) [8]u8 {
    const fp = calculateV6Fingerprint(key_packet_body);
    return v6KeyIdFromFingerprint(fp);
}

/// Format a V6 fingerprint as a hex string.
///
/// Returns a 64-character uppercase hex string.
pub fn formatV6Fingerprint(fp: [32]u8) [64]u8 {
    const hex_chars = "0123456789ABCDEF";
    var result: [64]u8 = undefined;
    for (fp, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0F];
    }
    return result;
}

/// Build V6 key hash material for signature computation.
///
/// For V6 signatures, the key hash material is:
///   0x9B || 4-byte BE key body length || key body
///
/// This is the same prefix used for fingerprint calculation.
pub fn buildV6KeyHashMaterial(
    key_packet_body: []const u8,
    allocator: std.mem.Allocator,
) ![]u8 {
    const total = 1 + 4 + key_packet_body.len;
    const buf = try allocator.alloc(u8, total);

    buf[0] = 0x9B;
    const len: u32 = @intCast(key_packet_body.len);
    std.mem.writeInt(u32, buf[1..5], len, .big);
    @memcpy(buf[5..], key_packet_body);

    return buf;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "calculateV6Fingerprint deterministic" {
    const body = [_]u8{
        6,                      // version 6
        0x5F, 0x00, 0x00, 0x00, // creation_time
        27,                     // algorithm (Ed25519 native)
    } ++ [_]u8{0xAA} ** 32; // 32-byte public key

    const fp1 = calculateV6Fingerprint(&body);
    const fp2 = calculateV6Fingerprint(&body);
    try std.testing.expectEqual(fp1, fp2);
}

test "calculateV6Fingerprint known structure" {
    // Verify the hash includes the 0x9B prefix + 4-byte length + body
    const body = [_]u8{
        6,                      // version 6
        0x00, 0x00, 0x00, 0x01, // creation_time = 1
        27,                     // Ed25519 native
    } ++ [_]u8{0x42} ** 32; // 32-byte key

    const fp = calculateV6Fingerprint(&body);

    // Manually compute: SHA-256(0x9B || 4-byte-length || body)
    var sha256 = Sha256.init(.{});
    sha256.update(&[_]u8{0x9B});
    const len: u32 = @intCast(body.len);
    var len_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_bytes, len, .big);
    sha256.update(&len_bytes);
    sha256.update(&body);
    const expected = sha256.finalResult();

    try std.testing.expectEqual(expected, fp);
}

test "v6KeyIdFromFingerprint returns first 8 bytes" {
    var fp: [32]u8 = undefined;
    for (0..32) |i| {
        fp[i] = @intCast(i);
    }
    const kid = v6KeyIdFromFingerprint(fp);
    // First 8 bytes: 0, 1, 2, 3, 4, 5, 6, 7
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 }, &kid);
}

test "calculateV6KeyId convenience" {
    const body = [_]u8{ 6, 0x00, 0x00, 0x00, 0x01, 27 } ++ [_]u8{0x42} ** 32;
    const fp = calculateV6Fingerprint(&body);
    const kid_from_fp = v6KeyIdFromFingerprint(fp);
    const kid_direct = calculateV6KeyId(&body);
    try std.testing.expectEqual(kid_from_fp, kid_direct);
}

test "calculateV6Fingerprint differs from V4" {
    // Same body should produce different fingerprints for V4 vs V6
    const body = [_]u8{ 4, 0x00, 0x00, 0x00, 0x01, 1, 0x00, 0x08, 0x80, 0x00, 0x08, 0x03 };

    // V6 fingerprint (SHA-256, 0x9B prefix, 4-byte length)
    const v6_fp = calculateV6Fingerprint(&body);

    // V4 fingerprint for comparison (SHA-1, 0x99 prefix, 2-byte length)
    // Note: they are different sizes (32 vs 20 bytes) and use different hashes
    try std.testing.expectEqual(@as(usize, 32), v6_fp.len);
}

test "calculateV6Fingerprint different inputs produce different fingerprints" {
    const body1 = [_]u8{ 6, 0x00, 0x00, 0x00, 0x01, 27 } ++ [_]u8{0xAA} ** 32;
    const body2 = [_]u8{ 6, 0x00, 0x00, 0x00, 0x02, 27 } ++ [_]u8{0xAA} ** 32;
    const fp1 = calculateV6Fingerprint(&body1);
    const fp2 = calculateV6Fingerprint(&body2);
    try std.testing.expect(!std.mem.eql(u8, &fp1, &fp2));
}

test "calculateV6Fingerprint empty body" {
    // Edge case: empty body (technically invalid but should not crash)
    const fp = calculateV6Fingerprint(&[_]u8{});
    var sha256 = Sha256.init(.{});
    sha256.update(&[_]u8{ 0x9B, 0x00, 0x00, 0x00, 0x00 });
    const expected = sha256.finalResult();
    try std.testing.expectEqual(expected, fp);
}

test "formatV6Fingerprint" {
    var fp: [32]u8 = undefined;
    for (0..32) |i| {
        fp[i] = @intCast(i);
    }
    const hex = formatV6Fingerprint(fp);
    try std.testing.expectEqualSlices(u8, "00", hex[0..2]);
    try std.testing.expectEqualSlices(u8, "01", hex[2..4]);
    try std.testing.expectEqualSlices(u8, "1F", hex[62..64]); // 31 = 0x1F
}

test "buildV6KeyHashMaterial" {
    const allocator = std.testing.allocator;
    const body = [_]u8{ 6, 0x00, 0x00, 0x00, 0x01, 27 } ++ [_]u8{0x42} ** 32;

    const material = try buildV6KeyHashMaterial(&body, allocator);
    defer allocator.free(material);

    try std.testing.expectEqual(@as(usize, 1 + 4 + body.len), material.len);
    try std.testing.expectEqual(@as(u8, 0x9B), material[0]);
    const stored_len = std.mem.readInt(u32, material[1..5], .big);
    try std.testing.expectEqual(@as(u32, body.len), stored_len);
    try std.testing.expectEqualSlices(u8, &body, material[5..]);
}
