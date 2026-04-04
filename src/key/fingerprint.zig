// SPDX-License-Identifier: MIT
//! V4 key fingerprint calculation per RFC 4880 Section 12.2.
//!
//! A V4 fingerprint is the 160-bit SHA-1 hash of:
//!   0x99 || 2-byte big-endian key packet body length || key packet body
//!
//! The Key ID is the low-order 64 bits (last 8 bytes) of the fingerprint.

const std = @import("std");
const Sha1 = std.crypto.hash.Sha1;

/// Calculate the V4 fingerprint (SHA-1) for a public key packet body.
///
/// The input `key_packet_body` is the raw body of a Public-Key Packet
/// (tag 6 or 14), i.e. version(1) + creation_time(4) + algorithm(1) + MPIs.
pub fn calculateV4Fingerprint(key_packet_body: []const u8) [20]u8 {
    var sha1 = Sha1.init(.{});

    // 0x99 tag byte
    sha1.update(&[_]u8{0x99});

    // 2-byte big-endian length of the key packet body
    const len: u16 = @intCast(key_packet_body.len);
    var len_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_bytes, len, .big);
    sha1.update(&len_bytes);

    // Key packet body
    sha1.update(key_packet_body);

    return sha1.finalResult();
}

/// Extract the Key ID (last 8 bytes) from a V4 fingerprint.
pub fn keyIdFromFingerprint(fp: [20]u8) [8]u8 {
    return fp[12..20].*;
}

/// Calculate the V4 Key ID directly from a key packet body.
pub fn calculateV4KeyId(key_packet_body: []const u8) [8]u8 {
    const fp = calculateV4Fingerprint(key_packet_body);
    return keyIdFromFingerprint(fp);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "calculateV4Fingerprint deterministic" {
    // The same input must always produce the same fingerprint.
    const body = [_]u8{
        4,                      // version
        0x5F, 0x00, 0x00, 0x00, // creation_time
        1,                      // algorithm (RSA)
        0x00, 0x08,             // MPI bit count = 8
        0xFF,                   // MPI data
        0x00, 0x08,             // MPI bit count = 8
        0x03,                   // MPI data (e=3)
    };

    const fp1 = calculateV4Fingerprint(&body);
    const fp2 = calculateV4Fingerprint(&body);
    try std.testing.expectEqual(fp1, fp2);
}

test "calculateV4Fingerprint known structure" {
    // Verify the hash includes the 0x99 prefix + 2-byte length + body.
    // We can verify by computing SHA-1 manually.
    const body = [_]u8{ 4, 0x00, 0x00, 0x00, 0x01, 1, 0x00, 0x08, 0x80, 0x00, 0x08, 0x03 };

    const fp = calculateV4Fingerprint(&body);

    // Manually compute: SHA-1(0x99 || 0x00 0x0C || body)
    var sha1 = Sha1.init(.{});
    sha1.update(&[_]u8{0x99});
    sha1.update(&[_]u8{ 0x00, 0x0C }); // length = 12
    sha1.update(&body);
    const expected = sha1.finalResult();

    try std.testing.expectEqual(expected, fp);
}

test "keyIdFromFingerprint returns last 8 bytes" {
    var fp: [20]u8 = undefined;
    for (0..20) |i| {
        fp[i] = @intCast(i);
    }
    const kid = keyIdFromFingerprint(fp);
    // Bytes 12..20: 12, 13, 14, 15, 16, 17, 18, 19
    try std.testing.expectEqualSlices(u8, &[_]u8{ 12, 13, 14, 15, 16, 17, 18, 19 }, &kid);
}

test "calculateV4KeyId convenience" {
    const body = [_]u8{ 4, 0x00, 0x00, 0x00, 0x01, 1, 0x00, 0x08, 0x80, 0x00, 0x08, 0x03 };
    const fp = calculateV4Fingerprint(&body);
    const kid_from_fp = keyIdFromFingerprint(fp);
    const kid_direct = calculateV4KeyId(&body);
    try std.testing.expectEqual(kid_from_fp, kid_direct);
}

test "calculateV4Fingerprint different inputs produce different fingerprints" {
    const body1 = [_]u8{ 4, 0x00, 0x00, 0x00, 0x01, 1, 0x00, 0x08, 0x80, 0x00, 0x08, 0x03 };
    const body2 = [_]u8{ 4, 0x00, 0x00, 0x00, 0x02, 1, 0x00, 0x08, 0x80, 0x00, 0x08, 0x03 };
    const fp1 = calculateV4Fingerprint(&body1);
    const fp2 = calculateV4Fingerprint(&body2);
    try std.testing.expect(!std.mem.eql(u8, &fp1, &fp2));
}

test "calculateV4Fingerprint empty body" {
    // Edge case: empty body is technically invalid but should not crash.
    const fp = calculateV4Fingerprint(&[_]u8{});
    // SHA-1(0x99 || 0x00 0x00) — should be a valid hash
    var sha1 = Sha1.init(.{});
    sha1.update(&[_]u8{ 0x99, 0x00, 0x00 });
    const expected = sha1.finalResult();
    try std.testing.expectEqual(expected, fp);
}
