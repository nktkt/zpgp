// SPDX-License-Identifier: MIT
//! Signature hash computation per RFC 4880 Section 5.2.
//!
//! For V4 signatures, the hash input consists of the data being signed
//! followed by a signature trailer.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const HashAlgorithm = @import("../types/enums.zig").HashAlgorithm;
const PublicKeyAlgorithm = @import("../types/enums.zig").PublicKeyAlgorithm;
const hash_mod = @import("../crypto/hash.zig");
const HashContext = hash_mod.HashContext;

/// Result of a hash computation: the full digest and the 2-byte prefix
/// used in the signature packet's hash_prefix field.
pub const HashResult = struct {
    /// Digest buffer (up to 64 bytes for SHA-512).
    digest: [64]u8,
    /// Actual digest length in bytes.
    digest_len: usize,
    /// First two bytes of the digest, used as the hash prefix in signatures.
    prefix: [2]u8,

    /// Return a slice of the actual digest bytes.
    pub fn digestSlice(self: *const HashResult) []const u8 {
        return self.digest[0..self.digest_len];
    }
};

/// Build the V4 signature trailer that is appended after the hashed data.
///
/// The trailer consists of:
///   version(1) + sig_type(1) + pub_algo(1) + hash_algo(1) +
///   hashed_subpackets_length(2) + hashed_subpackets
///
/// Followed by the final trailer:
///   0x04 + 0xFF + 4-byte BE total length of the above
pub fn buildV4HashedData(
    sig_type: u8,
    pub_algo: u8,
    hash_algo_id: u8,
    hashed_subpackets: []const u8,
    allocator: Allocator,
) ![]u8 {
    // The hashed portion: version + sig_type + pub_algo + hash_algo + subpacket_len + subpackets
    const hashed_len = 4 + 2 + hashed_subpackets.len;
    const total = hashed_len + 6; // + final trailer (0x04 + 0xFF + 4 bytes)

    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);

    // Version 4 header
    buf[0] = 0x04;
    buf[1] = sig_type;
    buf[2] = pub_algo;
    buf[3] = hash_algo_id;

    // Hashed subpackets length (2 bytes, big-endian)
    const sp_len: u16 = @intCast(hashed_subpackets.len);
    mem.writeInt(u16, buf[4..6], sp_len, .big);

    // Hashed subpackets data
    if (hashed_subpackets.len > 0) {
        @memcpy(buf[6 .. 6 + hashed_subpackets.len], hashed_subpackets);
    }

    // Final trailer: 0x04 + 0xFF + 4-byte BE length of hashed portion
    const trailer_offset = 6 + hashed_subpackets.len;
    buf[trailer_offset] = 0x04;
    buf[trailer_offset + 1] = 0xFF;
    const hashed_len_u32: u32 = @intCast(hashed_len);
    mem.writeInt(u32, buf[trailer_offset + 2 ..][0..4], hashed_len_u32, .big);

    return buf;
}

/// Compute the hash for a document signature (sig_type 0x00 or 0x01).
///
/// Hash input = document || v4_hashed_data_with_trailer
pub fn computeDocumentHash(
    hash_algo: HashAlgorithm,
    document: []const u8,
    sig_type: u8,
    pub_algo: u8,
    hash_algo_id: u8,
    hashed_subpackets: []const u8,
    allocator: Allocator,
) !HashResult {
    const hashed_data = try buildV4HashedData(sig_type, pub_algo, hash_algo_id, hashed_subpackets, allocator);
    defer allocator.free(hashed_data);

    var ctx = try HashContext.init(hash_algo);
    ctx.update(document);
    ctx.update(hashed_data);

    const digest_size = try hash_mod.digestSize(hash_algo);
    var result = HashResult{
        .digest = [_]u8{0} ** 64,
        .digest_len = digest_size,
        .prefix = undefined,
    };
    ctx.final(result.digest[0..digest_size]);
    result.prefix = result.digest[0..2].*;
    return result;
}

/// Compute the hash for a key certification signature (sig_type 0x10-0x13).
///
/// Hash input = key_hash_material || user_id_hash_material || v4_hashed_data_with_trailer
///
/// Key hash material (V4):
///   0x99 || 2-byte BE key body length || key body
///
/// User ID hash material (V4):
///   0xB4 || 4-byte BE user ID length || user ID bytes
pub fn computeCertificationHash(
    hash_algo: HashAlgorithm,
    key_packet_body: []const u8,
    user_id: []const u8,
    sig_type: u8,
    pub_algo: u8,
    hash_algo_id: u8,
    hashed_subpackets: []const u8,
    allocator: Allocator,
) !HashResult {
    const hashed_data = try buildV4HashedData(sig_type, pub_algo, hash_algo_id, hashed_subpackets, allocator);
    defer allocator.free(hashed_data);

    var ctx = try HashContext.init(hash_algo);

    // Key hash material: 0x99 + 2-byte BE length + key body
    ctx.update(&[_]u8{0x99});
    var key_len_bytes: [2]u8 = undefined;
    const key_len: u16 = @intCast(key_packet_body.len);
    mem.writeInt(u16, &key_len_bytes, key_len, .big);
    ctx.update(&key_len_bytes);
    ctx.update(key_packet_body);

    // User ID hash material: 0xB4 + 4-byte BE length + user ID
    ctx.update(&[_]u8{0xB4});
    var uid_len_bytes: [4]u8 = undefined;
    const uid_len: u32 = @intCast(user_id.len);
    mem.writeInt(u32, &uid_len_bytes, uid_len, .big);
    ctx.update(&uid_len_bytes);
    ctx.update(user_id);

    // Signature trailer
    ctx.update(hashed_data);

    const digest_size = try hash_mod.digestSize(hash_algo);
    var result = HashResult{
        .digest = [_]u8{0} ** 64,
        .digest_len = digest_size,
        .prefix = undefined,
    };
    ctx.final(result.digest[0..digest_size]);
    result.prefix = result.digest[0..2].*;
    return result;
}

/// Compute the hash for a subkey binding signature (sig_type 0x18 or 0x19).
///
/// Hash input = primary_key_hash_material || subkey_hash_material || v4_hashed_data_with_trailer
///
/// Both key hash materials use the same format:
///   0x99 || 2-byte BE key body length || key body
pub fn computeSubkeyBindingHash(
    hash_algo: HashAlgorithm,
    primary_key_body: []const u8,
    subkey_body: []const u8,
    sig_type: u8,
    pub_algo: u8,
    hash_algo_id: u8,
    hashed_subpackets: []const u8,
    allocator: Allocator,
) !HashResult {
    const hashed_data = try buildV4HashedData(sig_type, pub_algo, hash_algo_id, hashed_subpackets, allocator);
    defer allocator.free(hashed_data);

    var ctx = try HashContext.init(hash_algo);

    // Primary key hash material
    ctx.update(&[_]u8{0x99});
    var pk_len_bytes: [2]u8 = undefined;
    mem.writeInt(u16, &pk_len_bytes, @as(u16, @intCast(primary_key_body.len)), .big);
    ctx.update(&pk_len_bytes);
    ctx.update(primary_key_body);

    // Subkey hash material
    ctx.update(&[_]u8{0x99});
    var sk_len_bytes: [2]u8 = undefined;
    mem.writeInt(u16, &sk_len_bytes, @as(u16, @intCast(subkey_body.len)), .big);
    ctx.update(&sk_len_bytes);
    ctx.update(subkey_body);

    // Signature trailer
    ctx.update(hashed_data);

    const digest_size = try hash_mod.digestSize(hash_algo);
    var result = HashResult{
        .digest = [_]u8{0} ** 64,
        .digest_len = digest_size,
        .prefix = undefined,
    };
    ctx.final(result.digest[0..digest_size]);
    result.prefix = result.digest[0..2].*;
    return result;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "buildV4HashedData structure" {
    const allocator = std.testing.allocator;

    const subpackets = [_]u8{ 0x05, 0x02, 0x5F, 0x00, 0x00, 0x00 };
    const hashed_data = try buildV4HashedData(0x00, 1, 8, &subpackets, allocator);
    defer allocator.free(hashed_data);

    // Expected structure:
    // [0] = 0x04 (version)
    // [1] = 0x00 (sig_type)
    // [2] = 0x01 (pub_algo = RSA)
    // [3] = 0x08 (hash_algo = SHA256)
    // [4..6] = 0x00, 0x06 (subpacket length = 6)
    // [6..12] = subpacket data
    // [12] = 0x04 (trailer version)
    // [13] = 0xFF
    // [14..18] = 0x00, 0x00, 0x00, 0x0C (hashed portion length = 12)

    try std.testing.expectEqual(@as(usize, 18), hashed_data.len);
    try std.testing.expectEqual(@as(u8, 0x04), hashed_data[0]);
    try std.testing.expectEqual(@as(u8, 0x00), hashed_data[1]);
    try std.testing.expectEqual(@as(u8, 1), hashed_data[2]);
    try std.testing.expectEqual(@as(u8, 8), hashed_data[3]);
    try std.testing.expectEqual(@as(u16, 6), mem.readInt(u16, hashed_data[4..6], .big));
    try std.testing.expectEqualSlices(u8, &subpackets, hashed_data[6..12]);
    try std.testing.expectEqual(@as(u8, 0x04), hashed_data[12]);
    try std.testing.expectEqual(@as(u8, 0xFF), hashed_data[13]);
    try std.testing.expectEqual(@as(u32, 12), mem.readInt(u32, hashed_data[14..18], .big));
}

test "buildV4HashedData empty subpackets" {
    const allocator = std.testing.allocator;

    const hashed_data = try buildV4HashedData(0x13, 17, 2, &[_]u8{}, allocator);
    defer allocator.free(hashed_data);

    // 4 (header) + 2 (sp len) + 0 (sp data) + 6 (trailer) = 12
    try std.testing.expectEqual(@as(usize, 12), hashed_data.len);
    try std.testing.expectEqual(@as(u8, 0x04), hashed_data[0]);
    try std.testing.expectEqual(@as(u8, 0x13), hashed_data[1]);
    try std.testing.expectEqual(@as(u16, 0), mem.readInt(u16, hashed_data[4..6], .big));
    // Trailer: hashed portion = 4 + 2 + 0 = 6
    try std.testing.expectEqual(@as(u32, 6), mem.readInt(u32, hashed_data[8..12], .big));
}

test "HashResult digestSlice" {
    var result = HashResult{
        .digest = [_]u8{0} ** 64,
        .digest_len = 32,
        .prefix = [_]u8{ 0xAB, 0xCD },
    };
    result.digest[0] = 0xAB;
    result.digest[1] = 0xCD;
    result.digest[31] = 0xFF;

    const slice = result.digestSlice();
    try std.testing.expectEqual(@as(usize, 32), slice.len);
    try std.testing.expectEqual(@as(u8, 0xAB), slice[0]);
    try std.testing.expectEqual(@as(u8, 0xFF), slice[31]);
}
