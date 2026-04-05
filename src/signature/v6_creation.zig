// SPDX-License-Identifier: MIT
//! V6 signature hash computation per RFC 9580 Section 5.2.
//!
//! V6 signatures differ from V4 in several key ways:
//!   - A random salt is included in the hash computation
//!   - Subpacket lengths are 4 bytes (instead of 2 in V4)
//!   - The hash trailer uses 8-byte lengths (instead of 4)
//!   - Salt size depends on the hash algorithm
//!
//! V6 signature hash computation:
//!   Hash = H(salt || data_to_sign || sig_header || hashed_subpackets || trailer)
//!
//! Where the trailer is:
//!   0x06 || 0xFF || 8-byte BE total length of hashed portion
//!
//! And the hashed portion is:
//!   version(1) || sig_type(1) || pub_algo(1) || hash_algo(1) ||
//!   hashed_sp_length(4) || hashed_subpackets

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const HashAlgorithm = @import("../types/enums.zig").HashAlgorithm;
const PublicKeyAlgorithm = @import("../types/enums.zig").PublicKeyAlgorithm;
const hash_mod = @import("../crypto/hash.zig");
const HashContext = hash_mod.HashContext;
const v4_creation = @import("creation.zig");
const HashResult = v4_creation.HashResult;
const v6_fingerprint_mod = @import("../key/v6_fingerprint.zig");

/// Salt sizes for V6 signatures per RFC 9580 Section 5.2.3.
///
/// The salt size is determined by the hash algorithm:
///   SHA-256: 16 bytes
///   SHA-384: 24 bytes
///   SHA-512: 32 bytes
///   SHA-224: 16 bytes
///   SHA-1:   16 bytes (not recommended)
pub fn saltSizeForHash(hash_algo: HashAlgorithm) ?usize {
    return switch (hash_algo) {
        .sha256 => 16,
        .sha384 => 24,
        .sha512 => 32,
        .sha224 => 16,
        .sha1 => 16,
        else => null,
    };
}

/// Result of salt generation.
pub const SaltResult = struct {
    /// Buffer holding the salt (up to 32 bytes).
    salt: [32]u8,
    /// Actual number of salt bytes used.
    len: usize,

    /// Return a slice of the actual salt bytes.
    pub fn saltSlice(self: *const SaltResult) []const u8 {
        return self.salt[0..self.len];
    }
};

/// Generate a random salt appropriate for the given hash algorithm.
///
/// The salt size is determined by the hash algorithm per RFC 9580.
/// Returns error if the hash algorithm is not supported for V6 signatures.
pub fn generateSalt(hash_algo: HashAlgorithm) !SaltResult {
    const salt_len = saltSizeForHash(hash_algo) orelse return error.UnsupportedAlgorithm;

    var result = SaltResult{
        .salt = [_]u8{0} ** 32,
        .len = salt_len,
    };

    std.crypto.random.bytes(result.salt[0..salt_len]);
    return result;
}

/// Build the V6 signature hashed data that goes into the hash computation.
///
/// The hashed portion consists of:
///   version(1) || sig_type(1) || pub_algo(1) || hash_algo(1) ||
///   hashed_sp_length(4 bytes, big-endian) || hashed_subpackets
///
/// Followed by the final trailer:
///   0x06 || 0xFF || 8-byte BE total length of the above hashed portion
pub fn buildV6HashedData(
    sig_type: u8,
    pub_algo: u8,
    hash_algo_id: u8,
    hashed_subpackets: []const u8,
    allocator: Allocator,
) ![]u8 {
    // The hashed portion: version(1) + sig_type(1) + pub_algo(1) + hash_algo(1)
    //                    + sp_len(4) + subpackets
    const hashed_len = 4 + 4 + hashed_subpackets.len;
    // Final trailer: 0x06 + 0xFF + 8-byte length = 10 bytes
    const total = hashed_len + 10;

    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);

    // Version 6 header
    buf[0] = 0x06;
    buf[1] = sig_type;
    buf[2] = pub_algo;
    buf[3] = hash_algo_id;

    // Hashed subpackets length (4 bytes, big-endian) -- V6 uses 4 bytes
    mem.writeInt(u32, buf[4..8], @intCast(hashed_subpackets.len), .big);

    // Hashed subpackets data
    if (hashed_subpackets.len > 0) {
        @memcpy(buf[8 .. 8 + hashed_subpackets.len], hashed_subpackets);
    }

    // Final trailer: 0x06 + 0xFF + 8-byte BE length of hashed portion
    const trailer_offset = 8 + hashed_subpackets.len;
    buf[trailer_offset] = 0x06;
    buf[trailer_offset + 1] = 0xFF;
    // 8-byte big-endian length of the hashed portion
    mem.writeInt(u64, buf[trailer_offset + 2 ..][0..8], @intCast(hashed_len), .big);

    return buf;
}

/// Build the V6 signature trailer (compact version, fixed-size).
///
/// Returns a 10-byte trailer:
///   version(1) || 0xFF(1) || 8-byte BE hashed portion length
pub fn buildV6Trailer(
    version: u8,
    sig_type: u8,
    pub_algo: u8,
    hash_algo: u8,
    hashed_subpackets_len: u32,
) [10]u8 {
    _ = sig_type;
    _ = pub_algo;
    _ = hash_algo;

    var trailer: [10]u8 = undefined;
    trailer[0] = version;
    trailer[1] = 0xFF;
    // The hashed portion length = 4 (header) + 4 (sp_len) + subpackets
    const hashed_len: u64 = 4 + 4 + @as(u64, hashed_subpackets_len);
    mem.writeInt(u64, trailer[2..10], hashed_len, .big);
    return trailer;
}

/// Compute the hash for a V6 document signature (sig_type 0x00 or 0x01).
///
/// V6 hash computation:
///   Hash(salt || document || v6_hashed_data_with_trailer)
///
/// The salt is prepended to the data before hashing, as specified in
/// RFC 9580 Section 5.2.4.
pub fn computeV6DocumentHash(
    hash_algo: HashAlgorithm,
    document: []const u8,
    sig_type: u8,
    pub_algo: u8,
    hash_algo_id: u8,
    hashed_subpackets: []const u8,
    salt: []const u8,
    allocator: Allocator,
) !HashResult {
    const hashed_data = try buildV6HashedData(sig_type, pub_algo, hash_algo_id, hashed_subpackets, allocator);
    defer allocator.free(hashed_data);

    var ctx = try HashContext.init(hash_algo);

    // V6: salt first
    ctx.update(salt);

    // Then document data
    ctx.update(document);

    // Then hashed data with trailer
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

/// Compute the hash for a V6 certification signature (sig_type 0x10-0x13).
///
/// V6 hash computation for certifications:
///   Hash(salt || key_hash_material || user_id_hash_material || v6_hashed_data_with_trailer)
///
/// V6 key hash material uses the V6 format:
///   0x9B || 4-byte BE key body length || key body
///
/// V6 user ID hash material:
///   0xB4 || 4-byte BE user ID length || user ID bytes
pub fn computeV6CertificationHash(
    hash_algo: HashAlgorithm,
    key_packet_body: []const u8,
    user_id: []const u8,
    sig_type: u8,
    pub_algo: u8,
    hash_algo_id: u8,
    hashed_subpackets: []const u8,
    salt: []const u8,
    allocator: Allocator,
) !HashResult {
    const hashed_data = try buildV6HashedData(sig_type, pub_algo, hash_algo_id, hashed_subpackets, allocator);
    defer allocator.free(hashed_data);

    var ctx = try HashContext.init(hash_algo);

    // V6: salt first
    ctx.update(salt);

    // V6 key hash material: 0x9B + 4-byte BE length + key body
    ctx.update(&[_]u8{0x9B});
    var key_len_bytes: [4]u8 = undefined;
    mem.writeInt(u32, &key_len_bytes, @intCast(key_packet_body.len), .big);
    ctx.update(&key_len_bytes);
    ctx.update(key_packet_body);

    // User ID hash material: 0xB4 + 4-byte BE length + user ID
    ctx.update(&[_]u8{0xB4});
    var uid_len_bytes: [4]u8 = undefined;
    mem.writeInt(u32, &uid_len_bytes, @intCast(user_id.len), .big);
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

/// Compute the hash for a V6 subkey binding signature (sig_type 0x18 or 0x19).
///
/// V6 hash computation for subkey binding:
///   Hash(salt || primary_key_material || subkey_material || v6_hashed_data_with_trailer)
///
/// Both key materials use the V6 format:
///   0x9B || 4-byte BE key body length || key body
pub fn computeV6SubkeyBindingHash(
    hash_algo: HashAlgorithm,
    primary_key_body: []const u8,
    subkey_body: []const u8,
    sig_type: u8,
    pub_algo: u8,
    hash_algo_id: u8,
    hashed_subpackets: []const u8,
    salt: []const u8,
    allocator: Allocator,
) !HashResult {
    const hashed_data = try buildV6HashedData(sig_type, pub_algo, hash_algo_id, hashed_subpackets, allocator);
    defer allocator.free(hashed_data);

    var ctx = try HashContext.init(hash_algo);

    // V6: salt first
    ctx.update(salt);

    // Primary key hash material: 0x9B + 4-byte BE length + key body
    ctx.update(&[_]u8{0x9B});
    var pk_len_bytes: [4]u8 = undefined;
    mem.writeInt(u32, &pk_len_bytes, @intCast(primary_key_body.len), .big);
    ctx.update(&pk_len_bytes);
    ctx.update(primary_key_body);

    // Subkey hash material: 0x9B + 4-byte BE length + subkey body
    ctx.update(&[_]u8{0x9B});
    var sk_len_bytes: [4]u8 = undefined;
    mem.writeInt(u32, &sk_len_bytes, @intCast(subkey_body.len), .big);
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

/// Compute the hash for a V6 direct key signature (sig_type 0x1F).
///
/// V6 hash computation for direct key signatures:
///   Hash(salt || key_hash_material || v6_hashed_data_with_trailer)
pub fn computeV6DirectKeyHash(
    hash_algo: HashAlgorithm,
    key_packet_body: []const u8,
    sig_type: u8,
    pub_algo: u8,
    hash_algo_id: u8,
    hashed_subpackets: []const u8,
    salt: []const u8,
    allocator: Allocator,
) !HashResult {
    const hashed_data = try buildV6HashedData(sig_type, pub_algo, hash_algo_id, hashed_subpackets, allocator);
    defer allocator.free(hashed_data);

    var ctx = try HashContext.init(hash_algo);

    // V6: salt first
    ctx.update(salt);

    // V6 key hash material
    ctx.update(&[_]u8{0x9B});
    var key_len_bytes: [4]u8 = undefined;
    mem.writeInt(u32, &key_len_bytes, @intCast(key_packet_body.len), .big);
    ctx.update(&key_len_bytes);
    ctx.update(key_packet_body);

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

test "saltSizeForHash returns correct sizes" {
    try std.testing.expectEqual(@as(usize, 16), saltSizeForHash(.sha256).?);
    try std.testing.expectEqual(@as(usize, 24), saltSizeForHash(.sha384).?);
    try std.testing.expectEqual(@as(usize, 32), saltSizeForHash(.sha512).?);
    try std.testing.expectEqual(@as(usize, 16), saltSizeForHash(.sha224).?);
    try std.testing.expectEqual(@as(usize, 16), saltSizeForHash(.sha1).?);
    try std.testing.expect(saltSizeForHash(.md5) == null);
}

test "generateSalt produces correct size" {
    const result = try generateSalt(.sha256);
    try std.testing.expectEqual(@as(usize, 16), result.len);
    try std.testing.expectEqual(@as(usize, 16), result.saltSlice().len);

    const result512 = try generateSalt(.sha512);
    try std.testing.expectEqual(@as(usize, 32), result512.len);
}

test "generateSalt produces different salts" {
    const r1 = try generateSalt(.sha256);
    const r2 = try generateSalt(.sha256);
    // Extremely unlikely to be equal
    try std.testing.expect(!mem.eql(u8, r1.saltSlice(), r2.saltSlice()));
}

test "generateSalt rejects unsupported algorithms" {
    try std.testing.expectError(error.UnsupportedAlgorithm, generateSalt(.md5));
}

test "buildV6HashedData structure" {
    const allocator = std.testing.allocator;

    const subpackets = [_]u8{ 0x05, 0x02, 0x5F, 0x00, 0x00, 0x00 };
    const hashed_data = try buildV6HashedData(0x00, 1, 8, &subpackets, allocator);
    defer allocator.free(hashed_data);

    // Expected structure:
    // [0] = 0x06 (version)
    // [1] = 0x00 (sig_type)
    // [2] = 0x01 (pub_algo = RSA)
    // [3] = 0x08 (hash_algo = SHA256)
    // [4..8] = 0x00, 0x00, 0x00, 0x06 (subpacket length = 6, 4 bytes)
    // [8..14] = subpacket data
    // [14] = 0x06 (trailer version)
    // [15] = 0xFF
    // [16..24] = 8-byte BE hashed portion length = 4 + 4 + 6 = 14

    try std.testing.expectEqual(@as(usize, 24), hashed_data.len);
    try std.testing.expectEqual(@as(u8, 0x06), hashed_data[0]);
    try std.testing.expectEqual(@as(u8, 0x00), hashed_data[1]);
    try std.testing.expectEqual(@as(u8, 1), hashed_data[2]);
    try std.testing.expectEqual(@as(u8, 8), hashed_data[3]);
    try std.testing.expectEqual(@as(u32, 6), mem.readInt(u32, hashed_data[4..8], .big));
    try std.testing.expectEqualSlices(u8, &subpackets, hashed_data[8..14]);
    try std.testing.expectEqual(@as(u8, 0x06), hashed_data[14]);
    try std.testing.expectEqual(@as(u8, 0xFF), hashed_data[15]);
    try std.testing.expectEqual(@as(u64, 14), mem.readInt(u64, hashed_data[16..24], .big));
}

test "buildV6HashedData empty subpackets" {
    const allocator = std.testing.allocator;

    const hashed_data = try buildV6HashedData(0x13, 17, 2, &[_]u8{}, allocator);
    defer allocator.free(hashed_data);

    // 4 (header) + 4 (sp len) + 0 (sp data) + 10 (trailer) = 18
    try std.testing.expectEqual(@as(usize, 18), hashed_data.len);
    try std.testing.expectEqual(@as(u8, 0x06), hashed_data[0]);
    try std.testing.expectEqual(@as(u32, 0), mem.readInt(u32, hashed_data[4..8], .big));
    // Trailer: hashed portion = 4 + 4 + 0 = 8
    try std.testing.expectEqual(@as(u64, 8), mem.readInt(u64, hashed_data[10..18], .big));
}

test "buildV6HashedData differs from V4" {
    const allocator = std.testing.allocator;

    const subpackets = [_]u8{0x01};

    // V4: 2-byte sp length, 4-byte trailer length
    const v4_data = try v4_creation.buildV4HashedData(0x00, 1, 8, &subpackets, allocator);
    defer allocator.free(v4_data);

    // V6: 4-byte sp length, 8-byte trailer length
    const v6_data = try buildV6HashedData(0x00, 1, 8, &subpackets, allocator);
    defer allocator.free(v6_data);

    // They should be different sizes
    try std.testing.expect(v4_data.len != v6_data.len);

    // V4 version byte is 0x04, V6 is 0x06
    try std.testing.expectEqual(@as(u8, 0x04), v4_data[0]);
    try std.testing.expectEqual(@as(u8, 0x06), v6_data[0]);
}

test "buildV6Trailer" {
    const trailer = buildV6Trailer(0x06, 0x00, 1, 8, 10);
    try std.testing.expectEqual(@as(u8, 0x06), trailer[0]);
    try std.testing.expectEqual(@as(u8, 0xFF), trailer[1]);
    // hashed_len = 4 + 4 + 10 = 18
    try std.testing.expectEqual(@as(u64, 18), mem.readInt(u64, trailer[2..10], .big));
}

test "computeV6DocumentHash deterministic with same salt" {
    const allocator = std.testing.allocator;

    const document = "Hello, RFC 9580!";
    const salt = [_]u8{0x42} ** 16;
    const subpackets = [_]u8{0x01};

    const result1 = try computeV6DocumentHash(
        .sha256,
        document,
        0x00,
        @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign),
        @intFromEnum(HashAlgorithm.sha256),
        &subpackets,
        &salt,
        allocator,
    );

    const result2 = try computeV6DocumentHash(
        .sha256,
        document,
        0x00,
        @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign),
        @intFromEnum(HashAlgorithm.sha256),
        &subpackets,
        &salt,
        allocator,
    );

    try std.testing.expectEqualSlices(u8, result1.digestSlice(), result2.digestSlice());
    try std.testing.expectEqual(result1.prefix, result2.prefix);
}

test "computeV6DocumentHash differs with different salt" {
    const allocator = std.testing.allocator;

    const document = "Hello, RFC 9580!";
    const salt1 = [_]u8{0x42} ** 16;
    const salt2 = [_]u8{0x43} ** 16;
    const subpackets = [_]u8{};

    const result1 = try computeV6DocumentHash(
        .sha256,
        document,
        0x00,
        1,
        8,
        &subpackets,
        &salt1,
        allocator,
    );

    const result2 = try computeV6DocumentHash(
        .sha256,
        document,
        0x00,
        1,
        8,
        &subpackets,
        &salt2,
        allocator,
    );

    try std.testing.expect(!mem.eql(u8, result1.digestSlice(), result2.digestSlice()));
}

test "computeV6DocumentHash differs from V4" {
    const allocator = std.testing.allocator;

    const document = "test document";
    const salt = [_]u8{0} ** 16;
    const subpackets = [_]u8{};

    const v6_result = try computeV6DocumentHash(
        .sha256,
        document,
        0x00,
        1,
        8,
        &subpackets,
        &salt,
        allocator,
    );

    const v4_result = try v4_creation.computeDocumentHash(
        .sha256,
        document,
        0x00,
        1,
        8,
        &subpackets,
        allocator,
    );

    // V6 and V4 hashes should be different (different structure, salt, etc.)
    try std.testing.expect(!mem.eql(u8, v6_result.digestSlice(), v4_result.digestSlice()));
}

test "computeV6CertificationHash basic" {
    const allocator = std.testing.allocator;

    const key_body = [_]u8{ 6, 0x00, 0x00, 0x00, 0x01, 27 } ++ [_]u8{0x42} ** 32;
    const user_id = "Alice <alice@example.com>";
    const salt = [_]u8{0xAA} ** 16;
    const subpackets = [_]u8{};

    const result = try computeV6CertificationHash(
        .sha256,
        &key_body,
        user_id,
        0x13,
        @intFromEnum(PublicKeyAlgorithm.ed25519),
        @intFromEnum(HashAlgorithm.sha256),
        &subpackets,
        &salt,
        allocator,
    );

    try std.testing.expectEqual(@as(usize, 32), result.digest_len);
    try std.testing.expectEqual(result.digest[0], result.prefix[0]);
    try std.testing.expectEqual(result.digest[1], result.prefix[1]);
}

test "computeV6CertificationHash deterministic" {
    const allocator = std.testing.allocator;

    const key_body = [_]u8{ 6, 0, 0, 0, 1, 27 } ++ [_]u8{0x42} ** 32;
    const user_id = "Bob <bob@example.com>";
    const salt = [_]u8{0xBB} ** 16;
    const subpackets = [_]u8{ 0x05, 0x02, 0x60, 0x00, 0x00, 0x00 };

    const r1 = try computeV6CertificationHash(
        .sha256,
        &key_body,
        user_id,
        0x13,
        27,
        8,
        &subpackets,
        &salt,
        allocator,
    );

    const r2 = try computeV6CertificationHash(
        .sha256,
        &key_body,
        user_id,
        0x13,
        27,
        8,
        &subpackets,
        &salt,
        allocator,
    );

    try std.testing.expectEqualSlices(u8, r1.digestSlice(), r2.digestSlice());
}

test "computeV6SubkeyBindingHash basic" {
    const allocator = std.testing.allocator;

    const primary = [_]u8{ 6, 0, 0, 0, 1, 27 } ++ [_]u8{0xAA} ** 32;
    const subkey = [_]u8{ 6, 0, 0, 0, 2, 25 } ++ [_]u8{0xBB} ** 32;
    const salt = [_]u8{0xCC} ** 16;
    const subpackets = [_]u8{};

    const result = try computeV6SubkeyBindingHash(
        .sha256,
        &primary,
        &subkey,
        0x18,
        27,
        8,
        &subpackets,
        &salt,
        allocator,
    );

    try std.testing.expectEqual(@as(usize, 32), result.digest_len);
}

test "computeV6SubkeyBindingHash different keys differ" {
    const allocator = std.testing.allocator;

    const primary = [_]u8{ 6, 0, 0, 0, 1, 27 } ++ [_]u8{0xAA} ** 32;
    const subkey1 = [_]u8{ 6, 0, 0, 0, 2, 25 } ++ [_]u8{0xBB} ** 32;
    const subkey2 = [_]u8{ 6, 0, 0, 0, 3, 25 } ++ [_]u8{0xCC} ** 32;
    const salt = [_]u8{0xDD} ** 16;

    const r1 = try computeV6SubkeyBindingHash(
        .sha256,
        &primary,
        &subkey1,
        0x18,
        27,
        8,
        &[_]u8{},
        &salt,
        allocator,
    );

    const r2 = try computeV6SubkeyBindingHash(
        .sha256,
        &primary,
        &subkey2,
        0x18,
        27,
        8,
        &[_]u8{},
        &salt,
        allocator,
    );

    try std.testing.expect(!mem.eql(u8, r1.digestSlice(), r2.digestSlice()));
}

test "computeV6DirectKeyHash basic" {
    const allocator = std.testing.allocator;

    const key_body = [_]u8{ 6, 0, 0, 0, 1, 27 } ++ [_]u8{0x42} ** 32;
    const salt = [_]u8{0xEE} ** 16;

    const result = try computeV6DirectKeyHash(
        .sha256,
        &key_body,
        0x1F,
        27,
        8,
        &[_]u8{},
        &salt,
        allocator,
    );

    try std.testing.expectEqual(@as(usize, 32), result.digest_len);
}

test "computeV6DocumentHash with SHA-512" {
    const allocator = std.testing.allocator;

    const document = "SHA-512 test";
    const salt = [_]u8{0x55} ** 32; // 32-byte salt for SHA-512

    const result = try computeV6DocumentHash(
        .sha512,
        document,
        0x00,
        1,
        10,
        &[_]u8{},
        &salt,
        allocator,
    );

    try std.testing.expectEqual(@as(usize, 64), result.digest_len);
}
