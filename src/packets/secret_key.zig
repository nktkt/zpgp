// SPDX-License-Identifier: MIT
//! OpenPGP Secret-Key Packet (Tag 5) and Secret-Subkey Packet (Tag 7)
//! per RFC 4880 Section 5.5.3.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const PublicKeyPacket = @import("public_key.zig").PublicKeyPacket;
const SymmetricAlgorithm = @import("../types/enums.zig").SymmetricAlgorithm;

/// RFC 4880 Section 5.5.3 — Secret-Key Packet.
///
/// A secret-key packet contains a public-key portion followed by the
/// secret-key material, which may be encrypted.
///
/// s2k_usage byte:
///   0   — secret data is not encrypted (no S2K, no IV)
///   254 — secret data is encrypted; SHA-1 hash check
///   255 — secret data is encrypted; two-octet checksum
///   other — value is symmetric algorithm ID; simple checksum
pub const SecretKeyPacket = struct {
    public_key: PublicKeyPacket,
    s2k_usage: u8,
    /// Symmetric algorithm (present when s2k_usage != 0).
    symmetric_algo: ?SymmetricAlgorithm,
    /// Raw S2K specifier bytes (present when s2k_usage == 254 or 255).
    s2k_data: ?[]const u8,
    /// Initialization vector (present when s2k_usage != 0).
    iv: ?[]const u8,
    /// Secret key data (encrypted or plaintext MPI data).
    secret_data: []const u8,
    /// Checksum or SHA-1 hash at the end.
    checksum_data: []const u8,

    is_subkey: bool,

    /// Parse a Secret-Key Packet from the raw body bytes.
    pub fn parse(allocator: Allocator, body: []const u8, is_subkey: bool) !SecretKeyPacket {
        // First, figure out where the public-key portion ends.
        // We need to parse the public key header to find the boundary.
        if (body.len < 6) return error.InvalidPacket;

        const version = body[0];
        if (version != 4) return error.UnsupportedVersion;

        // Parse algorithm to determine MPI count in public part
        const algorithm_byte = body[5];
        const algo = @import("../types/enums.zig").PublicKeyAlgorithm;
        const algorithm: algo = @enumFromInt(algorithm_byte);

        // Calculate public key portion length
        var pub_end: usize = 6;
        const mpi_count: ?usize = switch (algorithm) {
            .rsa_encrypt_sign, .rsa_encrypt_only, .rsa_sign_only => 2,
            .dsa => 4,
            .elgamal => 3,
            .ecdsa, .eddsa, .ecdh => null,
            _ => null,
        };

        if (mpi_count) |count| {
            // Skip over `count` MPIs
            for (0..count) |_| {
                if (pub_end + 2 > body.len) return error.InvalidPacket;
                const bit_count = mem.readInt(u16, body[pub_end..][0..2], .big);
                const byte_len: usize = if (bit_count == 0) 0 else ((@as(usize, bit_count) + 7) / 8);
                pub_end += 2 + byte_len;
                if (pub_end > body.len) return error.InvalidPacket;
            }
        } else {
            // ECC: we need to skip the OID + MPI.
            // OID format: length byte + OID bytes, then one MPI.
            // For ECDH there may also be KDF params at end.
            // For Phase 1, we scan forward by reading OID length, OID, then MPI.
            if (pub_end >= body.len) return error.InvalidPacket;
            const oid_len: usize = body[pub_end];
            pub_end += 1 + oid_len;
            if (pub_end > body.len) return error.InvalidPacket;
            // Read one MPI (the public point)
            if (pub_end + 2 > body.len) return error.InvalidPacket;
            const bit_count = mem.readInt(u16, body[pub_end..][0..2], .big);
            const byte_len: usize = if (bit_count == 0) 0 else ((@as(usize, bit_count) + 7) / 8);
            pub_end += 2 + byte_len;
            if (pub_end > body.len) return error.InvalidPacket;
            // ECDH has additional KDF params: 1 byte length + kdf bytes
            if (algorithm == .ecdh) {
                if (pub_end >= body.len) return error.InvalidPacket;
                const kdf_len: usize = body[pub_end];
                pub_end += 1 + kdf_len;
                if (pub_end > body.len) return error.InvalidPacket;
            }
        }

        // Parse public key from the public portion
        const public_key = try PublicKeyPacket.parse(allocator, body[0..pub_end], is_subkey);
        errdefer public_key.deinit(allocator);

        // Now parse secret key material
        if (pub_end >= body.len) return error.InvalidPacket;
        const s2k_usage = body[pub_end];
        var offset = pub_end + 1;

        var symmetric_algo: ?SymmetricAlgorithm = null;
        var s2k_data: ?[]const u8 = null;
        var iv: ?[]const u8 = null;

        if (s2k_usage != 0) {
            if (s2k_usage == 254 or s2k_usage == 255) {
                // Symmetric algo byte + S2K specifier
                if (offset >= body.len) return error.InvalidPacket;
                symmetric_algo = @enumFromInt(body[offset]);
                offset += 1;

                // Parse S2K to determine its length
                if (offset >= body.len) return error.InvalidPacket;
                const s2k_type = body[offset];
                const s2k_len: usize = switch (s2k_type) {
                    0 => 2, // Simple S2K: type(1) + hash(1)
                    1 => 10, // Salted S2K: type(1) + hash(1) + salt(8)
                    3 => 11, // Iterated+Salted: type(1) + hash(1) + salt(8) + count(1)
                    else => 2, // Fallback: treat as simple
                };

                if (offset + s2k_len > body.len) return error.InvalidPacket;
                const s2k = try allocator.dupe(u8, body[offset .. offset + s2k_len]);
                errdefer allocator.free(s2k);
                s2k_data = s2k;
                offset += s2k_len;
            } else {
                // s2k_usage IS the symmetric algorithm ID
                symmetric_algo = @enumFromInt(s2k_usage);
            }

            // Read IV (block size of symmetric algorithm)
            const block_size: usize = if (symmetric_algo) |sa| sa.blockSize() orelse 8 else 8;
            if (offset + block_size > body.len) return error.InvalidPacket;
            const iv_data = try allocator.dupe(u8, body[offset .. offset + block_size]);
            errdefer allocator.free(iv_data);
            iv = iv_data;
            offset += block_size;
        }

        // Remaining data: secret key material + checksum/hash
        // For encrypted data (s2k_usage != 0):
        //   All remaining is encrypted blob (checksum is inside encrypted data)
        // For unencrypted (s2k_usage == 0):
        //   plaintext MPIs + 2-byte checksum
        if (offset > body.len) return error.InvalidPacket;
        const remaining = body[offset..];

        var secret_data: []const u8 = undefined;
        var checksum_data: []const u8 = undefined;

        if (s2k_usage == 0) {
            // Unencrypted: last 2 bytes are checksum
            if (remaining.len < 2) return error.InvalidPacket;
            secret_data = try allocator.dupe(u8, remaining[0 .. remaining.len - 2]);
            errdefer allocator.free(secret_data);
            checksum_data = try allocator.dupe(u8, remaining[remaining.len - 2 ..]);
        } else if (s2k_usage == 254) {
            // SHA-1 check: last 20 bytes are hash
            if (remaining.len < 20) return error.InvalidPacket;
            secret_data = try allocator.dupe(u8, remaining[0 .. remaining.len - 20]);
            errdefer allocator.free(secret_data);
            checksum_data = try allocator.dupe(u8, remaining[remaining.len - 20 ..]);
        } else {
            // s2k_usage == 255 or other: last 2 bytes are checksum
            // But when encrypted, the entire blob is opaque — store all as secret_data
            // and empty checksum (checksum is inside the encrypted data).
            secret_data = try allocator.dupe(u8, remaining);
            errdefer allocator.free(secret_data);
            checksum_data = try allocator.dupe(u8, &[_]u8{});
        }

        return .{
            .public_key = public_key,
            .s2k_usage = s2k_usage,
            .symmetric_algo = symmetric_algo,
            .s2k_data = s2k_data,
            .iv = iv,
            .secret_data = secret_data,
            .checksum_data = checksum_data,
            .is_subkey = is_subkey,
        };
    }

    /// Free all allocator-owned memory.
    pub fn deinit(self: SecretKeyPacket, allocator: Allocator) void {
        self.public_key.deinit(allocator);
        if (self.s2k_data) |s| allocator.free(s);
        if (self.iv) |v| allocator.free(v);
        if (self.secret_data.len > 0) allocator.free(self.secret_data);
        if (self.checksum_data.len > 0) allocator.free(self.checksum_data);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "SecretKeyPacket parse unencrypted RSA" {
    const allocator = std.testing.allocator;

    // Public portion: v4, creation=100, algo=RSA(1), 2 small MPIs
    // Secret portion: s2k_usage=0, secret data bytes, 2-byte checksum
    var body: [30]u8 = undefined;
    body[0] = 4; // version
    mem.writeInt(u32, body[1..5], 100, .big);
    body[5] = 1; // RSA
    // MPI n: 8 bits, 1 byte
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xAB;
    // MPI e: 8 bits, 1 byte
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;
    // -- secret key portion --
    body[12] = 0; // s2k_usage = 0 (unencrypted)
    // Secret data (e.g., plaintext MPIs as raw bytes)
    body[13] = 0xDE;
    body[14] = 0xAD;
    body[15] = 0xBE;
    body[16] = 0xEF;
    // 2-byte checksum
    body[17] = 0xCA;
    body[18] = 0xFE;

    const pkt = try SecretKeyPacket.parse(allocator, body[0..19], false);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 0), pkt.s2k_usage);
    try std.testing.expect(pkt.symmetric_algo == null);
    try std.testing.expect(pkt.s2k_data == null);
    try std.testing.expect(pkt.iv == null);
    try std.testing.expect(!pkt.is_subkey);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, pkt.secret_data);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xCA, 0xFE }, pkt.checksum_data);
    // Verify public key portion
    try std.testing.expectEqual(@as(u8, 4), pkt.public_key.version);
    try std.testing.expectEqual(@as(usize, 2), pkt.public_key.key_material.len);
}

test "SecretKeyPacket parse encrypted with S2K (usage=254)" {
    const allocator = std.testing.allocator;

    // Public portion: v4, creation=200, algo=RSA(1), 2 small MPIs
    var body: [60]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], 200, .big);
    body[5] = 1; // RSA
    // MPI n: 8 bits
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xFF;
    // MPI e: 8 bits
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x11;
    // -- secret portion --
    body[12] = 254; // s2k_usage = SHA-1 check
    body[13] = 9; // AES-256
    // S2K: Iterated+Salted (type=3, hash=SHA256(8), 8-byte salt, count)
    body[14] = 3; // type
    body[15] = 8; // hash algo (SHA256)
    @memset(body[16..24], 0xAA); // salt (8 bytes)
    body[24] = 0x60; // count
    // IV: AES block size = 16 bytes
    @memset(body[25..41], 0xBB);
    // Encrypted secret data (arbitrary) + 20-byte SHA-1 hash
    @memset(body[41..50], 0xCC); // 9 bytes secret data
    @memset(body[50..60], 0xDD); // ... more for the 20-byte hash (we only have 10 more)

    // Actually we need enough room for at least 20 bytes of "hash" at end.
    // Let's recalculate: offset after IV = 41, remaining = body[41..60] = 19 bytes
    // For SHA-1 check, need at least 20. Let's use a bigger buffer.
    var body2: [65]u8 = undefined;
    @memcpy(body2[0..41], body[0..41]);
    @memset(body2[41..45], 0xCC); // 4 bytes secret
    @memset(body2[45..65], 0xDD); // 20 bytes hash

    const pkt = try SecretKeyPacket.parse(allocator, body2[0..65], false);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 254), pkt.s2k_usage);
    try std.testing.expectEqual(SymmetricAlgorithm.aes256, pkt.symmetric_algo.?);
    try std.testing.expect(pkt.s2k_data != null);
    try std.testing.expectEqual(@as(usize, 11), pkt.s2k_data.?.len); // Iterated+Salted
    try std.testing.expect(pkt.iv != null);
    try std.testing.expectEqual(@as(usize, 16), pkt.iv.?.len);
    try std.testing.expectEqual(@as(usize, 4), pkt.secret_data.len);
    try std.testing.expectEqual(@as(usize, 20), pkt.checksum_data.len);
}

test "SecretKeyPacket parse body too short" {
    const allocator = std.testing.allocator;
    const body = [_]u8{ 4, 0, 0, 0, 0 };
    try std.testing.expectError(error.InvalidPacket, SecretKeyPacket.parse(allocator, &body, false));
}

test "SecretKeyPacket subkey flag" {
    const allocator = std.testing.allocator;

    // Minimal unencrypted RSA
    var body: [19]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], 0, .big);
    body[5] = 1;
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0x80;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;
    body[12] = 0; // unencrypted
    body[13] = 0x01;
    body[14] = 0x02;
    body[15] = 0x03;
    body[16] = 0x04;
    body[17] = 0xAA;
    body[18] = 0xBB;

    const pkt = try SecretKeyPacket.parse(allocator, &body, true);
    defer pkt.deinit(allocator);

    try std.testing.expect(pkt.is_subkey);
}
