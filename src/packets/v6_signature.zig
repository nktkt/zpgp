// SPDX-License-Identifier: MIT
//! OpenPGP V6 Signature Packet (Tag 2) per RFC 9580 Section 5.2.
//!
//! V6 signature packet layout:
//!   1 octet  -- version (6)
//!   1 octet  -- signature type
//!   1 octet  -- public-key algorithm
//!   1 octet  -- hash algorithm
//!   4 octets -- hashed subpackets length (big-endian) -- 4 bytes in V6 (was 2 in V4)
//!   N octets -- hashed subpackets data
//!   4 octets -- unhashed subpackets length (big-endian) -- 4 bytes in V6 (was 2 in V4)
//!   M octets -- unhashed subpackets data
//!   2 octets -- hash prefix (left 16 bits of hash)
//!   K octets -- salt (length depends on hash algorithm)
//!   MPI(s)   -- signature value(s)
//!
//! V6 signature salt sizes per RFC 9580:
//!   - SHA-256: 16 bytes
//!   - SHA-384: 24 bytes
//!   - SHA-512: 32 bytes
//!   - SHA-224: 16 bytes
//!   - SHA3-256: 16 bytes (etc.)

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Mpi = @import("../types/mpi.zig").Mpi;
const PublicKeyAlgorithm = @import("../types/enums.zig").PublicKeyAlgorithm;
const HashAlgorithm = @import("../types/enums.zig").HashAlgorithm;

/// RFC 9580 Section 5.2 -- V6 Signature Packet.
pub const V6SignaturePacket = struct {
    version: u8,
    sig_type: u8,
    pub_algo: PublicKeyAlgorithm,
    hash_algo: HashAlgorithm,
    hashed_subpacket_data: []const u8,
    unhashed_subpacket_data: []const u8,
    hash_prefix: [2]u8,
    /// V6 signature salt. Length depends on hash algorithm.
    salt: []const u8,
    signature_mpis: []Mpi,

    /// Return the salt size for a given hash algorithm per RFC 9580.
    pub fn saltSize(hash_algo: HashAlgorithm) ?usize {
        return switch (hash_algo) {
            .sha256 => 16,
            .sha384 => 24,
            .sha512 => 32,
            .sha224 => 16,
            .sha1 => 16, // not recommended but defined
            else => null,
        };
    }

    /// Return the number of signature MPIs for a given algorithm.
    fn sigMpiCount(algo: PublicKeyAlgorithm) usize {
        return switch (algo) {
            .rsa_encrypt_sign, .rsa_encrypt_only, .rsa_sign_only => 1,
            .dsa, .ecdsa, .eddsa => 2,
            else => 1,
        };
    }

    /// Parse a V6 Signature Packet from the raw body bytes.
    pub fn parse(allocator: Allocator, body: []const u8) !V6SignaturePacket {
        // Minimum: version(1) + sig_type(1) + pub_algo(1) + hash_algo(1)
        //        + hashed_len(4) + unhashed_len(4) + hash_prefix(2) = 14
        if (body.len < 14) return error.InvalidPacket;

        const version = body[0];
        if (version != 6) return error.UnsupportedVersion;

        const sig_type = body[1];
        const pub_algo: PublicKeyAlgorithm = @enumFromInt(body[2]);
        const hash_algo: HashAlgorithm = @enumFromInt(body[3]);

        var offset: usize = 4;

        // Hashed subpackets (4 bytes length in V6)
        if (offset + 4 > body.len) return error.InvalidPacket;
        const hashed_len: usize = mem.readInt(u32, body[offset..][0..4], .big);
        offset += 4;
        if (offset + hashed_len > body.len) return error.InvalidPacket;
        const hashed_subpacket_data = try allocator.dupe(u8, body[offset .. offset + hashed_len]);
        errdefer allocator.free(hashed_subpacket_data);
        offset += hashed_len;

        // Unhashed subpackets (4 bytes length in V6)
        if (offset + 4 > body.len) return error.InvalidPacket;
        const unhashed_len: usize = mem.readInt(u32, body[offset..][0..4], .big);
        offset += 4;
        if (offset + unhashed_len > body.len) return error.InvalidPacket;
        const unhashed_subpacket_data = try allocator.dupe(u8, body[offset .. offset + unhashed_len]);
        errdefer allocator.free(unhashed_subpacket_data);
        offset += unhashed_len;

        // Hash prefix (2 bytes)
        if (offset + 2 > body.len) return error.InvalidPacket;
        const hash_prefix: [2]u8 = body[offset..][0..2].*;
        offset += 2;

        // Salt (variable length based on hash algorithm)
        const salt_len = saltSize(hash_algo) orelse 16; // default to 16 if unknown
        if (offset + salt_len > body.len) return error.InvalidPacket;
        const salt = try allocator.dupe(u8, body[offset .. offset + salt_len]);
        errdefer allocator.free(salt);
        offset += salt_len;

        // Signature MPIs
        const mpi_count = sigMpiCount(pub_algo);
        var mpis = try allocator.alloc(Mpi, mpi_count);
        errdefer {
            for (mpis[0..mpi_count]) |m| m.deinit(allocator);
            allocator.free(mpis);
        }

        for (0..mpi_count) |i| {
            if (offset >= body.len) {
                // Not enough data for all MPIs - free already-parsed ones
                for (mpis[0..i]) |m| m.deinit(allocator);
                allocator.free(mpis);
                return error.InvalidPacket;
            }
            var fbs = std.io.fixedBufferStream(body[offset..]);
            mpis[i] = Mpi.readFrom(allocator, fbs.reader()) catch {
                for (mpis[0..i]) |m| m.deinit(allocator);
                allocator.free(mpis);
                return error.InvalidPacket;
            };
            offset += mpis[i].wireLen();
        }

        return .{
            .version = version,
            .sig_type = sig_type,
            .pub_algo = pub_algo,
            .hash_algo = hash_algo,
            .hashed_subpacket_data = hashed_subpacket_data,
            .unhashed_subpacket_data = unhashed_subpacket_data,
            .hash_prefix = hash_prefix,
            .salt = salt,
            .signature_mpis = mpis,
        };
    }

    /// Free all allocator-owned memory.
    pub fn deinit(self: V6SignaturePacket, allocator: Allocator) void {
        allocator.free(self.hashed_subpacket_data);
        allocator.free(self.unhashed_subpacket_data);
        allocator.free(self.salt);
        for (self.signature_mpis) |mpi_item| {
            mpi_item.deinit(allocator);
        }
        allocator.free(self.signature_mpis);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "V6SignaturePacket parse basic RSA" {
    const allocator = std.testing.allocator;

    // Build a minimal V6 RSA signature packet body
    var body: [200]u8 = undefined;
    body[0] = 6; // version
    body[1] = 0x00; // sig type: binary signature
    body[2] = @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign);
    body[3] = @intFromEnum(HashAlgorithm.sha256);

    // Hashed subpackets: length 0 (4 bytes)
    mem.writeInt(u32, body[4..8], 0, .big);
    // Unhashed subpackets: length 0 (4 bytes)
    mem.writeInt(u32, body[8..12], 0, .big);
    // Hash prefix
    body[12] = 0xAB;
    body[13] = 0xCD;
    // Salt: 16 bytes for SHA-256
    @memset(body[14..30], 0x42);
    // Signature MPI: 1 MPI for RSA (8-bit value 0xFF)
    mem.writeInt(u16, body[30..32], 8, .big);
    body[32] = 0xFF;

    const pkt = try V6SignaturePacket.parse(allocator, body[0..33]);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 6), pkt.version);
    try std.testing.expectEqual(@as(u8, 0x00), pkt.sig_type);
    try std.testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, pkt.pub_algo);
    try std.testing.expectEqual(HashAlgorithm.sha256, pkt.hash_algo);
    try std.testing.expectEqual(@as(usize, 0), pkt.hashed_subpacket_data.len);
    try std.testing.expectEqual(@as(usize, 0), pkt.unhashed_subpacket_data.len);
    try std.testing.expectEqual(@as(u8, 0xAB), pkt.hash_prefix[0]);
    try std.testing.expectEqual(@as(u8, 0xCD), pkt.hash_prefix[1]);
    try std.testing.expectEqual(@as(usize, 16), pkt.salt.len);
    try std.testing.expectEqual(@as(usize, 1), pkt.signature_mpis.len);
}

test "V6SignaturePacket parse DSA with subpackets" {
    const allocator = std.testing.allocator;

    var body: [200]u8 = undefined;
    body[0] = 6;
    body[1] = 0x01; // text signature
    body[2] = @intFromEnum(PublicKeyAlgorithm.dsa);
    body[3] = @intFromEnum(HashAlgorithm.sha512);

    // Hashed subpackets: 4 bytes of data
    mem.writeInt(u32, body[4..8], 4, .big);
    @memset(body[8..12], 0xAA);
    // Unhashed subpackets: 2 bytes of data
    mem.writeInt(u32, body[12..16], 2, .big);
    @memset(body[16..18], 0xBB);
    // Hash prefix
    body[18] = 0x12;
    body[19] = 0x34;
    // Salt: 32 bytes for SHA-512
    @memset(body[20..52], 0x55);
    // Two DSA MPIs
    mem.writeInt(u16, body[52..54], 8, .big);
    body[54] = 0x42;
    mem.writeInt(u16, body[55..57], 8, .big);
    body[57] = 0x43;

    const pkt = try V6SignaturePacket.parse(allocator, body[0..58]);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 6), pkt.version);
    try std.testing.expectEqual(PublicKeyAlgorithm.dsa, pkt.pub_algo);
    try std.testing.expectEqual(HashAlgorithm.sha512, pkt.hash_algo);
    try std.testing.expectEqual(@as(usize, 4), pkt.hashed_subpacket_data.len);
    try std.testing.expectEqual(@as(usize, 2), pkt.unhashed_subpacket_data.len);
    try std.testing.expectEqual(@as(usize, 32), pkt.salt.len);
    try std.testing.expectEqual(@as(usize, 2), pkt.signature_mpis.len);
}

test "V6SignaturePacket wrong version" {
    const allocator = std.testing.allocator;

    var body: [50]u8 = undefined;
    body[0] = 4; // wrong version
    @memset(body[1..], 0);

    try std.testing.expectError(error.UnsupportedVersion, V6SignaturePacket.parse(allocator, &body));
}

test "V6SignaturePacket body too short" {
    const allocator = std.testing.allocator;

    const body = [_]u8{ 6, 0, 0 };
    try std.testing.expectError(error.InvalidPacket, V6SignaturePacket.parse(allocator, &body));
}

test "V6SignaturePacket salt sizes" {
    try std.testing.expectEqual(@as(usize, 16), V6SignaturePacket.saltSize(.sha256).?);
    try std.testing.expectEqual(@as(usize, 24), V6SignaturePacket.saltSize(.sha384).?);
    try std.testing.expectEqual(@as(usize, 32), V6SignaturePacket.saltSize(.sha512).?);
    try std.testing.expectEqual(@as(usize, 16), V6SignaturePacket.saltSize(.sha224).?);
}

test "V6SignaturePacket data is a copy" {
    const allocator = std.testing.allocator;

    var body: [200]u8 = undefined;
    body[0] = 6;
    body[1] = 0x00;
    body[2] = @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign);
    body[3] = @intFromEnum(HashAlgorithm.sha256);
    mem.writeInt(u32, body[4..8], 0, .big);
    mem.writeInt(u32, body[8..12], 0, .big);
    body[12] = 0xAB;
    body[13] = 0xCD;
    @memset(body[14..30], 0x42);
    mem.writeInt(u16, body[30..32], 8, .big);
    body[32] = 0xFF;

    const pkt = try V6SignaturePacket.parse(allocator, body[0..33]);
    defer pkt.deinit(allocator);

    // Modify original
    body[14] = 0xFF;

    // Parsed salt should still be 0x42
    try std.testing.expectEqual(@as(u8, 0x42), pkt.salt[0]);
}

test "V6SignaturePacket hashed subpackets length is 4 bytes" {
    const allocator = std.testing.allocator;

    // Test with a larger subpacket length that requires >2 bytes
    var body: [300]u8 = undefined;
    body[0] = 6;
    body[1] = 0x00;
    body[2] = @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign);
    body[3] = @intFromEnum(HashAlgorithm.sha256);

    // Hashed subpackets: 100 bytes
    mem.writeInt(u32, body[4..8], 100, .big);
    @memset(body[8..108], 0xAA);
    // Unhashed subpackets: 0 bytes
    mem.writeInt(u32, body[108..112], 0, .big);
    // Hash prefix
    body[112] = 0x12;
    body[113] = 0x34;
    // Salt: 16 bytes for SHA-256
    @memset(body[114..130], 0x55);
    // MPI
    mem.writeInt(u16, body[130..132], 8, .big);
    body[132] = 0xFF;

    const pkt = try V6SignaturePacket.parse(allocator, body[0..133]);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 100), pkt.hashed_subpacket_data.len);
}
