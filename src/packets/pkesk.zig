// SPDX-License-Identifier: MIT
//! OpenPGP Public-Key Encrypted Session Key Packet (Tag 1)
//! per RFC 4880 Section 5.1.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Mpi = @import("../types/mpi.zig").Mpi;
const PublicKeyAlgorithm = @import("../types/enums.zig").PublicKeyAlgorithm;

/// RFC 4880 Section 5.1 — Public-Key Encrypted Session Key Packet.
///
/// Layout (v3):
///   1 octet  — version (3)
///   8 octets — key ID
///   1 octet  — public-key algorithm
///   MPI(s)   — encrypted session key
///             RSA: 1 MPI; Elgamal: 2 MPIs
pub const PKESKPacket = struct {
    version: u8,
    key_id: [8]u8,
    algorithm: PublicKeyAlgorithm,
    encrypted_session_key: []Mpi,

    /// Return the number of encrypted session key MPIs for a given algorithm.
    fn encMpiCount(algo: PublicKeyAlgorithm) usize {
        return switch (algo) {
            .rsa_encrypt_sign, .rsa_encrypt_only, .rsa_sign_only => 1,
            .elgamal => 2,
            .ecdh => 1,
            else => 1, // Fallback
        };
    }

    /// Parse a PKESK Packet from the raw body bytes.
    pub fn parse(allocator: Allocator, body: []const u8) !PKESKPacket {
        // Minimum: version(1) + key_id(8) + algorithm(1) = 10
        if (body.len < 10) return error.InvalidPacket;

        const version = body[0];
        if (version != 3) return error.UnsupportedVersion;

        var key_id: [8]u8 = undefined;
        @memcpy(&key_id, body[1..9]);

        const algorithm: PublicKeyAlgorithm = @enumFromInt(body[9]);

        var offset: usize = 10;
        const mpi_count = encMpiCount(algorithm);

        var mpis: std.ArrayList(Mpi) = .empty;
        errdefer {
            for (mpis.items) |m| m.deinit(allocator);
            mpis.deinit(allocator);
        }

        for (0..mpi_count) |_| {
            if (offset + 2 > body.len) return error.InvalidPacket;
            const bit_count = mem.readInt(u16, body[offset..][0..2], .big);
            const byte_len: usize = if (bit_count == 0) 0 else ((@as(usize, bit_count) + 7) / 8);
            offset += 2;

            if (offset + byte_len > body.len) return error.InvalidPacket;
            const data = try allocator.dupe(u8, body[offset .. offset + byte_len]);
            errdefer allocator.free(data);
            try mpis.append(allocator, Mpi{ .bit_count = bit_count, .data = data });
            offset += byte_len;
        }

        return .{
            .version = version,
            .key_id = key_id,
            .algorithm = algorithm,
            .encrypted_session_key = try mpis.toOwnedSlice(allocator),
        };
    }

    /// Free all allocator-owned memory.
    pub fn deinit(self: PKESKPacket, allocator: Allocator) void {
        for (self.encrypted_session_key) |m| m.deinit(allocator);
        allocator.free(self.encrypted_session_key);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "PKESKPacket parse v3 RSA" {
    const allocator = std.testing.allocator;

    // version=3, key_id=0x0102030405060708, algo=RSA(1), 1 MPI (16 bits)
    var body: [16]u8 = undefined;
    body[0] = 3; // version
    // key_id
    body[1] = 0x01;
    body[2] = 0x02;
    body[3] = 0x03;
    body[4] = 0x04;
    body[5] = 0x05;
    body[6] = 0x06;
    body[7] = 0x07;
    body[8] = 0x08;
    body[9] = 1; // RSA
    // MPI: 16 bits = 2 bytes
    mem.writeInt(u16, body[10..12], 16, .big);
    body[12] = 0xCA;
    body[13] = 0xFE;

    const pkt = try PKESKPacket.parse(allocator, body[0..14]);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 3), pkt.version);
    try std.testing.expectEqual([8]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }, pkt.key_id);
    try std.testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, pkt.algorithm);
    try std.testing.expectEqual(@as(usize, 1), pkt.encrypted_session_key.len);
    try std.testing.expectEqual(@as(u16, 16), pkt.encrypted_session_key[0].bit_count);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xCA, 0xFE }, pkt.encrypted_session_key[0].data);
}

test "PKESKPacket parse v3 Elgamal (2 MPIs)" {
    const allocator = std.testing.allocator;

    var body: [20]u8 = undefined;
    body[0] = 3;
    @memset(body[1..9], 0xFF); // key_id
    body[9] = 16; // Elgamal
    // MPI 1: 8 bits = 1 byte
    mem.writeInt(u16, body[10..12], 8, .big);
    body[12] = 0xAA;
    // MPI 2: 8 bits = 1 byte
    mem.writeInt(u16, body[13..15], 8, .big);
    body[15] = 0xBB;

    const pkt = try PKESKPacket.parse(allocator, body[0..16]);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(PublicKeyAlgorithm.elgamal, pkt.algorithm);
    try std.testing.expectEqual(@as(usize, 2), pkt.encrypted_session_key.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{0xAA}, pkt.encrypted_session_key[0].data);
    try std.testing.expectEqualSlices(u8, &[_]u8{0xBB}, pkt.encrypted_session_key[1].data);
}

test "PKESKPacket body too short" {
    const allocator = std.testing.allocator;
    const body = [_]u8{ 3, 0, 0, 0, 0, 0, 0, 0, 0 }; // 9 bytes, need 10
    try std.testing.expectError(error.InvalidPacket, PKESKPacket.parse(allocator, &body));
}

test "PKESKPacket unsupported version" {
    const allocator = std.testing.allocator;
    var body: [14]u8 = undefined;
    body[0] = 2; // wrong version
    @memset(body[1..], 0);
    try std.testing.expectError(error.UnsupportedVersion, PKESKPacket.parse(allocator, &body));
}

test "PKESKPacket wildcard key_id" {
    const allocator = std.testing.allocator;

    // All-zero key ID means "try all available keys"
    var body: [16]u8 = undefined;
    body[0] = 3;
    @memset(body[1..9], 0x00);
    body[9] = 1; // RSA
    mem.writeInt(u16, body[10..12], 8, .big);
    body[12] = 0x42;

    const pkt = try PKESKPacket.parse(allocator, body[0..13]);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual([8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }, pkt.key_id);
}
