// SPDX-License-Identifier: MIT
//! OpenPGP Public-Key Packet (Tag 6) and Public-Subkey Packet (Tag 14)
//! per RFC 4880 Section 5.5.2.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Mpi = @import("../types/mpi.zig").Mpi;
const PublicKeyAlgorithm = @import("../types/enums.zig").PublicKeyAlgorithm;

/// RFC 4880 Section 5.5.2 — Public-Key Packet.
///
/// Layout (v4):
///   1 octet  — version (4)
///   4 octets — creation time (big-endian)
///   1 octet  — public-key algorithm
///   algorithm-specific MPI data
pub const PublicKeyPacket = struct {
    version: u8,
    creation_time: u32,
    algorithm: PublicKeyAlgorithm,
    /// Algorithm-specific key material stored as raw MPIs.
    /// RSA: n, e; DSA: p, q, g, y; Elgamal: p, g, y; ECC: raw point.
    key_material: []Mpi,
    /// Whether this is a subkey packet (tag 14 vs tag 6).
    is_subkey: bool,
    /// Raw bytes of the key packet body (for fingerprint calculation).
    raw_body: []const u8,

    /// Return the number of MPIs expected for a given algorithm.
    fn mpiCount(algo: PublicKeyAlgorithm) ?usize {
        return switch (algo) {
            .rsa_encrypt_sign, .rsa_encrypt_only, .rsa_sign_only => 2,
            .dsa => 4,
            .elgamal => 3,
            // ECC algorithms: handled specially (store remaining as 1 raw MPI)
            .ecdsa, .eddsa, .ecdh => null,
            // RFC 9580 native key types use raw bytes, not MPIs
            .x25519, .x448, .ed25519, .ed448 => null,
            _ => null,
        };
    }

    /// Parse a Public-Key Packet from the raw body bytes.
    pub fn parse(allocator: Allocator, body: []const u8, is_subkey: bool) !PublicKeyPacket {
        // Minimum: version(1) + creation_time(4) + algorithm(1) = 6
        if (body.len < 6) return error.InvalidPacket;

        const version = body[0];
        if (version != 4) return error.UnsupportedVersion;

        const creation_time = mem.readInt(u32, body[1..5], .big);
        const algorithm: PublicKeyAlgorithm = @enumFromInt(body[5]);

        var offset: usize = 6;

        // Parse MPIs based on algorithm
        const count_opt = mpiCount(algorithm);

        var mpis: std.ArrayList(Mpi) = .empty;
        errdefer {
            for (mpis.items) |m| m.deinit(allocator);
            mpis.deinit(allocator);
        }

        if (count_opt) |count| {
            // Standard algorithms: read exactly `count` MPIs
            for (0..count) |_| {
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
        } else {
            // ECC or unknown: store all remaining key data as a single raw MPI
            if (offset < body.len) {
                const remaining = try allocator.dupe(u8, body[offset..]);
                errdefer allocator.free(remaining);
                var raw_mpi = Mpi.fromBytes(remaining);
                // Fixup: fromBytes doesn't allocate so we need to set data to our dupe
                raw_mpi.data = remaining;
                try mpis.append(allocator, raw_mpi);
            }
        }

        const raw_body = try allocator.dupe(u8, body);

        return .{
            .version = version,
            .creation_time = creation_time,
            .algorithm = algorithm,
            .key_material = try mpis.toOwnedSlice(allocator),
            .is_subkey = is_subkey,
            .raw_body = raw_body,
        };
    }

    /// Serialize the packet body (without the packet header).
    pub fn serialize(self: PublicKeyPacket, allocator: Allocator) ![]u8 {
        // Calculate total size
        var total: usize = 6; // version + creation_time + algorithm

        const count_opt = mpiCount(self.algorithm);
        if (count_opt) |_| {
            for (self.key_material) |m| {
                total += m.wireLen();
            }
        } else {
            // ECC/unknown: write raw data
            for (self.key_material) |m| {
                total += m.data.len;
            }
        }

        const buf = try allocator.alloc(u8, total);
        errdefer allocator.free(buf);

        buf[0] = self.version;
        mem.writeInt(u32, buf[1..5], self.creation_time, .big);
        buf[5] = @intFromEnum(self.algorithm);

        var offset: usize = 6;
        if (count_opt) |_| {
            for (self.key_material) |m| {
                mem.writeInt(u16, buf[offset..][0..2], m.bit_count, .big);
                offset += 2;
                if (m.data.len > 0) {
                    @memcpy(buf[offset .. offset + m.data.len], m.data);
                    offset += m.data.len;
                }
            }
        } else {
            for (self.key_material) |m| {
                @memcpy(buf[offset .. offset + m.data.len], m.data);
                offset += m.data.len;
            }
        }

        return buf;
    }

    /// Free all allocator-owned memory.
    pub fn deinit(self: PublicKeyPacket, allocator: Allocator) void {
        for (self.key_material) |m| {
            m.deinit(allocator);
        }
        allocator.free(self.key_material);
        allocator.free(self.raw_body);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "PublicKeyPacket parse RSA v4 key" {
    const allocator = std.testing.allocator;

    // Build a v4 RSA key body:
    //   version=4, creation_time=0x5F000000, algo=1 (RSA encrypt+sign)
    //   MPI n: bit_count=16, data=0x80,0x01 (2 bytes)
    //   MPI e: bit_count=17, data=0x01,0x00,0x01 (3 bytes)
    var body: [16]u8 = undefined;
    body[0] = 4; // version
    mem.writeInt(u32, body[1..5], 0x5F000000, .big);
    body[5] = 1; // RSA encrypt+sign
    // MPI n: 16 bits = 2 bytes
    mem.writeInt(u16, body[6..8], 16, .big);
    body[8] = 0x80;
    body[9] = 0x01;
    // MPI e: 17 bits = 3 bytes
    mem.writeInt(u16, body[10..12], 17, .big);
    body[12] = 0x01;
    body[13] = 0x00;
    body[14] = 0x01;

    const pkt = try PublicKeyPacket.parse(allocator, body[0..15], false);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 4), pkt.version);
    try std.testing.expectEqual(@as(u32, 0x5F000000), pkt.creation_time);
    try std.testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, pkt.algorithm);
    try std.testing.expect(!pkt.is_subkey);
    try std.testing.expectEqual(@as(usize, 2), pkt.key_material.len);
    try std.testing.expectEqual(@as(u16, 16), pkt.key_material[0].bit_count);
    try std.testing.expectEqual(@as(u16, 17), pkt.key_material[1].bit_count);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x80, 0x01 }, pkt.key_material[0].data);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00, 0x01 }, pkt.key_material[1].data);
    try std.testing.expectEqualSlices(u8, body[0..15], pkt.raw_body);
}

test "PublicKeyPacket parse DSA v4 key" {
    const allocator = std.testing.allocator;

    // DSA: 4 MPIs (p, q, g, y) — each 8 bits = 1 byte for simplicity
    var body: [20]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], 1000, .big);
    body[5] = 17; // DSA
    var offset: usize = 6;
    for (0..4) |i| {
        mem.writeInt(u16, body[offset..][0..2], 8, .big);
        offset += 2;
        body[offset] = @intCast(0xA0 + i);
        offset += 1;
    }

    const pkt = try PublicKeyPacket.parse(allocator, body[0..offset], false);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(PublicKeyAlgorithm.dsa, pkt.algorithm);
    try std.testing.expectEqual(@as(usize, 4), pkt.key_material.len);
}

test "PublicKeyPacket parse Elgamal v4 key" {
    const allocator = std.testing.allocator;

    // Elgamal: 3 MPIs (p, g, y) — each 8 bits
    var body: [15]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], 2000, .big);
    body[5] = 16; // Elgamal
    var offset: usize = 6;
    for (0..3) |i| {
        mem.writeInt(u16, body[offset..][0..2], 8, .big);
        offset += 2;
        body[offset] = @intCast(0xB0 + i);
        offset += 1;
    }

    const pkt = try PublicKeyPacket.parse(allocator, body[0..offset], false);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(PublicKeyAlgorithm.elgamal, pkt.algorithm);
    try std.testing.expectEqual(@as(usize, 3), pkt.key_material.len);
}

test "PublicKeyPacket parse ECC stores remaining as raw" {
    const allocator = std.testing.allocator;

    // EdDSA (22): remaining bytes stored as single raw MPI
    var body: [12]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], 3000, .big);
    body[5] = 22; // EdDSA
    // OID + point data (opaque)
    body[6] = 0x09;
    body[7] = 0x2B;
    body[8] = 0x06;
    body[9] = 0x01;
    body[10] = 0x04;
    body[11] = 0x01;

    const pkt = try PublicKeyPacket.parse(allocator, &body, false);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(PublicKeyAlgorithm.eddsa, pkt.algorithm);
    try std.testing.expectEqual(@as(usize, 1), pkt.key_material.len);
    try std.testing.expectEqual(@as(usize, 6), pkt.key_material[0].data.len);
}

test "PublicKeyPacket subkey flag" {
    const allocator = std.testing.allocator;

    // Minimal RSA key
    var body: [16]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], 100, .big);
    body[5] = 1;
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xFF;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;

    const pkt = try PublicKeyPacket.parse(allocator, body[0..12], true);
    defer pkt.deinit(allocator);

    try std.testing.expect(pkt.is_subkey);
}

test "PublicKeyPacket serialize RSA round-trip" {
    const allocator = std.testing.allocator;

    var body: [16]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], 0x5F000000, .big);
    body[5] = 1;
    mem.writeInt(u16, body[6..8], 16, .big);
    body[8] = 0x80;
    body[9] = 0x01;
    mem.writeInt(u16, body[10..12], 17, .big);
    body[12] = 0x01;
    body[13] = 0x00;
    body[14] = 0x01;

    const pkt = try PublicKeyPacket.parse(allocator, body[0..15], false);
    defer pkt.deinit(allocator);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);

    try std.testing.expectEqualSlices(u8, body[0..15], serialized);
}

test "PublicKeyPacket body too short" {
    const allocator = std.testing.allocator;
    const body = [_]u8{ 4, 0, 0 };
    try std.testing.expectError(error.InvalidPacket, PublicKeyPacket.parse(allocator, &body, false));
}

test "PublicKeyPacket unsupported version" {
    const allocator = std.testing.allocator;
    var body: [6]u8 = undefined;
    body[0] = 3; // v3
    mem.writeInt(u32, body[1..5], 0, .big);
    body[5] = 1;
    try std.testing.expectError(error.UnsupportedVersion, PublicKeyPacket.parse(allocator, &body, false));
}
