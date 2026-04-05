// SPDX-License-Identifier: MIT
//! OpenPGP V6 Public-Key Packet (Tag 6) and Public-Subkey Packet (Tag 14)
//! per RFC 9580 Section 5.5.2.
//!
//! V6 key packet layout:
//!   1 octet  -- version (6)
//!   4 octets -- creation time (big-endian)
//!   1 octet  -- public-key algorithm
//!   4 octets -- key material length (big-endian) -- NEW in V6
//!   N octets -- algorithm-specific key material
//!
//! V6 fingerprint = SHA-256 of: 0x9B + 4-byte body length (big-endian) + body
//! V6 key ID = first 8 bytes of fingerprint

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Mpi = @import("../types/mpi.zig").Mpi;
const PublicKeyAlgorithm = @import("../types/enums.zig").PublicKeyAlgorithm;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// RFC 9580 Section 5.5.2 -- V6 Public-Key Packet.
pub const V6PublicKeyPacket = struct {
    version: u8,
    creation_time: u32,
    algorithm: PublicKeyAlgorithm,
    /// Key material length in bytes (new in V6).
    key_material_length: u32,
    /// Algorithm-specific key material stored as raw MPIs.
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
            .ecdsa, .eddsa, .ecdh => null,
            // RFC 9580 native key types use raw bytes, not MPIs
            .x25519, .x448, .ed25519, .ed448 => null,
            _ => null,
        };
    }

    /// Parse a V6 Public-Key Packet from the raw body bytes.
    pub fn parse(allocator: Allocator, body: []const u8, is_subkey: bool) !V6PublicKeyPacket {
        // Minimum: version(1) + creation_time(4) + algorithm(1) + key_material_length(4) = 10
        if (body.len < 10) return error.InvalidPacket;

        const version = body[0];
        if (version != 6) return error.UnsupportedVersion;

        const creation_time = mem.readInt(u32, body[1..5], .big);
        const algorithm: PublicKeyAlgorithm = @enumFromInt(body[5]);
        const key_material_length = mem.readInt(u32, body[6..10], .big);

        // Validate that we have enough data
        if (body.len < 10 + key_material_length) return error.InvalidPacket;

        var offset: usize = 10;
        const key_material_end = 10 + key_material_length;

        // Parse MPIs from key material
        const count_opt = mpiCount(algorithm);

        var mpis: std.ArrayList(Mpi) = .empty;
        errdefer {
            for (mpis.items) |m| m.deinit(allocator);
            mpis.deinit(allocator);
        }

        if (count_opt) |count| {
            for (0..count) |_| {
                if (offset >= key_material_end) break;
                var fbs = std.io.fixedBufferStream(body[offset..key_material_end]);
                const mpi_item = Mpi.readFrom(allocator, fbs.reader()) catch return error.InvalidPacket;
                try mpis.append(allocator, mpi_item);
                offset += mpi_item.wireLen();
            }
        } else {
            // ECC or native key types: read remaining key material as MPIs
            while (offset < key_material_end) {
                var fbs = std.io.fixedBufferStream(body[offset..key_material_end]);
                const mpi_item = Mpi.readFrom(allocator, fbs.reader()) catch break;
                try mpis.append(allocator, mpi_item);
                offset += mpi_item.wireLen();
            }
        }

        // Store raw body for fingerprint calculation
        const raw_body = try allocator.dupe(u8, body);

        return .{
            .version = version,
            .creation_time = creation_time,
            .algorithm = algorithm,
            .key_material_length = key_material_length,
            .key_material = try mpis.toOwnedSlice(allocator),
            .is_subkey = is_subkey,
            .raw_body = raw_body,
        };
    }

    /// Serialize the V6 public key packet body.
    pub fn serialize(self: V6PublicKeyPacket, allocator: Allocator) ![]u8 {
        // If we have the raw body, just return a copy
        if (self.raw_body.len > 0) {
            return try allocator.dupe(u8, self.raw_body);
        }

        // Otherwise, build from fields
        // Calculate key material size
        var key_mat_size: usize = 0;
        for (self.key_material) |mpi_item| {
            key_mat_size += mpi_item.wireLen();
        }

        const total_len = 1 + 4 + 1 + 4 + key_mat_size;
        const buf = try allocator.alloc(u8, total_len);
        errdefer allocator.free(buf);

        buf[0] = 6; // version
        mem.writeInt(u32, buf[1..5], self.creation_time, .big);
        buf[5] = @intFromEnum(self.algorithm);
        mem.writeInt(u32, buf[6..10], @intCast(key_mat_size), .big);

        var offset: usize = 10;
        for (self.key_material) |mpi_item| {
            mem.writeInt(u16, buf[offset..][0..2], mpi_item.bit_count, .big);
            offset += 2;
            @memcpy(buf[offset..][0..mpi_item.byteLen()], mpi_item.data);
            offset += mpi_item.byteLen();
        }

        return buf;
    }

    /// V6 fingerprint = SHA-256 of: 0x9B + 4-byte body length (big-endian) + body
    pub fn fingerprint(self: V6PublicKeyPacket) [32]u8 {
        var hasher = Sha256.init(.{});

        // 0x9B is the "virtual" packet header byte for V6 key fingerprinting
        hasher.update(&[_]u8{0x9B});

        // 4-byte body length
        var len_buf: [4]u8 = undefined;
        mem.writeInt(u32, &len_buf, @intCast(self.raw_body.len), .big);
        hasher.update(&len_buf);

        // Body
        hasher.update(self.raw_body);

        return hasher.finalResult();
    }

    /// V6 key ID = first 8 bytes of the SHA-256 fingerprint.
    pub fn keyId(self: V6PublicKeyPacket) [8]u8 {
        const fp = self.fingerprint();
        return fp[0..8].*;
    }

    /// Free all allocator-owned memory.
    pub fn deinit(self: V6PublicKeyPacket, allocator: Allocator) void {
        for (self.key_material) |mpi_item| {
            mpi_item.deinit(allocator);
        }
        allocator.free(self.key_material);
        allocator.free(self.raw_body);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "V6PublicKeyPacket parse RSA" {
    const allocator = std.testing.allocator;

    // Build a minimal V6 RSA public key packet body
    var body: [200]u8 = undefined;
    body[0] = 6; // version
    mem.writeInt(u32, body[1..5], 0x65000000, .big); // creation time
    body[5] = @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign);

    // Key material: two MPIs (n=8 bits, e=8 bits) = 2 + 1 + 2 + 1 = 6 bytes
    mem.writeInt(u32, body[6..10], 6, .big); // key material length
    // MPI 1: n = 0xFF (8 bits)
    mem.writeInt(u16, body[10..12], 8, .big);
    body[12] = 0xFF;
    // MPI 2: e = 0x11 (5 bits)
    mem.writeInt(u16, body[13..15], 5, .big);
    body[15] = 0x11;

    const pkt = try V6PublicKeyPacket.parse(allocator, body[0..16], false);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 6), pkt.version);
    try std.testing.expectEqual(@as(u32, 0x65000000), pkt.creation_time);
    try std.testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, pkt.algorithm);
    try std.testing.expectEqual(@as(u32, 6), pkt.key_material_length);
    try std.testing.expectEqual(@as(usize, 2), pkt.key_material.len);
    try std.testing.expect(!pkt.is_subkey);
}

test "V6PublicKeyPacket parse as subkey" {
    const allocator = std.testing.allocator;

    var body: [200]u8 = undefined;
    body[0] = 6;
    mem.writeInt(u32, body[1..5], 1000, .big);
    body[5] = @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign);
    mem.writeInt(u32, body[6..10], 6, .big);
    mem.writeInt(u16, body[10..12], 8, .big);
    body[12] = 0xFF;
    mem.writeInt(u16, body[13..15], 8, .big);
    body[15] = 0x03;

    const pkt = try V6PublicKeyPacket.parse(allocator, body[0..16], true);
    defer pkt.deinit(allocator);

    try std.testing.expect(pkt.is_subkey);
}

test "V6PublicKeyPacket wrong version" {
    const allocator = std.testing.allocator;

    var body: [16]u8 = undefined;
    body[0] = 4; // wrong version
    @memset(body[1..], 0);

    try std.testing.expectError(error.UnsupportedVersion, V6PublicKeyPacket.parse(allocator, &body, false));
}

test "V6PublicKeyPacket body too short" {
    const allocator = std.testing.allocator;

    const body = [_]u8{ 6, 0, 0 };
    try std.testing.expectError(error.InvalidPacket, V6PublicKeyPacket.parse(allocator, &body, false));
}

test "V6PublicKeyPacket fingerprint is SHA-256" {
    const allocator = std.testing.allocator;

    var body: [200]u8 = undefined;
    body[0] = 6;
    mem.writeInt(u32, body[1..5], 12345, .big);
    body[5] = @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign);
    mem.writeInt(u32, body[6..10], 6, .big);
    mem.writeInt(u16, body[10..12], 8, .big);
    body[12] = 0xFF;
    mem.writeInt(u16, body[13..15], 8, .big);
    body[15] = 0x03;

    const pkt = try V6PublicKeyPacket.parse(allocator, body[0..16], false);
    defer pkt.deinit(allocator);

    const fp = pkt.fingerprint();

    // Fingerprint should be 32 bytes (SHA-256)
    try std.testing.expectEqual(@as(usize, 32), fp.len);

    // Verify manually: SHA-256(0x9B || 00 00 00 10 || body[0..16])
    var hasher = Sha256.init(.{});
    hasher.update(&[_]u8{0x9B});
    var len_buf: [4]u8 = undefined;
    mem.writeInt(u32, &len_buf, 16, .big);
    hasher.update(&len_buf);
    hasher.update(body[0..16]);
    const expected = hasher.finalResult();

    try std.testing.expectEqualSlices(u8, &expected, &fp);
}

test "V6PublicKeyPacket keyId is first 8 bytes of fingerprint" {
    const allocator = std.testing.allocator;

    var body: [200]u8 = undefined;
    body[0] = 6;
    mem.writeInt(u32, body[1..5], 12345, .big);
    body[5] = @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign);
    mem.writeInt(u32, body[6..10], 6, .big);
    mem.writeInt(u16, body[10..12], 8, .big);
    body[12] = 0xFF;
    mem.writeInt(u16, body[13..15], 8, .big);
    body[15] = 0x03;

    const pkt = try V6PublicKeyPacket.parse(allocator, body[0..16], false);
    defer pkt.deinit(allocator);

    const fp = pkt.fingerprint();
    const kid = pkt.keyId();

    try std.testing.expectEqualSlices(u8, fp[0..8], &kid);
}

test "V6PublicKeyPacket serialize round-trip" {
    const allocator = std.testing.allocator;

    var body: [200]u8 = undefined;
    body[0] = 6;
    mem.writeInt(u32, body[1..5], 42, .big);
    body[5] = @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign);
    mem.writeInt(u32, body[6..10], 6, .big);
    mem.writeInt(u16, body[10..12], 8, .big);
    body[12] = 0xFF;
    mem.writeInt(u16, body[13..15], 5, .big);
    body[15] = 0x11;

    const pkt = try V6PublicKeyPacket.parse(allocator, body[0..16], false);
    defer pkt.deinit(allocator);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);

    try std.testing.expectEqualSlices(u8, body[0..16], serialized);
}

test "V6PublicKeyPacket data is a copy" {
    const allocator = std.testing.allocator;

    var body: [200]u8 = undefined;
    body[0] = 6;
    mem.writeInt(u32, body[1..5], 99, .big);
    body[5] = @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign);
    mem.writeInt(u32, body[6..10], 6, .big);
    mem.writeInt(u16, body[10..12], 8, .big);
    body[12] = 0xFF;
    mem.writeInt(u16, body[13..15], 8, .big);
    body[15] = 0x03;

    const pkt = try V6PublicKeyPacket.parse(allocator, body[0..16], false);
    defer pkt.deinit(allocator);

    // Mutate original body
    body[0] = 0xFF;

    // Parsed packet should still have version 6
    try std.testing.expectEqual(@as(u8, 6), pkt.version);
    try std.testing.expectEqual(@as(u8, 6), pkt.raw_body[0]);
}
