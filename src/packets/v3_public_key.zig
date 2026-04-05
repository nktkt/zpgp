// SPDX-License-Identifier: MIT
//! OpenPGP V3 Public-Key Packet per RFC 4880 Section 5.5.2.
//!
//! V3 public key packets differ from V4:
//!   1 octet  -- version (3)
//!   4 octets -- creation time (big-endian)
//!   2 octets -- validity period in days (0 = no expiry)
//!   1 octet  -- public-key algorithm
//!   algorithm-specific MPI data
//!
//! V3 keys only support RSA (algorithms 1, 2, 3).  The fingerprint is
//! the MD5 hash of the key material (n || e), and the key ID is the low
//! 64 bits of n.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Mpi = @import("../types/mpi.zig").Mpi;
const PublicKeyAlgorithm = @import("../types/enums.zig").PublicKeyAlgorithm;

/// RFC 4880 Section 5.5.2 -- V3 Public-Key Packet.
pub const V3PublicKeyPacket = struct {
    creation_time: u32,
    validity_days: u16,
    algorithm: PublicKeyAlgorithm,
    /// Algorithm-specific key material stored as raw MPIs.
    /// For RSA: n, e.
    key_material: []Mpi,
    /// Raw bytes of the key packet body (for reference/hashing).
    raw_body: []const u8,

    /// Return the number of MPIs expected for a given V3 algorithm.
    /// V3 only supports RSA, so we always expect 2 MPIs (n, e).
    fn mpiCount(algo: PublicKeyAlgorithm) !usize {
        return switch (algo) {
            .rsa_encrypt_sign, .rsa_encrypt_only, .rsa_sign_only => 2,
            else => error.UnsupportedAlgorithm,
        };
    }

    /// Parse a V3 Public-Key Packet from the raw body bytes.
    ///
    /// Expected layout:
    ///   [0]     version = 3
    ///   [1..5]  creation time (4 bytes, big-endian)
    ///   [5..7]  validity period in days (2 bytes, big-endian)
    ///   [7]     public-key algorithm
    ///   [8..]   algorithm-specific MPI data
    pub fn parse(allocator: Allocator, body: []const u8) !V3PublicKeyPacket {
        // Minimum: version(1) + creation_time(4) + validity_days(2) + algo(1) = 8
        if (body.len < 8) return error.InvalidPacket;

        const version = body[0];
        if (version != 3) return error.UnsupportedVersion;

        const creation_time = mem.readInt(u32, body[1..5], .big);
        const validity_days = mem.readInt(u16, body[5..7], .big);
        const algorithm: PublicKeyAlgorithm = @enumFromInt(body[7]);

        const count = mpiCount(algorithm) catch return error.UnsupportedAlgorithm;

        var offset: usize = 8;
        var mpis: std.ArrayList(Mpi) = .empty;
        errdefer {
            for (mpis.items) |m| m.deinit(allocator);
            mpis.deinit(allocator);
        }

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

        const raw_body = try allocator.dupe(u8, body);

        return .{
            .creation_time = creation_time,
            .validity_days = validity_days,
            .algorithm = algorithm,
            .key_material = try mpis.toOwnedSlice(allocator),
            .raw_body = raw_body,
        };
    }

    /// Free all allocator-owned memory.
    pub fn deinit(self: @This(), allocator: Allocator) void {
        for (self.key_material) |m| m.deinit(allocator);
        allocator.free(self.key_material);
        allocator.free(self.raw_body);
    }

    /// Compute the V3 fingerprint.
    ///
    /// V3 fingerprint = MD5(n_bytes || e_bytes), where n and e are the raw
    /// MPI data bytes (without the 2-byte bit-count headers).
    ///
    /// Returns a 16-byte MD5 digest.
    pub fn fingerprint(self: @This()) [16]u8 {
        // V3 fingerprint only applies to RSA keys (n, e).
        if (self.key_material.len < 2) {
            return [_]u8{0} ** 16;
        }

        const n_data = self.key_material[0].data;
        const e_data = self.key_material[1].data;

        var hasher = std.crypto.hash.Md5.init(.{});
        hasher.update(n_data);
        hasher.update(e_data);
        var result: [16]u8 = undefined;
        hasher.final(&result);
        return result;
    }

    /// Compute the V3 key ID.
    ///
    /// V3 key ID = low 64 bits of the RSA modulus n.
    /// If n is shorter than 8 bytes, the result is zero-padded on the left.
    pub fn keyId(self: @This()) [8]u8 {
        if (self.key_material.len < 1) {
            return [_]u8{0} ** 8;
        }

        const n_data = self.key_material[0].data;
        var result: [8]u8 = [_]u8{0} ** 8;

        if (n_data.len >= 8) {
            @memcpy(&result, n_data[n_data.len - 8 ..]);
        } else if (n_data.len > 0) {
            // Zero-pad on the left
            const pad = 8 - n_data.len;
            @memcpy(result[pad..], n_data);
        }

        return result;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "V3PublicKeyPacket parse RSA key" {
    const allocator = std.testing.allocator;

    // Build a V3 RSA key body:
    //   version=3, creation_time=0x5F000000, validity_days=365, algo=1 (RSA)
    //   MPI n: bit_count=16, data=0x80,0x01 (2 bytes)
    //   MPI e: bit_count=17, data=0x01,0x00,0x01 (3 bytes)
    var body: [17]u8 = undefined;
    body[0] = 3; // version
    mem.writeInt(u32, body[1..5], 0x5F000000, .big);
    mem.writeInt(u16, body[5..7], 365, .big); // validity days
    body[7] = 1; // RSA encrypt+sign
    // MPI n: 16 bits = 2 bytes
    mem.writeInt(u16, body[8..10], 16, .big);
    body[10] = 0x80;
    body[11] = 0x01;
    // MPI e: 17 bits = 3 bytes
    mem.writeInt(u16, body[12..14], 17, .big);
    body[14] = 0x01;
    body[15] = 0x00;
    body[16] = 0x01;

    const pkt = try V3PublicKeyPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(u32, 0x5F000000), pkt.creation_time);
    try std.testing.expectEqual(@as(u16, 365), pkt.validity_days);
    try std.testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, pkt.algorithm);
    try std.testing.expectEqual(@as(usize, 2), pkt.key_material.len);
    try std.testing.expectEqual(@as(u16, 16), pkt.key_material[0].bit_count);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x80, 0x01 }, pkt.key_material[0].data);
    try std.testing.expectEqual(@as(u16, 17), pkt.key_material[1].bit_count);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00, 0x01 }, pkt.key_material[1].data);
    try std.testing.expectEqualSlices(u8, &body, pkt.raw_body);
}

test "V3PublicKeyPacket zero validity means no expiry" {
    const allocator = std.testing.allocator;

    var body: [17]u8 = undefined;
    body[0] = 3;
    mem.writeInt(u32, body[1..5], 1000, .big);
    mem.writeInt(u16, body[5..7], 0, .big); // no expiry
    body[7] = 1; // RSA
    mem.writeInt(u16, body[8..10], 16, .big);
    body[10] = 0x80;
    body[11] = 0x01;
    mem.writeInt(u16, body[12..14], 17, .big);
    body[14] = 0x01;
    body[15] = 0x00;
    body[16] = 0x01;

    const pkt = try V3PublicKeyPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 0), pkt.validity_days);
}

test "V3PublicKeyPacket fingerprint (MD5 of n||e)" {
    const allocator = std.testing.allocator;

    var body: [17]u8 = undefined;
    body[0] = 3;
    mem.writeInt(u32, body[1..5], 0, .big);
    mem.writeInt(u16, body[5..7], 0, .big);
    body[7] = 1;
    // n = 0x80, 0x01
    mem.writeInt(u16, body[8..10], 16, .big);
    body[10] = 0x80;
    body[11] = 0x01;
    // e = 0x01, 0x00, 0x01
    mem.writeInt(u16, body[12..14], 17, .big);
    body[14] = 0x01;
    body[15] = 0x00;
    body[16] = 0x01;

    const pkt = try V3PublicKeyPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    const fp = pkt.fingerprint();

    // Verify it matches MD5(n_bytes || e_bytes) = MD5(0x80,0x01,0x01,0x00,0x01)
    var expected_md5: [16]u8 = undefined;
    var hasher = std.crypto.hash.Md5.init(.{});
    hasher.update(&[_]u8{ 0x80, 0x01 }); // n
    hasher.update(&[_]u8{ 0x01, 0x00, 0x01 }); // e
    hasher.final(&expected_md5);

    try std.testing.expectEqualSlices(u8, &expected_md5, &fp);
}

test "V3PublicKeyPacket keyId (low 64 bits of n)" {
    const allocator = std.testing.allocator;

    // Build a key where n has enough bytes to extract the low 64 bits.
    // n = 10 bytes: 0x01, 0x02, ..., 0x0A
    // header(8) + n_hdr(2) + n_data(10) + e_hdr(2) + e_data(1) = 23 bytes
    var body: [23]u8 = undefined;
    body[0] = 3;
    mem.writeInt(u32, body[1..5], 0, .big);
    mem.writeInt(u16, body[5..7], 0, .big);
    body[7] = 1;
    // n: 73 bits = 10 bytes
    mem.writeInt(u16, body[8..10], 73, .big);
    for (0..10) |i| {
        body[10 + i] = @intCast(i + 1);
    }
    // e: 8 bits = 1 byte
    mem.writeInt(u16, body[20..22], 8, .big);
    body[22] = 0x03;

    const pkt = try V3PublicKeyPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    const kid = pkt.keyId();
    // n = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]
    // low 64 bits = last 8 bytes = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A }, &kid);
}

test "V3PublicKeyPacket keyId short n (< 8 bytes)" {
    const allocator = std.testing.allocator;

    // n is only 3 bytes: result should be zero-padded on left
    var body: [16]u8 = undefined;
    body[0] = 3;
    mem.writeInt(u32, body[1..5], 0, .big);
    mem.writeInt(u16, body[5..7], 0, .big);
    body[7] = 1;
    // n: 24 bits = 3 bytes
    mem.writeInt(u16, body[8..10], 24, .big);
    body[10] = 0xAA;
    body[11] = 0xBB;
    body[12] = 0xCC;
    // e: 8 bits = 1 byte
    mem.writeInt(u16, body[13..15], 8, .big);
    body[15] = 0x03;

    const pkt = try V3PublicKeyPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    const kid = pkt.keyId();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC }, &kid);
}

test "V3PublicKeyPacket body too short" {
    const allocator = std.testing.allocator;
    const body = [_]u8{ 3, 0, 0, 0, 0, 0, 0 }; // only 7 bytes, need 8
    try std.testing.expectError(error.InvalidPacket, V3PublicKeyPacket.parse(allocator, &body));
}

test "V3PublicKeyPacket wrong version" {
    const allocator = std.testing.allocator;
    var body: [17]u8 = undefined;
    body[0] = 4; // v4, not v3
    @memset(body[1..], 0);
    try std.testing.expectError(error.UnsupportedVersion, V3PublicKeyPacket.parse(allocator, &body));
}

test "V3PublicKeyPacket unsupported algorithm (DSA)" {
    const allocator = std.testing.allocator;
    var body: [8]u8 = undefined;
    body[0] = 3;
    mem.writeInt(u32, body[1..5], 0, .big);
    mem.writeInt(u16, body[5..7], 0, .big);
    body[7] = 17; // DSA -- not valid for V3
    try std.testing.expectError(error.UnsupportedAlgorithm, V3PublicKeyPacket.parse(allocator, &body));
}

test "V3PublicKeyPacket truncated MPI" {
    const allocator = std.testing.allocator;

    // First MPI says 16 bits but no data follows
    var body: [10]u8 = undefined;
    body[0] = 3;
    mem.writeInt(u32, body[1..5], 0, .big);
    mem.writeInt(u16, body[5..7], 0, .big);
    body[7] = 1; // RSA
    mem.writeInt(u16, body[8..10], 16, .big);
    // No data follows

    try std.testing.expectError(error.InvalidPacket, V3PublicKeyPacket.parse(allocator, &body));
}
