// SPDX-License-Identifier: MIT
//! OpenPGP V3 Signature Packet per RFC 4880 Section 5.2.2.
//!
//! V3 signatures have a simpler format than V4:
//!   1 octet  -- version (3)
//!   1 octet  -- hashed material length (always 5)
//!   1 octet  -- signature type
//!   4 octets -- creation time (big-endian)
//!   8 octets -- key ID of signer
//!   1 octet  -- public-key algorithm
//!   1 octet  -- hash algorithm
//!   2 octets -- hash prefix (left 16 bits of signed hash value)
//!   MPI(s)   -- signature value(s)

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Mpi = @import("../types/mpi.zig").Mpi;
const PublicKeyAlgorithm = @import("../types/enums.zig").PublicKeyAlgorithm;
const HashAlgorithm = @import("../types/enums.zig").HashAlgorithm;

/// RFC 4880 Section 5.2.2 -- V3 Signature Packet.
pub const V3SignaturePacket = struct {
    sig_type: u8,
    creation_time: u32,
    key_id: [8]u8,
    pub_algo: PublicKeyAlgorithm,
    hash_algo: HashAlgorithm,
    hash_prefix: [2]u8,
    signature_mpis: []Mpi,

    /// Return the expected number of signature MPIs for a given algorithm.
    fn sigMpiCount(algo: PublicKeyAlgorithm) usize {
        return switch (algo) {
            .rsa_encrypt_sign, .rsa_encrypt_only, .rsa_sign_only => 1,
            .dsa, .ecdsa, .eddsa => 2,
            else => 1,
        };
    }

    /// Parse a V3 Signature Packet from the raw body bytes (after the
    /// packet header has been stripped).
    ///
    /// Expected layout:
    ///   [0]     version = 3
    ///   [1]     hashed material length = 5
    ///   [2]     signature type
    ///   [3..7]  creation time (4 bytes, big-endian)
    ///   [7..15] key ID (8 bytes)
    ///   [15]    public-key algorithm
    ///   [16]    hash algorithm
    ///   [17..19] hash prefix (2 bytes)
    ///   [19..]  signature MPI(s)
    pub fn parse(allocator: Allocator, body: []const u8) !V3SignaturePacket {
        // Minimum size: version(1) + hashed_len(1) + sig_type(1) +
        //   creation_time(4) + key_id(8) + pub_algo(1) + hash_algo(1) +
        //   hash_prefix(2) = 19, plus at least 2 bytes for one MPI header.
        if (body.len < 19) return error.InvalidPacket;

        const version = body[0];
        if (version != 3) return error.UnsupportedVersion;

        const hashed_len = body[1];
        if (hashed_len != 5) return error.InvalidPacket;

        const sig_type = body[2];
        const creation_time = mem.readInt(u32, body[3..7], .big);

        var key_id: [8]u8 = undefined;
        @memcpy(&key_id, body[7..15]);

        const pub_algo: PublicKeyAlgorithm = @enumFromInt(body[15]);
        const hash_algo: HashAlgorithm = @enumFromInt(body[16]);

        const hash_prefix: [2]u8 = body[17..19].*;

        // Parse signature MPIs
        var offset: usize = 19;
        const mpi_count = sigMpiCount(pub_algo);

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
            .sig_type = sig_type,
            .creation_time = creation_time,
            .key_id = key_id,
            .pub_algo = pub_algo,
            .hash_algo = hash_algo,
            .hash_prefix = hash_prefix,
            .signature_mpis = try mpis.toOwnedSlice(allocator),
        };
    }

    /// Serialize the V3 signature packet body (without the packet header).
    ///
    /// Layout:
    ///   version(1) + hashed_len(1) + sig_type(1) + creation_time(4) +
    ///   key_id(8) + pub_algo(1) + hash_algo(1) + hash_prefix(2) + MPIs
    pub fn serialize(self: @This(), allocator: Allocator) ![]u8 {
        var total: usize = 19; // fixed header portion
        for (self.signature_mpis) |m| {
            total += m.wireLen();
        }

        const buf = try allocator.alloc(u8, total);
        errdefer allocator.free(buf);

        buf[0] = 3; // version
        buf[1] = 5; // hashed material length (always 5)
        buf[2] = self.sig_type;
        mem.writeInt(u32, buf[3..7], self.creation_time, .big);
        @memcpy(buf[7..15], &self.key_id);
        buf[15] = @intFromEnum(self.pub_algo);
        buf[16] = @intFromEnum(self.hash_algo);
        buf[17] = self.hash_prefix[0];
        buf[18] = self.hash_prefix[1];

        var offset: usize = 19;
        for (self.signature_mpis) |m| {
            mem.writeInt(u16, buf[offset..][0..2], m.bit_count, .big);
            offset += 2;
            if (m.data.len > 0) {
                @memcpy(buf[offset .. offset + m.data.len], m.data);
                offset += m.data.len;
            }
        }

        return buf;
    }

    /// Free all allocator-owned memory.
    pub fn deinit(self: @This(), allocator: Allocator) void {
        for (self.signature_mpis) |m| m.deinit(allocator);
        allocator.free(self.signature_mpis);
    }

    /// Build the hashed data for V3 signature verification.
    ///
    /// For V3 signatures, the hashed material is just 5 bytes:
    ///   sig_type(1) + creation_time(4)
    ///
    /// This is what gets appended to the document hash for verification.
    pub fn hashedMaterial(self: @This()) [5]u8 {
        var buf: [5]u8 = undefined;
        buf[0] = self.sig_type;
        mem.writeInt(u32, buf[1..5], self.creation_time, .big);
        return buf;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "V3SignaturePacket parse RSA signature" {
    const allocator = std.testing.allocator;

    // Build a V3 RSA signature body:
    //   version=3, hashed_len=5, sig_type=0x00 (binary doc)
    //   creation_time=0x5F000000
    //   key_id=0x0102030405060708
    //   pub_algo=1 (RSA), hash_algo=2 (SHA1)
    //   hash_prefix=0xAB,0xCD
    //   1 MPI for RSA signature: 16 bits = 2 bytes (0xDE, 0xAD)
    var body: [23]u8 = undefined;
    body[0] = 3; // version
    body[1] = 5; // hashed material length
    body[2] = 0x00; // sig_type: binary document
    mem.writeInt(u32, body[3..7], 0x5F000000, .big);
    // key ID
    body[7] = 0x01;
    body[8] = 0x02;
    body[9] = 0x03;
    body[10] = 0x04;
    body[11] = 0x05;
    body[12] = 0x06;
    body[13] = 0x07;
    body[14] = 0x08;
    body[15] = 1; // RSA
    body[16] = 2; // SHA1
    body[17] = 0xAB; // hash prefix
    body[18] = 0xCD;
    // RSA signature MPI: 16 bits = 2 bytes
    mem.writeInt(u16, body[19..21], 16, .big);
    body[21] = 0xDE;
    body[22] = 0xAD;

    const pkt = try V3SignaturePacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 0x00), pkt.sig_type);
    try std.testing.expectEqual(@as(u32, 0x5F000000), pkt.creation_time);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }, &pkt.key_id);
    try std.testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, pkt.pub_algo);
    try std.testing.expectEqual(HashAlgorithm.sha1, pkt.hash_algo);
    try std.testing.expectEqual([2]u8{ 0xAB, 0xCD }, pkt.hash_prefix);
    try std.testing.expectEqual(@as(usize, 1), pkt.signature_mpis.len);
    try std.testing.expectEqual(@as(u16, 16), pkt.signature_mpis[0].bit_count);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD }, pkt.signature_mpis[0].data);
}

test "V3SignaturePacket parse DSA signature (2 MPIs)" {
    const allocator = std.testing.allocator;

    // DSA signature with 2 MPIs
    var body: [27]u8 = undefined;
    body[0] = 3;
    body[1] = 5;
    body[2] = 0x13; // positive certification
    mem.writeInt(u32, body[3..7], 1000, .big);
    @memset(body[7..15], 0xAA); // key ID
    body[15] = 17; // DSA
    body[16] = 8; // SHA256
    body[17] = 0x11;
    body[18] = 0x22;
    // MPI r: 8 bits = 1 byte
    mem.writeInt(u16, body[19..21], 8, .big);
    body[21] = 0xAA;
    // MPI s: 16 bits = 2 bytes
    mem.writeInt(u16, body[22..24], 16, .big);
    body[24] = 0xBB;
    body[25] = 0xCC;

    const pkt = try V3SignaturePacket.parse(allocator, body[0..26]);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(PublicKeyAlgorithm.dsa, pkt.pub_algo);
    try std.testing.expectEqual(@as(usize, 2), pkt.signature_mpis.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{0xAA}, pkt.signature_mpis[0].data);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xBB, 0xCC }, pkt.signature_mpis[1].data);
}

test "V3SignaturePacket serialize round-trip" {
    const allocator = std.testing.allocator;

    var body: [23]u8 = undefined;
    body[0] = 3;
    body[1] = 5;
    body[2] = 0x01; // canonical text
    mem.writeInt(u32, body[3..7], 0x12345678, .big);
    @memcpy(body[7..15], &[_]u8{ 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87 });
    body[15] = 1; // RSA
    body[16] = 8; // SHA256
    body[17] = 0xEE;
    body[18] = 0xFF;
    mem.writeInt(u16, body[19..21], 8, .big);
    body[21] = 0x42;

    const pkt = try V3SignaturePacket.parse(allocator, body[0..22]);
    defer pkt.deinit(allocator);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);

    try std.testing.expectEqualSlices(u8, body[0..22], serialized);
}

test "V3SignaturePacket body too short" {
    const allocator = std.testing.allocator;
    // Only 18 bytes, need at least 19
    var body: [18]u8 = undefined;
    body[0] = 3;
    body[1] = 5;
    @memset(body[2..], 0);
    try std.testing.expectError(error.InvalidPacket, V3SignaturePacket.parse(allocator, &body));
}

test "V3SignaturePacket wrong version" {
    const allocator = std.testing.allocator;
    var body: [23]u8 = undefined;
    body[0] = 4; // v4, not v3
    body[1] = 5;
    @memset(body[2..], 0);
    try std.testing.expectError(error.UnsupportedVersion, V3SignaturePacket.parse(allocator, &body));
}

test "V3SignaturePacket invalid hashed length" {
    const allocator = std.testing.allocator;
    var body: [23]u8 = undefined;
    body[0] = 3;
    body[1] = 7; // should be 5
    @memset(body[2..], 0);
    try std.testing.expectError(error.InvalidPacket, V3SignaturePacket.parse(allocator, &body));
}

test "V3SignaturePacket hashedMaterial" {
    const allocator = std.testing.allocator;

    var body: [23]u8 = undefined;
    body[0] = 3;
    body[1] = 5;
    body[2] = 0x00; // binary document
    mem.writeInt(u32, body[3..7], 0xAABBCCDD, .big);
    @memset(body[7..15], 0x11);
    body[15] = 1;
    body[16] = 2;
    body[17] = 0xEE;
    body[18] = 0xFF;
    mem.writeInt(u16, body[19..21], 8, .big);
    body[21] = 0x42;

    const pkt = try V3SignaturePacket.parse(allocator, body[0..22]);
    defer pkt.deinit(allocator);

    const hashed = pkt.hashedMaterial();
    try std.testing.expectEqual(@as(u8, 0x00), hashed[0]);
    try std.testing.expectEqual(@as(u32, 0xAABBCCDD), mem.readInt(u32, hashed[1..5], .big));
}

test "V3SignaturePacket truncated MPI data" {
    const allocator = std.testing.allocator;

    // Header is valid but MPI claims 16 bits (2 bytes) but only 1 byte follows
    var body: [22]u8 = undefined;
    body[0] = 3;
    body[1] = 5;
    body[2] = 0x00;
    mem.writeInt(u32, body[3..7], 100, .big);
    @memset(body[7..15], 0);
    body[15] = 1; // RSA
    body[16] = 2; // SHA1
    body[17] = 0x00;
    body[18] = 0x00;
    // MPI header says 16 bits = 2 bytes, but only 1 byte of data follows
    mem.writeInt(u16, body[19..21], 16, .big);
    body[21] = 0xFF;
    // Total is 22 bytes, but MPI needs offset 21 + 2 bytes = 23 > 22

    try std.testing.expectError(error.InvalidPacket, V3SignaturePacket.parse(allocator, &body));
}

test "V3SignaturePacket large RSA MPI" {
    const allocator = std.testing.allocator;

    // Build a V3 signature with a larger MPI (128 bits = 16 bytes)
    const mpi_bytes = 16;
    const total_len = 19 + 2 + mpi_bytes; // header + MPI header + MPI data
    var body: [total_len]u8 = undefined;
    body[0] = 3;
    body[1] = 5;
    body[2] = 0x00;
    mem.writeInt(u32, body[3..7], 0xDEADBEEF, .big);
    @memset(body[7..15], 0x42);
    body[15] = 1; // RSA
    body[16] = 10; // SHA512
    body[17] = 0xCA;
    body[18] = 0xFE;
    mem.writeInt(u16, body[19..21], 128, .big);
    @memset(body[21 .. 21 + mpi_bytes], 0xAB);

    const pkt = try V3SignaturePacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 128), pkt.signature_mpis[0].bit_count);
    try std.testing.expectEqual(@as(usize, 16), pkt.signature_mpis[0].data.len);
    try std.testing.expectEqual(HashAlgorithm.sha512, pkt.hash_algo);
}
