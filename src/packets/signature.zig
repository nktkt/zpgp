// SPDX-License-Identifier: MIT
//! OpenPGP Signature Packet (Tag 2) per RFC 4880 Section 5.2.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Mpi = @import("../types/mpi.zig").Mpi;
const PublicKeyAlgorithm = @import("../types/enums.zig").PublicKeyAlgorithm;
const HashAlgorithm = @import("../types/enums.zig").HashAlgorithm;

/// RFC 4880 Section 5.2 — Signature Packet (v4).
///
/// Layout (v4):
///   1 octet  — version (4)
///   1 octet  — signature type
///   1 octet  — public-key algorithm
///   1 octet  — hash algorithm
///   2 octets — hashed subpackets length (big-endian)
///   N octets — hashed subpackets data
///   2 octets — unhashed subpackets length (big-endian)
///   M octets — unhashed subpackets data
///   2 octets — hash prefix (left 16 bits of hash)
///   MPI(s)   — signature value(s)
pub const SignaturePacket = struct {
    version: u8,
    sig_type: u8,
    pub_algo: PublicKeyAlgorithm,
    hash_algo: HashAlgorithm,
    hashed_subpacket_data: []const u8,
    unhashed_subpacket_data: []const u8,
    hash_prefix: [2]u8,
    signature_mpis: []Mpi,

    /// Return the number of signature MPIs for a given algorithm.
    fn sigMpiCount(algo: PublicKeyAlgorithm) usize {
        return switch (algo) {
            .rsa_encrypt_sign, .rsa_encrypt_only, .rsa_sign_only => 1,
            .dsa, .ecdsa, .eddsa => 2,
            else => 1, // Fallback
        };
    }

    /// Parse a Signature Packet from the raw body bytes.
    pub fn parse(allocator: Allocator, body: []const u8) !SignaturePacket {
        // Minimum: version(1) + sig_type(1) + pub_algo(1) + hash_algo(1)
        //        + hashed_len(2) + unhashed_len(2) + hash_prefix(2) = 10
        if (body.len < 10) return error.InvalidPacket;

        const version = body[0];
        if (version != 4) return error.UnsupportedVersion;

        const sig_type = body[1];
        const pub_algo: PublicKeyAlgorithm = @enumFromInt(body[2]);
        const hash_algo: HashAlgorithm = @enumFromInt(body[3]);

        var offset: usize = 4;

        // Hashed subpackets
        if (offset + 2 > body.len) return error.InvalidPacket;
        const hashed_len: usize = mem.readInt(u16, body[offset..][0..2], .big);
        offset += 2;
        if (offset + hashed_len > body.len) return error.InvalidPacket;
        const hashed_subpacket_data = try allocator.dupe(u8, body[offset .. offset + hashed_len]);
        errdefer allocator.free(hashed_subpacket_data);
        offset += hashed_len;

        // Unhashed subpackets
        if (offset + 2 > body.len) return error.InvalidPacket;
        const unhashed_len: usize = mem.readInt(u16, body[offset..][0..2], .big);
        offset += 2;
        if (offset + unhashed_len > body.len) return error.InvalidPacket;
        const unhashed_subpacket_data = try allocator.dupe(u8, body[offset .. offset + unhashed_len]);
        errdefer allocator.free(unhashed_subpacket_data);
        offset += unhashed_len;

        // Hash prefix (2 bytes)
        if (offset + 2 > body.len) return error.InvalidPacket;
        const hash_prefix: [2]u8 = body[offset..][0..2].*;
        offset += 2;

        // Signature MPIs
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
            .version = version,
            .sig_type = sig_type,
            .pub_algo = pub_algo,
            .hash_algo = hash_algo,
            .hashed_subpacket_data = hashed_subpacket_data,
            .unhashed_subpacket_data = unhashed_subpacket_data,
            .hash_prefix = hash_prefix,
            .signature_mpis = try mpis.toOwnedSlice(allocator),
        };
    }

    /// Free all allocator-owned memory.
    pub fn deinit(self: SignaturePacket, allocator: Allocator) void {
        allocator.free(self.hashed_subpacket_data);
        allocator.free(self.unhashed_subpacket_data);
        for (self.signature_mpis) |m| m.deinit(allocator);
        allocator.free(self.signature_mpis);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "SignaturePacket parse v4 RSA signature" {
    const allocator = std.testing.allocator;

    // Build v4 RSA signature body:
    //   version=4, sig_type=0x00 (binary doc), pub_algo=1(RSA), hash_algo=8(SHA256)
    //   hashed subpackets: 3 bytes
    //   unhashed subpackets: 2 bytes
    //   hash_prefix: 0xAB, 0xCD
    //   1 MPI for RSA signature: 16 bits = 2 bytes
    var body: [20]u8 = undefined;
    body[0] = 4; // version
    body[1] = 0x00; // sig_type: binary document
    body[2] = 1; // RSA
    body[3] = 8; // SHA256
    // Hashed subpackets length = 3
    mem.writeInt(u16, body[4..6], 3, .big);
    body[6] = 0x01;
    body[7] = 0x02;
    body[8] = 0x03;
    // Unhashed subpackets length = 2
    mem.writeInt(u16, body[9..11], 2, .big);
    body[11] = 0x04;
    body[12] = 0x05;
    // Hash prefix
    body[13] = 0xAB;
    body[14] = 0xCD;
    // RSA signature MPI: 16 bits = 2 bytes
    mem.writeInt(u16, body[15..17], 16, .big);
    body[17] = 0xDE;
    body[18] = 0xAD;

    const pkt = try SignaturePacket.parse(allocator, body[0..19]);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 4), pkt.version);
    try std.testing.expectEqual(@as(u8, 0x00), pkt.sig_type);
    try std.testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, pkt.pub_algo);
    try std.testing.expectEqual(HashAlgorithm.sha256, pkt.hash_algo);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, pkt.hashed_subpacket_data);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x04, 0x05 }, pkt.unhashed_subpacket_data);
    try std.testing.expectEqual([2]u8{ 0xAB, 0xCD }, pkt.hash_prefix);
    try std.testing.expectEqual(@as(usize, 1), pkt.signature_mpis.len);
    try std.testing.expectEqual(@as(u16, 16), pkt.signature_mpis[0].bit_count);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD }, pkt.signature_mpis[0].data);
}

test "SignaturePacket parse v4 DSA signature (2 MPIs)" {
    const allocator = std.testing.allocator;

    // DSA: 2 MPIs (r, s)
    var body: [24]u8 = undefined;
    body[0] = 4;
    body[1] = 0x13; // sig_type: positive certification
    body[2] = 17; // DSA
    body[3] = 2; // SHA1
    // Empty hashed/unhashed subpackets
    mem.writeInt(u16, body[4..6], 0, .big);
    mem.writeInt(u16, body[6..8], 0, .big);
    // Hash prefix
    body[8] = 0x11;
    body[9] = 0x22;
    // MPI r: 8 bits = 1 byte
    mem.writeInt(u16, body[10..12], 8, .big);
    body[12] = 0xAA;
    // MPI s: 8 bits = 1 byte
    mem.writeInt(u16, body[13..15], 8, .big);
    body[15] = 0xBB;

    const pkt = try SignaturePacket.parse(allocator, body[0..16]);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(PublicKeyAlgorithm.dsa, pkt.pub_algo);
    try std.testing.expectEqual(@as(usize, 2), pkt.signature_mpis.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{0xAA}, pkt.signature_mpis[0].data);
    try std.testing.expectEqualSlices(u8, &[_]u8{0xBB}, pkt.signature_mpis[1].data);
}

test "SignaturePacket parse with subpacket data" {
    const allocator = std.testing.allocator;

    // Verify subpacket data is preserved correctly
    const hashed = [_]u8{ 0x05, 0x02, 0x5F, 0x00, 0x00, 0x00 }; // 6 bytes
    const unhashed = [_]u8{ 0x09, 0x10, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 }; // 10 bytes

    var body: [30]u8 = undefined;
    body[0] = 4;
    body[1] = 0x00;
    body[2] = 1; // RSA
    body[3] = 8; // SHA256
    mem.writeInt(u16, body[4..6], hashed.len, .big);
    @memcpy(body[6 .. 6 + hashed.len], &hashed);
    const uh_offset = 6 + hashed.len;
    mem.writeInt(u16, body[uh_offset..][0..2], unhashed.len, .big);
    @memcpy(body[uh_offset + 2 .. uh_offset + 2 + unhashed.len], &unhashed);
    const hp_offset = uh_offset + 2 + unhashed.len;
    body[hp_offset] = 0xEE;
    body[hp_offset + 1] = 0xFF;
    // RSA MPI
    mem.writeInt(u16, body[hp_offset + 2 ..][0..2], 8, .big);
    body[hp_offset + 4] = 0x42;

    const total = hp_offset + 5;
    const pkt = try SignaturePacket.parse(allocator, body[0..total]);
    defer pkt.deinit(allocator);

    try std.testing.expectEqualSlices(u8, &hashed, pkt.hashed_subpacket_data);
    try std.testing.expectEqualSlices(u8, &unhashed, pkt.unhashed_subpacket_data);
    try std.testing.expectEqual([2]u8{ 0xEE, 0xFF }, pkt.hash_prefix);
}

test "SignaturePacket body too short" {
    const allocator = std.testing.allocator;
    const body = [_]u8{ 4, 0, 1, 8, 0, 0, 0, 0, 0 }; // 9 bytes, minimum is 10
    try std.testing.expectError(error.InvalidPacket, SignaturePacket.parse(allocator, &body));
}

test "SignaturePacket unsupported version" {
    const allocator = std.testing.allocator;
    var body: [14]u8 = undefined;
    body[0] = 3; // v3
    @memset(body[1..], 0);
    try std.testing.expectError(error.UnsupportedVersion, SignaturePacket.parse(allocator, &body));
}

test "SignaturePacket empty subpackets" {
    const allocator = std.testing.allocator;

    // RSA sig with empty hashed/unhashed subpackets
    var body: [15]u8 = undefined;
    body[0] = 4;
    body[1] = 0x00;
    body[2] = 1;
    body[3] = 8;
    mem.writeInt(u16, body[4..6], 0, .big);
    mem.writeInt(u16, body[6..8], 0, .big);
    body[8] = 0x12;
    body[9] = 0x34;
    mem.writeInt(u16, body[10..12], 8, .big);
    body[12] = 0xFF;

    const pkt = try SignaturePacket.parse(allocator, body[0..13]);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), pkt.hashed_subpacket_data.len);
    try std.testing.expectEqual(@as(usize, 0), pkt.unhashed_subpacket_data.len);
}
