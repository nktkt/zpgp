// SPDX-License-Identifier: MIT
//! OpenPGP Modification Detection Code Packet (Tag 19) per RFC 4880 Section 5.14.

const std = @import("std");

/// RFC 4880 Section 5.14 — Modification Detection Code Packet.
///
/// The body is exactly 20 bytes — a SHA-1 hash of the preceding
/// plaintext within a Sym. Encrypted Integrity Protected Data Packet.
pub const ModDetectionCodePacket = struct {
    hash: [20]u8,

    /// Parse a Modification Detection Code Packet from the raw body bytes.
    pub fn parse(body: []const u8) !ModDetectionCodePacket {
        if (body.len != 20) return error.InvalidPacket;
        return .{
            .hash = body[0..20].*,
        };
    }

    /// Serialize the packet body — always exactly 20 bytes.
    pub fn serialize(self: ModDetectionCodePacket) [20]u8 {
        return self.hash;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ModDetectionCodePacket parse and serialize round-trip" {
    const body = [20]u8{
        0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55,
        0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90, 0xAF, 0xD8, 0x07, 0x09,
    };

    const pkt = try ModDetectionCodePacket.parse(&body);
    try std.testing.expectEqualSlices(u8, &body, &pkt.hash);

    const serialized = pkt.serialize();
    try std.testing.expectEqualSlices(u8, &body, &serialized);
}

test "ModDetectionCodePacket wrong body length" {
    const short = [_]u8{0} ** 19;
    try std.testing.expectError(error.InvalidPacket, ModDetectionCodePacket.parse(&short));

    const long = [_]u8{0} ** 21;
    try std.testing.expectError(error.InvalidPacket, ModDetectionCodePacket.parse(&long));

    try std.testing.expectError(error.InvalidPacket, ModDetectionCodePacket.parse(""));
}

test "ModDetectionCodePacket all zeros" {
    const body: [20]u8 = .{0} ** 20;
    const pkt = try ModDetectionCodePacket.parse(&body);
    const serialized = pkt.serialize();
    try std.testing.expectEqualSlices(u8, &body, &serialized);
}

test "ModDetectionCodePacket all ones" {
    const body: [20]u8 = .{0xFF} ** 20;
    const pkt = try ModDetectionCodePacket.parse(&body);
    try std.testing.expectEqual(@as(u8, 0xFF), pkt.hash[0]);
    try std.testing.expectEqual(@as(u8, 0xFF), pkt.hash[19]);
}
