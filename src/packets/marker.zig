// SPDX-License-Identifier: MIT
//! OpenPGP Marker Packet (Tag 10) per RFC 4880 Section 5.8.

const std = @import("std");

/// RFC 4880 Section 5.8 — Marker Packet.
///
/// The body of a Marker Packet is the three octets 0x50, 0x47, 0x50
/// (ASCII "PGP"). It is used for legacy compatibility and MUST be
/// ignored when received.
pub const MarkerPacket = struct {
    /// Parse a Marker Packet from the raw body bytes.
    /// Returns error if the body is not exactly "PGP".
    pub fn parse(body: []const u8) !MarkerPacket {
        if (body.len != 3) return error.InvalidPacket;
        if (!std.mem.eql(u8, body, "PGP")) return error.InvalidPacket;
        return .{};
    }

    /// Serialize the packet body — always the three bytes "PGP".
    pub fn serialize() [3]u8 {
        return .{ 'P', 'G', 'P' };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "MarkerPacket parse valid" {
    const pkt = try MarkerPacket.parse("PGP");
    _ = pkt;
}

test "MarkerPacket serialize" {
    const body = MarkerPacket.serialize();
    try std.testing.expectEqualStrings("PGP", &body);
}

test "MarkerPacket parse invalid content" {
    try std.testing.expectError(error.InvalidPacket, MarkerPacket.parse("XYZ"));
}

test "MarkerPacket parse wrong length" {
    try std.testing.expectError(error.InvalidPacket, MarkerPacket.parse("PG"));
    try std.testing.expectError(error.InvalidPacket, MarkerPacket.parse("PGPX"));
    try std.testing.expectError(error.InvalidPacket, MarkerPacket.parse(""));
}

test "MarkerPacket round-trip" {
    const body = MarkerPacket.serialize();
    const pkt = try MarkerPacket.parse(&body);
    _ = pkt;
    const body2 = MarkerPacket.serialize();
    try std.testing.expectEqualSlices(u8, &body, &body2);
}
