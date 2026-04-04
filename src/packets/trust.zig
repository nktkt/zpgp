// SPDX-License-Identifier: MIT
//! OpenPGP Trust Packet (Tag 12) per RFC 4880 Section 5.10.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// RFC 4880 Section 5.10 — Trust Packet.
///
/// Trust packets are implementation-defined and used only within keyrings.
/// Their content is opaque to other implementations.
pub const TrustPacket = struct {
    data: []const u8,

    /// Parse a Trust Packet from the raw body bytes.
    pub fn parse(allocator: Allocator, body: []const u8) !TrustPacket {
        return .{
            .data = try allocator.dupe(u8, body),
        };
    }

    /// Serialize the packet body (without the packet header).
    pub fn serialize(self: TrustPacket, allocator: Allocator) ![]u8 {
        return try allocator.dupe(u8, self.data);
    }

    /// Free all allocator-owned memory.
    pub fn deinit(self: TrustPacket, allocator: Allocator) void {
        allocator.free(self.data);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "TrustPacket parse and serialize round-trip" {
    const allocator = std.testing.allocator;
    const body = [_]u8{ 0x05, 0x60 }; // GnuPG-style trust value

    const pkt = try TrustPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqualSlices(u8, &body, pkt.data);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try std.testing.expectEqualSlices(u8, &body, serialized);
}

test "TrustPacket empty body" {
    const allocator = std.testing.allocator;

    const pkt = try TrustPacket.parse(allocator, "");
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), pkt.data.len);
}

test "TrustPacket single byte" {
    const allocator = std.testing.allocator;
    const body = [_]u8{0xFF};

    const pkt = try TrustPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), pkt.data.len);
    try std.testing.expectEqual(@as(u8, 0xFF), pkt.data[0]);
}
