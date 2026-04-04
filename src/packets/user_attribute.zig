// SPDX-License-Identifier: MIT
//! OpenPGP User Attribute Packet (Tag 17) per RFC 4880 Section 5.12.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// RFC 4880 Section 5.12 — User Attribute Packet.
///
/// The body contains one or more user attribute subpackets. This
/// implementation stores the raw subpacket data; individual subpacket
/// parsing (e.g. image attributes) can be layered on top.
pub const UserAttributePacket = struct {
    data: []const u8,

    /// Parse a User Attribute Packet from the raw body bytes.
    pub fn parse(allocator: Allocator, body: []const u8) !UserAttributePacket {
        return .{
            .data = try allocator.dupe(u8, body),
        };
    }

    /// Serialize the packet body (without the packet header).
    pub fn serialize(self: UserAttributePacket, allocator: Allocator) ![]u8 {
        return try allocator.dupe(u8, self.data);
    }

    /// Free all allocator-owned memory.
    pub fn deinit(self: UserAttributePacket, allocator: Allocator) void {
        allocator.free(self.data);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "UserAttributePacket parse and serialize round-trip" {
    const allocator = std.testing.allocator;
    const body = [_]u8{ 0x01, 0x02, 0x03, 0xFF, 0x00, 0xAB };

    const pkt = try UserAttributePacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqualSlices(u8, &body, pkt.data);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try std.testing.expectEqualSlices(u8, &body, serialized);
}

test "UserAttributePacket empty body" {
    const allocator = std.testing.allocator;

    const pkt = try UserAttributePacket.parse(allocator, "");
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), pkt.data.len);
}
