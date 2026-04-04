// SPDX-License-Identifier: MIT
//! OpenPGP User ID Packet (Tag 13) per RFC 4880 Section 5.11.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// RFC 4880 Section 5.11 — User ID Packet.
///
/// The body is simply a UTF-8 string, conventionally in the form
/// "Name (Comment) <email@example.com>".
pub const UserIdPacket = struct {
    id: []const u8,

    /// Parse a User ID Packet from the raw body bytes.
    pub fn parse(allocator: Allocator, body: []const u8) !UserIdPacket {
        return .{
            .id = try allocator.dupe(u8, body),
        };
    }

    /// Serialize the packet body (without the packet header).
    pub fn serialize(self: UserIdPacket, allocator: Allocator) ![]u8 {
        return try allocator.dupe(u8, self.id);
    }

    /// Free all allocator-owned memory.
    pub fn deinit(self: UserIdPacket, allocator: Allocator) void {
        allocator.free(self.id);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "UserIdPacket parse and serialize round-trip" {
    const allocator = std.testing.allocator;
    const body = "Alice <alice@example.com>";

    const pkt = try UserIdPacket.parse(allocator, body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqualStrings("Alice <alice@example.com>", pkt.id);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try std.testing.expectEqualStrings(body, serialized);
}

test "UserIdPacket empty body" {
    const allocator = std.testing.allocator;

    const pkt = try UserIdPacket.parse(allocator, "");
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), pkt.id.len);
}

test "UserIdPacket full RFC format" {
    const allocator = std.testing.allocator;
    const body = "Bob (Security) <bob@pgp.example.org>";

    const pkt = try UserIdPacket.parse(allocator, body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqualStrings(body, pkt.id);
}
