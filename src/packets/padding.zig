// SPDX-License-Identifier: MIT
//! OpenPGP Padding Packet (Tag 21) per RFC 9580 Section 5.14.
//!
//! The padding packet contains random data and is used to obscure the
//! exact size of the plaintext within an encrypted message. Implementations
//! MUST ignore the contents of a padding packet.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// RFC 9580 Section 5.14 -- Padding Packet.
///
/// Body: random octets. The content is meaningless and MUST be ignored
/// by receiving implementations.
pub const PaddingPacket = struct {
    /// Random padding data.
    data: []const u8,

    /// Parse a Padding Packet from the raw body bytes.
    /// The entire body is treated as padding data.
    pub fn parse(allocator: Allocator, body: []const u8) !PaddingPacket {
        const data = try allocator.dupe(u8, body);
        return .{ .data = data };
    }

    /// Create a new Padding Packet with random data of the given size.
    pub fn create(allocator: Allocator, size: usize) !PaddingPacket {
        const data = try allocator.alloc(u8, size);
        std.crypto.random.bytes(data);
        return .{ .data = data };
    }

    /// Free all allocator-owned memory.
    pub fn deinit(self: PaddingPacket, allocator: Allocator) void {
        allocator.free(self.data);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "PaddingPacket parse" {
    const allocator = std.testing.allocator;

    const body = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const pkt = try PaddingPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 4), pkt.data.len);
    try std.testing.expectEqual(@as(u8, 0xDE), pkt.data[0]);
    try std.testing.expectEqual(@as(u8, 0xEF), pkt.data[3]);
}

test "PaddingPacket parse empty" {
    const allocator = std.testing.allocator;

    const pkt = try PaddingPacket.parse(allocator, &.{});
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), pkt.data.len);
}

test "PaddingPacket create" {
    const allocator = std.testing.allocator;

    const pkt = try PaddingPacket.create(allocator, 32);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 32), pkt.data.len);

    // Should not be all zeros (random data, extremely unlikely)
    var all_zero = true;
    for (pkt.data) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "PaddingPacket create zero size" {
    const allocator = std.testing.allocator;

    const pkt = try PaddingPacket.create(allocator, 0);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), pkt.data.len);
}

test "PaddingPacket data is a copy" {
    const allocator = std.testing.allocator;

    var body = [_]u8{ 0x42, 0x43 };
    const pkt = try PaddingPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    body[0] = 0xFF;
    try std.testing.expectEqual(@as(u8, 0x42), pkt.data[0]);
}

test "PaddingPacket two creates produce different data" {
    const allocator = std.testing.allocator;

    const pkt1 = try PaddingPacket.create(allocator, 16);
    defer pkt1.deinit(allocator);

    const pkt2 = try PaddingPacket.create(allocator, 16);
    defer pkt2.deinit(allocator);

    // Random data should differ (extremely unlikely to match)
    try std.testing.expect(!mem.eql(u8, pkt1.data, pkt2.data));
}
