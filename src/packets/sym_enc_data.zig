// SPDX-License-Identifier: MIT
//! OpenPGP Symmetrically Encrypted Data Packet (Tag 9)
//! per RFC 4880 Section 5.7.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// RFC 4880 Section 5.7 — Symmetrically Encrypted Data Packet.
///
/// Layout:
///   All bytes are encrypted data. The encrypted data is composed of
///   the output of the selected symmetric-key cipher operating in
///   OpenPGP's variant of Cipher Feedback (CFB) mode.
pub const SymEncDataPacket = struct {
    data: []const u8,

    /// Parse a Symmetrically Encrypted Data Packet from the raw body bytes.
    pub fn parse(allocator: Allocator, body: []const u8) !SymEncDataPacket {
        const data = try allocator.dupe(u8, body);
        return .{ .data = data };
    }

    /// Free all allocator-owned memory.
    pub fn deinit(self: SymEncDataPacket, allocator: Allocator) void {
        allocator.free(self.data);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "SymEncDataPacket parse" {
    const allocator = std.testing.allocator;

    const body = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const pkt = try SymEncDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 8), pkt.data.len);
    try std.testing.expectEqualSlices(u8, &body, pkt.data);
}

test "SymEncDataPacket parse empty" {
    const allocator = std.testing.allocator;

    const body = [_]u8{};
    const pkt = try SymEncDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), pkt.data.len);
}

test "SymEncDataPacket parse large data" {
    const allocator = std.testing.allocator;

    var body: [256]u8 = undefined;
    for (&body, 0..) |*b, i| b.* = @truncate(i);

    const pkt = try SymEncDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 256), pkt.data.len);
    try std.testing.expectEqualSlices(u8, &body, pkt.data);
}

test "SymEncDataPacket data is a copy" {
    const allocator = std.testing.allocator;

    var body = [_]u8{ 0xAA, 0xBB, 0xCC };
    const pkt = try SymEncDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    // Mutating source should not affect parsed data
    body[0] = 0xFF;
    try std.testing.expectEqual(@as(u8, 0xAA), pkt.data[0]);
}
