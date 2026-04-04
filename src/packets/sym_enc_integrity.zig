// SPDX-License-Identifier: MIT
//! OpenPGP Sym. Encrypted Integrity Protected Data Packet (Tag 18)
//! per RFC 4880 Section 5.13.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// RFC 4880 Section 5.13 — Sym. Encrypted Integrity Protected Data Packet.
///
/// Layout:
///   1 octet   — version (1)
///   remaining — encrypted data (includes prefix, encrypted packets,
///               and the MDC packet)
pub const SymEncIntegrityPacket = struct {
    version: u8,
    /// Encrypted data blob. When decrypted, this contains:
    ///   - block_size+2 bytes of random prefix
    ///   - encrypted literal/compressed data packets
    ///   - a Modification Detection Code (MDC) packet (tag 19)
    data: []const u8,

    /// Parse a Sym. Encrypted Integrity Protected Data Packet from the raw body bytes.
    pub fn parse(allocator: Allocator, body: []const u8) !SymEncIntegrityPacket {
        // Minimum: version(1)
        if (body.len < 1) return error.InvalidPacket;

        const version = body[0];
        if (version != 1) return error.UnsupportedVersion;

        const data = try allocator.dupe(u8, body[1..]);

        return .{
            .version = version,
            .data = data,
        };
    }

    /// Free all allocator-owned memory.
    pub fn deinit(self: SymEncIntegrityPacket, allocator: Allocator) void {
        allocator.free(self.data);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "SymEncIntegrityPacket parse v1" {
    const allocator = std.testing.allocator;

    // version=1, some encrypted data
    var body: [17]u8 = undefined;
    body[0] = 1; // version
    @memset(body[1..], 0xAB);

    const pkt = try SymEncIntegrityPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 1), pkt.version);
    try std.testing.expectEqual(@as(usize, 16), pkt.data.len);
    for (pkt.data) |b| {
        try std.testing.expectEqual(@as(u8, 0xAB), b);
    }
}

test "SymEncIntegrityPacket parse with real-looking data" {
    const allocator = std.testing.allocator;

    // Simulate encrypted data: version + prefix + encrypted content + MDC
    var body: [40]u8 = undefined;
    body[0] = 1;
    // Fill with pseudo-random bytes
    for (body[1..], 0..) |*b, i| b.* = @truncate(i *% 37 +% 13);

    const pkt = try SymEncIntegrityPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 1), pkt.version);
    try std.testing.expectEqual(@as(usize, 39), pkt.data.len);
}

test "SymEncIntegrityPacket body too short" {
    const allocator = std.testing.allocator;
    const body = [_]u8{};
    try std.testing.expectError(error.InvalidPacket, SymEncIntegrityPacket.parse(allocator, &body));
}

test "SymEncIntegrityPacket unsupported version" {
    const allocator = std.testing.allocator;
    var body: [10]u8 = undefined;
    body[0] = 2; // wrong version
    @memset(body[1..], 0);
    try std.testing.expectError(error.UnsupportedVersion, SymEncIntegrityPacket.parse(allocator, &body));
}

test "SymEncIntegrityPacket version only (empty data)" {
    const allocator = std.testing.allocator;
    const body = [_]u8{1};
    const pkt = try SymEncIntegrityPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 1), pkt.version);
    try std.testing.expectEqual(@as(usize, 0), pkt.data.len);
}

test "SymEncIntegrityPacket data is a copy" {
    const allocator = std.testing.allocator;

    var body = [_]u8{ 1, 0xDE, 0xAD };
    const pkt = try SymEncIntegrityPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    body[1] = 0xFF;
    try std.testing.expectEqual(@as(u8, 0xDE), pkt.data[0]);
}
