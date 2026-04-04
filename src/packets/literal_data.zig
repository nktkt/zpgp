// SPDX-License-Identifier: MIT
//! OpenPGP Literal Data Packet (Tag 11) per RFC 4880 Section 5.9.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Data format byte.
pub const DataFormat = enum(u8) {
    /// Binary data ('b')
    binary = 'b',
    /// Text data ('t') — line endings are canonical <CR><LF>
    text = 't',
    /// UTF-8 text data ('u')
    utf8 = 'u',
    /// Unknown / other format
    _,
};

/// RFC 4880 Section 5.9 — Literal Data Packet.
///
/// Layout:
///   1 octet  — data format
///   1 octet  — filename length (n)
///   n octets — filename
///   4 octets — timestamp (big-endian)
///   remaining — literal data
pub const LiteralDataPacket = struct {
    format: DataFormat,
    filename: []const u8,
    timestamp: u32,
    data: []const u8,

    /// Parse a Literal Data Packet from the raw body bytes.
    pub fn parse(allocator: Allocator, body: []const u8) !LiteralDataPacket {
        if (body.len < 6) return error.InvalidPacket;

        const format: DataFormat = @enumFromInt(body[0]);
        const filename_len: usize = body[1];

        // 1 (format) + 1 (filename_len) + filename_len + 4 (timestamp)
        const header_len = 2 + filename_len + 4;
        if (body.len < header_len) return error.InvalidPacket;

        const filename = try allocator.dupe(u8, body[2 .. 2 + filename_len]);
        errdefer allocator.free(filename);

        const ts_offset = 2 + filename_len;
        const timestamp = mem.readInt(u32, body[ts_offset..][0..4], .big);

        const data = try allocator.dupe(u8, body[header_len..]);

        return .{
            .format = format,
            .filename = filename,
            .timestamp = timestamp,
            .data = data,
        };
    }

    /// Serialize the packet body (without the packet header).
    pub fn serialize(self: LiteralDataPacket, allocator: Allocator) ![]u8 {
        const filename_len: u8 = @intCast(self.filename.len);
        const total_len = 1 + 1 + self.filename.len + 4 + self.data.len;
        const buf = try allocator.alloc(u8, total_len);
        errdefer allocator.free(buf);

        buf[0] = @intFromEnum(self.format);
        buf[1] = filename_len;
        @memcpy(buf[2 .. 2 + self.filename.len], self.filename);

        const ts_offset = 2 + self.filename.len;
        mem.writeInt(u32, buf[ts_offset..][0..4], self.timestamp, .big);
        @memcpy(buf[ts_offset + 4 ..], self.data);

        return buf;
    }

    /// Free all allocator-owned memory.
    pub fn deinit(self: LiteralDataPacket, allocator: Allocator) void {
        allocator.free(self.filename);
        allocator.free(self.data);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "LiteralDataPacket parse and serialize round-trip" {
    const allocator = std.testing.allocator;

    // Build a body: format='b', filename="hello.txt", timestamp=0x12345678, data="world"
    const filename = "hello.txt";
    const data = "world";
    const body_len = 1 + 1 + filename.len + 4 + data.len;
    var body: [body_len]u8 = undefined;
    body[0] = 'b';
    body[1] = @intCast(filename.len);
    @memcpy(body[2 .. 2 + filename.len], filename);
    mem.writeInt(u32, body[2 + filename.len ..][0..4], 0x12345678, .big);
    @memcpy(body[2 + filename.len + 4 ..], data);

    const pkt = try LiteralDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(DataFormat.binary, pkt.format);
    try std.testing.expectEqualStrings("hello.txt", pkt.filename);
    try std.testing.expectEqual(@as(u32, 0x12345678), pkt.timestamp);
    try std.testing.expectEqualStrings("world", pkt.data);

    // Round-trip
    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try std.testing.expectEqualSlices(u8, &body, serialized);
}

test "LiteralDataPacket empty filename and data" {
    const allocator = std.testing.allocator;

    // format='t', filename="", timestamp=0, data=""
    const body = [_]u8{ 't', 0, 0, 0, 0, 0 };
    const pkt = try LiteralDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(DataFormat.text, pkt.format);
    try std.testing.expectEqual(@as(usize, 0), pkt.filename.len);
    try std.testing.expectEqual(@as(u32, 0), pkt.timestamp);
    try std.testing.expectEqual(@as(usize, 0), pkt.data.len);
}

test "LiteralDataPacket body too short" {
    const allocator = std.testing.allocator;
    const body = [_]u8{ 'b', 5 }; // claims 5-byte filename but body is too short
    try std.testing.expectError(error.InvalidPacket, LiteralDataPacket.parse(allocator, &body));
}

test "LiteralDataPacket utf8 format" {
    const allocator = std.testing.allocator;
    const body = [_]u8{ 'u', 0, 0, 0, 0, 0 };
    const pkt = try LiteralDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);
    try std.testing.expectEqual(DataFormat.utf8, pkt.format);
}
