// SPDX-License-Identifier: MIT
//! OpenPGP Compressed Data Packet (Tag 8) per RFC 4880 Section 5.6.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const CompressionAlgorithm = @import("../types/enums.zig").CompressionAlgorithm;
const bzip2 = @import("../crypto/bzip2.zig");

/// RFC 4880 Section 5.6 — Compressed Data Packet.
///
/// Layout:
///   1 octet   — compression algorithm
///   remaining — compressed data
pub const CompressedDataPacket = struct {
    algorithm: CompressionAlgorithm,
    /// The raw compressed packet data (to be decompressed later).
    compressed_data: []const u8,

    /// Parse a Compressed Data Packet from the raw body bytes.
    pub fn parse(allocator: Allocator, body: []const u8) !CompressedDataPacket {
        // Minimum: algorithm(1)
        if (body.len < 1) return error.InvalidPacket;

        const algorithm: CompressionAlgorithm = @enumFromInt(body[0]);
        const compressed_data = try allocator.dupe(u8, body[1..]);

        return .{
            .algorithm = algorithm,
            .compressed_data = compressed_data,
        };
    }

    /// Free all allocator-owned memory.
    pub fn deinit(self: CompressedDataPacket, allocator: Allocator) void {
        allocator.free(self.compressed_data);
    }

    /// Decompress the packet data and return the raw inner packet bytes.
    pub fn decompress(self: CompressedDataPacket, allocator: Allocator) ![]u8 {
        return switch (self.algorithm) {
            .uncompressed => try allocator.dupe(u8, self.compressed_data),
            .zip => decompressDeflate(allocator, self.compressed_data, .raw),
            .zlib => decompressDeflate(allocator, self.compressed_data, .zlib),
            .bzip2 => bzip2.decompress(allocator, self.compressed_data) catch
                return error.DecompressionFailed,
            _ => error.UnsupportedAlgorithm,
        };
    }

    /// Decompress raw DEFLATE or ZLIB data using std.compress.flate.
    fn decompressDeflate(
        allocator: Allocator,
        data: []const u8,
        container: std.compress.flate.Container,
    ) ![]u8 {
        var reader: std.Io.Reader = .fixed(data);
        var decompress_buf: [std.compress.flate.max_window_len]u8 = undefined;
        var decompressor: std.compress.flate.Decompress = .init(&reader, container, &decompress_buf);

        // Stream all decompressed data into an ArrayList
        var result: std.ArrayList(u8) = .{};
        errdefer result.deinit(allocator);

        var buf: [4096]u8 = undefined;
        while (true) {
            const n = decompressor.reader.readSliceShort(&buf) catch |err| {
                if (decompressor.err) |_| {
                    return error.DecompressionFailed;
                }
                return err;
            };
            if (n == 0) break;
            try result.appendSlice(allocator, buf[0..n]);
        }

        return result.toOwnedSlice(allocator);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "CompressedDataPacket parse ZIP" {
    const allocator = std.testing.allocator;

    // algo=ZIP(1), compressed data = 5 bytes
    const body = [_]u8{ 1, 0x78, 0x9C, 0xAB, 0xCA, 0x00 };
    const pkt = try CompressedDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(CompressionAlgorithm.zip, pkt.algorithm);
    try std.testing.expectEqual(@as(usize, 5), pkt.compressed_data.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x78, 0x9C, 0xAB, 0xCA, 0x00 }, pkt.compressed_data);
}

test "CompressedDataPacket parse ZLIB" {
    const allocator = std.testing.allocator;

    const body = [_]u8{ 2, 0x01, 0x02, 0x03 };
    const pkt = try CompressedDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(CompressionAlgorithm.zlib, pkt.algorithm);
    try std.testing.expectEqual(@as(usize, 3), pkt.compressed_data.len);
}

test "CompressedDataPacket parse Uncompressed" {
    const allocator = std.testing.allocator;

    // Uncompressed: the "compressed" data is just raw packet data
    const body = [_]u8{ 0, 0xCB, 0x10, 'h', 'e', 'l', 'l', 'o' };
    const pkt = try CompressedDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(CompressionAlgorithm.uncompressed, pkt.algorithm);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xCB, 0x10, 'h', 'e', 'l', 'l', 'o' }, pkt.compressed_data);
}

test "CompressedDataPacket parse BZip2 with empty data" {
    const allocator = std.testing.allocator;

    // algo=BZip2(3), no compressed data
    const body = [_]u8{3};
    const pkt = try CompressedDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(CompressionAlgorithm.bzip2, pkt.algorithm);
    try std.testing.expectEqual(@as(usize, 0), pkt.compressed_data.len);
}

test "CompressedDataPacket body too short" {
    const allocator = std.testing.allocator;
    const body = [_]u8{};
    try std.testing.expectError(error.InvalidPacket, CompressedDataPacket.parse(allocator, &body));
}

test "CompressedDataPacket decompress uncompressed" {
    const allocator = std.testing.allocator;
    const body = [_]u8{ 0, 'h', 'e', 'l', 'l', 'o' };
    const pkt = try CompressedDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    const result = try pkt.decompress(allocator);
    defer allocator.free(result);

    try std.testing.expectEqualStrings("hello", result);
}

test "CompressedDataPacket decompress ZLIB" {
    const allocator = std.testing.allocator;
    // algo=ZLIB(2), followed by zlib-compressed "hello"
    const body = [_]u8{ 2, 0x78, 0x9C, 0xCB, 0x48, 0xCD, 0xC9, 0xC9, 0x07, 0x00, 0x06, 0x2C, 0x02, 0x15 };
    const pkt = try CompressedDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    const result = try pkt.decompress(allocator);
    defer allocator.free(result);

    try std.testing.expectEqualStrings("hello", result);
}

test "CompressedDataPacket decompress ZIP (raw deflate)" {
    const allocator = std.testing.allocator;
    // algo=ZIP(1), followed by raw deflate of "hello"
    const body = [_]u8{ 1, 0xCB, 0x48, 0xCD, 0xC9, 0xC9, 0x07, 0x00 };
    const pkt = try CompressedDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    const result = try pkt.decompress(allocator);
    defer allocator.free(result);

    try std.testing.expectEqualStrings("hello", result);
}
