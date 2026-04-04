// SPDX-License-Identifier: MIT
//! Multi-Precision Integer encoding per RFC 4880 Section 3.2.
//!
//! An MPI is encoded as a two-octet big-endian scalar giving the number of
//! bits in the MPI, followed by a string of octets that is the actual integer
//! value. The length in octets is `ceil(bit_count / 8)`.

const std = @import("std");

pub const Mpi = struct {
    /// Number of significant bits (as declared in the wire format).
    bit_count: u16,
    /// Raw big-endian integer data.  Length == `byteLen()`.
    data: []const u8,

    /// Number of bytes used to represent the integer value.
    pub fn byteLen(self: Mpi) usize {
        if (self.bit_count == 0) return 0;
        return ((@as(usize, self.bit_count) + 7) / 8);
    }

    /// Total wire length: 2 (bit count) + data bytes.
    pub fn wireLen(self: Mpi) usize {
        return 2 + self.byteLen();
    }

    /// Read an MPI from any `reader` that supports `readInt` and `readAtLeast`.
    /// Allocates data via `allocator`.  Caller must call `deinit` when done.
    pub fn readFrom(allocator: std.mem.Allocator, reader: anytype) !Mpi {
        const bit_count = try reader.readInt(u16, .big);
        const byte_len: usize = if (bit_count == 0) 0 else ((@as(usize, bit_count) + 7) / 8);

        if (byte_len == 0) {
            return Mpi{
                .bit_count = bit_count,
                .data = &.{},
            };
        }

        const buf = try allocator.alloc(u8, byte_len);
        errdefer allocator.free(buf);

        const n = try reader.readAtLeast(buf, byte_len);
        if (n < byte_len) {
            allocator.free(buf);
            return error.EndOfStream;
        }

        return Mpi{
            .bit_count = bit_count,
            .data = buf,
        };
    }

    /// Write the MPI to any `writer` that supports `writeInt` and `writeAll`.
    pub fn writeTo(self: Mpi, writer: anytype) !void {
        try writer.writeInt(u16, self.bit_count, .big);
        if (self.data.len > 0) {
            try writer.writeAll(self.data);
        }
    }

    /// Free the data buffer.  Safe to call on zero-length MPIs.
    pub fn deinit(self: Mpi, allocator: std.mem.Allocator) void {
        if (self.data.len > 0) {
            allocator.free(self.data);
        }
    }

    /// Create an Mpi from a raw big-endian byte slice without copying.
    /// The caller keeps ownership of the data (do not call deinit).
    pub fn fromBytes(data: []const u8) Mpi {
        if (data.len == 0) {
            return Mpi{ .bit_count = 0, .data = data };
        }

        // Compute bit count: (byte_len - 1) * 8 + significant bits in MSB.
        const msb = data[0];
        const sig_bits: u16 = if (msb == 0) 0 else (8 - @as(u16, @clz(msb)));
        const bit_count: u16 = @as(u16, @intCast(data.len - 1)) * 8 + sig_bits;

        return Mpi{ .bit_count = bit_count, .data = data };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Mpi byteLen calculation" {
    // 0 bits => 0 bytes
    try std.testing.expectEqual(@as(usize, 0), (Mpi{ .bit_count = 0, .data = &.{} }).byteLen());
    // 1 bit  => 1 byte
    try std.testing.expectEqual(@as(usize, 1), (Mpi{ .bit_count = 1, .data = &.{0} }).byteLen());
    // 8 bits => 1 byte
    try std.testing.expectEqual(@as(usize, 1), (Mpi{ .bit_count = 8, .data = &.{0} }).byteLen());
    // 9 bits => 2 bytes
    try std.testing.expectEqual(@as(usize, 2), (Mpi{ .bit_count = 9, .data = &.{ 0, 0 } }).byteLen());
    // 2048 bits => 256 bytes
    try std.testing.expectEqual(@as(usize, 256), (Mpi{ .bit_count = 2048, .data = &.{} }).byteLen());
}

test "Mpi round-trip encode/decode" {
    const allocator = std.testing.allocator;

    // Encode the integer 0x01FF (= 511, which needs 9 bits).
    const original_data = [_]u8{ 0x01, 0xFF };
    const original = Mpi{ .bit_count = 9, .data = &original_data };

    // Write to buffer.
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try original.writeTo(fbs.writer());

    // Check the wire bytes:  00 09  01 FF
    try std.testing.expectEqual(@as(usize, 4), fbs.pos);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x09, 0x01, 0xFF }, buf[0..4]);

    // Read it back.
    fbs.pos = 0;
    const decoded = try Mpi.readFrom(allocator, fbs.reader());
    defer decoded.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 9), decoded.bit_count);
    try std.testing.expectEqual(@as(usize, 2), decoded.byteLen());
    try std.testing.expectEqualSlices(u8, &original_data, decoded.data);
}

test "Mpi round-trip zero" {
    const allocator = std.testing.allocator;

    const original = Mpi{ .bit_count = 0, .data = &.{} };

    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try original.writeTo(fbs.writer());

    try std.testing.expectEqual(@as(usize, 2), fbs.pos);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00 }, buf[0..2]);

    fbs.pos = 0;
    const decoded = try Mpi.readFrom(allocator, fbs.reader());
    defer decoded.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 0), decoded.bit_count);
    try std.testing.expectEqual(@as(usize, 0), decoded.byteLen());
}

test "Mpi fromBytes" {
    // 0x80 = 128 = 1000_0000  => 8 bits, 1 byte
    const data1 = [_]u8{0x80};
    const m1 = Mpi.fromBytes(&data1);
    try std.testing.expectEqual(@as(u16, 8), m1.bit_count);
    try std.testing.expectEqual(@as(usize, 1), m1.byteLen());

    // 0x01 0xFF => leading byte 0x01 has 1 significant bit, total = 1 + 8 = 9 bits
    const data2 = [_]u8{ 0x01, 0xFF };
    const m2 = Mpi.fromBytes(&data2);
    try std.testing.expectEqual(@as(u16, 9), m2.bit_count);

    // Empty => 0 bits
    const m3 = Mpi.fromBytes(&.{});
    try std.testing.expectEqual(@as(u16, 0), m3.bit_count);
}

test "Mpi wireLen" {
    const m = Mpi{ .bit_count = 9, .data = &[_]u8{ 0x01, 0xFF } };
    try std.testing.expectEqual(@as(usize, 4), m.wireLen());

    const m0 = Mpi{ .bit_count = 0, .data = &.{} };
    try std.testing.expectEqual(@as(usize, 2), m0.wireLen());
}

test "Mpi round-trip large value" {
    const allocator = std.testing.allocator;

    // A 2048-bit RSA-like value (256 bytes, MSB = 0xC3 => 8 significant bits).
    var big_data: [256]u8 = undefined;
    @memset(&big_data, 0xAB);
    big_data[0] = 0xC3; // 1100_0011 => 8 significant bits in MSB

    const original = Mpi.fromBytes(&big_data);
    try std.testing.expectEqual(@as(u16, 2048), original.bit_count);

    var buf: [260]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try original.writeTo(fbs.writer());
    try std.testing.expectEqual(@as(usize, 258), fbs.pos); // 2 + 256

    fbs.pos = 0;
    const decoded = try Mpi.readFrom(allocator, fbs.reader());
    defer decoded.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 2048), decoded.bit_count);
    try std.testing.expectEqualSlices(u8, &big_data, decoded.data);
}
