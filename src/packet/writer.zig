const std = @import("std");
const PacketTag = @import("tags.zig").PacketTag;
const header_mod = @import("header.zig");

/// A streaming PGP packet writer that wraps any underlying writer type.
///
/// Usage:
///   1. Call `startPacket(tag, length)` to write the packet header.
///   2. Use `writer()` to get a writer for the packet body.
///   3. Call `endPacket()` to finalize (flush any state).
///
/// If `length` is `null` in `startPacket`, partial body length encoding
/// is used (new format only), and body data is chunked automatically.
pub fn PacketWriter(comptime WriterType: type) type {
    return struct {
        const Self = @This();

        pub const Error = WriterType.Error;

        /// Writer type exposed to callers for writing packet body data.
        pub const Writer = std.io.GenericWriter(*Self, WriterType.Error, write);

        inner: WriterType,
        /// Whether we are currently inside a packet.
        in_packet: bool = false,
        /// If using partial body encoding, this tracks buffered body data.
        /// When null, the packet has a known length (header already written).
        partial_buf: ?[]u8 = null,
        partial_buf_pos: usize = 0,
        /// Power-of-2 chunk size for partial body encoding.
        partial_chunk_power: u5 = 9, // 2^9 = 512 bytes default chunk
        /// Internal buffer for partial body encoding.
        partial_storage: [512]u8 = undefined,

        /// Create a PacketWriter wrapping the given underlying writer.
        pub fn init(underlying: WriterType) Self {
            var self = Self{ .inner = underlying };
            self.partial_buf = &self.partial_storage;
            return self;
        }

        /// Start writing a new packet with the given tag.
        ///
        /// If `length` is provided, a definite-length header is written
        /// (new format). The caller must write exactly that many body bytes.
        ///
        /// If `length` is `null`, partial body length encoding is used.
        /// Body data is automatically chunked. Call `endPacket()` to write
        /// the final chunk.
        pub fn startPacket(self: *Self, tag: PacketTag, length: ?u32) Error!void {
            if (length) |len| {
                // Write a definite-length new-format header.
                try header_mod.writeHeader(self.inner, tag, len);
                self.in_packet = true;
                self.partial_buf = null;
                self.partial_buf_pos = 0;
            } else {
                // Write only the tag byte; lengths will be emitted per chunk.
                const tag_byte: u8 = 0xC0 | @intFromEnum(tag);
                try self.inner.writeByte(tag_byte);
                self.in_packet = true;
                self.partial_buf = &self.partial_storage;
                self.partial_buf_pos = 0;
            }
        }

        /// Get a writer for the current packet body.
        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        /// Finalize the current packet. For partial body encoding, this
        /// flushes remaining buffered data as a final (non-partial) chunk.
        pub fn endPacket(self: *Self) Error!void {
            if (self.partial_buf != null and self.partial_buf_pos > 0) {
                // Write final chunk with a definite (non-partial) length.
                try writeNewFormatLength(self.inner, @as(u32, @intCast(self.partial_buf_pos)));
                try self.inner.writeAll(self.partial_storage[0..self.partial_buf_pos]);
                self.partial_buf_pos = 0;
            } else if (self.partial_buf != null) {
                // Empty final chunk: write zero-length.
                try self.inner.writeByte(0);
            }
            self.in_packet = false;
            self.partial_buf = null;
        }

        /// Write body data. This is the underlying implementation for the
        /// GenericWriter interface.
        fn write(self: *Self, bytes: []const u8) Error!usize {
            if (!self.in_packet) return 0;
            if (bytes.len == 0) return 0;

            if (self.partial_buf == null) {
                // Definite-length mode: pass through directly.
                try self.inner.writeAll(bytes);
                return bytes.len;
            }

            // Partial body mode: buffer data and emit chunks.
            var written: usize = 0;
            var remaining = bytes;

            while (remaining.len > 0) {
                const chunk_size = self.partial_storage.len;
                const space = chunk_size - self.partial_buf_pos;
                const to_copy = @min(space, remaining.len);

                @memcpy(
                    self.partial_storage[self.partial_buf_pos..][0..to_copy],
                    remaining[0..to_copy],
                );
                self.partial_buf_pos += to_copy;
                remaining = remaining[to_copy..];
                written += to_copy;

                if (self.partial_buf_pos == chunk_size) {
                    // Emit a partial body length header and the chunk.
                    try self.emitPartialChunk();
                }
            }

            return written;
        }

        /// Emit the buffered data as a partial body chunk.
        fn emitPartialChunk(self: *Self) Error!void {
            const chunk_size = self.partial_storage.len;
            // Partial body length byte: 0xE0 | power
            const partial_byte: u8 = 0xE0 | @as(u8, self.partial_chunk_power);
            try self.inner.writeByte(partial_byte);
            try self.inner.writeAll(self.partial_storage[0..chunk_size]);
            self.partial_buf_pos = 0;
        }
    };
}

/// Encode a new-format body length and write it.
fn writeNewFormatLength(wtr: anytype, length: u32) @TypeOf(wtr).Error!void {
    if (length < 192) {
        try wtr.writeByte(@truncate(length));
    } else if (length < 8384) {
        const adjusted = length - 192;
        const first: u8 = @truncate(adjusted / 256 + 192);
        const second: u8 = @truncate(adjusted % 256);
        try wtr.writeByte(first);
        try wtr.writeByte(second);
    } else {
        try wtr.writeByte(0xFF);
        try wtr.writeInt(u32, length, .big);
    }
}

/// Helper: create a `PacketWriter` from any underlying writer value.
pub fn packetWriter(underlying: anytype) PacketWriter(@TypeOf(underlying)) {
    return PacketWriter(@TypeOf(underlying)).init(underlying);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "PacketWriter - definite length packet" {
    var buf: [128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    var pw = packetWriter(fbs.writer());

    try pw.startPacket(PacketTag.user_id, 5);
    const w = pw.writer();
    try w.writeAll("Alice");
    try pw.endPacket();

    const written = fbs.getWritten();
    // Header: 0xCD (0xC0 | 13), length 5, then "Alice"
    try std.testing.expectEqual(@as(u8, 0xCD), written[0]);
    try std.testing.expectEqual(@as(u8, 5), written[1]);
    try std.testing.expectEqualStrings("Alice", written[2..7]);
}

test "PacketWriter - definite length round-trip with PacketReader" {
    const packet_reader_mod = @import("reader.zig");

    var buf: [128]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    var pw = packetWriter(wfbs.writer());

    // Write a packet
    try pw.startPacket(PacketTag.literal_data, 11);
    try pw.writer().writeAll("Hello World");
    try pw.endPacket();

    // Read it back
    const written = wfbs.getWritten();
    var rfbs = std.io.fixedBufferStream(written);
    var pr = packet_reader_mod.packetReader(rfbs.reader());

    const pkt = (try pr.next()).?;
    try std.testing.expectEqual(PacketTag.literal_data, pkt.tag);
    try std.testing.expectEqual(@as(u32, 11), pkt.body_length.fixed);

    var body: [32]u8 = undefined;
    const n = try pr.reader().readAll(&body);
    try std.testing.expectEqualStrings("Hello World", body[0..n]);
}

test "PacketWriter - partial body encoding" {
    const packet_reader_mod = @import("reader.zig");

    var buf: [4096]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    var pw = packetWriter(wfbs.writer());

    // Write a packet using partial body encoding (null length)
    try pw.startPacket(PacketTag.symmetrically_encrypted_data, null);
    const w = pw.writer();

    // Write enough data to trigger at least one partial chunk (512 bytes)
    // plus some remainder.
    var test_data: [600]u8 = undefined;
    for (&test_data, 0..) |*b, i| {
        b.* = @truncate(i);
    }
    try w.writeAll(&test_data);
    try pw.endPacket();

    // Read it back using PacketReader
    const written = wfbs.getWritten();
    var rfbs = std.io.fixedBufferStream(written);
    var pr = packet_reader_mod.packetReader(rfbs.reader());

    const pkt = (try pr.next()).?;
    try std.testing.expectEqual(PacketTag.symmetrically_encrypted_data, pkt.tag);

    // Read all body data
    var read_buf: [1024]u8 = undefined;
    const n = try pr.reader().readAll(&read_buf);
    try std.testing.expectEqual(@as(usize, 600), n);
    try std.testing.expectEqualSlices(u8, &test_data, read_buf[0..n]);
}

test "PacketWriter - two packets sequentially" {
    const packet_reader_mod = @import("reader.zig");

    var buf: [256]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    var pw = packetWriter(wfbs.writer());

    // Packet 1
    try pw.startPacket(PacketTag.user_id, 3);
    try pw.writer().writeAll("Bob");
    try pw.endPacket();

    // Packet 2
    try pw.startPacket(PacketTag.signature, 2);
    try pw.writer().writeAll(&[_]u8{ 0xDE, 0xAD });
    try pw.endPacket();

    // Read back
    const written = wfbs.getWritten();
    var rfbs = std.io.fixedBufferStream(written);
    var pr = packet_reader_mod.packetReader(rfbs.reader());

    const pkt1 = (try pr.next()).?;
    try std.testing.expectEqual(PacketTag.user_id, pkt1.tag);
    var body1: [16]u8 = undefined;
    const n1 = try pr.reader().readAll(&body1);
    try std.testing.expectEqualStrings("Bob", body1[0..n1]);

    const pkt2 = (try pr.next()).?;
    try std.testing.expectEqual(PacketTag.signature, pkt2.tag);
    var body2: [16]u8 = undefined;
    const n2 = try pr.reader().readAll(&body2);
    try std.testing.expectEqual(@as(usize, 2), n2);
    try std.testing.expectEqual(@as(u8, 0xDE), body2[0]);
    try std.testing.expectEqual(@as(u8, 0xAD), body2[1]);

    try std.testing.expectEqual(@as(?@import("header.zig").PacketHeader, null), try pr.next());
}
