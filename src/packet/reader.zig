const std = @import("std");
const PacketTag = @import("tags.zig").PacketTag;
const hdr = @import("header.zig");
const PacketHeader = hdr.PacketHeader;
const BodyLength = hdr.BodyLength;
const Format = hdr.Format;

/// A streaming PGP packet reader that wraps any underlying reader type.
///
/// Reads packet headers one at a time and provides a bounded reader for
/// each packet body. Handles new-format partial body length chunks
/// transparently.
pub fn PacketReader(comptime ReaderType: type) type {
    return struct {
        const Self = @This();

        /// Error type combining the underlying reader errors with PGP-specific errors.
        pub const Error = ReaderType.Error || ReaderType.NoEofError || error{InvalidPacketTag};

        /// Reader type exposed to callers for reading packet body data.
        pub const Reader = std.io.GenericReader(*Self, ReaderType.Error, read);

        inner: ReaderType,
        /// Current packet header (null if no packet is active).
        current_header: ?PacketHeader = null,
        /// Remaining bytes in the current (chunk of) body.
        remaining: u32 = 0,
        /// True if we have reached the end of the current packet body
        /// (no more partial chunks).
        body_done: bool = true,

        /// Create a PacketReader wrapping the given underlying reader.
        pub fn init(underlying: ReaderType) Self {
            return .{ .inner = underlying };
        }

        /// Read the next packet header. Returns `null` on end-of-stream
        /// (no more packets). Automatically skips any unread bytes in the
        /// current packet body before reading the next header.
        pub fn next(self: *Self) Error!?PacketHeader {
            // Skip remaining body data of the previous packet.
            try self.skipRemainingBody();

            // Read the first byte to check for end-of-stream.
            const first_byte = self.inner.readByte() catch |err| switch (err) {
                error.EndOfStream => return null,
                else => |e| return e,
            };

            // Validate the packet bit.
            if (first_byte & 0x80 == 0) {
                return error.InvalidPacketTag;
            }

            var header: PacketHeader = undefined;

            if (first_byte & 0x40 != 0) {
                // New format
                const tag_val: u8 = first_byte & 0x3F;
                header.tag = @enumFromInt(tag_val);
                header.format = .new;
                header.body_length = try readNewFormatLength(self.inner);
            } else {
                // Old format
                const tag_val: u8 = (first_byte >> 2) & 0x0F;
                header.tag = @enumFromInt(tag_val);
                header.format = .old;
                const length_type: u2 = @truncate(first_byte & 0x03);
                header.body_length = switch (length_type) {
                    0 => BodyLength{ .fixed = try self.inner.readByte() },
                    1 => BodyLength{ .fixed = try self.inner.readInt(u16, .big) },
                    2 => BodyLength{ .fixed = try self.inner.readInt(u32, .big) },
                    3 => BodyLength{ .indeterminate = {} },
                };
            }

            self.current_header = header;

            switch (header.body_length) {
                .fixed => |len| {
                    self.remaining = len;
                    self.body_done = true; // No partial chunks to follow.
                },
                .partial => |len| {
                    self.remaining = len;
                    self.body_done = false; // More chunks expected.
                },
                .indeterminate => {
                    // Read until underlying stream ends.
                    self.remaining = std.math.maxInt(u32);
                    self.body_done = true;
                },
            }

            return header;
        }

        /// Get a reader for the current packet body. The reader is bounded
        /// to the packet's body length and handles partial body chunks
        /// transparently.
        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }

        /// Read body bytes. This is the underlying implementation for the
        /// GenericReader interface.
        fn read(self: *Self, dest: []u8) ReaderType.Error!usize {
            if (dest.len == 0) return 0;

            // If current chunk is exhausted, try to get the next partial chunk.
            if (self.remaining == 0) {
                if (self.body_done) return 0; // End of packet body.
                // Read next chunk length (new-format partial body).
                const body_len = readNewFormatLength(self.inner) catch return 0;
                switch (body_len) {
                    .fixed => |len| {
                        self.remaining = len;
                        self.body_done = true; // This is the final chunk.
                    },
                    .partial => |len| {
                        self.remaining = len;
                        self.body_done = false; // More chunks follow.
                    },
                    .indeterminate => {
                        self.remaining = 0;
                        self.body_done = true;
                        return 0;
                    },
                }
            }

            const to_read = @min(dest.len, self.remaining);
            const n = try self.inner.readAll(dest[0..to_read]);
            self.remaining -= @as(u32, @intCast(n));
            return n;
        }

        /// Skip all remaining body bytes of the current packet (including
        /// any partial body chunks).
        fn skipRemainingBody(self: *Self) (ReaderType.Error || error{EndOfStream})!void {
            while (true) {
                // Skip remaining bytes in current chunk.
                while (self.remaining > 0) {
                    var skip_buf: [4096]u8 = undefined;
                    const to_skip = @min(skip_buf.len, self.remaining);
                    const n = try self.inner.readAll(skip_buf[0..to_skip]);
                    if (n == 0) {
                        // End of underlying stream.
                        self.remaining = 0;
                        self.body_done = true;
                        return;
                    }
                    self.remaining -= @as(u32, @intCast(n));
                }

                if (self.body_done) break;

                // Read next partial chunk header.
                const body_len = readNewFormatLength(self.inner) catch {
                    self.body_done = true;
                    return;
                };
                switch (body_len) {
                    .fixed => |len| {
                        self.remaining = len;
                        self.body_done = true;
                    },
                    .partial => |len| {
                        self.remaining = len;
                        self.body_done = false;
                    },
                    .indeterminate => {
                        self.remaining = 0;
                        self.body_done = true;
                    },
                }
            }
        }
    };
}

/// Decode a new-format body length. Separated to be reusable from
/// both header parsing and partial body reading.
fn readNewFormatLength(rdr: anytype) @TypeOf(rdr).NoEofError!BodyLength {
    const first = try rdr.readByte();

    if (first < 192) {
        return .{ .fixed = first };
    } else if (first < 224) {
        const second = try rdr.readByte();
        const len: u32 = (@as(u32, first) - 192) * 256 + @as(u32, second) + 192;
        return .{ .fixed = len };
    } else if (first == 255) {
        return .{ .fixed = try rdr.readInt(u32, .big) };
    } else {
        const power: u5 = @truncate(first & 0x1F);
        return .{ .partial = @as(u32, 1) << power };
    }
}

/// Helper: create a `PacketReader` from any underlying reader value.
pub fn packetReader(underlying: anytype) PacketReader(@TypeOf(underlying)) {
    return PacketReader(@TypeOf(underlying)).init(underlying);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "PacketReader - read a single fixed-length packet" {
    // Build a packet: new format, tag = literal_data (11), length = 5, body = "Hello"
    var buf: [64]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();

    // Header: 0xC0 | 11 = 0xCB, length 5
    try w.writeByte(0xCB);
    try w.writeByte(5);
    // Body
    try w.writeAll("Hello");

    const written = wfbs.getWritten();
    var rfbs = std.io.fixedBufferStream(written);
    var pr = packetReader(rfbs.reader());

    // Read header
    const pkt = (try pr.next()) orelse return error.EndOfStream;
    try std.testing.expectEqual(PacketTag.literal_data, pkt.tag);
    try std.testing.expectEqual(Format.new, pkt.format);
    try std.testing.expectEqual(BodyLength{ .fixed = 5 }, pkt.body_length);

    // Read body
    var body: [16]u8 = undefined;
    const rdr = pr.reader();
    const n = try rdr.readAll(&body);
    try std.testing.expectEqual(@as(usize, 5), n);
    try std.testing.expectEqualStrings("Hello", body[0..n]);

    // Next packet should be null (end of stream)
    try std.testing.expectEqual(@as(?PacketHeader, null), try pr.next());
}

test "PacketReader - read two consecutive packets" {
    var buf: [128]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();

    // Packet 1: tag = user_id (13), body = "Alice"
    try w.writeByte(0xC0 | 13); // 0xCD
    try w.writeByte(5);
    try w.writeAll("Alice");

    // Packet 2: tag = signature (2), body = 3 bytes
    try w.writeByte(0xC0 | 2); // 0xC2
    try w.writeByte(3);
    try w.writeAll(&[_]u8{ 0xAA, 0xBB, 0xCC });

    const written = wfbs.getWritten();
    var rfbs = std.io.fixedBufferStream(written);
    var pr = packetReader(rfbs.reader());

    // First packet
    const pkt1 = (try pr.next()).?;
    try std.testing.expectEqual(PacketTag.user_id, pkt1.tag);
    var body1: [16]u8 = undefined;
    const n1 = try pr.reader().readAll(&body1);
    try std.testing.expectEqualStrings("Alice", body1[0..n1]);

    // Second packet
    const pkt2 = (try pr.next()).?;
    try std.testing.expectEqual(PacketTag.signature, pkt2.tag);
    var body2: [16]u8 = undefined;
    const n2 = try pr.reader().readAll(&body2);
    try std.testing.expectEqual(@as(usize, 3), n2);
    try std.testing.expectEqual(@as(u8, 0xAA), body2[0]);
    try std.testing.expectEqual(@as(u8, 0xBB), body2[1]);
    try std.testing.expectEqual(@as(u8, 0xCC), body2[2]);

    // No more packets
    try std.testing.expectEqual(@as(?PacketHeader, null), try pr.next());
}

test "PacketReader - skip unread body before next packet" {
    var buf: [128]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();

    // Packet 1: tag = literal_data, body = 10 bytes (we will NOT read them)
    try w.writeByte(0xCB);
    try w.writeByte(10);
    try w.writeAll("0123456789");

    // Packet 2: tag = user_id, body = "Bob"
    try w.writeByte(0xCD);
    try w.writeByte(3);
    try w.writeAll("Bob");

    const written = wfbs.getWritten();
    var rfbs = std.io.fixedBufferStream(written);
    var pr = packetReader(rfbs.reader());

    // Read first header but skip body
    const pkt1 = (try pr.next()).?;
    try std.testing.expectEqual(PacketTag.literal_data, pkt1.tag);

    // Read second header (should auto-skip packet 1's body)
    const pkt2 = (try pr.next()).?;
    try std.testing.expectEqual(PacketTag.user_id, pkt2.tag);
    var body: [16]u8 = undefined;
    const n = try pr.reader().readAll(&body);
    try std.testing.expectEqualStrings("Bob", body[0..n]);
}

test "PacketReader - partial body length chunks" {
    var buf: [128]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();

    // New format packet: tag = symmetrically_encrypted_data (9)
    try w.writeByte(0xC0 | 9); // 0xC9

    // Partial body chunk 1: 2^1 = 2 bytes (0xE1)
    try w.writeByte(0xE1);
    try w.writeAll("AB");

    // Partial body chunk 2: 2^2 = 4 bytes (0xE2)
    try w.writeByte(0xE2);
    try w.writeAll("CDEF");

    // Final chunk: fixed length 3
    try w.writeByte(3);
    try w.writeAll("GHI");

    const written = wfbs.getWritten();
    var rfbs = std.io.fixedBufferStream(written);
    var pr = packetReader(rfbs.reader());

    const pkt = (try pr.next()).?;
    try std.testing.expectEqual(PacketTag.symmetrically_encrypted_data, pkt.tag);
    try std.testing.expectEqual(BodyLength{ .partial = 2 }, pkt.body_length);

    // Read all body data across chunks
    var body: [32]u8 = undefined;
    const rdr = pr.reader();
    const n = try rdr.readAll(&body);
    try std.testing.expectEqual(@as(usize, 9), n);
    try std.testing.expectEqualStrings("ABCDEFGHI", body[0..n]);
}

test "PacketReader - old format packet" {
    var buf: [64]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();

    // Old format: tag = public_key (6), 1-byte length = 4
    // Header byte: 0x80 | (6 << 2) | 0 = 0x98
    try w.writeByte(0x98);
    try w.writeByte(4);
    try w.writeAll(&[_]u8{ 0x04, 0x01, 0x02, 0x03 });

    const written = wfbs.getWritten();
    var rfbs = std.io.fixedBufferStream(written);
    var pr = packetReader(rfbs.reader());

    const pkt = (try pr.next()).?;
    try std.testing.expectEqual(PacketTag.public_key, pkt.tag);
    try std.testing.expectEqual(Format.old, pkt.format);
    try std.testing.expectEqual(BodyLength{ .fixed = 4 }, pkt.body_length);

    var body: [16]u8 = undefined;
    const n = try pr.reader().readAll(&body);
    try std.testing.expectEqual(@as(usize, 4), n);
    try std.testing.expectEqual(@as(u8, 0x04), body[0]);
}
