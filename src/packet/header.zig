const std = @import("std");
const PacketTag = @import("tags.zig").PacketTag;

/// Packet format: old (RFC 4880 Section 4.2.1) or new (Section 4.2.2).
pub const Format = enum { old, new };

/// Body length encoding for a packet.
pub const BodyLength = union(enum) {
    /// A definite body length in bytes.
    fixed: u32,
    /// Old-format indeterminate length (read until EOF).
    indeterminate: void,
    /// New-format partial body length: this chunk has the given size,
    /// and more chunks follow.
    partial: u32,
};

/// A parsed PGP packet header.
pub const PacketHeader = struct {
    tag: PacketTag,
    format: Format,
    body_length: BodyLength,
};

/// Errors that can occur during header parsing.
pub const HeaderError = error{
    /// The first byte does not have bit 7 set (not a valid PGP packet).
    InvalidPacketTag,
    /// End of stream reached while reading the header.
    EndOfStream,
};

/// Read a PGP packet header from `rdr`.
///
/// `rdr` must be a value whose type has `readByte() !u8` and
/// `readInt(comptime T, endian) !T` methods (e.g. the reader from
/// `std.io.fixedBufferStream` or any `GenericReader`).
pub fn readHeader(rdr: anytype) (@TypeOf(rdr).NoEofError || error{InvalidPacketTag})!PacketHeader {
    // First byte: bit 7 must be 1.
    const first_byte = try rdr.readByte();

    if (first_byte & 0x80 == 0) {
        return error.InvalidPacketTag;
    }

    if (first_byte & 0x40 != 0) {
        // --- New format (bit 6 = 1) ---
        const tag_val: u8 = first_byte & 0x3F;
        const tag: PacketTag = @enumFromInt(tag_val);
        const body_length = try readNewFormatLength(rdr);
        return .{
            .tag = tag,
            .format = .new,
            .body_length = body_length,
        };
    } else {
        // --- Old format (bit 6 = 0) ---
        const tag_val: u8 = (first_byte >> 2) & 0x0F;
        const tag: PacketTag = @enumFromInt(tag_val);
        const length_type: u2 = @truncate(first_byte & 0x03);
        const body_length: BodyLength = switch (length_type) {
            0 => .{ .fixed = try rdr.readByte() },
            1 => .{ .fixed = try rdr.readInt(u16, .big) },
            2 => .{ .fixed = try rdr.readInt(u32, .big) },
            3 => .{ .indeterminate = {} },
        };
        return .{
            .tag = tag,
            .format = .old,
            .body_length = body_length,
        };
    }
}

/// Decode a new-format body length from `rdr`.
fn readNewFormatLength(rdr: anytype) @TypeOf(rdr).NoEofError!BodyLength {
    const first = try rdr.readByte();

    if (first < 192) {
        // One-octet length
        return .{ .fixed = first };
    } else if (first < 224) {
        // Two-octet length
        const second = try rdr.readByte();
        const len: u32 = (@as(u32, first) - 192) * 256 + @as(u32, second) + 192;
        return .{ .fixed = len };
    } else if (first == 255) {
        // Five-octet length (0xFF prefix + 4 byte big-endian)
        return .{ .fixed = try rdr.readInt(u32, .big) };
    } else {
        // Partial body length: 2^(first & 0x1F)
        const power: u5 = @truncate(first & 0x1F);
        return .{ .partial = @as(u32, 1) << power };
    }
}

/// Write a new-format packet header for `tag` with a definite `length`.
pub fn writeHeader(wtr: anytype, tag: PacketTag, length: u32) @TypeOf(wtr).Error!void {
    // New format: bit 7 = 1, bit 6 = 1, bits 5-0 = tag
    const tag_byte: u8 = 0xC0 | @intFromEnum(tag);
    try wtr.writeByte(tag_byte);
    try writeNewFormatLength(wtr, length);
}

/// Write an old-format packet header for `tag` with a definite `length`.
/// The tag value must fit in 4 bits (0-15).
pub fn writeOldHeader(wtr: anytype, tag: PacketTag, length: u32) @TypeOf(wtr).Error!void {
    const tag_val = @intFromEnum(tag);
    if (length < 256) {
        // 1-byte length
        const header_byte: u8 = 0x80 | (@as(u8, tag_val) << 2) | 0;
        try wtr.writeByte(header_byte);
        try wtr.writeByte(@truncate(length));
    } else if (length < 65536) {
        // 2-byte length
        const header_byte: u8 = 0x80 | (@as(u8, tag_val) << 2) | 1;
        try wtr.writeByte(header_byte);
        try wtr.writeInt(u16, @truncate(length), .big);
    } else {
        // 4-byte length
        const header_byte: u8 = 0x80 | (@as(u8, tag_val) << 2) | 2;
        try wtr.writeByte(header_byte);
        try wtr.writeInt(u32, length, .big);
    }
}

/// Encode a new-format body length and write it.
fn writeNewFormatLength(wtr: anytype, length: u32) @TypeOf(wtr).Error!void {
    if (length < 192) {
        try wtr.writeByte(@truncate(length));
    } else if (length < 8384) {
        // Two-octet: length = (first - 192) * 256 + second + 192
        // => first  = (length - 192) / 256 + 192
        //    second = (length - 192) % 256
        const adjusted = length - 192;
        const first: u8 = @truncate(adjusted / 256 + 192);
        const second: u8 = @truncate(adjusted % 256);
        try wtr.writeByte(first);
        try wtr.writeByte(second);
    } else {
        // Five-octet
        try wtr.writeByte(0xFF);
        try wtr.writeInt(u32, length, .big);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "readHeader - new format, one-octet length" {
    // New format: tag = 2 (signature), length = 100
    // Header byte: 0xC0 | 2 = 0xC2
    // Length: 100 (one octet, < 192)
    const data = [_]u8{ 0xC2, 100 };
    var fbs = std.io.fixedBufferStream(&data);
    const hdr = try readHeader(fbs.reader());

    try std.testing.expectEqual(PacketTag.signature, hdr.tag);
    try std.testing.expectEqual(Format.new, hdr.format);
    try std.testing.expectEqual(BodyLength{ .fixed = 100 }, hdr.body_length);
}

test "readHeader - new format, two-octet length" {
    // New format: tag = 11 (literal_data), length = 1000
    // Header byte: 0xC0 | 11 = 0xCB
    // Two-octet: adjusted = 1000 - 192 = 808
    //   first  = 808 / 256 + 192 = 195
    //   second = 808 % 256 = 40
    const data = [_]u8{ 0xCB, 195, 40 };
    var fbs = std.io.fixedBufferStream(&data);
    const hdr = try readHeader(fbs.reader());

    try std.testing.expectEqual(PacketTag.literal_data, hdr.tag);
    try std.testing.expectEqual(Format.new, hdr.format);
    try std.testing.expectEqual(BodyLength{ .fixed = 1000 }, hdr.body_length);
}

test "readHeader - new format, five-octet length" {
    // New format: tag = 8 (compressed_data), length = 100000
    // Header byte: 0xC0 | 8 = 0xC8
    // Five-octet: 0xFF followed by big-endian u32
    const data = [_]u8{ 0xC8, 0xFF, 0x00, 0x01, 0x86, 0xA0 };
    var fbs = std.io.fixedBufferStream(&data);
    const hdr = try readHeader(fbs.reader());

    try std.testing.expectEqual(PacketTag.compressed_data, hdr.tag);
    try std.testing.expectEqual(Format.new, hdr.format);
    try std.testing.expectEqual(BodyLength{ .fixed = 100000 }, hdr.body_length);
}

test "readHeader - new format, partial body length" {
    // New format: tag = 9 (symmetrically_encrypted_data)
    // Header byte: 0xC0 | 9 = 0xC9
    // Partial: byte 0xE1 => 2^1 = 2 bytes
    const data = [_]u8{ 0xC9, 0xE1 };
    var fbs = std.io.fixedBufferStream(&data);
    const hdr = try readHeader(fbs.reader());

    try std.testing.expectEqual(PacketTag.symmetrically_encrypted_data, hdr.tag);
    try std.testing.expectEqual(Format.new, hdr.format);
    try std.testing.expectEqual(BodyLength{ .partial = 2 }, hdr.body_length);
}

test "readHeader - old format, 1-byte length" {
    // Old format: tag = 2 (signature), 1-byte length = 50
    // Header byte: 0x80 | (2 << 2) | 0 = 0x88
    const data = [_]u8{ 0x88, 50 };
    var fbs = std.io.fixedBufferStream(&data);
    const hdr = try readHeader(fbs.reader());

    try std.testing.expectEqual(PacketTag.signature, hdr.tag);
    try std.testing.expectEqual(Format.old, hdr.format);
    try std.testing.expectEqual(BodyLength{ .fixed = 50 }, hdr.body_length);
}

test "readHeader - old format, 2-byte length" {
    // Old format: tag = 6 (public_key), 2-byte length = 300
    // Header byte: 0x80 | (6 << 2) | 1 = 0x99
    // Length: 0x012C (300 big-endian)
    const data = [_]u8{ 0x99, 0x01, 0x2C };
    var fbs = std.io.fixedBufferStream(&data);
    const hdr = try readHeader(fbs.reader());

    try std.testing.expectEqual(PacketTag.public_key, hdr.tag);
    try std.testing.expectEqual(Format.old, hdr.format);
    try std.testing.expectEqual(BodyLength{ .fixed = 300 }, hdr.body_length);
}

test "readHeader - old format, 4-byte length" {
    // Old format: tag = 8 (compressed_data), 4-byte length = 70000
    // Header byte: 0x80 | (8 << 2) | 2 = 0xA2
    // Length: 0x00011170 (70000 big-endian)
    const data = [_]u8{ 0xA2, 0x00, 0x01, 0x11, 0x70 };
    var fbs = std.io.fixedBufferStream(&data);
    const hdr = try readHeader(fbs.reader());

    try std.testing.expectEqual(PacketTag.compressed_data, hdr.tag);
    try std.testing.expectEqual(Format.old, hdr.format);
    try std.testing.expectEqual(BodyLength{ .fixed = 70000 }, hdr.body_length);
}

test "readHeader - old format, indeterminate length" {
    // Old format: tag = 11 (literal_data), indeterminate
    // Header byte: 0x80 | (11 << 2) | 3 = 0xAF
    const data = [_]u8{0xAF};
    var fbs = std.io.fixedBufferStream(&data);
    const hdr = try readHeader(fbs.reader());

    try std.testing.expectEqual(PacketTag.literal_data, hdr.tag);
    try std.testing.expectEqual(Format.old, hdr.format);
    try std.testing.expectEqual(BodyLength{ .indeterminate = {} }, hdr.body_length);
}

test "readHeader - invalid packet (bit 7 not set)" {
    const data = [_]u8{0x01};
    var fbs = std.io.fixedBufferStream(&data);
    const result = readHeader(fbs.reader());
    try std.testing.expectError(error.InvalidPacketTag, result);
}

test "writeHeader - new format, one-octet length" {
    var buf: [16]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeHeader(fbs.writer(), PacketTag.signature, 100);

    const written = fbs.getWritten();
    try std.testing.expectEqual(@as(usize, 2), written.len);
    try std.testing.expectEqual(@as(u8, 0xC2), written[0]);
    try std.testing.expectEqual(@as(u8, 100), written[1]);
}

test "writeHeader - new format, two-octet length" {
    var buf: [16]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeHeader(fbs.writer(), PacketTag.literal_data, 1000);

    const written = fbs.getWritten();
    try std.testing.expectEqual(@as(usize, 3), written.len);
    try std.testing.expectEqual(@as(u8, 0xCB), written[0]);
    try std.testing.expectEqual(@as(u8, 195), written[1]);
    try std.testing.expectEqual(@as(u8, 40), written[2]);
}

test "writeHeader - new format, five-octet length" {
    var buf: [16]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeHeader(fbs.writer(), PacketTag.compressed_data, 100000);

    const written = fbs.getWritten();
    try std.testing.expectEqual(@as(usize, 6), written.len);
    try std.testing.expectEqual(@as(u8, 0xC8), written[0]);
    try std.testing.expectEqual(@as(u8, 0xFF), written[1]);
    // 100000 = 0x000186A0
    try std.testing.expectEqual(@as(u8, 0x00), written[2]);
    try std.testing.expectEqual(@as(u8, 0x01), written[3]);
    try std.testing.expectEqual(@as(u8, 0x86), written[4]);
    try std.testing.expectEqual(@as(u8, 0xA0), written[5]);
}

test "writeOldHeader - 1-byte length" {
    var buf: [16]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeOldHeader(fbs.writer(), PacketTag.signature, 50);

    const written = fbs.getWritten();
    try std.testing.expectEqual(@as(usize, 2), written.len);
    try std.testing.expectEqual(@as(u8, 0x88), written[0]);
    try std.testing.expectEqual(@as(u8, 50), written[1]);
}

test "writeOldHeader - 2-byte length" {
    var buf: [16]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeOldHeader(fbs.writer(), PacketTag.public_key, 300);

    const written = fbs.getWritten();
    try std.testing.expectEqual(@as(usize, 3), written.len);
    try std.testing.expectEqual(@as(u8, 0x99), written[0]);
    try std.testing.expectEqual(@as(u8, 0x01), written[1]);
    try std.testing.expectEqual(@as(u8, 0x2C), written[2]);
}

test "writeOldHeader - 4-byte length" {
    var buf: [16]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeOldHeader(fbs.writer(), PacketTag.compressed_data, 70000);

    const written = fbs.getWritten();
    try std.testing.expectEqual(@as(usize, 5), written.len);
    try std.testing.expectEqual(@as(u8, 0xA2), written[0]);
    try std.testing.expectEqual(@as(u8, 0x00), written[1]);
    try std.testing.expectEqual(@as(u8, 0x01), written[2]);
    try std.testing.expectEqual(@as(u8, 0x11), written[3]);
    try std.testing.expectEqual(@as(u8, 0x70), written[4]);
}

test "writeHeader then readHeader round-trip" {
    var buf: [64]u8 = undefined;

    // Write
    var wfbs = std.io.fixedBufferStream(&buf);
    try writeHeader(wfbs.writer(), PacketTag.user_id, 42);

    // Read back
    const written = wfbs.getWritten();
    var rfbs = std.io.fixedBufferStream(written);
    const hdr = try readHeader(rfbs.reader());

    try std.testing.expectEqual(PacketTag.user_id, hdr.tag);
    try std.testing.expectEqual(Format.new, hdr.format);
    try std.testing.expectEqual(BodyLength{ .fixed = 42 }, hdr.body_length);
}

test "writeOldHeader then readHeader round-trip" {
    var buf: [64]u8 = undefined;

    // Write
    var wfbs = std.io.fixedBufferStream(&buf);
    try writeOldHeader(wfbs.writer(), PacketTag.public_key, 500);

    // Read back
    const written = wfbs.getWritten();
    var rfbs = std.io.fixedBufferStream(written);
    const hdr = try readHeader(rfbs.reader());

    try std.testing.expectEqual(PacketTag.public_key, hdr.tag);
    try std.testing.expectEqual(Format.old, hdr.format);
    try std.testing.expectEqual(BodyLength{ .fixed = 500 }, hdr.body_length);
}
