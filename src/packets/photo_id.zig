// SPDX-License-Identifier: MIT
//! OpenPGP Photo ID support (User Attribute subpacket type 1).
//!
//! Per RFC 4880 Section 5.12.1, a User Attribute packet may contain
//! image attribute subpackets. Each image attribute subpacket contains:
//!   - Subpacket length (1, 2, or 5 bytes)
//!   - Subpacket type (1 byte): 0x01 for image
//!   - Image header (3+ bytes):
//!     - Header length (2 bytes LE): total header length including these 2 bytes
//!     - Header version (1 byte): 0x01 for current
//!     - Image encoding (1 byte): 0x01 for JPEG
//!     - Reserved (12 bytes of zeroes for version 1)
//!   - Image data (JPEG)
//!
//! This module provides parsing, creation, and validation of photo ID
//! subpackets and JPEG image data.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// A parsed Photo ID from a User Attribute subpacket.
pub const PhotoId = struct {
    /// The image format.
    image_format: ImageFormat,
    /// The raw image data (typically JPEG).
    image_data: []const u8,

    /// Supported image formats per RFC 4880.
    pub const ImageFormat = enum(u8) {
        /// JPEG image (the only format defined in RFC 4880).
        jpeg = 1,
        /// Non-standard or future format.
        _,

        pub fn name(self: ImageFormat) []const u8 {
            return switch (self) {
                .jpeg => "JPEG",
                _ => "Unknown",
            };
        }

        pub fn mimeType(self: ImageFormat) []const u8 {
            return switch (self) {
                .jpeg => "image/jpeg",
                _ => "application/octet-stream",
            };
        }
    };

    /// Parse a Photo ID from a User Attribute subpacket body.
    ///
    /// The subpacket body format (after the subpacket type byte) is:
    ///   - Little-endian 2-byte header length
    ///   - Header version (1 byte)
    ///   - Image encoding (1 byte)
    ///   - Reserved bytes (header_length - 4 bytes)
    ///   - Image data (remainder)
    pub fn parse(allocator: Allocator, subpacket_data: []const u8) !PhotoId {
        // Minimum: 2 (header len) + 1 (version) + 1 (encoding) = 4 bytes
        if (subpacket_data.len < 4) return error.InvalidFormat;

        // Header length (little-endian)
        const header_len = mem.readInt(u16, subpacket_data[0..2], .little);
        if (header_len < 4) return error.InvalidFormat;

        // Ensure we have enough data for the header
        if (subpacket_data.len < header_len) return error.InvalidFormat;

        const version = subpacket_data[2];
        if (version != 0x01) return error.UnsupportedVersion;

        const encoding = subpacket_data[3];

        const image_start = @as(usize, header_len);
        if (image_start > subpacket_data.len) return error.InvalidFormat;

        const image_data = subpacket_data[image_start..];
        const duped = try allocator.dupe(u8, image_data);

        return .{
            .image_format = @enumFromInt(encoding),
            .image_data = duped,
        };
    }

    /// Serialize the Photo ID back to subpacket body format.
    ///
    /// Produces the data that goes inside a User Attribute subpacket
    /// (after the subpacket type byte 0x01).
    pub fn serialize(self: PhotoId, allocator: Allocator) ![]u8 {
        // Header: 2 (header_len) + 1 (version) + 1 (encoding) + 12 (reserved) = 16
        const header_len: u16 = 16;
        const total = @as(usize, header_len) + self.image_data.len;

        const buf = try allocator.alloc(u8, total);
        errdefer allocator.free(buf);

        // Header length (little-endian)
        mem.writeInt(u16, buf[0..2], header_len, .little);
        // Version
        buf[2] = 0x01;
        // Image encoding
        buf[3] = @intFromEnum(self.image_format);
        // Reserved (12 bytes of zeroes)
        @memset(buf[4..16], 0x00);
        // Image data
        @memcpy(buf[16..], self.image_data);

        return buf;
    }

    /// Free the allocated image data.
    pub fn deinit(self: PhotoId, allocator: Allocator) void {
        allocator.free(self.image_data);
    }

    /// Get JPEG image dimensions from SOF (Start of Frame) marker.
    ///
    /// Scans the JPEG data for an SOF0 (0xFFC0) or SOF2 (0xFFC2) marker
    /// and extracts the width and height from it.
    ///
    /// Returns null if the image is not valid JPEG or no SOF marker is found.
    pub fn getJpegDimensions(self: PhotoId) ?struct { width: u16, height: u16 } {
        if (self.image_format != .jpeg) return null;
        return extractJpegDimensions(self.image_data);
    }

    /// Validate that the image data is a valid JPEG.
    ///
    /// Checks for the JPEG SOI (Start of Image) marker (0xFFD8) at the
    /// beginning of the data.
    pub fn isValidJpeg(self: PhotoId) bool {
        if (self.image_format != .jpeg) return false;
        return isValidJpegData(self.image_data);
    }

    /// Get the size of the image data in bytes.
    pub fn imageSize(self: PhotoId) usize {
        return self.image_data.len;
    }
};

/// Check if data starts with a valid JPEG SOI marker.
pub fn isValidJpegData(data: []const u8) bool {
    if (data.len < 2) return false;
    return data[0] == 0xFF and data[1] == 0xD8;
}

/// Extract dimensions from JPEG data by finding SOF marker.
pub fn extractJpegDimensions(data: []const u8) ?struct { width: u16, height: u16 } {
    if (data.len < 2) return null;
    if (data[0] != 0xFF or data[1] != 0xD8) return null;

    var offset: usize = 2;
    while (offset + 1 < data.len) {
        // Find next marker
        if (data[offset] != 0xFF) {
            offset += 1;
            continue;
        }

        // Skip padding 0xFF bytes
        while (offset + 1 < data.len and data[offset + 1] == 0xFF) {
            offset += 1;
        }

        if (offset + 1 >= data.len) break;

        const marker = data[offset + 1];
        offset += 2;

        // SOF markers: C0 (baseline), C1 (extended), C2 (progressive)
        if ((marker >= 0xC0 and marker <= 0xC2) or marker == 0xC9) {
            // SOF segment: length(2) + precision(1) + height(2) + width(2)
            if (offset + 7 > data.len) return null;

            // Skip segment length (2 bytes) and precision (1 byte)
            const height = mem.readInt(u16, data[offset + 3 ..][0..2], .big);
            const width = mem.readInt(u16, data[offset + 5 ..][0..2], .big);

            return .{ .width = width, .height = height };
        }

        // Skip non-SOF segments
        if (marker == 0xD9) return null; // EOI
        if (marker == 0x00 or marker == 0x01 or (marker >= 0xD0 and marker <= 0xD8)) {
            // Standalone markers (no length field)
            continue;
        }

        // Read segment length and skip
        if (offset + 1 >= data.len) break;
        const seg_len = mem.readInt(u16, data[offset..][0..2], .big);
        if (seg_len < 2) break;
        offset += seg_len;
    }

    return null;
}

/// Extract all Photo IDs from raw User Attribute packet data.
///
/// The User Attribute packet body contains one or more subpackets.
/// Each subpacket has:
///   - Length (1, 2, or 5 bytes per OpenPGP subpacket encoding)
///   - Type (1 byte)
///   - Data
///
/// This function extracts subpackets of type 1 (image attribute).
pub fn getPhotoIds(allocator: Allocator, user_attr_data: []const u8) ![]PhotoId {
    var photos = std.ArrayList(PhotoId).init(allocator);
    errdefer {
        for (photos.items) |p| p.deinit(allocator);
        photos.deinit();
    }

    var offset: usize = 0;
    while (offset < user_attr_data.len) {
        // Parse subpacket length (OpenPGP encoding)
        const len_result = parseSubpacketLength(user_attr_data[offset..]) orelse break;
        offset += len_result.header_len;

        if (len_result.body_len == 0 or offset + len_result.body_len > user_attr_data.len) break;

        const subpacket_body = user_attr_data[offset .. offset + len_result.body_len];
        offset += len_result.body_len;

        if (subpacket_body.len < 1) continue;

        const subpacket_type = subpacket_body[0];
        if (subpacket_type == 0x01 and subpacket_body.len > 1) {
            // Image attribute subpacket
            const photo = PhotoId.parse(allocator, subpacket_body[1..]) catch continue;
            try photos.append(photo);
        }
    }

    return photos.toOwnedSlice();
}

/// Create a complete User Attribute subpacket for a JPEG photo.
///
/// Returns the full subpacket data including the length prefix and
/// subpacket type byte, ready to be included in a User Attribute packet.
pub fn createPhotoIdSubpacket(allocator: Allocator, jpeg_data: []const u8) ![]u8 {
    if (!isValidJpegData(jpeg_data)) return error.InvalidFormat;

    // Build the inner data: subpacket_type(1) + header(16) + jpeg_data
    const inner_len = 1 + 16 + jpeg_data.len;

    // Calculate subpacket length encoding size
    const len_encoding_size: usize = if (inner_len < 192)
        1
    else if (inner_len < 8384)
        2
    else
        5;

    const total = len_encoding_size + inner_len;
    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);

    var offset: usize = 0;

    // Encode length
    if (inner_len < 192) {
        buf[offset] = @intCast(inner_len);
        offset += 1;
    } else if (inner_len < 8384) {
        const adjusted = inner_len - 192;
        buf[offset] = @intCast((adjusted >> 8) + 192);
        offset += 1;
        buf[offset] = @intCast(adjusted & 0xFF);
        offset += 1;
    } else {
        buf[offset] = 0xFF;
        offset += 1;
        mem.writeInt(u32, buf[offset..][0..4], @intCast(inner_len), .big);
        offset += 4;
    }

    // Subpacket type: 0x01 (image attribute)
    buf[offset] = 0x01;
    offset += 1;

    // Image header (16 bytes)
    mem.writeInt(u16, buf[offset..][0..2], 16, .little); // header length
    buf[offset + 2] = 0x01; // version
    buf[offset + 3] = 0x01; // JPEG encoding
    @memset(buf[offset + 4 .. offset + 16], 0x00); // reserved
    offset += 16;

    // JPEG data
    @memcpy(buf[offset..], jpeg_data);

    return buf;
}

// ---------------------------------------------------------------------------
// Subpacket length parsing (OpenPGP style)
// ---------------------------------------------------------------------------

const SubpacketLengthResult = struct {
    body_len: usize,
    header_len: usize,
};

fn parseSubpacketLength(data: []const u8) ?SubpacketLengthResult {
    if (data.len < 1) return null;

    const first = data[0];
    if (first < 192) {
        return .{ .body_len = first, .header_len = 1 };
    } else if (first < 255) {
        if (data.len < 2) return null;
        const second = data[1];
        const len = (@as(usize, first) - 192) * 256 + @as(usize, second) + 192;
        return .{ .body_len = len, .header_len = 2 };
    } else {
        // 5-byte length
        if (data.len < 5) return null;
        const len = mem.readInt(u32, data[1..5], .big);
        return .{ .body_len = len, .header_len = 5 };
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Minimal valid JPEG data (SOI + EOI markers).
const MINIMAL_JPEG = [_]u8{ 0xFF, 0xD8, 0xFF, 0xD9 };

/// JPEG with SOF0 marker for dimension extraction.
fn makeJpegWithDimensions(width: u16, height: u16) [20]u8 {
    var data: [20]u8 = undefined;
    // SOI
    data[0] = 0xFF;
    data[1] = 0xD8;
    // APP0 marker (minimal, 2-byte length)
    data[2] = 0xFF;
    data[3] = 0xE0;
    data[4] = 0x00;
    data[5] = 0x02; // length = 2 (just the length field itself)
    // SOF0 marker
    data[6] = 0xFF;
    data[7] = 0xC0;
    // SOF0 segment: length(2) + precision(1) + height(2) + width(2) + ...
    data[8] = 0x00;
    data[9] = 0x0B; // length = 11
    data[10] = 0x08; // precision = 8 bits
    mem.writeInt(u16, data[11..13], height, .big);
    mem.writeInt(u16, data[13..15], width, .big);
    data[15] = 0x03; // components = 3
    data[16] = 0x01;
    data[17] = 0x11;
    data[18] = 0x00; // component data
    // EOI
    data[19] = 0xFF;
    return data;
}

test "PhotoId parse and serialize round-trip" {
    const allocator = std.testing.allocator;

    // Build subpacket body: header(16) + jpeg
    var body: [16 + 4]u8 = undefined;
    mem.writeInt(u16, body[0..2], 16, .little); // header length
    body[2] = 0x01; // version
    body[3] = 0x01; // JPEG encoding
    @memset(body[4..16], 0x00); // reserved
    @memcpy(body[16..20], &MINIMAL_JPEG); // JPEG data

    const photo = try PhotoId.parse(allocator, &body);
    defer photo.deinit(allocator);

    try std.testing.expectEqual(PhotoId.ImageFormat.jpeg, photo.image_format);
    try std.testing.expectEqualSlices(u8, &MINIMAL_JPEG, photo.image_data);

    // Serialize back
    const serialized = try photo.serialize(allocator);
    defer allocator.free(serialized);

    try std.testing.expectEqualSlices(u8, &body, serialized);
}

test "PhotoId parse too short" {
    const allocator = std.testing.allocator;
    const short = [_]u8{ 0x01, 0x00 };
    const result = PhotoId.parse(allocator, &short);
    try std.testing.expectError(error.InvalidFormat, result);
}

test "PhotoId parse bad version" {
    const allocator = std.testing.allocator;
    var body: [20]u8 = undefined;
    mem.writeInt(u16, body[0..2], 16, .little);
    body[2] = 0x02; // unsupported version
    body[3] = 0x01;
    @memset(body[4..20], 0x00);

    const result = PhotoId.parse(allocator, &body);
    try std.testing.expectError(error.UnsupportedVersion, result);
}

test "PhotoId parse header too short" {
    const allocator = std.testing.allocator;
    var body: [4]u8 = undefined;
    mem.writeInt(u16, body[0..2], 2, .little); // header_len < 4
    body[2] = 0x01;
    body[3] = 0x01;

    const result = PhotoId.parse(allocator, &body);
    try std.testing.expectError(error.InvalidFormat, result);
}

test "PhotoId isValidJpeg" {
    const allocator = std.testing.allocator;

    var body: [16 + 4]u8 = undefined;
    mem.writeInt(u16, body[0..2], 16, .little);
    body[2] = 0x01;
    body[3] = 0x01;
    @memset(body[4..16], 0x00);
    @memcpy(body[16..20], &MINIMAL_JPEG);

    const photo = try PhotoId.parse(allocator, &body);
    defer photo.deinit(allocator);

    try std.testing.expect(photo.isValidJpeg());
}

test "PhotoId not valid jpeg" {
    const allocator = std.testing.allocator;

    var body: [16 + 4]u8 = undefined;
    mem.writeInt(u16, body[0..2], 16, .little);
    body[2] = 0x01;
    body[3] = 0x01;
    @memset(body[4..16], 0x00);
    body[16] = 0x00; // Not a JPEG
    body[17] = 0x00;
    body[18] = 0x00;
    body[19] = 0x00;

    const photo = try PhotoId.parse(allocator, &body);
    defer photo.deinit(allocator);

    try std.testing.expect(!photo.isValidJpeg());
}

test "PhotoId getJpegDimensions" {
    const allocator = std.testing.allocator;

    const jpeg = makeJpegWithDimensions(640, 480);

    var body: [16 + 20]u8 = undefined;
    mem.writeInt(u16, body[0..2], 16, .little);
    body[2] = 0x01;
    body[3] = 0x01;
    @memset(body[4..16], 0x00);
    @memcpy(body[16..36], &jpeg);

    const photo = try PhotoId.parse(allocator, &body);
    defer photo.deinit(allocator);

    const dims = photo.getJpegDimensions();
    try std.testing.expect(dims != null);
    try std.testing.expectEqual(@as(u16, 640), dims.?.width);
    try std.testing.expectEqual(@as(u16, 480), dims.?.height);
}

test "PhotoId getJpegDimensions not jpeg" {
    const allocator = std.testing.allocator;

    // Create photo with non-JPEG format
    const duped = try allocator.dupe(u8, &[_]u8{ 0x00, 0x01, 0x02 });
    const photo = PhotoId{
        .image_format = @enumFromInt(0x42),
        .image_data = duped,
    };
    defer photo.deinit(allocator);

    try std.testing.expect(photo.getJpegDimensions() == null);
}

test "PhotoId imageSize" {
    const allocator = std.testing.allocator;

    var body: [16 + 4]u8 = undefined;
    mem.writeInt(u16, body[0..2], 16, .little);
    body[2] = 0x01;
    body[3] = 0x01;
    @memset(body[4..16], 0x00);
    @memcpy(body[16..20], &MINIMAL_JPEG);

    const photo = try PhotoId.parse(allocator, &body);
    defer photo.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 4), photo.imageSize());
}

test "ImageFormat names" {
    try std.testing.expectEqualStrings("JPEG", PhotoId.ImageFormat.jpeg.name());
    const unknown: PhotoId.ImageFormat = @enumFromInt(42);
    try std.testing.expectEqualStrings("Unknown", unknown.name());
}

test "ImageFormat mimeType" {
    try std.testing.expectEqualStrings("image/jpeg", PhotoId.ImageFormat.jpeg.mimeType());
    const unknown: PhotoId.ImageFormat = @enumFromInt(42);
    try std.testing.expectEqualStrings("application/octet-stream", unknown.mimeType());
}

test "isValidJpegData" {
    try std.testing.expect(isValidJpegData(&MINIMAL_JPEG));
    try std.testing.expect(!isValidJpegData(&[_]u8{ 0x00, 0x00 }));
    try std.testing.expect(!isValidJpegData(&[_]u8{0xFF}));
    try std.testing.expect(!isValidJpegData(&[_]u8{}));
}

test "extractJpegDimensions with SOF0" {
    const jpeg = makeJpegWithDimensions(1024, 768);
    const dims = extractJpegDimensions(&jpeg);
    try std.testing.expect(dims != null);
    try std.testing.expectEqual(@as(u16, 1024), dims.?.width);
    try std.testing.expectEqual(@as(u16, 768), dims.?.height);
}

test "extractJpegDimensions minimal jpeg" {
    // Minimal JPEG has no SOF marker
    const dims = extractJpegDimensions(&MINIMAL_JPEG);
    try std.testing.expect(dims == null);
}

test "extractJpegDimensions not jpeg" {
    const dims = extractJpegDimensions(&[_]u8{ 0x89, 0x50, 0x4E, 0x47 }); // PNG header
    try std.testing.expect(dims == null);
}

test "createPhotoIdSubpacket" {
    const allocator = std.testing.allocator;

    const subpacket = try createPhotoIdSubpacket(allocator, &MINIMAL_JPEG);
    defer allocator.free(subpacket);

    // Should have length prefix + type(1) + header(16) + jpeg(4) = at least 22
    try std.testing.expect(subpacket.len >= 22);

    // Find the subpacket type byte
    const len_result = parseSubpacketLength(subpacket).?;
    const type_offset = len_result.header_len;
    try std.testing.expectEqual(@as(u8, 0x01), subpacket[type_offset]); // image attribute
}

test "createPhotoIdSubpacket invalid jpeg" {
    const allocator = std.testing.allocator;
    const result = createPhotoIdSubpacket(allocator, &[_]u8{ 0x00, 0x00 });
    try std.testing.expectError(error.InvalidFormat, result);
}

test "getPhotoIds empty" {
    const allocator = std.testing.allocator;
    const photos = try getPhotoIds(allocator, &[_]u8{});
    defer {
        for (photos) |p| p.deinit(allocator);
        allocator.free(photos);
    }
    try std.testing.expectEqual(@as(usize, 0), photos.len);
}

test "getPhotoIds single photo" {
    const allocator = std.testing.allocator;

    // Create a subpacket
    const subpacket = try createPhotoIdSubpacket(allocator, &MINIMAL_JPEG);
    defer allocator.free(subpacket);

    const photos = try getPhotoIds(allocator, subpacket);
    defer {
        for (photos) |p| p.deinit(allocator);
        allocator.free(photos);
    }

    try std.testing.expectEqual(@as(usize, 1), photos.len);
    try std.testing.expectEqual(PhotoId.ImageFormat.jpeg, photos[0].image_format);
    try std.testing.expect(photos[0].isValidJpeg());
}

test "parseSubpacketLength one byte" {
    const data = [_]u8{ 10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A };
    const result = parseSubpacketLength(&data).?;
    try std.testing.expectEqual(@as(usize, 10), result.body_len);
    try std.testing.expectEqual(@as(usize, 1), result.header_len);
}

test "parseSubpacketLength two byte" {
    // Encoding: first >= 192, first < 255
    // body_len = (first - 192) * 256 + second + 192
    // For body_len = 200: (first - 192) * 256 + second + 192 = 200
    // first = 192, second = 8: (192-192)*256 + 8 + 192 = 200
    const data = [_]u8{ 192, 8, 0x01 };
    const result = parseSubpacketLength(&data).?;
    try std.testing.expectEqual(@as(usize, 200), result.body_len);
    try std.testing.expectEqual(@as(usize, 2), result.header_len);
}

test "parseSubpacketLength five byte" {
    var data: [6]u8 = undefined;
    data[0] = 0xFF;
    mem.writeInt(u32, data[1..5], 1000, .big);
    data[5] = 0x00;
    const result = parseSubpacketLength(&data).?;
    try std.testing.expectEqual(@as(usize, 1000), result.body_len);
    try std.testing.expectEqual(@as(usize, 5), result.header_len);
}

test "parseSubpacketLength empty" {
    const result = parseSubpacketLength(&[_]u8{});
    try std.testing.expect(result == null);
}
