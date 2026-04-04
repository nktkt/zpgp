// SPDX-License-Identifier: MIT
//! Message composition — creating OpenPGP messages.
//!
//! Provides functions to create literal data packets, compress data,
//! and build signed/encrypted message packet sequences.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const header_mod = @import("../packet/header.zig");
const PacketTag = @import("../packet/tags.zig").PacketTag;
const LiteralDataPacket = @import("../packets/literal_data.zig").LiteralDataPacket;
const CompressionAlgorithm = @import("../types/enums.zig").CompressionAlgorithm;
const SymmetricAlgorithm = @import("../types/enums.zig").SymmetricAlgorithm;
const HashAlgorithm = @import("../types/enums.zig").HashAlgorithm;
const Key = @import("../key/key.zig").Key;

pub const ComposeError = error{
    InvalidAlgorithm,
    CompressionFailed,
    NotImplemented,
    OutOfMemory,
    Overflow,
    NoSpaceLeft,
};

/// Create a literal data packet wrapping the given data.
///
/// Returns the complete packet (header + body) as a byte slice.
pub fn createLiteralData(
    allocator: Allocator,
    data: []const u8,
    filename: []const u8,
    binary: bool,
) ComposeError![]u8 {
    // Build the literal data packet body:
    //   format(1) + filename_len(1) + filename + timestamp(4) + data
    const filename_len: u8 = if (filename.len > 255) 255 else @intCast(filename.len);
    const actual_filename = filename[0..filename_len];
    const body_len = 1 + 1 + @as(usize, filename_len) + 4 + data.len;

    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // Write packet header
    var hdr_buf: [6]u8 = undefined;
    var hdr_fbs = std.io.fixedBufferStream(&hdr_buf);
    header_mod.writeHeader(hdr_fbs.writer(), .literal_data, @intCast(body_len)) catch
        return error.Overflow;
    const hdr_bytes = hdr_fbs.getWritten();
    output.appendSlice(allocator, hdr_bytes) catch return error.OutOfMemory;

    // Write body
    output.append(allocator, if (binary) 'b' else 't') catch return error.OutOfMemory;
    output.append(allocator, filename_len) catch return error.OutOfMemory;
    if (actual_filename.len > 0) {
        output.appendSlice(allocator, actual_filename) catch return error.OutOfMemory;
    }
    // Timestamp: 0 (not specified)
    output.appendSlice(allocator, &[_]u8{ 0, 0, 0, 0 }) catch return error.OutOfMemory;
    if (data.len > 0) {
        output.appendSlice(allocator, data) catch return error.OutOfMemory;
    }

    return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Compress data using the specified algorithm.
///
/// Returns the complete Compressed Data packet (header + body).
/// Supports: uncompressed (algo 0), ZIP/deflate (algo 1), ZLIB (algo 2).
///
/// For ZIP and ZLIB, uses deflate "stored blocks" format which produces valid
/// deflate streams without actual compression. This ensures compatibility while
/// avoiding Zig 0.15's complex streaming compress API. A future version can
/// replace this with true LZ77 compression.
pub fn compressData(
    allocator: Allocator,
    data: []const u8,
    algo: CompressionAlgorithm,
) ComposeError![]u8 {
    switch (algo) {
        .uncompressed => {
            // Wrap in a compressed data packet with algorithm byte 0
            const body_len = 1 + data.len;
            var output: std.ArrayList(u8) = .empty;
            errdefer output.deinit(allocator);

            var hdr_buf: [6]u8 = undefined;
            var hdr_fbs = std.io.fixedBufferStream(&hdr_buf);
            header_mod.writeHeader(hdr_fbs.writer(), .compressed_data, @intCast(body_len)) catch
                return error.Overflow;
            output.appendSlice(allocator, hdr_fbs.getWritten()) catch return error.OutOfMemory;

            output.append(allocator, 0) catch return error.OutOfMemory; // algorithm byte
            output.appendSlice(allocator, data) catch return error.OutOfMemory;

            return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
        },
        .zip => {
            // ZIP = raw deflate (stored blocks)
            const compressed = deflateStoredBlocks(allocator, data) catch
                return error.CompressionFailed;
            defer allocator.free(compressed);

            const body_len = 1 + compressed.len;
            var output: std.ArrayList(u8) = .empty;
            errdefer output.deinit(allocator);

            var hdr_buf: [6]u8 = undefined;
            var hdr_fbs = std.io.fixedBufferStream(&hdr_buf);
            header_mod.writeHeader(hdr_fbs.writer(), .compressed_data, @intCast(body_len)) catch
                return error.Overflow;
            output.appendSlice(allocator, hdr_fbs.getWritten()) catch return error.OutOfMemory;

            output.append(allocator, 1) catch return error.OutOfMemory; // algorithm byte
            output.appendSlice(allocator, compressed) catch return error.OutOfMemory;

            return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
        },
        .zlib => {
            // ZLIB = zlib header + deflate stored blocks + adler32 footer
            const compressed = zlibStoredBlocks(allocator, data) catch
                return error.CompressionFailed;
            defer allocator.free(compressed);

            const body_len = 1 + compressed.len;
            var output: std.ArrayList(u8) = .empty;
            errdefer output.deinit(allocator);

            var hdr_buf: [6]u8 = undefined;
            var hdr_fbs = std.io.fixedBufferStream(&hdr_buf);
            header_mod.writeHeader(hdr_fbs.writer(), .compressed_data, @intCast(body_len)) catch
                return error.Overflow;
            output.appendSlice(allocator, hdr_fbs.getWritten()) catch return error.OutOfMemory;

            output.append(allocator, 2) catch return error.OutOfMemory; // algorithm byte
            output.appendSlice(allocator, compressed) catch return error.OutOfMemory;

            return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
        },
        .bzip2 => return error.InvalidAlgorithm,
        _ => return error.InvalidAlgorithm,
    }
}

/// Encode data as deflate "stored blocks" (no compression).
///
/// Deflate stored block format (RFC 1951 Section 3.2.4):
///   For each block (max 65535 bytes):
///     1 bit  BFINAL (1 if last block)
///     2 bits BTYPE  (00 = no compression)
///     -- byte aligned --
///     2 bytes LEN (little-endian)
///     2 bytes NLEN (one's complement of LEN, little-endian)
///     LEN bytes of literal data
fn deflateStoredBlocks(allocator: Allocator, data: []const u8) ![]u8 {
    const max_block_size: usize = 65535;
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    var offset: usize = 0;
    while (true) {
        const remaining = data.len - offset;
        const block_size: u16 = @intCast(@min(remaining, max_block_size));
        const is_final = (offset + block_size >= data.len);

        // BFINAL(1 bit) + BTYPE(2 bits) = 0b000 or 0b001, byte-aligned
        // For stored block: BTYPE=00, BFINAL=0 or 1
        const header_byte: u8 = if (is_final) 0x01 else 0x00;
        try output.append(allocator, header_byte);

        // LEN (2 bytes, little-endian)
        var len_bytes: [2]u8 = undefined;
        mem.writeInt(u16, &len_bytes, block_size, .little);
        try output.appendSlice(allocator, &len_bytes);

        // NLEN (one's complement of LEN, 2 bytes, little-endian)
        var nlen_bytes: [2]u8 = undefined;
        mem.writeInt(u16, &nlen_bytes, ~block_size, .little);
        try output.appendSlice(allocator, &nlen_bytes);

        // Literal data
        if (block_size > 0) {
            try output.appendSlice(allocator, data[offset .. offset + block_size]);
        }

        offset += block_size;
        if (is_final) break;
    }

    return try output.toOwnedSlice(allocator);
}

/// Encode data as zlib format: zlib header + deflate stored blocks + adler32.
///
/// Zlib format (RFC 1950):
///   CMF: 0x78 (CM=8 deflate, CINFO=7 32K window)
///   FLG: calculated for check (CMF*256 + FLG must be multiple of 31)
///   compressed data (deflate stored blocks)
///   Adler-32 checksum (4 bytes, big-endian)
fn zlibStoredBlocks(allocator: Allocator, data: []const u8) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // Zlib header: CMF=0x78 (deflate, 32K window), FLG chosen so (CMF*256+FLG)%31==0
    const cmf: u8 = 0x78;
    // FLG: FCHECK must make (0x78 * 256 + FLG) % 31 == 0
    // 0x7800 % 31 = 0x7800 = 30720, 30720 % 31 = 30720 - 991*31 = 30720 - 30721 = need to check
    // 30720 / 31 = 990 remainder 30720 - 990*31 = 30720 - 30690 = 30
    // So FCHECK = 31 - 30 = 1
    const flg: u8 = 0x01;
    try output.append(allocator, cmf);
    try output.append(allocator, flg);

    // Deflate stored blocks
    const deflated = try deflateStoredBlocks(allocator, data);
    defer allocator.free(deflated);
    try output.appendSlice(allocator, deflated);

    // Adler-32 checksum (big-endian)
    const adler = adler32(data);
    var adler_bytes: [4]u8 = undefined;
    mem.writeInt(u32, &adler_bytes, adler, .big);
    try output.appendSlice(allocator, &adler_bytes);

    return try output.toOwnedSlice(allocator);
}

/// Compute the Adler-32 checksum per RFC 1950.
fn adler32(data: []const u8) u32 {
    const MOD_ADLER: u32 = 65521;
    var a: u32 = 1;
    var b: u32 = 0;

    for (data) |byte| {
        a = (a + byte) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }

    return (b << 16) | a;
}

/// Create a signed message.
///
/// Returns the complete signed message as a packet sequence:
///   One-Pass Signature + Literal Data + Signature
///
/// Note: Actual cryptographic signing requires the crypto modules being
/// built in parallel. Returns error.NotImplemented for now.
pub fn createSignedMessage(
    allocator: Allocator,
    data: []const u8,
    filename: []const u8,
    signer_key: *const Key,
    passphrase: ?[]const u8,
    hash_algo: HashAlgorithm,
) ComposeError![]u8 {
    _ = allocator;
    _ = data;
    _ = filename;
    _ = signer_key;
    _ = passphrase;
    _ = hash_algo;
    return error.NotImplemented;
}

/// Encrypt data for recipients (public key encryption).
///
/// Returns PKESK + SEIPD packet sequence.
/// The encryption flow:
///   1. Wrap plaintext in LiteralData packet
///   2. Optionally compress
///   3. Prepend random prefix (block_size + 2 bytes)
///   4. Append MDC packet (SHA-1 of everything including prefix and MDC tag+length)
///   5. Encrypt with OpenPGP CFB (non-resyncing)
///   6. Wrap in SEIPD packet (version 1)
///   7. Prepend PKESK packets
///
/// Note: Requires crypto modules being built in parallel.
/// Returns error.NotImplemented for now.
pub fn encryptMessage(
    allocator: Allocator,
    data: []const u8,
    filename: []const u8,
    recipients: []const *const Key,
    sym_algo: SymmetricAlgorithm,
    compress_algo: ?CompressionAlgorithm,
) ComposeError![]u8 {
    _ = allocator;
    _ = data;
    _ = filename;
    _ = recipients;
    _ = sym_algo;
    _ = compress_algo;
    return error.NotImplemented;
}

/// Encrypt data with passphrase (symmetric encryption).
///
/// Returns SKESK + SEIPD packet sequence.
///
/// Note: Requires crypto modules being built in parallel.
/// Returns error.NotImplemented for now.
pub fn encryptMessageSymmetric(
    allocator: Allocator,
    data: []const u8,
    filename: []const u8,
    passphrase: []const u8,
    sym_algo: SymmetricAlgorithm,
    compress_algo: ?CompressionAlgorithm,
) ComposeError![]u8 {
    _ = allocator;
    _ = data;
    _ = filename;
    _ = passphrase;
    _ = sym_algo;
    _ = compress_algo;
    return error.NotImplemented;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "createLiteralData binary" {
    const allocator = std.testing.allocator;

    const result = try createLiteralData(allocator, "Hello, PGP!", "test.txt", true);
    defer allocator.free(result);

    // Parse the result back: should start with a packet header for tag 11
    var fbs = std.io.fixedBufferStream(result);
    const hdr = try header_mod.readHeader(fbs.reader());
    try std.testing.expectEqual(PacketTag.literal_data, hdr.tag);

    const body_len = switch (hdr.body_length) {
        .fixed => |len| len,
        else => unreachable,
    };

    const body = result[fbs.pos .. fbs.pos + body_len];
    const pkt = try LiteralDataPacket.parse(allocator, body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@import("../packets/literal_data.zig").DataFormat.binary, pkt.format);
    try std.testing.expectEqualStrings("test.txt", pkt.filename);
    try std.testing.expectEqualStrings("Hello, PGP!", pkt.data);
}

test "createLiteralData text mode" {
    const allocator = std.testing.allocator;

    const result = try createLiteralData(allocator, "text data", "", false);
    defer allocator.free(result);

    var fbs = std.io.fixedBufferStream(result);
    const hdr = try header_mod.readHeader(fbs.reader());
    const body_len = switch (hdr.body_length) {
        .fixed => |len| len,
        else => unreachable,
    };

    const body = result[fbs.pos .. fbs.pos + body_len];
    const pkt = try LiteralDataPacket.parse(allocator, body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@import("../packets/literal_data.zig").DataFormat.text, pkt.format);
    try std.testing.expectEqualStrings("", pkt.filename);
    try std.testing.expectEqualStrings("text data", pkt.data);
}

test "createLiteralData empty data" {
    const allocator = std.testing.allocator;

    const result = try createLiteralData(allocator, "", "empty.bin", true);
    defer allocator.free(result);

    var fbs = std.io.fixedBufferStream(result);
    const hdr = try header_mod.readHeader(fbs.reader());
    const body_len = switch (hdr.body_length) {
        .fixed => |len| len,
        else => unreachable,
    };

    const body = result[fbs.pos .. fbs.pos + body_len];
    const pkt = try LiteralDataPacket.parse(allocator, body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), pkt.data.len);
    try std.testing.expectEqualStrings("empty.bin", pkt.filename);
}

test "compressData uncompressed" {
    const allocator = std.testing.allocator;

    const input = "Hello, uncompressed world!";
    const result = try compressData(allocator, input, .uncompressed);
    defer allocator.free(result);

    // Parse back: should be tag 8 (compressed data)
    var fbs = std.io.fixedBufferStream(result);
    const hdr = try header_mod.readHeader(fbs.reader());
    try std.testing.expectEqual(PacketTag.compressed_data, hdr.tag);

    const body_len = switch (hdr.body_length) {
        .fixed => |len| len,
        else => unreachable,
    };

    const body = result[fbs.pos .. fbs.pos + body_len];
    try std.testing.expectEqual(@as(u8, 0), body[0]); // algorithm = uncompressed
    try std.testing.expectEqualStrings(input, body[1..]);
}

test "compressData ZIP deflate stored blocks" {
    const allocator = std.testing.allocator;

    const input = "Hello, compressed world!";
    const result = try compressData(allocator, input, .zip);
    defer allocator.free(result);

    // Parse back
    var fbs = std.io.fixedBufferStream(result);
    const hdr = try header_mod.readHeader(fbs.reader());
    try std.testing.expectEqual(PacketTag.compressed_data, hdr.tag);

    const body_len = switch (hdr.body_length) {
        .fixed => |len| len,
        else => unreachable,
    };

    const body = result[fbs.pos .. fbs.pos + body_len];
    try std.testing.expectEqual(@as(u8, 1), body[0]); // algorithm = ZIP

    // Verify the deflate stored block structure manually
    const deflated = body[1..];
    // First byte should be 0x01 (BFINAL=1, BTYPE=00 stored)
    try std.testing.expectEqual(@as(u8, 0x01), deflated[0]);

    // LEN (2 bytes, little-endian)
    const block_len = mem.readInt(u16, deflated[1..3], .little);
    try std.testing.expectEqual(@as(u16, @intCast(input.len)), block_len);

    // NLEN
    const nlen = mem.readInt(u16, deflated[3..5], .little);
    try std.testing.expectEqual(~@as(u16, @intCast(input.len)), nlen);

    // Data
    try std.testing.expectEqualStrings(input, deflated[5 .. 5 + input.len]);
}

test "compressData ZLIB stored blocks" {
    const allocator = std.testing.allocator;

    const input = "ZLIB compressed data test";
    const result = try compressData(allocator, input, .zlib);
    defer allocator.free(result);

    // Parse back
    var fbs = std.io.fixedBufferStream(result);
    const hdr = try header_mod.readHeader(fbs.reader());
    try std.testing.expectEqual(PacketTag.compressed_data, hdr.tag);

    const body_len = switch (hdr.body_length) {
        .fixed => |len| len,
        else => unreachable,
    };

    const body = result[fbs.pos .. fbs.pos + body_len];
    try std.testing.expectEqual(@as(u8, 2), body[0]); // algorithm = ZLIB

    const zlib_data = body[1..];

    // Check zlib header
    try std.testing.expectEqual(@as(u8, 0x78), zlib_data[0]); // CMF
    try std.testing.expectEqual(@as(u8, 0x01), zlib_data[1]); // FLG

    // Verify (CMF*256 + FLG) % 31 == 0
    const check = @as(u16, 0x78) * 256 + @as(u16, 0x01);
    try std.testing.expectEqual(@as(u16, 0), check % 31);

    // Check adler32 at end (last 4 bytes, big-endian)
    const expected_adler = adler32(input);
    const actual_adler = mem.readInt(u32, zlib_data[zlib_data.len - 4 ..][0..4], .big);
    try std.testing.expectEqual(expected_adler, actual_adler);
}

test "compressData bzip2 returns error" {
    const allocator = std.testing.allocator;
    const result = compressData(allocator, "test", .bzip2);
    try std.testing.expectError(error.InvalidAlgorithm, result);
}

test "compressData ZIP empty data" {
    const allocator = std.testing.allocator;

    const result = try compressData(allocator, "", .zip);
    defer allocator.free(result);

    var fbs = std.io.fixedBufferStream(result);
    const hdr = try header_mod.readHeader(fbs.reader());
    try std.testing.expectEqual(PacketTag.compressed_data, hdr.tag);
}

test "compressData ZLIB empty data" {
    const allocator = std.testing.allocator;

    const result = try compressData(allocator, "", .zlib);
    defer allocator.free(result);

    var fbs = std.io.fixedBufferStream(result);
    const hdr = try header_mod.readHeader(fbs.reader());
    try std.testing.expectEqual(PacketTag.compressed_data, hdr.tag);
}

test "deflateStoredBlocks round-trip structure" {
    const allocator = std.testing.allocator;

    const data = "Test data for deflate stored blocks";
    const deflated = try deflateStoredBlocks(allocator, data);
    defer allocator.free(deflated);

    // For data <= 65535, should be one block: 1 + 2 + 2 + data.len = 5 + data.len
    try std.testing.expectEqual(5 + data.len, deflated.len);
}

test "adler32 known values" {
    // Empty data: adler32 = 1
    try std.testing.expectEqual(@as(u32, 1), adler32(""));

    // "Wikipedia" example: known value
    // adler32("Wikipedia") = 0x11E60398
    try std.testing.expectEqual(@as(u32, 0x11E60398), adler32("Wikipedia"));
}

test "createSignedMessage returns NotImplemented" {
    const allocator = std.testing.allocator;
    const result = createSignedMessage(allocator, "data", "file.txt", undefined, null, .sha256);
    try std.testing.expectError(error.NotImplemented, result);
}

test "encryptMessage returns NotImplemented" {
    const allocator = std.testing.allocator;
    const result = encryptMessage(allocator, "data", "file.txt", &[_]*const Key{}, .aes128, null);
    try std.testing.expectError(error.NotImplemented, result);
}

test "encryptMessageSymmetric returns NotImplemented" {
    const allocator = std.testing.allocator;
    const result = encryptMessageSymmetric(allocator, "data", "file.txt", "pass", .aes256, null);
    try std.testing.expectError(error.NotImplemented, result);
}
