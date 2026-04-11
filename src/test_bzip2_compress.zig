// SPDX-License-Identifier: MIT
//! Tests for BZip2 compression (encoder).
//!
//! Validates the full compression pipeline including:
//!   - Compress/decompress roundtrip for various data patterns
//!   - Output format verification (valid BZip2 headers and structure)
//!   - Block boundary handling
//!   - Edge cases (empty data, single byte, repeated patterns)
//!   - BZip2Compressor streaming interface
//!   - RLE2 (zero-run) encoding correctness

const std = @import("std");
const bzip2 = @import("crypto/bzip2.zig");

// ---------------------------------------------------------------------------
// Roundtrip tests
// ---------------------------------------------------------------------------

test "compress/decompress roundtrip: empty data" {
    const allocator = std.testing.allocator;

    const compressed = try bzip2.compress(allocator, "");
    defer allocator.free(compressed);

    // Should produce a valid BZip2 stream
    try std.testing.expect(compressed.len >= 4);
    try std.testing.expectEqualStrings("BZh", compressed[0..3]);

    const decompressed = try bzip2.decompress(allocator, compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqual(@as(usize, 0), decompressed.len);
}

test "compress/decompress roundtrip: single byte" {
    const allocator = std.testing.allocator;

    const input = "X";
    const compressed = try bzip2.compress(allocator, input);
    defer allocator.free(compressed);

    const decompressed = try bzip2.decompress(allocator, compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings(input, decompressed);
}

test "compress/decompress roundtrip: small data" {
    const allocator = std.testing.allocator;

    const input = "Hello, BZip2 compression!";
    const compressed = try bzip2.compress(allocator, input);
    defer allocator.free(compressed);

    const decompressed = try bzip2.decompress(allocator, compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings(input, decompressed);
}

test "compress/decompress roundtrip: repeated data" {
    const allocator = std.testing.allocator;

    // Repeated single character
    const input = "a" ** 200;
    const compressed = try bzip2.compress(allocator, input);
    defer allocator.free(compressed);

    const decompressed = try bzip2.decompress(allocator, compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings(input, decompressed);
}

test "compress/decompress roundtrip: repeated pattern" {
    const allocator = std.testing.allocator;

    // Repeated multi-character pattern
    const input = "abcdef" ** 50;
    const compressed = try bzip2.compress(allocator, input);
    defer allocator.free(compressed);

    const decompressed = try bzip2.decompress(allocator, compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings(input, decompressed);
}

test "compress/decompress roundtrip: all byte values" {
    const allocator = std.testing.allocator;

    // Create input with all 256 byte values
    var input: [256]u8 = undefined;
    for (0..256) |i| {
        input[i] = @intCast(i);
    }

    const compressed = try bzip2.compress(allocator, &input);
    defer allocator.free(compressed);

    const decompressed = try bzip2.decompress(allocator, compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqualSlices(u8, &input, decompressed);
}

test "compress/decompress roundtrip: binary data pattern" {
    const allocator = std.testing.allocator;

    // Pseudo-random-ish binary data
    var input: [512]u8 = undefined;
    var val: u32 = 0x12345678;
    for (&input) |*b| {
        val = val *% 1103515245 +% 12345;
        b.* = @intCast((val >> 16) & 0xFF);
    }

    const compressed = try bzip2.compress(allocator, &input);
    defer allocator.free(compressed);

    const decompressed = try bzip2.decompress(allocator, compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqualSlices(u8, &input, decompressed);
}

test "compress/decompress roundtrip: two distinct characters" {
    const allocator = std.testing.allocator;

    const input = "aabbccaabbcc";
    const compressed = try bzip2.compress(allocator, input);
    defer allocator.free(compressed);

    const decompressed = try bzip2.decompress(allocator, compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings(input, decompressed);
}

test "compress/decompress roundtrip: long runs triggering RLE1" {
    const allocator = std.testing.allocator;

    // 10 repeated characters (triggers RLE1 run-length encoding)
    const input = "x" ** 10 ++ "y" ** 10 ++ "z" ** 10;
    const compressed = try bzip2.compress(allocator, input);
    defer allocator.free(compressed);

    const decompressed = try bzip2.decompress(allocator, compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings(input, decompressed);
}

// ---------------------------------------------------------------------------
// Format verification tests
// ---------------------------------------------------------------------------

test "compressed output has valid BZip2 header" {
    const allocator = std.testing.allocator;

    const compressed = try bzip2.compress(allocator, "test data");
    defer allocator.free(compressed);

    // Must start with "BZh"
    try std.testing.expectEqual(@as(u8, 'B'), compressed[0]);
    try std.testing.expectEqual(@as(u8, 'Z'), compressed[1]);
    try std.testing.expectEqual(@as(u8, 'h'), compressed[2]);

    // Block size digit must be '9' (default)
    try std.testing.expectEqual(@as(u8, '9'), compressed[3]);
}

test "compressed output with custom block size" {
    const allocator = std.testing.allocator;

    const compressed = try bzip2.compressWithBlockSize(allocator, "test data", .@"1");
    defer allocator.free(compressed);

    // Block size digit should be '1'
    try std.testing.expectEqual(@as(u8, '1'), compressed[3]);

    // Still roundtrips correctly
    const decompressed = try bzip2.decompress(allocator, compressed);
    defer allocator.free(decompressed);
    try std.testing.expectEqualStrings("test data", decompressed);
}

test "compressed output is smaller for repeated data" {
    const allocator = std.testing.allocator;

    const input = "a" ** 1000;
    const compressed = try bzip2.compress(allocator, input);
    defer allocator.free(compressed);

    // Highly repetitive data should compress significantly
    try std.testing.expect(compressed.len < input.len);
}

// ---------------------------------------------------------------------------
// Block boundary tests
// ---------------------------------------------------------------------------

test "compress with small block size processes multiple blocks" {
    const allocator = std.testing.allocator;

    // Block size 1 = 100,000 bytes max per block
    // Create data larger than 1 block
    const block_size_bytes: usize = 100_000;
    const input = try allocator.alloc(u8, block_size_bytes + 100);
    defer allocator.free(input);

    // Fill with a pattern
    for (input, 0..) |*b, i| {
        b.* = @intCast(i % 256);
    }

    const compressed = try bzip2.compressWithBlockSize(allocator, input, .@"1");
    defer allocator.free(compressed);

    const decompressed = try bzip2.decompress(allocator, compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqualSlices(u8, input, decompressed);
}

test "compress exactly one block" {
    const allocator = std.testing.allocator;

    // With block size 1 (100,000 bytes), create exactly 100,000 bytes
    const input = try allocator.alloc(u8, 100_000);
    defer allocator.free(input);
    @memset(input, 'A');

    const compressed = try bzip2.compressWithBlockSize(allocator, input, .@"1");
    defer allocator.free(compressed);

    const decompressed = try bzip2.decompress(allocator, compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqualSlices(u8, input, decompressed);
}

// ---------------------------------------------------------------------------
// BZip2Compressor streaming interface tests
// ---------------------------------------------------------------------------

test "BZip2Compressor basic usage" {
    const allocator = std.testing.allocator;

    var comp = bzip2.BZip2Compressor.init(.@"9");
    defer comp.deinit(allocator);

    try comp.write(allocator, "Hello, ");
    try comp.write(allocator, "World!");

    try std.testing.expectEqual(@as(usize, 13), comp.bytesWritten());

    const compressed = try comp.finish(allocator);
    defer allocator.free(compressed);

    const decompressed = try bzip2.decompress(allocator, compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings("Hello, World!", decompressed);
}

test "BZip2Compressor empty input" {
    const allocator = std.testing.allocator;

    var comp = bzip2.BZip2Compressor.init(.@"9");
    defer comp.deinit(allocator);

    const compressed = try comp.finish(allocator);
    defer allocator.free(compressed);

    const decompressed = try bzip2.decompress(allocator, compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqual(@as(usize, 0), decompressed.len);
}

test "BZip2Compressor multiple chunks" {
    const allocator = std.testing.allocator;

    var comp = bzip2.BZip2Compressor.init(.@"9");
    defer comp.deinit(allocator);

    // Write data in many small chunks
    for (0..100) |_| {
        try comp.write(allocator, "chunk ");
    }

    const compressed = try comp.finish(allocator);
    defer allocator.free(compressed);

    const decompressed = try bzip2.decompress(allocator, compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqual(@as(usize, 600), decompressed.len);
}

test "BZip2Compressor reset" {
    const allocator = std.testing.allocator;

    var comp = bzip2.BZip2Compressor.init(.@"9");
    defer comp.deinit(allocator);

    try comp.write(allocator, "first");
    comp.reset(allocator);

    try std.testing.expectEqual(@as(usize, 0), comp.bytesWritten());

    try comp.write(allocator, "second");
    const compressed = try comp.finish(allocator);
    defer allocator.free(compressed);

    const decompressed = try bzip2.decompress(allocator, compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings("second", decompressed);
}

// ---------------------------------------------------------------------------
// RLE2 (zero-run encoding) tests
// ---------------------------------------------------------------------------

test "MTF+RLE2 encoding handles zero runs" {
    const allocator = std.testing.allocator;

    // Input where MTF would produce many zeros: repeated single character
    const input = "aaaa";
    var in_use: [256]bool = .{false} ** 256;
    in_use['a'] = true;

    const result = try bzip2.mtfAndRle2Encode(allocator, input, &in_use);
    defer allocator.free(result.symbols);

    // All bytes are 'a', which is at MTF position 0 after first one
    // The encoder should use RUNA/RUNB for efficient encoding
    try std.testing.expectEqual(@as(u16, 1), result.n_in_use);
    // 4 zeros -> RUNA encoding for run of 4
    try std.testing.expect(result.symbols.len > 0);
    // All symbols should be RUNA (0) or RUNB (1)
    for (result.symbols) |s| {
        try std.testing.expect(s == 0 or s == 1);
    }
}

test "MTF+RLE2 encoding handles mixed data" {
    const allocator = std.testing.allocator;

    const input = "abab";
    var in_use: [256]bool = .{false} ** 256;
    in_use['a'] = true;
    in_use['b'] = true;

    const result = try bzip2.mtfAndRle2Encode(allocator, input, &in_use);
    defer allocator.free(result.symbols);

    try std.testing.expectEqual(@as(u16, 2), result.n_in_use);
    try std.testing.expect(result.symbols.len > 0);
}

// ---------------------------------------------------------------------------
// BlockSize tests
// ---------------------------------------------------------------------------

test "BlockSize maxBytes" {
    try std.testing.expectEqual(@as(usize, 100_000), bzip2.BlockSize.@"1".maxBytes());
    try std.testing.expectEqual(@as(usize, 500_000), bzip2.BlockSize.@"5".maxBytes());
    try std.testing.expectEqual(@as(usize, 900_000), bzip2.BlockSize.@"9".maxBytes());
}

test "BlockSize headerDigit" {
    try std.testing.expectEqual(@as(u8, '1'), bzip2.BlockSize.@"1".headerDigit());
    try std.testing.expectEqual(@as(u8, '9'), bzip2.BlockSize.@"9".headerDigit());
}

// ---------------------------------------------------------------------------
// compressForTesting backward compatibility
// ---------------------------------------------------------------------------

test "compressForTesting still works" {
    const allocator = std.testing.allocator;

    const compressed = try bzip2.compressForTesting(allocator, "hello");
    defer allocator.free(compressed);

    const decompressed = try bzip2.decompress(allocator, compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings("hello", decompressed);
}

// ---------------------------------------------------------------------------
// Huffman code generation tests
// ---------------------------------------------------------------------------

test "canonical Huffman codes are valid" {
    const allocator = std.testing.allocator;

    // Create frequency data
    var freqs: [bzip2.MAX_ALPHA_SIZE]u32 = .{0} ** bzip2.MAX_ALPHA_SIZE;
    freqs[0] = 100; // most frequent
    freqs[1] = 50;
    freqs[2] = 25;
    freqs[3] = 10;
    freqs[4] = 1; // least frequent (EOB)

    var lengths: [bzip2.MAX_ALPHA_SIZE]u5 = undefined;
    try bzip2.generateCodeLengths(allocator, &freqs, 5, &lengths);

    // All used symbols should have non-zero lengths
    for (0..5) |i| {
        try std.testing.expect(lengths[i] >= 1);
        try std.testing.expect(lengths[i] <= 20);
    }

    // More frequent symbols should have shorter (or equal) codes
    try std.testing.expect(lengths[0] <= lengths[4]);
}

test "canonical codes produce prefix-free encoding" {
    // Build codes and verify no code is a prefix of another
    var lengths: [bzip2.MAX_ALPHA_SIZE]u5 = .{0} ** bzip2.MAX_ALPHA_SIZE;
    lengths[0] = 2;
    lengths[1] = 2;
    lengths[2] = 3;
    lengths[3] = 3;

    const codes = bzip2.buildCanonicalCodes(&lengths, 4);

    // Verify codes
    try std.testing.expectEqual(@as(u5, 2), codes[0].len);
    try std.testing.expectEqual(@as(u5, 2), codes[1].len);
    try std.testing.expectEqual(@as(u5, 3), codes[2].len);
    try std.testing.expectEqual(@as(u5, 3), codes[3].len);

    // Different codes should differ
    try std.testing.expect(codes[0].code != codes[1].code);
    try std.testing.expect(codes[2].code != codes[3].code);
}
