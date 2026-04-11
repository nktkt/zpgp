// SPDX-License-Identifier: MIT
//! Fuzz testing infrastructure for OpenPGP parser components.
//!
//! Each fuzz function accepts arbitrary bytes and feeds them to a parser.
//! The contract is: the parser must never crash, panic, or leak memory,
//! regardless of input. Invalid input should be rejected gracefully with
//! error returns.
//!
//! Property tests verify round-trip invariants: any output produced by
//! an encoder must be accepted by the corresponding decoder, and the
//! decoded result must match the original input.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;

const armor = @import("../armor/armor.zig");
const crc24 = @import("../armor/crc24.zig");
const mpi_mod = @import("../types/mpi.zig");
const Mpi = mpi_mod.Mpi;
const header_mod = @import("../packet/header.zig");
const PacketTag = @import("../packet/tags.zig").PacketTag;

// ---------------------------------------------------------------------------
// Fuzz entry points
// ---------------------------------------------------------------------------

/// Feed arbitrary bytes to the armor decoder.
///
/// Must not crash, panic, or leak. Invalid armor is rejected with an error.
pub fn fuzzArmorDecoder(allocator: Allocator, data: []const u8) void {
    var result = armor.decode(allocator, data) catch return;
    result.deinit();
}

/// Feed arbitrary bytes to the MPI reader.
///
/// Reads a single MPI from the data. Must not crash or leak.
pub fn fuzzMpiReader(allocator: Allocator, data: []const u8) void {
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader();
    const mpi = Mpi.readFrom(allocator, reader) catch return;
    mpi.deinit(allocator);
}

/// Feed arbitrary bytes to the packet header parser.
///
/// Attempts to parse a single packet header. Must not crash or leak.
pub fn fuzzPacketHeader(data: []const u8) void {
    if (data.len == 0) return;
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader();
    _ = header_mod.PacketHeader.parse(reader) catch return;
}

/// Feed arbitrary bytes treated as a packet stream.
///
/// Iterates through packet headers without reading bodies. Must not crash.
pub fn fuzzPacketParser(data: []const u8) void {
    var offset: usize = 0;
    var iterations: usize = 0;
    const max_iterations = 1000; // prevent infinite loops on adversarial input

    while (offset < data.len and iterations < max_iterations) : (iterations += 1) {
        const byte = data[offset];
        if (byte & 0x80 == 0) return; // not a valid packet

        if (byte & 0x40 != 0) {
            // New format
            offset += 1;
            if (offset >= data.len) return;
            const len_byte = data[offset];
            if (len_byte < 192) {
                offset += 1;
                if (offset + len_byte > data.len) return;
                offset += len_byte;
            } else if (len_byte < 224) {
                if (offset + 1 >= data.len) return;
                const body_len = (@as(usize, len_byte - 192) << 8) + @as(usize, data[offset + 1]) + 192;
                offset += 2;
                if (offset + body_len > data.len) return;
                offset += body_len;
            } else if (len_byte == 255) {
                if (offset + 4 >= data.len) return;
                const body_len = @as(usize, data[offset + 1]) << 24 |
                    @as(usize, data[offset + 2]) << 16 |
                    @as(usize, data[offset + 3]) << 8 |
                    @as(usize, data[offset + 4]);
                offset += 5;
                if (offset + body_len > data.len) return;
                offset += body_len;
            } else {
                return; // partial body, bail
            }
        } else {
            // Old format
            const length_type = byte & 0x03;
            offset += 1;
            switch (length_type) {
                0 => {
                    if (offset >= data.len) return;
                    const body_len = @as(usize, data[offset]);
                    offset += 1;
                    if (offset + body_len > data.len) return;
                    offset += body_len;
                },
                1 => {
                    if (offset + 1 >= data.len) return;
                    const body_len = @as(usize, data[offset]) << 8 | @as(usize, data[offset + 1]);
                    offset += 2;
                    if (offset + body_len > data.len) return;
                    offset += body_len;
                },
                2 => {
                    if (offset + 3 >= data.len) return;
                    const body_len = @as(usize, data[offset]) << 24 |
                        @as(usize, data[offset + 1]) << 16 |
                        @as(usize, data[offset + 2]) << 8 |
                        @as(usize, data[offset + 3]);
                    offset += 4;
                    if (offset + body_len > data.len) return;
                    offset += body_len;
                },
                3 => return, // indeterminate length, consume rest
                else => unreachable,
            }
        }
    }
}

/// Feed arbitrary bytes to the CRC-24 computation.
///
/// CRC-24 must not crash on any input. The result is discarded.
pub fn fuzzCrc24(data: []const u8) void {
    _ = crc24.compute(data);
}

/// Attempt to parse arbitrary data as a key packet body for fingerprint.
///
/// The fingerprint function operates on raw bytes, so it must handle
/// any input without crashing.
pub fn fuzzFingerprintCalculation(data: []const u8) void {
    const fingerprint_mod = @import("../key/fingerprint.zig");
    _ = fingerprint_mod.calculateV4Fingerprint(data);
}

// ---------------------------------------------------------------------------
// Property tests (round-trip invariants)
// ---------------------------------------------------------------------------

/// Property: armor.encode output can always be decoded by armor.decode.
pub fn propertyArmorRoundtrip(allocator: Allocator, data: []const u8) !bool {
    const types = [_]armor.ArmorType{ .public_key, .private_key, .message, .signature };
    for (types) |at| {
        const encoded = armor.encode(allocator, data, at, null) catch continue;
        defer allocator.free(encoded);

        var decoded = armor.decode(allocator, encoded) catch return false;
        defer decoded.deinit();

        if (!mem.eql(u8, decoded.data, data)) return false;
        if (decoded.armor_type != at) return false;
    }
    return true;
}

/// Property: MPI write then read is the identity function.
pub fn propertyMpiRoundtrip(allocator: Allocator, data: []const u8) !bool {
    if (data.len == 0) return true;
    if (data.len > 8192) return true; // skip unreasonably large MPIs

    const mpi = Mpi.fromBytes(data);

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    const writer = buf.writer(allocator);
    mpi.writeTo(writer) catch return false;

    var stream = std.io.fixedBufferStream(buf.items);
    const reader = stream.reader();
    const read_mpi = Mpi.readFrom(allocator, reader) catch return false;
    defer read_mpi.deinit(allocator);

    if (read_mpi.bit_count != mpi.bit_count) return false;
    return mem.eql(u8, read_mpi.data, mpi.data);
}

/// Property: CRC-24 is deterministic (same input always gives same output).
pub fn propertyCrc24Deterministic(data: []const u8) bool {
    const a = crc24.compute(data);
    const b = crc24.compute(data);
    return a == b;
}

// ---------------------------------------------------------------------------
// Batch fuzz runner (for use in tests with seed-based pseudo-random input)
// ---------------------------------------------------------------------------

/// Run a batch of fuzz iterations using a deterministic PRNG.
///
/// Each iteration generates a random-length buffer of random bytes and
/// feeds it to the given fuzz function.
pub fn runFuzzBatch(
    allocator: Allocator,
    comptime fuzz_fn: anytype,
    comptime FnType: type,
    seed: u64,
    iterations: usize,
    max_len: usize,
) !void {
    _ = FnType;
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    for (0..iterations) |_| {
        const len = random.intRangeAtMost(usize, 0, max_len);
        const buf = try allocator.alloc(u8, len);
        defer allocator.free(buf);
        random.bytes(buf);

        const FnInfo = @typeInfo(@TypeOf(fuzz_fn));
        const params = FnInfo.@"fn".params;
        if (params.len == 2) {
            fuzz_fn(allocator, buf);
        } else {
            fuzz_fn(buf);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "fuzzArmorDecoder does not crash on empty input" {
    const allocator = testing.allocator;
    fuzzArmorDecoder(allocator, "");
}

test "fuzzArmorDecoder does not crash on garbage" {
    const allocator = testing.allocator;
    fuzzArmorDecoder(allocator, "\xff\xfe\xfd\x00\x01\x02\x03");
}

test "fuzzArmorDecoder does not crash on partial armor" {
    const allocator = testing.allocator;
    fuzzArmorDecoder(allocator, "-----BEGIN PGP PUBLIC KEY BLOCK-----\n");
}

test "fuzzMpiReader does not crash on empty" {
    const allocator = testing.allocator;
    fuzzMpiReader(allocator, "");
}

test "fuzzMpiReader does not crash on short data" {
    const allocator = testing.allocator;
    fuzzMpiReader(allocator, "\x00");
    fuzzMpiReader(allocator, "\x00\x01");
    fuzzMpiReader(allocator, "\xFF\xFF");
}

test "fuzzMpiReader does not crash on valid MPI" {
    const allocator = testing.allocator;
    // MPI with bit_count=8, data=0xFF
    fuzzMpiReader(allocator, &[_]u8{ 0x00, 0x08, 0xFF });
}

test "fuzzPacketHeader does not crash on empty" {
    fuzzPacketHeader("");
}

test "fuzzPacketHeader does not crash on garbage" {
    fuzzPacketHeader(&[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF });
}

test "fuzzPacketParser does not crash on empty" {
    fuzzPacketParser("");
}

test "fuzzPacketParser does not crash on non-packet data" {
    fuzzPacketParser(&[_]u8{ 0x00, 0x01, 0x02 });
}

test "fuzzPacketParser does not crash on valid packet header" {
    // New format tag 6, length 1, body 0x04
    fuzzPacketParser(&[_]u8{ 0xC6, 0x01, 0x04 });
}

test "fuzzCrc24 does not crash" {
    fuzzCrc24("");
    fuzzCrc24("hello");
    var big: [4096]u8 = undefined;
    @memset(&big, 0xAA);
    fuzzCrc24(&big);
}

test "fuzzFingerprintCalculation does not crash" {
    fuzzFingerprintCalculation("");
    fuzzFingerprintCalculation("short");
    fuzzFingerprintCalculation(&([_]u8{0x42} ** 100));
}

test "propertyArmorRoundtrip" {
    const allocator = testing.allocator;
    try testing.expect(try propertyArmorRoundtrip(allocator, "test data"));
    try testing.expect(try propertyArmorRoundtrip(allocator, ""));
    var binary: [64]u8 = undefined;
    for (&binary, 0..) |*b, i| b.* = @intCast(i * 3 & 0xFF);
    try testing.expect(try propertyArmorRoundtrip(allocator, &binary));
}

test "propertyMpiRoundtrip" {
    const allocator = testing.allocator;
    try testing.expect(try propertyMpiRoundtrip(allocator, &[_]u8{0xFF}));
    try testing.expect(try propertyMpiRoundtrip(allocator, &[_]u8{ 0x01, 0x00 }));
    try testing.expect(try propertyMpiRoundtrip(allocator, ""));
    var large: [256]u8 = undefined;
    large[0] = 0x7F;
    for (large[1..]) |*b| b.* = 0xCC;
    try testing.expect(try propertyMpiRoundtrip(allocator, &large));
}

test "propertyCrc24Deterministic" {
    try testing.expect(propertyCrc24Deterministic(""));
    try testing.expect(propertyCrc24Deterministic("hello world"));
    try testing.expect(propertyCrc24Deterministic(&([_]u8{0x00} ** 1000)));
}

test "batch fuzz armor decoder" {
    const allocator = testing.allocator;
    try runFuzzBatch(allocator, fuzzArmorDecoder, void, 12345, 50, 128);
}

test "batch fuzz MPI reader" {
    const allocator = testing.allocator;
    try runFuzzBatch(allocator, fuzzMpiReader, void, 54321, 50, 64);
}

test "batch fuzz packet parser" {
    const allocator = testing.allocator;
    try runFuzzBatch(allocator, fuzzPacketParser, void, 99999, 50, 256);
}

test "batch fuzz packet header" {
    const allocator = testing.allocator;
    try runFuzzBatch(allocator, fuzzPacketHeader, void, 11111, 50, 32);
}

test "batch fuzz CRC-24" {
    const allocator = testing.allocator;
    try runFuzzBatch(allocator, fuzzCrc24, void, 77777, 50, 512);
}

test "batch fuzz fingerprint" {
    const allocator = testing.allocator;
    try runFuzzBatch(allocator, fuzzFingerprintCalculation, void, 33333, 50, 128);
}
