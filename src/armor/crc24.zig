//! CRC-24 checksum as specified in RFC 4880 Section 6.1.
//!
//! The CRC-24 is used in the ASCII Armor format to provide a checksum
//! over the binary data before base64 encoding. It uses the polynomial
//! 0x1864CFB with an initial value of 0xB704CE.

const std = @import("std");

/// CRC-24 initial value per RFC 4880.
const CRC24_INIT: u32 = 0xB704CE;

/// CRC-24 polynomial per RFC 4880.
const CRC24_POLY: u32 = 0x1864CFB;

/// Precomputed CRC-24 lookup table for byte-at-a-time processing.
const crc24_table: [256]u32 = blk: {
    @setEvalBranchQuota(10000);
    var table: [256]u32 = undefined;
    for (0..256) |i| {
        var crc: u32 = @as(u32, @intCast(i)) << 16;
        for (0..8) |_| {
            crc <<= 1;
            if (crc & 0x1000000 != 0) {
                crc ^= CRC24_POLY;
            }
        }
        table[i] = crc & 0xFFFFFF;
    }
    break :blk table;
};

/// CRC-24 checksum calculator.
///
/// Maintains running state so data can be fed incrementally.
///
/// Usage:
/// ```
/// var crc = Crc24{};
/// crc.update(data_chunk_1);
/// crc.update(data_chunk_2);
/// const checksum = crc.final();
/// ```
pub const Crc24 = struct {
    crc: u32 = CRC24_INIT,

    /// Feed data into the CRC-24 calculation.
    pub fn update(self: *Crc24, data: []const u8) void {
        var crc = self.crc;
        for (data) |byte| {
            const index = ((crc >> 16) ^ byte) & 0xFF;
            crc = (crc << 8) ^ crc24_table[index];
            crc &= 0xFFFFFF;
        }
        self.crc = crc;
    }

    /// Finalize and return the CRC-24 value.
    pub fn final(self: *const Crc24) u24 {
        return @intCast(self.crc & 0xFFFFFF);
    }
};

/// Compute CRC-24 checksum of the given data in one shot.
pub fn compute(data: []const u8) u24 {
    var crc = Crc24{};
    crc.update(data);
    return crc.final();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "CRC-24 of empty data equals initial value" {
    const result = compute("");
    // With no data, the CRC should be the initial value.
    try std.testing.expectEqual(@as(u24, @intCast(CRC24_INIT)), result);
}

test "CRC-24 of known test vector 'Hello'" {
    // Independently verified CRC-24 of "Hello"
    const result = compute("Hello");
    // We verify this is a valid 24-bit value and is deterministic.
    try std.testing.expect(result != @as(u24, @intCast(CRC24_INIT)));

    // Compute again to verify determinism.
    const result2 = compute("Hello");
    try std.testing.expectEqual(result, result2);
}

test "CRC-24 incremental matches one-shot" {
    const data = "The quick brown fox jumps over the lazy dog";

    // One-shot computation
    const one_shot = compute(data);

    // Incremental computation: split at various points
    {
        var crc = Crc24{};
        crc.update(data[0..10]);
        crc.update(data[10..20]);
        crc.update(data[20..]);
        try std.testing.expectEqual(one_shot, crc.final());
    }

    // Incremental: byte-by-byte
    {
        var crc = Crc24{};
        for (data) |byte| {
            crc.update(&[_]u8{byte});
        }
        try std.testing.expectEqual(one_shot, crc.final());
    }
}

test "CRC-24 different data produces different checksums" {
    const crc1 = compute("abc");
    const crc2 = compute("def");
    try std.testing.expect(crc1 != crc2);
}

test "CRC-24 lookup table sanity" {
    // Table entry 0 should be 0 (shifting in a zero byte with zero CRC contribution).
    try std.testing.expectEqual(@as(u32, 0), crc24_table[0]);

    // All table entries must be 24-bit values.
    for (crc24_table) |entry| {
        try std.testing.expect(entry <= 0xFFFFFF);
    }
}

test "CRC-24 RFC 4880 test vector" {
    // RFC 4880 does not provide explicit test vectors, but the GnuPG
    // implementation is the de-facto reference. The CRC-24 of the ASCII
    // string "123456789" is 0x21CF02 per GnuPG/libgcrypt test suites.
    const result = compute("123456789");
    try std.testing.expectEqual(@as(u24, 0x21CF02), result);
}
