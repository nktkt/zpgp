// SPDX-License-Identifier: MIT
//! Argon2 key derivation for OpenPGP (RFC 9580 Section 3.7.2.2, S2K type 4).
//!
//! RFC 9580 specifies Argon2id as the memory-hard KDF for S2K type 4.
//! This module wraps the Zig standard library's Argon2 implementation and
//! provides the S2K type 4 wire format:
//!
//!   type (1 byte, value 4)
//!   salt (16 bytes)
//!   t    (1 byte) - number of passes (iterations)
//!   p    (1 byte) - degree of parallelism
//!   m    (1 byte) - encoded memory: actual memory = 2^m KiB
//!
//! Unlike S2K types 0, 1, and 3, Argon2 S2K does not include a hash
//! algorithm field - it always uses Argon2id internally.

const std = @import("std");
const argon2_impl = std.crypto.pwhash.argon2;

pub const Argon2Error = error{
    WeakParameters,
    OutOfMemory,
    OutputTooLong,
    OutputTooShort,
};

/// S2K type 4 (Argon2) specifier per RFC 9580.
pub const Argon2S2K = struct {
    /// 16-byte salt (RFC 9580 uses 16-byte salt, not 8-byte like older S2K types).
    salt: [16]u8,
    /// Number of passes (t parameter). Must be >= 1.
    passes: u8,
    /// Degree of parallelism (p parameter). Must be >= 1.
    parallelism: u8,
    /// Encoded memory parameter. Actual memory = 2^encoded_memory KiB.
    /// For example, encoded_memory=21 means 2^21 = 2 MiB.
    encoded_memory: u8,

    /// Parse an Argon2 S2K from a reader.
    ///
    /// The caller must have already read the type byte (4).
    /// This reads the remaining 19 bytes: salt(16) + t(1) + p(1) + m(1).
    pub fn readFrom(reader: anytype) !Argon2S2K {
        var salt: [16]u8 = undefined;
        const n = try reader.readAll(&salt);
        if (n != 16) return error.EndOfStream;

        const passes = try reader.readByte();
        const parallelism = try reader.readByte();
        const encoded_memory = try reader.readByte();

        return .{
            .salt = salt,
            .passes = passes,
            .parallelism = parallelism,
            .encoded_memory = encoded_memory,
        };
    }

    /// Write the Argon2 S2K to a writer.
    ///
    /// Writes the full S2K specifier including the type byte (4).
    pub fn writeTo(self: Argon2S2K, writer: anytype) !void {
        try writer.writeByte(4); // S2K type 4
        try writer.writeAll(&self.salt);
        try writer.writeByte(self.passes);
        try writer.writeByte(self.parallelism);
        try writer.writeByte(self.encoded_memory);
    }

    /// Size of this S2K specifier on the wire, in bytes.
    /// type(1) + salt(16) + t(1) + p(1) + m(1) = 20
    pub fn wireSize() usize {
        return 20;
    }

    /// Compute the actual memory usage in KiB.
    pub fn memoryKiB(self: Argon2S2K) u64 {
        return @as(u64, 1) << @intCast(self.encoded_memory);
    }

    /// Compute the actual memory usage in bytes.
    pub fn memoryBytes(self: Argon2S2K) u64 {
        return self.memoryKiB() * 1024;
    }

    /// Derive key material from a passphrase using Argon2id.
    ///
    /// `passphrase` - The user's passphrase.
    /// `out` - Buffer to receive the derived key (must be at least 4 bytes).
    pub fn deriveKey(self: Argon2S2K, allocator: std.mem.Allocator, passphrase: []const u8, out: []u8) Argon2Error!void {
        if (out.len < 4) return Argon2Error.OutputTooShort;
        if (self.passes < 1 or self.parallelism < 1) return Argon2Error.WeakParameters;

        const m = self.memoryKiB();
        if (m > std.math.maxInt(u32)) return Argon2Error.WeakParameters;

        const params = argon2_impl.Params{
            .t = @as(u32, self.passes),
            .m = @intCast(m),
            .p = @intCast(self.parallelism),
        };

        argon2_impl.kdf(
            allocator,
            out,
            passphrase,
            &self.salt,
            params,
            .argon2id,
        ) catch |err| {
            return switch (err) {
                error.OutOfMemory => Argon2Error.OutOfMemory,
                else => Argon2Error.WeakParameters,
            };
        };
    }

    /// Create an Argon2S2K with reasonable defaults for interactive use.
    ///
    /// Uses recommended parameters from RFC 9580:
    /// - t=1 (1 pass)
    /// - p=4 (4 lanes of parallelism)
    /// - encoded_memory=21 (2^21 = 2 MiB)
    pub fn defaultInteractive() Argon2S2K {
        var salt: [16]u8 = undefined;
        std.crypto.random.bytes(&salt);
        return .{
            .salt = salt,
            .passes = 1,
            .parallelism = 4,
            .encoded_memory = 21, // 2 MiB
        };
    }

    /// Create with custom parameters and random salt.
    pub fn withParams(passes: u8, parallelism: u8, encoded_memory: u8) Argon2S2K {
        var salt: [16]u8 = undefined;
        std.crypto.random.bytes(&salt);
        return .{
            .salt = salt,
            .passes = passes,
            .parallelism = parallelism,
            .encoded_memory = encoded_memory,
        };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Argon2S2K wire format round-trip" {
    const original = Argon2S2K{
        .salt = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 },
        .passes = 3,
        .parallelism = 4,
        .encoded_memory = 21,
    };

    // Write
    var buf: [20]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try original.writeTo(fbs.writer());

    try std.testing.expectEqual(@as(usize, 20), fbs.pos);
    try std.testing.expectEqual(@as(u8, 4), buf[0]); // type byte

    // Read back (skip the type byte - readFrom expects it was already consumed)
    fbs.pos = 1;
    const parsed = try Argon2S2K.readFrom(fbs.reader());

    try std.testing.expectEqualSlices(u8, &original.salt, &parsed.salt);
    try std.testing.expectEqual(original.passes, parsed.passes);
    try std.testing.expectEqual(original.parallelism, parsed.parallelism);
    try std.testing.expectEqual(original.encoded_memory, parsed.encoded_memory);
}

test "Argon2S2K wireSize" {
    try std.testing.expectEqual(@as(usize, 20), Argon2S2K.wireSize());
}

test "Argon2S2K memoryKiB" {
    const s2k = Argon2S2K{
        .salt = [_]u8{0} ** 16,
        .passes = 1,
        .parallelism = 1,
        .encoded_memory = 21,
    };
    try std.testing.expectEqual(@as(u64, 2097152), s2k.memoryKiB()); // 2^21 = 2 MiB in KiB

    const s2k10 = Argon2S2K{
        .salt = [_]u8{0} ** 16,
        .passes = 1,
        .parallelism = 1,
        .encoded_memory = 10,
    };
    try std.testing.expectEqual(@as(u64, 1024), s2k10.memoryKiB()); // 2^10 = 1024 KiB
}

test "Argon2S2K memoryBytes" {
    const s2k = Argon2S2K{
        .salt = [_]u8{0} ** 16,
        .passes = 1,
        .parallelism = 1,
        .encoded_memory = 10,
    };
    try std.testing.expectEqual(@as(u64, 1024 * 1024), s2k.memoryBytes()); // 1024 KiB * 1024 = 1 MiB
}

test "Argon2S2K deriveKey basic" {
    const allocator = std.testing.allocator;
    const s2k = Argon2S2K{
        .salt = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 },
        .passes = 1,
        .parallelism = 1,
        .encoded_memory = 10, // 1024 KiB - small for testing
    };

    var key1: [32]u8 = undefined;
    try s2k.deriveKey(allocator, "password", &key1);

    // Same parameters must produce same key
    var key2: [32]u8 = undefined;
    try s2k.deriveKey(allocator, "password", &key2);
    try std.testing.expectEqualSlices(u8, &key1, &key2);

    // Different password must produce different key
    var key3: [32]u8 = undefined;
    try s2k.deriveKey(allocator, "different", &key3);
    try std.testing.expect(!std.mem.eql(u8, &key1, &key3));
}

test "Argon2S2K deriveKey different salts produce different keys" {
    const allocator = std.testing.allocator;

    const s2k1 = Argon2S2K{
        .salt = [_]u8{0xAA} ** 16,
        .passes = 1,
        .parallelism = 1,
        .encoded_memory = 10,
    };
    const s2k2 = Argon2S2K{
        .salt = [_]u8{0xBB} ** 16,
        .passes = 1,
        .parallelism = 1,
        .encoded_memory = 10,
    };

    var key1: [32]u8 = undefined;
    try s2k1.deriveKey(allocator, "password", &key1);

    var key2: [32]u8 = undefined;
    try s2k2.deriveKey(allocator, "password", &key2);

    try std.testing.expect(!std.mem.eql(u8, &key1, &key2));
}

test "Argon2S2K deriveKey output too short" {
    const allocator = std.testing.allocator;
    const s2k = Argon2S2K{
        .salt = [_]u8{0} ** 16,
        .passes = 1,
        .parallelism = 1,
        .encoded_memory = 10,
    };

    var key: [3]u8 = undefined;
    try std.testing.expectError(Argon2Error.OutputTooShort, s2k.deriveKey(allocator, "test", &key));
}

test "Argon2S2K weak parameters" {
    const allocator = std.testing.allocator;
    const s2k = Argon2S2K{
        .salt = [_]u8{0} ** 16,
        .passes = 0, // invalid: must be >= 1
        .parallelism = 1,
        .encoded_memory = 10,
    };

    var key: [32]u8 = undefined;
    try std.testing.expectError(Argon2Error.WeakParameters, s2k.deriveKey(allocator, "test", &key));
}

test "Argon2S2K defaultInteractive has valid parameters" {
    const s2k = Argon2S2K.defaultInteractive();
    try std.testing.expect(s2k.passes >= 1);
    try std.testing.expect(s2k.parallelism >= 1);
    try std.testing.expect(s2k.encoded_memory >= 10); // at least 1 MiB
}
