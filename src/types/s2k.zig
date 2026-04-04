// SPDX-License-Identifier: MIT
//! String-to-Key (S2K) specifier per RFC 4880 Section 3.7.
//!
//! S2K is used to derive symmetric key material from a passphrase.  Three
//! types are defined:
//! - Type 0 (Simple): Hash(passphrase)
//! - Type 1 (Salted): Hash(salt || passphrase)
//! - Type 3 (Iterated and Salted): Hash(repeated(salt || passphrase) up to count bytes)
//!
//! When the derived key needs to be longer than a single hash digest, multiple
//! passes are used with increasing zero-byte prefixes.

const std = @import("std");
const HashAlgorithm = @import("enums.zig").HashAlgorithm;
const HashContext = @import("../crypto/hash.zig").HashContext;
const digestSize = @import("../crypto/hash.zig").digestSize;

pub const S2kType = enum(u8) {
    simple = 0,
    salted = 1,
    iterated = 3, // note: 2 is reserved
    _,
};

pub const S2kError = error{
    UnsupportedS2kType,
    UnsupportedAlgorithm,
    OutputTooLarge,
    EndOfStream,
};

pub const S2K = struct {
    s2k_type: S2kType,
    hash_algo: HashAlgorithm,
    salt: [8]u8, // for types 1 and 3 (zeroed for type 0)
    coded_count: u8, // for type 3 only

    /// Parse an S2K specifier from a reader.
    pub fn readFrom(reader: anytype) !S2K {
        const type_byte = try reader.readByte();
        const s2k_type: S2kType = @enumFromInt(type_byte);
        const hash_algo: HashAlgorithm = @enumFromInt(try reader.readByte());

        var salt = [_]u8{0} ** 8;
        var coded_count: u8 = 0;

        switch (s2k_type) {
            .simple => {},
            .salted => {
                _ = try reader.readAll(&salt);
            },
            .iterated => {
                _ = try reader.readAll(&salt);
                coded_count = try reader.readByte();
            },
            _ => return S2kError.UnsupportedS2kType,
        }

        return .{
            .s2k_type = s2k_type,
            .hash_algo = hash_algo,
            .salt = salt,
            .coded_count = coded_count,
        };
    }

    /// Write the S2K specifier to a writer.
    pub fn writeTo(self: S2K, writer: anytype) !void {
        try writer.writeByte(@intFromEnum(self.s2k_type));
        try writer.writeByte(@intFromEnum(self.hash_algo));

        switch (self.s2k_type) {
            .simple => {},
            .salted => {
                try writer.writeAll(&self.salt);
            },
            .iterated => {
                try writer.writeAll(&self.salt);
                try writer.writeByte(self.coded_count);
            },
            _ => return S2kError.UnsupportedS2kType,
        }
    }

    /// Size of this S2K specifier on the wire, in bytes.
    pub fn wireSize(self: S2K) usize {
        return switch (self.s2k_type) {
            .simple => 2, // type + hash_algo
            .salted => 10, // type + hash_algo + 8-byte salt
            .iterated => 11, // type + hash_algo + 8-byte salt + coded_count
            _ => 2, // unknown, minimum
        };
    }

    /// Decode the coded count to the actual iteration byte count.
    ///
    /// RFC 4880 Section 3.7.1.3:
    ///   count = (16 + (c & 15)) << ((c >> 4) + 6)
    pub fn iterationCount(self: S2K) u32 {
        const c: u32 = self.coded_count;
        return (16 + (c & 15)) << @intCast((c >> 4) + 6);
    }

    /// Derive key material from a passphrase.
    ///
    /// `out` must be large enough to hold the desired key length. If the
    /// output is longer than a single hash digest, multiple passes are
    /// performed with increasing zero-byte prefixes (pass 0 has no prefix,
    /// pass 1 has one 0x00 prefix, etc.).
    pub fn deriveKey(self: S2K, passphrase: []const u8, out: []u8) !void {
        const digest_len = try digestSize(self.hash_algo);
        var pass: usize = 0;
        var offset: usize = 0;

        while (offset < out.len) : (pass += 1) {
            var ctx = try HashContext.init(self.hash_algo);

            // Prepend `pass` zero bytes for multi-pass derivation
            const zeros = [_]u8{0} ** 16; // max reasonable pass count
            if (pass > zeros.len) return S2kError.OutputTooLarge;
            if (pass > 0) {
                ctx.update(zeros[0..pass]);
            }

            switch (self.s2k_type) {
                .simple => {
                    // Hash(passphrase)
                    ctx.update(passphrase);
                },
                .salted => {
                    // Hash(salt || passphrase)
                    ctx.update(&self.salt);
                    ctx.update(passphrase);
                },
                .iterated => {
                    // Hash(repeated(salt || passphrase) up to count bytes)
                    const count = self.iterationCount();
                    const combined_len = self.salt.len + passphrase.len;
                    // The count must be at least as large as the combined data
                    const actual_count = @max(count, combined_len);
                    var remaining: usize = actual_count;

                    while (remaining > 0) {
                        if (remaining >= combined_len) {
                            ctx.update(&self.salt);
                            ctx.update(passphrase);
                            remaining -= combined_len;
                        } else if (remaining > self.salt.len) {
                            ctx.update(&self.salt);
                            const passphrase_part = remaining - self.salt.len;
                            ctx.update(passphrase[0..passphrase_part]);
                            remaining = 0;
                        } else {
                            ctx.update(self.salt[0..remaining]);
                            remaining = 0;
                        }
                    }
                },
                _ => return S2kError.UnsupportedS2kType,
            }

            var digest: [64]u8 = undefined; // max digest size (SHA-512)
            ctx.final(digest[0..digest_len]);

            const copy_len = @min(digest_len, out.len - offset);
            @memcpy(out[offset..][0..copy_len], digest[0..copy_len]);
            offset += copy_len;
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "S2K type 0 (simple) derivation" {
    const s2k = S2K{
        .s2k_type = .simple,
        .hash_algo = .sha256,
        .salt = [_]u8{0} ** 8,
        .coded_count = 0,
    };

    var key: [16]u8 = undefined;
    try s2k.deriveKey("password", &key);

    // Verify: SHA-256("password") truncated to 16 bytes
    var expected_full: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("password", &expected_full, .{});
    try std.testing.expectEqualSlices(u8, expected_full[0..16], &key);
}

test "S2K type 1 (salted) derivation" {
    const salt = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const s2k = S2K{
        .s2k_type = .salted,
        .hash_algo = .sha256,
        .salt = salt,
        .coded_count = 0,
    };

    var key: [32]u8 = undefined;
    try s2k.deriveKey("test", &key);

    // Verify: SHA-256(salt || "test")
    var expected: [32]u8 = undefined;
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(&salt);
    h.update("test");
    expected = h.finalResult();
    try std.testing.expectEqualSlices(u8, &expected, &key);
}

test "S2K type 3 (iterated) derivation" {
    const salt = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 };
    const s2k = S2K{
        .s2k_type = .iterated,
        .hash_algo = .sha256,
        .salt = salt,
        .coded_count = 96, // (16 + 0) << (6 + 6) = 16 << 12 = 65536
    };

    try std.testing.expectEqual(@as(u32, 65536), s2k.iterationCount());

    var key: [16]u8 = undefined;
    try s2k.deriveKey("passphrase", &key);

    // The key should be deterministic. Verify by computing manually.
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    const combined_len = salt.len + "passphrase".len; // 8 + 10 = 18
    var remaining: usize = 65536;
    while (remaining > 0) {
        if (remaining >= combined_len) {
            h.update(&salt);
            h.update("passphrase");
            remaining -= combined_len;
        } else if (remaining > salt.len) {
            h.update(&salt);
            const pp: []const u8 = "passphrase";
            h.update(pp[0 .. remaining - salt.len]);
            remaining = 0;
        } else {
            h.update(salt[0..remaining]);
            remaining = 0;
        }
    }
    const expected = h.finalResult();
    try std.testing.expectEqualSlices(u8, expected[0..16], &key);
}

test "S2K multi-pass derivation for long keys" {
    const s2k = S2K{
        .s2k_type = .simple,
        .hash_algo = .sha1, // 20-byte digest
        .salt = [_]u8{0} ** 8,
        .coded_count = 0,
    };

    // Request 32 bytes from SHA-1 (20-byte digest) = needs 2 passes
    var key: [32]u8 = undefined;
    try s2k.deriveKey("test", &key);

    // Pass 0: SHA-1("test")
    var pass0: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash("test", &pass0, .{});

    // Pass 1: SHA-1(0x00 || "test")
    var h1 = std.crypto.hash.Sha1.init(.{});
    h1.update(&[_]u8{0x00});
    h1.update("test");
    var pass1: [20]u8 = undefined;
    pass1 = h1.finalResult();

    try std.testing.expectEqualSlices(u8, &pass0, key[0..20]);
    try std.testing.expectEqualSlices(u8, pass1[0..12], key[20..32]);
}

test "S2K iteration count decoding" {
    // coded_count = 96 -> (16 + 0) << (6 + 6) = 16 << 12 = 65536
    const s2k96 = S2K{
        .s2k_type = .iterated,
        .hash_algo = .sha256,
        .salt = [_]u8{0} ** 8,
        .coded_count = 96,
    };
    try std.testing.expectEqual(@as(u32, 65536), s2k96.iterationCount());

    // coded_count = 255 -> (16 + 15) << (15 + 6) = 31 << 21 = 65011712
    const s2k255 = S2K{
        .s2k_type = .iterated,
        .hash_algo = .sha256,
        .salt = [_]u8{0} ** 8,
        .coded_count = 255,
    };
    try std.testing.expectEqual(@as(u32, 65011712), s2k255.iterationCount());
}

test "S2K wire size" {
    try std.testing.expectEqual(@as(usize, 2), (S2K{
        .s2k_type = .simple,
        .hash_algo = .sha256,
        .salt = undefined,
        .coded_count = 0,
    }).wireSize());

    try std.testing.expectEqual(@as(usize, 10), (S2K{
        .s2k_type = .salted,
        .hash_algo = .sha256,
        .salt = undefined,
        .coded_count = 0,
    }).wireSize());

    try std.testing.expectEqual(@as(usize, 11), (S2K{
        .s2k_type = .iterated,
        .hash_algo = .sha256,
        .salt = undefined,
        .coded_count = 96,
    }).wireSize());
}

test "S2K read/write round-trip" {
    const original = S2K{
        .s2k_type = .iterated,
        .hash_algo = .sha256,
        .salt = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
        .coded_count = 200,
    };

    // Write
    var buf: [11]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try original.writeTo(fbs.writer());

    // Read back
    fbs.pos = 0;
    const parsed = try S2K.readFrom(fbs.reader());

    try std.testing.expectEqual(original.s2k_type, parsed.s2k_type);
    try std.testing.expectEqual(original.hash_algo, parsed.hash_algo);
    try std.testing.expectEqualSlices(u8, &original.salt, &parsed.salt);
    try std.testing.expectEqual(original.coded_count, parsed.coded_count);
}
