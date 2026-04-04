// SPDX-License-Identifier: MIT
//! Runtime-dispatched hash algorithm support for OpenPGP.
//!
//! Bridges the gap between OpenPGP's runtime `HashAlgorithm` enum and Zig's
//! comptime-parameterized hash implementations from `std.crypto`.

const std = @import("std");
const HashAlgorithm = @import("../types/enums.zig").HashAlgorithm;

pub const HashError = error{UnsupportedAlgorithm};

/// Return the digest size in bytes for the given hash algorithm.
pub fn digestSize(algo: HashAlgorithm) HashError!usize {
    return switch (algo) {
        .sha1 => 20,
        .sha256 => 32,
        .sha512 => 64,
        .sha224 => 28,
        .sha384 => 48,
        .md5, .ripemd160 => error.UnsupportedAlgorithm,
        _ => error.UnsupportedAlgorithm,
    };
}

/// A runtime-dispatched hash context that wraps std.crypto hash implementations.
pub const HashContext = struct {
    state: State,

    const State = union(enum) {
        sha1: std.crypto.hash.Sha1,
        sha256: std.crypto.hash.sha2.Sha256,
        sha512: std.crypto.hash.sha2.Sha512,
        sha224: std.crypto.hash.sha2.Sha224,
        sha384: std.crypto.hash.sha2.Sha384,
    };

    /// Initialize a new hash context for the given algorithm.
    pub fn init(algo: HashAlgorithm) HashError!HashContext {
        return .{
            .state = switch (algo) {
                .sha1 => .{ .sha1 = std.crypto.hash.Sha1.init(.{}) },
                .sha256 => .{ .sha256 = std.crypto.hash.sha2.Sha256.init(.{}) },
                .sha512 => .{ .sha512 = std.crypto.hash.sha2.Sha512.init(.{}) },
                .sha224 => .{ .sha224 = std.crypto.hash.sha2.Sha224.init(.{}) },
                .sha384 => .{ .sha384 = std.crypto.hash.sha2.Sha384.init(.{}) },
                .md5, .ripemd160 => return error.UnsupportedAlgorithm,
                _ => return error.UnsupportedAlgorithm,
            },
        };
    }

    /// Feed data into the hash.
    pub fn update(self: *HashContext, data: []const u8) void {
        switch (self.state) {
            .sha1 => |*s| s.update(data),
            .sha256 => |*s| s.update(data),
            .sha512 => |*s| s.update(data),
            .sha224 => |*s| s.update(data),
            .sha384 => |*s| s.update(data),
        }
    }

    /// Finalize the hash and write the digest into `out`.
    /// `out` must be at least `digestSize()` bytes long.
    pub fn final(self: *HashContext, out: []u8) void {
        switch (self.state) {
            .sha1 => |*s| {
                const d = s.finalResult();
                @memcpy(out[0..d.len], &d);
            },
            .sha256 => |*s| {
                const d = s.finalResult();
                @memcpy(out[0..d.len], &d);
            },
            .sha512 => |*s| {
                const d = s.finalResult();
                @memcpy(out[0..d.len], &d);
            },
            .sha224 => |*s| {
                const d = s.finalResult();
                @memcpy(out[0..d.len], &d);
            },
            .sha384 => |*s| {
                const d = s.finalResult();
                @memcpy(out[0..d.len], &d);
            },
        }
    }

    /// Convenience: hash data in one shot, writing the digest to `out`.
    pub fn hash(algo: HashAlgorithm, data: []const u8, out: []u8) HashError!void {
        var ctx = try init(algo);
        ctx.update(data);
        ctx.final(out);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "SHA-256 known digest (empty string)" {
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    const expected = [_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    var out: [32]u8 = undefined;
    try HashContext.hash(.sha256, "", &out);
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "SHA-256 known digest (abc)" {
    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    const expected = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    var out: [32]u8 = undefined;
    try HashContext.hash(.sha256, "abc", &out);
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "HashContext SHA-256 matches std library" {
    var ctx = try HashContext.init(.sha256);
    ctx.update("hello");
    var digest: [32]u8 = undefined;
    ctx.final(&digest);

    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("hello", &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &digest);
}

test "SHA-1 known digest" {
    // SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
    const expected = [_]u8{
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
        0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
        0x9c, 0xd0, 0xd8, 0x9d,
    };
    var out: [20]u8 = undefined;
    try HashContext.hash(.sha1, "abc", &out);
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "HashContext SHA-1 matches std library" {
    var ctx = try HashContext.init(.sha1);
    ctx.update("test");
    var digest: [20]u8 = undefined;
    ctx.final(&digest);

    var expected: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash("test", &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &digest);
}

test "SHA-512 known digest" {
    // SHA-512("abc")
    const expected = [_]u8{
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
        0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
        0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
        0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
        0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
    };
    var out: [64]u8 = undefined;
    try HashContext.hash(.sha512, "abc", &out);
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "digestSize returns correct sizes" {
    try std.testing.expectEqual(@as(usize, 20), try digestSize(.sha1));
    try std.testing.expectEqual(@as(usize, 32), try digestSize(.sha256));
    try std.testing.expectEqual(@as(usize, 48), try digestSize(.sha384));
    try std.testing.expectEqual(@as(usize, 64), try digestSize(.sha512));
    try std.testing.expectEqual(@as(usize, 28), try digestSize(.sha224));
}

test "unsupported algorithm returns error" {
    try std.testing.expectError(error.UnsupportedAlgorithm, HashContext.init(.md5));
    try std.testing.expectError(error.UnsupportedAlgorithm, HashContext.init(.ripemd160));
    try std.testing.expectError(error.UnsupportedAlgorithm, digestSize(@enumFromInt(99)));
}

test "incremental update produces same result as one-shot" {
    var ctx = try HashContext.init(.sha256);
    ctx.update("hello");
    ctx.update(" ");
    ctx.update("world");
    var incremental: [32]u8 = undefined;
    ctx.final(&incremental);

    var oneshot: [32]u8 = undefined;
    try HashContext.hash(.sha256, "hello world", &oneshot);

    try std.testing.expectEqualSlices(u8, &oneshot, &incremental);
}
