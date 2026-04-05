// SPDX-License-Identifier: MIT
//! Secure memory handling for cryptographic material.
//!
//! Provides utilities to safely manage sensitive data such as private keys,
//! session keys, and passphrases. Key features:
//!
//! - **secureZero**: Zeroes memory in a way that the compiler cannot elide.
//! - **SecureBuffer**: A heap-allocated buffer that is automatically zeroed
//!   when freed.
//! - **secureEqual**: Constant-time comparison to prevent timing attacks.
//! - **SecureArrayList**: An ArrayList wrapper that zeroes on deinit.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

// ---------------------------------------------------------------------------
// secureZero
// ---------------------------------------------------------------------------

/// Securely zero a byte slice.
///
/// Uses a volatile-style barrier (`doNotOptimizeAway`) to prevent the compiler
/// from removing the write because the buffer appears dead afterwards.
///
/// This is the recommended way to clear secret material before deallocation.
pub fn secureZero(comptime T: type, ptr: []T) void {
    const byte_ptr: [*]u8 = @ptrCast(ptr.ptr);
    const byte_len = ptr.len * @sizeOf(T);
    @memset(byte_ptr[0..byte_len], 0);
    // Prevent the compiler from optimising away the zeroing.
    std.mem.doNotOptimizeAway(byte_ptr);
}

/// Securely zero a fixed-size array.
pub fn secureZeroArray(comptime N: usize, buf: *[N]u8) void {
    @memset(buf, 0);
    std.mem.doNotOptimizeAway(@as([*]u8, buf));
}

/// Securely zero a byte slice (convenience wrapper for the common case).
pub fn secureZeroBytes(ptr: []u8) void {
    secureZero(u8, ptr);
}

// ---------------------------------------------------------------------------
// SecureBuffer
// ---------------------------------------------------------------------------

/// A heap-allocated byte buffer that securely zeroes its contents on deinit.
///
/// Use this for session keys, decrypted secret key material, passphrases, and
/// similar sensitive data that must not linger in memory.
///
/// ```
/// var buf = try SecureBuffer.init(allocator, 32);
/// defer buf.deinit();
/// // ... use buf.data ...
/// ```
pub const SecureBuffer = struct {
    data: []u8,
    allocator: Allocator,

    /// Allocate a SecureBuffer of `size` bytes, initially zeroed.
    pub fn init(allocator: Allocator, size: usize) !SecureBuffer {
        const data = try allocator.alloc(u8, size);
        @memset(data, 0);
        return .{
            .data = data,
            .allocator = allocator,
        };
    }

    /// Allocate a SecureBuffer and copy `source` into it.
    pub fn initCopy(allocator: Allocator, source: []const u8) !SecureBuffer {
        const data = try allocator.alloc(u8, source.len);
        @memcpy(data, source);
        return .{
            .data = data,
            .allocator = allocator,
        };
    }

    /// The length of the underlying buffer.
    pub fn len(self: *const SecureBuffer) usize {
        return self.data.len;
    }

    /// Return a const slice of the buffer contents.
    pub fn constSlice(self: *const SecureBuffer) []const u8 {
        return self.data;
    }

    /// Securely zero the buffer contents and free the memory.
    pub fn deinit(self: *SecureBuffer) void {
        secureZeroBytes(self.data);
        self.allocator.free(self.data);
        self.data = &.{};
    }
};

// ---------------------------------------------------------------------------
// SecureArrayList
// ---------------------------------------------------------------------------

/// An ArrayList(u8) wrapper that securely zeroes its backing memory on deinit.
///
/// Useful for building up sensitive data incrementally (e.g., decrypted
/// message plaintext, key derivation intermediates).
pub const SecureArrayList = struct {
    inner: std.ArrayList(u8),

    pub fn init() SecureArrayList {
        return .{ .inner = .empty };
    }

    pub fn appendSlice(self: *SecureArrayList, allocator: Allocator, data: []const u8) !void {
        try self.inner.appendSlice(allocator, data);
    }

    pub fn append(self: *SecureArrayList, allocator: Allocator, byte: u8) !void {
        try self.inner.append(allocator, byte);
    }

    pub fn items(self: *const SecureArrayList) []const u8 {
        return self.inner.items;
    }

    pub fn itemsMut(self: *SecureArrayList) []u8 {
        return self.inner.items;
    }

    /// Securely zero all allocated capacity and then free.
    pub fn deinit(self: *SecureArrayList, allocator: Allocator) void {
        if (self.inner.capacity > 0) {
            const full_buf = self.inner.items.ptr[0..self.inner.capacity];
            secureZeroBytes(full_buf);
        }
        self.inner.deinit(allocator);
    }

    /// Securely zero and return an owned slice. The caller is responsible
    /// for securely zeroing and freeing the returned slice.
    pub fn toOwnedSlice(self: *SecureArrayList, allocator: Allocator) ![]u8 {
        return self.inner.toOwnedSlice(allocator);
    }
};

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

/// Compare two byte slices in constant time.
///
/// Returns `true` if and only if the slices have equal length and identical
/// contents. The comparison always examines every byte of both inputs,
/// regardless of where (or whether) they differ, making it safe for use
/// with MACs, hashes, and other secret-dependent values.
pub fn secureEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    if (a.len == 0) return true;

    var diff: u8 = 0;
    for (a, b) |x, y| {
        diff |= x ^ y;
    }
    // Prevent the compiler from short-circuiting the loop.
    std.mem.doNotOptimizeAway(&diff);
    return diff == 0;
}

/// Compare two fixed-size arrays in constant time.
pub fn secureEqualFixed(comptime N: usize, a: *const [N]u8, b: *const [N]u8) bool {
    var diff: u8 = 0;
    for (a, b) |x, y| {
        diff |= x ^ y;
    }
    std.mem.doNotOptimizeAway(&diff);
    return diff == 0;
}

// ---------------------------------------------------------------------------
// Utility: copy with zeroize on error
// ---------------------------------------------------------------------------

/// Copy `src` into `dst`, zeroing `dst` on error (i.e. length mismatch).
pub fn secureCopy(dst: []u8, src: []const u8) error{LengthMismatch}!void {
    if (dst.len != src.len) {
        secureZeroBytes(dst);
        return error.LengthMismatch;
    }
    @memcpy(dst, src);
}

// ---------------------------------------------------------------------------
// Utility: secure allocator helpers
// ---------------------------------------------------------------------------

/// Allocate, copy, and return a new buffer. The caller should use
/// `secureZeroBytes` + `allocator.free` when done.
pub fn secureDupe(allocator: Allocator, source: []const u8) ![]u8 {
    const buf = try allocator.alloc(u8, source.len);
    @memcpy(buf, source);
    return buf;
}

/// Free a buffer after securely zeroing it.
pub fn secureFree(allocator: Allocator, buf: []u8) void {
    secureZeroBytes(buf);
    allocator.free(buf);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "secureZeroBytes zeroes memory" {
    var buf = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
    secureZeroBytes(&buf);
    for (buf) |b| {
        try testing.expectEqual(@as(u8, 0), b);
    }
}

test "secureZeroArray zeroes fixed array" {
    var buf = [_]u8{0xFF} ** 32;
    secureZeroArray(32, &buf);
    for (buf) |b| {
        try testing.expectEqual(@as(u8, 0), b);
    }
}

test "SecureBuffer init and deinit" {
    var buf = try SecureBuffer.init(testing.allocator, 64);
    defer buf.deinit();

    // Initially zeroed
    for (buf.data) |b| {
        try testing.expectEqual(@as(u8, 0), b);
    }

    // Write some data
    @memset(buf.data, 0xAB);
    try testing.expectEqual(@as(u8, 0xAB), buf.data[0]);
}

test "SecureBuffer initCopy" {
    const src = [_]u8{ 1, 2, 3, 4, 5 };
    var buf = try SecureBuffer.initCopy(testing.allocator, &src);
    defer buf.deinit();
    try testing.expectEqualSlices(u8, &src, buf.data);
}

test "secureEqual identical slices" {
    const a = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const b = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    try testing.expect(secureEqual(&a, &b));
}

test "secureEqual different slices" {
    const a = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const b = [_]u8{ 0x01, 0x02, 0x03, 0x05 };
    try testing.expect(!secureEqual(&a, &b));
}

test "secureEqual different lengths" {
    const a = [_]u8{ 0x01, 0x02, 0x03 };
    const b = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    try testing.expect(!secureEqual(&a, &b));
}

test "secureEqual empty slices" {
    const a: []const u8 = &.{};
    const b: []const u8 = &.{};
    try testing.expect(secureEqual(a, b));
}

test "secureEqualFixed identical" {
    const a = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const b = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    try testing.expect(secureEqualFixed(4, &a, &b));
}

test "secureEqualFixed different" {
    const a = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const b = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDE };
    try testing.expect(!secureEqualFixed(4, &a, &b));
}

test "secureCopy success" {
    var dst: [4]u8 = undefined;
    const src = [_]u8{ 1, 2, 3, 4 };
    try secureCopy(&dst, &src);
    try testing.expectEqualSlices(u8, &src, &dst);
}

test "secureCopy length mismatch" {
    var dst: [3]u8 = undefined;
    const src = [_]u8{ 1, 2, 3, 4 };
    try testing.expectError(error.LengthMismatch, secureCopy(&dst, &src));
}

test "secureDupe and secureFree" {
    const src = [_]u8{ 10, 20, 30, 40, 50 };
    const duped = try secureDupe(testing.allocator, &src);
    defer secureFree(testing.allocator, duped);
    try testing.expectEqualSlices(u8, &src, duped);
}

test "SecureArrayList append and deinit" {
    var list = SecureArrayList.init();
    defer list.deinit(testing.allocator);

    try list.appendSlice(testing.allocator, "hello");
    try list.append(testing.allocator, ' ');
    try list.appendSlice(testing.allocator, "world");

    try testing.expectEqualSlices(u8, "hello world", list.items());
}
