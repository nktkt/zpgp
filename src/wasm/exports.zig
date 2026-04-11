// SPDX-License-Identifier: MIT
//! WASM entry points for zpgp.
//!
//! Provides a minimal set of exported functions for use from JavaScript
//! or other WASM host environments. Uses a FixedBufferAllocator over
//! a static memory region.
//!
//! ## Memory Model
//!
//! WASM linear memory is managed via a fixed-buffer allocator backed
//! by a 1 MB static array. The host must call `wasm_alloc` to obtain
//! memory for input buffers and `wasm_free_all` to reset the allocator
//! when an operation completes.
//!
//! ## Exported Functions
//!
//! All exported functions follow this convention:
//! - Input data is passed as (pointer, length) pairs
//! - Output is written to a buffer from the fixed allocator
//! - Return value is a packed u64: high 32 bits = pointer, low 32 = length
//!   (or 0 on error)
//!
//! ## Usage from JavaScript
//!
//! ```javascript
//! const wasm = await WebAssembly.instantiate(wasmBytes);
//! const exports = wasm.instance.exports;
//!
//! // Allocate input buffer
//! const inputPtr = exports.wasm_alloc(inputData.length);
//! new Uint8Array(exports.memory.buffer, inputPtr, inputData.length)
//!     .set(inputData);
//!
//! // Compute CRC
//! const crc = exports.wasm_bzip2_crc32(inputPtr, inputData.length);
//!
//! // Cleanup
//! exports.wasm_free_all();
//! ```

const std = @import("std");

// ---------------------------------------------------------------------------
// Memory management
// ---------------------------------------------------------------------------

/// Size of the fixed allocator heap (1 MB).
const HEAP_SIZE: usize = 1024 * 1024;

/// Fixed staging buffer for small operations (4 KB).
const STAGING_SIZE: usize = 4096;

/// Staging buffer for passing small amounts of data.
var staging_buffer: [STAGING_SIZE]u8 = undefined;

/// Heap memory for the allocator.
var heap_memory: [HEAP_SIZE]u8 = undefined;

/// Static FixedBufferAllocator instance.
var fba = std.heap.FixedBufferAllocator.init(&heap_memory);

/// Get the allocator for WASM operations.
fn getAllocator() std.mem.Allocator {
    return fba.allocator();
}

// ---------------------------------------------------------------------------
// Result encoding
// ---------------------------------------------------------------------------

/// Encode a (pointer, length) pair as a packed u64 for WASM return value.
fn packResult(ptr: [*]const u8, len: usize) u64 {
    const ptr_val: u64 = @intFromPtr(ptr);
    const len_val: u64 = @as(u64, @intCast(len & 0xFFFFFFFF));
    return (ptr_val << 32) | len_val;
}

/// Error result (null pointer, zero length).
const ERROR_RESULT: u64 = 0;

// ---------------------------------------------------------------------------
// Exported WASM functions — memory management
// ---------------------------------------------------------------------------

/// Allocate `size` bytes from the WASM heap.
///
/// Returns a pointer to the allocated memory, or 0 if OOM.
export fn wasm_alloc(size: u32) u32 {
    const allocator = getAllocator();
    const buf = allocator.alloc(u8, @as(usize, size)) catch return 0;
    return @intCast(@intFromPtr(buf.ptr));
}

/// Free all allocations from the WASM heap.
///
/// Call this after each operation to reclaim memory.
export fn wasm_free_all() void {
    fba.end_index = 0;
}

/// Get a pointer to the staging buffer.
export fn wasm_get_staging_ptr() u32 {
    return @intCast(@intFromPtr(&staging_buffer));
}

/// Get the size of the staging buffer.
export fn wasm_get_staging_size() u32 {
    return STAGING_SIZE;
}

/// Get the remaining heap capacity in bytes.
export fn wasm_heap_available() u32 {
    if (fba.end_index >= HEAP_SIZE) return 0;
    return @intCast(HEAP_SIZE - fba.end_index);
}

/// Get the total heap size.
export fn wasm_heap_total() u32 {
    return HEAP_SIZE;
}

// ---------------------------------------------------------------------------
// Exported WASM functions — crypto operations
// ---------------------------------------------------------------------------

/// Compute a BZip2 CRC-32 checksum over data.
///
/// Parameters:
///   - data_ptr: Pointer to input data.
///   - data_len: Length of input data.
///
/// Returns: CRC-32 value.
export fn wasm_bzip2_crc32(data_ptr: [*]const u8, data_len: u32) u32 {
    const bzip2 = @import("../crypto/bzip2.zig");
    const data = data_ptr[0..data_len];
    return bzip2.bzip2CrcBlock(data);
}

/// Compress data using BZip2.
///
/// Parameters:
///   - data_ptr: Pointer to input data.
///   - data_len: Length of input data.
///
/// Returns: packed (pointer, length) of compressed output, or 0 on error.
export fn wasm_bzip2_compress(data_ptr: [*]const u8, data_len: u32) u64 {
    const allocator = getAllocator();
    const bzip2 = @import("../crypto/bzip2.zig");
    const data = data_ptr[0..data_len];

    const result = bzip2.compress(allocator, data) catch return ERROR_RESULT;
    return packResult(result.ptr, result.len);
}

/// Decompress BZip2 data.
///
/// Parameters:
///   - data_ptr: Pointer to compressed data.
///   - data_len: Length of compressed data.
///
/// Returns: packed (pointer, length) of decompressed output, or 0 on error.
export fn wasm_bzip2_decompress(data_ptr: [*]const u8, data_len: u32) u64 {
    const allocator = getAllocator();
    const bzip2 = @import("../crypto/bzip2.zig");
    const data = data_ptr[0..data_len];

    const result = bzip2.decompress(allocator, data) catch return ERROR_RESULT;
    return packResult(result.ptr, result.len);
}

// ---------------------------------------------------------------------------
// Exported WASM functions — i18n
// ---------------------------------------------------------------------------

/// Get a localized error message.
///
/// Parameters:
///   - error_code: Numeric ErrorCode value (0-47).
///   - locale: 0 = English, 1 = Japanese.
///
/// Returns: packed (pointer, length) of the message string, or 0 on error.
/// The returned string is a reference to static comptime data and must
/// NOT be freed.
export fn wasm_get_error_message(error_code: u32, locale_id: u32) u64 {
    const i18n = @import("../i18n/messages.zig");

    const code_count = i18n.errorCodeCount();
    if (error_code >= code_count) return ERROR_RESULT;

    const code: i18n.ErrorCode = @enumFromInt(@as(u8, @intCast(error_code)));
    const locale: i18n.Locale = if (locale_id == 1) .ja else .en;

    const msg = i18n.getMessage(code, locale);
    return packResult(msg.ptr, msg.len);
}

// ---------------------------------------------------------------------------
// Exported WASM functions — misc
// ---------------------------------------------------------------------------

/// Get the zpgp version string.
///
/// Returns: packed (pointer, length) of the version string.
export fn wasm_version() u64 {
    const version = "zpgp 0.1.0 (wasm)";
    return packResult(version.ptr, version.len);
}

// ---------------------------------------------------------------------------
// Tests (run on host, not WASM target)
// ---------------------------------------------------------------------------

test "FixedBufferAllocator basic" {
    fba.end_index = 0;
    const allocator = getAllocator();

    const buf = try allocator.alloc(u8, 64);
    try std.testing.expectEqual(@as(usize, 64), buf.len);

    fba.end_index = 0;
}

test "wasm_alloc and free" {
    fba.end_index = 0;
    const ptr = wasm_alloc(64);
    try std.testing.expect(ptr != 0);

    wasm_free_all();
}

test "wasm_heap_available" {
    fba.end_index = 0;
    const full = wasm_heap_available();
    try std.testing.expectEqual(@as(u32, HEAP_SIZE), full);

    _ = wasm_alloc(100);
    const after = wasm_heap_available();
    try std.testing.expect(after < full);
    wasm_free_all();
}

test "packResult encoding" {
    const buf: [4]u8 = .{ 'a', 'b', 'c', 'd' };
    const result = packResult(&buf, 4);
    const ptr_part = result >> 32;
    const len_part = result & 0xFFFFFFFF;
    try std.testing.expectEqual(@as(u64, @intFromPtr(&buf)), ptr_part);
    try std.testing.expectEqual(@as(u64, 4), len_part);
}

test "wasm_version" {
    const result = wasm_version();
    try std.testing.expect(result != 0);
    const len = @as(usize, @intCast(result & 0xFFFFFFFF));
    try std.testing.expect(len > 0);
}

test "wasm_get_staging_ptr" {
    const ptr = wasm_get_staging_ptr();
    try std.testing.expect(ptr != 0);
    try std.testing.expectEqual(@as(u32, STAGING_SIZE), wasm_get_staging_size());
}

test "wasm_get_error_message valid" {
    const result = wasm_get_error_message(0, 0); // key_not_found, en
    try std.testing.expect(result != 0);

    const result_ja = wasm_get_error_message(0, 1); // key_not_found, ja
    try std.testing.expect(result_ja != 0);
    try std.testing.expect(result != result_ja); // Different messages
}

test "wasm_get_error_message invalid code" {
    const result = wasm_get_error_message(999, 0);
    try std.testing.expectEqual(ERROR_RESULT, result);
}

test "wasm_bzip2_crc32" {
    const data = "Hello";
    const crc = wasm_bzip2_crc32(data.ptr, data.len);
    try std.testing.expect(crc != 0);

    // Same data should produce same CRC
    const crc2 = wasm_bzip2_crc32(data.ptr, data.len);
    try std.testing.expectEqual(crc, crc2);
}

test "wasm_heap_total" {
    try std.testing.expectEqual(@as(u32, HEAP_SIZE), wasm_heap_total());
}
