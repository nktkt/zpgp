// SPDX-License-Identifier: MIT
//! OpenPGP timestamp utilities.
//!
//! RFC 4880 represents times as a four-octet (u32) number of seconds
//! elapsed since midnight, 1 January 1970 UTC.

const std = @import("std");

/// Seconds since the Unix epoch (1970-01-01T00:00:00Z).
/// This is the wire representation used throughout OpenPGP.
pub const Timestamp = u32;

/// Maximum representable timestamp (2106-02-07T06:28:15Z).
pub const max_timestamp: Timestamp = std.math.maxInt(u32);

/// Return the current time as an OpenPGP timestamp.
/// Returns 0 if the system clock reports a time before the Unix epoch,
/// and saturates at `max_timestamp` for dates beyond 2106.
pub fn now() Timestamp {
    return fromEpoch(std.time.timestamp());
}

/// Convert a signed 64-bit epoch value (as returned by `std.time.timestamp()`)
/// to an OpenPGP u32 timestamp.  Clamps negative values to 0 and values
/// exceeding u32 range to `max_timestamp`.
pub fn fromEpoch(epoch: i64) Timestamp {
    if (epoch <= 0) return 0;
    if (epoch > @as(i64, max_timestamp)) return max_timestamp;
    return @intCast(epoch);
}

/// Convert an OpenPGP timestamp back to a signed 64-bit epoch.
pub fn toEpoch(ts: Timestamp) i64 {
    return @as(i64, ts);
}

/// Read a timestamp from any reader (4-byte big-endian).
pub fn readFrom(reader: anytype) !Timestamp {
    return try reader.readInt(u32, .big);
}

/// Write a timestamp to any writer (4-byte big-endian).
pub fn writeTo(ts: Timestamp, writer: anytype) !void {
    try writer.writeInt(u32, ts, .big);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "fromEpoch basic values" {
    try std.testing.expectEqual(@as(Timestamp, 0), fromEpoch(0));
    try std.testing.expectEqual(@as(Timestamp, 1000), fromEpoch(1000));
    try std.testing.expectEqual(@as(Timestamp, 1234567890), fromEpoch(1234567890));
}

test "fromEpoch clamps negative" {
    try std.testing.expectEqual(@as(Timestamp, 0), fromEpoch(-1));
    try std.testing.expectEqual(@as(Timestamp, 0), fromEpoch(-9999999));
}

test "fromEpoch clamps overflow" {
    // u32 max = 4294967295
    try std.testing.expectEqual(max_timestamp, fromEpoch(4294967295));
    try std.testing.expectEqual(max_timestamp, fromEpoch(4294967296));
    try std.testing.expectEqual(max_timestamp, fromEpoch(std.math.maxInt(i64)));
}

test "toEpoch round-trip" {
    const ts: Timestamp = 1700000000;
    try std.testing.expectEqual(@as(i64, 1700000000), toEpoch(ts));
    try std.testing.expectEqual(ts, fromEpoch(toEpoch(ts)));
}

test "now returns a reasonable value" {
    const ts = now();
    // Any time after 2020-01-01 is reasonable.
    try std.testing.expect(ts > 1577836800);
}

test "readFrom and writeTo round-trip" {
    const original: Timestamp = 0xDEADBEEF;

    var buf: [8]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeTo(original, fbs.writer());

    // Verify wire format: big-endian.
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, buf[0..4]);

    fbs.pos = 0;
    const decoded = try readFrom(fbs.reader());
    try std.testing.expectEqual(original, decoded);
}

test "readFrom and writeTo zero" {
    var buf: [4]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeTo(0, fbs.writer());
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, &buf);

    fbs.pos = 0;
    const decoded = try readFrom(fbs.reader());
    try std.testing.expectEqual(@as(Timestamp, 0), decoded);
}
