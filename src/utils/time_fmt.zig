// SPDX-License-Identifier: MIT
//! Time formatting utilities for OpenPGP.
//!
//! OpenPGP stores times as u32 Unix timestamps (seconds since 1970-01-01
//! 00:00:00 UTC). This module provides human-readable formatting and
//! parsing utilities for these timestamps.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

pub const TimeError = error{
    InvalidDate,
    BufferTooSmall,
    Overflow,
};

/// Format a Unix timestamp as "YYYY-MM-DD HH:MM:SS UTC".
///
/// Writes into the provided buffer and returns a slice of the written
/// portion. The buffer must be at least 23 bytes.
///
/// Returns the formatted string slice (pointing into `buf`).
pub fn formatTimestamp(ts: u32, buf: []u8) TimeError![]const u8 {
    if (buf.len < 23) return error.BufferTooSmall;

    const epoch_seconds: i64 = @as(i64, ts);
    const es = std.time.epoch.EpochSeconds{ .secs = @intCast(epoch_seconds) };
    const epoch_day = es.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = es.getDaySeconds();

    const year = year_day.year;
    const month = @as(u32, @intFromEnum(month_day.month));
    const day = @as(u32, month_day.day_index) + 1;
    const hour = day_seconds.getHoursIntoDay();
    const minute = day_seconds.getMinutesIntoHour();
    const second = day_seconds.getSecondsIntoMinute();

    // Format: "YYYY-MM-DD HH:MM:SS UTC"
    _ = std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} UTC", .{
        year,
        month,
        day,
        hour,
        minute,
        second,
    }) catch return error.BufferTooSmall;

    return buf[0..23];
}

/// Format a duration in seconds as a human-readable string.
///
/// Examples:
///   - 86400 -> "1 day"
///   - 172800 -> "2 days"
///   - 3600 -> "1 hour"
///   - 31536000 -> "365 days"
///
/// Writes into the provided buffer and returns a slice of the written
/// portion. The buffer must be at least 32 bytes.
pub fn formatDuration(seconds: u64, buf: []u8) TimeError![]const u8 {
    if (buf.len < 32) return error.BufferTooSmall;

    if (seconds == 0) {
        const result = std.fmt.bufPrint(buf, "0 seconds", .{}) catch
            return error.BufferTooSmall;
        return result;
    }

    const days = seconds / 86400;
    const remaining_hours = (seconds % 86400) / 3600;
    const remaining_minutes = (seconds % 3600) / 60;
    const remaining_seconds = seconds % 60;

    if (days > 0) {
        if (days == 1) {
            const result = std.fmt.bufPrint(buf, "1 day", .{}) catch
                return error.BufferTooSmall;
            return result;
        }
        const result = std.fmt.bufPrint(buf, "{d} days", .{days}) catch
            return error.BufferTooSmall;
        return result;
    }

    if (remaining_hours > 0) {
        if (remaining_hours == 1) {
            const result = std.fmt.bufPrint(buf, "1 hour", .{}) catch
                return error.BufferTooSmall;
            return result;
        }
        const result = std.fmt.bufPrint(buf, "{d} hours", .{remaining_hours}) catch
            return error.BufferTooSmall;
        return result;
    }

    if (remaining_minutes > 0) {
        if (remaining_minutes == 1) {
            const result = std.fmt.bufPrint(buf, "1 minute", .{}) catch
                return error.BufferTooSmall;
            return result;
        }
        const result = std.fmt.bufPrint(buf, "{d} minutes", .{remaining_minutes}) catch
            return error.BufferTooSmall;
        return result;
    }

    if (remaining_seconds == 1) {
        const result = std.fmt.bufPrint(buf, "1 second", .{}) catch
            return error.BufferTooSmall;
        return result;
    }
    const result = std.fmt.bufPrint(buf, "{d} seconds", .{remaining_seconds}) catch
        return error.BufferTooSmall;
    return result;
}

/// Parse an ISO 8601 date string ("YYYY-MM-DD") to a Unix timestamp.
///
/// Returns the timestamp for midnight UTC on the given date.
/// The input must be exactly 10 characters: "YYYY-MM-DD".
pub fn parseIsoDate(date: []const u8) TimeError!u32 {
    if (date.len != 10) return error.InvalidDate;
    if (date[4] != '-' or date[7] != '-') return error.InvalidDate;

    const year = std.fmt.parseInt(i32, date[0..4], 10) catch return error.InvalidDate;
    const month_raw = std.fmt.parseInt(u32, date[5..7], 10) catch return error.InvalidDate;
    const day = std.fmt.parseInt(u32, date[8..10], 10) catch return error.InvalidDate;

    if (month_raw < 1 or month_raw > 12) return error.InvalidDate;
    if (day < 1 or day > 31) return error.InvalidDate;
    if (year < 1970) return error.InvalidDate;

    const month: std.time.epoch.Month = @enumFromInt(month_raw);

    // Calculate days since epoch using the standard library's epoch utilities
    const year_u: u16 = if (year >= 0 and year <= 65535) @intCast(year) else return error.InvalidDate;

    // Calculate the number of days from epoch to the start of the year
    const epoch_year: u16 = 1970;
    var total_days: i64 = 0;

    if (year_u >= epoch_year) {
        var y: u16 = epoch_year;
        while (y < year_u) : (y += 1) {
            total_days += if (isLeapYear(y)) @as(i64, 366) else @as(i64, 365);
        }
    } else {
        return error.InvalidDate;
    }

    // Add days for months in the current year
    const is_leap = isLeapYear(year_u);
    const days_per_month = if (is_leap)
        [_]u32{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
    else
        [_]u32{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

    _ = month;
    var m: u32 = 1;
    while (m < month_raw) : (m += 1) {
        total_days += days_per_month[m - 1];
    }

    // Validate day for the specific month
    if (day > days_per_month[month_raw - 1]) return error.InvalidDate;

    total_days += day - 1; // day_index is 0-based

    const timestamp = total_days * 86400;
    if (timestamp < 0 or timestamp > @as(i64, std.math.maxInt(u32))) return error.Overflow;

    return @intCast(timestamp);
}

/// Calculate the number of days until a key expires.
///
/// Arguments:
///   - `creation`: Key creation timestamp (Unix seconds)
///   - `expiry_offset`: Expiration offset in seconds after creation (0 = never)
///   - `now`: Current timestamp (Unix seconds)
///
/// Returns:
///   - null if the key never expires (expiry_offset == 0)
///   - Negative value if already expired
///   - Positive value for days remaining
pub fn daysUntilExpiry(creation: u32, expiry_offset: u32, now_ts: u32) ?i64 {
    if (expiry_offset == 0) return null; // Never expires

    const expiry_time = @as(i64, creation) + @as(i64, expiry_offset);
    const current = @as(i64, now_ts);
    const diff_seconds = expiry_time - current;

    return @divTrunc(diff_seconds, 86400);
}

/// Check if a given year is a leap year.
fn isLeapYear(year: u16) bool {
    if (year % 4 != 0) return false;
    if (year % 100 != 0) return true;
    if (year % 400 != 0) return false;
    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "formatTimestamp epoch" {
    var buf: [32]u8 = undefined;
    const result = try formatTimestamp(0, &buf);
    try std.testing.expectEqualStrings("1970-01-01 00:00:00 UTC", result);
}

test "formatTimestamp known date" {
    var buf: [32]u8 = undefined;
    // 2024-03-15 14:30:00 UTC = 1710513000
    const result = try formatTimestamp(1710513000, &buf);
    try std.testing.expectEqualStrings("2024-03-15 14:30:00 UTC", result);
}

test "formatTimestamp buffer too small" {
    var buf: [10]u8 = undefined;
    const result = formatTimestamp(0, &buf);
    try std.testing.expectError(error.BufferTooSmall, result);
}

test "formatDuration days" {
    var buf: [64]u8 = undefined;
    const result = try formatDuration(86400, &buf);
    try std.testing.expectEqualStrings("1 day", result);

    const result2 = try formatDuration(172800, &buf);
    try std.testing.expectEqualStrings("2 days", result2);

    const result3 = try formatDuration(86400 * 365, &buf);
    try std.testing.expectEqualStrings("365 days", result3);
}

test "formatDuration hours" {
    var buf: [64]u8 = undefined;
    const result = try formatDuration(3600, &buf);
    try std.testing.expectEqualStrings("1 hour", result);

    const result2 = try formatDuration(7200, &buf);
    try std.testing.expectEqualStrings("2 hours", result2);
}

test "formatDuration seconds" {
    var buf: [64]u8 = undefined;
    const result = try formatDuration(1, &buf);
    try std.testing.expectEqualStrings("1 second", result);

    const result2 = try formatDuration(42, &buf);
    try std.testing.expectEqualStrings("42 seconds", result2);
}

test "formatDuration zero" {
    var buf: [64]u8 = undefined;
    const result = try formatDuration(0, &buf);
    try std.testing.expectEqualStrings("0 seconds", result);
}

test "parseIsoDate basic" {
    const ts = try parseIsoDate("1970-01-01");
    try std.testing.expectEqual(@as(u32, 0), ts);
}

test "parseIsoDate 2024" {
    const ts = try parseIsoDate("2024-01-01");
    // 2024-01-01 = 19723 days * 86400 = 1704067200
    try std.testing.expectEqual(@as(u32, 1704067200), ts);
}

test "parseIsoDate invalid format" {
    try std.testing.expectError(error.InvalidDate, parseIsoDate("2024/01/01"));
    try std.testing.expectError(error.InvalidDate, parseIsoDate("20240101"));
    try std.testing.expectError(error.InvalidDate, parseIsoDate(""));
}

test "parseIsoDate invalid values" {
    try std.testing.expectError(error.InvalidDate, parseIsoDate("2024-13-01"));
    try std.testing.expectError(error.InvalidDate, parseIsoDate("2024-00-01"));
    try std.testing.expectError(error.InvalidDate, parseIsoDate("2024-01-32"));
    try std.testing.expectError(error.InvalidDate, parseIsoDate("2023-02-29")); // Not a leap year
}

test "parseIsoDate leap year" {
    // 2024 IS a leap year
    const ts = try parseIsoDate("2024-02-29");
    _ = ts;
}

test "daysUntilExpiry never expires" {
    const result = daysUntilExpiry(1000, 0, 2000);
    try std.testing.expect(result == null);
}

test "daysUntilExpiry future" {
    // Created at day 0, expires in 10 days, now is day 5
    const result = daysUntilExpiry(0, 86400 * 10, 86400 * 5);
    try std.testing.expectEqual(@as(i64, 5), result.?);
}

test "daysUntilExpiry expired" {
    // Created at day 0, expires in 5 days, now is day 10
    const result = daysUntilExpiry(0, 86400 * 5, 86400 * 10);
    try std.testing.expectEqual(@as(i64, -5), result.?);
}
