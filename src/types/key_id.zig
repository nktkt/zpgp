// SPDX-License-Identifier: MIT
//! Key ID and Fingerprint types and formatting utilities.
//!
//! Per RFC 4880, a Key ID is the low 64 bits (8 bytes) of the key fingerprint,
//! and a V4 fingerprint is the 160-bit SHA-1 hash of the key material.

const std = @import("std");

/// 8-byte Key ID (low 64 bits of the fingerprint).
pub const KeyId = [8]u8;

/// 20-byte V4 fingerprint (SHA-1).
pub const Fingerprint = [20]u8;

const hex_charset = "0123456789ABCDEF";

/// Format a Key ID as a 16-character uppercase hex string.
pub fn formatKeyId(id: KeyId) [16]u8 {
    return std.fmt.bytesToHex(id, .upper);
}

/// Format a Fingerprint as a 40-character uppercase hex string.
pub fn formatFingerprint(fp: Fingerprint) [40]u8 {
    return std.fmt.bytesToHex(fp, .upper);
}

/// Extract a Key ID from a fingerprint (last 8 bytes per RFC 4880 Section 12.2).
pub fn keyIdFromFingerprint(fp: Fingerprint) KeyId {
    return fp[12..20].*;
}

/// Parse a 16-character hex string into a Key ID.
/// Returns error.InvalidCharacter if the input contains non-hex characters.
pub fn parseKeyId(hex: *const [16]u8) ![8]u8 {
    var result: [8]u8 = undefined;
    for (0..8) |i| {
        const hi: u8 = try hexDigit(hex[i * 2]);
        const lo: u8 = try hexDigit(hex[i * 2 + 1]);
        result[i] = (hi << 4) | lo;
    }
    return result;
}

/// Parse a 40-character hex string into a Fingerprint.
pub fn parseFingerprint(hex: *const [40]u8) ![20]u8 {
    var result: [20]u8 = undefined;
    for (0..20) |i| {
        const hi: u8 = try hexDigit(hex[i * 2]);
        const lo: u8 = try hexDigit(hex[i * 2 + 1]);
        result[i] = (hi << 4) | lo;
    }
    return result;
}

fn hexDigit(c: u8) !u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'A'...'F' => @intCast(c - 'A' + 10),
        'a'...'f' => @intCast(c - 'a' + 10),
        else => error.InvalidCharacter,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "formatKeyId" {
    const id = KeyId{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
    const hex = formatKeyId(id);
    try std.testing.expectEqualStrings("DEADBEEFCAFEBABE", &hex);
}

test "formatKeyId all zeros" {
    const id = KeyId{ 0, 0, 0, 0, 0, 0, 0, 0 };
    const hex = formatKeyId(id);
    try std.testing.expectEqualStrings("0000000000000000", &hex);
}

test "formatFingerprint" {
    var fp: Fingerprint = undefined;
    for (0..20) |i| {
        fp[i] = @intCast(i);
    }
    const hex = formatFingerprint(fp);
    try std.testing.expectEqualStrings("000102030405060708090A0B0C0D0E0F10111213", &hex);
}

test "keyIdFromFingerprint" {
    var fp: Fingerprint = undefined;
    for (0..20) |i| {
        fp[i] = @intCast(i * 10);
    }
    const kid = keyIdFromFingerprint(fp);
    // Last 8 bytes: indices 12..20, values 120,130,140,150,160,170,180,190
    try std.testing.expectEqualSlices(u8, &[_]u8{ 120, 130, 140, 150, 160, 170, 180, 190 }, &kid);
}

test "formatKeyId and parseKeyId round-trip" {
    const original = KeyId{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    const hex = formatKeyId(original);
    const parsed = try parseKeyId(&hex);
    try std.testing.expectEqualSlices(u8, &original, &parsed);
}

test "formatFingerprint and parseFingerprint round-trip" {
    var original: Fingerprint = undefined;
    for (0..20) |i| {
        original[i] = @intCast(i * 13);
    }
    const hex = formatFingerprint(original);
    const parsed = try parseFingerprint(&hex);
    try std.testing.expectEqualSlices(u8, &original, &parsed);
}

test "parseKeyId invalid character" {
    const bad = "ZZZZZZZZZZZZZZZZ";
    try std.testing.expectError(error.InvalidCharacter, parseKeyId(bad));
}

test "keyIdFromFingerprint matches format" {
    var fp: Fingerprint = undefined;
    @memset(&fp, 0xFF);
    // Override last 8 bytes.
    const tail = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    @memcpy(fp[12..20], &tail);

    const kid = keyIdFromFingerprint(fp);
    try std.testing.expectEqualSlices(u8, &tail, &kid);

    const hex = formatKeyId(kid);
    try std.testing.expectEqualStrings("0102030405060708", &hex);
}
