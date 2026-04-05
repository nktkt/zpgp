// SPDX-License-Identifier: MIT
//! Notation Data subpacket support per RFC 4880 Section 5.2.3.16.
//!
//! Notation data (subpacket type 20) allows attaching arbitrary name-value
//! pairs to signatures. The format is:
//!   4 bytes  — flags (bit 0 of byte 0 = human-readable)
//!   2 bytes  — name length (big-endian)
//!   2 bytes  — value length (big-endian)
//!   N bytes  — name (UTF-8)
//!   M bytes  — value (UTF-8 if human-readable, else octets)

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const subpackets_mod = @import("subpackets.zig");
const SubpacketTag = subpackets_mod.SubpacketTag;
const SignaturePacket = @import("../packets/signature.zig").SignaturePacket;

/// A single notation data entry.
pub const NotationData = struct {
    human_readable: bool,
    name: []const u8,
    value: []const u8,

    /// Free owned copies of name and value.
    pub fn deinit(self: NotationData, allocator: Allocator) void {
        allocator.free(self.name);
        allocator.free(self.value);
    }
};

/// Parse notation data from a raw subpacket data body.
///
/// The data format is:
///   flags[4] + name_len[2] + value_len[2] + name[name_len] + value[value_len]
///
/// Returns an owned NotationData. Caller must call deinit.
pub fn parseNotation(data: []const u8, allocator: Allocator) !NotationData {
    if (data.len < 8) return error.InvalidNotation;

    // Flags: 4 bytes, bit 0 of first byte = human-readable
    const human_readable = (data[0] & 0x80) != 0;

    const name_len = mem.readInt(u16, data[4..6], .big);
    const value_len = mem.readInt(u16, data[6..8], .big);

    const expected_len: usize = 8 + @as(usize, name_len) + @as(usize, value_len);
    if (data.len < expected_len) return error.InvalidNotation;

    const name = try allocator.dupe(u8, data[8 .. 8 + name_len]);
    errdefer allocator.free(name);
    const value = try allocator.dupe(u8, data[8 + name_len .. 8 + name_len + value_len]);

    return .{
        .human_readable = human_readable,
        .name = name,
        .value = value,
    };
}

/// Create the body bytes for a notation data subpacket.
///
/// The returned bytes are suitable as the data portion of a subpacket
/// with tag 20 (notation_data). Caller owns the returned slice.
pub fn createNotation(
    allocator: Allocator,
    name: []const u8,
    value: []const u8,
    human_readable: bool,
) ![]u8 {
    const name_len: u16 = @intCast(name.len);
    const value_len: u16 = @intCast(value.len);
    const total: usize = 8 + name.len + value.len;

    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);

    // Flags: 4 bytes
    buf[0] = if (human_readable) 0x80 else 0x00;
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;

    // Name length (2 bytes BE)
    mem.writeInt(u16, buf[4..6], name_len, .big);

    // Value length (2 bytes BE)
    mem.writeInt(u16, buf[6..8], value_len, .big);

    // Name
    if (name.len > 0) {
        @memcpy(buf[8 .. 8 + name.len], name);
    }

    // Value
    if (value.len > 0) {
        @memcpy(buf[8 + name.len .. 8 + name.len + value.len], value);
    }

    return buf;
}

/// Extract all notation data entries from a signature's hashed subpackets.
///
/// Returns an owned slice of NotationData. Caller must call freeNotations.
pub fn getNotations(sig: *const SignaturePacket, allocator: Allocator) ![]NotationData {
    var result: std.ArrayList(NotationData) = .empty;
    errdefer {
        for (result.items) |n| n.deinit(allocator);
        result.deinit(allocator);
    }

    // Parse hashed subpackets
    const hashed_subs = try subpackets_mod.parseSubpackets(allocator, sig.hashed_subpacket_data);
    defer subpackets_mod.freeSubpackets(allocator, hashed_subs);

    for (hashed_subs) |sp| {
        if (sp.tag == .notation_data) {
            const notation = parseNotation(sp.data, allocator) catch continue;
            try result.append(allocator, notation);
        }
    }

    // Also check unhashed subpackets
    const unhashed_subs = try subpackets_mod.parseSubpackets(allocator, sig.unhashed_subpacket_data);
    defer subpackets_mod.freeSubpackets(allocator, unhashed_subs);

    for (unhashed_subs) |sp| {
        if (sp.tag == .notation_data) {
            const notation = parseNotation(sp.data, allocator) catch continue;
            try result.append(allocator, notation);
        }
    }

    return result.toOwnedSlice(allocator);
}

/// Free a slice of NotationData returned by getNotations.
pub fn freeNotations(notations: []NotationData, allocator: Allocator) void {
    for (notations) |n| {
        n.deinit(allocator);
    }
    allocator.free(notations);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "createNotation human-readable" {
    const allocator = std.testing.allocator;

    const data = try createNotation(allocator, "test@example.com", "hello world", true);
    defer allocator.free(data);

    // Check structure
    try std.testing.expect(data.len == 8 + 16 + 11);
    // Flags: human-readable
    try std.testing.expectEqual(@as(u8, 0x80), data[0]);
    try std.testing.expectEqual(@as(u8, 0), data[1]);
    try std.testing.expectEqual(@as(u8, 0), data[2]);
    try std.testing.expectEqual(@as(u8, 0), data[3]);
    // Name length = 16
    try std.testing.expectEqual(@as(u16, 16), mem.readInt(u16, data[4..6], .big));
    // Value length = 11
    try std.testing.expectEqual(@as(u16, 11), mem.readInt(u16, data[6..8], .big));
    // Name
    try std.testing.expectEqualStrings("test@example.com", data[8..24]);
    // Value
    try std.testing.expectEqualStrings("hello world", data[24..35]);
}

test "createNotation non-human-readable" {
    const allocator = std.testing.allocator;

    const data = try createNotation(allocator, "binary-data", &[_]u8{ 0x00, 0xFF }, false);
    defer allocator.free(data);

    try std.testing.expectEqual(@as(u8, 0x00), data[0]); // not human-readable
    try std.testing.expectEqual(@as(u16, 11), mem.readInt(u16, data[4..6], .big));
    try std.testing.expectEqual(@as(u16, 2), mem.readInt(u16, data[6..8], .big));
}

test "parseNotation round-trip" {
    const allocator = std.testing.allocator;

    const data = try createNotation(allocator, "issuer@example.org", "my notation value", true);
    defer allocator.free(data);

    const notation = try parseNotation(data, allocator);
    defer notation.deinit(allocator);

    try std.testing.expect(notation.human_readable);
    try std.testing.expectEqualStrings("issuer@example.org", notation.name);
    try std.testing.expectEqualStrings("my notation value", notation.value);
}

test "parseNotation empty value" {
    const allocator = std.testing.allocator;

    const data = try createNotation(allocator, "flag", "", true);
    defer allocator.free(data);

    const notation = try parseNotation(data, allocator);
    defer notation.deinit(allocator);

    try std.testing.expectEqualStrings("flag", notation.name);
    try std.testing.expectEqual(@as(usize, 0), notation.value.len);
}

test "parseNotation too short" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidNotation, parseNotation(&[_]u8{ 0, 0, 0 }, allocator));
}

test "parseNotation truncated data" {
    const allocator = std.testing.allocator;
    // Flags(4) + name_len=10(2) + value_len=5(2) but no actual name/value data
    var data: [8]u8 = undefined;
    data[0] = 0x80;
    data[1] = 0;
    data[2] = 0;
    data[3] = 0;
    mem.writeInt(u16, data[4..6], 10, .big);
    mem.writeInt(u16, data[6..8], 5, .big);

    try std.testing.expectError(error.InvalidNotation, parseNotation(&data, allocator));
}

test "getNotations from signature with notation subpacket" {
    const allocator = std.testing.allocator;

    // Build a notation subpacket
    const notation_body = try createNotation(allocator, "test@key", "value123", true);
    defer allocator.free(notation_body);

    // Build hashed subpacket area: length + tag(20) + notation_body
    const sp_body_len = 1 + notation_body.len; // tag + data
    var hashed_sp: std.ArrayList(u8) = .empty;
    defer hashed_sp.deinit(allocator);

    // Subpacket length
    if (sp_body_len < 192) {
        try hashed_sp.append(allocator, @intCast(sp_body_len));
    } else {
        const adjusted = sp_body_len - 192;
        try hashed_sp.append(allocator, @intCast(adjusted / 256 + 192));
        try hashed_sp.append(allocator, @intCast(adjusted % 256));
    }
    try hashed_sp.append(allocator, 20); // notation_data tag
    try hashed_sp.appendSlice(allocator, notation_body);

    const hashed_data = try hashed_sp.toOwnedSlice(allocator);
    defer allocator.free(hashed_data);

    // Build minimal signature packet body
    var sig_body: std.ArrayList(u8) = .empty;
    defer sig_body.deinit(allocator);

    try sig_body.append(allocator, 4); // version
    try sig_body.append(allocator, 0x13); // positive certification
    try sig_body.append(allocator, 1); // RSA
    try sig_body.append(allocator, 8); // SHA256

    // Hashed subpackets
    const h_len: u16 = @intCast(hashed_data.len);
    var h_len_buf: [2]u8 = undefined;
    mem.writeInt(u16, &h_len_buf, h_len, .big);
    try sig_body.appendSlice(allocator, &h_len_buf);
    try sig_body.appendSlice(allocator, hashed_data);

    // No unhashed subpackets
    try sig_body.appendSlice(allocator, &[_]u8{ 0, 0 });

    // Hash prefix
    try sig_body.appendSlice(allocator, &[_]u8{ 0xAA, 0xBB });

    // Signature MPI placeholder
    try sig_body.appendSlice(allocator, &[_]u8{ 0x00, 0x01, 0x00 });

    const sig_bytes = try sig_body.toOwnedSlice(allocator);
    defer allocator.free(sig_bytes);

    const sig = try SignaturePacket.parse(allocator, sig_bytes);
    defer sig.deinit(allocator);

    const notations = try getNotations(&sig, allocator);
    defer freeNotations(notations, allocator);

    try std.testing.expectEqual(@as(usize, 1), notations.len);
    try std.testing.expectEqualStrings("test@key", notations[0].name);
    try std.testing.expectEqualStrings("value123", notations[0].value);
    try std.testing.expect(notations[0].human_readable);
}

test "getNotations from signature with no notations" {
    const allocator = std.testing.allocator;

    // Build minimal signature without notations
    var sig_body: [13]u8 = undefined;
    sig_body[0] = 4;
    sig_body[1] = 0x00;
    sig_body[2] = 1;
    sig_body[3] = 8;
    mem.writeInt(u16, sig_body[4..6], 0, .big);
    mem.writeInt(u16, sig_body[6..8], 0, .big);
    sig_body[8] = 0xAB;
    sig_body[9] = 0xCD;
    mem.writeInt(u16, sig_body[10..12], 8, .big);
    sig_body[12] = 0xFF;

    const sig = try SignaturePacket.parse(allocator, sig_body[0..13]);
    defer sig.deinit(allocator);

    const notations = try getNotations(&sig, allocator);
    defer freeNotations(notations, allocator);

    try std.testing.expectEqual(@as(usize, 0), notations.len);
}

test "freeNotations empty slice" {
    const allocator = std.testing.allocator;
    const empty = try allocator.alloc(NotationData, 0);
    freeNotations(empty, allocator);
}

test "createNotation empty name" {
    const allocator = std.testing.allocator;

    const data = try createNotation(allocator, "", "value", true);
    defer allocator.free(data);

    try std.testing.expectEqual(@as(usize, 8 + 0 + 5), data.len);
    try std.testing.expectEqual(@as(u16, 0), mem.readInt(u16, data[4..6], .big));
    try std.testing.expectEqual(@as(u16, 5), mem.readInt(u16, data[6..8], .big));
}

test "parseNotation non-human-readable" {
    const allocator = std.testing.allocator;

    const data = try createNotation(allocator, "bin", &[_]u8{ 0xDE, 0xAD }, false);
    defer allocator.free(data);

    const notation = try parseNotation(data, allocator);
    defer notation.deinit(allocator);

    try std.testing.expect(!notation.human_readable);
    try std.testing.expectEqualStrings("bin", notation.name);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD }, notation.value);
}
