// SPDX-License-Identifier: MIT
//! OpenPGP Symmetric-Key Encrypted Session Key Packet (Tag 3)
//! per RFC 4880 Section 5.3.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const SymmetricAlgorithm = @import("../types/enums.zig").SymmetricAlgorithm;

/// RFC 4880 Section 5.3 — Symmetric-Key Encrypted Session Key Packet.
///
/// Layout (v4):
///   1 octet  — version (4)
///   1 octet  — symmetric algorithm
///   S2K specifier (variable length)
///   optional encrypted session key (remaining bytes)
pub const SKESKPacket = struct {
    version: u8,
    symmetric_algo: SymmetricAlgorithm,
    /// Raw S2K specifier bytes.
    s2k_data: []const u8,
    /// Optional encrypted session key (may be absent if the S2K
    /// produces the session key directly).
    encrypted_session_key: ?[]const u8,

    /// Parse the S2K specifier length from the body starting at `offset`.
    fn s2kLen(body: []const u8, offset: usize) !usize {
        if (offset >= body.len) return error.InvalidPacket;
        const s2k_type = body[offset];
        return switch (s2k_type) {
            0 => 2, // Simple S2K: type(1) + hash(1)
            1 => 10, // Salted S2K: type(1) + hash(1) + salt(8)
            3 => 11, // Iterated+Salted S2K: type(1) + hash(1) + salt(8) + count(1)
            else => 2, // Fallback: treat as simple
        };
    }

    /// Parse a SKESK Packet from the raw body bytes.
    pub fn parse(allocator: Allocator, body: []const u8) !SKESKPacket {
        // Minimum: version(1) + algo(1) + S2K(at least 2) = 4
        if (body.len < 4) return error.InvalidPacket;

        const version = body[0];
        if (version != 4) return error.UnsupportedVersion;

        const symmetric_algo: SymmetricAlgorithm = @enumFromInt(body[1]);

        // Parse S2K
        const s2k_length = try s2kLen(body, 2);
        if (2 + s2k_length > body.len) return error.InvalidPacket;
        const s2k_data = try allocator.dupe(u8, body[2 .. 2 + s2k_length]);
        errdefer allocator.free(s2k_data);

        const offset = 2 + s2k_length;
        const encrypted_session_key: ?[]const u8 = if (offset < body.len) blk: {
            const esk = try allocator.dupe(u8, body[offset..]);
            break :blk esk;
        } else null;

        return .{
            .version = version,
            .symmetric_algo = symmetric_algo,
            .s2k_data = s2k_data,
            .encrypted_session_key = encrypted_session_key,
        };
    }

    /// Free all allocator-owned memory.
    pub fn deinit(self: SKESKPacket, allocator: Allocator) void {
        allocator.free(self.s2k_data);
        if (self.encrypted_session_key) |esk| allocator.free(esk);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "SKESKPacket parse v4 with Simple S2K, no session key" {
    const allocator = std.testing.allocator;

    // version=4, algo=AES128(7), S2K: Simple(type=0, hash=SHA256(8))
    const body = [_]u8{ 4, 7, 0, 8 };

    const pkt = try SKESKPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 4), pkt.version);
    try std.testing.expectEqual(SymmetricAlgorithm.aes128, pkt.symmetric_algo);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 8 }, pkt.s2k_data);
    try std.testing.expect(pkt.encrypted_session_key == null);
}

test "SKESKPacket parse v4 with Salted S2K + encrypted session key" {
    const allocator = std.testing.allocator;

    // version=4, algo=AES256(9), S2K: Salted(type=1, hash=SHA256(8), salt=8 bytes)
    // + encrypted session key (3 bytes)
    var body: [15]u8 = undefined;
    body[0] = 4;
    body[1] = 9; // AES-256
    body[2] = 1; // Salted S2K
    body[3] = 8; // SHA256
    @memset(body[4..12], 0xAA); // salt
    body[12] = 0xDE; // encrypted session key
    body[13] = 0xAD;
    body[14] = 0xFF;

    const pkt = try SKESKPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(SymmetricAlgorithm.aes256, pkt.symmetric_algo);
    try std.testing.expectEqual(@as(usize, 10), pkt.s2k_data.len);
    try std.testing.expectEqual(@as(u8, 1), pkt.s2k_data[0]); // type
    try std.testing.expect(pkt.encrypted_session_key != null);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xFF }, pkt.encrypted_session_key.?);
}

test "SKESKPacket parse v4 with Iterated+Salted S2K" {
    const allocator = std.testing.allocator;

    // version=4, algo=CAST5(3), S2K: Iterated(type=3, hash=SHA1(2), salt=8, count=1)
    var body: [13]u8 = undefined;
    body[0] = 4;
    body[1] = 3; // CAST5
    body[2] = 3; // Iterated+Salted
    body[3] = 2; // SHA1
    @memset(body[4..12], 0xBB); // salt
    body[12] = 0x60; // count

    const pkt = try SKESKPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(SymmetricAlgorithm.cast5, pkt.symmetric_algo);
    try std.testing.expectEqual(@as(usize, 11), pkt.s2k_data.len);
    try std.testing.expect(pkt.encrypted_session_key == null);
}

test "SKESKPacket body too short" {
    const allocator = std.testing.allocator;
    const body = [_]u8{ 4, 7, 0 }; // 3 bytes, minimum is 4
    try std.testing.expectError(error.InvalidPacket, SKESKPacket.parse(allocator, &body));
}

test "SKESKPacket unsupported version" {
    const allocator = std.testing.allocator;
    const body = [_]u8{ 5, 7, 0, 8 };
    try std.testing.expectError(error.UnsupportedVersion, SKESKPacket.parse(allocator, &body));
}
