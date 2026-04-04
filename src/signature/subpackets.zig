// SPDX-License-Identifier: MIT
//! OpenPGP Signature Subpacket parsing per RFC 4880 Section 5.2.3.1.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// RFC 4880 Section 5.2.3.1 — Signature subpacket type tags.
pub const SubpacketTag = enum(u8) {
    creation_time = 2,
    expiration_time = 3,
    exportable = 4,
    trust_signature = 5,
    regular_expression = 6,
    revocable = 7,
    key_expiration_time = 9,
    preferred_symmetric = 11,
    revocation_key = 12,
    issuer = 16,
    notation_data = 20,
    preferred_hash = 21,
    preferred_compression = 22,
    key_server_preferences = 23,
    preferred_key_server = 24,
    primary_user_id = 25,
    policy_uri = 26,
    key_flags = 27,
    signers_user_id = 28,
    reason_for_revocation = 29,
    features = 30,
    signature_target = 31,
    embedded_signature = 32,
    issuer_fingerprint = 33,
    _,
};

/// Key usage flags per RFC 4880 Section 5.2.3.21.
pub const KeyFlags = packed struct(u8) {
    certify: bool,
    sign: bool,
    encrypt_communications: bool,
    encrypt_storage: bool,
    split_key: bool,
    authentication: bool,
    group_key: bool,
    _padding: u1 = 0,
};

/// Issuer fingerprint subpacket data (v4 keys).
pub const IssuerFingerprint = struct {
    version: u8,
    fingerprint: [20]u8,
};

/// A single parsed subpacket.
pub const Subpacket = struct {
    critical: bool,
    tag: SubpacketTag,
    data: []const u8,

    /// Interpret subpacket as a 4-byte big-endian creation timestamp.
    pub fn asCreationTime(self: Subpacket) ?u32 {
        if (self.tag != .creation_time) return null;
        if (self.data.len != 4) return null;
        return mem.readInt(u32, self.data[0..4], .big);
    }

    /// Interpret subpacket as a 4-byte big-endian expiration time offset.
    pub fn asExpirationTime(self: Subpacket) ?u32 {
        if (self.tag != .expiration_time) return null;
        if (self.data.len != 4) return null;
        return mem.readInt(u32, self.data[0..4], .big);
    }

    /// Interpret subpacket as a 4-byte big-endian key expiration time offset.
    pub fn asKeyExpirationTime(self: Subpacket) ?u32 {
        if (self.tag != .key_expiration_time) return null;
        if (self.data.len != 4) return null;
        return mem.readInt(u32, self.data[0..4], .big);
    }

    /// Interpret subpacket as an 8-byte issuer Key ID.
    pub fn asIssuer(self: Subpacket) ?[8]u8 {
        if (self.tag != .issuer) return null;
        if (self.data.len != 8) return null;
        return self.data[0..8].*;
    }

    /// Interpret subpacket as key usage flags.
    pub fn asKeyFlags(self: Subpacket) ?KeyFlags {
        if (self.tag != .key_flags) return null;
        if (self.data.len < 1) return null;
        return @bitCast(self.data[0]);
    }

    /// Interpret subpacket as an issuer fingerprint (version byte + 20-byte SHA-1).
    pub fn asIssuerFingerprint(self: Subpacket) ?IssuerFingerprint {
        if (self.tag != .issuer_fingerprint) return null;
        if (self.data.len < 21) return null;
        return IssuerFingerprint{
            .version = self.data[0],
            .fingerprint = self.data[1..21].*,
        };
    }

    /// Interpret subpacket as a boolean (exportable, revocable, primary_user_id).
    pub fn asBool(self: Subpacket) ?bool {
        if (self.data.len != 1) return null;
        return self.data[0] != 0;
    }
};

/// Parse a subpacket area (raw bytes from hashed_subpacket_data or unhashed_subpacket_data)
/// into an array of Subpacket structs. Caller must call `freeSubpackets` when done.
pub fn parseSubpackets(allocator: Allocator, data: []const u8) ![]Subpacket {
    var result: std.ArrayList(Subpacket) = .empty;
    errdefer result.deinit(allocator);

    var offset: usize = 0;
    while (offset < data.len) {
        // Decode subpacket length (RFC 4880 Section 5.2.3.1)
        if (offset >= data.len) break;
        var body_len: usize = undefined;
        const first = data[offset];
        offset += 1;

        if (first < 192) {
            body_len = @as(usize, first);
        } else if (first <= 254) {
            if (offset >= data.len) return error.InvalidSubpacket;
            const second = data[offset];
            offset += 1;
            body_len = (@as(usize, first) - 192) * 256 + @as(usize, second) + 192;
        } else {
            // first == 255
            if (offset + 4 > data.len) return error.InvalidSubpacket;
            body_len = mem.readInt(u32, data[offset..][0..4], .big);
            offset += 4;
        }

        // body_len includes the type byte
        if (body_len == 0) return error.InvalidSubpacket;
        if (offset + body_len > data.len) return error.InvalidSubpacket;

        // Type byte: bit 7 = critical, bits 6-0 = type
        const type_byte = data[offset];
        const critical = (type_byte & 0x80) != 0;
        const tag: SubpacketTag = @enumFromInt(type_byte & 0x7F);

        const subpacket_data = data[offset + 1 .. offset + body_len];

        try result.append(allocator, .{
            .critical = critical,
            .tag = tag,
            .data = subpacket_data,
        });

        offset += body_len;
    }

    return result.toOwnedSlice(allocator);
}

/// Find the first subpacket with a given tag.
pub fn findSubpacket(subpackets: []const Subpacket, tag: SubpacketTag) ?Subpacket {
    for (subpackets) |sp| {
        if (sp.tag == tag) return sp;
    }
    return null;
}

/// Free a subpackets array returned by `parseSubpackets`.
/// Note: the individual data slices point into the original subpacket area
/// and are not separately freed.
pub fn freeSubpackets(allocator: Allocator, subpackets: []Subpacket) void {
    allocator.free(subpackets);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseSubpackets creation time" {
    // Subpacket: length=5 (1 type byte + 4 data bytes), type=2 (creation_time)
    // Time = 0x5F000000
    const data = [_]u8{
        5, // length (short form)
        2, // type = creation_time
        0x5F, 0x00, 0x00, 0x00, // time
    };

    const allocator = std.testing.allocator;
    const subpackets = try parseSubpackets(allocator, &data);
    defer freeSubpackets(allocator, subpackets);

    try std.testing.expectEqual(@as(usize, 1), subpackets.len);
    try std.testing.expectEqual(SubpacketTag.creation_time, subpackets[0].tag);
    try std.testing.expect(!subpackets[0].critical);
    try std.testing.expectEqual(@as(u32, 0x5F000000), subpackets[0].asCreationTime().?);
}

test "parseSubpackets issuer key id" {
    // Subpacket: length=9, type=16 (issuer), data = 8 bytes of key ID
    const data = [_]u8{
        9, // length
        16, // type = issuer
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    };

    const allocator = std.testing.allocator;
    const subpackets = try parseSubpackets(allocator, &data);
    defer freeSubpackets(allocator, subpackets);

    try std.testing.expectEqual(@as(usize, 1), subpackets.len);
    const kid = subpackets[0].asIssuer().?;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE }, &kid);
}

test "parseSubpackets critical flag" {
    // Subpacket with critical bit set: type byte = 0x80 | 2 = 0x82
    const data = [_]u8{
        5,    // length
        0x82, // type = creation_time with critical bit
        0x00, 0x00, 0x00, 0x01,
    };

    const allocator = std.testing.allocator;
    const subpackets = try parseSubpackets(allocator, &data);
    defer freeSubpackets(allocator, subpackets);

    try std.testing.expectEqual(@as(usize, 1), subpackets.len);
    try std.testing.expect(subpackets[0].critical);
    try std.testing.expectEqual(SubpacketTag.creation_time, subpackets[0].tag);
}

test "parseSubpackets key flags" {
    // Subpacket: length=2, type=27 (key_flags), data = 1 byte flags
    // flags: certify=true, sign=true => bits 0,1 set => 0x03
    const data = [_]u8{
        2,    // length
        27,   // type = key_flags
        0x03, // certify + sign
    };

    const allocator = std.testing.allocator;
    const subpackets = try parseSubpackets(allocator, &data);
    defer freeSubpackets(allocator, subpackets);

    try std.testing.expectEqual(@as(usize, 1), subpackets.len);
    const flags = subpackets[0].asKeyFlags().?;
    try std.testing.expect(flags.certify);
    try std.testing.expect(flags.sign);
    try std.testing.expect(!flags.encrypt_communications);
    try std.testing.expect(!flags.encrypt_storage);
}

test "parseSubpackets multiple subpackets" {
    // Two subpackets: creation_time + issuer
    const data = [_]u8{
        5,    2, 0x5F, 0x00, 0x00, 0x00, // creation_time
        9,    16, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // issuer
    };

    const allocator = std.testing.allocator;
    const subpackets = try parseSubpackets(allocator, &data);
    defer freeSubpackets(allocator, subpackets);

    try std.testing.expectEqual(@as(usize, 2), subpackets.len);
    try std.testing.expectEqual(SubpacketTag.creation_time, subpackets[0].tag);
    try std.testing.expectEqual(SubpacketTag.issuer, subpackets[1].tag);
}

test "parseSubpackets two-byte length encoding" {
    // Two-byte length: first byte in 192..254
    // Length = (first - 192) * 256 + second + 192
    // For length = 192: first=192, second=0 => (192-192)*256 + 0 + 192 = 192
    // We'll use length = 193: first=192, second=1 => (0)*256 + 1 + 192 = 193
    // This means 193 bytes of body (1 type + 192 data)
    var data: [195]u8 = undefined;
    data[0] = 192; // first byte of length
    data[1] = 1; // second byte of length => body_len = 193
    data[2] = 20; // type = notation_data
    @memset(data[3..195], 0xAA); // 192 bytes of data

    const allocator = std.testing.allocator;
    const subpackets = try parseSubpackets(allocator, &data);
    defer freeSubpackets(allocator, subpackets);

    try std.testing.expectEqual(@as(usize, 1), subpackets.len);
    try std.testing.expectEqual(SubpacketTag.notation_data, subpackets[0].tag);
    try std.testing.expectEqual(@as(usize, 192), subpackets[0].data.len);
}

test "parseSubpackets four-byte length encoding" {
    // Four-byte length: first byte == 255, followed by 4-byte big-endian length
    // Length = 5 (1 type + 4 data)
    const data = [_]u8{
        255,
        0x00, 0x00, 0x00, 0x05, // body_len = 5
        2, // type = creation_time
        0x00, 0x00, 0x00, 0x01, // time = 1
    };

    const allocator = std.testing.allocator;
    const subpackets = try parseSubpackets(allocator, &data);
    defer freeSubpackets(allocator, subpackets);

    try std.testing.expectEqual(@as(usize, 1), subpackets.len);
    try std.testing.expectEqual(@as(u32, 1), subpackets[0].asCreationTime().?);
}

test "parseSubpackets issuer fingerprint" {
    // Subpacket: length=22, type=33 (issuer_fingerprint), data = version(1) + fingerprint(20)
    var data: [23]u8 = undefined;
    data[0] = 22; // length
    data[1] = 33; // type = issuer_fingerprint
    data[2] = 4; // version
    for (0..20) |i| {
        data[3 + i] = @intCast(i);
    }

    const allocator = std.testing.allocator;
    const subpackets = try parseSubpackets(allocator, &data);
    defer freeSubpackets(allocator, subpackets);

    try std.testing.expectEqual(@as(usize, 1), subpackets.len);
    const ifp = subpackets[0].asIssuerFingerprint().?;
    try std.testing.expectEqual(@as(u8, 4), ifp.version);
    var expected_fp: [20]u8 = undefined;
    for (0..20) |i| {
        expected_fp[i] = @intCast(i);
    }
    try std.testing.expectEqualSlices(u8, &expected_fp, &ifp.fingerprint);
}

test "parseSubpackets empty area" {
    const allocator = std.testing.allocator;
    const subpackets = try parseSubpackets(allocator, &[_]u8{});
    defer freeSubpackets(allocator, subpackets);

    try std.testing.expectEqual(@as(usize, 0), subpackets.len);
}

test "findSubpacket returns first match" {
    const data = [_]u8{
        5,    2, 0x5F, 0x00, 0x00, 0x00, // creation_time #1
        5,    2, 0x60, 0x00, 0x00, 0x00, // creation_time #2
    };

    const allocator = std.testing.allocator;
    const subpackets = try parseSubpackets(allocator, &data);
    defer freeSubpackets(allocator, subpackets);

    const found = findSubpacket(subpackets, .creation_time);
    try std.testing.expect(found != null);
    try std.testing.expectEqual(@as(u32, 0x5F000000), found.?.asCreationTime().?);
}

test "findSubpacket returns null for missing tag" {
    const data = [_]u8{
        5, 2, 0x5F, 0x00, 0x00, 0x00,
    };

    const allocator = std.testing.allocator;
    const subpackets = try parseSubpackets(allocator, &data);
    defer freeSubpackets(allocator, subpackets);

    try std.testing.expect(findSubpacket(subpackets, .issuer) == null);
}

test "parseSubpackets invalid zero-length body" {
    const data = [_]u8{0}; // length=0, which is invalid (no type byte)
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidSubpacket, parseSubpackets(allocator, &data));
}

test "parseSubpackets truncated data" {
    const data = [_]u8{10, 2}; // claims length=10, but only 1 byte of body available
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidSubpacket, parseSubpackets(allocator, &data));
}
