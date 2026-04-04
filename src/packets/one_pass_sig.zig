// SPDX-License-Identifier: MIT
//! OpenPGP One-Pass Signature Packet (Tag 4) per RFC 4880 Section 5.4.

const std = @import("std");
const mem = std.mem;

const enums = @import("../types/enums.zig");
const HashAlgorithm = enums.HashAlgorithm;
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;

/// RFC 4880 Section 5.4 — One-Pass Signature Packet.
///
/// Layout (always 13 bytes):
///   1 octet  — version (must be 3)
///   1 octet  — signature type
///   1 octet  — hash algorithm
///   1 octet  — public-key algorithm
///   8 octets — key ID
///   1 octet  — nested flag (0 = nested, 1 = not nested / last)
pub const OnePassSignaturePacket = struct {
    version: u8,
    sig_type: u8,
    hash_algo: HashAlgorithm,
    pub_algo: PublicKeyAlgorithm,
    key_id: [8]u8,
    nested: u8,

    /// Parse a One-Pass Signature Packet from the raw body bytes.
    pub fn parse(body: []const u8) !OnePassSignaturePacket {
        if (body.len != 13) return error.InvalidPacket;

        return .{
            .version = body[0],
            .sig_type = body[1],
            .hash_algo = @enumFromInt(body[2]),
            .pub_algo = @enumFromInt(body[3]),
            .key_id = body[4..12].*,
            .nested = body[12],
        };
    }

    /// Serialize the packet body — always exactly 13 bytes.
    pub fn serialize(self: OnePassSignaturePacket) [13]u8 {
        var buf: [13]u8 = undefined;
        buf[0] = self.version;
        buf[1] = self.sig_type;
        buf[2] = @intFromEnum(self.hash_algo);
        buf[3] = @intFromEnum(self.pub_algo);
        @memcpy(buf[4..12], &self.key_id);
        buf[12] = self.nested;
        return buf;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "OnePassSignaturePacket parse and serialize round-trip" {
    const body = [13]u8{
        3, // version
        0x00, // sig_type: binary signature
        2, // hash_algo: SHA1
        1, // pub_algo: RSA
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, // key_id
        1, // nested: not nested (last)
    };

    const pkt = try OnePassSignaturePacket.parse(&body);

    try std.testing.expectEqual(@as(u8, 3), pkt.version);
    try std.testing.expectEqual(@as(u8, 0x00), pkt.sig_type);
    try std.testing.expectEqual(HashAlgorithm.sha1, pkt.hash_algo);
    try std.testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, pkt.pub_algo);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE }, &pkt.key_id);
    try std.testing.expectEqual(@as(u8, 1), pkt.nested);

    const serialized = pkt.serialize();
    try std.testing.expectEqualSlices(u8, &body, &serialized);
}

test "OnePassSignaturePacket wrong body length" {
    const short = [_]u8{ 3, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0 }; // 12 bytes
    try std.testing.expectError(error.InvalidPacket, OnePassSignaturePacket.parse(&short));

    const long = [_]u8{ 3, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xFF }; // 14 bytes
    try std.testing.expectError(error.InvalidPacket, OnePassSignaturePacket.parse(&long));
}

test "OnePassSignaturePacket DSA + SHA256" {
    const body = [13]u8{
        3, // version
        0x01, // sig_type: text signature
        8, // hash_algo: SHA256
        17, // pub_algo: DSA
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // key_id
        0, // nested
    };

    const pkt = try OnePassSignaturePacket.parse(&body);

    try std.testing.expectEqual(HashAlgorithm.sha256, pkt.hash_algo);
    try std.testing.expectEqual(PublicKeyAlgorithm.dsa, pkt.pub_algo);
    try std.testing.expectEqual(@as(u8, 0), pkt.nested);
}
