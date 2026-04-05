// SPDX-License-Identifier: MIT
//! Detached signature support per RFC 4880.
//!
//! A detached signature is a signature packet that is stored separately
//! from the data it signs.  This is used when the original document should
//! not be modified (e.g., signing a binary file).
//!
//! The signature covers the document data directly (for binary signatures,
//! sig_type 0x00) or a canonicalized version (for text signatures,
//! sig_type 0x01), followed by the V4 signature trailer.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const HashAlgorithm = @import("../types/enums.zig").HashAlgorithm;
const PublicKeyAlgorithm = @import("../types/enums.zig").PublicKeyAlgorithm;
const SignaturePacket = @import("../packets/signature.zig").SignaturePacket;
const PublicKeyPacket = @import("../packets/public_key.zig").PublicKeyPacket;
const armor = @import("../armor/armor.zig");
const sig_creation = @import("creation.zig");
const sig_verification = @import("verification.zig");

/// Result of verifying a detached signature.
pub const VerifyResult = struct {
    /// Whether the signature is cryptographically valid.
    valid: bool,
    /// Key ID of the signer (from the signature packet).
    signer_key_id: [8]u8,
    /// Signature creation time (from hashed subpackets), or null if absent.
    creation_time: ?u32,
    /// Hash algorithm used.
    hash_algo: HashAlgorithm,
};

/// Create a detached signature for data.
///
/// This function wraps pre-built signature packet bytes into the
/// appropriate format (binary or ASCII-armored).
///
/// For a complete signing flow, the caller should:
///   1. Build hashed subpackets (creation time, issuer key ID, etc.).
///   2. Compute the document hash using sig_creation.computeDocumentHash().
///   3. Sign the hash digest with the private key (RSA/DSA).
///   4. Assemble a V4 signature packet.
///   5. Pass the serialized packet bytes to this function.
pub fn createDetachedSignature(
    allocator: Allocator,
    signature_packet_bytes: []const u8,
    armored: bool,
) ![]u8 {
    if (armored) {
        return try armor.encode(allocator, signature_packet_bytes, .signature, null);
    } else {
        // For binary output, we need to add the OpenPGP packet header.
        // Tag 2 (Signature Packet) with new-format header.
        return try wrapInPacket(allocator, 2, signature_packet_bytes);
    }
}

/// Verify a detached signature against data.
///
/// The signature may be binary or ASCII-armored.  If armored, it is
/// decoded first.  The public key may also be armored.
///
/// Returns a VerifyResult with the verification outcome and metadata.
pub fn verifyDetachedSignature(
    allocator: Allocator,
    data: []const u8,
    signature: []const u8,
    public_key_data: []const u8,
) !VerifyResult {
    // Try to decode armor if present, otherwise use raw bytes
    const sig_bytes = try maybeDearmor(allocator, signature, .signature);
    defer if (sig_bytes.needs_free) allocator.free(sig_bytes.data);

    const key_bytes = try maybeDearmor(allocator, public_key_data, .public_key);
    defer if (key_bytes.needs_free) allocator.free(key_bytes.data);

    // Parse the signature packet.  Skip the packet header to get the body.
    const sig_body = try skipPacketHeader(sig_bytes.data);
    const sig_pkt = SignaturePacket.parse(allocator, sig_body) catch return error.InvalidSignature;
    defer sig_pkt.deinit(allocator);

    // Parse the public key packet.
    const key_body = try skipPacketHeader(key_bytes.data);
    const pub_key = PublicKeyPacket.parse(allocator, key_body, false) catch return error.InvalidKey;
    defer pub_key.deinit(allocator);

    // Extract key ID from unhashed subpackets (issuer subpacket, type 16)
    var signer_key_id: [8]u8 = [_]u8{0} ** 8;
    extractIssuerKeyId(sig_pkt.unhashed_subpacket_data, &signer_key_id);
    // Also try hashed subpackets
    if (mem.eql(u8, &signer_key_id, &([_]u8{0} ** 8))) {
        extractIssuerKeyId(sig_pkt.hashed_subpacket_data, &signer_key_id);
    }

    // Extract creation time from hashed subpackets (type 2)
    const creation_time = extractCreationTime(sig_pkt.hashed_subpacket_data);

    // Verify the signature
    const valid = sig_verification.verifyDocumentSignature(
        &sig_pkt,
        data,
        &pub_key,
        allocator,
    ) catch false;

    return .{
        .valid = valid,
        .signer_key_id = signer_key_id,
        .creation_time = creation_time,
        .hash_algo = sig_pkt.hash_algo,
    };
}

/// Result of a de-armor attempt: the data and whether it was allocated.
const DeArmorResult = struct {
    data: []const u8,
    needs_free: bool,
};

/// Try to decode ASCII armor.  If the data does not look armored, return
/// it as-is.
fn maybeDearmor(
    allocator: Allocator,
    data: []const u8,
    expected_type: armor.ArmorType,
) !DeArmorResult {
    _ = expected_type;

    // Quick check: does it look like ASCII armor?
    if (mem.indexOf(u8, data, "-----BEGIN ")) |_| {
        const result = armor.decode(allocator, data) catch return .{
            .data = data,
            .needs_free = false,
        };
        // Transfer ownership -- caller must free result.data
        const owned = result.data;
        // Free headers but not data
        for (result.headers) |hdr| {
            allocator.free(hdr.name);
            allocator.free(hdr.value);
        }
        allocator.free(result.headers);
        return .{
            .data = owned,
            .needs_free = true,
        };
    }

    return .{
        .data = data,
        .needs_free = false,
    };
}

/// Skip an OpenPGP packet header to get to the packet body.
///
/// Supports both old-format and new-format packet headers.
fn skipPacketHeader(data: []const u8) ![]const u8 {
    if (data.len < 2) return error.InvalidPacket;

    const tag_byte = data[0];

    // Check the always-1 bit
    if (tag_byte & 0x80 == 0) {
        // Not a valid packet header.  Might be a raw packet body already.
        // Try to use the data as-is (for the case where armor decoding
        // already stripped the header, or the data is just a body).
        return data;
    }

    if (tag_byte & 0x40 != 0) {
        // New-format packet header
        if (data.len < 2) return error.InvalidPacket;
        const len_byte = data[1];

        if (len_byte < 192) {
            // One-octet length
            const body_len: usize = len_byte;
            if (2 + body_len > data.len) return error.InvalidPacket;
            return data[2 .. 2 + body_len];
        } else if (len_byte < 224) {
            // Two-octet length
            if (data.len < 3) return error.InvalidPacket;
            const body_len: usize = (@as(usize, len_byte - 192) << 8) + @as(usize, data[2]) + 192;
            if (3 + body_len > data.len) return error.InvalidPacket;
            return data[3 .. 3 + body_len];
        } else if (len_byte == 255) {
            // Five-octet length
            if (data.len < 6) return error.InvalidPacket;
            const body_len: usize = mem.readInt(u32, data[2..6], .big);
            if (6 + body_len > data.len) return error.InvalidPacket;
            return data[6 .. 6 + body_len];
        }
        return error.InvalidPacket;
    } else {
        // Old-format packet header
        const length_type = tag_byte & 0x03;

        switch (length_type) {
            0 => {
                // 1-byte length
                if (data.len < 2) return error.InvalidPacket;
                const body_len: usize = data[1];
                if (2 + body_len > data.len) return error.InvalidPacket;
                return data[2 .. 2 + body_len];
            },
            1 => {
                // 2-byte length
                if (data.len < 3) return error.InvalidPacket;
                const body_len: usize = mem.readInt(u16, data[1..3], .big);
                if (3 + body_len > data.len) return error.InvalidPacket;
                return data[3 .. 3 + body_len];
            },
            2 => {
                // 4-byte length
                if (data.len < 5) return error.InvalidPacket;
                const body_len: usize = mem.readInt(u32, data[1..5], .big);
                if (5 + body_len > data.len) return error.InvalidPacket;
                return data[5 .. 5 + body_len];
            },
            3 => {
                // Indeterminate length -- rest of data is the body
                return data[1..];
            },
            else => unreachable,
        }
    }
}

/// Wrap a packet body with a new-format OpenPGP packet header.
fn wrapInPacket(allocator: Allocator, tag: u8, body: []const u8) ![]u8 {
    // New-format header: 0xC0 | tag
    const header_byte = 0xC0 | tag;

    if (body.len < 192) {
        // One-octet length
        const result = try allocator.alloc(u8, 2 + body.len);
        result[0] = header_byte;
        result[1] = @intCast(body.len);
        @memcpy(result[2..], body);
        return result;
    } else if (body.len < 8384) {
        // Two-octet length
        const adj = body.len - 192;
        const result = try allocator.alloc(u8, 3 + body.len);
        result[0] = header_byte;
        result[1] = @intCast((adj >> 8) + 192);
        result[2] = @intCast(adj & 0xFF);
        @memcpy(result[3..], body);
        return result;
    } else {
        // Five-octet length
        const result = try allocator.alloc(u8, 6 + body.len);
        result[0] = header_byte;
        result[1] = 255;
        mem.writeInt(u32, result[2..6], @intCast(body.len), .big);
        @memcpy(result[6..], body);
        return result;
    }
}

/// Extract the issuer key ID from a subpacket area.
///
/// Subpacket type 16 (Issuer) contains the 8-byte key ID.
fn extractIssuerKeyId(subpackets: []const u8, out: *[8]u8) void {
    var offset: usize = 0;
    while (offset < subpackets.len) {
        // Parse subpacket length
        if (offset >= subpackets.len) break;
        const sp_len_byte = subpackets[offset];
        var sp_len: usize = undefined;
        var sp_data_start: usize = undefined;

        if (sp_len_byte < 192) {
            sp_len = sp_len_byte;
            sp_data_start = offset + 1;
        } else if (sp_len_byte < 255) {
            if (offset + 1 >= subpackets.len) break;
            sp_len = (@as(usize, sp_len_byte - 192) << 8) + @as(usize, subpackets[offset + 1]) + 192;
            sp_data_start = offset + 2;
        } else {
            // 5-byte length
            if (offset + 4 >= subpackets.len) break;
            sp_len = mem.readInt(u32, subpackets[offset + 1 ..][0..4], .big);
            sp_data_start = offset + 5;
        }

        if (sp_len == 0 or sp_data_start >= subpackets.len) break;
        if (sp_data_start + sp_len > subpackets.len) break;

        // First byte of subpacket data is the type
        const sp_type = subpackets[sp_data_start] & 0x7F; // strip critical bit
        if (sp_type == 16 and sp_len >= 9) {
            // Issuer: 8 bytes after the type byte
            @memcpy(out, subpackets[sp_data_start + 1 .. sp_data_start + 9]);
            return;
        }

        offset = sp_data_start + sp_len;
    }
}

/// Extract the creation time from a subpacket area.
///
/// Subpacket type 2 (Signature Creation Time) contains a 4-byte timestamp.
fn extractCreationTime(subpackets: []const u8) ?u32 {
    var offset: usize = 0;
    while (offset < subpackets.len) {
        if (offset >= subpackets.len) break;
        const sp_len_byte = subpackets[offset];
        var sp_len: usize = undefined;
        var sp_data_start: usize = undefined;

        if (sp_len_byte < 192) {
            sp_len = sp_len_byte;
            sp_data_start = offset + 1;
        } else if (sp_len_byte < 255) {
            if (offset + 1 >= subpackets.len) break;
            sp_len = (@as(usize, sp_len_byte - 192) << 8) + @as(usize, subpackets[offset + 1]) + 192;
            sp_data_start = offset + 2;
        } else {
            if (offset + 4 >= subpackets.len) break;
            sp_len = mem.readInt(u32, subpackets[offset + 1 ..][0..4], .big);
            sp_data_start = offset + 5;
        }

        if (sp_len == 0 or sp_data_start >= subpackets.len) break;
        if (sp_data_start + sp_len > subpackets.len) break;

        const sp_type = subpackets[sp_data_start] & 0x7F;
        if (sp_type == 2 and sp_len >= 5) {
            return mem.readInt(u32, subpackets[sp_data_start + 1 ..][0..4], .big);
        }

        offset = sp_data_start + sp_len;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "createDetachedSignature armored" {
    const allocator = std.testing.allocator;

    const fake_body = "test signature body for armored detached sig";

    const armored_sig = try createDetachedSignature(allocator, fake_body, true);
    defer allocator.free(armored_sig);

    // Should contain armor markers
    try std.testing.expect(mem.indexOf(u8, armored_sig, "-----BEGIN PGP SIGNATURE-----") != null);
    try std.testing.expect(mem.indexOf(u8, armored_sig, "-----END PGP SIGNATURE-----") != null);
}

test "createDetachedSignature binary" {
    const allocator = std.testing.allocator;

    const fake_body = "short";

    const binary_sig = try createDetachedSignature(allocator, fake_body, false);
    defer allocator.free(binary_sig);

    // Should start with a packet header
    try std.testing.expect(binary_sig[0] & 0x80 != 0); // valid packet
    // Tag should be 2 (signature)
    try std.testing.expectEqual(@as(u8, 0xC2), binary_sig[0]);
}

test "wrapInPacket short body" {
    const allocator = std.testing.allocator;
    const body = "Hello";
    const result = try wrapInPacket(allocator, 2, body);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(u8, 0xC2), result[0]); // new-format tag 2
    try std.testing.expectEqual(@as(u8, 5), result[1]); // length = 5
    try std.testing.expectEqualSlices(u8, body, result[2..]);
}

test "wrapInPacket medium body" {
    const allocator = std.testing.allocator;
    // 200 bytes -- needs two-octet length
    const body = "A" ** 200;
    const result = try wrapInPacket(allocator, 2, body);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(u8, 0xC2), result[0]);
    // Two-octet length encoding: (200 - 192) = 8
    const decoded_len = (@as(usize, result[1]) - 192) * 256 + @as(usize, result[2]) + 192;
    try std.testing.expectEqual(@as(usize, 200), decoded_len);
}

test "skipPacketHeader new-format short" {
    // New-format packet: tag byte 0xC2, length 3, body "abc"
    const data = [_]u8{ 0xC2, 3, 'a', 'b', 'c' };
    const body = try skipPacketHeader(&data);
    try std.testing.expectEqualStrings("abc", body);
}

test "skipPacketHeader old-format one-byte length" {
    // Old-format: tag=2, length_type=0, length=3
    // Tag byte = 0x80 | (2 << 2) | 0 = 0x88
    const data = [_]u8{ 0x88, 3, 'x', 'y', 'z' };
    const body = try skipPacketHeader(&data);
    try std.testing.expectEqualStrings("xyz", body);
}

test "skipPacketHeader raw body fallback" {
    // Data that does not have the 0x80 bit set -- treated as raw body
    const data = [_]u8{ 0x04, 0x00, 0x01 };
    const body = try skipPacketHeader(&data);
    try std.testing.expectEqualSlices(u8, &data, body);
}

test "extractIssuerKeyId from subpackets" {
    // Build a subpacket area with an issuer subpacket (type 16, length 9)
    var subpackets: [20]u8 = undefined;
    // First subpacket: type 2 (creation time), length 5 (1 type + 4 data)
    subpackets[0] = 5; // length
    subpackets[1] = 2; // type
    mem.writeInt(u32, subpackets[2..6], 0x12345678, .big);
    // Second subpacket: type 16 (issuer), length 9 (1 type + 8 data)
    subpackets[6] = 9; // length
    subpackets[7] = 16; // type
    @memcpy(subpackets[8..16], &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 });

    var key_id: [8]u8 = [_]u8{0} ** 8;
    extractIssuerKeyId(subpackets[0..16], &key_id);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 }, &key_id);
}

test "extractCreationTime from subpackets" {
    // Build a creation time subpacket (type 2, length 5)
    var subpackets: [6]u8 = undefined;
    subpackets[0] = 5; // length
    subpackets[1] = 2; // type
    mem.writeInt(u32, subpackets[2..6], 0xDEADBEEF, .big);

    const ct = extractCreationTime(&subpackets);
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), ct.?);
}

test "extractCreationTime returns null for empty subpackets" {
    const ct = extractCreationTime(&[_]u8{});
    try std.testing.expect(ct == null);
}

test "extractIssuerKeyId no issuer subpacket" {
    // Only a creation time subpacket, no issuer
    var subpackets: [6]u8 = undefined;
    subpackets[0] = 5;
    subpackets[1] = 2;
    mem.writeInt(u32, subpackets[2..6], 100, .big);

    var key_id: [8]u8 = [_]u8{0xFF} ** 8;
    extractIssuerKeyId(&subpackets, &key_id);
    // Should remain unchanged (not found)
    try std.testing.expectEqualSlices(u8, &([_]u8{0xFF} ** 8), &key_id);
}

test "VerifyResult struct fields" {
    const vr = VerifyResult{
        .valid = true,
        .signer_key_id = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .creation_time = 1000,
        .hash_algo = .sha256,
    };
    try std.testing.expect(vr.valid);
    try std.testing.expectEqual(@as(u32, 1000), vr.creation_time.?);
    try std.testing.expectEqual(HashAlgorithm.sha256, vr.hash_algo);
}
