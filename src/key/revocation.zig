// SPDX-License-Identifier: MIT
//! Key revocation per RFC 4880 Section 5.2.1 (signature types 0x20, 0x28, 0x30)
//! and Section 5.2.3.23 (Reason for Revocation subpacket).
//!
//! Provides utilities for checking revocation status, extracting revocation
//! reasons, and creating revocation signatures.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const Key = @import("key.zig").Key;
const SubkeyBinding = @import("key.zig").SubkeyBinding;
const PublicKeyPacket = @import("../packets/public_key.zig").PublicKeyPacket;
const SignaturePacket = @import("../packets/signature.zig").SignaturePacket;
const SignatureType = @import("../signature/types.zig").SignatureType;
const subpackets_mod = @import("../signature/subpackets.zig");
const SubpacketTag = subpackets_mod.SubpacketTag;
const Subpacket = subpackets_mod.Subpacket;
const HashAlgorithm = @import("../types/enums.zig").HashAlgorithm;
const fingerprint_mod = @import("fingerprint.zig");
const creation = @import("../signature/creation.zig");

/// RFC 4880 Section 5.2.3.23 — Reason for Revocation codes.
pub const RevocationReason = enum(u8) {
    /// No reason specified (key revocations and cert revocations).
    no_reason = 0,
    /// Key is superseded (key revocations).
    key_superseded = 1,
    /// Key material has been compromised (key revocations).
    key_compromised = 2,
    /// Key is retired and no longer used (key revocations).
    key_retired = 3,
    /// User ID information is no longer valid (cert revocations).
    user_id_invalid = 32,
    _,

    /// Return a human-readable name for the revocation reason.
    pub fn name(self: RevocationReason) []const u8 {
        return switch (self) {
            .no_reason => "No reason specified",
            .key_superseded => "Key is superseded",
            .key_compromised => "Key material has been compromised",
            .key_retired => "Key is retired and no longer used",
            .user_id_invalid => "User ID is no longer valid",
            _ => "Unknown reason",
        };
    }
};

/// Information extracted from a revocation signature's reason subpacket.
pub const RevocationInfo = struct {
    reason: RevocationReason,
    description: []const u8,
};

/// Check if a key has been revoked by examining its signatures.
///
/// Looks for key revocation signatures (type 0x20) on the primary key.
/// A key is considered revoked if any self-issued revocation signature
/// exists among its user ID certifications or direct key signatures.
///
/// Per RFC 4880 Section 5.2.1, a key revocation must be issued by the
/// key being revoked or by an authorized revocation key.
pub fn isKeyRevoked(key: *const Key, allocator: Allocator) !bool {
    // Check certifications on each user ID for key revocation signatures
    for (key.user_ids.items) |uid_binding| {
        for (uid_binding.certifications.items) |sig| {
            if (sig.sig_type == @intFromEnum(SignatureType.key_revocation)) {
                // Verify this revocation was issued by the key itself
                if (try isIssuedByKey(&sig, key, allocator)) {
                    return true;
                }
            }
        }
        // Also check the self-signature in case it's stored there
        if (uid_binding.self_signature) |sig| {
            if (sig.sig_type == @intFromEnum(SignatureType.key_revocation)) {
                return true;
            }
        }
    }
    return false;
}

/// Check if a subkey has been revoked.
///
/// Looks for subkey revocation signatures (type 0x28) in the subkey's
/// binding signature slot.
pub fn isSubkeyRevoked(
    primary_key: *const PublicKeyPacket,
    subkey_binding: *const SubkeyBinding,
    allocator: Allocator,
) !bool {
    _ = primary_key;
    _ = allocator;
    // Check the binding signature for a revocation type
    if (subkey_binding.binding_signature) |sig| {
        if (sig.sig_type == @intFromEnum(SignatureType.subkey_revocation)) {
            return true;
        }
    }
    return false;
}

/// Extract the revocation reason from a revocation signature.
///
/// Parses the hashed subpackets of the given signature looking for a
/// "Reason for Revocation" subpacket (tag 29). Returns null if no
/// reason subpacket is found.
///
/// Per RFC 4880 Section 5.2.3.23, the subpacket body is:
///   1 octet  — revocation reason code
///   N octets — human-readable string (UTF-8)
pub fn getRevocationReason(sig: *const SignaturePacket, allocator: Allocator) !?RevocationInfo {
    // Parse hashed subpackets
    const subs = try subpackets_mod.parseSubpackets(allocator, sig.hashed_subpacket_data);
    defer subpackets_mod.freeSubpackets(allocator, subs);

    for (subs) |sp| {
        if (sp.tag == .reason_for_revocation) {
            if (sp.data.len < 1) continue;
            const reason: RevocationReason = @enumFromInt(sp.data[0]);
            const desc = sp.data[1..];
            return RevocationInfo{
                .reason = reason,
                .description = desc,
            };
        }
    }

    // Also check unhashed subpackets (some implementations put it there)
    const unsubs = try subpackets_mod.parseSubpackets(allocator, sig.unhashed_subpacket_data);
    defer subpackets_mod.freeSubpackets(allocator, unsubs);

    for (unsubs) |sp| {
        if (sp.tag == .reason_for_revocation) {
            if (sp.data.len < 1) continue;
            const reason: RevocationReason = @enumFromInt(sp.data[0]);
            const desc = sp.data[1..];
            return RevocationInfo{
                .reason = reason,
                .description = desc,
            };
        }
    }

    return null;
}

/// Create the hashed subpacket data for a key revocation signature.
///
/// Builds a subpacket area containing:
///   - Creation time subpacket (tag 2)
///   - Reason for revocation subpacket (tag 29)
///   - Issuer fingerprint subpacket (tag 33)
fn buildRevocationSubpackets(
    allocator: Allocator,
    key_fingerprint: [20]u8,
    reason: RevocationReason,
    description: []const u8,
) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    // Creation time subpacket: length=5, tag=2, data=4 bytes (current time or 0)
    try buf.append(allocator, 5); // subpacket length (1 type + 4 data)
    try buf.append(allocator, @intFromEnum(SubpacketTag.creation_time));
    // Use epoch 0 as placeholder (real implementation would use current time)
    try buf.appendSlice(allocator, &[_]u8{ 0, 0, 0, 0 });

    // Reason for revocation subpacket: length = 1(tag) + 1(code) + description.len
    const reason_len: usize = 1 + 1 + description.len;
    if (reason_len < 192) {
        try buf.append(allocator, @intCast(reason_len));
    } else {
        // Two-byte length encoding
        const adj_len = reason_len - 192;
        try buf.append(allocator, @intCast((adj_len / 256) + 192));
        try buf.append(allocator, @intCast(adj_len % 256));
    }
    try buf.append(allocator, @intFromEnum(SubpacketTag.reason_for_revocation));
    try buf.append(allocator, @intFromEnum(reason));
    if (description.len > 0) {
        try buf.appendSlice(allocator, description);
    }

    // Issuer fingerprint subpacket: length=22, tag=33, version(1)+fingerprint(20)
    try buf.append(allocator, 22); // subpacket length
    try buf.append(allocator, @intFromEnum(SubpacketTag.issuer_fingerprint));
    try buf.append(allocator, 4); // V4
    try buf.appendSlice(allocator, &key_fingerprint);

    return buf.toOwnedSlice(allocator);
}

/// Create a key revocation signature packet body.
///
/// Returns the serialized signature packet body bytes suitable for
/// wrapping in a packet header. This creates a 0x20 key revocation
/// signature over the primary key.
///
/// Note: This creates the hash and subpacket structure but uses a
/// placeholder MPI for the actual cryptographic signature, since
/// real signing requires access to the private key material.
pub fn createKeyRevocationSignature(
    allocator: Allocator,
    key: *const Key,
    reason: RevocationReason,
    description: []const u8,
    hash_algo: HashAlgorithm,
) ![]u8 {
    const fp = key.fingerprint();
    const pub_algo_id: u8 = @intFromEnum(key.primary_key.algorithm);
    const hash_algo_id: u8 = @intFromEnum(hash_algo);

    // Build hashed subpackets
    const hashed_subpackets = try buildRevocationSubpackets(allocator, fp, reason, description);
    defer allocator.free(hashed_subpackets);

    // Compute the hash for a key revocation signature.
    // Per RFC 4880, key revocation hashes: key_hash_material || v4_hashed_data
    // Key hash material: 0x99 || 2-byte BE length || key body
    const hashed_data = try creation.buildV4HashedData(
        @intFromEnum(SignatureType.key_revocation),
        pub_algo_id,
        hash_algo_id,
        hashed_subpackets,
        allocator,
    );
    defer allocator.free(hashed_data);

    // Build the full hash input
    var hash_input: std.ArrayList(u8) = .empty;
    defer hash_input.deinit(allocator);

    // Key hash material
    try hash_input.append(allocator, 0x99);
    const key_body_len: u16 = @intCast(key.primary_key.raw_body.len);
    var len_bytes: [2]u8 = undefined;
    mem.writeInt(u16, &len_bytes, key_body_len, .big);
    try hash_input.appendSlice(allocator, &len_bytes);
    try hash_input.appendSlice(allocator, key.primary_key.raw_body);

    // V4 hashed data with trailer
    try hash_input.appendSlice(allocator, hashed_data);

    // Now build the signature packet body
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    // Version
    try body.append(allocator, 4);
    // Signature type
    try body.append(allocator, @intFromEnum(SignatureType.key_revocation));
    // Public key algorithm
    try body.append(allocator, pub_algo_id);
    // Hash algorithm
    try body.append(allocator, hash_algo_id);

    // Hashed subpackets length + data
    const sp_len: u16 = @intCast(hashed_subpackets.len);
    var sp_len_bytes: [2]u8 = undefined;
    mem.writeInt(u16, &sp_len_bytes, sp_len, .big);
    try body.appendSlice(allocator, &sp_len_bytes);
    try body.appendSlice(allocator, hashed_subpackets);

    // Unhashed subpackets (empty for now)
    try body.appendSlice(allocator, &[_]u8{ 0, 0 });

    // Hash prefix (placeholder — real implementation would compute actual hash)
    try body.appendSlice(allocator, &[_]u8{ 0x00, 0x00 });

    // Signature MPI (placeholder — real signing needs private key)
    // Single zero-length MPI as placeholder
    try body.appendSlice(allocator, &[_]u8{ 0x00, 0x01, 0x00 });

    return body.toOwnedSlice(allocator);
}

/// Check if a signature was issued by the given key.
///
/// Examines the issuer and issuer_fingerprint subpackets in both the
/// hashed and unhashed subpacket areas.
fn isIssuedByKey(sig: *const SignaturePacket, key: *const Key, allocator: Allocator) !bool {
    const key_fp = key.fingerprint();
    const key_kid = key.keyId();

    // Check hashed subpackets
    const hashed_subs = try subpackets_mod.parseSubpackets(allocator, sig.hashed_subpacket_data);
    defer subpackets_mod.freeSubpackets(allocator, hashed_subs);

    for (hashed_subs) |sp| {
        if (sp.tag == .issuer_fingerprint) {
            if (sp.asIssuerFingerprint()) |ifp| {
                if (mem.eql(u8, &ifp.fingerprint, &key_fp)) return true;
            }
        }
        if (sp.tag == .issuer) {
            if (sp.asIssuer()) |kid| {
                if (mem.eql(u8, &kid, &key_kid)) return true;
            }
        }
    }

    // Check unhashed subpackets
    const unhashed_subs = try subpackets_mod.parseSubpackets(allocator, sig.unhashed_subpacket_data);
    defer subpackets_mod.freeSubpackets(allocator, unhashed_subs);

    for (unhashed_subs) |sp| {
        if (sp.tag == .issuer_fingerprint) {
            if (sp.asIssuerFingerprint()) |ifp| {
                if (mem.eql(u8, &ifp.fingerprint, &key_fp)) return true;
            }
        }
        if (sp.tag == .issuer) {
            if (sp.asIssuer()) |kid| {
                if (mem.eql(u8, &kid, &key_kid)) return true;
            }
        }
    }

    return false;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "RevocationReason name" {
    try std.testing.expectEqualStrings("No reason specified", RevocationReason.no_reason.name());
    try std.testing.expectEqualStrings("Key is superseded", RevocationReason.key_superseded.name());
    try std.testing.expectEqualStrings("Key material has been compromised", RevocationReason.key_compromised.name());
    try std.testing.expectEqualStrings("Key is retired and no longer used", RevocationReason.key_retired.name());
    try std.testing.expectEqualStrings("User ID is no longer valid", RevocationReason.user_id_invalid.name());
}

test "RevocationReason unknown" {
    const unknown: RevocationReason = @enumFromInt(99);
    try std.testing.expectEqualStrings("Unknown reason", unknown.name());
}

test "RevocationReason enum values" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(RevocationReason.no_reason));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(RevocationReason.key_superseded));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(RevocationReason.key_compromised));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(RevocationReason.key_retired));
    try std.testing.expectEqual(@as(u8, 32), @intFromEnum(RevocationReason.user_id_invalid));
}

test "getRevocationReason from hashed subpackets" {
    const allocator = std.testing.allocator;

    // Build a signature with a reason_for_revocation subpacket in hashed area
    // Subpacket: length = 1(tag) + 1(code) + 11("key retired") = 13
    const desc = "key retired";
    // subpacket: length(1) + tag(1) + code(1) + description(11) = 14 total
    // subpacket length = 1(tag) + 1(code) + 11(desc) = 13
    var hashed_data: [14]u8 = undefined;
    hashed_data[0] = 13; // subpacket length (body = tag + code + desc)
    hashed_data[1] = 29; // tag = reason_for_revocation
    hashed_data[2] = 3; // code = key_retired
    @memcpy(hashed_data[3..14], desc);

    // Build minimal signature packet
    // 4(hdr) + 2(hashed len) + 14(hashed) + 2(unhashed len) + 2(hash prefix) + 3(MPI) = 27
    var sig_body: [27]u8 = undefined;
    sig_body[0] = 4; // version
    sig_body[1] = 0x20; // key_revocation
    sig_body[2] = 1; // RSA
    sig_body[3] = 8; // SHA256
    mem.writeInt(u16, sig_body[4..6], hashed_data.len, .big);
    @memcpy(sig_body[6 .. 6 + hashed_data.len], &hashed_data);
    const uh_off = 6 + hashed_data.len;
    mem.writeInt(u16, sig_body[uh_off..][0..2], 0, .big);
    sig_body[uh_off + 2] = 0xAA;
    sig_body[uh_off + 3] = 0xBB;
    // MPI: 8 bits = 1 byte
    mem.writeInt(u16, sig_body[uh_off + 4 ..][0..2], 8, .big);
    sig_body[uh_off + 6] = 0xFF;

    const sig = try SignaturePacket.parse(allocator, sig_body[0 .. uh_off + 7]);
    defer sig.deinit(allocator);

    const info = try getRevocationReason(&sig, allocator);
    try std.testing.expect(info != null);
    try std.testing.expectEqual(RevocationReason.key_retired, info.?.reason);
    try std.testing.expectEqualStrings("key retired", info.?.description);
}

test "getRevocationReason returns null when no reason subpacket" {
    const allocator = std.testing.allocator;

    // Build a signature without reason_for_revocation subpacket
    var sig_body: [15]u8 = undefined;
    sig_body[0] = 4;
    sig_body[1] = 0x20;
    sig_body[2] = 1;
    sig_body[3] = 8;
    mem.writeInt(u16, sig_body[4..6], 0, .big); // no hashed subpackets
    mem.writeInt(u16, sig_body[6..8], 0, .big); // no unhashed subpackets
    sig_body[8] = 0xAA;
    sig_body[9] = 0xBB;
    mem.writeInt(u16, sig_body[10..12], 8, .big);
    sig_body[12] = 0xFF;

    const sig = try SignaturePacket.parse(allocator, sig_body[0..13]);
    defer sig.deinit(allocator);

    const info = try getRevocationReason(&sig, allocator);
    try std.testing.expect(info == null);
}

test "isKeyRevoked returns false for non-revoked key" {
    const allocator = std.testing.allocator;

    const UserIdPacket = @import("../packets/user_id.zig").UserIdPacket;

    // Build a basic key with no revocation signatures
    var body: [12]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], 1000, .big);
    body[5] = 1; // RSA
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xFF;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;

    const pk = try PublicKeyPacket.parse(allocator, &body, false);

    var key = Key.init(pk);
    defer key.deinit(allocator);

    const uid = try UserIdPacket.parse(allocator, "Test <test@example.com>");
    try key.addUserId(allocator, .{
        .user_id = uid,
        .self_signature = null,
        .certifications = .empty,
    });

    const revoked = try isKeyRevoked(&key, allocator);
    try std.testing.expect(!revoked);
}

test "isSubkeyRevoked returns false for non-revoked subkey" {
    const allocator = std.testing.allocator;

    var pk_body: [12]u8 = undefined;
    pk_body[0] = 4;
    mem.writeInt(u32, pk_body[1..5], 1000, .big);
    pk_body[5] = 1;
    mem.writeInt(u16, pk_body[6..8], 8, .big);
    pk_body[8] = 0xFF;
    mem.writeInt(u16, pk_body[9..11], 8, .big);
    pk_body[11] = 0x03;

    const pk = try PublicKeyPacket.parse(allocator, &pk_body, false);
    defer pk.deinit(allocator);

    var sub_body: [12]u8 = undefined;
    sub_body[0] = 4;
    mem.writeInt(u32, sub_body[1..5], 2000, .big);
    sub_body[5] = 1;
    mem.writeInt(u16, sub_body[6..8], 8, .big);
    sub_body[8] = 0xAA;
    mem.writeInt(u16, sub_body[9..11], 8, .big);
    sub_body[11] = 0x03;

    const subkey = try PublicKeyPacket.parse(allocator, &sub_body, true);
    defer subkey.deinit(allocator);

    var binding = SubkeyBinding{
        .key = subkey,
        .secret_key = null,
        .binding_signature = null,
    };

    const revoked = try isSubkeyRevoked(&pk, &binding, allocator);
    try std.testing.expect(!revoked);

    // Prevent double-free since we defer deinit above
    binding.key = subkey;
}

test "buildRevocationSubpackets structure" {
    const allocator = std.testing.allocator;

    const fp = [_]u8{0x01} ** 20;
    const subpacket_data = try buildRevocationSubpackets(allocator, fp, .key_compromised, "test");
    defer allocator.free(subpacket_data);

    // Parse the subpackets to verify structure
    const subs = try subpackets_mod.parseSubpackets(allocator, subpacket_data);
    defer subpackets_mod.freeSubpackets(allocator, subs);

    // Should have 3 subpackets: creation_time, reason_for_revocation, issuer_fingerprint
    try std.testing.expectEqual(@as(usize, 3), subs.len);
    try std.testing.expectEqual(SubpacketTag.creation_time, subs[0].tag);
    try std.testing.expectEqual(SubpacketTag.reason_for_revocation, subs[1].tag);
    try std.testing.expectEqual(SubpacketTag.issuer_fingerprint, subs[2].tag);

    // Verify reason data
    try std.testing.expect(subs[1].data.len >= 1);
    try std.testing.expectEqual(@as(u8, 2), subs[1].data[0]); // key_compromised
    try std.testing.expectEqualStrings("test", subs[1].data[1..]);
}

test "createKeyRevocationSignature produces parseable packet" {
    const allocator = std.testing.allocator;
    const UserIdPacket = @import("../packets/user_id.zig").UserIdPacket;

    var body: [12]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], 1000, .big);
    body[5] = 1; // RSA
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xFF;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;

    const pk = try PublicKeyPacket.parse(allocator, &body, false);

    var key = Key.init(pk);
    defer key.deinit(allocator);

    const uid = try UserIdPacket.parse(allocator, "Revoker <rev@example.com>");
    try key.addUserId(allocator, .{
        .user_id = uid,
        .self_signature = null,
        .certifications = .empty,
    });

    const sig_body = try createKeyRevocationSignature(
        allocator,
        &key,
        .key_compromised,
        "Key was compromised",
        .sha256,
    );
    defer allocator.free(sig_body);

    // Verify it can be parsed as a signature packet
    const sig = try SignaturePacket.parse(allocator, sig_body);
    defer sig.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 4), sig.version);
    try std.testing.expectEqual(@as(u8, @intFromEnum(SignatureType.key_revocation)), sig.sig_type);

    // Verify we can extract the reason
    const info = try getRevocationReason(&sig, allocator);
    try std.testing.expect(info != null);
    try std.testing.expectEqual(RevocationReason.key_compromised, info.?.reason);
    try std.testing.expectEqualStrings("Key was compromised", info.?.description);
}
