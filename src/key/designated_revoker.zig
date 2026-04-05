// SPDX-License-Identifier: MIT
//! Designated revoker support per RFC 4880 Section 5.2.3.15.
//!
//! A designated revoker (subpacket type 12) allows a key owner to authorize
//! another key to issue revocation signatures on their behalf. The subpacket
//! contains:
//!   1 byte  — class (0x80 normal, 0xC0 sensitive)
//!   1 byte  — public key algorithm of the revoker
//!   20 bytes — fingerprint of the revoker key (V4)

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const Key = @import("key.zig").Key;
const PublicKeyPacket = @import("../packets/public_key.zig").PublicKeyPacket;
const SignaturePacket = @import("../packets/signature.zig").SignaturePacket;
const SignatureType = @import("../signature/types.zig").SignatureType;
const subpackets_mod = @import("../signature/subpackets.zig");
const SubpacketTag = subpackets_mod.SubpacketTag;
const PublicKeyAlgorithm = @import("../types/enums.zig").PublicKeyAlgorithm;
const fingerprint_mod = @import("fingerprint.zig");

/// A designated revoker entry.
pub const DesignatedRevoker = struct {
    /// Class byte. 0x80 = normal authorization, 0xC0 = sensitive + authorization.
    class: u8,
    /// The public key algorithm of the designated revoker key.
    algorithm: PublicKeyAlgorithm,
    /// The V4 fingerprint of the designated revoker key.
    fingerprint: [20]u8,
};

/// Get all designated revokers for a key.
///
/// Scans the self-signatures of the key's user IDs for revocation_key
/// subpackets (tag 12). Returns an owned slice; caller must free it.
pub fn getDesignatedRevokers(key: *const Key, allocator: Allocator) ![]DesignatedRevoker {
    var result: std.ArrayList(DesignatedRevoker) = .empty;
    errdefer result.deinit(allocator);

    for (key.user_ids.items) |uid_binding| {
        if (uid_binding.self_signature) |sig| {
            const subs = try subpackets_mod.parseSubpackets(allocator, sig.hashed_subpacket_data);
            defer subpackets_mod.freeSubpackets(allocator, subs);

            for (subs) |sp| {
                if (sp.tag == .revocation_key) {
                    if (sp.data.len >= 22) {
                        const revoker = DesignatedRevoker{
                            .class = sp.data[0],
                            .algorithm = @enumFromInt(sp.data[1]),
                            .fingerprint = sp.data[2..22].*,
                        };
                        try result.append(allocator, revoker);
                    }
                }
            }
        }

        // Also check certifications
        for (uid_binding.certifications.items) |sig| {
            const subs = try subpackets_mod.parseSubpackets(allocator, sig.hashed_subpacket_data);
            defer subpackets_mod.freeSubpackets(allocator, subs);

            for (subs) |sp| {
                if (sp.tag == .revocation_key) {
                    if (sp.data.len >= 22) {
                        const revoker = DesignatedRevoker{
                            .class = sp.data[0],
                            .algorithm = @enumFromInt(sp.data[1]),
                            .fingerprint = sp.data[2..22].*,
                        };
                        try result.append(allocator, revoker);
                    }
                }
            }
        }
    }

    return result.toOwnedSlice(allocator);
}

/// Add a designated revoker to a key.
///
/// This creates a new self-signature (direct key signature, type 0x1F)
/// containing a revocation_key subpacket. In practice, the caller should
/// replace the self-signature. For simplicity, we add a certification
/// to the first UID's certifications list.
///
/// Note: The signature uses a placeholder MPI (not cryptographically signed).
pub fn addDesignatedRevoker(
    allocator: Allocator,
    key: *Key,
    revoker_fingerprint: [20]u8,
    revoker_algorithm: PublicKeyAlgorithm,
    sensitive: bool,
) !void {
    if (key.user_ids.items.len == 0) return error.NoUserIds;

    // Build hashed subpackets for the direct key signature
    var hashed: std.ArrayList(u8) = .empty;
    errdefer hashed.deinit(allocator);

    // Creation time subpacket
    try appendSubpacket(allocator, &hashed, @intFromEnum(SubpacketTag.creation_time), &blk: {
        var buf: [4]u8 = undefined;
        mem.writeInt(u32, &buf, 0, .big); // placeholder time
        break :blk buf;
    });

    // Revocation key subpacket (tag 12)
    // Data: class(1) + algorithm(1) + fingerprint(20) = 22 bytes
    var rev_data: [22]u8 = undefined;
    rev_data[0] = if (sensitive) 0xC0 else 0x80;
    rev_data[1] = @intFromEnum(revoker_algorithm);
    @memcpy(rev_data[2..22], &revoker_fingerprint);
    try appendSubpacket(allocator, &hashed, @intFromEnum(SubpacketTag.revocation_key), &rev_data);

    // Issuer fingerprint subpacket
    const key_fp = key.fingerprint();
    var fp_data: [21]u8 = undefined;
    fp_data[0] = 4; // V4
    @memcpy(fp_data[1..21], &key_fp);
    try appendSubpacket(allocator, &hashed, @intFromEnum(SubpacketTag.issuer_fingerprint), &fp_data);

    const hashed_data = try hashed.toOwnedSlice(allocator);
    defer allocator.free(hashed_data);

    // Build signature packet body
    var sig_body: std.ArrayList(u8) = .empty;
    errdefer sig_body.deinit(allocator);

    try sig_body.append(allocator, 4); // version
    try sig_body.append(allocator, @intFromEnum(SignatureType.direct_key)); // direct key sig
    try sig_body.append(allocator, @intFromEnum(key.primary_key.algorithm)); // pub algo
    try sig_body.append(allocator, 8); // SHA256

    const h_len: u16 = @intCast(hashed_data.len);
    var h_len_buf: [2]u8 = undefined;
    mem.writeInt(u16, &h_len_buf, h_len, .big);
    try sig_body.appendSlice(allocator, &h_len_buf);
    try sig_body.appendSlice(allocator, hashed_data);

    // No unhashed subpackets
    try sig_body.appendSlice(allocator, &[_]u8{ 0, 0 });

    // Hash prefix placeholder
    try sig_body.appendSlice(allocator, &[_]u8{ 0x00, 0x00 });

    // Signature MPI placeholder
    try sig_body.appendSlice(allocator, &[_]u8{ 0x00, 0x01, 0x00 });

    const body = try sig_body.toOwnedSlice(allocator);
    defer allocator.free(body);

    const sig = try SignaturePacket.parse(allocator, body);

    // Add the signature as a certification on the first UID
    try key.user_ids.items[0].certifications.append(allocator, sig);
}

/// Verify that a revocation signature was issued by a designated revoker.
///
/// Checks that:
///   1. The key has the revoker_key designated as a revocation key
///   2. The signature claims to be issued by the revoker_key (issuer subpacket)
///
/// Note: This does NOT verify the cryptographic signature. That would require
/// the actual signing verification code.
pub fn isValidDesignatedRevocation(
    sig: *const SignaturePacket,
    key: *const Key,
    revoker_key: *const Key,
    allocator: Allocator,
) !bool {
    // Check that sig is a key revocation
    const sig_type: SignatureType = @enumFromInt(sig.sig_type);
    if (!sig_type.isRevocation()) return false;

    // Get designated revokers for the key
    const revokers = try getDesignatedRevokers(key, allocator);
    defer allocator.free(revokers);

    const revoker_fp = revoker_key.fingerprint();

    // Check if the revoker is designated
    var is_designated = false;
    for (revokers) |rev| {
        if (mem.eql(u8, &rev.fingerprint, &revoker_fp)) {
            is_designated = true;
            break;
        }
    }
    if (!is_designated) return false;

    // Check that the signature claims to be from the revoker
    const issuer_fp = try getIssuerFingerprint(sig, allocator);
    if (issuer_fp) |ifp| {
        return mem.eql(u8, &ifp, &revoker_fp);
    }

    // Fall back to key ID check
    const revoker_kid = revoker_key.keyId();
    const issuer_kid = try getIssuerKeyId(sig, allocator);
    if (issuer_kid) |ikid| {
        return mem.eql(u8, &ikid, &revoker_kid);
    }

    return false;
}

/// Helper to get issuer fingerprint from a signature's subpackets.
fn getIssuerFingerprint(sig: *const SignaturePacket, allocator: Allocator) !?[20]u8 {
    const subs = try subpackets_mod.parseSubpackets(allocator, sig.hashed_subpacket_data);
    defer subpackets_mod.freeSubpackets(allocator, subs);

    for (subs) |sp| {
        if (sp.tag == .issuer_fingerprint) {
            if (sp.asIssuerFingerprint()) |ifp| {
                return ifp.fingerprint;
            }
        }
    }

    // Also check unhashed
    const usubs = try subpackets_mod.parseSubpackets(allocator, sig.unhashed_subpacket_data);
    defer subpackets_mod.freeSubpackets(allocator, usubs);

    for (usubs) |sp| {
        if (sp.tag == .issuer_fingerprint) {
            if (sp.asIssuerFingerprint()) |ifp| {
                return ifp.fingerprint;
            }
        }
    }

    return null;
}

/// Helper to get issuer key ID from a signature's subpackets.
fn getIssuerKeyId(sig: *const SignaturePacket, allocator: Allocator) !?[8]u8 {
    const subs = try subpackets_mod.parseSubpackets(allocator, sig.hashed_subpacket_data);
    defer subpackets_mod.freeSubpackets(allocator, subs);

    for (subs) |sp| {
        if (sp.tag == .issuer) {
            if (sp.asIssuer()) |kid| {
                return kid;
            }
        }
    }

    const usubs = try subpackets_mod.parseSubpackets(allocator, sig.unhashed_subpacket_data);
    defer subpackets_mod.freeSubpackets(allocator, usubs);

    for (usubs) |sp| {
        if (sp.tag == .issuer) {
            if (sp.asIssuer()) |kid| {
                return kid;
            }
        }
    }

    return null;
}

/// Append a subpacket to a buffer (same format as used in generate.zig).
fn appendSubpacket(
    allocator: Allocator,
    list: *std.ArrayList(u8),
    tag: u8,
    data: []const u8,
) !void {
    const sp_len = 1 + data.len;
    if (sp_len < 192) {
        try list.append(allocator, @intCast(sp_len));
    } else {
        const adjusted = sp_len - 192;
        try list.append(allocator, @intCast(adjusted / 256 + 192));
        try list.append(allocator, @intCast(adjusted % 256));
    }
    try list.append(allocator, tag);
    try list.appendSlice(allocator, data);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const UserIdPacket = @import("../packets/user_id.zig").UserIdPacket;

fn buildTestKey(allocator: Allocator, email: []const u8, creation_time: u32) !Key {
    var body: [12]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], creation_time, .big);
    body[5] = 1; // RSA
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xFF;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;

    const pk = try PublicKeyPacket.parse(allocator, &body, false);
    errdefer pk.deinit(allocator);

    var key = Key.init(pk);
    errdefer key.deinit(allocator);

    const uid = try UserIdPacket.parse(allocator, email);
    try key.addUserId(allocator, .{
        .user_id = uid,
        .self_signature = null,
        .certifications = .empty,
    });

    return key;
}

test "getDesignatedRevokers empty" {
    const allocator = std.testing.allocator;

    var key = try buildTestKey(allocator, "test@test.com", 1000);
    defer key.deinit(allocator);

    const revokers = try getDesignatedRevokers(&key, allocator);
    defer allocator.free(revokers);

    try std.testing.expectEqual(@as(usize, 0), revokers.len);
}

test "addDesignatedRevoker and retrieve" {
    const allocator = std.testing.allocator;

    var key = try buildTestKey(allocator, "owner@test.com", 1000);
    defer key.deinit(allocator);

    const revoker_fp = [_]u8{0xAA} ** 20;
    try addDesignatedRevoker(allocator, &key, revoker_fp, .rsa_encrypt_sign, false);

    const revokers = try getDesignatedRevokers(&key, allocator);
    defer allocator.free(revokers);

    try std.testing.expectEqual(@as(usize, 1), revokers.len);
    try std.testing.expectEqual(@as(u8, 0x80), revokers[0].class);
    try std.testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, revokers[0].algorithm);
    try std.testing.expectEqualSlices(u8, &revoker_fp, &revokers[0].fingerprint);
}

test "addDesignatedRevoker sensitive flag" {
    const allocator = std.testing.allocator;

    var key = try buildTestKey(allocator, "owner@test.com", 1000);
    defer key.deinit(allocator);

    const revoker_fp = [_]u8{0xBB} ** 20;
    try addDesignatedRevoker(allocator, &key, revoker_fp, .dsa, true);

    const revokers = try getDesignatedRevokers(&key, allocator);
    defer allocator.free(revokers);

    try std.testing.expectEqual(@as(usize, 1), revokers.len);
    try std.testing.expectEqual(@as(u8, 0xC0), revokers[0].class);
    try std.testing.expectEqual(PublicKeyAlgorithm.dsa, revokers[0].algorithm);
}

test "addDesignatedRevoker to key with no user IDs fails" {
    const allocator = std.testing.allocator;

    var body: [12]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], 1000, .big);
    body[5] = 1;
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xFF;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;

    const pk = try PublicKeyPacket.parse(allocator, &body, false);
    var key = Key.init(pk);
    defer key.deinit(allocator);

    const revoker_fp = [_]u8{0xCC} ** 20;
    try std.testing.expectError(error.NoUserIds, addDesignatedRevoker(allocator, &key, revoker_fp, .rsa_encrypt_sign, false));
}

test "isValidDesignatedRevocation with no designated revokers" {
    const allocator = std.testing.allocator;

    var key = try buildTestKey(allocator, "owner@test.com", 1000);
    defer key.deinit(allocator);

    var revoker_key = try buildTestKey(allocator, "revoker@test.com", 2000);
    defer revoker_key.deinit(allocator);

    // Build a fake revocation signature
    var sig_body: [13]u8 = undefined;
    sig_body[0] = 4;
    sig_body[1] = @intFromEnum(SignatureType.key_revocation);
    sig_body[2] = 1;
    sig_body[3] = 8;
    mem.writeInt(u16, sig_body[4..6], 0, .big);
    mem.writeInt(u16, sig_body[6..8], 0, .big);
    sig_body[8] = 0xAA;
    sig_body[9] = 0xBB;
    mem.writeInt(u16, sig_body[10..12], 8, .big);
    sig_body[12] = 0xFF;

    const sig = try SignaturePacket.parse(allocator, sig_body[0..13]);
    defer sig.deinit(allocator);

    const valid = try isValidDesignatedRevocation(&sig, &key, &revoker_key, allocator);
    try std.testing.expect(!valid);
}

test "DesignatedRevoker struct fields" {
    const rev = DesignatedRevoker{
        .class = 0x80,
        .algorithm = .rsa_encrypt_sign,
        .fingerprint = [_]u8{0x42} ** 20,
    };

    try std.testing.expectEqual(@as(u8, 0x80), rev.class);
    try std.testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, rev.algorithm);
    try std.testing.expectEqual(@as(u8, 0x42), rev.fingerprint[0]);
}

test "addDesignatedRevoker multiple revokers" {
    const allocator = std.testing.allocator;

    var key = try buildTestKey(allocator, "owner@test.com", 1000);
    defer key.deinit(allocator);

    const fp1 = [_]u8{0x11} ** 20;
    const fp2 = [_]u8{0x22} ** 20;

    try addDesignatedRevoker(allocator, &key, fp1, .rsa_encrypt_sign, false);
    try addDesignatedRevoker(allocator, &key, fp2, .dsa, true);

    const revokers = try getDesignatedRevokers(&key, allocator);
    defer allocator.free(revokers);

    try std.testing.expectEqual(@as(usize, 2), revokers.len);
}
