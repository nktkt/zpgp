// SPDX-License-Identifier: MIT
//! Basic Web of Trust model per RFC 4880 concepts.
//!
//! Implements a simplified trust database that tracks owner trust levels
//! for keys and calculates key validity based on certification chains.
//!
//! The trust model follows the classic PGP Web of Trust:
//!   - Keys with ultimate trust are fully valid
//!   - Keys certified by fully trusted keys are fully valid
//!   - Keys certified by 3+ marginally trusted keys are marginally valid

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const Key = @import("key.zig").Key;
const Keyring = @import("keyring.zig").Keyring;
const SignatureType = @import("../signature/types.zig").SignatureType;
const subpackets_mod = @import("../signature/subpackets.zig");
const fingerprint_mod = @import("fingerprint.zig");

/// Owner trust level assigned to a key's owner.
///
/// This represents how much we trust the owner of a key to correctly
/// verify other people's identities before certifying their keys.
pub const TrustLevel = enum(u8) {
    /// Trust level has not been set.
    unknown = 0,
    /// Key owner is explicitly distrusted.
    never = 1,
    /// Key owner is marginally trusted.
    marginal = 2,
    /// Key owner is fully trusted.
    full = 3,
    /// Key owner is ultimately trusted (typically our own keys).
    ultimate = 4,
};

/// Calculated validity of a key's user IDs.
///
/// This represents how confident we are that the key actually belongs
/// to the person described by its user IDs.
pub const Validity = enum(u8) {
    /// Validity has not been calculated or is unknown.
    unknown = 0,
    /// Key is known to be invalid.
    invalid = 1,
    /// Key has marginal validity (some certifications from marginally trusted keys).
    marginal = 2,
    /// Key is fully valid (certified by a fully trusted key or enough marginal ones).
    full = 3,
    /// Key is ultimately valid (it is one of our own keys).
    ultimate = 4,
};

/// Number of marginally trusted certifications required for marginal validity.
const MARGINALS_NEEDED: usize = 3;

/// Number of fully trusted certifications required for full validity.
const COMPLETES_NEEDED: usize = 1;

/// A trust database mapping key fingerprints to owner trust levels.
pub const TrustDB = struct {
    allocator: Allocator,
    /// Map from 20-byte fingerprint to owner trust level.
    trust_map: std.AutoHashMap([20]u8, TrustLevel),

    /// Initialize an empty trust database.
    pub fn init(allocator: Allocator) TrustDB {
        return .{
            .allocator = allocator,
            .trust_map = std.AutoHashMap([20]u8, TrustLevel).init(allocator),
        };
    }

    /// Free all memory associated with the trust database.
    pub fn deinit(self: *TrustDB) void {
        self.trust_map.deinit();
    }

    /// Set the owner trust for a key identified by its fingerprint.
    pub fn setOwnerTrust(self: *TrustDB, fingerprint: [20]u8, level: TrustLevel) !void {
        try self.trust_map.put(fingerprint, level);
    }

    /// Get the owner trust for a key identified by its fingerprint.
    ///
    /// Returns `.unknown` if no trust has been set for this key.
    pub fn getOwnerTrust(self: *const TrustDB, fingerprint: [20]u8) TrustLevel {
        return self.trust_map.get(fingerprint) orelse .unknown;
    }

    /// Calculate the validity of a key based on certifications and trust.
    ///
    /// Simple Web of Trust model:
    ///   1. Keys with ultimate owner trust are ultimately valid.
    ///   2. Keys certified by at least one fully trusted key are fully valid.
    ///   3. Keys certified by 3+ marginally trusted keys are marginally valid.
    ///   4. Otherwise, validity is unknown.
    ///
    /// Certifications are found by examining the third-party certification
    /// signatures on each user ID binding of the target key, and looking
    /// up the certifier's trust level in the database.
    pub fn calculateValidity(
        self: *const TrustDB,
        key: *const Key,
        keyring: *const Keyring,
    ) Validity {
        const fp = key.fingerprint();

        // Rule 1: If the key itself has ultimate trust, it is ultimately valid
        const own_trust = self.getOwnerTrust(fp);
        if (own_trust == .ultimate) return .ultimate;

        // Count certifications from trusted keys
        var full_certs: usize = 0;
        var marginal_certs: usize = 0;

        for (key.user_ids.items) |uid_binding| {
            for (uid_binding.certifications.items) |cert_sig| {
                // Only consider certification signatures (0x10-0x13)
                const sig_type: SignatureType = @enumFromInt(cert_sig.sig_type);
                if (!sig_type.isCertification()) continue;

                // Find the certifier's key in the keyring
                const certifier_fp = getCertifierFingerprint(&cert_sig, keyring);
                if (certifier_fp) |cfp| {
                    const certifier_trust = self.getOwnerTrust(cfp);
                    switch (certifier_trust) {
                        .ultimate, .full => full_certs += 1,
                        .marginal => marginal_certs += 1,
                        else => {},
                    }
                }
            }
        }

        // Rule 2: Certified by a fully trusted key
        if (full_certs >= COMPLETES_NEEDED) return .full;

        // Rule 3: Certified by enough marginally trusted keys
        if (marginal_certs >= MARGINALS_NEEDED) return .marginal;

        return .unknown;
    }
};

/// Extract the certifier's fingerprint from a certification signature.
///
/// Tries issuer_fingerprint subpacket first, then falls back to
/// issuer key ID and looks it up in the keyring.
fn getCertifierFingerprint(sig: *const @import("../packets/signature.zig").SignaturePacket, keyring: *const Keyring) ?[20]u8 {
    // Try to find issuer fingerprint in hashed subpackets (without allocating)
    // We do a simple scan for the issuer subpacket pattern
    if (findIssuerFingerprintRaw(sig.hashed_subpacket_data)) |fp| return fp;
    if (findIssuerFingerprintRaw(sig.unhashed_subpacket_data)) |fp| return fp;

    // Try issuer key ID
    if (findIssuerKeyIdRaw(sig.hashed_subpacket_data)) |kid| {
        if (keyring.findByKeyId(kid)) |key| return key.fingerprint();
    }
    if (findIssuerKeyIdRaw(sig.unhashed_subpacket_data)) |kid| {
        if (keyring.findByKeyId(kid)) |key| return key.fingerprint();
    }

    return null;
}

/// Scan raw subpacket data for an issuer_fingerprint subpacket (tag 33)
/// without allocating. Returns the fingerprint if found.
fn findIssuerFingerprintRaw(data: []const u8) ?[20]u8 {
    var offset: usize = 0;
    while (offset < data.len) {
        if (offset >= data.len) break;
        const first = data[offset];
        offset += 1;

        var body_len: usize = undefined;
        if (first < 192) {
            body_len = @as(usize, first);
        } else if (first <= 254) {
            if (offset >= data.len) return null;
            const second = data[offset];
            offset += 1;
            body_len = (@as(usize, first) - 192) * 256 + @as(usize, second) + 192;
        } else {
            if (offset + 4 > data.len) return null;
            body_len = mem.readInt(u32, data[offset..][0..4], .big);
            offset += 4;
        }

        if (body_len == 0 or offset + body_len > data.len) return null;

        const type_byte = data[offset];
        const tag_val = type_byte & 0x7F;

        // issuer_fingerprint = 33
        if (tag_val == 33 and body_len >= 22) {
            // data[offset+1] = version, data[offset+2..offset+22] = fingerprint
            return data[offset + 2 .. offset + 22][0..20].*;
        }

        offset += body_len;
    }
    return null;
}

/// Scan raw subpacket data for an issuer subpacket (tag 16)
/// without allocating. Returns the Key ID if found.
fn findIssuerKeyIdRaw(data: []const u8) ?[8]u8 {
    var offset: usize = 0;
    while (offset < data.len) {
        if (offset >= data.len) break;
        const first = data[offset];
        offset += 1;

        var body_len: usize = undefined;
        if (first < 192) {
            body_len = @as(usize, first);
        } else if (first <= 254) {
            if (offset >= data.len) return null;
            const second = data[offset];
            offset += 1;
            body_len = (@as(usize, first) - 192) * 256 + @as(usize, second) + 192;
        } else {
            if (offset + 4 > data.len) return null;
            body_len = mem.readInt(u32, data[offset..][0..4], .big);
            offset += 4;
        }

        if (body_len == 0 or offset + body_len > data.len) return null;

        const type_byte = data[offset];
        const tag_val = type_byte & 0x7F;

        // issuer = 16, body_len = 9 (1 type + 8 key ID)
        if (tag_val == 16 and body_len == 9) {
            return data[offset + 1 .. offset + 9][0..8].*;
        }

        offset += body_len;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const PublicKeyPacket = @import("../packets/public_key.zig").PublicKeyPacket;
const UserIdPacket = @import("../packets/user_id.zig").UserIdPacket;
const UserIdBinding = @import("key.zig").UserIdBinding;
const SignaturePacket = @import("../packets/signature.zig").SignaturePacket;

fn buildTestKeyBody(creation_time: u32) [12]u8 {
    var body: [12]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], creation_time, .big);
    body[5] = 1; // RSA
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xFF;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;
    return body;
}

fn createTestKey(allocator: Allocator, email: []const u8, creation_time: u32) !Key {
    var body = buildTestKeyBody(creation_time);
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

test "TrustDB init and deinit" {
    const allocator = std.testing.allocator;
    var db = TrustDB.init(allocator);
    defer db.deinit();
}

test "TrustDB setOwnerTrust and getOwnerTrust" {
    const allocator = std.testing.allocator;
    var db = TrustDB.init(allocator);
    defer db.deinit();

    const fp = [_]u8{0x42} ** 20;

    // Default is unknown
    try std.testing.expectEqual(TrustLevel.unknown, db.getOwnerTrust(fp));

    // Set and retrieve
    try db.setOwnerTrust(fp, .full);
    try std.testing.expectEqual(TrustLevel.full, db.getOwnerTrust(fp));

    // Update
    try db.setOwnerTrust(fp, .marginal);
    try std.testing.expectEqual(TrustLevel.marginal, db.getOwnerTrust(fp));
}

test "TrustDB multiple fingerprints" {
    const allocator = std.testing.allocator;
    var db = TrustDB.init(allocator);
    defer db.deinit();

    const fp1 = [_]u8{0x01} ** 20;
    const fp2 = [_]u8{0x02} ** 20;
    const fp3 = [_]u8{0x03} ** 20;

    try db.setOwnerTrust(fp1, .ultimate);
    try db.setOwnerTrust(fp2, .full);
    try db.setOwnerTrust(fp3, .never);

    try std.testing.expectEqual(TrustLevel.ultimate, db.getOwnerTrust(fp1));
    try std.testing.expectEqual(TrustLevel.full, db.getOwnerTrust(fp2));
    try std.testing.expectEqual(TrustLevel.never, db.getOwnerTrust(fp3));

    // Non-existent is unknown
    const fp4 = [_]u8{0x04} ** 20;
    try std.testing.expectEqual(TrustLevel.unknown, db.getOwnerTrust(fp4));
}

test "TrustLevel enum values" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(TrustLevel.unknown));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(TrustLevel.never));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(TrustLevel.marginal));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(TrustLevel.full));
    try std.testing.expectEqual(@as(u8, 4), @intFromEnum(TrustLevel.ultimate));
}

test "Validity enum values" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(Validity.unknown));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(Validity.invalid));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(Validity.marginal));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(Validity.full));
    try std.testing.expectEqual(@as(u8, 4), @intFromEnum(Validity.ultimate));
}

test "calculateValidity ultimate trust" {
    const allocator = std.testing.allocator;

    var db = TrustDB.init(allocator);
    defer db.deinit();

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    var key = try createTestKey(allocator, "Alice <alice@example.com>", 1000);
    defer key.deinit(allocator);

    const fp = key.fingerprint();
    try db.setOwnerTrust(fp, .ultimate);

    const validity = db.calculateValidity(&key, &kr);
    try std.testing.expectEqual(Validity.ultimate, validity);
}

test "calculateValidity unknown without certifications" {
    const allocator = std.testing.allocator;

    var db = TrustDB.init(allocator);
    defer db.deinit();

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    var key = try createTestKey(allocator, "Bob <bob@example.com>", 2000);
    defer key.deinit(allocator);

    const validity = db.calculateValidity(&key, &kr);
    try std.testing.expectEqual(Validity.unknown, validity);
}

test "findIssuerFingerprintRaw" {
    // Build raw subpacket data with issuer_fingerprint subpacket
    // length=22, type=33, version=4, fingerprint=20 bytes
    var data: [23]u8 = undefined;
    data[0] = 22; // subpacket length
    data[1] = 33; // type = issuer_fingerprint
    data[2] = 4; // version
    for (0..20) |i| {
        data[3 + i] = @intCast(0xA0 + i);
    }

    const result = findIssuerFingerprintRaw(&data);
    try std.testing.expect(result != null);
    for (0..20) |i| {
        try std.testing.expectEqual(@as(u8, @intCast(0xA0 + i)), result.?[i]);
    }
}

test "findIssuerFingerprintRaw returns null for empty data" {
    const result = findIssuerFingerprintRaw(&[_]u8{});
    try std.testing.expect(result == null);
}

test "findIssuerKeyIdRaw" {
    // Build raw subpacket data with issuer subpacket
    // length=9, type=16, data=8 bytes
    var data: [10]u8 = undefined;
    data[0] = 9; // subpacket length
    data[1] = 16; // type = issuer
    for (0..8) |i| {
        data[2 + i] = @intCast(0xD0 + i);
    }

    const result = findIssuerKeyIdRaw(&data);
    try std.testing.expect(result != null);
    for (0..8) |i| {
        try std.testing.expectEqual(@as(u8, @intCast(0xD0 + i)), result.?[i]);
    }
}

test "findIssuerKeyIdRaw returns null for empty data" {
    const result = findIssuerKeyIdRaw(&[_]u8{});
    try std.testing.expect(result == null);
}
