// SPDX-License-Identifier: MIT
//! V6 assembled key structure per RFC 9580 Section 10.1 (Transferable Public Keys).
//!
//! A V6 transferable public key consists of a V6 primary key packet, followed by
//! direct key signatures, user ID packets (each with self-signatures and optional
//! certifications), and optional V6 subkey packets (each with binding signatures).
//!
//! V6 keys differ from V4 keys:
//!   - Key packet version is 6 (with 4-byte key material length field)
//!   - Fingerprint is SHA-256 based (32 bytes) instead of SHA-1 (20 bytes)
//!   - Key ID is the first 8 bytes of the fingerprint (not last 8)
//!   - Signature packets use V6 format (4-byte subpacket lengths, salt)
//!   - Direct key signatures are more prominently used

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const V6PublicKeyPacket = @import("../packets/v6_public_key.zig").V6PublicKeyPacket;
const V6SignaturePacket = @import("../packets/v6_signature.zig").V6SignaturePacket;
const PublicKeyAlgorithm = @import("../types/enums.zig").PublicKeyAlgorithm;
const v6_fingerprint_mod = @import("v6_fingerprint.zig");

/// A user ID binding for a V6 key.
///
/// Associates a user ID string with its self-signature (by the primary key)
/// and optional third-party certifications.
pub const V6UserIdBinding = struct {
    /// The user ID string (e.g., "Alice <alice@example.com>").
    user_id: []const u8,
    /// The self-signature certifying this user ID (sig_type 0x10-0x13).
    self_signature: ?V6SignaturePacket,
    /// Third-party certification signatures.
    certifications: std.ArrayList(V6SignaturePacket),

    /// Free all allocator-owned memory.
    pub fn deinit(self: *V6UserIdBinding, allocator: Allocator) void {
        allocator.free(self.user_id);
        if (self.self_signature) |sig| sig.deinit(allocator);
        for (self.certifications.items) |sig| sig.deinit(allocator);
        self.certifications.deinit(allocator);
    }
};

/// A subkey binding for a V6 key.
///
/// Associates a subkey with its binding signature from the primary key.
pub const V6SubkeyBinding = struct {
    /// The V6 public subkey packet.
    key: V6PublicKeyPacket,
    /// Optional secret key data for this subkey.
    secret_key_data: ?[]const u8,
    /// The subkey binding signature (sig_type 0x18).
    binding_signature: ?V6SignaturePacket,

    /// Free all allocator-owned memory.
    pub fn deinit(self: *V6SubkeyBinding, allocator: Allocator) void {
        self.key.deinit(allocator);
        if (self.secret_key_data) |sk| allocator.free(sk);
        if (self.binding_signature) |sig| sig.deinit(allocator);
    }
};

/// An assembled V6 OpenPGP key (public or private).
///
/// This structure represents a complete transferable V6 key with all its
/// component packets assembled into a coherent structure.
pub const V6Key = struct {
    /// The V6 primary key packet.
    primary_key: V6PublicKeyPacket,
    /// Optional secret key material for the primary key.
    secret_key_data: ?[]const u8,
    /// User IDs and their signatures.
    user_ids: std.ArrayList(V6UserIdBinding),
    /// Subkeys and their binding signatures.
    subkeys: std.ArrayList(V6SubkeyBinding),
    /// Direct key signatures (sig_type 0x1F).
    direct_signatures: std.ArrayList(V6SignaturePacket),
    /// The allocator used for this key.
    allocator: Allocator,

    /// Initialize a new V6Key structure.
    pub fn init(allocator: Allocator, primary_key: V6PublicKeyPacket) V6Key {
        return .{
            .primary_key = primary_key,
            .secret_key_data = null,
            .user_ids = .empty,
            .subkeys = .empty,
            .direct_signatures = .empty,
            .allocator = allocator,
        };
    }

    /// Free all memory associated with this key.
    pub fn deinit(self: *V6Key) void {
        self.primary_key.deinit(self.allocator);
        if (self.secret_key_data) |sk| self.allocator.free(sk);

        for (self.user_ids.items) |*uid| {
            uid.deinit(self.allocator);
        }
        self.user_ids.deinit(self.allocator);

        for (self.subkeys.items) |*sub| {
            sub.deinit(self.allocator);
        }
        self.subkeys.deinit(self.allocator);

        for (self.direct_signatures.items) |sig| {
            sig.deinit(self.allocator);
        }
        self.direct_signatures.deinit(self.allocator);
    }

    /// Calculate the V6 fingerprint (SHA-256, 32 bytes) of the primary key.
    pub fn fingerprint(self: *const V6Key) [32]u8 {
        return self.primary_key.fingerprint();
    }

    /// Get the V6 Key ID (first 8 bytes of the fingerprint).
    pub fn keyId(self: *const V6Key) [8]u8 {
        return self.primary_key.keyId();
    }

    /// Return the primary user ID string, if any user ID bindings exist.
    ///
    /// Returns the first user ID. A more sophisticated implementation
    /// would check for the Primary User ID subpacket in self-signatures.
    pub fn primaryUserId(self: *const V6Key) ?[]const u8 {
        if (self.user_ids.items.len == 0) return null;
        return self.user_ids.items[0].user_id;
    }

    /// Add a user ID binding to this key.
    pub fn addUserId(self: *V6Key, uid: []const u8, sig: ?V6SignaturePacket) !void {
        const uid_copy = try self.allocator.dupe(u8, uid);
        errdefer self.allocator.free(uid_copy);

        try self.user_ids.append(self.allocator, .{
            .user_id = uid_copy,
            .self_signature = sig,
            .certifications = .empty,
        });
    }

    /// Add a subkey binding to this key.
    pub fn addSubkey(self: *V6Key, key: V6PublicKeyPacket, sig: ?V6SignaturePacket) !void {
        try self.subkeys.append(self.allocator, .{
            .key = key,
            .secret_key_data = null,
            .binding_signature = sig,
        });
    }

    /// Add a direct key signature.
    pub fn addDirectSignature(self: *V6Key, sig: V6SignaturePacket) !void {
        try self.direct_signatures.append(self.allocator, sig);
    }

    /// Get the public key algorithm of the primary key.
    pub fn algorithm(self: *const V6Key) PublicKeyAlgorithm {
        return self.primary_key.algorithm;
    }

    /// Get the creation time of the primary key.
    pub fn creationTime(self: *const V6Key) u32 {
        return self.primary_key.creation_time;
    }

    /// Check if this key has any secret key material.
    pub fn hasSecretKey(self: *const V6Key) bool {
        return self.secret_key_data != null;
    }

    /// Check if this key has any encryption-capable subkeys.
    pub fn hasEncryptionSubkey(self: *const V6Key) bool {
        for (self.subkeys.items) |sub| {
            if (sub.key.algorithm.canEncrypt()) return true;
        }
        return false;
    }

    /// Check if this key has any signing-capable subkeys.
    pub fn hasSigningSubkey(self: *const V6Key) bool {
        for (self.subkeys.items) |sub| {
            if (sub.key.algorithm.canSign()) return true;
        }
        return false;
    }

    /// Get a subkey by its fingerprint.
    pub fn findSubkeyByFingerprint(self: *const V6Key, fp: [32]u8) ?*const V6SubkeyBinding {
        for (self.subkeys.items) |*sub| {
            if (mem.eql(u8, &sub.key.fingerprint(), &fp)) return sub;
        }
        return null;
    }

    /// Get a subkey by its key ID (first 8 bytes of fingerprint).
    pub fn findSubkeyByKeyId(self: *const V6Key, kid: [8]u8) ?*const V6SubkeyBinding {
        for (self.subkeys.items) |*sub| {
            if (mem.eql(u8, &sub.key.keyId(), &kid)) return sub;
        }
        return null;
    }

    /// Get the first encryption-capable subkey, if any.
    pub fn encryptionSubkey(self: *const V6Key) ?*const V6SubkeyBinding {
        for (self.subkeys.items) |*sub| {
            if (sub.key.algorithm.canEncrypt()) return sub;
        }
        return null;
    }

    /// Get the first signing-capable subkey, if any.
    pub fn signingSubkey(self: *const V6Key) ?*const V6SubkeyBinding {
        for (self.subkeys.items) |*sub| {
            if (sub.key.algorithm.canSign()) return sub;
        }
        return null;
    }

    /// Count total number of user IDs.
    pub fn userIdCount(self: *const V6Key) usize {
        return self.user_ids.items.len;
    }

    /// Count total number of subkeys.
    pub fn subkeyCount(self: *const V6Key) usize {
        return self.subkeys.items.len;
    }

    /// Format the fingerprint as a hex string.
    pub fn fingerprintHex(self: *const V6Key) [64]u8 {
        return v6_fingerprint_mod.formatV6Fingerprint(self.fingerprint());
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn buildTestV6KeyBody() [16]u8 {
    var body: [16]u8 = undefined;
    body[0] = 6; // version
    mem.writeInt(u32, body[1..5], 1000, .big); // creation time
    body[5] = @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign);
    mem.writeInt(u32, body[6..10], 6, .big); // key material length
    mem.writeInt(u16, body[10..12], 8, .big); // MPI 1: n
    body[12] = 0xFF;
    mem.writeInt(u16, body[13..15], 8, .big); // MPI 2: e
    body[15] = 0x03;
    return body;
}

test "V6Key init and deinit" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestV6KeyBody();
    const pk = try V6PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = V6Key.init(allocator, pk);
    defer key.deinit();

    try std.testing.expectEqual(@as(u8, 6), key.primary_key.version);
    try std.testing.expect(key.secret_key_data == null);
    try std.testing.expectEqual(@as(usize, 0), key.user_ids.items.len);
    try std.testing.expectEqual(@as(usize, 0), key.subkeys.items.len);
    try std.testing.expectEqual(@as(usize, 0), key.direct_signatures.items.len);
}

test "V6Key fingerprint is 32 bytes" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestV6KeyBody();
    const pk = try V6PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = V6Key.init(allocator, pk);
    defer key.deinit();

    const fp = key.fingerprint();
    try std.testing.expectEqual(@as(usize, 32), fp.len);

    // Verify it matches direct calculation
    const expected_fp = v6_fingerprint_mod.calculateV6Fingerprint(&pk_body);
    try std.testing.expectEqual(expected_fp, fp);
}

test "V6Key keyId is first 8 bytes of fingerprint" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestV6KeyBody();
    const pk = try V6PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = V6Key.init(allocator, pk);
    defer key.deinit();

    const fp = key.fingerprint();
    const kid = key.keyId();

    // V6 key ID is the first 8 bytes of the fingerprint
    try std.testing.expectEqualSlices(u8, fp[0..8], &kid);
}

test "V6Key primaryUserId returns null when empty" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestV6KeyBody();
    const pk = try V6PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = V6Key.init(allocator, pk);
    defer key.deinit();

    try std.testing.expect(key.primaryUserId() == null);
}

test "V6Key addUserId and primaryUserId" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestV6KeyBody();
    const pk = try V6PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = V6Key.init(allocator, pk);
    defer key.deinit();

    try key.addUserId("Alice <alice@example.com>", null);

    try std.testing.expectEqual(@as(usize, 1), key.userIdCount());
    try std.testing.expectEqualStrings("Alice <alice@example.com>", key.primaryUserId().?);
}

test "V6Key multiple user IDs" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestV6KeyBody();
    const pk = try V6PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = V6Key.init(allocator, pk);
    defer key.deinit();

    try key.addUserId("Alice <alice@home.com>", null);
    try key.addUserId("Alice <alice@work.com>", null);

    try std.testing.expectEqual(@as(usize, 2), key.userIdCount());
    // primaryUserId returns the first one
    try std.testing.expectEqualStrings("Alice <alice@home.com>", key.primaryUserId().?);
}

test "V6Key addSubkey" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestV6KeyBody();
    const pk = try V6PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = V6Key.init(allocator, pk);
    defer key.deinit();

    var sub_body: [16]u8 = undefined;
    sub_body[0] = 6;
    mem.writeInt(u32, sub_body[1..5], 2000, .big);
    sub_body[5] = @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign);
    mem.writeInt(u32, sub_body[6..10], 6, .big);
    mem.writeInt(u16, sub_body[10..12], 8, .big);
    sub_body[12] = 0xAA;
    mem.writeInt(u16, sub_body[13..15], 8, .big);
    sub_body[15] = 0x03;

    const subkey = try V6PublicKeyPacket.parse(allocator, &sub_body, true);
    try key.addSubkey(subkey, null);

    try std.testing.expectEqual(@as(usize, 1), key.subkeyCount());
    try std.testing.expect(key.subkeys.items[0].key.is_subkey);
}

test "V6Key algorithm" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestV6KeyBody();
    const pk = try V6PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = V6Key.init(allocator, pk);
    defer key.deinit();

    try std.testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, key.algorithm());
}

test "V6Key creationTime" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestV6KeyBody();
    const pk = try V6PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = V6Key.init(allocator, pk);
    defer key.deinit();

    try std.testing.expectEqual(@as(u32, 1000), key.creationTime());
}

test "V6Key hasSecretKey" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestV6KeyBody();
    const pk = try V6PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = V6Key.init(allocator, pk);
    defer key.deinit();

    try std.testing.expect(!key.hasSecretKey());
}

test "V6Key hasEncryptionSubkey and hasSigningSubkey" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestV6KeyBody();
    const pk = try V6PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = V6Key.init(allocator, pk);
    defer key.deinit();

    try std.testing.expect(!key.hasEncryptionSubkey());
    try std.testing.expect(!key.hasSigningSubkey());

    // Add an RSA subkey (can both sign and encrypt)
    var sub_body: [16]u8 = undefined;
    sub_body[0] = 6;
    mem.writeInt(u32, sub_body[1..5], 3000, .big);
    sub_body[5] = @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign);
    mem.writeInt(u32, sub_body[6..10], 6, .big);
    mem.writeInt(u16, sub_body[10..12], 8, .big);
    sub_body[12] = 0xBB;
    mem.writeInt(u16, sub_body[13..15], 8, .big);
    sub_body[15] = 0x03;

    const subkey = try V6PublicKeyPacket.parse(allocator, &sub_body, true);
    try key.addSubkey(subkey, null);

    try std.testing.expect(key.hasEncryptionSubkey());
    try std.testing.expect(key.hasSigningSubkey());
}

test "V6Key fingerprintHex" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestV6KeyBody();
    const pk = try V6PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = V6Key.init(allocator, pk);
    defer key.deinit();

    const hex = key.fingerprintHex();
    try std.testing.expectEqual(@as(usize, 64), hex.len);

    // Verify it matches the formatted fingerprint
    const expected_hex = v6_fingerprint_mod.formatV6Fingerprint(key.fingerprint());
    try std.testing.expectEqual(expected_hex, hex);
}

test "V6Key encryptionSubkey and signingSubkey return null when no subkeys" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestV6KeyBody();
    const pk = try V6PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = V6Key.init(allocator, pk);
    defer key.deinit();

    try std.testing.expect(key.encryptionSubkey() == null);
    try std.testing.expect(key.signingSubkey() == null);
}
