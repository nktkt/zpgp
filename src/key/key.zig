// SPDX-License-Identifier: MIT
//! Assembled key structure per RFC 4880 Section 11.1 (Transferable Public Keys).
//!
//! A transferable public key consists of a primary key packet, followed by
//! user ID packets (each with self-signatures and optional certifications),
//! and optional subkey packets (each with binding signatures).

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const PublicKeyPacket = @import("../packets/public_key.zig").PublicKeyPacket;
const SecretKeyPacket = @import("../packets/secret_key.zig").SecretKeyPacket;
const SignaturePacket = @import("../packets/signature.zig").SignaturePacket;
const UserIdPacket = @import("../packets/user_id.zig").UserIdPacket;
const fingerprint_mod = @import("fingerprint.zig");

/// A user ID with its associated signatures.
pub const UserIdBinding = struct {
    user_id: UserIdPacket,
    /// The self-signature (certification by the primary key) if found.
    self_signature: ?SignaturePacket,
    /// Third-party certifications.
    certifications: std.ArrayList(SignaturePacket),

    pub fn deinit(self: *UserIdBinding, allocator: Allocator) void {
        self.user_id.deinit(allocator);
        if (self.self_signature) |sig| sig.deinit(allocator);
        for (self.certifications.items) |sig| sig.deinit(allocator);
        self.certifications.deinit(allocator);
    }
};

/// A subkey with its binding signature.
pub const SubkeyBinding = struct {
    key: PublicKeyPacket,
    /// Optional secret key portion (for private keyrings).
    secret_key: ?SecretKeyPacket,
    /// The subkey binding signature from the primary key.
    binding_signature: ?SignaturePacket,

    pub fn deinit(self: *SubkeyBinding, allocator: Allocator) void {
        self.key.deinit(allocator);
        if (self.secret_key) |sk| sk.deinit(allocator);
        if (self.binding_signature) |sig| sig.deinit(allocator);
    }
};

/// An assembled OpenPGP key (public or private).
pub const Key = struct {
    primary_key: PublicKeyPacket,
    /// Optional secret key material for the primary key.
    secret_key: ?SecretKeyPacket,
    /// User IDs and their signatures.
    user_ids: std.ArrayList(UserIdBinding),
    /// Subkeys and their binding signatures.
    subkeys: std.ArrayList(SubkeyBinding),

    /// Initialize an empty Key structure with a primary key.
    pub fn init(primary_key: PublicKeyPacket) Key {
        return .{
            .primary_key = primary_key,
            .secret_key = null,
            .user_ids = .empty,
            .subkeys = .empty,
        };
    }

    /// Calculate the V4 fingerprint of the primary key.
    pub fn fingerprint(self: *const Key) [20]u8 {
        return fingerprint_mod.calculateV4Fingerprint(self.primary_key.raw_body);
    }

    /// Get the Key ID (last 8 bytes of the fingerprint).
    pub fn keyId(self: *const Key) [8]u8 {
        return fingerprint_mod.calculateV4KeyId(self.primary_key.raw_body);
    }

    /// Return the primary user ID string, if any user ID bindings exist.
    /// Prefers the UID marked with a primary_user_id subpacket in its
    /// self-signature; falls back to the first UID.
    pub fn primaryUserId(self: *const Key) ?[]const u8 {
        if (self.user_ids.items.len == 0) return null;

        // Look for a UID with primary_user_id subpacket set in self-sig
        // (This would require subpacket parsing; for now, return the first UID)
        return self.user_ids.items[0].user_id.id;
    }

    /// Add a user ID binding to this key.
    pub fn addUserId(self: *Key, allocator: Allocator, binding: UserIdBinding) !void {
        try self.user_ids.append(allocator, binding);
    }

    /// Add a subkey binding to this key.
    pub fn addSubkey(self: *Key, allocator: Allocator, binding: SubkeyBinding) !void {
        try self.subkeys.append(allocator, binding);
    }

    /// Free all memory associated with this key.
    pub fn deinit(self: *Key, allocator: Allocator) void {
        self.primary_key.deinit(allocator);
        if (self.secret_key) |sk| sk.deinit(allocator);

        for (self.user_ids.items) |*uid| {
            uid.deinit(allocator);
        }
        self.user_ids.deinit(allocator);

        for (self.subkeys.items) |*sub| {
            sub.deinit(allocator);
        }
        self.subkeys.deinit(allocator);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Key init and deinit" {
    const allocator = std.testing.allocator;

    // Build a minimal RSA public key packet body
    var body: [12]u8 = undefined;
    body[0] = 4; // version
    mem.writeInt(u32, body[1..5], 1000, .big);
    body[5] = 1; // RSA
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xFF;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;

    const pk = try PublicKeyPacket.parse(allocator, &body, false);

    var key = Key.init(pk);
    defer key.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 4), key.primary_key.version);
    try std.testing.expect(key.secret_key == null);
    try std.testing.expectEqual(@as(usize, 0), key.user_ids.items.len);
    try std.testing.expectEqual(@as(usize, 0), key.subkeys.items.len);
}

test "Key fingerprint and keyId" {
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

    const fp = key.fingerprint();
    const kid = key.keyId();

    // Key ID should be last 8 bytes of fingerprint
    try std.testing.expectEqualSlices(u8, fp[12..20], &kid);

    // Fingerprint should match direct calculation
    const expected_fp = fingerprint_mod.calculateV4Fingerprint(&body);
    try std.testing.expectEqual(expected_fp, fp);
}

test "Key primaryUserId returns null when empty" {
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

    try std.testing.expect(key.primaryUserId() == null);
}

test "Key addUserId and primaryUserId" {
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

    const uid = try UserIdPacket.parse(allocator, "Alice <alice@example.com>");
    try key.addUserId(allocator, .{
        .user_id = uid,
        .self_signature = null,
        .certifications = .empty,
    });

    try std.testing.expectEqual(@as(usize, 1), key.user_ids.items.len);
    try std.testing.expectEqualStrings("Alice <alice@example.com>", key.primaryUserId().?);
}

test "Key addSubkey" {
    const allocator = std.testing.allocator;

    // Primary key
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

    // Subkey
    var sub_body: [12]u8 = undefined;
    sub_body[0] = 4;
    mem.writeInt(u32, sub_body[1..5], 2000, .big);
    sub_body[5] = 1;
    mem.writeInt(u16, sub_body[6..8], 8, .big);
    sub_body[8] = 0xAA;
    mem.writeInt(u16, sub_body[9..11], 8, .big);
    sub_body[11] = 0x03;

    const subkey = try PublicKeyPacket.parse(allocator, &sub_body, true);

    try key.addSubkey(allocator, .{
        .key = subkey,
        .secret_key = null,
        .binding_signature = null,
    });

    try std.testing.expectEqual(@as(usize, 1), key.subkeys.items.len);
    try std.testing.expect(key.subkeys.items[0].key.is_subkey);
}

test "Key multiple user ids" {
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

    const uid1 = try UserIdPacket.parse(allocator, "Alice <alice@example.com>");
    try key.addUserId(allocator, .{
        .user_id = uid1,
        .self_signature = null,
        .certifications = .empty,
    });

    const uid2 = try UserIdPacket.parse(allocator, "Alice <alice@work.com>");
    try key.addUserId(allocator, .{
        .user_id = uid2,
        .self_signature = null,
        .certifications = .empty,
    });

    try std.testing.expectEqual(@as(usize, 2), key.user_ids.items.len);
    // primaryUserId should return the first one
    try std.testing.expectEqualStrings("Alice <alice@example.com>", key.primaryUserId().?);
}
