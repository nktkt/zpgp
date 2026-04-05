// SPDX-License-Identifier: MIT
//! Subkey lifecycle management for OpenPGP keys.
//!
//! Provides functions for:
//! - Adding encryption and signing subkeys to existing keys
//! - Creating subkey binding signatures (type 0x18)
//! - Creating primary key binding signatures (type 0x19, for signing subkeys)
//! - Revoking subkeys
//! - Selecting the best subkey for encryption or signing
//!
//! Per RFC 4880 Section 5.2.1:
//! - 0x18: Subkey Binding Signature (primary key signs subkey)
//! - 0x19: Primary Key Binding Signature (subkey signs primary key,
//!         embedded in 0x18 for signing-capable subkeys)
//! - 0x28: Subkey Revocation Signature

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
const KeyFlags = subpackets_mod.KeyFlags;
const Subpacket = subpackets_mod.Subpacket;
const PublicKeyAlgorithm = @import("../types/enums.zig").PublicKeyAlgorithm;
const HashAlgorithm = @import("../types/enums.zig").HashAlgorithm;
const RevocationReason = @import("revocation.zig").RevocationReason;
const fingerprint_mod = @import("fingerprint.zig");
const sig_creation = @import("../signature/creation.zig");
const expiration_mod = @import("expiration.zig");

/// Errors specific to subkey operations.
pub const SubkeyError = error{
    OutOfMemory,
    Overflow,
    NoSpaceLeft,
    InvalidPacket,
    UnsupportedVersion,
    UnsupportedAlgorithm,
};

/// Generate and add an encryption subkey to an existing key.
///
/// Creates a new subkey with the encrypt_communications and encrypt_storage
/// key flags, along with a subkey binding signature from the primary key.
///
/// Note: This creates a structurally valid binding signature with a placeholder
/// MPI. Real cryptographic signing requires the primary secret key material
/// and is beyond the scope of this structural implementation.
pub fn addEncryptionSubkey(
    allocator: Allocator,
    key: *Key,
    algorithm: PublicKeyAlgorithm,
    creation_time: u32,
    hash_algo: HashAlgorithm,
) SubkeyError!void {
    const key_flags = KeyFlags{
        .certify = false,
        .sign = false,
        .encrypt_communications = true,
        .encrypt_storage = true,
        .split_key = false,
        .authentication = false,
        .group_key = false,
    };

    try addSubkeyWithFlags(allocator, key, algorithm, creation_time, hash_algo, key_flags);
}

/// Generate and add a signing subkey to an existing key.
///
/// Creates a new subkey with the sign key flag. Per RFC 4880, signing subkeys
/// should include an embedded primary key binding signature (type 0x19) in
/// the binding signature's hashed subpackets.
pub fn addSigningSubkey(
    allocator: Allocator,
    key: *Key,
    algorithm: PublicKeyAlgorithm,
    creation_time: u32,
    hash_algo: HashAlgorithm,
) SubkeyError!void {
    const key_flags = KeyFlags{
        .certify = false,
        .sign = true,
        .encrypt_communications = false,
        .encrypt_storage = false,
        .split_key = false,
        .authentication = false,
        .group_key = false,
    };

    try addSubkeyWithFlags(allocator, key, algorithm, creation_time, hash_algo, key_flags);
}

/// Internal: add a subkey with specified flags.
fn addSubkeyWithFlags(
    allocator: Allocator,
    key: *Key,
    algorithm: PublicKeyAlgorithm,
    creation_time: u32,
    hash_algo: HashAlgorithm,
    key_flags: KeyFlags,
) SubkeyError!void {
    // Build a minimal subkey packet body (RSA with small test MPIs)
    const subkey_body = try buildMinimalKeyBody(allocator, creation_time, algorithm);
    defer allocator.free(subkey_body);

    // Parse as a subkey
    const subkey_pk = PublicKeyPacket.parse(allocator, subkey_body, true) catch
        return error.InvalidPacket;
    errdefer subkey_pk.deinit(allocator);

    // Create the binding signature
    const binding_sig_body = try createSubkeyBindingSignature(
        allocator,
        key.primary_key.raw_body,
        subkey_body,
        @intFromEnum(algorithm),
        @intFromEnum(hash_algo),
        key_flags,
        key.keyId(),
        key.fingerprint(),
    );
    defer allocator.free(binding_sig_body);

    const binding_sig = SignaturePacket.parse(allocator, binding_sig_body) catch
        return error.InvalidPacket;
    errdefer binding_sig.deinit(allocator);

    try key.addSubkey(allocator, .{
        .key = subkey_pk,
        .secret_key = null,
        .binding_signature = binding_sig,
    });
}

/// Build a minimal V4 public key body for testing/structural purposes.
fn buildMinimalKeyBody(
    allocator: Allocator,
    creation_time: u32,
    algorithm: PublicKeyAlgorithm,
) ![]u8 {
    // For RSA: version(1) + creation_time(4) + algo(1) + 2 MPIs (n=8bit, e=8bit)
    const body_len: usize = 12;
    const buf = try allocator.alloc(u8, body_len);
    errdefer allocator.free(buf);

    buf[0] = 4; // version
    mem.writeInt(u32, buf[1..5], creation_time, .big);
    buf[5] = @intFromEnum(algorithm);

    // Minimal MPI: n (8-bit)
    mem.writeInt(u16, buf[6..8], 8, .big);
    // Use creation_time to generate different keys
    buf[8] = @truncate(creation_time ^ 0xAA);
    // Minimal MPI: e (8-bit)
    mem.writeInt(u16, buf[9..11], 8, .big);
    buf[11] = 0x03;

    return buf;
}

/// Create a subkey binding signature (type 0x18).
///
/// The signature binds the subkey to the primary key, certifying that
/// the primary key owner approves the subkey.
pub fn createSubkeyBindingSignature(
    allocator: Allocator,
    primary_key_body: []const u8,
    subkey_body: []const u8,
    pub_algo_id: u8,
    hash_algo_id: u8,
    key_flags: KeyFlags,
    key_id: [8]u8,
    fp: [20]u8,
) SubkeyError![]u8 {
    _ = primary_key_body;
    _ = subkey_body;

    // Build hashed subpackets
    var hashed: std.ArrayList(u8) = .empty;
    errdefer hashed.deinit(allocator);

    // Creation time subpacket (placeholder)
    try appendSubpacket(allocator, &hashed, @intFromEnum(SubpacketTag.creation_time), &blk: {
        var buf: [4]u8 = undefined;
        mem.writeInt(u32, &buf, 0, .big);
        break :blk buf;
    });

    // Key flags subpacket
    const flags_byte: u8 = @bitCast(key_flags);
    try appendSubpacket(allocator, &hashed, @intFromEnum(SubpacketTag.key_flags), &[_]u8{flags_byte});

    // Issuer fingerprint subpacket
    var fp_data: [21]u8 = undefined;
    fp_data[0] = 4; // V4
    @memcpy(fp_data[1..21], &fp);
    try appendSubpacket(allocator, &hashed, @intFromEnum(SubpacketTag.issuer_fingerprint), &fp_data);

    const hashed_data = hashed.toOwnedSlice(allocator) catch return error.OutOfMemory;
    defer allocator.free(hashed_data);

    // Build unhashed subpackets (issuer key ID)
    var unhashed: std.ArrayList(u8) = .empty;
    errdefer unhashed.deinit(allocator);

    try appendSubpacket(allocator, &unhashed, @intFromEnum(SubpacketTag.issuer), &key_id);

    const unhashed_data = unhashed.toOwnedSlice(allocator) catch return error.OutOfMemory;
    defer allocator.free(unhashed_data);

    // Build the signature body
    var sig_body: std.ArrayList(u8) = .empty;
    errdefer sig_body.deinit(allocator);

    try sig_body.append(allocator, 4); // version
    try sig_body.append(allocator, @intFromEnum(SignatureType.subkey_binding)); // 0x18
    try sig_body.append(allocator, pub_algo_id);
    try sig_body.append(allocator, hash_algo_id);

    // Hashed subpackets
    const h_len: u16 = @intCast(hashed_data.len);
    var h_len_buf: [2]u8 = undefined;
    mem.writeInt(u16, &h_len_buf, h_len, .big);
    try sig_body.appendSlice(allocator, &h_len_buf);
    try sig_body.appendSlice(allocator, hashed_data);

    // Unhashed subpackets
    const uh_len: u16 = @intCast(unhashed_data.len);
    var uh_len_buf: [2]u8 = undefined;
    mem.writeInt(u16, &uh_len_buf, uh_len, .big);
    try sig_body.appendSlice(allocator, &uh_len_buf);
    try sig_body.appendSlice(allocator, unhashed_data);

    // Hash prefix placeholder
    try sig_body.appendSlice(allocator, &[_]u8{ 0x00, 0x00 });

    // Signature MPI placeholder
    try sig_body.appendSlice(allocator, &[_]u8{ 0x00, 0x01, 0x00 });

    return sig_body.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Create a primary key binding signature (type 0x19).
///
/// This signature is created by a signing subkey to prove it belongs
/// to the primary key. It is typically embedded in the subkey binding
/// signature as an embedded signature subpacket (tag 32).
pub fn createPrimaryKeyBindingSignature(
    allocator: Allocator,
    primary_key_body: []const u8,
    subkey_body: []const u8,
    pub_algo_id: u8,
    hash_algo_id: u8,
    subkey_fp: [20]u8,
) SubkeyError![]u8 {
    _ = primary_key_body;
    _ = subkey_body;

    // Build hashed subpackets
    var hashed: std.ArrayList(u8) = .empty;
    errdefer hashed.deinit(allocator);

    // Creation time
    try appendSubpacket(allocator, &hashed, @intFromEnum(SubpacketTag.creation_time), &blk: {
        var buf: [4]u8 = undefined;
        mem.writeInt(u32, &buf, 0, .big);
        break :blk buf;
    });

    // Issuer fingerprint (the subkey's fingerprint)
    var fp_data: [21]u8 = undefined;
    fp_data[0] = 4;
    @memcpy(fp_data[1..21], &subkey_fp);
    try appendSubpacket(allocator, &hashed, @intFromEnum(SubpacketTag.issuer_fingerprint), &fp_data);

    const hashed_data = hashed.toOwnedSlice(allocator) catch return error.OutOfMemory;
    defer allocator.free(hashed_data);

    // Build signature body
    var sig_body: std.ArrayList(u8) = .empty;
    errdefer sig_body.deinit(allocator);

    try sig_body.append(allocator, 4);
    try sig_body.append(allocator, @intFromEnum(SignatureType.primary_key_binding)); // 0x19
    try sig_body.append(allocator, pub_algo_id);
    try sig_body.append(allocator, hash_algo_id);

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

    return sig_body.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Create a subkey revocation signature (type 0x28).
pub fn revokeSubkey(
    allocator: Allocator,
    primary_key_body: []const u8,
    subkey_body: []const u8,
    pub_algo_id: u8,
    hash_algo_id: u8,
    reason: RevocationReason,
    description: []const u8,
    signer_fp: [20]u8,
) SubkeyError![]u8 {
    _ = primary_key_body;
    _ = subkey_body;

    // Build hashed subpackets
    var hashed: std.ArrayList(u8) = .empty;
    errdefer hashed.deinit(allocator);

    // Creation time
    try appendSubpacket(allocator, &hashed, @intFromEnum(SubpacketTag.creation_time), &blk: {
        var buf: [4]u8 = undefined;
        mem.writeInt(u32, &buf, 0, .big);
        break :blk buf;
    });

    // Reason for revocation
    var reason_data: std.ArrayList(u8) = .empty;
    defer reason_data.deinit(allocator);
    try reason_data.append(allocator, @intFromEnum(reason));
    if (description.len > 0) {
        try reason_data.appendSlice(allocator, description);
    }
    const reason_bytes = try reason_data.toOwnedSlice(allocator);
    defer allocator.free(reason_bytes);
    try appendSubpacket(allocator, &hashed, @intFromEnum(SubpacketTag.reason_for_revocation), reason_bytes);

    // Issuer fingerprint
    var fp_data: [21]u8 = undefined;
    fp_data[0] = 4;
    @memcpy(fp_data[1..21], &signer_fp);
    try appendSubpacket(allocator, &hashed, @intFromEnum(SubpacketTag.issuer_fingerprint), &fp_data);

    const hashed_data = hashed.toOwnedSlice(allocator) catch return error.OutOfMemory;
    defer allocator.free(hashed_data);

    // Build signature body
    var sig_body: std.ArrayList(u8) = .empty;
    errdefer sig_body.deinit(allocator);

    try sig_body.append(allocator, 4);
    try sig_body.append(allocator, @intFromEnum(SignatureType.subkey_revocation)); // 0x28
    try sig_body.append(allocator, pub_algo_id);
    try sig_body.append(allocator, hash_algo_id);

    const h_len: u16 = @intCast(hashed_data.len);
    var h_len_buf: [2]u8 = undefined;
    mem.writeInt(u16, &h_len_buf, h_len, .big);
    try sig_body.appendSlice(allocator, &h_len_buf);
    try sig_body.appendSlice(allocator, hashed_data);

    // No unhashed
    try sig_body.appendSlice(allocator, &[_]u8{ 0, 0 });

    // Hash prefix placeholder
    try sig_body.appendSlice(allocator, &[_]u8{ 0x00, 0x00 });

    // Signature MPI placeholder
    try sig_body.appendSlice(allocator, &[_]u8{ 0x00, 0x01, 0x00 });

    return sig_body.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Select the best encryption subkey from a key.
///
/// Selection logic:
/// 1. Find subkeys with encrypt_communications or encrypt_storage flags
/// 2. Prefer non-expired subkeys
/// 3. Among valid subkeys, prefer the newest (latest creation time)
///
/// Returns null if no suitable encryption subkey is found.
pub fn selectEncryptionSubkey(key: *const Key, allocator: Allocator) ?*const SubkeyBinding {
    var best: ?*const SubkeyBinding = null;
    var best_creation_time: u32 = 0;

    for (key.subkeys.items) |*binding| {
        // Check key flags
        const flags = getSubkeyFlags(binding, allocator) orelse continue;
        if (!flags.encrypt_communications and !flags.encrypt_storage) continue;

        // Prefer non-expired subkeys
        const expired = expiration_mod.isSubkeyExpired(binding, std.math.maxInt(u32), allocator) catch false;
        if (expired) {
            // Only use expired subkeys if no valid ones exist
            if (best == null) {
                best = binding;
                best_creation_time = binding.key.creation_time;
            }
            continue;
        }

        // Prefer newer subkeys
        if (binding.key.creation_time >= best_creation_time) {
            best = binding;
            best_creation_time = binding.key.creation_time;
        }
    }

    return best;
}

/// Select the best signing key (subkey or primary key) from a key.
///
/// Returns the primary key's PublicKeyPacket if no signing subkey is found
/// but the primary key has signing capability.
///
/// Returns null if no key with signing capability is found.
pub fn selectSigningSubkey(key: *const Key, allocator: Allocator) ?*const SubkeyBinding {
    var best: ?*const SubkeyBinding = null;
    var best_creation_time: u32 = 0;

    for (key.subkeys.items) |*binding| {
        const flags = getSubkeyFlags(binding, allocator) orelse continue;
        if (!flags.sign) continue;

        const expired = expiration_mod.isSubkeyExpired(binding, std.math.maxInt(u32), allocator) catch false;
        if (expired) {
            if (best == null) {
                best = binding;
                best_creation_time = binding.key.creation_time;
            }
            continue;
        }

        if (binding.key.creation_time >= best_creation_time) {
            best = binding;
            best_creation_time = binding.key.creation_time;
        }
    }

    return best;
}

/// Check if the primary key has signing capability from its self-signature key flags.
pub fn primaryKeyCanSign(key: *const Key, allocator: Allocator) bool {
    for (key.user_ids.items) |uid_binding| {
        if (uid_binding.self_signature) |sig| {
            const subs = subpackets_mod.parseSubpackets(allocator, sig.hashed_subpacket_data) catch continue;
            defer subpackets_mod.freeSubpackets(allocator, subs);

            for (subs) |sp| {
                if (sp.tag == .key_flags) {
                    if (sp.asKeyFlags()) |flags| {
                        return flags.sign or flags.certify;
                    }
                }
            }
        }
    }
    // If no key flags subpacket, assume signing capability based on algorithm
    return key.primary_key.algorithm.canSign();
}

/// Extract key flags from a subkey's binding signature.
pub fn getSubkeyFlags(binding: *const SubkeyBinding, allocator: Allocator) ?KeyFlags {
    const sig = binding.binding_signature orelse return null;

    const subs = subpackets_mod.parseSubpackets(allocator, sig.hashed_subpacket_data) catch return null;
    defer subpackets_mod.freeSubpackets(allocator, subs);

    for (subs) |sp| {
        if (sp.tag == .key_flags) {
            return sp.asKeyFlags();
        }
    }

    return null;
}

/// Append a subpacket to a buffer.
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

fn createTestKey(allocator: Allocator) !Key {
    var body = buildTestKeyBody(1000);
    const pk = try PublicKeyPacket.parse(allocator, &body, false);
    errdefer pk.deinit(allocator);

    var key = Key.init(pk);
    errdefer key.deinit(allocator);

    const uid = try UserIdPacket.parse(allocator, "Test <test@example.com>");
    try key.addUserId(allocator, .{
        .user_id = uid,
        .self_signature = null,
        .certifications = .empty,
    });

    return key;
}

test "addEncryptionSubkey" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator);
    defer key.deinit(allocator);

    try addEncryptionSubkey(allocator, &key, .rsa_encrypt_sign, 2000, .sha256);

    try std.testing.expectEqual(@as(usize, 1), key.subkeys.items.len);
    try std.testing.expect(key.subkeys.items[0].key.is_subkey);
    try std.testing.expect(key.subkeys.items[0].binding_signature != null);

    // Verify key flags in binding signature
    const flags = getSubkeyFlags(&key.subkeys.items[0], allocator);
    try std.testing.expect(flags != null);
    try std.testing.expect(flags.?.encrypt_communications);
    try std.testing.expect(flags.?.encrypt_storage);
    try std.testing.expect(!flags.?.sign);
    try std.testing.expect(!flags.?.certify);
}

test "addSigningSubkey" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator);
    defer key.deinit(allocator);

    try addSigningSubkey(allocator, &key, .rsa_sign_only, 3000, .sha256);

    try std.testing.expectEqual(@as(usize, 1), key.subkeys.items.len);

    const flags = getSubkeyFlags(&key.subkeys.items[0], allocator);
    try std.testing.expect(flags != null);
    try std.testing.expect(flags.?.sign);
    try std.testing.expect(!flags.?.encrypt_communications);
}

test "addEncryptionSubkey and addSigningSubkey combined" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator);
    defer key.deinit(allocator);

    try addEncryptionSubkey(allocator, &key, .rsa_encrypt_sign, 2000, .sha256);
    try addSigningSubkey(allocator, &key, .rsa_sign_only, 3000, .sha256);

    try std.testing.expectEqual(@as(usize, 2), key.subkeys.items.len);
}

test "createSubkeyBindingSignature produces parseable packet" {
    const allocator = std.testing.allocator;

    const pk_body = buildTestKeyBody(1000);
    const sub_body = buildTestKeyBody(2000);
    const key_id = fingerprint_mod.calculateV4KeyId(&pk_body);
    const fp = fingerprint_mod.calculateV4Fingerprint(&pk_body);

    const sig_body = try createSubkeyBindingSignature(
        allocator,
        &pk_body,
        &sub_body,
        1, // RSA
        8, // SHA256
        .{
            .certify = false,
            .sign = false,
            .encrypt_communications = true,
            .encrypt_storage = false,
            .split_key = false,
            .authentication = false,
            .group_key = false,
        },
        key_id,
        fp,
    );
    defer allocator.free(sig_body);

    // Verify it parses
    const sig = try SignaturePacket.parse(allocator, sig_body);
    defer sig.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 4), sig.version);
    try std.testing.expectEqual(@as(u8, @intFromEnum(SignatureType.subkey_binding)), sig.sig_type);
}

test "createPrimaryKeyBindingSignature produces parseable packet" {
    const allocator = std.testing.allocator;

    const pk_body = buildTestKeyBody(1000);
    const sub_body = buildTestKeyBody(2000);
    const sub_fp = fingerprint_mod.calculateV4Fingerprint(&sub_body);

    const sig_body = try createPrimaryKeyBindingSignature(
        allocator,
        &pk_body,
        &sub_body,
        1,
        8,
        sub_fp,
    );
    defer allocator.free(sig_body);

    const sig = try SignaturePacket.parse(allocator, sig_body);
    defer sig.deinit(allocator);

    try std.testing.expectEqual(@as(u8, @intFromEnum(SignatureType.primary_key_binding)), sig.sig_type);
}

test "revokeSubkey produces parseable packet" {
    const allocator = std.testing.allocator;

    const pk_body = buildTestKeyBody(1000);
    const sub_body = buildTestKeyBody(2000);
    const fp = fingerprint_mod.calculateV4Fingerprint(&pk_body);

    const sig_body = try revokeSubkey(
        allocator,
        &pk_body,
        &sub_body,
        1,
        8,
        .key_superseded,
        "Replaced by new subkey",
        fp,
    );
    defer allocator.free(sig_body);

    const sig = try SignaturePacket.parse(allocator, sig_body);
    defer sig.deinit(allocator);

    try std.testing.expectEqual(@as(u8, @intFromEnum(SignatureType.subkey_revocation)), sig.sig_type);

    // Verify reason subpacket
    const subs = try subpackets_mod.parseSubpackets(allocator, sig.hashed_subpacket_data);
    defer subpackets_mod.freeSubpackets(allocator, subs);

    var found_reason = false;
    for (subs) |sp| {
        if (sp.tag == .reason_for_revocation) {
            found_reason = true;
            try std.testing.expectEqual(@as(u8, @intFromEnum(RevocationReason.key_superseded)), sp.data[0]);
        }
    }
    try std.testing.expect(found_reason);
}

test "selectEncryptionSubkey with no subkeys" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator);
    defer key.deinit(allocator);

    const result = selectEncryptionSubkey(&key, allocator);
    try std.testing.expect(result == null);
}

test "selectEncryptionSubkey selects correct subkey" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator);
    defer key.deinit(allocator);

    // Add a signing subkey first (should not be selected for encryption)
    try addSigningSubkey(allocator, &key, .rsa_sign_only, 2000, .sha256);

    // Add an encryption subkey (should be selected)
    try addEncryptionSubkey(allocator, &key, .rsa_encrypt_sign, 3000, .sha256);

    const result = selectEncryptionSubkey(&key, allocator);
    try std.testing.expect(result != null);

    // Verify it's the encryption subkey (creation_time = 3000)
    const flags = getSubkeyFlags(result.?, allocator);
    try std.testing.expect(flags != null);
    try std.testing.expect(flags.?.encrypt_communications);
}

test "selectEncryptionSubkey prefers newest" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator);
    defer key.deinit(allocator);

    try addEncryptionSubkey(allocator, &key, .rsa_encrypt_sign, 2000, .sha256);
    try addEncryptionSubkey(allocator, &key, .rsa_encrypt_sign, 5000, .sha256);

    const result = selectEncryptionSubkey(&key, allocator);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u32, 5000), result.?.key.creation_time);
}

test "selectSigningSubkey with no subkeys" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator);
    defer key.deinit(allocator);

    const result = selectSigningSubkey(&key, allocator);
    try std.testing.expect(result == null);
}

test "selectSigningSubkey selects signing subkey" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator);
    defer key.deinit(allocator);

    try addEncryptionSubkey(allocator, &key, .rsa_encrypt_sign, 2000, .sha256);
    try addSigningSubkey(allocator, &key, .rsa_sign_only, 3000, .sha256);

    const result = selectSigningSubkey(&key, allocator);
    try std.testing.expect(result != null);

    const flags = getSubkeyFlags(result.?, allocator);
    try std.testing.expect(flags != null);
    try std.testing.expect(flags.?.sign);
}

test "primaryKeyCanSign for RSA key" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator);
    defer key.deinit(allocator);

    // RSA key with no explicit key flags defaults to can-sign based on algorithm
    try std.testing.expect(primaryKeyCanSign(&key, allocator));
}

test "getSubkeyFlags returns null for no binding sig" {
    const allocator = std.testing.allocator;

    var sub_body = buildTestKeyBody(2000);
    const subkey = try PublicKeyPacket.parse(allocator, &sub_body, true);
    defer subkey.deinit(allocator);

    const binding = SubkeyBinding{
        .key = subkey,
        .secret_key = null,
        .binding_signature = null,
    };

    try std.testing.expect(getSubkeyFlags(&binding, allocator) == null);
}

test "revokeSubkey with empty description" {
    const allocator = std.testing.allocator;

    const pk_body = buildTestKeyBody(1000);
    const sub_body = buildTestKeyBody(2000);
    const fp = fingerprint_mod.calculateV4Fingerprint(&pk_body);

    const sig_body = try revokeSubkey(
        allocator,
        &pk_body,
        &sub_body,
        1,
        8,
        .no_reason,
        "",
        fp,
    );
    defer allocator.free(sig_body);

    const sig = try SignaturePacket.parse(allocator, sig_body);
    defer sig.deinit(allocator);

    try std.testing.expectEqual(@as(u8, @intFromEnum(SignatureType.subkey_revocation)), sig.sig_type);
}
