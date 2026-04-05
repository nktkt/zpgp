// SPDX-License-Identifier: MIT
//! Key and signature expiration enforcement per RFC 4880.
//!
//! RFC 4880 Section 5.2.3.6 defines the "Key Expiration Time" subpacket
//! (tag 9), which specifies the number of seconds after the key creation
//! time that the key expires. A value of zero means the key never expires.
//!
//! Section 5.2.3.10 defines the "Signature Expiration Time" subpacket
//! (tag 3), which works similarly for signatures.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const Key = @import("key.zig").Key;
const SubkeyBinding = @import("key.zig").SubkeyBinding;
const PublicKeyPacket = @import("../packets/public_key.zig").PublicKeyPacket;
const SignaturePacket = @import("../packets/signature.zig").SignaturePacket;
const subpackets_mod = @import("../signature/subpackets.zig");
const revocation_mod = @import("revocation.zig");

/// Comprehensive key validity status.
pub const KeyValidity = struct {
    valid: bool,
    expired: bool,
    revoked: bool,
    reason: ?[]const u8,
};

/// Get the creation time of the primary key.
pub fn getKeyCreationTime(key: *const Key) u32 {
    return key.primary_key.creation_time;
}

/// Get the key expiration time as an absolute timestamp.
///
/// Returns null if the key has no expiration (never expires).
/// The expiration is found in the self-signature's key_expiration_time subpacket.
pub fn getKeyExpirationTime(key: *const Key, allocator: Allocator) !?u32 {
    // Look for key_expiration_time in the self-signature of the primary user ID
    for (key.user_ids.items) |uid_binding| {
        if (uid_binding.self_signature) |sig| {
            const exp = try getKeyExpirationFromSignature(&sig, allocator);
            if (exp) |offset| {
                if (offset == 0) return null; // 0 means never expires
                return key.primary_key.creation_time +| offset;
            }
        }
    }
    return null;
}

/// Extract key_expiration_time subpacket value from a signature.
/// Returns the offset (seconds after creation), or null if not present.
fn getKeyExpirationFromSignature(sig: *const SignaturePacket, allocator: Allocator) !?u32 {
    const subs = try subpackets_mod.parseSubpackets(allocator, sig.hashed_subpacket_data);
    defer subpackets_mod.freeSubpackets(allocator, subs);

    for (subs) |sp| {
        if (sp.tag == .key_expiration_time) {
            if (sp.asKeyExpirationTime()) |t| {
                return t;
            }
        }
    }
    return null;
}

/// Check if a key has expired based on the given current time.
///
/// A key is expired if its self-signature contains a key_expiration_time
/// subpacket and creation_time + expiration_offset < now.
pub fn isKeyExpired(key: *const Key, now: u32, allocator: Allocator) !bool {
    const exp_time = try getKeyExpirationTime(key, allocator);
    if (exp_time) |t| {
        return now >= t;
    }
    return false;
}

/// Check if a subkey has expired based on its binding signature.
pub fn isSubkeyExpired(binding: *const SubkeyBinding, now: u32, allocator: Allocator) !bool {
    if (binding.binding_signature) |sig| {
        const exp = try getKeyExpirationFromSignature(&sig, allocator);
        if (exp) |offset| {
            if (offset == 0) return false;
            return now >= (binding.key.creation_time +| offset);
        }
    }
    return false;
}

/// Check if a signature has expired.
///
/// Uses the signature's expiration_time subpacket (tag 3) and creation_time
/// subpacket (tag 2). If creation_time + expiration_offset < now, expired.
pub fn isSignatureExpired(sig: *const SignaturePacket, now: u32, allocator: Allocator) !bool {
    const subs = try subpackets_mod.parseSubpackets(allocator, sig.hashed_subpacket_data);
    defer subpackets_mod.freeSubpackets(allocator, subs);

    var creation_time: ?u32 = null;
    var expiration_offset: ?u32 = null;

    for (subs) |sp| {
        if (sp.tag == .creation_time) {
            creation_time = sp.asCreationTime();
        }
        if (sp.tag == .expiration_time) {
            expiration_offset = sp.asExpirationTime();
        }
    }

    if (creation_time) |ct| {
        if (expiration_offset) |eo| {
            if (eo == 0) return false; // 0 means never expires
            return now >= (ct +| eo);
        }
    }

    return false;
}

/// Perform a comprehensive key validity check.
///
/// Checks both expiration and revocation status.
pub fn isKeyValid(key: *const Key, now: u32, allocator: Allocator) !KeyValidity {
    const expired = try isKeyExpired(key, now, allocator);
    const revoked = try revocation_mod.isKeyRevoked(key, allocator);

    var reason: ?[]const u8 = null;
    if (expired and revoked) {
        reason = "Key is both expired and revoked";
    } else if (expired) {
        reason = "Key has expired";
    } else if (revoked) {
        reason = "Key has been revoked";
    }

    return .{
        .valid = !expired and !revoked,
        .expired = expired,
        .revoked = revoked,
        .reason = reason,
    };
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

fn buildSigWithKeyExpiration(allocator: Allocator, expiration_offset: u32) !SignaturePacket {
    // Build hashed subpackets with key_expiration_time
    var hashed: std.ArrayList(u8) = .empty;
    defer hashed.deinit(allocator);

    // Creation time subpacket
    try hashed.append(allocator, 5);
    try hashed.append(allocator, @intFromEnum(subpackets_mod.SubpacketTag.creation_time));
    var ct_buf: [4]u8 = undefined;
    mem.writeInt(u32, &ct_buf, 1000, .big);
    try hashed.appendSlice(allocator, &ct_buf);

    // Key expiration time subpacket
    try hashed.append(allocator, 5);
    try hashed.append(allocator, @intFromEnum(subpackets_mod.SubpacketTag.key_expiration_time));
    var exp_buf: [4]u8 = undefined;
    mem.writeInt(u32, &exp_buf, expiration_offset, .big);
    try hashed.appendSlice(allocator, &exp_buf);

    const hashed_data = try hashed.toOwnedSlice(allocator);
    defer allocator.free(hashed_data);

    // Build sig body
    var sig_body: std.ArrayList(u8) = .empty;
    defer sig_body.deinit(allocator);

    try sig_body.append(allocator, 4);
    try sig_body.append(allocator, 0x13); // positive certification
    try sig_body.append(allocator, 1); // RSA
    try sig_body.append(allocator, 8); // SHA256

    const h_len: u16 = @intCast(hashed_data.len);
    var h_len_buf: [2]u8 = undefined;
    mem.writeInt(u16, &h_len_buf, h_len, .big);
    try sig_body.appendSlice(allocator, &h_len_buf);
    try sig_body.appendSlice(allocator, hashed_data);

    // No unhashed
    try sig_body.appendSlice(allocator, &[_]u8{ 0, 0 });
    // Hash prefix
    try sig_body.appendSlice(allocator, &[_]u8{ 0xAA, 0xBB });
    // MPI placeholder
    try sig_body.appendSlice(allocator, &[_]u8{ 0x00, 0x01, 0x00 });

    const body = try sig_body.toOwnedSlice(allocator);
    defer allocator.free(body);

    return SignaturePacket.parse(allocator, body);
}

pub fn createTestKeyWithExpiration(allocator: Allocator, creation_time: u32, expiration_offset: u32) !Key {
    var pk_body = buildTestKeyBody(creation_time);
    const pk = try PublicKeyPacket.parse(allocator, &pk_body, false);
    errdefer pk.deinit(allocator);

    var key = Key.init(pk);
    errdefer key.deinit(allocator);

    const sig = try buildSigWithKeyExpiration(allocator, expiration_offset);

    const uid = try UserIdPacket.parse(allocator, "Test <test@example.com>");
    try key.addUserId(allocator, .{
        .user_id = uid,
        .self_signature = sig,
        .certifications = .empty,
    });

    return key;
}

test "getKeyCreationTime" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestKeyBody(12345);
    const pk = try PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = Key.init(pk);
    defer key.deinit(allocator);

    try std.testing.expectEqual(@as(u32, 12345), getKeyCreationTime(&key));
}

test "getKeyExpirationTime returns null for no expiration" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestKeyBody(1000);
    const pk = try PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = Key.init(pk);
    defer key.deinit(allocator);

    // No user IDs, no self-signature
    const exp = try getKeyExpirationTime(&key, allocator);
    try std.testing.expect(exp == null);
}

test "getKeyExpirationTime with expiration" {
    const allocator = std.testing.allocator;

    var key = try createTestKeyWithExpiration(allocator, 1000, 86400);
    defer key.deinit(allocator);

    const exp = try getKeyExpirationTime(&key, allocator);
    try std.testing.expect(exp != null);
    try std.testing.expectEqual(@as(u32, 1000 + 86400), exp.?);
}

test "getKeyExpirationTime with zero offset (never expires)" {
    const allocator = std.testing.allocator;

    var key = try createTestKeyWithExpiration(allocator, 1000, 0);
    defer key.deinit(allocator);

    const exp = try getKeyExpirationTime(&key, allocator);
    try std.testing.expect(exp == null);
}

test "isKeyExpired with no expiration" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestKeyBody(1000);
    const pk = try PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = Key.init(pk);
    defer key.deinit(allocator);

    const uid = try UserIdPacket.parse(allocator, "Test <test@test.com>");
    try key.addUserId(allocator, .{
        .user_id = uid,
        .self_signature = null,
        .certifications = .empty,
    });

    try std.testing.expect(!try isKeyExpired(&key, 999999, allocator));
}

test "isKeyExpired with expiration - not yet expired" {
    const allocator = std.testing.allocator;

    var key = try createTestKeyWithExpiration(allocator, 1000, 86400);
    defer key.deinit(allocator);

    // Key expires at 1000 + 86400 = 87400
    try std.testing.expect(!try isKeyExpired(&key, 50000, allocator));
}

test "isKeyExpired with expiration - expired" {
    const allocator = std.testing.allocator;

    var key = try createTestKeyWithExpiration(allocator, 1000, 86400);
    defer key.deinit(allocator);

    // Key expires at 87400, test at 100000
    try std.testing.expect(try isKeyExpired(&key, 100000, allocator));
}

test "isSubkeyExpired with no binding signature" {
    const allocator = std.testing.allocator;

    var sub_body = buildTestKeyBody(2000);
    const subkey = try PublicKeyPacket.parse(allocator, &sub_body, true);
    defer subkey.deinit(allocator);

    const binding = SubkeyBinding{
        .key = subkey,
        .secret_key = null,
        .binding_signature = null,
    };

    try std.testing.expect(!try isSubkeyExpired(&binding, 999999, allocator));
}

test "isSubkeyExpired with binding signature - not expired" {
    const allocator = std.testing.allocator;

    var sub_body = buildTestKeyBody(2000);
    const subkey = try PublicKeyPacket.parse(allocator, &sub_body, true);
    defer subkey.deinit(allocator);

    const sig = try buildSigWithKeyExpiration(allocator, 100000);
    defer sig.deinit(allocator);

    const binding = SubkeyBinding{
        .key = subkey,
        .secret_key = null,
        .binding_signature = sig,
    };

    // Subkey created at 2000, expires at 2000 + 100000 = 102000
    try std.testing.expect(!try isSubkeyExpired(&binding, 50000, allocator));
}

test "isSubkeyExpired with binding signature - expired" {
    const allocator = std.testing.allocator;

    var sub_body = buildTestKeyBody(2000);
    const subkey = try PublicKeyPacket.parse(allocator, &sub_body, true);
    defer subkey.deinit(allocator);

    const sig = try buildSigWithKeyExpiration(allocator, 1000);
    defer sig.deinit(allocator);

    const binding = SubkeyBinding{
        .key = subkey,
        .secret_key = null,
        .binding_signature = sig,
    };

    // Subkey created at 2000, expires at 2000 + 1000 = 3000
    try std.testing.expect(try isSubkeyExpired(&binding, 5000, allocator));
}

test "isSignatureExpired" {
    const allocator = std.testing.allocator;

    // Build a signature with creation_time=1000 and expiration=3600
    var hashed: std.ArrayList(u8) = .empty;
    defer hashed.deinit(allocator);

    // Creation time
    try hashed.append(allocator, 5);
    try hashed.append(allocator, 2);
    var ct_buf: [4]u8 = undefined;
    mem.writeInt(u32, &ct_buf, 1000, .big);
    try hashed.appendSlice(allocator, &ct_buf);

    // Sig expiration time
    try hashed.append(allocator, 5);
    try hashed.append(allocator, 3);
    var et_buf: [4]u8 = undefined;
    mem.writeInt(u32, &et_buf, 3600, .big);
    try hashed.appendSlice(allocator, &et_buf);

    const hashed_data = try hashed.toOwnedSlice(allocator);
    defer allocator.free(hashed_data);

    var sig_body: std.ArrayList(u8) = .empty;
    defer sig_body.deinit(allocator);

    try sig_body.append(allocator, 4);
    try sig_body.append(allocator, 0x00);
    try sig_body.append(allocator, 1);
    try sig_body.append(allocator, 8);

    const h_len: u16 = @intCast(hashed_data.len);
    var h_len_buf: [2]u8 = undefined;
    mem.writeInt(u16, &h_len_buf, h_len, .big);
    try sig_body.appendSlice(allocator, &h_len_buf);
    try sig_body.appendSlice(allocator, hashed_data);

    try sig_body.appendSlice(allocator, &[_]u8{ 0, 0 });
    try sig_body.appendSlice(allocator, &[_]u8{ 0xAA, 0xBB });
    try sig_body.appendSlice(allocator, &[_]u8{ 0x00, 0x01, 0x00 });

    const body = try sig_body.toOwnedSlice(allocator);
    defer allocator.free(body);

    const sig = try SignaturePacket.parse(allocator, body);
    defer sig.deinit(allocator);

    // Not expired at 2000 (creation=1000, expires at 1000+3600=4600)
    try std.testing.expect(!try isSignatureExpired(&sig, 2000, allocator));

    // Expired at 5000
    try std.testing.expect(try isSignatureExpired(&sig, 5000, allocator));
}

test "isKeyValid - valid key" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestKeyBody(1000);
    const pk = try PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = Key.init(pk);
    defer key.deinit(allocator);

    const uid = try UserIdPacket.parse(allocator, "Valid <valid@test.com>");
    try key.addUserId(allocator, .{
        .user_id = uid,
        .self_signature = null,
        .certifications = .empty,
    });

    const validity = try isKeyValid(&key, 5000, allocator);
    try std.testing.expect(validity.valid);
    try std.testing.expect(!validity.expired);
    try std.testing.expect(!validity.revoked);
    try std.testing.expect(validity.reason == null);
}

test "isKeyValid - expired key" {
    const allocator = std.testing.allocator;

    var key = try createTestKeyWithExpiration(allocator, 1000, 500);
    defer key.deinit(allocator);

    const validity = try isKeyValid(&key, 5000, allocator);
    try std.testing.expect(!validity.valid);
    try std.testing.expect(validity.expired);
    try std.testing.expect(!validity.revoked);
    try std.testing.expect(validity.reason != null);
}
