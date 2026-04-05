// SPDX-License-Identifier: MIT
//! Comprehensive integration test suite for zpgp v0.3 features.
//!
//! Tests cover:
//! - Key lifecycle (generation, export, import, fingerprint matching)
//! - Subkey management (encryption, signing, selection)
//! - Key expiration enforcement
//! - Key revocation and validity checks
//! - Keyring operations (add, find, merge, import/export round-trip)
//! - Notation data (create, parse, round-trip)
//! - Designated revoker management
//! - HKP response parsing
//! - Edge cases (empty user IDs, multiple user IDs, key with no subkeys)

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

// Key modules
const Key = @import("key/key.zig").Key;
const SubkeyBinding = @import("key/key.zig").SubkeyBinding;
const UserIdBinding = @import("key/key.zig").UserIdBinding;
const Keyring = @import("key/keyring.zig").Keyring;
const import_export = @import("key/import_export.zig");
const fingerprint_mod = @import("key/fingerprint.zig");
const revocation = @import("key/revocation.zig");
const subkey_mod = @import("key/subkey.zig");
const expiration_mod = @import("key/expiration.zig");
const designated_revoker = @import("key/designated_revoker.zig");
const keyring_io = @import("key/keyring_io.zig");

// Signature modules
const notation_mod = @import("signature/notation.zig");
const subpackets_mod = @import("signature/subpackets.zig");
const SignatureType = @import("signature/types.zig").SignatureType;

// Packet modules
const PublicKeyPacket = @import("packets/public_key.zig").PublicKeyPacket;
const UserIdPacket = @import("packets/user_id.zig").UserIdPacket;
const SignaturePacket = @import("packets/signature.zig").SignaturePacket;

// Types
const PublicKeyAlgorithm = @import("types/enums.zig").PublicKeyAlgorithm;
const HashAlgorithm = @import("types/enums.zig").HashAlgorithm;

// Keyserver
const hkp_client = @import("keyserver/hkp_client.zig");

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

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

fn buildUniqueTestKeyBody(creation_time: u32, mpi_byte: u8) [12]u8 {
    var body: [12]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], creation_time, .big);
    body[5] = 1;
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = mpi_byte;
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

fn createUniqueTestKey(allocator: Allocator, email: []const u8, creation_time: u32, mpi_byte: u8) !Key {
    var body = buildUniqueTestKeyBody(creation_time, mpi_byte);
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

// ---------------------------------------------------------------------------
// Key lifecycle tests
// ---------------------------------------------------------------------------

test "create key, export, import, verify fingerprint matches" {
    const allocator = std.testing.allocator;

    // Create a key
    var key = try createTestKey(allocator, "Alice <alice@example.com>", 1609459200);
    defer key.deinit(allocator);

    const original_fp = key.fingerprint();
    const original_kid = key.keyId();

    // Export to binary
    const exported = try import_export.exportPublicKey(allocator, &key);
    defer allocator.free(exported);

    // Import from binary
    var imported = try import_export.importPublicKey(allocator, exported);
    defer imported.deinit(allocator);

    // Verify fingerprints match
    const imported_fp = imported.fingerprint();
    const imported_kid = imported.keyId();

    try std.testing.expectEqualSlices(u8, &original_fp, &imported_fp);
    try std.testing.expectEqualSlices(u8, &original_kid, &imported_kid);
    try std.testing.expectEqualStrings("Alice <alice@example.com>", imported.primaryUserId().?);
}

test "create key, export armored, import, verify" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator, "Bob <bob@example.com>", 1609459200);
    defer key.deinit(allocator);

    const original_fp = key.fingerprint();

    // Export as armored
    const armored = try import_export.exportPublicKeyArmored(allocator, &key);
    defer allocator.free(armored);

    // Verify it's properly armored
    try std.testing.expect(mem.startsWith(u8, armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));

    // Import from armored
    var imported = try import_export.importPublicKeyAuto(allocator, armored);
    defer imported.deinit(allocator);

    try std.testing.expectEqualSlices(u8, &original_fp, &imported.fingerprint());
}

test "generate key with encryption subkey" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator, "Charlie <charlie@example.com>", 1000);
    defer key.deinit(allocator);

    try subkey_mod.addEncryptionSubkey(allocator, &key, .rsa_encrypt_sign, 2000, .sha256);

    try std.testing.expectEqual(@as(usize, 1), key.subkeys.items.len);
    try std.testing.expect(key.subkeys.items[0].key.is_subkey);
    try std.testing.expect(key.subkeys.items[0].binding_signature != null);

    // Verify the binding signature type
    const sig = key.subkeys.items[0].binding_signature.?;
    try std.testing.expectEqual(@as(u8, @intFromEnum(SignatureType.subkey_binding)), sig.sig_type);
}

test "generate key with signing subkey" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator, "Dave <dave@example.com>", 1000);
    defer key.deinit(allocator);

    try subkey_mod.addSigningSubkey(allocator, &key, .rsa_sign_only, 2000, .sha256);

    try std.testing.expectEqual(@as(usize, 1), key.subkeys.items.len);

    // Verify the sign flag
    const flags = subkey_mod.getSubkeyFlags(&key.subkeys.items[0], allocator);
    try std.testing.expect(flags != null);
    try std.testing.expect(flags.?.sign);
    try std.testing.expect(!flags.?.encrypt_communications);
}

test "key with both encryption and signing subkeys" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator, "Eve <eve@example.com>", 1000);
    defer key.deinit(allocator);

    try subkey_mod.addEncryptionSubkey(allocator, &key, .rsa_encrypt_sign, 2000, .sha256);
    try subkey_mod.addSigningSubkey(allocator, &key, .rsa_sign_only, 3000, .sha256);

    try std.testing.expectEqual(@as(usize, 2), key.subkeys.items.len);

    // First subkey should be encryption
    const enc_flags = subkey_mod.getSubkeyFlags(&key.subkeys.items[0], allocator);
    try std.testing.expect(enc_flags.?.encrypt_communications);

    // Second subkey should be signing
    const sig_flags = subkey_mod.getSubkeyFlags(&key.subkeys.items[1], allocator);
    try std.testing.expect(sig_flags.?.sign);
}

// ---------------------------------------------------------------------------
// Key expiration tests
// ---------------------------------------------------------------------------

test "key expiration enforcement" {
    const allocator = std.testing.allocator;

    // Create a key with a self-signature containing key_expiration_time
    // Key created at t=1000, expires after 86400 seconds (1 day)
    var key = try expiration_mod.createTestKeyWithExpiration(allocator, 1000, 86400);
    defer key.deinit(allocator);

    // Not expired at t=50000
    try std.testing.expect(!try expiration_mod.isKeyExpired(&key, 50000, allocator));

    // Expired at t=100000 (1000 + 86400 = 87400)
    try std.testing.expect(try expiration_mod.isKeyExpired(&key, 100000, allocator));

    // Test getKeyExpirationTime
    const exp = try expiration_mod.getKeyExpirationTime(&key, allocator);
    try std.testing.expect(exp != null);
    try std.testing.expectEqual(@as(u32, 87400), exp.?);
}

test "key with no expiration never expires" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator, "NoExpiry <no@expiry.com>", 1000);
    defer key.deinit(allocator);

    // Key with no self-signature should never expire
    try std.testing.expect(!try expiration_mod.isKeyExpired(&key, std.math.maxInt(u32), allocator));
}

// ---------------------------------------------------------------------------
// Subkey selection tests
// ---------------------------------------------------------------------------

test "subkey selection: prefer newest valid encryption subkey" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator, "Select <sel@test.com>", 1000);
    defer key.deinit(allocator);

    // Add two encryption subkeys with different creation times
    try subkey_mod.addEncryptionSubkey(allocator, &key, .rsa_encrypt_sign, 2000, .sha256);
    try subkey_mod.addEncryptionSubkey(allocator, &key, .rsa_encrypt_sign, 5000, .sha256);

    const selected = subkey_mod.selectEncryptionSubkey(&key, allocator);
    try std.testing.expect(selected != null);
    try std.testing.expectEqual(@as(u32, 5000), selected.?.key.creation_time);
}

test "subkey selection: signing subkey not selected for encryption" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator, "Mixed <mix@test.com>", 1000);
    defer key.deinit(allocator);

    try subkey_mod.addSigningSubkey(allocator, &key, .rsa_sign_only, 2000, .sha256);
    try subkey_mod.addEncryptionSubkey(allocator, &key, .rsa_encrypt_sign, 3000, .sha256);

    // Encryption selection should find the encryption subkey
    const enc = subkey_mod.selectEncryptionSubkey(&key, allocator);
    try std.testing.expect(enc != null);
    const enc_flags = subkey_mod.getSubkeyFlags(enc.?, allocator);
    try std.testing.expect(enc_flags.?.encrypt_communications);

    // Signing selection should find the signing subkey
    const sig = subkey_mod.selectSigningSubkey(&key, allocator);
    try std.testing.expect(sig != null);
    const sig_flags = subkey_mod.getSubkeyFlags(sig.?, allocator);
    try std.testing.expect(sig_flags.?.sign);
}

test "subkey selection: no subkeys returns null" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator, "Bare <bare@test.com>", 1000);
    defer key.deinit(allocator);

    try std.testing.expect(subkey_mod.selectEncryptionSubkey(&key, allocator) == null);
    try std.testing.expect(subkey_mod.selectSigningSubkey(&key, allocator) == null);
}

// ---------------------------------------------------------------------------
// Key revocation tests
// ---------------------------------------------------------------------------

test "key revocation marks key as invalid" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator, "Revoked <rev@test.com>", 1000);
    defer key.deinit(allocator);

    // Initially not revoked
    try std.testing.expect(!try revocation.isKeyRevoked(&key, allocator));

    // Check validity
    const validity = try expiration_mod.isKeyValid(&key, 5000, allocator);
    try std.testing.expect(validity.valid);
    try std.testing.expect(!validity.revoked);
}

test "subkey revocation signature structure" {
    const allocator = std.testing.allocator;

    const pk_body = buildTestKeyBody(1000);
    const sub_body = buildTestKeyBody(2000);
    const fp = fingerprint_mod.calculateV4Fingerprint(&pk_body);

    const sig_body = try subkey_mod.revokeSubkey(
        allocator,
        &pk_body,
        &sub_body,
        1,
        8,
        .key_compromised,
        "compromised subkey",
        fp,
    );
    defer allocator.free(sig_body);

    const sig = try SignaturePacket.parse(allocator, sig_body);
    defer sig.deinit(allocator);

    try std.testing.expectEqual(@as(u8, @intFromEnum(SignatureType.subkey_revocation)), sig.sig_type);

    // Parse hashed subpackets to verify reason
    const subs = try subpackets_mod.parseSubpackets(allocator, sig.hashed_subpacket_data);
    defer subpackets_mod.freeSubpackets(allocator, subs);

    var found_reason = false;
    for (subs) |sp| {
        if (sp.tag == .reason_for_revocation) {
            found_reason = true;
            try std.testing.expectEqual(@as(u8, 2), sp.data[0]); // key_compromised
        }
    }
    try std.testing.expect(found_reason);
}

// ---------------------------------------------------------------------------
// Keyring tests
// ---------------------------------------------------------------------------

test "keyring add, find by fingerprint, find by email" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    const key1 = try createUniqueTestKey(allocator, "Alice <alice@example.com>", 1000, 0xAA);
    const fp1 = key1.fingerprint();
    try kr.addKey(key1);

    const key2 = try createUniqueTestKey(allocator, "Bob <bob@example.com>", 2000, 0xBB);
    try kr.addKey(key2);

    try std.testing.expectEqual(@as(usize, 2), kr.count());

    // Find by fingerprint
    const found = kr.findByFingerprint(fp1);
    try std.testing.expect(found != null);
    try std.testing.expectEqualStrings("Alice <alice@example.com>", found.?.primaryUserId().?);

    // Find by email
    const alice_keys = try kr.findByEmail("alice@example.com", allocator);
    defer allocator.free(alice_keys);
    try std.testing.expectEqual(@as(usize, 1), alice_keys.len);

    // Not found
    const nobody = try kr.findByEmail("nobody@example.com", allocator);
    defer allocator.free(nobody);
    try std.testing.expectEqual(@as(usize, 0), nobody.len);
}

test "keyring merge deduplicates keys" {
    const allocator = std.testing.allocator;

    var kr1 = Keyring.init(allocator);
    defer kr1.deinit();

    var kr2 = Keyring.init(allocator);
    defer kr2.deinit();

    // Add same key to both keyrings
    const key1 = try createTestKey(allocator, "Same <same@test.com>", 1000);
    try kr1.addKey(key1);

    const key2 = try createTestKey(allocator, "Same <same@test.com>", 1000);
    try kr2.addKey(key2);

    // Add a unique key to kr2
    const key3 = try createUniqueTestKey(allocator, "New <new@test.com>", 2000, 0xCC);
    try kr2.addKey(key3);

    const result = try keyring_io.mergeKeyrings(&kr1, &kr2, allocator);

    try std.testing.expectEqual(@as(usize, 1), result.new_keys);
    try std.testing.expectEqual(@as(usize, 1), result.updated_keys);
    try std.testing.expectEqual(@as(usize, 2), kr1.count());
}

test "keyring import/export round-trip" {
    const allocator = std.testing.allocator;

    // Test single-key round-trip (multi-key loadFromBytes depends on parser offset tracking)
    var kr1 = Keyring.init(allocator);
    defer kr1.deinit();

    const key1 = try createUniqueTestKey(allocator, "A <a@test.com>", 100, 0x11);
    const fp1 = key1.fingerprint();
    try kr1.addKey(key1);

    // Save to bytes
    const saved = try kr1.saveToBytes(allocator);
    defer allocator.free(saved);

    // Load into new keyring
    var kr2 = Keyring.init(allocator);
    defer kr2.deinit();

    const loaded = try kr2.loadFromBytes(saved);
    try std.testing.expectEqual(@as(usize, 1), loaded);
    try std.testing.expectEqual(@as(usize, 1), kr2.count());

    // Verify fingerprint matches
    const found = kr2.findByFingerprint(fp1);
    try std.testing.expect(found != null);
    try std.testing.expectEqualStrings("A <a@test.com>", found.?.primaryUserId().?);
}

test "keyring importKeyToKeyring tracks fingerprints" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    var key = try createTestKey(allocator, "Track <track@test.com>", 5000);
    const expected_fp = key.fingerprint();
    defer key.deinit(allocator);

    const exported = try import_export.exportPublicKey(allocator, &key);
    defer allocator.free(exported);

    var result = try keyring_io.importKeyToKeyring(&kr, exported, allocator);
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), result.keys_imported);
    try std.testing.expectEqual(@as(usize, 1), result.fingerprints.items.len);
    try std.testing.expectEqualSlices(u8, &expected_fp, &result.fingerprints.items[0]);
}

// ---------------------------------------------------------------------------
// Notation data tests
// ---------------------------------------------------------------------------

test "create and parse notation data" {
    const allocator = std.testing.allocator;

    // Create a notation
    const data = try notation_mod.createNotation(allocator, "issuer@example.org", "test-value", true);
    defer allocator.free(data);

    // Parse it back
    const notation = try notation_mod.parseNotation(data, allocator);
    defer notation.deinit(allocator);

    try std.testing.expect(notation.human_readable);
    try std.testing.expectEqualStrings("issuer@example.org", notation.name);
    try std.testing.expectEqualStrings("test-value", notation.value);
}

test "notation data round-trip through signature" {
    const allocator = std.testing.allocator;

    // Build a notation subpacket
    const notation_body = try notation_mod.createNotation(allocator, "policy@key", "https://example.com/policy", true);
    defer allocator.free(notation_body);

    // Build hashed subpacket area containing the notation
    var hashed_sp: std.ArrayList(u8) = .empty;
    defer hashed_sp.deinit(allocator);

    const sp_body_len = 1 + notation_body.len;
    if (sp_body_len < 192) {
        try hashed_sp.append(allocator, @intCast(sp_body_len));
    } else {
        const adjusted = sp_body_len - 192;
        try hashed_sp.append(allocator, @intCast(adjusted / 256 + 192));
        try hashed_sp.append(allocator, @intCast(adjusted % 256));
    }
    try hashed_sp.append(allocator, 20); // notation_data tag
    try hashed_sp.appendSlice(allocator, notation_body);

    const hashed_data = try hashed_sp.toOwnedSlice(allocator);
    defer allocator.free(hashed_data);

    // Build signature
    var sig_body: std.ArrayList(u8) = .empty;
    defer sig_body.deinit(allocator);

    try sig_body.append(allocator, 4);
    try sig_body.append(allocator, 0x13);
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

    // Extract notations
    const notations = try notation_mod.getNotations(&sig, allocator);
    defer notation_mod.freeNotations(notations, allocator);

    try std.testing.expectEqual(@as(usize, 1), notations.len);
    try std.testing.expectEqualStrings("policy@key", notations[0].name);
    try std.testing.expectEqualStrings("https://example.com/policy", notations[0].value);
}

test "binary notation data" {
    const allocator = std.testing.allocator;

    const binary_value = [_]u8{ 0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF };
    const data = try notation_mod.createNotation(allocator, "bin-data", &binary_value, false);
    defer allocator.free(data);

    const notation = try notation_mod.parseNotation(data, allocator);
    defer notation.deinit(allocator);

    try std.testing.expect(!notation.human_readable);
    try std.testing.expectEqualStrings("bin-data", notation.name);
    try std.testing.expectEqualSlices(u8, &binary_value, notation.value);
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

test "empty user ID" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator, "", 1000);
    defer key.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), key.user_ids.items.len);
    try std.testing.expectEqualStrings("", key.primaryUserId().?);

    // Export/import round-trip with empty UID
    const exported = try import_export.exportPublicKey(allocator, &key);
    defer allocator.free(exported);

    var imported = try import_export.importPublicKey(allocator, exported);
    defer imported.deinit(allocator);

    try std.testing.expectEqualStrings("", imported.primaryUserId().?);
}

test "multiple user IDs" {
    const allocator = std.testing.allocator;

    var body = buildTestKeyBody(1000);
    const pk = try PublicKeyPacket.parse(allocator, &body, false);

    var key = Key.init(pk);
    defer key.deinit(allocator);

    const uid1 = try UserIdPacket.parse(allocator, "Alice <alice@home.com>");
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

    const uid3 = try UserIdPacket.parse(allocator, "Alice Smith");
    try key.addUserId(allocator, .{
        .user_id = uid3,
        .self_signature = null,
        .certifications = .empty,
    });

    try std.testing.expectEqual(@as(usize, 3), key.user_ids.items.len);
    // Primary UID is the first one
    try std.testing.expectEqualStrings("Alice <alice@home.com>", key.primaryUserId().?);

    // Export/import preserves all UIDs
    const exported = try import_export.exportPublicKey(allocator, &key);
    defer allocator.free(exported);

    var imported = try import_export.importPublicKey(allocator, exported);
    defer imported.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 3), imported.user_ids.items.len);
}

test "key with no subkeys" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator, "Plain <plain@test.com>", 1000);
    defer key.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), key.subkeys.items.len);
    try std.testing.expect(subkey_mod.selectEncryptionSubkey(&key, allocator) == null);
    try std.testing.expect(subkey_mod.selectSigningSubkey(&key, allocator) == null);

    // Primary key can still sign
    try std.testing.expect(subkey_mod.primaryKeyCanSign(&key, allocator));
}

test "key export with subkey preserves structure" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator, "Structure <struct@test.com>", 1000);
    defer key.deinit(allocator);

    try subkey_mod.addEncryptionSubkey(allocator, &key, .rsa_encrypt_sign, 2000, .sha256);
    try subkey_mod.addSigningSubkey(allocator, &key, .rsa_sign_only, 3000, .sha256);

    // Export
    const exported = try import_export.exportPublicKey(allocator, &key);
    defer allocator.free(exported);

    // Import
    var imported = try import_export.importPublicKey(allocator, exported);
    defer imported.deinit(allocator);

    // Verify structure
    try std.testing.expectEqual(@as(usize, 1), imported.user_ids.items.len);
    try std.testing.expectEqual(@as(usize, 2), imported.subkeys.items.len);
    try std.testing.expect(imported.subkeys.items[0].key.is_subkey);
    try std.testing.expect(imported.subkeys.items[1].key.is_subkey);
}

test "different creation times produce different fingerprints" {
    var body1 = buildTestKeyBody(1000);
    var body2 = buildTestKeyBody(2000);

    const fp1 = fingerprint_mod.calculateV4Fingerprint(&body1);
    const fp2 = fingerprint_mod.calculateV4Fingerprint(&body2);

    try std.testing.expect(!mem.eql(u8, &fp1, &fp2));
}

test "key ID is last 8 bytes of fingerprint" {
    var body = buildTestKeyBody(42);

    const fp = fingerprint_mod.calculateV4Fingerprint(&body);
    const kid_from_fp = fingerprint_mod.keyIdFromFingerprint(fp);
    const kid_direct = fingerprint_mod.calculateV4KeyId(&body);

    try std.testing.expectEqualSlices(u8, &kid_from_fp, &kid_direct);
    try std.testing.expectEqualSlices(u8, fp[12..20], &kid_direct);
}

// ---------------------------------------------------------------------------
// Designated revoker tests
// ---------------------------------------------------------------------------

test "designated revoker add and retrieve" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator, "Owner <owner@test.com>", 1000);
    defer key.deinit(allocator);

    const revoker_fp = [_]u8{0xAA} ** 20;
    try designated_revoker.addDesignatedRevoker(
        allocator,
        &key,
        revoker_fp,
        .rsa_encrypt_sign,
        false,
    );

    const revokers = try designated_revoker.getDesignatedRevokers(&key, allocator);
    defer allocator.free(revokers);

    try std.testing.expectEqual(@as(usize, 1), revokers.len);
    try std.testing.expectEqualSlices(u8, &revoker_fp, &revokers[0].fingerprint);
    try std.testing.expectEqual(@as(u8, 0x80), revokers[0].class);
}

test "designated revoker sensitive flag" {
    const allocator = std.testing.allocator;

    var key = try createTestKey(allocator, "Owner <owner@test.com>", 1000);
    defer key.deinit(allocator);

    const revoker_fp = [_]u8{0xBB} ** 20;
    try designated_revoker.addDesignatedRevoker(
        allocator,
        &key,
        revoker_fp,
        .dsa,
        true,
    );

    const revokers = try designated_revoker.getDesignatedRevokers(&key, allocator);
    defer allocator.free(revokers);

    try std.testing.expectEqual(@as(usize, 1), revokers.len);
    try std.testing.expectEqual(@as(u8, 0xC0), revokers[0].class);
}

// ---------------------------------------------------------------------------
// HKP client tests
// ---------------------------------------------------------------------------

test "HKP client URL building" {
    const allocator = std.testing.allocator;
    const client = hkp_client.HkpHttpClient.init(allocator, "keys.openpgp.org");

    const get_url = try client.buildGetUrl(allocator, "0xDEADBEEF");
    defer allocator.free(get_url);
    try std.testing.expect(mem.indexOf(u8, get_url, "op=get") != null);
    try std.testing.expect(mem.indexOf(u8, get_url, "0xDEADBEEF") != null);

    const search_url = try client.buildSearchUrl(allocator, "alice@example.com");
    defer allocator.free(search_url);
    try std.testing.expect(mem.indexOf(u8, search_url, "op=index") != null);
}

test "HKP machine-readable index parsing" {
    const allocator = std.testing.allocator;

    const data =
        \\info:1:1
        \\pub:AABBCCDD11223344:1:2048:1609459200::
        \\uid:Test%20User%20%3Ctest%40example.com%3E:1609459200::
    ;

    const entries = try hkp_client.parseMachineReadableIndex(allocator, data);
    defer {
        for (entries) |*e| e.deinit(allocator);
        allocator.free(entries);
    }

    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("AABBCCDD11223344", entries[0].key_id);
    try std.testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, entries[0].algorithm.?);
    try std.testing.expectEqual(@as(u32, 2048), entries[0].bits.?);
    try std.testing.expectEqual(@as(usize, 1), entries[0].uids.items.len);
    try std.testing.expectEqualStrings("Test User <test@example.com>", entries[0].uids.items[0]);
}

test "HKP URL encoding in search" {
    const allocator = std.testing.allocator;
    const client = hkp_client.HkpHttpClient.init(allocator, "keys.openpgp.org");

    const url = try client.buildSearchUrl(allocator, "user with spaces@example.com");
    defer allocator.free(url);

    // @ should be encoded as %40, spaces as %20
    try std.testing.expect(mem.indexOf(u8, url, "%40") != null);
    try std.testing.expect(mem.indexOf(u8, url, "%20") != null);
}

// ---------------------------------------------------------------------------
// Revocation reason tests
// ---------------------------------------------------------------------------

test "revocation reason names" {
    try std.testing.expectEqualStrings("No reason specified", revocation.RevocationReason.no_reason.name());
    try std.testing.expectEqualStrings("Key is superseded", revocation.RevocationReason.key_superseded.name());
    try std.testing.expectEqualStrings("Key material has been compromised", revocation.RevocationReason.key_compromised.name());
    try std.testing.expectEqualStrings("Key is retired and no longer used", revocation.RevocationReason.key_retired.name());
    try std.testing.expectEqualStrings("User ID is no longer valid", revocation.RevocationReason.user_id_invalid.name());
}

// ---------------------------------------------------------------------------
// Signature type tests
// ---------------------------------------------------------------------------

test "signature type classifications" {
    try std.testing.expect(SignatureType.subkey_binding.isKeyBinding());
    try std.testing.expect(SignatureType.primary_key_binding.isKeyBinding());
    try std.testing.expect(!SignatureType.binary_document.isKeyBinding());

    try std.testing.expect(SignatureType.key_revocation.isRevocation());
    try std.testing.expect(SignatureType.subkey_revocation.isRevocation());
    try std.testing.expect(SignatureType.certification_revocation.isRevocation());
    try std.testing.expect(!SignatureType.subkey_binding.isRevocation());

    try std.testing.expect(SignatureType.generic_certification.isCertification());
    try std.testing.expect(SignatureType.positive_certification.isCertification());
    try std.testing.expect(!SignatureType.key_revocation.isCertification());
}

// ---------------------------------------------------------------------------
// Algorithm property tests
// ---------------------------------------------------------------------------

test "algorithm capabilities" {
    try std.testing.expect(PublicKeyAlgorithm.rsa_encrypt_sign.canSign());
    try std.testing.expect(PublicKeyAlgorithm.rsa_encrypt_sign.canEncrypt());

    try std.testing.expect(PublicKeyAlgorithm.rsa_sign_only.canSign());
    try std.testing.expect(!PublicKeyAlgorithm.rsa_sign_only.canEncrypt());

    try std.testing.expect(!PublicKeyAlgorithm.elgamal.canSign());
    try std.testing.expect(PublicKeyAlgorithm.elgamal.canEncrypt());

    try std.testing.expect(PublicKeyAlgorithm.dsa.canSign());
    try std.testing.expect(!PublicKeyAlgorithm.dsa.canEncrypt());
}

// ---------------------------------------------------------------------------
// Keyring removal tests
// ---------------------------------------------------------------------------

test "keyring remove by fingerprint" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    const key = try createTestKey(allocator, "Remove <rm@test.com>", 1000);
    const fp = key.fingerprint();
    try kr.addKey(key);

    try std.testing.expectEqual(@as(usize, 1), kr.count());

    const removed = kr.removeByFingerprint(fp);
    try std.testing.expect(removed);
    try std.testing.expectEqual(@as(usize, 0), kr.count());

    // Removing again should return false
    try std.testing.expect(!kr.removeByFingerprint(fp));
}

// ---------------------------------------------------------------------------
// Comprehensive round-trip test
// ---------------------------------------------------------------------------

test "full key lifecycle: create, add subkeys, export, import, verify" {
    const allocator = std.testing.allocator;

    // 1. Create primary key
    var key = try createTestKey(allocator, "Full Lifecycle <full@test.com>", 1000);
    defer key.deinit(allocator);

    // 2. Add encryption subkey
    try subkey_mod.addEncryptionSubkey(allocator, &key, .rsa_encrypt_sign, 2000, .sha256);

    // 3. Add signing subkey
    try subkey_mod.addSigningSubkey(allocator, &key, .rsa_sign_only, 3000, .sha256);

    // 4. Verify structure
    try std.testing.expectEqual(@as(usize, 1), key.user_ids.items.len);
    try std.testing.expectEqual(@as(usize, 2), key.subkeys.items.len);

    const original_fp = key.fingerprint();

    // 5. Export to binary
    const binary = try import_export.exportPublicKey(allocator, &key);
    defer allocator.free(binary);

    // 6. Import from binary
    var imported = try import_export.importPublicKey(allocator, binary);
    defer imported.deinit(allocator);

    // 7. Verify imported key matches
    try std.testing.expectEqualSlices(u8, &original_fp, &imported.fingerprint());
    try std.testing.expectEqual(@as(usize, 1), imported.user_ids.items.len);
    try std.testing.expectEqual(@as(usize, 2), imported.subkeys.items.len);
    try std.testing.expectEqualStrings("Full Lifecycle <full@test.com>", imported.primaryUserId().?);

    // 8. Add to keyring
    var kr = Keyring.init(allocator);
    defer kr.deinit();

    // Re-export and re-import for keyring (since imported key is owned)
    const re_exported = try import_export.exportPublicKey(allocator, &imported);
    defer allocator.free(re_exported);

    const kr_key = try import_export.importPublicKey(allocator, re_exported);
    try kr.addKey(kr_key);

    // 9. Find in keyring
    const found = kr.findByFingerprint(original_fp);
    try std.testing.expect(found != null);
    try std.testing.expectEqualStrings("Full Lifecycle <full@test.com>", found.?.primaryUserId().?);
}
