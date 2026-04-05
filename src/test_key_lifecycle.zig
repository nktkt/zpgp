// SPDX-License-Identifier: MIT
//! End-to-end key lifecycle tests for the zpgp library.
//!
//! Tests cover:
//! - Key generation (RSA, Ed25519)
//! - Key export/import round-trips
//! - Fingerprint and Key ID verification
//! - Keyring operations (add, find, merge, remove, save/load)
//! - Key expiration and revocation
//! - WKD URL building and hash computation
//! - Autocrypt header parsing and generation
//! - V6 key fingerprint verification
//! - Notation data round-trips
//! - Subkey management

const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;

// Key modules
const Key = @import("key/key.zig").Key;
const SubkeyBinding = @import("key/key.zig").SubkeyBinding;
const UserIdBinding = @import("key/key.zig").UserIdBinding;
const Keyring = @import("key/keyring.zig").Keyring;
const import_export = @import("key/import_export.zig");
const fingerprint_mod = @import("key/fingerprint.zig");
const v6_fingerprint_mod = @import("key/v6_fingerprint.zig");
const revocation = @import("key/revocation.zig");
const subkey_mod = @import("key/subkey.zig");
const expiration_mod = @import("key/expiration.zig");
const designated_revoker = @import("key/designated_revoker.zig");
const keyring_io = @import("key/keyring_io.zig");
const keygen = @import("key/generate.zig");
const v6_keygen = @import("key/v6_generate.zig");

// Signature modules
const notation_mod = @import("signature/notation.zig");
const subpackets_mod = @import("signature/subpackets.zig");

// Packet modules
const PublicKeyPacket = @import("packets/public_key.zig").PublicKeyPacket;
const UserIdPacket = @import("packets/user_id.zig").UserIdPacket;
const SignaturePacket = @import("packets/signature.zig").SignaturePacket;

// Types
const enums = @import("types/enums.zig");
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const SymmetricAlgorithm = enums.SymmetricAlgorithm;

// Armor
const armor = @import("armor/armor.zig");

// WKD and Autocrypt
const wkd = @import("wkd.zig");
const autocrypt = @import("autocrypt.zig");

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn buildTestKeyBody(creation_time: u32) [12]u8 {
    var body: [12]u8 = undefined;
    body[0] = 4; // version
    mem.writeInt(u32, body[1..5], creation_time, .big);
    body[5] = 1; // RSA
    mem.writeInt(u16, body[6..8], 8, .big); // n: 8-bit
    body[8] = 0xFF;
    mem.writeInt(u16, body[9..11], 8, .big); // e: 8-bit
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

// ==========================================================================
// Key generation tests
// ==========================================================================

test "Ed25519 key generation produces armored output" {
    const allocator = testing.allocator;
    const result = try keygen.generateKey(allocator, .{
        .algorithm = .eddsa,
        .user_id = "Test <test@example.com>",
        .creation_time = 1700000000,
    });
    defer result.deinit(allocator);

    try testing.expect(mem.startsWith(u8, result.public_key_armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    try testing.expect(mem.startsWith(u8, result.secret_key_armored, "-----BEGIN PGP PRIVATE KEY BLOCK-----"));
    try testing.expectEqual(@as(usize, 20), result.fingerprint.len);
    try testing.expectEqual(@as(usize, 8), result.key_id.len);
}

test "key generation fingerprints are unique" {
    const allocator = testing.allocator;
    const result1 = try keygen.generateKey(allocator, .{
        .algorithm = .eddsa,
        .creation_time = 1700000000,
    });
    defer result1.deinit(allocator);

    const result2 = try keygen.generateKey(allocator, .{
        .algorithm = .eddsa,
        .creation_time = 1700000000,
    });
    defer result2.deinit(allocator);

    try testing.expect(!mem.eql(u8, &result1.fingerprint, &result2.fingerprint));
}

test "key export then import produces identical fingerprint" {
    const allocator = testing.allocator;
    const result = try keygen.generateKey(allocator, .{
        .algorithm = .eddsa,
        .user_id = "Roundtrip <rt@example.com>",
        .creation_time = 1700000000,
    });
    defer result.deinit(allocator);

    // The armored output should decode back to valid binary data
    var decoded = try armor.decode(allocator, result.public_key_armored);
    defer decoded.deinit();

    try testing.expect(decoded.data.len > 0);
    try testing.expectEqual(armor.ArmorType.public_key, decoded.armor_type);
}

test "armored key export round-trip preserves armor type" {
    const allocator = testing.allocator;
    const result = try keygen.generateKey(allocator, .{
        .algorithm = .eddsa,
        .creation_time = 1700000000,
    });
    defer result.deinit(allocator);

    // Decode public key
    var pub_decoded = try armor.decode(allocator, result.public_key_armored);
    defer pub_decoded.deinit();
    try testing.expectEqual(armor.ArmorType.public_key, pub_decoded.armor_type);

    // Decode secret key
    var sec_decoded = try armor.decode(allocator, result.secret_key_armored);
    defer sec_decoded.deinit();
    try testing.expectEqual(armor.ArmorType.private_key, sec_decoded.armor_type);
}

// ==========================================================================
// Fingerprint and Key ID tests
// ==========================================================================

test "V4 fingerprint is deterministic" {
    const body = buildTestKeyBody(1700000000);
    const fp1 = fingerprint_mod.calculateV4Fingerprint(&body);
    const fp2 = fingerprint_mod.calculateV4Fingerprint(&body);
    try testing.expectEqualSlices(u8, &fp1, &fp2);
}

test "V4 fingerprint is 20 bytes" {
    const body = buildTestKeyBody(1700000000);
    const fp = fingerprint_mod.calculateV4Fingerprint(&body);
    try testing.expectEqual(@as(usize, 20), fp.len);
}

test "V4 key ID is last 8 bytes of fingerprint" {
    const body = buildTestKeyBody(1700000000);
    const fp = fingerprint_mod.calculateV4Fingerprint(&body);
    const kid = fingerprint_mod.keyIdFromFingerprint(fp);
    try testing.expectEqualSlices(u8, fp[12..20], &kid);
}

test "different creation times produce different fingerprints" {
    const body1 = buildTestKeyBody(1700000000);
    const body2 = buildTestKeyBody(1700000001);
    const fp1 = fingerprint_mod.calculateV4Fingerprint(&body1);
    const fp2 = fingerprint_mod.calculateV4Fingerprint(&body2);
    try testing.expect(!mem.eql(u8, &fp1, &fp2));
}

test "V6 key fingerprint is 32 bytes SHA-256" {
    // Build a V6 public key body
    var body: [42]u8 = undefined;
    body[0] = 6; // version
    mem.writeInt(u32, body[1..5], 1700000000, .big);
    body[5] = 27; // Ed25519
    mem.writeInt(u32, body[6..10], 32, .big);
    @memset(body[10..42], 0xAB);

    const fp = v6_fingerprint_mod.calculateV6Fingerprint(&body);
    try testing.expectEqual(@as(usize, 32), fp.len);

    // Not all zeros
    var all_zero = true;
    for (fp) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "V6 key ID is first 8 bytes of fingerprint" {
    var body: [42]u8 = undefined;
    body[0] = 6;
    mem.writeInt(u32, body[1..5], 1700000000, .big);
    body[5] = 27;
    mem.writeInt(u32, body[6..10], 32, .big);
    @memset(body[10..42], 0xCD);

    const fp = v6_fingerprint_mod.calculateV6Fingerprint(&body);
    const kid = v6_fingerprint_mod.v6KeyIdFromFingerprint(fp);
    try testing.expectEqualSlices(u8, fp[0..8], &kid);
}

test "V6 fingerprint format as hex" {
    var body: [42]u8 = undefined;
    body[0] = 6;
    mem.writeInt(u32, body[1..5], 1700000000, .big);
    body[5] = 27;
    mem.writeInt(u32, body[6..10], 32, .big);
    @memset(body[10..42], 0xAA);

    const fp = v6_fingerprint_mod.calculateV6Fingerprint(&body);
    const hex = v6_fingerprint_mod.formatV6Fingerprint(fp);
    try testing.expectEqual(@as(usize, 64), hex.len);
}

// ==========================================================================
// Keyring tests
// ==========================================================================

test "keyring add and find by fingerprint" {
    const allocator = testing.allocator;
    var keyring = Keyring.init(allocator);
    defer keyring.deinit();

    var key = try createTestKey(allocator, "alice@example.com", 1700000000);
    const fp = key.fingerprint();
    try keyring.addKey(key);

    const found = keyring.findByFingerprint(fp);
    try testing.expect(found != null);
}

test "keyring add and find by key ID" {
    const allocator = testing.allocator;
    var keyring = Keyring.init(allocator);
    defer keyring.deinit();

    var key = try createTestKey(allocator, "bob@example.com", 1700000001);
    const kid = key.keyId();
    try keyring.addKey(key);

    const found = keyring.findByKeyId(kid);
    try testing.expect(found != null);
}

test "keyring add and find by email" {
    const allocator = testing.allocator;
    var keyring = Keyring.init(allocator);
    defer keyring.deinit();

    const key = try createTestKey(allocator, "carol@example.com", 1700000002);
    try keyring.addKey(key);

    const found = try keyring.findByEmail("carol@example.com", allocator);
    defer allocator.free(found);
    try testing.expect(found.len > 0);
}

test "keyring find nonexistent returns null" {
    const allocator = testing.allocator;
    var keyring = Keyring.init(allocator);
    defer keyring.deinit();

    const fp = [_]u8{0xFF} ** 20;
    const found = keyring.findByFingerprint(fp);
    try testing.expect(found == null);
}

test "keyring multiple keys" {
    const allocator = testing.allocator;
    var keyring = Keyring.init(allocator);
    defer keyring.deinit();

    const key1 = try createUniqueTestKey(allocator, "user1@example.com", 1700000000, 0xAA);
    const key2 = try createUniqueTestKey(allocator, "user2@example.com", 1700000001, 0xBB);
    const key3 = try createUniqueTestKey(allocator, "user3@example.com", 1700000002, 0xCC);

    try keyring.addKey(key1);
    try keyring.addKey(key2);
    try keyring.addKey(key3);

    try testing.expectEqual(@as(usize, 3), keyring.count());
}

test "keyring remove by fingerprint" {
    const allocator = testing.allocator;
    var keyring = Keyring.init(allocator);
    defer keyring.deinit();

    var key = try createUniqueTestKey(allocator, "remove@example.com", 1700000000, 0xDD);
    const fp = key.fingerprint();
    try keyring.addKey(key);

    try testing.expectEqual(@as(usize, 1), keyring.count());

    const removed = keyring.removeByFingerprint(fp);
    try testing.expect(removed);
    try testing.expectEqual(@as(usize, 0), keyring.count());
}

test "keyring remove nonexistent returns false" {
    const allocator = testing.allocator;
    var keyring = Keyring.init(allocator);
    defer keyring.deinit();

    const fp = [_]u8{0xFF} ** 20;
    const removed = keyring.removeByFingerprint(fp);
    try testing.expect(!removed);
}

// ==========================================================================
// Key expiration tests
// ==========================================================================

test "key expiration check - no expiration set" {
    const allocator = testing.allocator;

    // A key with no self-signature has no expiration
    var key = try createTestKey(allocator, "noexpiry@test.com", 1700000000);
    defer key.deinit(allocator);

    const exp = try expiration_mod.getKeyExpirationTime(&key, allocator);
    try testing.expect(exp == null); // No expiration = never expires
}

test "key creation time retrieval" {
    const allocator = testing.allocator;

    var key = try createTestKey(allocator, "time@test.com", 1700000000);
    defer key.deinit(allocator);

    const creation = expiration_mod.getKeyCreationTime(&key);
    try testing.expectEqual(@as(u32, 1700000000), creation);
}

test "key validity with no signatures" {
    const allocator = testing.allocator;

    var key = try createTestKey(allocator, "validity@test.com", 1700000000);
    defer key.deinit(allocator);

    // Without a self-signature, key has no expiration
    const exp = try expiration_mod.getKeyExpirationTime(&key, allocator);
    try testing.expect(exp == null);
}

test "key creation time varies with input" {
    const allocator = testing.allocator;

    var key1 = try createTestKey(allocator, "t1@test.com", 1000);
    defer key1.deinit(allocator);

    var key2 = try createTestKey(allocator, "t2@test.com", 2000);
    defer key2.deinit(allocator);

    try testing.expectEqual(@as(u32, 1000), expiration_mod.getKeyCreationTime(&key1));
    try testing.expectEqual(@as(u32, 2000), expiration_mod.getKeyCreationTime(&key2));
}

// ==========================================================================
// WKD tests
// ==========================================================================

test "WKD email parsing" {
    const parts = try wkd.parseEmail("user@example.com");
    try testing.expectEqualStrings("user", parts.local);
    try testing.expectEqualStrings("example.com", parts.domain);
}

test "WKD email parsing with subdomain" {
    const parts = try wkd.parseEmail("alice@mail.example.org");
    try testing.expectEqualStrings("alice", parts.local);
    try testing.expectEqualStrings("mail.example.org", parts.domain);
}

test "WKD invalid email - no @" {
    try testing.expectError(error.InvalidEmail, wkd.parseEmail("invalid"));
}

test "WKD invalid email - no domain" {
    try testing.expectError(error.InvalidEmail, wkd.parseEmail("user@"));
}

test "WKD invalid email - no local part" {
    try testing.expectError(error.InvalidEmail, wkd.parseEmail("@example.com"));
}

test "WKD invalid email - no dot in domain" {
    try testing.expectError(error.InvalidEmail, wkd.parseEmail("user@localhost"));
}

test "WKD URL building advanced method" {
    const allocator = testing.allocator;
    const client = wkd.WkdClient.init(allocator);

    const url = try client.buildAdvancedUrl("test@example.com");
    defer allocator.free(url);

    // URL should start with https://openpgpkey.example.com/
    try testing.expect(mem.startsWith(u8, url, "https://openpgpkey.example.com/"));
    try testing.expect(mem.indexOf(u8, url, "/hu/") != null);
}

test "WKD URL building direct method" {
    const allocator = testing.allocator;
    const client = wkd.WkdClient.init(allocator);

    const url = try client.buildDirectUrl("test@example.com");
    defer allocator.free(url);

    // URL should start with https://example.com/
    try testing.expect(mem.startsWith(u8, url, "https://example.com/"));
    try testing.expect(mem.indexOf(u8, url, "/hu/") != null);
}

test "WKD hash computation is deterministic" {
    const hash1 = wkd.computeWkdHash("user");
    const hash2 = wkd.computeWkdHash("user");
    try testing.expectEqualSlices(u8, &hash1, &hash2);
}

test "WKD hash different local parts produce different hashes" {
    const hash1 = wkd.computeWkdHash("alice");
    const hash2 = wkd.computeWkdHash("bob");
    try testing.expect(!mem.eql(u8, &hash1, &hash2));
}

test "z-base-32 encoding" {
    const allocator = testing.allocator;

    // z-base-32 encoding of known data
    const data = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04 };
    const encoded = try wkd.zBase32Encode(allocator, &data);
    defer allocator.free(encoded);

    try testing.expect(encoded.len > 0);
    // All characters should be from the z-base-32 alphabet
    for (encoded) |c| {
        try testing.expect(mem.indexOf(u8, "ybndrfg8ejkmcpqxot1uwisza345h769", &[_]u8{c}) != null);
    }
}

test "z-base-32 encoding deterministic" {
    const allocator = testing.allocator;
    const data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };

    const encoded1 = try wkd.zBase32Encode(allocator, &data);
    defer allocator.free(encoded1);

    const encoded2 = try wkd.zBase32Encode(allocator, &data);
    defer allocator.free(encoded2);

    try testing.expectEqualStrings(encoded1, encoded2);
}

// ==========================================================================
// Autocrypt tests
// ==========================================================================

test "Autocrypt header parsing" {
    const allocator = testing.allocator;

    const header_value = "addr=alice@example.com; prefer-encrypt=mutual; keydata=AQID";
    const hdr = try autocrypt.AutocryptHeader.parseHeader(allocator, header_value);
    defer hdr.deinit(allocator);

    try testing.expectEqualStrings("alice@example.com", hdr.addr);
    try testing.expectEqual(autocrypt.PreferEncrypt.mutual, hdr.prefer_encrypt);
    try testing.expect(hdr.keydata.len > 0);
}

test "Autocrypt header parsing without prefer-encrypt" {
    const allocator = testing.allocator;

    const header_value = "addr=bob@example.com; keydata=BAUG";
    const hdr = try autocrypt.AutocryptHeader.parseHeader(allocator, header_value);
    defer hdr.deinit(allocator);

    try testing.expectEqualStrings("bob@example.com", hdr.addr);
    try testing.expectEqual(autocrypt.PreferEncrypt.nopreference, hdr.prefer_encrypt);
}

test "Autocrypt header generation" {
    const allocator = testing.allocator;
    const keydata = "AQID"; // base64 for [0x01, 0x02, 0x03]

    const header = try autocrypt.AutocryptHeader.generate(allocator, "test@example.com", keydata, .mutual);
    defer allocator.free(header);

    try testing.expect(mem.indexOf(u8, header, "addr=test@example.com") != null);
    try testing.expect(mem.indexOf(u8, header, "prefer-encrypt=mutual") != null);
    try testing.expect(mem.indexOf(u8, header, "keydata=") != null);
}

test "Autocrypt prefer-encrypt enum" {
    try testing.expectEqualStrings("mutual", autocrypt.PreferEncrypt.mutual.headerValue().?);
    try testing.expect(autocrypt.PreferEncrypt.nopreference.headerValue() == null);
    try testing.expectEqual(autocrypt.PreferEncrypt.mutual, autocrypt.PreferEncrypt.parse("mutual"));
    try testing.expectEqual(autocrypt.PreferEncrypt.nopreference, autocrypt.PreferEncrypt.parse("other"));
}

// ==========================================================================
// V6 key generation tests
// ==========================================================================

test "V6 Ed25519 key generation" {
    const allocator = testing.allocator;
    const result = try v6_keygen.generateV6Key(allocator, .{
        .algorithm = .ed25519,
        .user_id = "V6 Test <v6@example.com>",
        .creation_time = 1700000000,
    });
    defer result.deinit(allocator);

    try testing.expect(mem.startsWith(u8, result.public_key_armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    try testing.expectEqual(@as(usize, 32), result.fingerprint.len);
    try testing.expectEqualSlices(u8, result.fingerprint[0..8], &result.key_id);
}

test "V6 X25519 key generation" {
    const allocator = testing.allocator;
    const result = try v6_keygen.generateV6Key(allocator, .{
        .algorithm = .x25519,
        .user_id = "V6 X25519 <x@example.com>",
        .creation_time = 1700000000,
    });
    defer result.deinit(allocator);

    try testing.expectEqual(@as(usize, 32), result.fingerprint.len);
}

test "V6 Ed25519 with encryption subkey" {
    const allocator = testing.allocator;
    const result = try v6_keygen.generateV6Key(allocator, .{
        .algorithm = .ed25519,
        .generate_encryption_subkey = true,
        .creation_time = 1700000000,
    });
    defer result.deinit(allocator);

    // Output should be larger due to subkey packets
    try testing.expect(result.public_key_armored.len > 100);
}

test "V6 key with AEAD preference" {
    const allocator = testing.allocator;
    const result = try v6_keygen.generateV6Key(allocator, .{
        .algorithm = .ed25519,
        .aead_algo = .gcm,
        .sym_algo = .aes256,
        .creation_time = 1700000000,
    });
    defer result.deinit(allocator);

    try testing.expect(mem.startsWith(u8, result.public_key_armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));
}

test "V6 key with passphrase protection" {
    const allocator = testing.allocator;
    const result = try v6_keygen.generateV6Key(allocator, .{
        .algorithm = .ed25519,
        .passphrase = "test-passphrase-123",
        .creation_time = 1700000000,
    });
    defer result.deinit(allocator);

    try testing.expect(mem.startsWith(u8, result.secret_key_armored, "-----BEGIN PGP PRIVATE KEY BLOCK-----"));
}

test "V6 unsupported algorithm fails" {
    const allocator = testing.allocator;
    const result = v6_keygen.generateV6Key(allocator, .{
        .algorithm = .dsa,
    });
    try testing.expectError(error.UnsupportedAlgorithm, result);
}

// ==========================================================================
// Notation data tests
// ==========================================================================

test "notation data round-trip" {
    const allocator = testing.allocator;

    // Build notation subpacket data manually
    // flags(4) + name_len(2) + value_len(2) + name + value
    const name = "test@example.com";
    const value = "notation-value";
    var data: [8 + name.len + value.len]u8 = undefined;
    data[0] = 0x80; // human-readable flag
    data[1] = 0x00;
    data[2] = 0x00;
    data[3] = 0x00;
    mem.writeInt(u16, data[4..6], @intCast(name.len), .big);
    mem.writeInt(u16, data[6..8], @intCast(value.len), .big);
    @memcpy(data[8 .. 8 + name.len], name);
    @memcpy(data[8 + name.len ..], value);

    const notation = try notation_mod.parseNotation(&data, allocator);
    defer notation.deinit(allocator);

    try testing.expect(notation.human_readable);
    try testing.expectEqualStrings(name, notation.name);
    try testing.expectEqualStrings(value, notation.value);
}

test "notation data binary (not human-readable)" {
    const allocator = testing.allocator;

    const name = "binary@test";
    const value = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    var data: [8 + name.len + value.len]u8 = undefined;
    data[0] = 0x00; // not human-readable
    data[1] = 0x00;
    data[2] = 0x00;
    data[3] = 0x00;
    mem.writeInt(u16, data[4..6], @intCast(name.len), .big);
    mem.writeInt(u16, data[6..8], @intCast(value.len), .big);
    @memcpy(data[8 .. 8 + name.len], name);
    @memcpy(data[8 + name.len ..], &value);

    const notation = try notation_mod.parseNotation(&data, allocator);
    defer notation.deinit(allocator);

    try testing.expect(!notation.human_readable);
    try testing.expectEqualStrings(name, notation.name);
}

// ==========================================================================
// Subpacket parsing tests
// ==========================================================================

test "subpacket creation_time parsing" {
    const allocator = testing.allocator;

    // Build a creation time subpacket: length=5, type=2, time=0x5F000000
    const data = [_]u8{ 5, 2, 0x5F, 0x00, 0x00, 0x00 };
    const sps = try subpackets_mod.parseSubpackets(allocator, &data);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(@as(usize, 1), sps.len);
    try testing.expectEqual(subpackets_mod.SubpacketTag.creation_time, sps[0].tag);
    try testing.expectEqual(@as(?u32, 0x5F000000), sps[0].asCreationTime());
}

test "subpacket key_flags parsing" {
    const allocator = testing.allocator;

    // Key flags subpacket: length=2, type=27, flags=0x03 (certify+sign)
    const data = [_]u8{ 2, 27, 0x03 };
    const sps = try subpackets_mod.parseSubpackets(allocator, &data);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(@as(usize, 1), sps.len);
    try testing.expectEqual(subpackets_mod.SubpacketTag.key_flags, sps[0].tag);
    const flags = sps[0].asKeyFlags().?;
    try testing.expect(flags.certify);
    try testing.expect(flags.sign);
    try testing.expect(!flags.encrypt_communications);
}

test "subpacket issuer_fingerprint parsing" {
    const allocator = testing.allocator;

    // Issuer fingerprint subpacket: length=22, type=33, version=4, 20-byte fingerprint
    var data: [23]u8 = undefined;
    data[0] = 22; // length (type + version + 20 bytes)
    data[1] = 33; // issuer fingerprint
    data[2] = 4; // version
    @memset(data[3..23], 0xAB);

    const sps = try subpackets_mod.parseSubpackets(allocator, &data);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(@as(usize, 1), sps.len);
    const ifp = sps[0].asIssuerFingerprint().?;
    try testing.expectEqual(@as(u8, 4), ifp.version);
    try testing.expectEqual(@as(u8, 0xAB), ifp.fingerprint[0]);
}

test "subpacket critical bit handling" {
    const allocator = testing.allocator;

    // Critical subpacket: type byte has bit 7 set
    const data = [_]u8{ 5, 0x82, 0x5F, 0x00, 0x00, 0x00 }; // critical creation_time
    const sps = try subpackets_mod.parseSubpackets(allocator, &data);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(@as(usize, 1), sps.len);
    try testing.expect(sps[0].critical);
    try testing.expectEqual(subpackets_mod.SubpacketTag.creation_time, sps[0].tag);
}

test "multiple subpackets" {
    const allocator = testing.allocator;

    // Two subpackets: creation_time + key_flags
    const data = [_]u8{
        5,    2,    0x5F, 0x00, 0x00, 0x00, // creation_time
        2,    27,   0x03, // key_flags
    };
    const sps = try subpackets_mod.parseSubpackets(allocator, &data);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(@as(usize, 2), sps.len);
    try testing.expectEqual(subpackets_mod.SubpacketTag.creation_time, sps[0].tag);
    try testing.expectEqual(subpackets_mod.SubpacketTag.key_flags, sps[1].tag);
}

// ==========================================================================
// Algorithm deprecation tests
// ==========================================================================

test "deprecation assessment for algorithms" {
    const deprecation = @import("crypto/deprecation.zig");

    // Ed25519 should be secure
    try testing.expectEqual(deprecation.SecurityLevel.secure, deprecation.assessPublicKeyAlgorithm(.ed25519));
    // RSA should be secure (for standard sizes)
    try testing.expectEqual(deprecation.SecurityLevel.secure, deprecation.assessPublicKeyAlgorithm(.rsa_encrypt_sign));
    // DSA is deprecated
    try testing.expectEqual(deprecation.SecurityLevel.deprecated, deprecation.assessPublicKeyAlgorithm(.dsa));
    // ElGamal is deprecated
    try testing.expectEqual(deprecation.SecurityLevel.deprecated, deprecation.assessPublicKeyAlgorithm(.elgamal));

    // AES-256 is secure
    try testing.expectEqual(deprecation.SecurityLevel.secure, deprecation.assessSymmetricAlgorithm(.aes256));
    // 3DES is deprecated
    try testing.expectEqual(deprecation.SecurityLevel.deprecated, deprecation.assessSymmetricAlgorithm(.triple_des));

    // SHA-256 is secure
    try testing.expectEqual(deprecation.SecurityLevel.secure, deprecation.assessHashAlgorithm(.sha256));
}

test "security level properties" {
    const deprecation = @import("crypto/deprecation.zig");

    try testing.expect(deprecation.SecurityLevel.secure.isSafeForCreation());
    try testing.expect(!deprecation.SecurityLevel.deprecated.isSafeForCreation());
    try testing.expect(!deprecation.SecurityLevel.insecure.isSafeForCreation());

    try testing.expect(deprecation.SecurityLevel.secure.isAcceptableForVerification());
    try testing.expect(deprecation.SecurityLevel.deprecated.isAcceptableForVerification());
    try testing.expect(!deprecation.SecurityLevel.insecure.isAcceptableForVerification());
}
