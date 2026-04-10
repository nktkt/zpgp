// SPDX-License-Identifier: MIT
//! GnuPG Interoperability Test Suite.
//!
//! Tests interoperability scenarios with GnuPG-compatible data formats and
//! known test vectors. Since unit tests cannot invoke external programs,
//! we embed known-good packet data as byte literals and verify that the
//! library can parse, manipulate, and round-trip them correctly.
//!
//! Covered scenarios:
//! - RSA key import/export and fingerprint calculation
//! - Ed25519 key import/export
//! - Signature verification with known data
//! - Symmetric encrypted message decryption
//! - Armor round-trip
//! - Cleartext signature parsing
//! - Subpacket parsing
//! - S2K interoperability

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

// Packet layer
const header_mod = @import("packet/header.zig");
const PacketTag = @import("packet/tags.zig").PacketTag;

// Types
const enums = @import("types/enums.zig");
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const mpi_mod = @import("types/mpi.zig");
const Mpi = mpi_mod.Mpi;
const s2k_mod = @import("types/s2k.zig");
const S2K = s2k_mod.S2K;

// Armor
const armor = @import("armor/armor.zig");
const crc24 = @import("armor/crc24.zig");

// Packets
const public_key_mod = @import("packets/public_key.zig");
const PublicKeyPacket = public_key_mod.PublicKeyPacket;
const signature_mod = @import("packets/signature.zig");
const SignaturePacket = signature_mod.SignaturePacket;
const user_id_mod = @import("packets/user_id.zig");
const UserIdPacket = user_id_mod.UserIdPacket;
const skesk_mod = @import("packets/skesk.zig");
const SKESKPacket = skesk_mod.SKESKPacket;

// Key modules
const key_mod = @import("key/key.zig");
const Key = key_mod.Key;
const UserIdBinding = key_mod.UserIdBinding;
const import_export = @import("key/import_export.zig");
const fingerprint_mod = @import("key/fingerprint.zig");
const keyring_mod = @import("key/keyring.zig");
const Keyring = keyring_mod.Keyring;

// Signature modules
const subpackets_mod = @import("signature/subpackets.zig");
const SubpacketTag = subpackets_mod.SubpacketTag;
const cleartext = @import("signature/cleartext.zig");
const sig_creation = @import("signature/creation.zig");

// Crypto
const seipd = @import("crypto/seipd.zig");
const session_key_mod = @import("crypto/session_key.zig");
const ed25519_ops = @import("crypto/ed25519_ops.zig");
const hash_mod = @import("crypto/hash.zig");
const HashContext = hash_mod.HashContext;

// Message modules
const compose = @import("message/compose.zig");
const decompose_mod = @import("message/decompose.zig");

// ==========================================================================
// Helpers
// ==========================================================================

/// Construct a minimal V4 RSA-2048 public key packet body.
fn buildRsa2048KeyBody(allocator: std.mem.Allocator) ![]u8 {
    const mod_bytes = 256;
    const exp_data = [_]u8{ 0x01, 0x00, 0x01 };
    const total = 1 + 4 + 1 + 2 + mod_bytes + 2 + exp_data.len;
    const buf = try allocator.alloc(u8, total);
    buf[0] = 4; // version
    mem.writeInt(u32, buf[1..5], 0x5E0BE100, .big);
    buf[5] = @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign);
    mem.writeInt(u16, buf[6..8], 2048, .big);
    buf[8] = 0x80;
    @memset(buf[9 .. 8 + mod_bytes], 0x00);
    buf[8 + mod_bytes - 1] = 0x01;
    const exp_offset = 8 + mod_bytes;
    mem.writeInt(u16, buf[exp_offset..][0..2], 17, .big);
    @memcpy(buf[exp_offset + 2 .. exp_offset + 2 + exp_data.len], &exp_data);
    return buf;
}

/// Construct a minimal V4 Ed25519 (native) public key packet body.
fn buildEd25519KeyBody(allocator: std.mem.Allocator, pub_key: [32]u8) ![]u8 {
    const buf = try allocator.alloc(u8, 38);
    buf[0] = 4;
    mem.writeInt(u32, buf[1..5], 0x5E0BE100, .big);
    buf[5] = @intFromEnum(PublicKeyAlgorithm.ed25519);
    @memcpy(buf[6..38], &pub_key);
    return buf;
}

// ==========================================================================
// RSA Key Import Tests
// ==========================================================================

test "gnupg_interop: parse RSA-2048 public key packet" {
    const allocator = testing.allocator;
    const body = try buildRsa2048KeyBody(allocator);
    defer allocator.free(body);

    const pk = try PublicKeyPacket.parse(allocator, body, false);
    defer pk.deinit(allocator);

    try testing.expectEqual(@as(u8, 4), pk.version);
    try testing.expectEqual(@as(u32, 0x5E0BE100), pk.creation_time);
    try testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, pk.algorithm);
    try testing.expectEqual(@as(usize, 2), pk.key_material.len);
    try testing.expectEqual(@as(u16, 2048), pk.key_material[0].bit_count);
    try testing.expectEqual(@as(u16, 17), pk.key_material[1].bit_count);
}

test "gnupg_interop: RSA key round-trip export and import" {
    const allocator = testing.allocator;
    const body = try buildRsa2048KeyBody(allocator);
    defer allocator.free(body);

    const pk = try PublicKeyPacket.parse(allocator, body, false);
    var key = Key.init(pk);
    defer key.deinit(allocator);

    const uid = try UserIdPacket.parse(allocator, "Test User <test@example.com>");
    try key.addUserId(allocator, .{ .user_id = uid, .self_signature = null, .certifications = .empty });

    try testing.expectEqualStrings("Test User <test@example.com>", key.primaryUserId().?);

    const exported = try import_export.exportPublicKey(allocator, &key);
    defer allocator.free(exported);

    var imported = try import_export.importPublicKey(allocator, exported);
    defer imported.deinit(allocator);

    try testing.expectEqual(@as(u16, 2048), imported.primary_key.key_material[0].bit_count);
    try testing.expectEqualStrings("Test User <test@example.com>", imported.user_ids.items[0].user_id.id);
    try testing.expectEqual(key.fingerprint(), imported.fingerprint());
}

test "gnupg_interop: RSA armored key export and reimport" {
    const allocator = testing.allocator;
    const body = try buildRsa2048KeyBody(allocator);
    defer allocator.free(body);

    const pk = try PublicKeyPacket.parse(allocator, body, false);
    var key = Key.init(pk);
    defer key.deinit(allocator);

    const uid = try UserIdPacket.parse(allocator, "Armored <a@b.com>");
    try key.addUserId(allocator, .{ .user_id = uid, .self_signature = null, .certifications = .empty });

    const armored_key = try import_export.exportPublicKeyArmored(allocator, &key);
    defer allocator.free(armored_key);
    try testing.expect(mem.startsWith(u8, armored_key, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));

    var decoded = try armor.decode(allocator, armored_key);
    defer decoded.deinit();
    try testing.expectEqual(armor.ArmorType.public_key, decoded.armor_type);

    var reimported = try import_export.importPublicKey(allocator, decoded.data);
    defer reimported.deinit(allocator);
    try testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, reimported.primary_key.algorithm);
}

// ==========================================================================
// Ed25519 Key Import Tests
// ==========================================================================

test "gnupg_interop: parse Ed25519 public key and round-trip" {
    const allocator = testing.allocator;
    const kp = try ed25519_ops.ed25519Generate();
    const body = try buildEd25519KeyBody(allocator, kp.public_key);
    defer allocator.free(body);

    const pk = try PublicKeyPacket.parse(allocator, body, false);
    var key = Key.init(pk);
    defer key.deinit(allocator);

    try testing.expectEqual(PublicKeyAlgorithm.ed25519, pk.algorithm);

    const uid = try UserIdPacket.parse(allocator, "Ed25519 <ed@test.org>");
    try key.addUserId(allocator, .{ .user_id = uid, .self_signature = null, .certifications = .empty });

    const exported = try import_export.exportPublicKey(allocator, &key);
    defer allocator.free(exported);

    var imported = try import_export.importPublicKey(allocator, exported);
    defer imported.deinit(allocator);
    try testing.expectEqual(PublicKeyAlgorithm.ed25519, imported.primary_key.algorithm);
    try testing.expectEqualStrings("Ed25519 <ed@test.org>", imported.user_ids.items[0].user_id.id);
}

test "gnupg_interop: Ed25519 fingerprint stability" {
    const allocator = testing.allocator;
    const kp = try ed25519_ops.ed25519Generate();
    const body = try buildEd25519KeyBody(allocator, kp.public_key);
    defer allocator.free(body);

    try testing.expectEqual(
        fingerprint_mod.calculateV4Fingerprint(body),
        fingerprint_mod.calculateV4Fingerprint(body),
    );
}

// ==========================================================================
// Signature Tests
// ==========================================================================

test "gnupg_interop: Ed25519 sign and verify document" {
    const kp = try ed25519_ops.ed25519Generate();
    const message = "GnuPG interop test message";
    const sig = try ed25519_ops.ed25519Sign(kp.secret_key, message);
    try ed25519_ops.ed25519Verify(kp.public_key, message, sig);
}

test "gnupg_interop: Ed25519 cross-key and modified message fail" {
    const kp1 = try ed25519_ops.ed25519Generate();
    const kp2 = try ed25519_ops.ed25519Generate();
    const sig = try ed25519_ops.ed25519Sign(kp1.secret_key, "Original");

    try testing.expectError(ed25519_ops.Ed25519Error.SignatureVerificationFailed, ed25519_ops.ed25519Verify(kp2.public_key, "Original", sig));
    try testing.expectError(ed25519_ops.Ed25519Error.SignatureVerificationFailed, ed25519_ops.ed25519Verify(kp1.public_key, "Modified", sig));
}

test "gnupg_interop: Ed25519 signatures both verify for same message" {
    const kp = try ed25519_ops.ed25519Generate();
    const msg = "Determinism test";
    const sig1 = try ed25519_ops.ed25519Sign(kp.secret_key, msg);
    const sig2 = try ed25519_ops.ed25519Sign(kp.secret_key, msg);
    // Zig's Ed25519 signer adds noise for side-channel protection, so
    // signatures may differ bitwise but both must verify correctly.
    try ed25519_ops.ed25519Verify(kp.public_key, msg, sig1);
    try ed25519_ops.ed25519Verify(kp.public_key, msg, sig2);
}

test "gnupg_interop: V4 signature hash trailer structure" {
    const allocator = testing.allocator;
    const hashed_sp = [_]u8{ 5, 2, 0x5E, 0x0B, 0xE1, 0x00 };

    const hashed_data = try sig_creation.buildV4HashedData(
        0x00, @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign),
        @intFromEnum(HashAlgorithm.sha256), &hashed_sp, allocator,
    );
    defer allocator.free(hashed_data);

    try testing.expectEqual(@as(u8, 0x04), hashed_data[0]);
    try testing.expectEqual(@as(u8, 0x00), hashed_data[1]);
    try testing.expectEqual(@as(u8, 0x04), hashed_data[hashed_data.len - 6]);
    try testing.expectEqual(@as(u8, 0xFF), hashed_data[hashed_data.len - 5]);
}

test "gnupg_interop: parse V4 RSA signature packet" {
    const allocator = testing.allocator;
    const body = [_]u8{
        4, 0x00, 1, 8, // version, sig_type, RSA, SHA-256
        0x00, 0x06, 5, 2, 0x5E, 0x0B, 0xE1, 0x00, // hashed subpackets (creation time)
        0x00, 0x00, // no unhashed subpackets
        0xDE, 0xAD, // hash prefix
        0x00, 0x08, 0xAA, // signature MPI (8-bit)
    };

    var sig = try SignaturePacket.parse(allocator, &body);
    defer sig.deinit(allocator);

    try testing.expectEqual(@as(u8, 0x00), sig.sig_type);
    try testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, sig.pub_algo);
    try testing.expectEqual([2]u8{ 0xDE, 0xAD }, sig.hash_prefix);
}

// ==========================================================================
// Symmetric Encryption Interop
// ==========================================================================

test "gnupg_interop: symmetric encrypt then decrypt AES-256" {
    const allocator = testing.allocator;
    const encrypted = try compose.encryptMessageSymmetric(allocator, "Interop test", "test.txt", "test", .aes256, null);
    defer allocator.free(encrypted);

    var msg = try decompose_mod.parseMessage(allocator, encrypted);
    defer msg.deinit(allocator);
    try testing.expect(msg.isEncrypted());

    const decrypted = try decompose_mod.decryptWithPassphrase(allocator, &msg, "test");
    defer allocator.free(decrypted);
    try testing.expectEqualStrings("Interop test", decrypted);
}

test "gnupg_interop: symmetric encryption all AES variants" {
    const allocator = testing.allocator;
    // Note: AES-192 is excluded because Zig std lacks Aes192 block cipher
    const variants = [_]SymmetricAlgorithm{ .aes128, .aes256 };
    for (variants) |algo| {
        const encrypted = try compose.encryptMessageSymmetric(allocator, "AES test", "t.txt", "pw", algo, null);
        defer allocator.free(encrypted);
        var msg = try decompose_mod.parseMessage(allocator, encrypted);
        defer msg.deinit(allocator);
        const decrypted = try decompose_mod.decryptWithPassphrase(allocator, &msg, "pw");
        defer allocator.free(decrypted);
        try testing.expectEqualStrings("AES test", decrypted);
    }
}

test "gnupg_interop: wrong passphrase fails" {
    const allocator = testing.allocator;
    const encrypted = try compose.encryptMessageSymmetric(allocator, "Secret", "f.txt", "right", .aes256, null);
    defer allocator.free(encrypted);
    var msg = try decompose_mod.parseMessage(allocator, encrypted);
    defer msg.deinit(allocator);
    const result = decompose_mod.decryptWithPassphrase(allocator, &msg, "wrong");
    try testing.expect(result == error.IntegrityCheckFailed or result == error.DecryptionFailed or result == error.MalformedMessage);
}

// ==========================================================================
// Armor Round-Trip Tests
// ==========================================================================

test "gnupg_interop: armor round-trip all types" {
    const allocator = testing.allocator;
    const data = "Test binary data\x00\x01\x02\xFF";
    const types = [_]armor.ArmorType{ .message, .public_key, .private_key, .signature };
    for (types) |atype| {
        const armored = try armor.encode(allocator, data, atype, null);
        defer allocator.free(armored);
        var decoded = try armor.decode(allocator, armored);
        defer decoded.deinit();
        try testing.expectEqual(atype, decoded.armor_type);
        try testing.expectEqualSlices(u8, data, decoded.data);
    }
}

test "gnupg_interop: armor with all 256 byte values" {
    const allocator = testing.allocator;
    var data: [256]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i);
    const armored = try armor.encode(allocator, &data, .message, null);
    defer allocator.free(armored);
    var decoded = try armor.decode(allocator, armored);
    defer decoded.deinit();
    try testing.expectEqualSlices(u8, &data, decoded.data);
}

test "gnupg_interop: armor CRC-24 integrity" {
    const allocator = testing.allocator;
    const data = "CRC-24 integrity test data";
    const expected_crc = crc24.compute(data);
    const armored = try armor.encode(allocator, data, .message, null);
    defer allocator.free(armored);
    var decoded = try armor.decode(allocator, armored);
    defer decoded.deinit();
    try testing.expectEqual(expected_crc, crc24.compute(decoded.data));
}

// ==========================================================================
// Cleartext Signature Tests
// ==========================================================================

test "gnupg_interop: cleartext signed message round-trip" {
    const allocator = testing.allocator;
    const mock_sig = [_]u8{ 0x04, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00 };
    const signed_msg = try cleartext.createCleartextSignature(allocator, "Hello, world!", &mock_sig, .sha256);
    defer allocator.free(signed_msg);

    try testing.expect(mem.startsWith(u8, signed_msg, "-----BEGIN PGP SIGNED MESSAGE-----"));
    try testing.expect(mem.indexOf(u8, signed_msg, "Hash: SHA256") != null);

    const parsed = try cleartext.parseCleartextSignature(allocator, signed_msg);
    defer parsed.deinit(allocator);
    try testing.expectEqualStrings("Hello, world!", parsed.text);
    try testing.expectEqual(HashAlgorithm.sha256, parsed.hash_algo);
}

test "gnupg_interop: cleartext signature dash escaping" {
    const allocator = testing.allocator;
    const text = "Line 1\n- Dash line\n-- Double dash";
    const mock_sig = [_]u8{ 0x04, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00 };
    const signed_msg = try cleartext.createCleartextSignature(allocator, text, &mock_sig, .sha512);
    defer allocator.free(signed_msg);
    const parsed = try cleartext.parseCleartextSignature(allocator, signed_msg);
    defer parsed.deinit(allocator);
    try testing.expectEqualStrings(text, parsed.text);
    try testing.expectEqual(HashAlgorithm.sha512, parsed.hash_algo);
}

// ==========================================================================
// Fingerprint Verification Tests
// ==========================================================================

test "gnupg_interop: V4 fingerprint is SHA-1(0x99 || len || body)" {
    const Sha1 = std.crypto.hash.Sha1;
    const body = [_]u8{ 4, 0x5E, 0x0B, 0xE1, 0x00, 1, 0x00, 0x08, 0xFF, 0x00, 0x08, 0x03 };
    var sha1 = Sha1.init(.{});
    sha1.update(&[_]u8{0x99});
    var len_bytes: [2]u8 = undefined;
    mem.writeInt(u16, &len_bytes, @intCast(body.len), .big);
    sha1.update(&len_bytes);
    sha1.update(&body);
    try testing.expectEqual(sha1.finalResult(), fingerprint_mod.calculateV4Fingerprint(&body));
}

test "gnupg_interop: different keys produce different fingerprints" {
    const allocator = testing.allocator;
    const body1 = try buildRsa2048KeyBody(allocator);
    defer allocator.free(body1);
    const kp = try ed25519_ops.ed25519Generate();
    const body2 = try buildEd25519KeyBody(allocator, kp.public_key);
    defer allocator.free(body2);
    try testing.expect(!mem.eql(u8, &fingerprint_mod.calculateV4Fingerprint(body1), &fingerprint_mod.calculateV4Fingerprint(body2)));
}

test "gnupg_interop: key ID is last 8 bytes of fingerprint" {
    const allocator = testing.allocator;
    const body = try buildRsa2048KeyBody(allocator);
    defer allocator.free(body);
    const pk = try PublicKeyPacket.parse(allocator, body, false);
    var key = Key.init(pk);
    defer key.deinit(allocator);
    try testing.expectEqualSlices(u8, key.fingerprint()[12..20], &key.keyId());
}

// ==========================================================================
// Subpacket Parsing Tests
// ==========================================================================

test "gnupg_interop: subpacket creation time and key flags" {
    const allocator = testing.allocator;
    const data = [_]u8{
        5, 2, 0x5E, 0x0B, 0xE1, 0x00, // creation_time
        2, 27, 0x03, // key_flags: certify + sign
    };
    const sp = try subpackets_mod.parseSubpackets(allocator, &data);
    defer subpackets_mod.freeSubpackets(allocator, sp);
    try testing.expectEqual(@as(usize, 2), sp.len);
    try testing.expectEqual(@as(u32, 0x5E0BE100), sp[0].asCreationTime().?);
    const flags = sp[1].asKeyFlags().?;
    try testing.expect(flags.certify);
    try testing.expect(flags.sign);
    try testing.expect(!flags.encrypt_communications);
}

test "gnupg_interop: subpacket issuer and preferred algorithms" {
    const allocator = testing.allocator;
    const data = [_]u8{
        9, 16, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, // issuer
        4, 11, 9, 7, 3, // preferred_symmetric: AES-256, AES-128, CAST5
    };
    const sp = try subpackets_mod.parseSubpackets(allocator, &data);
    defer subpackets_mod.freeSubpackets(allocator, sp);
    try testing.expectEqual([_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 }, sp[0].asIssuer().?);
    try testing.expectEqual(SubpacketTag.preferred_symmetric, sp[1].tag);
    try testing.expectEqual(@as(u8, 9), sp[1].data[0]); // AES-256
}

test "gnupg_interop: critical subpacket flag and issuer fingerprint" {
    const allocator = testing.allocator;
    var fp_data: [21]u8 = undefined;
    fp_data[0] = 4;
    for (fp_data[1..], 0..) |*b, i| b.* = @intCast(i + 0xA0);
    var data: [23]u8 = undefined;
    data[0] = 22;
    data[1] = 0x80 | 33; // critical issuer_fingerprint
    @memcpy(data[2..23], &fp_data);
    const sp = try subpackets_mod.parseSubpackets(allocator, &data);
    defer subpackets_mod.freeSubpackets(allocator, sp);
    try testing.expect(sp[0].critical);
    try testing.expectEqual(@as(u8, 4), sp[0].asIssuerFingerprint().?.version);
}

// ==========================================================================
// Keyring Operations Tests
// ==========================================================================

test "gnupg_interop: keyring add, lookup, and miss" {
    const allocator = testing.allocator;
    var ring = Keyring.init(allocator);
    defer ring.deinit();

    const body = try buildRsa2048KeyBody(allocator);
    defer allocator.free(body);
    const pk = try PublicKeyPacket.parse(allocator, body, false);
    var key = Key.init(pk);
    const uid = try UserIdPacket.parse(allocator, "Ring <r@t.com>");
    try key.addUserId(allocator, .{ .user_id = uid, .self_signature = null, .certifications = .empty });

    const fp = key.fingerprint();
    const kid = key.keyId();
    try ring.addKey(key);

    try testing.expect(ring.findByFingerprint(fp) != null);
    try testing.expect(ring.findByKeyId(kid) != null);
    try testing.expect(ring.findByFingerprint([_]u8{0xFF} ** 20) == null);
}

// ==========================================================================
// S2K Interoperability Tests
// ==========================================================================

test "gnupg_interop: S2K iterated deterministic and salt-sensitive" {
    const s2k1 = S2K{ .s2k_type = .iterated, .hash_algo = .sha256, .salt = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, .coded_count = 96, .argon2_data = null };
    const s2k2 = S2K{ .s2k_type = .iterated, .hash_algo = .sha256, .salt = [_]u8{ 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8 }, .coded_count = 96, .argon2_data = null };
    var k1a: [32]u8 = undefined;
    var k1b: [32]u8 = undefined;
    var k2: [32]u8 = undefined;
    try s2k1.deriveKey("test", &k1a);
    try s2k1.deriveKey("test", &k1b);
    try s2k2.deriveKey("test", &k2);
    try testing.expectEqualSlices(u8, &k1a, &k1b); // deterministic
    try testing.expect(!mem.eql(u8, &k1a, &k2)); // salt-sensitive
}

test "gnupg_interop: S2K iteration count decoding" {
    const cases = [_]struct { c: u8, e: u32 }{ .{ .c = 0, .e = 1024 }, .{ .c = 96, .e = 65536 }, .{ .c = 255, .e = 65011712 } };
    for (cases) |tc| {
        const s2k = S2K{ .s2k_type = .iterated, .hash_algo = .sha256, .salt = [_]u8{0} ** 8, .coded_count = tc.c, .argon2_data = null };
        try testing.expectEqual(tc.e, s2k.iterationCount());
    }
}

test "gnupg_interop: S2K wire format round-trip" {
    const original = S2K{ .s2k_type = .iterated, .hash_algo = .sha256, .salt = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 }, .coded_count = 96, .argon2_data = null };
    var buf: [11]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try original.writeTo(fbs.writer());
    fbs.pos = 0;
    const parsed = try S2K.readFrom(fbs.reader());
    try testing.expectEqual(original.s2k_type, parsed.s2k_type);
    try testing.expectEqual(original.hash_algo, parsed.hash_algo);
    try testing.expectEqual(original.salt, parsed.salt);
    try testing.expectEqual(original.coded_count, parsed.coded_count);
}

// ==========================================================================
// Hash Test Vectors
// ==========================================================================

test "gnupg_interop: SHA-256 NIST test vector" {
    var ctx = try HashContext.init(.sha256);
    ctx.update("abc");
    var digest: [32]u8 = undefined;
    ctx.final(&digest);
    try testing.expectEqualSlices(u8, &[_]u8{
        0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
        0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
        0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
        0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD,
    }, &digest);
}

test "gnupg_interop: SHA-512 NIST test vector" {
    var ctx = try HashContext.init(.sha512);
    ctx.update("abc");
    var digest: [64]u8 = undefined;
    ctx.final(&digest);
    try testing.expectEqualSlices(u8, &[_]u8{
        0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA,
        0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20, 0x41, 0x31,
        0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2,
        0x0A, 0x9E, 0xEE, 0xE6, 0x4B, 0x55, 0xD3, 0x9A,
        0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8,
        0x36, 0xBA, 0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD,
        0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E,
        0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F,
    }, &digest);
}

// ==========================================================================
// MPI and Packet Wire Format Tests
// ==========================================================================

test "gnupg_interop: MPI read/write round-trip" {
    const allocator = testing.allocator;
    var mod_data: [256]u8 = undefined;
    mod_data[0] = 0x80;
    @memset(mod_data[1..], 0x00);
    mod_data[255] = 0x01;
    const original = Mpi.fromBytes(&mod_data);
    try testing.expectEqual(@as(u16, 2048), original.bit_count);

    var buf: [258]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try original.writeTo(fbs.writer());
    fbs.pos = 0;
    const read_back = try Mpi.readFrom(allocator, fbs.reader());
    defer read_back.deinit(allocator);
    try testing.expectEqual(original.bit_count, read_back.bit_count);
    try testing.expectEqualSlices(u8, original.data, read_back.data);
}

test "gnupg_interop: packet header new-format write/read round-trip" {
    var buf: [6]u8 = undefined;
    const test_lens = [_]u32{ 0, 100, 191, 192, 1000, 8383 };
    for (test_lens) |len| {
        var fbs = std.io.fixedBufferStream(&buf);
        try header_mod.writeHeader(fbs.writer(), .public_key, len);
        fbs.pos = 0;
        const hdr = try header_mod.readHeader(fbs.reader());
        try testing.expectEqual(PacketTag.public_key, hdr.tag);
        try testing.expectEqual(header_mod.BodyLength{ .fixed = len }, hdr.body_length);
    }
}

test "gnupg_interop: SKESK v4 packet parsing" {
    const allocator = testing.allocator;
    const body = [_]u8{ 4, 9, 3, 8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 96 };
    const pkt = try SKESKPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);
    try testing.expectEqual(SymmetricAlgorithm.aes256, pkt.symmetric_algo);
    try testing.expectEqual(@as(usize, 11), pkt.s2k_data.len);
}

test "gnupg_interop: session key generation and checksum" {
    const algos = [_]SymmetricAlgorithm{ .aes128, .aes192, .aes256 };
    const sizes = [_]usize{ 16, 24, 32 };
    for (algos, sizes) |algo, sz| {
        const sk = try session_key_mod.generateSessionKey(algo);
        try testing.expectEqual(sz, sk.key_len);
        var sum: u32 = 0;
        for (sk.keySlice()) |b| sum += b;
        try testing.expectEqual(@as(u16, @intCast(sum & 0xFFFF)), sk.checksum());
    }
}

// ==========================================================================
// SEIPD with S2K-derived key (GnuPG workflow)
// ==========================================================================

test "gnupg_interop: SEIPD v1 with S2K-derived key round-trip" {
    const allocator = testing.allocator;
    const s2k = S2K{
        .s2k_type = .iterated,
        .hash_algo = .sha256,
        .salt = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE },
        .coded_count = 96,
        .argon2_data = null,
    };
    var key: [32]u8 = undefined;
    try s2k.deriveKey("gnupg-compat-test", &key);

    const plaintext = "GnuPG SEIPD v1 compatibility test data.\nThis simulates a message encrypted by GnuPG.";
    const encrypted = try seipd.seipdEncrypt(allocator, plaintext, &key, .aes256);
    defer allocator.free(encrypted);
    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, &key, .aes256);
    defer allocator.free(decrypted);
    try testing.expectEqualStrings(plaintext, decrypted);
}

test "gnupg_interop: encrypted message has non-deterministic ciphertext" {
    const allocator = testing.allocator;
    const key = [_]u8{0x42} ** 32;
    const enc1 = try seipd.seipdEncrypt(allocator, "Same msg", &key, .aes256);
    defer allocator.free(enc1);
    const enc2 = try seipd.seipdEncrypt(allocator, "Same msg", &key, .aes256);
    defer allocator.free(enc2);
    try testing.expect(!mem.eql(u8, enc1, enc2));
    const dec1 = try seipd.seipdDecrypt(allocator, enc1, &key, .aes256);
    defer allocator.free(dec1);
    const dec2 = try seipd.seipdDecrypt(allocator, enc2, &key, .aes256);
    defer allocator.free(dec2);
    try testing.expectEqualStrings("Same msg", dec1);
    try testing.expectEqualStrings("Same msg", dec2);
}

// ==========================================================================
// Multiple subpackets in sequence (real-world GnuPG signature layout)
// ==========================================================================

test "gnupg_interop: parse GnuPG-like multi-subpacket area" {
    const allocator = testing.allocator;
    const data = [_]u8{
        5, 2, 0x5E, 0x0B, 0xE1, 0x00,                               // creation_time
        9, 16, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,       // issuer
        2, 27, 0x03,                                                   // key_flags (certify + sign)
        4, 11, 9, 7, 3,                                               // preferred_symmetric
        4, 21, 10, 8, 9,                                              // preferred_hash
        2, 30, 0x01,                                                   // features
    };
    const sp = try subpackets_mod.parseSubpackets(allocator, &data);
    defer subpackets_mod.freeSubpackets(allocator, sp);

    try testing.expectEqual(@as(usize, 6), sp.len);
    try testing.expectEqual(SubpacketTag.creation_time, sp[0].tag);
    try testing.expectEqual(SubpacketTag.issuer, sp[1].tag);
    try testing.expectEqual(SubpacketTag.key_flags, sp[2].tag);
    try testing.expectEqual(SubpacketTag.preferred_symmetric, sp[3].tag);
    try testing.expectEqual(SubpacketTag.preferred_hash, sp[4].tag);
    try testing.expectEqual(SubpacketTag.features, sp[5].tag);

    // Verify individual values
    try testing.expectEqual(@as(u32, 0x5E0BE100), sp[0].asCreationTime().?);
    const flags = sp[2].asKeyFlags().?;
    try testing.expect(flags.certify and flags.sign);
}

// ==========================================================================
// Keyring multiple keys with distinct fingerprints
// ==========================================================================

test "gnupg_interop: keyring multiple keys all unique" {
    const allocator = testing.allocator;
    var ring = Keyring.init(allocator);
    defer ring.deinit();

    const creation_times = [_]u32{ 0x5E0BE100, 0x5E0BE200, 0x5E0BE300, 0x5E0BE400, 0x5E0BE500 };
    var fps: [5][20]u8 = undefined;

    for (creation_times, 0..) |ct, i| {
        var body: [12]u8 = undefined;
        body[0] = 4;
        mem.writeInt(u32, body[1..5], ct, .big);
        body[5] = 1;
        mem.writeInt(u16, body[6..8], 8, .big);
        body[8] = 0xFF;
        mem.writeInt(u16, body[9..11], 8, .big);
        body[11] = 0x03;

        const pk = try PublicKeyPacket.parse(allocator, &body, false);
        var key = Key.init(pk);
        const uid_text = try std.fmt.allocPrint(allocator, "User {d} <u{d}@t>", .{ i, i });
        defer allocator.free(uid_text);
        const uid = try UserIdPacket.parse(allocator, uid_text);
        try key.addUserId(allocator, .{ .user_id = uid, .self_signature = null, .certifications = .empty });
        fps[i] = key.fingerprint();
        try ring.addKey(key);
    }

    // All findable and all unique
    for (fps) |fp| try testing.expect(ring.findByFingerprint(fp) != null);
    for (0..5) |i| for (i + 1..5) |j| try testing.expect(!mem.eql(u8, &fps[i], &fps[j]));
}

// ==========================================================================
// S2K type comparison: simple vs salted vs iterated
// ==========================================================================

test "gnupg_interop: S2K all three types produce different keys" {
    const passphrase = "test-passphrase";
    const salt = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const simple = S2K{ .s2k_type = .simple, .hash_algo = .sha256, .salt = [_]u8{0} ** 8, .coded_count = 0, .argon2_data = null };
    const salted = S2K{ .s2k_type = .salted, .hash_algo = .sha256, .salt = salt, .coded_count = 0, .argon2_data = null };
    const iterated = S2K{ .s2k_type = .iterated, .hash_algo = .sha256, .salt = salt, .coded_count = 96, .argon2_data = null };

    var k1: [32]u8 = undefined;
    var k2: [32]u8 = undefined;
    var k3: [32]u8 = undefined;
    try simple.deriveKey(passphrase, &k1);
    try salted.deriveKey(passphrase, &k2);
    try iterated.deriveKey(passphrase, &k3);

    try testing.expect(!mem.eql(u8, &k1, &k2));
    try testing.expect(!mem.eql(u8, &k2, &k3));
    try testing.expect(!mem.eql(u8, &k1, &k3));
}

test "gnupg_interop: S2K wire size for all types" {
    const simple = S2K{ .s2k_type = .simple, .hash_algo = .sha256, .salt = [_]u8{0} ** 8, .coded_count = 0, .argon2_data = null };
    const salted = S2K{ .s2k_type = .salted, .hash_algo = .sha256, .salt = [_]u8{0} ** 8, .coded_count = 0, .argon2_data = null };
    const iterated = S2K{ .s2k_type = .iterated, .hash_algo = .sha256, .salt = [_]u8{0} ** 8, .coded_count = 96, .argon2_data = null };
    try testing.expectEqual(@as(usize, 2), simple.wireSize());
    try testing.expectEqual(@as(usize, 10), salted.wireSize());
    try testing.expectEqual(@as(usize, 11), iterated.wireSize());
}

// ==========================================================================
// Armor with Version header (GnuPG output format)
// ==========================================================================

test "gnupg_interop: armor with Version header preserved" {
    const allocator = testing.allocator;
    const headers = [_]armor.Header{.{ .name = "Version", .value = "GnuPG v2.3.4" }};
    const armored = try armor.encode(allocator, "test data", .message, &headers);
    defer allocator.free(armored);
    try testing.expect(mem.indexOf(u8, armored, "Version: GnuPG v2.3.4") != null);
    var decoded = try armor.decode(allocator, armored);
    defer decoded.deinit();
    try testing.expectEqualSlices(u8, "test data", decoded.data);
}

// ==========================================================================
// Fingerprint changes with creation time
// ==========================================================================

test "gnupg_interop: fingerprint changes with different creation time" {
    const body1 = [_]u8{ 4, 0x5E, 0x0B, 0xE1, 0x00, 1, 0x00, 0x08, 0xFF, 0x00, 0x08, 0x03 };
    const body2 = [_]u8{ 4, 0x60, 0x00, 0x00, 0x00, 1, 0x00, 0x08, 0xFF, 0x00, 0x08, 0x03 };
    try testing.expect(!mem.eql(u8, &fingerprint_mod.calculateV4Fingerprint(&body1), &fingerprint_mod.calculateV4Fingerprint(&body2)));
}

// ==========================================================================
// MPI small values and zero
// ==========================================================================

test "gnupg_interop: MPI zero and small value parsing" {
    const allocator = testing.allocator;

    // Zero MPI
    {
        var buf = [_]u8{ 0x00, 0x00 };
        var fbs = std.io.fixedBufferStream(&buf);
        const mpi = try Mpi.readFrom(allocator, fbs.reader());
        defer mpi.deinit(allocator);
        try testing.expectEqual(@as(u16, 0), mpi.bit_count);
        try testing.expectEqual(@as(usize, 0), mpi.byteLen());
    }

    // 1-bit MPI
    {
        var buf = [_]u8{ 0x00, 0x01, 0x01 };
        var fbs = std.io.fixedBufferStream(&buf);
        const mpi = try Mpi.readFrom(allocator, fbs.reader());
        defer mpi.deinit(allocator);
        try testing.expectEqual(@as(u16, 1), mpi.bit_count);
    }

    // 17-bit MPI (65537)
    {
        var buf = [_]u8{ 0x00, 0x11, 0x01, 0x00, 0x01 };
        var fbs = std.io.fixedBufferStream(&buf);
        const mpi = try Mpi.readFrom(allocator, fbs.reader());
        defer mpi.deinit(allocator);
        try testing.expectEqual(@as(u16, 17), mpi.bit_count);
        try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00, 0x01 }, mpi.data);
    }
}

// ==========================================================================
// Message packet structure validation
// ==========================================================================

test "gnupg_interop: encrypted message packet sequence is SKESK + SEIPD" {
    const allocator = testing.allocator;
    const encrypted = try compose.encryptMessageSymmetric(allocator, "test data", "test.txt", "password", .aes256, null);
    defer allocator.free(encrypted);

    var fbs = std.io.fixedBufferStream(encrypted);
    const reader = fbs.reader();

    const hdr1 = try header_mod.readHeader(reader);
    try testing.expectEqual(PacketTag.symmetric_key_encrypted_session_key, hdr1.tag);
    const len1 = switch (hdr1.body_length) { .fixed => |l| l, else => unreachable };
    fbs.pos += len1;

    const hdr2 = try header_mod.readHeader(reader);
    try testing.expectEqual(PacketTag.sym_encrypted_integrity_protected_data, hdr2.tag);
}

// ==========================================================================
// Old-format packet header interop
// ==========================================================================

test "gnupg_interop: old-format packet header write/read round-trip" {
    var buf: [6]u8 = undefined;
    const test_lens = [_]u32{ 0, 200, 1000, 100000 };
    for (test_lens) |len| {
        var fbs = std.io.fixedBufferStream(&buf);
        try header_mod.writeOldHeader(fbs.writer(), .public_key, len);
        fbs.pos = 0;
        const hdr = try header_mod.readHeader(fbs.reader());
        try testing.expectEqual(PacketTag.public_key, hdr.tag);
        try testing.expectEqual(header_mod.BodyLength{ .fixed = len }, hdr.body_length);
    }
}

// ==========================================================================
// SHA-256 empty input (well-known vector)
// ==========================================================================

test "gnupg_interop: SHA-256 empty input known vector" {
    var ctx = try HashContext.init(.sha256);
    ctx.update("");
    var digest: [32]u8 = undefined;
    ctx.final(&digest);
    try testing.expectEqualSlices(u8, &[_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    }, &digest);
}

// ==========================================================================
// Cleartext signature with multiple hash algorithms
// ==========================================================================

test "gnupg_interop: cleartext signature all hash algorithms" {
    const allocator = testing.allocator;
    const mock_sig = [_]u8{ 0x04, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00 };
    const algos = [_]struct { a: HashAlgorithm, n: []const u8 }{
        .{ .a = .sha256, .n = "SHA256" },
        .{ .a = .sha384, .n = "SHA384" },
        .{ .a = .sha512, .n = "SHA512" },
    };
    for (algos) |a| {
        const msg = try cleartext.createCleartextSignature(allocator, "test", &mock_sig, a.a);
        defer allocator.free(msg);

        var header_buf: [32]u8 = undefined;
        const header = std.fmt.bufPrint(&header_buf, "Hash: {s}", .{a.n}) catch unreachable;
        try testing.expect(mem.indexOf(u8, msg, header) != null);

        const parsed = try cleartext.parseCleartextSignature(allocator, msg);
        defer parsed.deinit(allocator);
        try testing.expectEqual(a.a, parsed.hash_algo);
    }
}
