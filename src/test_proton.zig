// SPDX-License-Identifier: MIT
//! Integration tests for Proton Mail / GopenPGP compatibility layer.
//!
//! Tests cover:
//!   - Proton key format parsing and serialization
//!   - GopenPGP type compatibility (KeyRing, SessionKey, PlainMessage, PGPMessage)
//!   - Message format detection
//!   - Address key management and rotation
//!   - Contact card types
//!   - Compatibility checking for algorithms

const std = @import("std");
const testing = std.testing;
const mem = std.mem;

const proton = @import("compat/proton.zig");
const ProtonArmorHeaders = proton.ProtonArmorHeaders;
const ProtonArmoredKey = proton.ProtonArmoredKey;
const ProtonCompat = proton.ProtonCompat;
const ProtonMessageType = proton.ProtonMessageType;
const ProtonMimeBuilder = proton.ProtonMimeBuilder;
const SessionKey = proton.SessionKey;
const PlainMessage = proton.PlainMessage;
const PGPMessage = proton.PGPMessage;
const PGPSignature = proton.PGPSignature;
const KeyRing = proton.KeyRing;
const ContactCardType = proton.ContactCardType;
const AddressKeyManager = proton.AddressKeyManager;

const enums = @import("types/enums.zig");
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;

// =========================================================================
// Proton Armor Header Tests
// =========================================================================

test "Proton armor headers: detect ProtonMail" {
    try testing.expect(ProtonArmorHeaders.isProtonArmor("Version: ProtonMail\r\n"));
    try testing.expect(ProtonArmorHeaders.isProtonArmor("Version: GopenPGP 2.7.5\r\n"));
    try testing.expect(ProtonArmorHeaders.isProtonArmor("Comment: https://protonmail.com\r\n"));
    try testing.expect(ProtonArmorHeaders.isProtonArmor("Comment: proton.me\r\n"));
}

test "Proton armor headers: reject non-Proton" {
    try testing.expect(!ProtonArmorHeaders.isProtonArmor("Version: GnuPG v2\r\n"));
    try testing.expect(!ProtonArmorHeaders.isProtonArmor("Version: Sequoia-PGP 1.0\r\n"));
    try testing.expect(!ProtonArmorHeaders.isProtonArmor(""));
}

test "Proton armor headers: generate" {
    const allocator = testing.allocator;
    const headers = try ProtonArmorHeaders.generateHeaders(allocator);
    defer allocator.free(headers);

    try testing.expect(headers.len > 0);
    try testing.expect(mem.indexOf(u8, headers, "GopenPGP") != null);
    try testing.expect(mem.indexOf(u8, headers, "protonmail.com") != null);
}

// =========================================================================
// Proton Armored Key Tests
// =========================================================================

test "ProtonArmoredKey: parse public key" {
    const allocator = testing.allocator;

    const armored =
        \\-----BEGIN PGP PUBLIC KEY BLOCK-----
        \\Version: GopenPGP 2.7.5
        \\Comment: https://protonmail.com
        \\
        \\bWVzc2FnZQ==
        \\-----END PGP PUBLIC KEY BLOCK-----
    ;

    var key = try ProtonArmoredKey.parse(allocator, armored);
    defer key.deinit(allocator);

    try testing.expectEqual(ProtonArmoredKey.KeyType.public, key.key_type);
    try testing.expect(key.is_primary);
    try testing.expect(key.address == null);
    try testing.expect(key.headers.len > 0);
    try testing.expect(key.body.len > 0);
}

test "ProtonArmoredKey: parse private key" {
    const allocator = testing.allocator;

    const armored =
        \\-----BEGIN PGP PRIVATE KEY BLOCK-----
        \\Version: ProtonMail
        \\
        \\c2VjcmV0
        \\-----END PGP PRIVATE KEY BLOCK-----
    ;

    var key = try ProtonArmoredKey.parse(allocator, armored);
    defer key.deinit(allocator);

    try testing.expectEqual(ProtonArmoredKey.KeyType.private, key.key_type);
}

test "ProtonArmoredKey: parse invalid format" {
    const allocator = testing.allocator;
    try testing.expectError(proton.ProtonError.InvalidKeyFormat,
        ProtonArmoredKey.parse(allocator, "Not a PGP key at all"));
}

test "ProtonArmoredKey: roundtrip armor" {
    const allocator = testing.allocator;

    const armored =
        \\-----BEGIN PGP PUBLIC KEY BLOCK-----
        \\Version: GopenPGP 2.7.5
        \\
        \\AQIDBA==
        \\-----END PGP PUBLIC KEY BLOCK-----
    ;

    var key = try ProtonArmoredKey.parse(allocator, armored);
    defer key.deinit(allocator);

    const rearmored = try key.toArmored(allocator);
    defer allocator.free(rearmored);

    try testing.expect(mem.indexOf(u8, rearmored, "BEGIN PGP PUBLIC KEY BLOCK") != null);
    try testing.expect(mem.indexOf(u8, rearmored, "END PGP PUBLIC KEY BLOCK") != null);
    try testing.expect(mem.indexOf(u8, rearmored, "AQIDBA==") != null);
}

test "ProtonArmoredKey: key type armor tags" {
    try testing.expectEqualStrings("PGP PUBLIC KEY BLOCK",
        ProtonArmoredKey.KeyType.public.armorTag());
    try testing.expectEqualStrings("PGP PRIVATE KEY BLOCK",
        ProtonArmoredKey.KeyType.private.armorTag());
}

// =========================================================================
// Session Key Tests
// =========================================================================

test "SessionKey: AES-256 creation" {
    const key_bytes: [32]u8 = .{0x42} ** 32;
    const sk = SessionKey.fromAes256(key_bytes);

    try testing.expectEqual(@as(u8, 32), sk.key_len);
    try testing.expectEqual(SymmetricAlgorithm.aes256, sk.algorithm);
    try testing.expect(sk.isProtonPreferred());
    try testing.expectEqual(@as(u8, 0x42), sk.keyBytes()[0]);
    try testing.expectEqual(@as(usize, 32), sk.keyBytes().len);
}

test "SessionKey: from raw bytes" {
    const raw: [24]u8 = .{0x01} ** 24;
    const sk = SessionKey.fromRaw(&raw, .aes192);

    try testing.expectEqual(@as(u8, 24), sk.key_len);
    try testing.expectEqual(SymmetricAlgorithm.aes192, sk.algorithm);
    try testing.expect(!sk.isProtonPreferred());
}

test "SessionKey: AES-128 is not Proton preferred" {
    const raw: [16]u8 = .{0x55} ** 16;
    const sk = SessionKey.fromRaw(&raw, .aes128);
    try testing.expect(!sk.isProtonPreferred());
}

test "SessionKey: zeroize clears key material" {
    var sk = SessionKey.fromAes256(.{0xFF} ** 32);
    try testing.expectEqual(@as(u8, 0xFF), sk.key[0]);

    sk.zeroize();
    try testing.expectEqual(@as(u8, 0), sk.key[0]);
    try testing.expectEqual(@as(u8, 0), sk.key[31]);
    try testing.expectEqual(@as(u8, 0), sk.key_len);
}

test "SessionKey: JSON serialization" {
    const allocator = testing.allocator;
    const sk = SessionKey.fromAes256(.{0xAB} ** 32);

    const json = try sk.toJson(allocator);
    defer allocator.free(json);

    try testing.expect(json.len > 0);
    try testing.expect(mem.indexOf(u8, json, "\"Key\":\"") != null);
    try testing.expect(mem.indexOf(u8, json, "\"Algo\":\"") != null);
    // AES-256 key bytes should be hex-encoded
    try testing.expect(mem.indexOf(u8, json, "abab") != null);
}

// =========================================================================
// PlainMessage / PGPMessage Tests
// =========================================================================

test "PlainMessage: text message" {
    const allocator = testing.allocator;
    const msg = try PlainMessage.text(allocator, "Hello, Proton!");
    defer msg.deinit(allocator);

    try testing.expect(msg.is_text);
    try testing.expectEqualStrings("Hello, Proton!", msg.getText().?);
    try testing.expect(msg.filename == null);
    try testing.expectEqual(@as(usize, 14), msg.getBinary().len);
}

test "PlainMessage: binary message" {
    const allocator = testing.allocator;
    const data: [8]u8 = .{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    const msg = try PlainMessage.binary(allocator, &data, "document.pdf");
    defer msg.deinit(allocator);

    try testing.expect(!msg.is_text);
    try testing.expect(msg.getText() == null);
    try testing.expectEqual(@as(usize, 8), msg.getBinary().len);
    try testing.expectEqualStrings("document.pdf", msg.filename.?);
}

test "PlainMessage: binary without filename" {
    const allocator = testing.allocator;
    const msg = try PlainMessage.binary(allocator, &.{0x42}, null);
    defer msg.deinit(allocator);

    try testing.expect(msg.filename == null);
}

test "PGPMessage: from armored" {
    const allocator = testing.allocator;
    const armored = "-----BEGIN PGP MESSAGE-----\ndata\n-----END PGP MESSAGE-----";
    const msg = try PGPMessage.fromArmored(allocator, armored);
    defer msg.deinit(allocator);

    try testing.expect(msg.is_armored);
    try testing.expectEqualStrings(armored, msg.getArmored().?);
}

test "PGPMessage: from binary" {
    const allocator = testing.allocator;
    const msg = try PGPMessage.fromBinary(allocator, &.{ 0xC0, 0x01, 0x02 });
    defer msg.deinit(allocator);

    try testing.expect(!msg.is_armored);
    try testing.expect(msg.getArmored() == null);
}

test "PGPSignature: from armored" {
    const allocator = testing.allocator;
    const sig = try PGPSignature.fromArmored(allocator, "-----BEGIN PGP SIGNATURE-----\nsig\n-----END PGP SIGNATURE-----");
    defer sig.deinit(allocator);

    try testing.expect(sig.is_armored);
}

// =========================================================================
// KeyRing Tests
// =========================================================================

test "KeyRing: add and find keys" {
    const allocator = testing.allocator;
    var ring = KeyRing.init(allocator);
    defer ring.deinit();

    try ring.addKey("ABCD1234", "armored-data", "alice@proton.me", true, true, false, true);
    try ring.addKey("EFGH5678", "enc-key-data", "alice@proton.me", false, false, true, false);
    try ring.addKey("IJKL9012", "bob-key-data", "bob@proton.me", false, true, true, true);

    try testing.expectEqual(@as(usize, 3), ring.count());

    // Find primary
    const primary = ring.getPrimaryKey();
    try testing.expect(primary != null);
    try testing.expectEqualStrings("ABCD1234", primary.?.fingerprint);
    try testing.expect(primary.?.can_sign);
    try testing.expect(!primary.?.can_encrypt);

    // Find by email
    const by_email = ring.findByEmail("bob@proton.me");
    try testing.expect(by_email != null);
    try testing.expectEqualStrings("IJKL9012", by_email.?.fingerprint);

    // Find by fingerprint
    const by_fp = ring.findByFingerprint("EFGH5678");
    try testing.expect(by_fp != null);
    try testing.expect(by_fp.?.can_encrypt);

    // Not found
    try testing.expect(ring.findByFingerprint("NONEXIST") == null);
    try testing.expect(ring.findByEmail("nobody@proton.me") == null);
}

test "KeyRing: signing and encryption key queries" {
    const allocator = testing.allocator;
    var ring = KeyRing.init(allocator);
    defer ring.deinit();

    try ring.addKey("SIG1", "k1", null, true, true, false, true); // signing + private
    try ring.addKey("ENC1", "k2", null, false, false, true, false); // encryption only
    try ring.addKey("BOTH", "k3", null, false, true, true, true); // both + private

    const signing = try ring.getSigningKeys(allocator);
    defer allocator.free(signing);
    try testing.expectEqual(@as(usize, 2), signing.len); // SIG1 + BOTH

    const encrypting = try ring.getEncryptionKeys(allocator);
    defer allocator.free(encrypting);
    try testing.expectEqual(@as(usize, 2), encrypting.len); // ENC1 + BOTH
}

test "KeyRing: JSON metadata generation" {
    const allocator = testing.allocator;
    var ring = KeyRing.init(allocator);
    defer ring.deinit();

    try ring.addKey("FP1", "key1", "user@proton.me", true, true, true, true);
    try ring.addKey("FP2", "key2", null, false, false, true, false);

    const json = try ring.toJsonMeta(allocator);
    defer allocator.free(json);

    try testing.expect(json.len > 0);
    // Check JSON structure
    try testing.expect(mem.indexOf(u8, json, "\"Keys\":[") != null);
    try testing.expect(mem.indexOf(u8, json, "\"FP1\"") != null);
    try testing.expect(mem.indexOf(u8, json, "\"FP2\"") != null);
    try testing.expect(mem.indexOf(u8, json, "\"Primary\":true") != null);
    try testing.expect(mem.indexOf(u8, json, "\"Primary\":false") != null);
    try testing.expect(mem.indexOf(u8, json, "\"Email\":\"user@proton.me\"") != null);
}

test "KeyRing: empty ring" {
    const allocator = testing.allocator;
    var ring = KeyRing.init(allocator);
    defer ring.deinit();

    try testing.expectEqual(@as(usize, 0), ring.count());
    try testing.expect(ring.getPrimaryKey() == null);
    try testing.expect(ring.findByEmail("x") == null);
}

// =========================================================================
// Contact Card Tests
// =========================================================================

test "ContactCardType: encryption and signing properties" {
    // Plain
    try testing.expect(!ContactCardType.plain.isEncrypted());
    try testing.expect(!ContactCardType.plain.isSigned());

    // Encrypted only
    try testing.expect(ContactCardType.encrypted.isEncrypted());
    try testing.expect(!ContactCardType.encrypted.isSigned());

    // Signed only
    try testing.expect(!ContactCardType.signed.isEncrypted());
    try testing.expect(ContactCardType.signed.isSigned());

    // Signed + Encrypted
    try testing.expect(ContactCardType.signed_encrypted.isEncrypted());
    try testing.expect(ContactCardType.signed_encrypted.isSigned());
}

test "ContactCardType: names" {
    try testing.expectEqualStrings("Plain", ContactCardType.plain.name());
    try testing.expectEqualStrings("Encrypted", ContactCardType.encrypted.name());
    try testing.expectEqualStrings("Signed", ContactCardType.signed.name());
    try testing.expectEqualStrings("Signed+Encrypted", ContactCardType.signed_encrypted.name());
}

// =========================================================================
// Proton Compatibility Checker Tests
// =========================================================================

test "ProtonCompat: Ed25519 is preferred" {
    const allocator = testing.allocator;
    var compat = try ProtonCompat.checkKeyCompatibility(allocator, .ed25519, 256);
    defer compat.deinit(allocator);

    try testing.expect(compat.compatible);
    try testing.expect(compat.preferred);
}

test "ProtonCompat: RSA-4096 is preferred RSA" {
    const allocator = testing.allocator;
    var compat = try ProtonCompat.checkKeyCompatibility(allocator, .rsa_encrypt_sign, 4096);
    defer compat.deinit(allocator);

    try testing.expect(compat.compatible);
    try testing.expect(compat.preferred);
}

test "ProtonCompat: RSA-2048 is compatible but not preferred" {
    const allocator = testing.allocator;
    var compat = try ProtonCompat.checkKeyCompatibility(allocator, .rsa_encrypt_sign, 2048);
    defer compat.deinit(allocator);

    try testing.expect(compat.compatible);
    try testing.expect(!compat.preferred);
}

test "ProtonCompat: RSA-1024 is not compatible" {
    const allocator = testing.allocator;
    var compat = try ProtonCompat.checkKeyCompatibility(allocator, .rsa_encrypt_sign, 1024);
    defer compat.deinit(allocator);

    try testing.expect(!compat.compatible);
}

test "ProtonCompat: DSA not compatible" {
    const allocator = testing.allocator;
    var compat = try ProtonCompat.checkKeyCompatibility(allocator, .dsa, 2048);
    defer compat.deinit(allocator);

    try testing.expect(!compat.compatible);
}

test "ProtonCompat: ElGamal not compatible" {
    const allocator = testing.allocator;
    var compat = try ProtonCompat.checkKeyCompatibility(allocator, .elgamal, 2048);
    defer compat.deinit(allocator);

    try testing.expect(!compat.compatible);
}

test "ProtonCompat: X25519 compatible" {
    const allocator = testing.allocator;
    var compat = try ProtonCompat.checkKeyCompatibility(allocator, .x25519, 256);
    defer compat.deinit(allocator);

    try testing.expect(compat.compatible);
}

test "ProtonCompat: algorithm preferences" {
    try testing.expect(ProtonCompat.isPreferredSymmetric(.aes256));
    try testing.expect(!ProtonCompat.isPreferredSymmetric(.aes128));
    try testing.expect(!ProtonCompat.isPreferredSymmetric(.cast5));
    try testing.expect(!ProtonCompat.isPreferredSymmetric(.triple_des));

    try testing.expectEqual(SymmetricAlgorithm.aes256, ProtonCompat.recommendedSessionKeyAlgo());
    try testing.expectEqual(HashAlgorithm.sha256, ProtonCompat.recommendedHashAlgo());
    try testing.expectEqual(@as(u8, 0), ProtonCompat.preferredCompression());
}

test "ProtonCompat: message detection" {
    try testing.expect(ProtonCompat.isProtonMessage("Version: ProtonMail\ndata"));
    try testing.expect(ProtonCompat.isProtonMessage("Comment: https://protonmail.com\ndata"));
    try testing.expect(!ProtonCompat.isProtonMessage("Version: GnuPG v2\ndata"));
}

// =========================================================================
// Address Key Manager Tests
// =========================================================================

test "AddressKeyManager: basic operations" {
    const allocator = testing.allocator;
    var mgr = AddressKeyManager.init(allocator);
    defer mgr.deinit();

    try mgr.setPrimaryKey("PRIMARY_FINGERPRINT");
    try testing.expectEqualStrings("PRIMARY_FINGERPRINT", mgr.primary_fingerprint.?);

    try mgr.addAddressKey("alice@proton.me", "FP_ALICE", 1);
    try mgr.addAddressKey("bob@proton.me", "FP_BOB", 1);

    try testing.expectEqual(@as(usize, 2), mgr.activeKeyCount());

    const alice_fp = mgr.findKeyForAddress("alice@proton.me");
    try testing.expect(alice_fp != null);
    try testing.expectEqualStrings("FP_ALICE", alice_fp.?);

    const bob_fp = mgr.findKeyForAddress("bob@proton.me");
    try testing.expect(bob_fp != null);
    try testing.expectEqualStrings("FP_BOB", bob_fp.?);

    try testing.expect(mgr.findKeyForAddress("nobody@proton.me") == null);
}

test "AddressKeyManager: key rotation" {
    const allocator = testing.allocator;
    var mgr = AddressKeyManager.init(allocator);
    defer mgr.deinit();

    try mgr.addAddressKey("user@proton.me", "FP_V1", 1);
    try testing.expectEqual(@as(usize, 1), mgr.activeKeyCount());
    try testing.expectEqualStrings("FP_V1", mgr.findKeyForAddress("user@proton.me").?);

    // Rotate key
    try mgr.rotateKey("user@proton.me", "FP_V2", 2);

    // Old key deactivated, new key active
    try testing.expectEqualStrings("FP_V2", mgr.findKeyForAddress("user@proton.me").?);
    // Active count should still be 1 (old deactivated, new activated)
    try testing.expectEqual(@as(usize, 1), mgr.activeKeyCount());
}

test "AddressKeyManager: multiple rotations" {
    const allocator = testing.allocator;
    var mgr = AddressKeyManager.init(allocator);
    defer mgr.deinit();

    try mgr.addAddressKey("user@proton.me", "FP_V1", 1);
    try mgr.rotateKey("user@proton.me", "FP_V2", 2);
    try mgr.rotateKey("user@proton.me", "FP_V3", 3);

    try testing.expectEqualStrings("FP_V3", mgr.findKeyForAddress("user@proton.me").?);
    try testing.expectEqual(@as(usize, 1), mgr.activeKeyCount());
}

test "AddressKeyManager: set primary key overwrites" {
    const allocator = testing.allocator;
    var mgr = AddressKeyManager.init(allocator);
    defer mgr.deinit();

    try mgr.setPrimaryKey("OLD_PRIMARY");
    try mgr.setPrimaryKey("NEW_PRIMARY");

    try testing.expectEqualStrings("NEW_PRIMARY", mgr.primary_fingerprint.?);
}

// =========================================================================
// MIME Builder Tests
// =========================================================================

test "ProtonMimeBuilder: text-only message" {
    const allocator = testing.allocator;
    var builder = ProtonMimeBuilder.init(allocator, "----=boundary1");
    defer builder.deinit();

    try builder.addTextPart("Hello, world!");

    const mime = try builder.build();
    defer allocator.free(mime);

    try testing.expect(mime.len > 0);
    try testing.expect(mem.indexOf(u8, mime, "----=boundary1") != null);
    try testing.expect(mem.indexOf(u8, mime, "text/plain") != null);
    try testing.expect(mem.indexOf(u8, mime, "Hello, world!") != null);
    try testing.expect(mem.indexOf(u8, mime, "quoted-printable") != null);
}

test "ProtonMimeBuilder: multipart with attachment" {
    const allocator = testing.allocator;
    var builder = ProtonMimeBuilder.init(allocator, "boundary42");
    defer builder.deinit();

    try builder.addTextPart("Body text");
    try builder.addHtmlPart("<p>Body text</p>");
    try builder.addAttachment("application/pdf", "document.pdf", "base64data");

    const mime = try builder.build();
    defer allocator.free(mime);

    try testing.expect(mem.indexOf(u8, mime, "boundary42") != null);
    try testing.expect(mem.indexOf(u8, mime, "text/plain") != null);
    try testing.expect(mem.indexOf(u8, mime, "text/html") != null);
    try testing.expect(mem.indexOf(u8, mime, "application/pdf") != null);
    try testing.expect(mem.indexOf(u8, mime, "document.pdf") != null);
    try testing.expect(mem.indexOf(u8, mime, "Content-Transfer-Encoding: base64") != null);
    // Final boundary should have --
    try testing.expect(mem.indexOf(u8, mime, "boundary42--") != null);
}

// =========================================================================
// Message Type Tests
// =========================================================================

test "ProtonMessageType names" {
    try testing.expectEqualStrings("Inline PGP", ProtonMessageType.inline_pgp.name());
    try testing.expectEqualStrings("PGP/MIME", ProtonMessageType.mime.name());
    try testing.expectEqualStrings("Clear-signed", ProtonMessageType.clear_signed.name());
    try testing.expectEqualStrings("Signed+Encrypted MIME", ProtonMessageType.signed_encrypted_mime.name());
}
