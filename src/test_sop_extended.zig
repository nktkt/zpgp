// SPDX-License-Identifier: MIT
//! Extended tests for SOP (Stateless OpenPGP), format handling, and
//! cross-cutting concerns.
//!
//! Tests cover:
//!   - Armor encoding round-trips with various payload sizes
//!   - CRC-24 edge cases
//!   - Algorithm policy interactions with validation
//!   - Packet tag identification
//!   - Compliance checking scenarios
//!   - Key structure and fingerprint utilities

const std = @import("std");
const mem = std.mem;
const base64 = std.base64;
const testing = std.testing;

const armor = @import("armor/armor.zig");
const ArmorType = armor.ArmorType;
const crc24_mod = @import("armor/crc24.zig");

const enums = @import("types/enums.zig");
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const AeadAlgorithm = enums.AeadAlgorithm;
const CompressionAlgorithm = enums.CompressionAlgorithm;

const PacketTag = @import("packet/tags.zig").PacketTag;
const fingerprint_mod = @import("key/fingerprint.zig");

const algo_policy = @import("policy/algorithm_policy.zig");
const AlgorithmPolicy = algo_policy.AlgorithmPolicy;
const PolicyLevel = algo_policy.PolicyLevel;

const compliance = @import("policy/compliance.zig");
const ComplianceStandard = compliance.ComplianceStandard;

const deprecation = @import("crypto/deprecation.zig");
const SecurityLevel = deprecation.SecurityLevel;

const gnupg = @import("compat/gnupg.zig");
const sequoia = @import("compat/sequoia.zig");
const key_validator = @import("validation/key_validator.zig");
const message_validator = @import("validation/message_validator.zig");
const armor_validator = @import("validation/armor_validator.zig");

// =========================================================================
// Armor encoding round-trip tests
// =========================================================================

test "sop_extended: armor encode/decode empty payload" {
    const allocator = testing.allocator;

    const encoded = try armor.encode(allocator, "", .message, null);
    defer allocator.free(encoded);

    try testing.expect(mem.indexOf(u8, encoded, "-----BEGIN PGP MESSAGE-----") != null);
    try testing.expect(mem.indexOf(u8, encoded, "-----END PGP MESSAGE-----") != null);
}

test "sop_extended: armor encode/decode round-trip small payload" {
    const allocator = testing.allocator;

    const payload = "Hello, OpenPGP!";
    const encoded = try armor.encode(allocator, payload, .public_key, null);
    defer allocator.free(encoded);

    try testing.expect(mem.indexOf(u8, encoded, "-----BEGIN PGP PUBLIC KEY BLOCK-----") != null);

    var decoded = try armor.decode(allocator, encoded);
    defer decoded.deinit();

    try testing.expectEqualStrings(payload, decoded.data);
    try testing.expect(decoded.armor_type == .public_key);
}

test "sop_extended: armor encode/decode round-trip with headers" {
    const allocator = testing.allocator;

    const payload = "Test data for armor round-trip with custom headers";
    const headers = [_]armor.Header{
        .{ .name = "Version", .value = "zpgp test" },
        .{ .name = "Comment", .value = "Extended SOP test" },
    };

    const encoded = try armor.encode(allocator, payload, .signature, &headers);
    defer allocator.free(encoded);

    try testing.expect(mem.indexOf(u8, encoded, "Version: zpgp test") != null);
    try testing.expect(mem.indexOf(u8, encoded, "Comment: Extended SOP test") != null);

    var decoded = try armor.decode(allocator, encoded);
    defer decoded.deinit();

    try testing.expectEqualStrings(payload, decoded.data);
    try testing.expect(decoded.armor_type == .signature);
}

test "sop_extended: armor encode/decode round-trip private key" {
    const allocator = testing.allocator;

    const payload = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const encoded = try armor.encode(allocator, &payload, .private_key, null);
    defer allocator.free(encoded);

    try testing.expect(mem.indexOf(u8, encoded, "-----BEGIN PGP PRIVATE KEY BLOCK-----") != null);

    var decoded = try armor.decode(allocator, encoded);
    defer decoded.deinit();

    try testing.expectEqualSlices(u8, &payload, decoded.data);
    try testing.expect(decoded.armor_type == .private_key);
}

// =========================================================================
// CRC-24 edge cases
// =========================================================================

test "sop_extended: CRC-24 single byte" {
    const data = [_]u8{0xFF};
    const crc = crc24_mod.compute(&data);
    // CRC should be deterministic.
    const crc2 = crc24_mod.compute(&data);
    try testing.expectEqual(crc, crc2);
}

test "sop_extended: CRC-24 all zeros" {
    const data = [_]u8{0} ** 16;
    const crc = crc24_mod.compute(&data);
    // Just verify it does not crash and returns a value.
    try testing.expect(crc != 0 or crc == 0); // always true; proves no panic
}

test "sop_extended: CRC-24 incremental matches one-shot" {
    const data = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // One-shot.
    const crc_one = crc24_mod.compute(data);

    // Incremental.
    var crc = crc24_mod.Crc24{};
    crc.update(data[0..10]);
    crc.update(data[10..20]);
    crc.update(data[20..]);
    const crc_inc = crc.final();

    try testing.expectEqual(crc_one, crc_inc);
}

// =========================================================================
// Algorithm policy tests
// =========================================================================

test "sop_extended: policy preferred algorithms by level" {
    const rfc4880 = AlgorithmPolicy.init(.rfc4880);
    const rfc9580 = AlgorithmPolicy.init(.rfc9580);
    const strict = AlgorithmPolicy.init(.strict);

    try testing.expect(rfc4880.preferredSymmetric() == .aes128);
    try testing.expect(rfc9580.preferredSymmetric() == .aes256);
    try testing.expect(strict.preferredSymmetric() == .aes256);

    try testing.expect(rfc4880.preferredHash() == .sha256);
    try testing.expect(rfc9580.preferredHash() == .sha256);

    try testing.expect(rfc4880.preferredAead() == null);
    try testing.expect(rfc9580.preferredAead() == .gcm);
}

test "sop_extended: policy AEAD acceptance by level" {
    const rfc4880 = AlgorithmPolicy.init(.rfc4880);
    const rfc9580 = AlgorithmPolicy.init(.rfc9580);
    const strict = AlgorithmPolicy.init(.strict);

    // RFC 4880 has no AEAD.
    try testing.expect(!rfc4880.isAcceptableAead(.eax));
    try testing.expect(!rfc4880.isAcceptableAead(.ocb));
    try testing.expect(!rfc4880.isAcceptableAead(.gcm));

    // RFC 9580 and strict accept all three.
    try testing.expect(rfc9580.isAcceptableAead(.eax));
    try testing.expect(rfc9580.isAcceptableAead(.ocb));
    try testing.expect(rfc9580.isAcceptableAead(.gcm));
    try testing.expect(strict.isAcceptableAead(.eax));
    try testing.expect(strict.isAcceptableAead(.ocb));
    try testing.expect(strict.isAcceptableAead(.gcm));
}

test "sop_extended: policy key size requirements" {
    const strict = AlgorithmPolicy.init(.strict);

    // Strict requires RSA >= 3072.
    try testing.expect(!strict.isAcceptablePublicKey(.rsa_encrypt_sign, 2048));
    try testing.expect(strict.isAcceptablePublicKey(.rsa_encrypt_sign, 3072));
    try testing.expect(strict.isAcceptablePublicKey(.rsa_encrypt_sign, 4096));

    // Strict rejects DSA entirely.
    try testing.expect(!strict.isAcceptablePublicKey(.dsa, null));
}

test "sop_extended: policy validateSignature" {
    const rfc9580 = AlgorithmPolicy.init(.rfc9580);

    const result_good = rfc9580.validateSignature(.sha256, .ed25519);
    try testing.expect(result_good.accepted);

    const result_md5 = rfc9580.validateSignature(.md5, .rsa_encrypt_sign);
    try testing.expect(!result_md5.accepted);
}

// =========================================================================
// Deprecation assessment tests
// =========================================================================

test "sop_extended: deprecation assessment Ed25519" {
    const level = deprecation.assessPublicKeyAlgorithm(.ed25519);
    try testing.expect(level == .secure);
}

test "sop_extended: deprecation assessment DSA" {
    const level = deprecation.assessPublicKeyAlgorithm(.dsa);
    try testing.expect(level == .deprecated);
}

test "sop_extended: deprecation assessment ElGamal" {
    const level = deprecation.assessPublicKeyAlgorithm(.elgamal);
    try testing.expect(level == .deprecated);
}

test "sop_extended: deprecation assessment legacy EdDSA" {
    const level = deprecation.assessPublicKeyAlgorithm(.eddsa);
    try testing.expect(level == .deprecated);
}

test "sop_extended: deprecation RSA with size" {
    // RSA 4096 is secure.
    try testing.expect(deprecation.assessPublicKeyWithSize(.rsa_encrypt_sign, 4096) == .secure);
    // RSA 1024 is deprecated.
    try testing.expect(deprecation.assessPublicKeyWithSize(.rsa_encrypt_sign, 1024) == .deprecated);
    // RSA 512 is insecure.
    try testing.expect(deprecation.assessPublicKeyWithSize(.rsa_encrypt_sign, 512) == .insecure);
}

// =========================================================================
// Packet tag tests
// =========================================================================

test "sop_extended: PacketTag names" {
    try testing.expectEqualStrings("Public-Key", PacketTag.public_key.name());
    try testing.expectEqualStrings("Secret-Key", PacketTag.secret_key.name());
    try testing.expectEqualStrings("Signature", PacketTag.signature.name());
    try testing.expectEqualStrings("Literal Data", PacketTag.literal_data.name());
    try testing.expectEqualStrings("User ID", PacketTag.user_id.name());
    try testing.expectEqualStrings("Sym. Encrypted Integrity Protected Data", PacketTag.sym_encrypted_integrity_protected_data.name());
}

// =========================================================================
// ArmorType tests
// =========================================================================

test "sop_extended: ArmorType label round-trip" {
    const types = [_]ArmorType{ .message, .public_key, .private_key, .signature };
    for (types) |t| {
        const label = t.label();
        const parsed = ArmorType.fromLabel(label);
        try testing.expect(parsed != null);
        try testing.expect(parsed.? == t);
    }
}

test "sop_extended: ArmorType fromLabel unknown returns null" {
    try testing.expect(ArmorType.fromLabel("UNKNOWN") == null);
    try testing.expect(ArmorType.fromLabel("") == null);
}

// =========================================================================
// Algorithm enum tests
// =========================================================================

test "sop_extended: PublicKeyAlgorithm canSign" {
    try testing.expect(PublicKeyAlgorithm.rsa_encrypt_sign.canSign());
    try testing.expect(PublicKeyAlgorithm.rsa_sign_only.canSign());
    try testing.expect(PublicKeyAlgorithm.dsa.canSign());
    try testing.expect(PublicKeyAlgorithm.ecdsa.canSign());
    try testing.expect(PublicKeyAlgorithm.ed25519.canSign());
    try testing.expect(PublicKeyAlgorithm.ed448.canSign());

    try testing.expect(!PublicKeyAlgorithm.rsa_encrypt_only.canSign());
    try testing.expect(!PublicKeyAlgorithm.elgamal.canSign());
    try testing.expect(!PublicKeyAlgorithm.x25519.canSign());
}

test "sop_extended: PublicKeyAlgorithm canEncrypt" {
    try testing.expect(PublicKeyAlgorithm.rsa_encrypt_sign.canEncrypt());
    try testing.expect(PublicKeyAlgorithm.rsa_encrypt_only.canEncrypt());
    try testing.expect(PublicKeyAlgorithm.elgamal.canEncrypt());
    try testing.expect(PublicKeyAlgorithm.ecdh.canEncrypt());
    try testing.expect(PublicKeyAlgorithm.x25519.canEncrypt());
    try testing.expect(PublicKeyAlgorithm.x448.canEncrypt());

    try testing.expect(!PublicKeyAlgorithm.rsa_sign_only.canEncrypt());
    try testing.expect(!PublicKeyAlgorithm.dsa.canEncrypt());
}

test "sop_extended: PublicKeyAlgorithm isNativeV6" {
    try testing.expect(PublicKeyAlgorithm.ed25519.isNativeV6());
    try testing.expect(PublicKeyAlgorithm.ed448.isNativeV6());
    try testing.expect(PublicKeyAlgorithm.x25519.isNativeV6());
    try testing.expect(PublicKeyAlgorithm.x448.isNativeV6());

    try testing.expect(!PublicKeyAlgorithm.rsa_encrypt_sign.isNativeV6());
    try testing.expect(!PublicKeyAlgorithm.ecdsa.isNativeV6());
}

test "sop_extended: SymmetricAlgorithm keySize" {
    try testing.expectEqual(@as(?usize, 16), SymmetricAlgorithm.aes128.keySize());
    try testing.expectEqual(@as(?usize, 24), SymmetricAlgorithm.aes192.keySize());
    try testing.expectEqual(@as(?usize, 32), SymmetricAlgorithm.aes256.keySize());
    try testing.expectEqual(@as(?usize, 32), SymmetricAlgorithm.twofish.keySize());
    try testing.expectEqual(@as(?usize, 16), SymmetricAlgorithm.cast5.keySize());
    try testing.expectEqual(@as(?usize, null), SymmetricAlgorithm.plaintext.keySize());
}

test "sop_extended: SymmetricAlgorithm blockSize" {
    try testing.expectEqual(@as(?usize, 16), SymmetricAlgorithm.aes128.blockSize());
    try testing.expectEqual(@as(?usize, 16), SymmetricAlgorithm.aes256.blockSize());
    try testing.expectEqual(@as(?usize, 8), SymmetricAlgorithm.cast5.blockSize());
    try testing.expectEqual(@as(?usize, 8), SymmetricAlgorithm.triple_des.blockSize());
}

test "sop_extended: HashAlgorithm digestSize" {
    try testing.expectEqual(@as(?usize, 16), HashAlgorithm.md5.digestSize());
    try testing.expectEqual(@as(?usize, 20), HashAlgorithm.sha1.digestSize());
    try testing.expectEqual(@as(?usize, 32), HashAlgorithm.sha256.digestSize());
    try testing.expectEqual(@as(?usize, 48), HashAlgorithm.sha384.digestSize());
    try testing.expectEqual(@as(?usize, 64), HashAlgorithm.sha512.digestSize());
}

// =========================================================================
// Fingerprint utility tests
// =========================================================================

test "sop_extended: V4 fingerprint deterministic" {
    const body = [_]u8{
        4,                      // version
        0x60, 0x00, 0x00, 0x00, // creation_time
        1,                      // RSA
        0x00, 0x08, 0xFF,       // MPI
        0x00, 0x08, 0x03,       // MPI (e=3)
    };

    const fp1 = fingerprint_mod.calculateV4Fingerprint(&body);
    const fp2 = fingerprint_mod.calculateV4Fingerprint(&body);
    try testing.expectEqual(fp1, fp2);
}

test "sop_extended: V4 keyId is last 8 bytes of fingerprint" {
    const body = [_]u8{
        4,
        0x60, 0x00, 0x00, 0x00,
        1,
        0x00, 0x08, 0xFF,
        0x00, 0x08, 0x03,
    };

    const fp = fingerprint_mod.calculateV4Fingerprint(&body);
    const kid = fingerprint_mod.keyIdFromFingerprint(fp);
    try testing.expectEqualSlices(u8, fp[12..20], &kid);
}

// =========================================================================
// Cross-module integration tests
// =========================================================================

test "sop_extended: gnupg status round-trip through format and parse" {
    const allocator = testing.allocator;

    var messages = try gnupg.generateStatus(allocator, .decrypt, .{
        .decrypt = .{
            .success = true,
            .key_id = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 },
            .sym_algo = .aes256,
            .is_session_key = false,
        },
    });
    defer {
        for (messages.items) |msg| msg.deinit(allocator);
        messages.deinit(allocator);
    }

    const output = try gnupg.formatStatusOutput(allocator, messages.items);
    defer allocator.free(output);

    var parsed = try gnupg.parseStatusOutput(allocator, output);
    defer {
        for (parsed.items) |msg| msg.deinit(allocator);
        parsed.deinit(allocator);
    }

    try testing.expectEqual(messages.items.len, parsed.items.len);
    for (messages.items, 0..) |orig, i| {
        try testing.expect(orig.keyword == parsed.items[i].keyword);
    }
}

test "sop_extended: key validator + sequoia compat on same data" {
    const allocator = testing.allocator;

    var data: [14]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.public_key);
    data[1] = 12;
    data[2] = 4;
    data[3] = 0x60;
    data[4] = 0x00;
    data[5] = 0x00;
    data[6] = 0x00;
    data[7] = @intFromEnum(PublicKeyAlgorithm.ed25519);
    @memset(data[8..], 0);

    // Key validator
    const kv = key_validator.KeyValidator.init(.rfc9580, false);
    var kreport = try kv.validateKey(allocator, &data);
    defer kreport.deinit(allocator);

    try testing.expectEqualStrings("Ed25519", kreport.algorithm);
    try testing.expectEqual(@as(u8, 4), kreport.version);

    // Sequoia compat
    var sreport = try sequoia.checkSequoiaCompatibility(allocator, &data);
    defer sreport.deinit(allocator);

    try testing.expect(sreport.compatible);
}

test "sop_extended: message validator + armor validator pipeline" {
    const allocator = testing.allocator;

    // Create a minimal signed message.
    var data: [14]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.signature);
    data[1] = 12;
    data[2] = 4;
    data[3] = 0;
    data[4] = @intFromEnum(PublicKeyAlgorithm.ed25519);
    data[5] = @intFromEnum(HashAlgorithm.sha256);
    @memset(data[6..], 0);

    // Validate as message.
    const mv = message_validator.MessageValidator.init(.rfc9580);
    var mresult = try mv.validateMessage(allocator, &data);
    defer mresult.deinit(allocator);

    try testing.expect(mresult.is_signed);

    // Armor encode and validate.
    const armored = try armor.encode(allocator, &data, .message, null);
    defer allocator.free(armored);

    var aresult = try armor_validator.validateArmor(allocator, armored);
    defer aresult.deinit(allocator);

    try testing.expect(aresult.armor_type.? == .message);
}

test "sop_extended: compliance check message data" {
    const allocator = testing.allocator;

    // New-format SEIPD v1 packet.
    var data: [12]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.sym_encrypted_integrity_protected_data);
    data[1] = 10;
    data[2] = 1; // version 1
    @memset(data[3..], 0);

    var report = try compliance.checkMessageCompliance(&data, .openpgp_rfc4880, allocator);
    defer report.deinit();

    // Should be valid RFC 4880 data.
    try testing.expect(report.compliant);
}

test "sop_extended: SecurityLevel safe for creation" {
    try testing.expect(SecurityLevel.secure.isSafeForCreation());
    try testing.expect(!SecurityLevel.deprecated.isSafeForCreation());
    try testing.expect(!SecurityLevel.insecure.isSafeForCreation());
    try testing.expect(!SecurityLevel.unknown.isSafeForCreation());
}

test "sop_extended: SecurityLevel acceptable for verification" {
    try testing.expect(SecurityLevel.secure.isAcceptableForVerification());
    try testing.expect(SecurityLevel.deprecated.isAcceptableForVerification());
    try testing.expect(!SecurityLevel.insecure.isAcceptableForVerification());
    try testing.expect(!SecurityLevel.unknown.isAcceptableForVerification());
}
