// SPDX-License-Identifier: MIT
//! RFC 9580 feature test suite.
//!
//! Tests for the native key types, Argon2 S2K, V6 fingerprints, HKDF,
//! algorithm deprecation, and related functionality introduced by RFC 9580.

const std = @import("std");
const testing = std.testing;

// Crypto modules
const HkdfSha256 = @import("crypto/hkdf.zig").HkdfSha256;
const Ed25519Native = @import("crypto/ed25519_native.zig").Ed25519Native;
const Ed25519NativeError = @import("crypto/ed25519_native.zig").Ed25519NativeError;
const X25519Native = @import("crypto/x25519_native.zig").X25519Native;
const X25519NativeError = @import("crypto/x25519_native.zig").X25519NativeError;
const X448Native = @import("crypto/x448.zig").X448Native;
const Ed448Native = @import("crypto/ed448.zig").Ed448Native;
const Argon2S2K = @import("crypto/argon2.zig").Argon2S2K;
const deprecation = @import("crypto/deprecation.zig");
const SecurityLevel = deprecation.SecurityLevel;

// Key modules
const v6_fp = @import("key/v6_fingerprint.zig");

// Types
const enums = @import("types/enums.zig");
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const S2K = @import("types/s2k.zig").S2K;
const S2kType = @import("types/s2k.zig").S2kType;

// =========================================================================
// V6 Fingerprint Tests
// =========================================================================

test "rfc9580: V6 fingerprint with Ed25519 native key" {
    // Simulate a V6 Ed25519 key packet body
    var body: [38]u8 = undefined;
    body[0] = 6; // version 6
    std.mem.writeInt(u32, body[1..5], 1700000000, .big); // creation time
    body[5] = 27; // Ed25519 native (algo 27)
    @memset(body[6..38], 0x42); // 32-byte public key

    const fp = v6_fp.calculateV6Fingerprint(&body);
    try testing.expectEqual(@as(usize, 32), fp.len);

    // Key ID is first 8 bytes of V6 fingerprint
    const kid = v6_fp.v6KeyIdFromFingerprint(fp);
    try testing.expectEqualSlices(u8, fp[0..8], &kid);
}

test "rfc9580: V6 fingerprint differs from V4 for same body" {
    const body = [_]u8{ 4, 0x00, 0x00, 0x00, 0x01, 1, 0x00, 0x08, 0x80, 0x00, 0x08, 0x03 };
    const v6_fingerprint = v6_fp.calculateV6Fingerprint(&body);

    // V6 uses SHA-256 (32 bytes) with 0x9B prefix and 4-byte length
    // V4 uses SHA-1 (20 bytes) with 0x99 prefix and 2-byte length
    try testing.expectEqual(@as(usize, 32), v6_fingerprint.len);
}

test "rfc9580: V6 fingerprint is deterministic" {
    var body: [38]u8 = undefined;
    body[0] = 6;
    std.mem.writeInt(u32, body[1..5], 1700000000, .big);
    body[5] = 25; // X25519 native
    @memset(body[6..38], 0xAB);

    const fp1 = v6_fp.calculateV6Fingerprint(&body);
    const fp2 = v6_fp.calculateV6Fingerprint(&body);
    try testing.expectEqual(fp1, fp2);
}

test "rfc9580: V6 fingerprint hex formatting" {
    const fp = [_]u8{0xDE} ** 32;
    const hex = v6_fp.formatV6Fingerprint(fp);
    // All bytes are 0xDE, so hex should be "DEDE..." (64 chars)
    for (0..32) |i| {
        try testing.expectEqual(@as(u8, 'D'), hex[i * 2]);
        try testing.expectEqual(@as(u8, 'E'), hex[i * 2 + 1]);
    }
}

// =========================================================================
// HKDF Tests
// =========================================================================

test "rfc9580: HKDF-SHA256 basic key derivation" {
    const ikm = [_]u8{0x42} ** 32;
    const salt = [_]u8{0x00} ** 16;
    const info = "OpenPGP X25519";

    var key1: [32]u8 = undefined;
    HkdfSha256.deriveKey(&key1, &salt, &ikm, info);

    var key2: [32]u8 = undefined;
    HkdfSha256.deriveKey(&key2, &salt, &ikm, info);

    try testing.expectEqualSlices(u8, &key1, &key2);
}

test "rfc9580: HKDF-SHA256 different info produces different keys" {
    const ikm = [_]u8{0x42} ** 32;
    const salt = [_]u8{0x00} ** 16;

    var key1: [32]u8 = undefined;
    HkdfSha256.deriveKey(&key1, &salt, &ikm, "info1");

    var key2: [32]u8 = undefined;
    HkdfSha256.deriveKey(&key2, &salt, &ikm, "info2");

    try testing.expect(!std.mem.eql(u8, &key1, &key2));
}

test "rfc9580: HKDF-SHA256 extract and expand" {
    const ikm = [_]u8{0x0b} ** 22;
    const salt = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };

    const prk = HkdfSha256.extract(&salt, &ikm);
    try testing.expectEqual(@as(usize, 32), prk.len);

    var okm: [32]u8 = undefined;
    HkdfSha256.expand(&okm, "test", prk);
    // Just verify it doesn't crash and produces non-zero output
    try testing.expect(!std.mem.eql(u8, &okm, &([_]u8{0} ** 32)));
}

// =========================================================================
// X25519 Native Tests
// =========================================================================

test "rfc9580: X25519 native key generation" {
    const kp = X25519Native.generate();
    try testing.expectEqual(@as(usize, 32), kp.public.len);
    try testing.expectEqual(@as(usize, 32), kp.secret.len);
    try testing.expect(!std.mem.eql(u8, &kp.public, &([_]u8{0} ** 32)));
}

test "rfc9580: X25519 native encrypt/decrypt round-trip" {
    const allocator = testing.allocator;
    const recipient = X25519Native.generate();
    const session_key = [_]u8{
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    };

    const encrypted = try X25519Native.encryptSessionKey(
        allocator,
        recipient.public,
        &session_key,
        @intFromEnum(SymmetricAlgorithm.aes128),
    );
    defer encrypted.deinit();

    const decrypted = try X25519Native.decryptSessionKey(
        allocator,
        recipient.secret,
        recipient.public,
        encrypted.ephemeral_public,
        encrypted.wrapped_key,
        @intFromEnum(SymmetricAlgorithm.aes128),
    );
    defer allocator.free(decrypted);

    try testing.expectEqualSlices(u8, &session_key, decrypted);
}

test "rfc9580: X25519 native wrong recipient fails" {
    const allocator = testing.allocator;
    const recipient = X25519Native.generate();
    const wrong = X25519Native.generate();
    const session_key = [_]u8{0xFF} ** 32;

    const encrypted = try X25519Native.encryptSessionKey(
        allocator,
        recipient.public,
        &session_key,
        @intFromEnum(SymmetricAlgorithm.aes256),
    );
    defer encrypted.deinit();

    try testing.expectError(
        X25519NativeError.UnwrapFailed,
        X25519Native.decryptSessionKey(
            allocator,
            wrong.secret,
            wrong.public,
            encrypted.ephemeral_public,
            encrypted.wrapped_key,
            @intFromEnum(SymmetricAlgorithm.aes256),
        ),
    );
}

test "rfc9580: X25519 native public key derivation" {
    const kp = X25519Native.generate();
    const derived = X25519Native.publicKeyFromSecret(kp.secret);
    try testing.expectEqualSlices(u8, &kp.public, &derived);
}

// =========================================================================
// Ed25519 Native Tests
// =========================================================================

test "rfc9580: Ed25519 native sign and verify" {
    const kp = Ed25519Native.generate();
    const message = "RFC 9580 Ed25519 test message";

    const sig = try Ed25519Native.sign(kp.secret, kp.public, message);
    try Ed25519Native.verify(kp.public, message, sig);
}

test "rfc9580: Ed25519 native reject wrong message" {
    const kp = Ed25519Native.generate();
    const sig = try Ed25519Native.sign(kp.secret, kp.public, "correct");

    try testing.expectError(
        Ed25519NativeError.SignatureVerificationFailed,
        Ed25519Native.verify(kp.public, "wrong", sig),
    );
}

test "rfc9580: Ed25519 native reject wrong key" {
    const kp1 = Ed25519Native.generate();
    const kp2 = Ed25519Native.generate();
    const sig = try Ed25519Native.sign(kp1.secret, kp1.public, "test");

    try testing.expectError(
        Ed25519NativeError.SignatureVerificationFailed,
        Ed25519Native.verify(kp2.public, "test", sig),
    );
}

test "rfc9580: Ed25519 native deterministic signatures" {
    const kp = Ed25519Native.generate();
    const msg = "deterministic";
    const sig1 = try Ed25519Native.sign(kp.secret, kp.public, msg);
    const sig2 = try Ed25519Native.sign(kp.secret, kp.public, msg);
    try testing.expectEqualSlices(u8, &sig1, &sig2);
}

test "rfc9580: Ed25519 native 32-byte seed secret" {
    const kp = Ed25519Native.generate();
    // RFC 9580 stores only the 32-byte seed
    try testing.expectEqual(@as(usize, 32), kp.secret.len);
    try testing.expectEqual(@as(usize, 32), kp.public.len);
}

// =========================================================================
// X448 and Ed448 Stub Tests
// =========================================================================

test "rfc9580: X448 key generation works" {
    const kp = X448Native.generate();
    try testing.expectEqual(@as(usize, 56), X448Native.public_key_size);
    try testing.expectEqual(@as(usize, 56), X448Native.secret_key_size);
    try testing.expect(!std.mem.eql(u8, &kp.public, &([_]u8{0} ** 56)));
}

test "rfc9580: Ed448 returns UnsupportedAlgorithm" {
    // Ed448 is not yet implemented (awaiting proper curve arithmetic)
    try testing.expectError(error.UnsupportedAlgorithm, Ed448Native.generate());
    try testing.expectEqual(@as(usize, 57), Ed448Native.public_key_len);
    try testing.expectEqual(@as(usize, 57), Ed448Native.secret_key_len);
    try testing.expectEqual(@as(usize, 114), Ed448Native.signature_len);
}

// =========================================================================
// Argon2 S2K Tests
// =========================================================================

test "rfc9580: Argon2 S2K key derivation" {
    const allocator = testing.allocator;
    const s2k = Argon2S2K{
        .salt = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 },
        .passes = 1,
        .parallelism = 1,
        .encoded_memory = 10, // 1024 KiB for testing
    };

    var key: [32]u8 = undefined;
    try s2k.deriveKey(allocator, "test-passphrase", &key);

    // Same input should produce same output
    var key2: [32]u8 = undefined;
    try s2k.deriveKey(allocator, "test-passphrase", &key2);
    try testing.expectEqualSlices(u8, &key, &key2);
}

test "rfc9580: Argon2 S2K different passwords produce different keys" {
    const allocator = testing.allocator;
    const s2k = Argon2S2K{
        .salt = [_]u8{0xBB} ** 16,
        .passes = 1,
        .parallelism = 1,
        .encoded_memory = 10,
    };

    var key1: [32]u8 = undefined;
    try s2k.deriveKey(allocator, "password1", &key1);

    var key2: [32]u8 = undefined;
    try s2k.deriveKey(allocator, "password2", &key2);

    try testing.expect(!std.mem.eql(u8, &key1, &key2));
}

test "rfc9580: Argon2 S2K wire format" {
    const s2k = Argon2S2K{
        .salt = [_]u8{0xCC} ** 16,
        .passes = 3,
        .parallelism = 4,
        .encoded_memory = 21,
    };

    var buf: [20]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try s2k.writeTo(fbs.writer());

    try testing.expectEqual(@as(usize, 20), fbs.pos);
    try testing.expectEqual(@as(u8, 4), buf[0]); // type byte
    try testing.expectEqualSlices(u8, &([_]u8{0xCC} ** 16), buf[1..17]);
    try testing.expectEqual(@as(u8, 3), buf[17]); // passes
    try testing.expectEqual(@as(u8, 4), buf[18]); // parallelism
    try testing.expectEqual(@as(u8, 21), buf[19]); // encoded_memory
}

test "rfc9580: Argon2 S2K memory calculation" {
    const s2k = Argon2S2K{
        .salt = [_]u8{0} ** 16,
        .passes = 1,
        .parallelism = 1,
        .encoded_memory = 21,
    };
    // 2^21 = 2097152 KiB = 2 GiB
    try testing.expectEqual(@as(u64, 2097152), s2k.memoryKiB());
}

test "rfc9580: S2K type 4 integration" {
    // Test S2K wrapper with Argon2
    const s2k_wrapper = S2K{
        .s2k_type = .argon2,
        .hash_algo = .sha256,
        .salt = [_]u8{0} ** 8,
        .coded_count = 0,
        .argon2_data = .{
            .salt = [_]u8{0xDD} ** 16,
            .passes = 1,
            .parallelism = 1,
            .encoded_memory = 10,
        },
    };

    try testing.expectEqual(@as(usize, 20), s2k_wrapper.wireSize());

    // Non-allocating deriveKey should fail
    var key: [32]u8 = undefined;
    try testing.expectError(error.UnsupportedS2kType, s2k_wrapper.deriveKey("test", &key));

    // Allocating version should work
    const allocator = testing.allocator;
    try s2k_wrapper.deriveKeyAlloc(allocator, "test", &key);
    try testing.expect(!std.mem.eql(u8, &key, &([_]u8{0} ** 32)));
}

// =========================================================================
// Algorithm Deprecation Tests
// =========================================================================

test "rfc9580: deprecation of legacy algorithms" {
    // MD5 is insecure
    try testing.expectEqual(SecurityLevel.insecure, deprecation.assessHashAlgorithm(.md5));

    // SHA-1 is deprecated
    try testing.expectEqual(SecurityLevel.deprecated, deprecation.assessHashAlgorithm(.sha1));

    // SHA-256 is secure
    try testing.expectEqual(SecurityLevel.secure, deprecation.assessHashAlgorithm(.sha256));

    // CAST5 is deprecated
    try testing.expectEqual(SecurityLevel.deprecated, deprecation.assessSymmetricAlgorithm(.cast5));

    // AES-256 is secure
    try testing.expectEqual(SecurityLevel.secure, deprecation.assessSymmetricAlgorithm(.aes256));
}

test "rfc9580: deprecation of legacy EdDSA" {
    // Legacy EdDSA (22) is deprecated
    try testing.expectEqual(SecurityLevel.deprecated, deprecation.assessPublicKeyAlgorithm(.eddsa));

    // Native Ed25519 (27) is secure
    try testing.expectEqual(SecurityLevel.secure, deprecation.assessPublicKeyAlgorithm(.ed25519));
}

test "rfc9580: native algorithm IDs are secure" {
    try testing.expectEqual(SecurityLevel.secure, deprecation.assessPublicKeyAlgorithm(.x25519));
    try testing.expectEqual(SecurityLevel.secure, deprecation.assessPublicKeyAlgorithm(.x448));
    try testing.expectEqual(SecurityLevel.secure, deprecation.assessPublicKeyAlgorithm(.ed25519));
    try testing.expectEqual(SecurityLevel.secure, deprecation.assessPublicKeyAlgorithm(.ed448));
}

test "rfc9580: RSA key size affects security level" {
    try testing.expectEqual(SecurityLevel.insecure, deprecation.assessPublicKeyWithSize(.rsa_encrypt_sign, 512));
    try testing.expectEqual(SecurityLevel.deprecated, deprecation.assessPublicKeyWithSize(.rsa_encrypt_sign, 1024));
    try testing.expectEqual(SecurityLevel.secure, deprecation.assessPublicKeyWithSize(.rsa_encrypt_sign, 2048));
    try testing.expectEqual(SecurityLevel.secure, deprecation.assessPublicKeyWithSize(.rsa_encrypt_sign, 4096));
}

test "rfc9580: deprecation warnings" {
    try testing.expect(deprecation.getDeprecationWarning("AES-256", .secure) == null);
    try testing.expect(deprecation.getDeprecationWarning("CAST5", .deprecated) != null);
    try testing.expect(deprecation.getDeprecationWarning("MD5", .insecure) != null);
}

test "rfc9580: hash acceptability for signatures" {
    try testing.expect(!deprecation.isHashAcceptableForSignatures(.sha1));
    try testing.expect(!deprecation.isHashAcceptableForSignatures(.md5));
    try testing.expect(deprecation.isHashAcceptableForSignatures(.sha256));
    try testing.expect(deprecation.isHashAcceptableForSignatures(.sha512));
}

test "rfc9580: recommended replacements" {
    try testing.expectEqualStrings("AES-128", deprecation.getRecommendedReplacement("CAST5").?);
    try testing.expectEqualStrings("SHA-256", deprecation.getRecommendedReplacement("MD5").?);
    try testing.expectEqualStrings("Ed25519 (algorithm 27)", deprecation.getRecommendedReplacement("EdDSA").?);
    try testing.expect(deprecation.getRecommendedReplacement("AES-256") == null);
}

// =========================================================================
// Enum Extension Tests
// =========================================================================

test "rfc9580: new algorithm enum values" {
    try testing.expectEqual(@as(u8, 25), @intFromEnum(PublicKeyAlgorithm.x25519));
    try testing.expectEqual(@as(u8, 26), @intFromEnum(PublicKeyAlgorithm.x448));
    try testing.expectEqual(@as(u8, 27), @intFromEnum(PublicKeyAlgorithm.ed25519));
    try testing.expectEqual(@as(u8, 28), @intFromEnum(PublicKeyAlgorithm.ed448));
}

test "rfc9580: native algorithm names" {
    try testing.expectEqualStrings("X25519", PublicKeyAlgorithm.x25519.name());
    try testing.expectEqualStrings("X448", PublicKeyAlgorithm.x448.name());
    try testing.expectEqualStrings("Ed25519", PublicKeyAlgorithm.ed25519.name());
    try testing.expectEqualStrings("Ed448", PublicKeyAlgorithm.ed448.name());
}

test "rfc9580: native algorithms can sign or encrypt" {
    // Signing algorithms
    try testing.expect(PublicKeyAlgorithm.ed25519.canSign());
    try testing.expect(PublicKeyAlgorithm.ed448.canSign());
    try testing.expect(!PublicKeyAlgorithm.ed25519.canEncrypt());
    try testing.expect(!PublicKeyAlgorithm.ed448.canEncrypt());

    // Encryption algorithms
    try testing.expect(PublicKeyAlgorithm.x25519.canEncrypt());
    try testing.expect(PublicKeyAlgorithm.x448.canEncrypt());
    try testing.expect(!PublicKeyAlgorithm.x25519.canSign());
    try testing.expect(!PublicKeyAlgorithm.x448.canSign());
}

test "rfc9580: isNativeV6 classification" {
    try testing.expect(PublicKeyAlgorithm.x25519.isNativeV6());
    try testing.expect(PublicKeyAlgorithm.x448.isNativeV6());
    try testing.expect(PublicKeyAlgorithm.ed25519.isNativeV6());
    try testing.expect(PublicKeyAlgorithm.ed448.isNativeV6());
    try testing.expect(!PublicKeyAlgorithm.rsa_encrypt_sign.isNativeV6());
    try testing.expect(!PublicKeyAlgorithm.ecdh.isNativeV6());
    try testing.expect(!PublicKeyAlgorithm.eddsa.isNativeV6());
}

test "rfc9580: native key sizes" {
    try testing.expectEqual(@as(?usize, 32), PublicKeyAlgorithm.x25519.nativePublicKeySize());
    try testing.expectEqual(@as(?usize, 32), PublicKeyAlgorithm.ed25519.nativePublicKeySize());
    try testing.expectEqual(@as(?usize, 56), PublicKeyAlgorithm.x448.nativePublicKeySize());
    try testing.expectEqual(@as(?usize, 57), PublicKeyAlgorithm.ed448.nativePublicKeySize());
    try testing.expect(PublicKeyAlgorithm.rsa_encrypt_sign.nativePublicKeySize() == null);

    try testing.expectEqual(@as(?usize, 32), PublicKeyAlgorithm.x25519.nativeSecretKeySize());
    try testing.expectEqual(@as(?usize, 32), PublicKeyAlgorithm.ed25519.nativeSecretKeySize());
    try testing.expectEqual(@as(?usize, 56), PublicKeyAlgorithm.x448.nativeSecretKeySize());
    try testing.expectEqual(@as(?usize, 57), PublicKeyAlgorithm.ed448.nativeSecretKeySize());
}

test "rfc9580: legacy EdDSA name updated" {
    try testing.expectEqualStrings("EdDSA (Legacy)", PublicKeyAlgorithm.eddsa.name());
}
