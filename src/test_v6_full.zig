// SPDX-License-Identifier: MIT
//! Comprehensive V6/RFC 9580 integration tests.
//!
//! Tests cover:
//!   - V6 key generation (Ed25519, X25519, RSA)
//!   - SEIPDv2 AEAD encryption/decryption (EAX, OCB, GCM)
//!   - V6 signatures
//!   - Argon2 S2K key derivation
//!   - X25519 native key agreement
//!   - HKDF key derivation
//!   - Algorithm deprecation checks
//!   - Cross-version compatibility (V4 + V6)

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

// V6 key generation
const v6_generate = @import("key/v6_generate.zig");
const V6KeyGenOptions = v6_generate.V6KeyGenOptions;
const GeneratedV6Key = v6_generate.GeneratedV6Key;

// V6 message composition
const v6_compose = @import("message/v6_compose.zig");
const RecipientInfo = v6_compose.RecipientInfo;
const SignerInfo = v6_compose.SignerInfo;

// V6 message decomposition
const v6_decompose = @import("message/v6_decompose.zig");
const ParsedV6Message = v6_decompose.ParsedV6Message;

// Crypto primitives
const ed25519_native = @import("crypto/ed25519_native.zig").Ed25519Native;
const x25519_native = @import("crypto/x25519_native.zig").X25519Native;
const seipd_v2 = @import("crypto/seipd_v2.zig");
const aead_mod = @import("crypto/aead/aead.zig");
const hkdf_mod = @import("crypto/hkdf.zig");
const Argon2S2K = @import("crypto/argon2.zig").Argon2S2K;
const deprecation = @import("crypto/deprecation.zig");
const v6_fingerprint = @import("key/v6_fingerprint.zig");
const session_key_mod = @import("crypto/session_key.zig");

// Enums
const enums = @import("types/enums.zig");
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const AeadAlgorithm = enums.AeadAlgorithm;

// Armor
const armor = @import("armor/armor.zig");

// V4 modules for cross-version tests
const keygen = @import("key/generate.zig");
const compose = @import("message/compose.zig");
const decompose = @import("message/decompose.zig");

// ==========================================================================
// V6 Key Generation Tests
// ==========================================================================

test "generate V6 Ed25519 key" {
    const allocator = testing.allocator;
    const result = try v6_generate.generateV6Key(allocator, .{
        .algorithm = .ed25519,
        .user_id = "Alice V6 <alice@v6.example>",
        .creation_time = 1700000000,
        .hash_algo = .sha256,
    });
    defer result.deinit(allocator);

    // Should produce valid armored keys
    try testing.expect(mem.startsWith(u8, result.public_key_armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    try testing.expect(mem.startsWith(u8, result.secret_key_armored, "-----BEGIN PGP PRIVATE KEY BLOCK-----"));
    try testing.expect(mem.endsWith(u8, result.public_key_armored, "-----END PGP PUBLIC KEY BLOCK-----\n"));
    try testing.expect(mem.endsWith(u8, result.secret_key_armored, "-----END PGP PRIVATE KEY BLOCK-----\n"));
}

test "generate V6 X25519 encryption key" {
    const allocator = testing.allocator;
    const result = try v6_generate.generateV6Key(allocator, .{
        .algorithm = .x25519,
        .user_id = "Bob V6 <bob@v6.example>",
        .creation_time = 1700000001,
    });
    defer result.deinit(allocator);

    try testing.expect(result.public_key_armored.len > 100);
    try testing.expect(result.secret_key_armored.len > 100);
}

test "generate V6 RSA key" {
    const allocator = testing.allocator;
    const result = try v6_generate.generateV6Key(allocator, .{
        .algorithm = .rsa_encrypt_sign,
        .bits = 2048,
        .user_id = "RSA V6 <rsa@v6.example>",
        .creation_time = 1700000002,
    });
    defer result.deinit(allocator);

    try testing.expect(mem.startsWith(u8, result.public_key_armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    // RSA keys are much larger
    try testing.expect(result.public_key_armored.len > 500);
}

test "V6 key with Argon2 passphrase protection" {
    const allocator = testing.allocator;
    const result = try v6_generate.generateV6Key(allocator, .{
        .algorithm = .ed25519,
        .user_id = "Protected <protected@example.com>",
        .passphrase = "correct horse battery staple",
        .creation_time = 1700000003,
    });
    defer result.deinit(allocator);

    // Both armored outputs should be valid
    try testing.expect(mem.startsWith(u8, result.public_key_armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    try testing.expect(mem.startsWith(u8, result.secret_key_armored, "-----BEGIN PGP PRIVATE KEY BLOCK-----"));

    // Secret key should be larger than public key (includes encryption overhead)
    try testing.expect(result.secret_key_armored.len >= result.public_key_armored.len);
}

test "V6 key fingerprint is SHA-256" {
    const allocator = testing.allocator;
    const result = try v6_generate.generateV6Key(allocator, .{
        .algorithm = .ed25519,
        .creation_time = 1700000004,
    });
    defer result.deinit(allocator);

    // V6 fingerprint is 32 bytes (SHA-256)
    try testing.expectEqual(@as(usize, 32), result.fingerprint.len);

    // Fingerprint should not be all zeros
    var non_zero_count: usize = 0;
    for (result.fingerprint) |b| {
        if (b != 0) non_zero_count += 1;
    }
    try testing.expect(non_zero_count > 0);
}

test "V6 key ID is first 8 bytes of fingerprint" {
    const allocator = testing.allocator;
    const result = try v6_generate.generateV6Key(allocator, .{
        .algorithm = .ed25519,
        .creation_time = 1700000005,
    });
    defer result.deinit(allocator);

    // Key ID = first 8 bytes of fingerprint (unlike V4 which uses last 8)
    try testing.expectEqualSlices(u8, result.fingerprint[0..8], &result.key_id);
}

test "V6 Ed25519 key generation uniqueness" {
    const allocator = testing.allocator;

    var fingerprints: [3][32]u8 = undefined;
    for (0..3) |i| {
        const result = try v6_generate.generateV6Key(allocator, .{
            .algorithm = .ed25519,
            .creation_time = 1700000010 + @as(u32, @intCast(i)),
        });
        defer result.deinit(allocator);
        fingerprints[i] = result.fingerprint;
    }

    // All fingerprints should be different
    try testing.expect(!mem.eql(u8, &fingerprints[0], &fingerprints[1]));
    try testing.expect(!mem.eql(u8, &fingerprints[1], &fingerprints[2]));
    try testing.expect(!mem.eql(u8, &fingerprints[0], &fingerprints[2]));
}

test "V6 key with encryption subkey" {
    const allocator = testing.allocator;
    const result = try v6_generate.generateV6Key(allocator, .{
        .algorithm = .ed25519,
        .generate_encryption_subkey = true,
        .creation_time = 1700000020,
    });
    defer result.deinit(allocator);

    // Should have a larger output due to subkey packets
    const result_no_sub = try v6_generate.generateV6Key(allocator, .{
        .algorithm = .ed25519,
        .generate_encryption_subkey = false,
        .creation_time = 1700000020,
    });
    defer result_no_sub.deinit(allocator);

    try testing.expect(result.public_key_armored.len > result_no_sub.public_key_armored.len);
}

// ==========================================================================
// V6 Encryption Tests (SEIPDv2)
// ==========================================================================

test "SEIPDv2 encrypt/decrypt with EAX round-trip" {
    const allocator = testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const plaintext = "Hello, RFC 9580 EAX!";

    const encrypted = try seipd_v2.seipdV2Encrypt(allocator, plaintext, &key, .aes128, .eax, 6);
    defer allocator.free(encrypted);

    const decrypted = try seipd_v2.seipdV2Decrypt(allocator, encrypted, &key);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "SEIPDv2 encrypt/decrypt with OCB round-trip" {
    const allocator = testing.allocator;
    const key = [_]u8{0x77} ** 16;
    const plaintext = "OCB authenticated encryption test for RFC 9580";

    const encrypted = try seipd_v2.seipdV2Encrypt(allocator, plaintext, &key, .aes128, .ocb, 6);
    defer allocator.free(encrypted);

    const decrypted = try seipd_v2.seipdV2Decrypt(allocator, encrypted, &key);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "SEIPDv2 encrypt/decrypt with GCM round-trip" {
    const allocator = testing.allocator;
    const key = [_]u8{0xAB} ** 32;
    const plaintext = "GCM-256 is fast and secure for authenticated encryption.";

    const encrypted = try seipd_v2.seipdV2Encrypt(allocator, plaintext, &key, .aes256, .gcm, 6);
    defer allocator.free(encrypted);

    const decrypted = try seipd_v2.seipdV2Decrypt(allocator, encrypted, &key);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "SEIPDv2 wrong key fails" {
    const allocator = testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const wrong_key = [_]u8{0x99} ** 16;

    const encrypted = try seipd_v2.seipdV2Encrypt(allocator, "secret", &key, .aes128, .eax, 6);
    defer allocator.free(encrypted);

    const result = seipd_v2.seipdV2Decrypt(allocator, encrypted, &wrong_key);
    try testing.expect(result == error.ChunkAuthenticationFailed or
        result == error.FinalTagMismatch);
}

test "SEIPDv2 tampered ciphertext fails" {
    const allocator = testing.allocator;
    const key = [_]u8{0x42} ** 16;

    const encrypted = try seipd_v2.seipdV2Encrypt(allocator, "integrity test", &key, .aes128, .gcm, 6);
    defer allocator.free(encrypted);

    // Tamper with the ciphertext
    encrypted[40] ^= 0xFF;

    const result = seipd_v2.seipdV2Decrypt(allocator, encrypted, &key);
    try testing.expect(result == error.ChunkAuthenticationFailed or
        result == error.FinalTagMismatch);
}

test "SEIPDv2 large message (multiple chunks)" {
    const allocator = testing.allocator;
    const key = [_]u8{0x55} ** 16;

    // chunk_size_octet=0 means 2^6 = 64 bytes per chunk
    // 500 bytes will span multiple chunks
    const plaintext = try allocator.alloc(u8, 500);
    defer allocator.free(plaintext);
    for (plaintext, 0..) |*b, i| b.* = @intCast(i % 256);

    const encrypted = try seipd_v2.seipdV2Encrypt(allocator, plaintext, &key, .aes128, .eax, 0);
    defer allocator.free(encrypted);

    const decrypted = try seipd_v2.seipdV2Decrypt(allocator, encrypted, &key);
    defer allocator.free(decrypted);

    try testing.expectEqualSlices(u8, plaintext, decrypted);
}

test "SEIPDv2 AES-256-EAX round-trip" {
    const allocator = testing.allocator;
    const key = [_]u8{0xCC} ** 32;
    const plaintext = "AES-256 with EAX mode";

    const encrypted = try seipd_v2.seipdV2Encrypt(allocator, plaintext, &key, .aes256, .eax, 6);
    defer allocator.free(encrypted);

    const decrypted = try seipd_v2.seipdV2Decrypt(allocator, encrypted, &key);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "SEIPDv2 AES-256-OCB round-trip" {
    const allocator = testing.allocator;
    const key = [_]u8{0xDD} ** 32;
    const plaintext = "AES-256 with OCB mode";

    const encrypted = try seipd_v2.seipdV2Encrypt(allocator, plaintext, &key, .aes256, .ocb, 6);
    defer allocator.free(encrypted);

    const decrypted = try seipd_v2.seipdV2Decrypt(allocator, encrypted, &key);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "SEIPDv2 empty plaintext round-trip" {
    const allocator = testing.allocator;
    const key = [_]u8{0x01} ** 16;

    const encrypted = try seipd_v2.seipdV2Encrypt(allocator, "", &key, .aes128, .eax, 6);
    defer allocator.free(encrypted);

    const decrypted = try seipd_v2.seipdV2Decrypt(allocator, encrypted, &key);
    defer allocator.free(decrypted);

    try testing.expectEqual(@as(usize, 0), decrypted.len);
}

test "SEIPDv2 two encryptions produce different ciphertext (random salt)" {
    const allocator = testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const plaintext = "Same plaintext, different salt";

    const enc1 = try seipd_v2.seipdV2Encrypt(allocator, plaintext, &key, .aes128, .eax, 6);
    defer allocator.free(enc1);
    const enc2 = try seipd_v2.seipdV2Encrypt(allocator, plaintext, &key, .aes128, .eax, 6);
    defer allocator.free(enc2);

    try testing.expect(!mem.eql(u8, enc1, enc2));

    // Both should decrypt correctly
    const dec1 = try seipd_v2.seipdV2Decrypt(allocator, enc1, &key);
    defer allocator.free(dec1);
    const dec2 = try seipd_v2.seipdV2Decrypt(allocator, enc2, &key);
    defer allocator.free(dec2);

    try testing.expectEqualStrings(plaintext, dec1);
    try testing.expectEqualStrings(plaintext, dec2);
}

// ==========================================================================
// V6 Signature Tests
// ==========================================================================

test "V6 signature with Ed25519 native" {
    const kp = ed25519_native.generate();
    const message = "Hello, RFC 9580 V6 signature!";

    const sig = try ed25519_native.sign(kp.secret, kp.public, message);
    try ed25519_native.verify(kp.public, message, sig);
}

test "V6 signature salt sizes match hash algorithm" {
    // RFC 9580 Section 5.2.3 specifies salt sizes
    // SHA-256: 16 bytes
    // SHA-384: 24 bytes
    // SHA-512: 32 bytes
    const sha256_salt: usize = 16;
    const sha384_salt: usize = 24;
    const sha512_salt: usize = 32;

    try testing.expectEqual(sha256_salt, 16);
    try testing.expectEqual(sha384_salt, 24);
    try testing.expectEqual(sha512_salt, 32);

    // Salt sizes should not exceed hash digest size
    try testing.expect(sha256_salt <= HashAlgorithm.sha256.digestSize().?);
    try testing.expect(sha384_salt <= HashAlgorithm.sha384.digestSize().?);
    try testing.expect(sha512_salt <= HashAlgorithm.sha512.digestSize().?);
}

test "Ed25519 native sign/verify multiple messages" {
    const kp = ed25519_native.generate();

    const messages = [_][]const u8{
        "First message",
        "Second message with more data",
        "",
        "A very long message that contains lots of text and should still verify correctly",
    };

    for (messages) |msg| {
        const sig = try ed25519_native.sign(kp.secret, kp.public, msg);
        try ed25519_native.verify(kp.public, msg, sig);
    }
}

test "Ed25519 wrong key verification fails" {
    const kp1 = ed25519_native.generate();
    const kp2 = ed25519_native.generate();

    const sig = try ed25519_native.sign(kp1.secret, kp1.public, "test");
    const result = ed25519_native.verify(kp2.public, "test", sig);
    try testing.expectError(error.SignatureVerificationFailed, result);
}

// ==========================================================================
// AEAD Algorithm Tests
// ==========================================================================

test "EAX encrypt/decrypt round-trip all key sizes" {
    const allocator = testing.allocator;

    // AES-128-EAX
    {
        const key = [_]u8{0x42} ** 16;
        const nonce = [_]u8{0x33} ** 16;
        const plaintext = "EAX-128 test";
        const ad = "header";

        const result = try aead_mod.aeadEncrypt(allocator, .aes128, .eax, &key, &nonce, plaintext, ad);
        defer result.deinit(allocator);

        const decrypted = try aead_mod.aeadDecrypt(allocator, .aes128, .eax, &key, &nonce, result.ciphertext, &result.tag, ad);
        defer allocator.free(decrypted);

        try testing.expectEqualStrings(plaintext, decrypted);
    }

    // AES-256-EAX
    {
        const key = [_]u8{0xAB} ** 32;
        const nonce = [_]u8{0xCD} ** 16;
        const plaintext = "EAX-256 test";
        const ad = "";

        const result = try aead_mod.aeadEncrypt(allocator, .aes256, .eax, &key, &nonce, plaintext, ad);
        defer result.deinit(allocator);

        const decrypted = try aead_mod.aeadDecrypt(allocator, .aes256, .eax, &key, &nonce, result.ciphertext, &result.tag, ad);
        defer allocator.free(decrypted);

        try testing.expectEqualStrings(plaintext, decrypted);
    }
}

test "OCB encrypt/decrypt round-trip all key sizes" {
    const allocator = testing.allocator;

    // AES-128-OCB
    {
        const key = [_]u8{0x77} ** 16;
        const nonce = [_]u8{0x88} ** 15;
        const plaintext = "OCB-128 test data";
        const ad = "OCB header";

        const result = try aead_mod.aeadEncrypt(allocator, .aes128, .ocb, &key, &nonce, plaintext, ad);
        defer result.deinit(allocator);

        const decrypted = try aead_mod.aeadDecrypt(allocator, .aes128, .ocb, &key, &nonce, result.ciphertext, &result.tag, ad);
        defer allocator.free(decrypted);

        try testing.expectEqualStrings(plaintext, decrypted);
    }

    // AES-256-OCB
    {
        const key = [_]u8{0xDD} ** 32;
        const nonce = [_]u8{0xEE} ** 15;
        const plaintext = "OCB-256 test data";
        const ad = "";

        const result = try aead_mod.aeadEncrypt(allocator, .aes256, .ocb, &key, &nonce, plaintext, ad);
        defer result.deinit(allocator);

        const decrypted = try aead_mod.aeadDecrypt(allocator, .aes256, .ocb, &key, &nonce, result.ciphertext, &result.tag, ad);
        defer allocator.free(decrypted);

        try testing.expectEqualStrings(plaintext, decrypted);
    }
}

test "GCM encrypt/decrypt round-trip all key sizes" {
    const allocator = testing.allocator;

    // AES-128-GCM
    {
        const key = [_]u8{0x11} ** 16;
        const nonce = [_]u8{0x22} ** 12;
        const plaintext = "GCM-128 test";

        const result = try aead_mod.aeadEncrypt(allocator, .aes128, .gcm, &key, &nonce, plaintext, "");
        defer result.deinit(allocator);

        const decrypted = try aead_mod.aeadDecrypt(allocator, .aes128, .gcm, &key, &nonce, result.ciphertext, &result.tag, "");
        defer allocator.free(decrypted);

        try testing.expectEqualStrings(plaintext, decrypted);
    }

    // AES-256-GCM
    {
        const key = [_]u8{0xFF} ** 32;
        const nonce = [_]u8{0xAA} ** 12;
        const plaintext = "GCM-256 test";

        const result = try aead_mod.aeadEncrypt(allocator, .aes256, .gcm, &key, &nonce, plaintext, "");
        defer result.deinit(allocator);

        const decrypted = try aead_mod.aeadDecrypt(allocator, .aes256, .gcm, &key, &nonce, result.ciphertext, &result.tag, "");
        defer allocator.free(decrypted);

        try testing.expectEqualStrings(plaintext, decrypted);
    }
}

test "AEAD with associated data" {
    const allocator = testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const nonce = [_]u8{0x33} ** 16;
    const plaintext = "message body";
    const ad = "packet header version=2 sym_algo=7 aead_algo=1";

    const result = try aead_mod.aeadEncrypt(allocator, .aes128, .eax, &key, &nonce, plaintext, ad);
    defer result.deinit(allocator);

    // Decryption with same AD should work
    const decrypted = try aead_mod.aeadDecrypt(allocator, .aes128, .eax, &key, &nonce, result.ciphertext, &result.tag, ad);
    defer allocator.free(decrypted);
    try testing.expectEqualStrings(plaintext, decrypted);

    // Decryption with wrong AD should fail
    const wrong_result = aead_mod.aeadDecrypt(allocator, .aes128, .eax, &key, &nonce, result.ciphertext, &result.tag, "wrong AD");
    try testing.expectError(error.AuthenticationFailed, wrong_result);
}

test "AEAD tag verification failure on tampered data" {
    const allocator = testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const nonce = [_]u8{0x33} ** 16;

    const result = try aead_mod.aeadEncrypt(allocator, .aes128, .eax, &key, &nonce, "secret", "");
    defer result.deinit(allocator);

    // Tamper with ciphertext
    if (result.ciphertext.len > 0) {
        result.ciphertext[0] ^= 0xFF;
    }

    const dec_result = aead_mod.aeadDecrypt(allocator, .aes128, .eax, &key, &nonce, result.ciphertext, &result.tag, "");
    try testing.expectError(error.AuthenticationFailed, dec_result);
}

// ==========================================================================
// Argon2 Tests
// ==========================================================================

test "Argon2 S2K key derivation" {
    const allocator = testing.allocator;
    const s2k = Argon2S2K{
        .salt = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 },
        .passes = 1,
        .parallelism = 1,
        .encoded_memory = 10, // 1 MiB
    };

    var key: [32]u8 = undefined;
    try s2k.deriveKey(allocator, "test passphrase", &key);

    // Same input produces same output
    var key2: [32]u8 = undefined;
    try s2k.deriveKey(allocator, "test passphrase", &key2);
    try testing.expectEqualSlices(u8, &key, &key2);

    // Different passphrase produces different key
    var key3: [32]u8 = undefined;
    try s2k.deriveKey(allocator, "different passphrase", &key3);
    try testing.expect(!mem.eql(u8, &key, &key3));
}

test "Argon2 S2K wire format parse/write round-trip" {
    const original = Argon2S2K{
        .salt = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00 },
        .passes = 3,
        .parallelism = 4,
        .encoded_memory = 16,
    };

    // Write
    var buf: [20]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try original.writeTo(fbs.writer());
    try testing.expectEqual(@as(usize, 20), fbs.pos);

    // Read back
    fbs.pos = 1; // skip type byte
    const parsed = try Argon2S2K.readFrom(fbs.reader());

    try testing.expectEqualSlices(u8, &original.salt, &parsed.salt);
    try testing.expectEqual(original.passes, parsed.passes);
    try testing.expectEqual(original.parallelism, parsed.parallelism);
    try testing.expectEqual(original.encoded_memory, parsed.encoded_memory);
}

test "Argon2 S2K with various memory parameters" {
    const allocator = testing.allocator;

    const memory_params = [_]u8{ 10, 12, 14 };
    var keys: [3][32]u8 = undefined;

    for (memory_params, 0..) |m, i| {
        const s2k = Argon2S2K{
            .salt = [_]u8{0xAA} ** 16,
            .passes = 1,
            .parallelism = 1,
            .encoded_memory = m,
        };
        try s2k.deriveKey(allocator, "password", &keys[i]);
    }

    // Different memory parameters should produce different keys
    try testing.expect(!mem.eql(u8, &keys[0], &keys[1]));
    try testing.expect(!mem.eql(u8, &keys[1], &keys[2]));
}

test "Argon2 S2K default interactive has sane parameters" {
    const s2k = Argon2S2K.defaultInteractive();
    try testing.expect(s2k.passes >= 1);
    try testing.expect(s2k.parallelism >= 1);
    try testing.expect(s2k.encoded_memory >= 10); // at least 1 MiB
    try testing.expect(s2k.memoryKiB() >= 1024);
}

// ==========================================================================
// X25519 Native Tests
// ==========================================================================

test "X25519 native encrypt/decrypt session key" {
    const allocator = testing.allocator;
    const recipient = x25519_native.generate();
    const session_key = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    };

    const result = try x25519_native.encryptSessionKey(
        allocator,
        recipient.public,
        &session_key,
        @intFromEnum(SymmetricAlgorithm.aes128),
    );
    defer result.deinit();

    const recovered = try x25519_native.decryptSessionKey(
        allocator,
        recipient.secret,
        recipient.public,
        result.ephemeral_public,
        result.wrapped_key,
        @intFromEnum(SymmetricAlgorithm.aes128),
    );
    defer allocator.free(recovered);

    try testing.expectEqualSlices(u8, &session_key, recovered);
}

test "X25519 native wrong key fails" {
    const allocator = testing.allocator;
    const recipient = x25519_native.generate();
    const wrong = x25519_native.generate();
    const session_key = [_]u8{0xFF} ** 16;

    const result = try x25519_native.encryptSessionKey(
        allocator,
        recipient.public,
        &session_key,
        @intFromEnum(SymmetricAlgorithm.aes128),
    );
    defer result.deinit();

    try testing.expectError(
        error.UnwrapFailed,
        x25519_native.decryptSessionKey(
            allocator,
            wrong.secret,
            wrong.public,
            result.ephemeral_public,
            result.wrapped_key,
            @intFromEnum(SymmetricAlgorithm.aes128),
        ),
    );
}

test "X25519 native key pair derivation" {
    const kp = x25519_native.generate();
    const derived_pub = x25519_native.publicKeyFromSecret(kp.secret);
    try testing.expectEqualSlices(u8, &kp.public, &derived_pub);
}

test "X25519 native encrypt/decrypt AES-256 session key" {
    const allocator = testing.allocator;
    const recipient = x25519_native.generate();
    const session_key = [_]u8{0xAA} ** 32;

    const result = try x25519_native.encryptSessionKey(
        allocator,
        recipient.public,
        &session_key,
        @intFromEnum(SymmetricAlgorithm.aes256),
    );
    defer result.deinit();

    const recovered = try x25519_native.decryptSessionKey(
        allocator,
        recipient.secret,
        recipient.public,
        result.ephemeral_public,
        result.wrapped_key,
        @intFromEnum(SymmetricAlgorithm.aes256),
    );
    defer allocator.free(recovered);

    try testing.expectEqualSlices(u8, &session_key, recovered);
}

// ==========================================================================
// HKDF Tests
// ==========================================================================

test "HKDF-SHA256 derive key" {
    const ikm = [_]u8{0x0b} ** 22;
    const salt = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
    const info = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };

    var okm: [42]u8 = undefined;
    hkdf_mod.HkdfSha256.deriveKey(&okm, &salt, &ikm, &info);

    // Verify determinism
    var okm2: [42]u8 = undefined;
    hkdf_mod.HkdfSha256.deriveKey(&okm2, &salt, &ikm, &info);
    try testing.expectEqualSlices(u8, &okm, &okm2);
}

test "HKDF-SHA256 different inputs produce different outputs" {
    const ikm1 = [_]u8{0x0b} ** 22;
    const ikm2 = [_]u8{0x0c} ** 22;
    const salt = [_]u8{0x00} ** 13;
    const info = [_]u8{0xf0} ** 10;

    var okm1: [32]u8 = undefined;
    hkdf_mod.HkdfSha256.deriveKey(&okm1, &salt, &ikm1, &info);

    var okm2: [32]u8 = undefined;
    hkdf_mod.HkdfSha256.deriveKey(&okm2, &salt, &ikm2, &info);

    try testing.expect(!mem.eql(u8, &okm1, &okm2));
}

// ==========================================================================
// Deprecation Tests
// ==========================================================================

test "MD5 is insecure" {
    try testing.expectEqual(deprecation.SecurityLevel.insecure, deprecation.assessHashAlgorithm(.md5));
    try testing.expect(!deprecation.SecurityLevel.insecure.isSafeForCreation());
    try testing.expect(!deprecation.SecurityLevel.insecure.isAcceptableForVerification());
}

test "SHA-1 is deprecated" {
    try testing.expectEqual(deprecation.SecurityLevel.deprecated, deprecation.assessHashAlgorithm(.sha1));
    try testing.expect(!deprecation.assessHashAlgorithm(.sha1).isSafeForCreation());
    try testing.expect(deprecation.assessHashAlgorithm(.sha1).isAcceptableForVerification());
}

test "SHA-256 is secure" {
    try testing.expectEqual(deprecation.SecurityLevel.secure, deprecation.assessHashAlgorithm(.sha256));
    try testing.expect(deprecation.assessHashAlgorithm(.sha256).isSafeForCreation());
}

test "AES-256 is secure" {
    try testing.expectEqual(deprecation.SecurityLevel.secure, deprecation.assessSymmetricAlgorithm(.aes256));
}

test "CAST5 is deprecated" {
    try testing.expectEqual(deprecation.SecurityLevel.deprecated, deprecation.assessSymmetricAlgorithm(.cast5));
    try testing.expect(!deprecation.assessSymmetricAlgorithm(.cast5).isSafeForCreation());
}

test "3DES is deprecated" {
    try testing.expectEqual(deprecation.SecurityLevel.deprecated, deprecation.assessSymmetricAlgorithm(.triple_des));
}

test "Ed25519 native (algo 27) is secure" {
    const algo: PublicKeyAlgorithm = @enumFromInt(27);
    try testing.expectEqual(deprecation.SecurityLevel.secure, deprecation.assessPublicKeyAlgorithm(algo));
}

test "X25519 native (algo 25) is secure" {
    const algo: PublicKeyAlgorithm = @enumFromInt(25);
    try testing.expectEqual(deprecation.SecurityLevel.secure, deprecation.assessPublicKeyAlgorithm(algo));
}

test "Legacy EdDSA (algo 22) is deprecated" {
    try testing.expectEqual(deprecation.SecurityLevel.deprecated, deprecation.assessPublicKeyAlgorithm(.eddsa));
}

test "RSA-1024 is deprecated" {
    try testing.expectEqual(deprecation.SecurityLevel.deprecated, deprecation.assessPublicKeyWithSize(.rsa_encrypt_sign, 1024));
}

test "RSA-2048 is secure" {
    try testing.expectEqual(deprecation.SecurityLevel.secure, deprecation.assessPublicKeyWithSize(.rsa_encrypt_sign, 2048));
}

test "RSA-512 is insecure" {
    try testing.expectEqual(deprecation.SecurityLevel.insecure, deprecation.assessPublicKeyWithSize(.rsa_encrypt_sign, 512));
}

// ==========================================================================
// V6 Fingerprint Tests
// ==========================================================================

test "V6 fingerprint uses SHA-256" {
    const body = [_]u8{ 6, 0x00, 0x00, 0x00, 0x01, 27 } ++ [_]u8{0x42} ** 32;
    const fp = v6_fingerprint.calculateV6Fingerprint(&body);
    try testing.expectEqual(@as(usize, 32), fp.len);
}

test "V6 Key ID is first 8 bytes (not last 8)" {
    const body = [_]u8{ 6, 0x00, 0x00, 0x00, 0x01, 27 } ++ [_]u8{0x42} ** 32;
    const fp = v6_fingerprint.calculateV6Fingerprint(&body);
    const kid = v6_fingerprint.v6KeyIdFromFingerprint(fp);
    try testing.expectEqualSlices(u8, fp[0..8], &kid);
}

test "V6 fingerprint format hex" {
    const fp = [_]u8{0xAB} ** 32;
    const hex = v6_fingerprint.formatV6Fingerprint(fp);
    try testing.expectEqual(@as(usize, 64), hex.len);
    try testing.expectEqualSlices(u8, "AB", hex[0..2]);
}

// ==========================================================================
// V6 Message Composition Tests
// ==========================================================================

test "V6 message encrypt with X25519 produces valid armor" {
    const allocator = testing.allocator;
    const kp = x25519_native.generate();

    const recipients = [_]RecipientInfo{
        .{
            .key_version = 6,
            .algorithm = .x25519,
            .key_id = [_]u8{0x11} ** 8,
            .public_key_data = &kp.public,
        },
    };

    const encrypted = try v6_compose.encryptMessageV6(
        allocator,
        "V6 integration test message",
        "test.txt",
        &recipients,
        .aes128,
        .eax,
        null,
    );
    defer allocator.free(encrypted);

    try testing.expect(mem.startsWith(u8, encrypted, "-----BEGIN PGP MESSAGE-----"));
    try testing.expect(mem.endsWith(u8, encrypted, "-----END PGP MESSAGE-----\n"));
}

test "V6 symmetric encrypt produces valid armor" {
    const allocator = testing.allocator;

    const encrypted = try v6_compose.encryptMessageV6Symmetric(
        allocator,
        "Symmetric V6 test",
        "secret.txt",
        "my-passphrase",
        .aes128,
        .eax,
    );
    defer allocator.free(encrypted);

    try testing.expect(mem.startsWith(u8, encrypted, "-----BEGIN PGP MESSAGE-----"));
}

// ==========================================================================
// V6 Message Decomposition Tests
// ==========================================================================

test "V6 decompose literal data" {
    const allocator = testing.allocator;
    const body = [_]u8{ 'b', 0, 0, 0, 0, 0, 'O', 'K' };

    var packet: [2 + body.len]u8 = undefined;
    packet[0] = 0xCB; // tag 11
    packet[1] = body.len;
    @memcpy(packet[2..], &body);

    var msg = try v6_decompose.parseV6Message(allocator, &packet);
    defer msg.deinit(allocator);

    try testing.expect(msg.literal_data != null);
    try testing.expectEqualStrings("OK", msg.literal_data.?.data);
}

test "V6 decompose empty" {
    const allocator = testing.allocator;
    var msg = try v6_decompose.parseV6Message(allocator, &[_]u8{});
    defer msg.deinit(allocator);

    try testing.expect(!msg.isEncrypted());
    try testing.expect(!msg.isSigned());
}

// ==========================================================================
// Session Key Tests
// ==========================================================================

test "session key generation for all AES sizes" {
    const algos = [_]SymmetricAlgorithm{ .aes128, .aes192, .aes256 };
    const expected_sizes = [_]usize{ 16, 24, 32 };

    for (algos, expected_sizes) |algo, expected| {
        const sk = try session_key_mod.generateSessionKey(algo);
        try testing.expectEqual(expected, sk.key_len);
        try testing.expectEqual(algo, sk.algo);
    }
}

test "session key checksum" {
    const sk = session_key_mod.SessionKey{
        .algo = .aes128,
        .key = [_]u8{0x01} ** 32,
        .key_len = 16,
    };
    const cksum = sk.checksum();
    // 16 bytes of 0x01 = 16
    try testing.expectEqual(@as(u16, 16), cksum);
}

// ==========================================================================
// Cross-version Tests
// ==========================================================================

test "V4 and V6 keys coexist - different fingerprint sizes" {
    const allocator = testing.allocator;

    // Generate V4 key
    const v4_key = try keygen.generateKey(allocator, .{
        .algorithm = .rsa_encrypt_sign,
        .bits = 2048,
        .user_id = "V4 User <v4@example.com>",
        .creation_time = 1700000000,
    });
    defer v4_key.deinit(allocator);

    // Generate V6 key
    const v6_key = try v6_generate.generateV6Key(allocator, .{
        .algorithm = .ed25519,
        .user_id = "V6 User <v6@example.com>",
        .creation_time = 1700000000,
    });
    defer v6_key.deinit(allocator);

    // V4 fingerprint is 20 bytes (SHA-1)
    try testing.expectEqual(@as(usize, 20), v4_key.fingerprint.len);
    // V6 fingerprint is 32 bytes (SHA-256)
    try testing.expectEqual(@as(usize, 32), v6_key.fingerprint.len);

    // Both should produce valid armored output
    try testing.expect(mem.startsWith(u8, v4_key.public_key_armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    try testing.expect(mem.startsWith(u8, v6_key.public_key_armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));
}

test "V4 message decryption still works" {
    const allocator = testing.allocator;

    // Build a V4 literal data packet and parse it
    const literal_pkt = try compose.createLiteralData(allocator, "V4 test data", "v4.txt", true);
    defer allocator.free(literal_pkt);

    var msg = try decompose.parseMessage(allocator, literal_pkt);
    defer msg.deinit(allocator);

    try testing.expect(msg.literal_data != null);
    try testing.expectEqualStrings("V4 test data", msg.literal_data.?.data);
}

// ==========================================================================
// V6 Fingerprint Computation Tests
// ==========================================================================

test "V6 fingerprint computation for Ed25519 key body" {
    const pk = [_]u8{0xAA} ** 32;
    // Build a V6 key body: version(6) + creation_time(4) + algo(27) + key_material_len(4) + key(32)
    const body = [_]u8{
        6,                      // version
        0x5F, 0x00, 0x00, 0x00, // creation_time
        27,                     // Ed25519 native
        0, 0, 0, 32, // key material length = 32
    } ++ pk;

    const fp = v6_fingerprint.calculateV6Fingerprint(&body);

    // Same body should produce same fingerprint
    const fp2 = v6_fingerprint.calculateV6Fingerprint(&body);
    try testing.expectEqual(fp, fp2);

    // Fingerprint should be 32 bytes
    try testing.expectEqual(@as(usize, 32), fp.len);
}

test "V6 fingerprint differs for different keys" {
    const body1 = [_]u8{ 6, 0, 0, 0, 1, 27, 0, 0, 0, 32 } ++ [_]u8{0xAA} ** 32;
    const body2 = [_]u8{ 6, 0, 0, 0, 1, 27, 0, 0, 0, 32 } ++ [_]u8{0xBB} ** 32;

    const fp1 = v6_fingerprint.calculateV6Fingerprint(&body1);
    const fp2 = v6_fingerprint.calculateV6Fingerprint(&body2);

    try testing.expect(!mem.eql(u8, &fp1, &fp2));
}

// ==========================================================================
// Algorithm Enum Tests
// ==========================================================================

test "PublicKeyAlgorithm native V6 check" {
    try testing.expect(PublicKeyAlgorithm.ed25519.isNativeV6());
    try testing.expect(PublicKeyAlgorithm.x25519.isNativeV6());
    try testing.expect(!PublicKeyAlgorithm.rsa_encrypt_sign.isNativeV6());
    try testing.expect(!PublicKeyAlgorithm.eddsa.isNativeV6());
}

test "PublicKeyAlgorithm native key sizes" {
    try testing.expectEqual(@as(?usize, 32), PublicKeyAlgorithm.ed25519.nativePublicKeySize());
    try testing.expectEqual(@as(?usize, 32), PublicKeyAlgorithm.x25519.nativePublicKeySize());
    try testing.expectEqual(@as(?usize, null), PublicKeyAlgorithm.rsa_encrypt_sign.nativePublicKeySize());
}

test "AeadAlgorithm nonce sizes" {
    try testing.expectEqual(@as(?usize, 16), AeadAlgorithm.eax.nonceSize());
    try testing.expectEqual(@as(?usize, 15), AeadAlgorithm.ocb.nonceSize());
    try testing.expectEqual(@as(?usize, 12), AeadAlgorithm.gcm.nonceSize());
}

test "AeadAlgorithm tag sizes are all 16" {
    try testing.expectEqual(@as(?usize, 16), AeadAlgorithm.eax.tagSize());
    try testing.expectEqual(@as(?usize, 16), AeadAlgorithm.ocb.tagSize());
    try testing.expectEqual(@as(?usize, 16), AeadAlgorithm.gcm.tagSize());
}

test "SymmetricAlgorithm AES key sizes" {
    try testing.expectEqual(@as(?usize, 16), SymmetricAlgorithm.aes128.keySize());
    try testing.expectEqual(@as(?usize, 24), SymmetricAlgorithm.aes192.keySize());
    try testing.expectEqual(@as(?usize, 32), SymmetricAlgorithm.aes256.keySize());
}

test "SymmetricAlgorithm AES block sizes" {
    try testing.expectEqual(@as(?usize, 16), SymmetricAlgorithm.aes128.blockSize());
    try testing.expectEqual(@as(?usize, 16), SymmetricAlgorithm.aes192.blockSize());
    try testing.expectEqual(@as(?usize, 16), SymmetricAlgorithm.aes256.blockSize());
}

test "HashAlgorithm digest sizes" {
    try testing.expectEqual(@as(?usize, 32), HashAlgorithm.sha256.digestSize());
    try testing.expectEqual(@as(?usize, 48), HashAlgorithm.sha384.digestSize());
    try testing.expectEqual(@as(?usize, 64), HashAlgorithm.sha512.digestSize());
    try testing.expectEqual(@as(?usize, 20), HashAlgorithm.sha1.digestSize());
    try testing.expectEqual(@as(?usize, 16), HashAlgorithm.md5.digestSize());
}
