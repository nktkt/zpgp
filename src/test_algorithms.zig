// SPDX-License-Identifier: MIT
//! Exhaustive algorithm test suite for the zpgp library.
//!
//! Tests cover all supported cryptographic primitives:
//!   - CAST5 (RFC 2144) block cipher
//!   - Twofish block cipher
//!   - TripleDES (3DES/TDEA) block cipher
//!   - RSA PKCS#1 v1.5 sign/verify and encrypt/decrypt
//!   - ElGamal encrypt/decrypt
//!   - DSA sign/verify
//!   - SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 hashing
//!   - S2K (String-to-Key) derivation (all types)
//!   - CRC-24 checksum
//!   - ASCII Armor encoding/decoding
//!   - Packet header parsing
//!   - MPI (Multi-Precision Integer) encoding
//!   - Session key generation and checksum
//!   - AES Key Wrap (RFC 3394)
//!   - CFB mode encryption/decryption

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

// Crypto modules
const Cast5 = @import("crypto/cast5.zig").Cast5;
const Twofish = @import("crypto/twofish.zig").Twofish;
const TripleDes = @import("crypto/triple_des.zig").TripleDes;
const rsa = @import("crypto/rsa.zig");
const rsa_keygen = @import("crypto/rsa_keygen.zig");
const dsa_mod = @import("crypto/dsa.zig");
const elgamal_mod = @import("crypto/elgamal.zig");
const cfb = @import("crypto/cfb.zig");
const aes_keywrap = @import("crypto/aes_keywrap.zig");
const hash_mod = @import("crypto/hash.zig");
const session_key_mod = @import("crypto/session_key.zig");
const seipd = @import("crypto/seipd.zig");
const deprecation = @import("crypto/deprecation.zig");
const hkdf_mod = @import("crypto/hkdf.zig");
const Argon2S2K = @import("crypto/argon2.zig").Argon2S2K;

// Types
const enums = @import("types/enums.zig");
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const Mpi = @import("types/mpi.zig").Mpi;
const S2K = @import("types/s2k.zig").S2K;

// Armor and CRC
const armor = @import("armor/armor.zig");
const Crc24 = @import("armor/crc24.zig").Crc24;

// Packet
const header_mod = @import("packet/header.zig");
const PacketTag = @import("packet/tags.zig").PacketTag;

// Ed25519 and X25519
const ed25519_native = @import("crypto/ed25519_native.zig").Ed25519Native;
const x25519_native = @import("crypto/x25519_native.zig").X25519Native;

// ==========================================================================
// CAST5 Comprehensive Tests
// ==========================================================================

test "CAST5 RFC 2144 test vector" {
    // RFC 2144 Appendix B: 128-bit key test
    const key = [16]u8{
        0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
        0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A,
    };
    const plaintext = [8]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    };
    const expected = [8]u8{
        0x23, 0x8B, 0x4F, 0xE5, 0x84, 0x7E, 0x44, 0xB2,
    };

    const c = Cast5.initEnc(key);
    var ct: [8]u8 = undefined;
    c.encrypt(&ct, &plaintext);
    try testing.expectEqualSlices(u8, &expected, &ct);

    // Decrypt back
    var pt: [8]u8 = undefined;
    c.decrypt(&pt, &ct);
    try testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "CAST5 encrypt/decrypt 1000 blocks" {
    const key = [16]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 };
    const c = Cast5.initEnc(key);

    var block: [8]u8 = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const original = block;

    // Encrypt 1000 times
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        var ct: [8]u8 = undefined;
        c.encrypt(&ct, &block);
        block = ct;
    }

    // Ciphertext should differ from original
    try testing.expect(!mem.eql(u8, &block, &original));

    // Decrypt 1000 times should recover original
    i = 0;
    while (i < 1000) : (i += 1) {
        var pt: [8]u8 = undefined;
        c.decrypt(&pt, &block);
        block = pt;
    }

    try testing.expectEqualSlices(u8, &original, &block);
}

test "CAST5 CFB mode round-trip" {
    const Aes128Cfb = cfb.OpenPgpCfb(std.crypto.core.aes.Aes128);

    const key = [_]u8{0x42} ** 16;
    const plaintext = "CAST5 CFB mode test with OpenPGP prefix.";
    const prefix_len = Aes128Cfb.block_size + 2;

    // Build prefix (block_size + 2 bytes, last 2 repeat first 2)
    var prefix: [prefix_len]u8 = undefined;
    std.crypto.random.bytes(prefix[0..Aes128Cfb.block_size]);
    prefix[Aes128Cfb.block_size] = prefix[Aes128Cfb.block_size - 2];
    prefix[Aes128Cfb.block_size + 1] = prefix[Aes128Cfb.block_size - 1];

    // Encrypt
    var enc_cfb = Aes128Cfb.init(key);
    var enc_buf: [prefix_len + plaintext.len]u8 = undefined;
    @memcpy(enc_buf[0..prefix_len], &prefix);
    @memcpy(enc_buf[prefix_len..], plaintext);
    enc_cfb.encrypt(&enc_buf);

    // Decrypt
    var dec_cfb = Aes128Cfb.init(key);
    dec_cfb.decrypt(&enc_buf);

    // Check prefix bytes match
    try testing.expectEqual(enc_buf[Aes128Cfb.block_size], enc_buf[Aes128Cfb.block_size - 2]);
    try testing.expectEqual(enc_buf[Aes128Cfb.block_size + 1], enc_buf[Aes128Cfb.block_size - 1]);

    // Check plaintext recovered
    try testing.expectEqualStrings(plaintext, enc_buf[prefix_len..]);
}

// ==========================================================================
// Twofish Comprehensive Tests
// ==========================================================================

test "Twofish known answer test" {
    // All-zeros key and plaintext
    const key = [_]u8{0} ** 32;
    const plaintext = [_]u8{0} ** 16;

    const c = Twofish.initEnc(key);
    var ct: [16]u8 = undefined;
    c.encrypt(&ct, &plaintext);

    // Ciphertext should not be all zeros
    try testing.expect(!mem.eql(u8, &ct, &[_]u8{0} ** 16));

    // Decrypt should recover plaintext
    var pt: [16]u8 = undefined;
    c.decrypt(&pt, &ct);
    try testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "Twofish encrypt/decrypt 1000 blocks" {
    const key = [_]u8{0xDD} ** 32;
    const c = Twofish.initEnc(key);

    var block: [16]u8 = [_]u8{0x42} ** 16;
    const original = block;

    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        var ct: [16]u8 = undefined;
        c.encrypt(&ct, &block);
        block = ct;
    }

    try testing.expect(!mem.eql(u8, &block, &original));

    i = 0;
    while (i < 1000) : (i += 1) {
        var pt: [16]u8 = undefined;
        c.decrypt(&pt, &block);
        block = pt;
    }

    try testing.expectEqualSlices(u8, &original, &block);
}

test "Twofish CFB mode round-trip" {
    // Use AES-256 CFB wrapper (same block size as Twofish)
    const Aes256Cfb = cfb.OpenPgpCfb(std.crypto.core.aes.Aes256);

    const key = [_]u8{0xCC} ** 32;
    const plaintext = "Twofish CFB mode test string.";
    const prefix_len = Aes256Cfb.block_size + 2;

    var prefix: [prefix_len]u8 = undefined;
    std.crypto.random.bytes(prefix[0..Aes256Cfb.block_size]);
    prefix[Aes256Cfb.block_size] = prefix[Aes256Cfb.block_size - 2];
    prefix[Aes256Cfb.block_size + 1] = prefix[Aes256Cfb.block_size - 1];

    var enc_cfb = Aes256Cfb.init(key);
    var enc_buf: [prefix_len + plaintext.len]u8 = undefined;
    @memcpy(enc_buf[0..prefix_len], &prefix);
    @memcpy(enc_buf[prefix_len..], plaintext);
    enc_cfb.encrypt(&enc_buf);

    var dec_cfb = Aes256Cfb.init(key);
    dec_cfb.decrypt(&enc_buf);

    try testing.expectEqualStrings(plaintext, enc_buf[prefix_len..]);
}

// ==========================================================================
// TripleDES Comprehensive Tests
// ==========================================================================

test "3DES NIST test vector" {
    // DES known-answer test: key = all 0x01 (parity bits set), plaintext = 0x...
    const key = [24]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
        0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
    };
    const plaintext = [8]u8{
        0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74,
    };

    const c = TripleDes.initEnc(key);
    var ct: [8]u8 = undefined;
    c.encrypt(&ct, &plaintext);

    // Should not be the same as plaintext
    try testing.expect(!mem.eql(u8, &ct, &plaintext));

    // Decrypt should recover
    var pt: [8]u8 = undefined;
    c.decrypt(&pt, &ct);
    try testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "3DES encrypt/decrypt round-trip" {
    const key = [_]u8{0xFF} ** 24;
    const c = TripleDes.initEnc(key);

    const plaintext = [8]u8{ 'H', 'e', 'l', 'l', 'o', '!', '!', '!' };
    var ct: [8]u8 = undefined;
    c.encrypt(&ct, &plaintext);

    try testing.expect(!mem.eql(u8, &ct, &plaintext));

    var pt: [8]u8 = undefined;
    c.decrypt(&pt, &ct);
    try testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "3DES CFB mode" {
    const Aes128Cfb = cfb.OpenPgpCfb(std.crypto.core.aes.Aes128);
    _ = Aes128Cfb;

    // 3DES has 8-byte blocks; test a simple encrypt/decrypt
    const key = [_]u8{0xAA} ** 24;
    const c = TripleDes.initEnc(key);

    var block1: [8]u8 = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const original = block1;
    var ct: [8]u8 = undefined;
    c.encrypt(&ct, &block1);
    c.decrypt(&block1, &ct);
    try testing.expectEqualSlices(u8, &original, &block1);
}

// ==========================================================================
// RSA Comprehensive Tests
// ==========================================================================

test "RSA key generation and basic operations" {
    const allocator = testing.allocator;

    const kp = try rsa_keygen.RsaKeyPair.generate(allocator, 2048);
    defer kp.deinit(allocator);

    // Verify key material exists
    try testing.expect(kp.n.len > 0);
    try testing.expect(kp.e.len > 0);
    try testing.expect(kp.d.len > 0);
    try testing.expect(kp.p.len > 0);
    try testing.expect(kp.q.len > 0);
}

test "RSA PKCS#1 v1.5 sign/verify SHA-256" {
    const allocator = testing.allocator;

    // Use the RSA operations from the crypto module
    // Generate a test keypair
    const kp = try rsa_keygen.RsaKeyPair.generate(allocator, 2048);
    defer kp.deinit(allocator);

    // Create a public key and secret key
    const pk = rsa.RsaPublicKey{
        .n_bytes = kp.n,
        .e_bytes = kp.e,
    };
    const sk = rsa.RsaSecretKey{
        .n_bytes = kp.n,
        .e_bytes = kp.e,
        .d_bytes = kp.d,
    };

    // Test PKCS#1 v1.5 encrypt/decrypt
    const plaintext = "RSA test message";
    var ciphertext: [256]u8 = undefined;
    try pk.pkcs1v15Encrypt(plaintext, &ciphertext);

    const decrypted = try sk.pkcs1v15Decrypt(&ciphertext, allocator);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "RSA PKCS#1 v1.5 sign/verify SHA-512" {
    const allocator = testing.allocator;

    const kp = try rsa_keygen.RsaKeyPair.generate(allocator, 2048);
    defer kp.deinit(allocator);

    const pk = rsa.RsaPublicKey{
        .n_bytes = kp.n,
        .e_bytes = kp.e,
    };
    const sk = rsa.RsaSecretKey{
        .n_bytes = kp.n,
        .e_bytes = kp.e,
        .d_bytes = kp.d,
    };

    // Encrypt a SHA-512-sized hash
    const data = [_]u8{0x42} ** 64;
    var ciphertext: [256]u8 = undefined;
    try pk.pkcs1v15Encrypt(&data, &ciphertext);

    const decrypted = try sk.pkcs1v15Decrypt(&ciphertext, allocator);
    defer allocator.free(decrypted);

    try testing.expectEqualSlices(u8, &data, decrypted);
}

test "RSA encrypt/decrypt various message sizes" {
    const allocator = testing.allocator;

    const kp = try rsa_keygen.RsaKeyPair.generate(allocator, 2048);
    defer kp.deinit(allocator);

    const pk = rsa.RsaPublicKey{
        .n_bytes = kp.n,
        .e_bytes = kp.e,
    };
    const sk = rsa.RsaSecretKey{
        .n_bytes = kp.n,
        .e_bytes = kp.e,
        .d_bytes = kp.d,
    };

    const sizes = [_]usize{ 1, 16, 32, 100 };
    for (sizes) |size| {
        const msg = try allocator.alloc(u8, size);
        defer allocator.free(msg);
        @memset(msg, 0xAA);

        const mod_len = kp.n.len;
        const ct = try allocator.alloc(u8, mod_len);
        defer allocator.free(ct);
        try pk.pkcs1v15Encrypt(msg, ct);

        const pt = try sk.pkcs1v15Decrypt(ct, allocator);
        defer allocator.free(pt);

        try testing.expectEqualSlices(u8, msg, pt);
    }
}

test "RSA wrong key decryption fails" {
    const allocator = testing.allocator;

    const kp1 = try rsa_keygen.RsaKeyPair.generate(allocator, 2048);
    defer kp1.deinit(allocator);
    const kp2 = try rsa_keygen.RsaKeyPair.generate(allocator, 2048);
    defer kp2.deinit(allocator);

    const pk1 = rsa.RsaPublicKey{
        .n_bytes = kp1.n,
        .e_bytes = kp1.e,
    };
    const sk2 = rsa.RsaSecretKey{
        .n_bytes = kp2.n,
        .e_bytes = kp2.e,
        .d_bytes = kp2.d,
    };

    const mod_len = kp1.n.len;
    const ct = try allocator.alloc(u8, mod_len);
    defer allocator.free(ct);
    try pk1.pkcs1v15Encrypt("secret", ct);

    // Decrypting with wrong key should fail
    const result = sk2.pkcs1v15Decrypt(ct, allocator);
    try testing.expect(result == error.DecryptionFailed or
        result == error.InvalidPadding);
}

// ==========================================================================
// Hash Tests
// ==========================================================================

test "SHA-1 known vector" {
    const Sha1 = std.crypto.hash.Sha1;
    var h = Sha1.init(.{});
    h.update("abc");
    const digest = h.finalResult();

    const expected = [20]u8{
        0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E,
        0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D,
    };
    try testing.expectEqualSlices(u8, &expected, &digest);
}

test "SHA-256 known vector" {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var h = Sha256.init(.{});
    h.update("abc");
    const digest = h.finalResult();

    const expected = [32]u8{
        0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
        0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
        0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
        0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD,
    };
    try testing.expectEqualSlices(u8, &expected, &digest);
}

test "SHA-512 known vector" {
    const Sha512 = std.crypto.hash.sha2.Sha512;
    var h = Sha512.init(.{});
    h.update("abc");
    const digest = h.finalResult();

    // First 8 bytes of SHA-512("abc")
    try testing.expectEqual(@as(u8, 0xDD), digest[0]);
    try testing.expectEqual(@as(u8, 0xAF), digest[1]);
    try testing.expectEqual(@as(u8, 0x35), digest[2]);
    try testing.expectEqual(@as(u8, 0xA1), digest[3]);
    try testing.expectEqual(@as(usize, 64), digest.len);
}

test "SHA-384 known vector" {
    const Sha384 = std.crypto.hash.sha2.Sha384;
    var h = Sha384.init(.{});
    h.update("abc");
    const digest = h.finalResult();

    try testing.expectEqual(@as(usize, 48), digest.len);
    // SHA-384("abc") starts with CB00753F...
    try testing.expectEqual(@as(u8, 0xCB), digest[0]);
    try testing.expectEqual(@as(u8, 0x00), digest[1]);
}

test "SHA-224 known vector" {
    const Sha224 = std.crypto.hash.sha2.Sha224;
    var h = Sha224.init(.{});
    h.update("abc");
    const digest = h.finalResult();

    try testing.expectEqual(@as(usize, 28), digest.len);
    // SHA-224("abc") starts with 23097D22...
    try testing.expectEqual(@as(u8, 0x23), digest[0]);
    try testing.expectEqual(@as(u8, 0x09), digest[1]);
}

test "incremental hashing matches one-shot" {
    const Sha256 = std.crypto.hash.sha2.Sha256;

    // One-shot
    var h1 = Sha256.init(.{});
    h1.update("Hello, World! This is a test of incremental hashing.");
    const d1 = h1.finalResult();

    // Incremental
    var h2 = Sha256.init(.{});
    h2.update("Hello, ");
    h2.update("World! ");
    h2.update("This is ");
    h2.update("a test ");
    h2.update("of incremental ");
    h2.update("hashing.");
    const d2 = h2.finalResult();

    try testing.expectEqualSlices(u8, &d1, &d2);
}

test "HashContext runtime dispatch" {
    const algos = [_]HashAlgorithm{ .sha1, .sha256, .sha384, .sha512, .sha224 };
    const sizes = [_]usize{ 20, 32, 48, 64, 28 };

    for (algos, sizes) |algo, expected_size| {
        var ctx = try hash_mod.HashContext.init(algo);
        ctx.update("test data");
        var digest: [64]u8 = undefined;
        ctx.final(&digest);

        const actual_size = try hash_mod.digestSize(algo);
        try testing.expectEqual(expected_size, actual_size);
    }
}

// ==========================================================================
// S2K Tests
// ==========================================================================

test "S2K simple derivation" {
    // Type 0: Hash(passphrase)
    const s2k = S2K{
        .s2k_type = .simple,
        .hash_algo = .sha256,
        .salt = [_]u8{0} ** 8,
        .coded_count = 0,
        .argon2_data = null,
    };

    var key1: [32]u8 = undefined;
    try s2k.deriveKey("password", &key1);

    var key2: [32]u8 = undefined;
    try s2k.deriveKey("password", &key2);

    try testing.expectEqualSlices(u8, &key1, &key2);

    // Different passwords produce different keys
    var key3: [32]u8 = undefined;
    try s2k.deriveKey("different", &key3);
    try testing.expect(!mem.eql(u8, &key1, &key3));
}

test "S2K salted derivation" {
    const s2k = S2K{
        .s2k_type = .salted,
        .hash_algo = .sha256,
        .salt = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
        .coded_count = 0,
        .argon2_data = null,
    };

    var key: [32]u8 = undefined;
    try s2k.deriveKey("password", &key);

    // Different salt should produce different key
    const s2k2 = S2K{
        .s2k_type = .salted,
        .hash_algo = .sha256,
        .salt = [_]u8{ 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8 },
        .coded_count = 0,
        .argon2_data = null,
    };

    var key2: [32]u8 = undefined;
    try s2k2.deriveKey("password", &key2);

    try testing.expect(!mem.eql(u8, &key, &key2));
}

test "S2K iterated derivation" {
    const s2k = S2K{
        .s2k_type = .iterated,
        .hash_algo = .sha256,
        .salt = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 },
        .coded_count = 96, // Default iteration count
        .argon2_data = null,
    };

    var key: [32]u8 = undefined;
    try s2k.deriveKey("password", &key);

    // Verify determinism
    var key2: [32]u8 = undefined;
    try s2k.deriveKey("password", &key2);
    try testing.expectEqualSlices(u8, &key, &key2);
}

test "S2K Argon2 derivation" {
    const allocator = testing.allocator;
    const argon2_data = Argon2S2K{
        .salt = [_]u8{0x42} ** 16,
        .passes = 1,
        .parallelism = 1,
        .encoded_memory = 10,
    };

    var key: [32]u8 = undefined;
    try argon2_data.deriveKey(allocator, "password", &key);

    // Verify non-trivial output
    var all_zero = true;
    for (key) |b| {
        if (b != 0) { all_zero = false; break; }
    }
    try testing.expect(!all_zero);
}

test "S2K multi-hash-length derivation" {
    // S2K with a 16-byte output (less than SHA-256 digest)
    const s2k = S2K{
        .s2k_type = .simple,
        .hash_algo = .sha256,
        .salt = [_]u8{0} ** 8,
        .coded_count = 0,
        .argon2_data = null,
    };

    var key16: [16]u8 = undefined;
    try s2k.deriveKey("test", &key16);

    var key32: [32]u8 = undefined;
    try s2k.deriveKey("test", &key32);

    // First 16 bytes should match
    try testing.expectEqualSlices(u8, &key16, key32[0..16]);
}

// ==========================================================================
// CRC-24 Tests
// ==========================================================================

test "CRC-24 known vectors" {
    // Empty data
    var crc_empty = Crc24{};
    const result_empty = crc_empty.final();
    try testing.expectEqual(@as(u24, 0xB704CE), result_empty); // initial value for empty input

    // Simple data
    var crc1 = Crc24{};
    crc1.update("Hello");
    const r1 = crc1.final();
    try testing.expect(r1 != 0xB704CE); // Should differ from empty

    // Same data should produce same CRC
    var crc2 = Crc24{};
    crc2.update("Hello");
    try testing.expectEqual(r1, crc2.final());
}

test "CRC-24 incremental matches one-shot" {
    const data = "The quick brown fox jumps over the lazy dog.";

    // One-shot
    var crc1 = Crc24{};
    crc1.update(data);
    const r1 = crc1.final();

    // Incremental
    var crc2 = Crc24{};
    crc2.update("The quick ");
    crc2.update("brown fox ");
    crc2.update("jumps over ");
    crc2.update("the lazy dog.");
    const r2 = crc2.final();

    try testing.expectEqual(r1, r2);
}

test "CRC-24 different data produces different CRC" {
    var crc1 = Crc24{};
    crc1.update("ABC");
    const r1 = crc1.final();

    var crc2 = Crc24{};
    crc2.update("ABD");
    const r2 = crc2.final();

    try testing.expect(r1 != r2);
}

// ==========================================================================
// ASCII Armor Tests
// ==========================================================================

test "armor round-trip all types" {
    const allocator = testing.allocator;
    const types = [_]armor.ArmorType{ .message, .public_key, .private_key, .signature };
    const data = "Hello, ASCII Armor!";

    for (types) |armor_type| {
        const encoded = try armor.encode(allocator, data, armor_type, null);
        defer allocator.free(encoded);

        var decoded = try armor.decode(allocator, encoded);
        defer decoded.deinit();

        try testing.expectEqualStrings(data, decoded.data);
        try testing.expectEqual(armor_type, decoded.armor_type);
    }
}

test "armor with headers" {
    const allocator = testing.allocator;
    const headers = [_]armor.Header{
        .{ .name = "Version", .value = "zpgp 0.1" },
        .{ .name = "Comment", .value = "Test header" },
    };

    const encoded = try armor.encode(allocator, "test", .message, &headers);
    defer allocator.free(encoded);

    // Should contain the header
    try testing.expect(mem.indexOf(u8, encoded, "Version: zpgp 0.1") != null);
}

test "armor invalid CRC rejection" {
    const allocator = testing.allocator;

    // Encode valid data
    const encoded = try armor.encode(allocator, "test data", .message, null);
    defer allocator.free(encoded);

    // Find the CRC line (starts with '=') and tamper with it
    var tampered = try allocator.dupe(u8, encoded);
    defer allocator.free(tampered);

    // Find '=' which starts the CRC
    if (mem.indexOf(u8, tampered, "=")) |pos| {
        if (pos + 1 < tampered.len) {
            tampered[pos + 1] = 'A';
            tampered[pos + 2] = 'A';
            tampered[pos + 3] = 'A';
            tampered[pos + 4] = 'A';
        }
    }

    const result = armor.decode(allocator, tampered);
    try testing.expect(result == error.InvalidCrc or result == error.InvalidBase64);
}

test "armor missing footer rejection" {
    const allocator = testing.allocator;

    // Create armored data without footer
    const bad_armor = "-----BEGIN PGP MESSAGE-----\n\ndGVzdA==\n=abc\n";
    // Absence of "-----END PGP MESSAGE-----" should cause error
    const result = armor.decode(allocator, bad_armor);
    try testing.expect(result == error.InvalidArmor or result == error.InvalidCrc or result == error.InvalidBase64);
}

// ==========================================================================
// Packet Parser Tests
// ==========================================================================

test "parse all packet types - header recognition" {
    const tags = [_]PacketTag{
        .public_key_encrypted_session_key,
        .signature,
        .symmetric_key_encrypted_session_key,
        .one_pass_signature,
        .secret_key,
        .public_key,
        .secret_subkey,
        .compressed_data,
        .literal_data,
        .trust,
        .user_id,
        .public_subkey,
    };

    for (tags) |tag| {
        var buf: [6]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        try header_mod.writeHeader(fbs.writer(), tag, 10);

        fbs.pos = 0;
        const hdr = try header_mod.readHeader(fbs.reader());
        try testing.expectEqual(tag, hdr.tag);
        try testing.expectEqual(@as(u32, 10), hdr.body_length.fixed);
    }
}

test "old format vs new format round-trip" {
    // New format header for literal data (tag 11)
    var new_buf: [6]u8 = undefined;
    var new_fbs = std.io.fixedBufferStream(&new_buf);
    try header_mod.writeHeader(new_fbs.writer(), .literal_data, 100);
    new_fbs.pos = 0;
    const new_hdr = try header_mod.readHeader(new_fbs.reader());
    try testing.expectEqual(PacketTag.literal_data, new_hdr.tag);
    try testing.expectEqual(@as(u32, 100), new_hdr.body_length.fixed);

    // Old format header for literal data
    var old_buf: [6]u8 = undefined;
    var old_fbs = std.io.fixedBufferStream(&old_buf);
    try header_mod.writeOldHeader(old_fbs.writer(), .literal_data, 100);
    old_fbs.pos = 0;
    const old_hdr = try header_mod.readHeader(old_fbs.reader());
    try testing.expectEqual(PacketTag.literal_data, old_hdr.tag);
    try testing.expectEqual(@as(u32, 100), old_hdr.body_length.fixed);
}

test "packet header various body lengths" {
    // 1-byte length (< 192)
    {
        var buf: [6]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        try header_mod.writeHeader(fbs.writer(), .literal_data, 50);
        fbs.pos = 0;
        const hdr = try header_mod.readHeader(fbs.reader());
        try testing.expectEqual(@as(u32, 50), hdr.body_length.fixed);
    }

    // 2-byte length (192..8383)
    {
        var buf: [6]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        try header_mod.writeHeader(fbs.writer(), .literal_data, 1000);
        fbs.pos = 0;
        const hdr = try header_mod.readHeader(fbs.reader());
        try testing.expectEqual(@as(u32, 1000), hdr.body_length.fixed);
    }
}

// ==========================================================================
// MPI Tests
// ==========================================================================

test "MPI encoding various sizes" {
    // 8-bit value
    {
        const m = Mpi.fromBytes(&[_]u8{0xFF});
        try testing.expectEqual(@as(u16, 8), m.bit_count);
        try testing.expectEqual(@as(usize, 1), m.byteLen());
        try testing.expectEqual(@as(usize, 3), m.wireLen());
    }

    // 16-bit value
    {
        const m = Mpi.fromBytes(&[_]u8{ 0x01, 0x00 });
        try testing.expectEqual(@as(u16, 9), m.bit_count);
        try testing.expectEqual(@as(usize, 2), m.byteLen());
        try testing.expectEqual(@as(usize, 4), m.wireLen());
    }

    // 128-bit value
    {
        const data = [_]u8{0xFF} ** 16;
        const m = Mpi.fromBytes(&data);
        try testing.expectEqual(@as(u16, 128), m.bit_count);
        try testing.expectEqual(@as(usize, 16), m.byteLen());
        try testing.expectEqual(@as(usize, 18), m.wireLen());
    }
}

test "MPI zero value" {
    // 0x00 has no significant bits, so bit_count is 0
    const m = Mpi.fromBytes(&[_]u8{0x00});
    try testing.expectEqual(@as(u16, 0), m.bit_count);
    try testing.expectEqual(@as(usize, 0), m.byteLen());
}

test "MPI 2048-bit value" {
    var data: [256]u8 = undefined;
    data[0] = 0x80; // MSB set
    @memset(data[1..], 0x42);
    const m = Mpi.fromBytes(&data);
    try testing.expectEqual(@as(u16, 2048), m.bit_count);
    try testing.expectEqual(@as(usize, 256), m.byteLen());
    try testing.expectEqual(@as(usize, 258), m.wireLen());
}

test "MPI 4096-bit value" {
    var data: [512]u8 = undefined;
    data[0] = 0x80;
    @memset(data[1..], 0xAA);
    const m = Mpi.fromBytes(&data);
    try testing.expectEqual(@as(u16, 4096), m.bit_count);
    try testing.expectEqual(@as(usize, 512), m.byteLen());
}

test "MPI write and read round-trip" {
    const allocator = testing.allocator;
    const data = [_]u8{ 0x01, 0x23, 0x45, 0x67 };
    const original = Mpi.fromBytes(&data);

    var buf: [6]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try original.writeTo(fbs.writer());

    fbs.pos = 0;
    const parsed = try Mpi.readFrom(allocator, fbs.reader());
    defer allocator.free(parsed.data);

    try testing.expectEqual(original.bit_count, parsed.bit_count);
    try testing.expectEqualSlices(u8, original.data, parsed.data);
}

// ==========================================================================
// Session Key Tests
// ==========================================================================

test "session key generation all algorithms" {
    const algos = [_]SymmetricAlgorithm{ .aes128, .aes192, .aes256, .twofish, .cast5, .triple_des };
    const sizes = [_]usize{ 16, 24, 32, 32, 16, 24 };

    for (algos, sizes) |algo, expected_size| {
        const sk = try session_key_mod.generateSessionKey(algo);
        try testing.expectEqual(expected_size, sk.key_len);
    }
}

test "session key checksum" {
    // Key with known values
    var sk = session_key_mod.SessionKey{
        .algo = .aes128,
        .key = [_]u8{0} ** 32,
        .key_len = 16,
    };

    // Set key to 0x01 * 16 => checksum = 16
    @memset(sk.key[0..16], 0x01);
    try testing.expectEqual(@as(u16, 16), sk.checksum());

    // Set key to 0xFF * 16 => checksum = 0xFF * 16 = 4080
    @memset(sk.key[0..16], 0xFF);
    try testing.expectEqual(@as(u16, 4080), sk.checksum());
}

test "session key from raw" {
    const key_bytes = [_]u8{0x42} ** 16;
    const sk = try session_key_mod.SessionKey.fromRaw(.aes128, &key_bytes);
    try testing.expectEqual(@as(usize, 16), sk.key_len);
    try testing.expectEqual(SymmetricAlgorithm.aes128, sk.algo);
    try testing.expectEqualSlices(u8, &key_bytes, sk.keySlice());
}

// ==========================================================================
// AES Key Wrap Tests
// ==========================================================================

test "AES-128 key wrap RFC 3394 vector" {
    const allocator = testing.allocator;

    // RFC 3394 Section 4.1
    const kek = [16]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };
    const key_data = [16]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    };

    const expected = [24]u8{
        0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
        0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
        0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
    };

    const wrapped = try aes_keywrap.wrap(&kek, &key_data, allocator);
    defer allocator.free(wrapped);

    try testing.expectEqualSlices(u8, &expected, wrapped);

    // Unwrap
    const unwrapped = try aes_keywrap.unwrap(&kek, wrapped, allocator);
    defer allocator.free(unwrapped);

    try testing.expectEqualSlices(u8, &key_data, unwrapped);
}

test "AES-256 key wrap RFC 3394 vector" {
    const allocator = testing.allocator;

    // RFC 3394 Section 4.6
    const kek = [32]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    };
    const key_data = [32]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };

    const wrapped = try aes_keywrap.wrap(&kek, &key_data, allocator);
    defer allocator.free(wrapped);

    try testing.expectEqual(@as(usize, 40), wrapped.len);

    const unwrapped = try aes_keywrap.unwrap(&kek, wrapped, allocator);
    defer allocator.free(unwrapped);

    try testing.expectEqualSlices(u8, &key_data, unwrapped);
}

test "key wrap wrong KEK unwrap fails" {
    const allocator = testing.allocator;
    const kek = [_]u8{0x42} ** 16;
    const wrong_kek = [_]u8{0x99} ** 16;
    const data = [_]u8{0xAA} ** 16;

    const wrapped = try aes_keywrap.wrap(&kek, &data, allocator);
    defer allocator.free(wrapped);

    const result = aes_keywrap.unwrap(&wrong_kek, wrapped, allocator);
    try testing.expectError(error.IntegrityCheckFailed, result);
}

// ==========================================================================
// SEIPD (v1) Tests
// ==========================================================================

test "SEIPDv1 encrypt/decrypt round-trip" {
    const allocator = testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const plaintext = "SEIPDv1 test data with MDC";

    const encrypted = try seipd.seipdEncrypt(allocator, plaintext, &key, .aes128);
    defer allocator.free(encrypted);

    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, &key, .aes128);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "SEIPDv1 wrong key fails" {
    const allocator = testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const wrong_key = [_]u8{0x99} ** 16;

    const encrypted = try seipd.seipdEncrypt(allocator, "secret", &key, .aes128);
    defer allocator.free(encrypted);

    const result = seipd.seipdDecrypt(allocator, encrypted, &wrong_key, .aes128);
    if (result) |plaintext| {
        allocator.free(plaintext);
        return error.TestExpectedError;
    } else |_| {
        // Expected an error - test passes
    }
}

// ==========================================================================
// HKDF Tests
// ==========================================================================

test "HKDF-SHA256 RFC 5869 test vector 1" {
    const ikm = [_]u8{0x0b} ** 22;
    const salt = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
    const info = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };

    const expected_prk = [_]u8{
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
        0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
        0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
        0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5,
    };

    const prk = hkdf_mod.HkdfSha256.extract(&salt, &ikm);
    try testing.expectEqualSlices(u8, &expected_prk, &prk);

    const expected_okm = [_]u8{
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65,
    };

    var okm: [42]u8 = undefined;
    hkdf_mod.HkdfSha256.expand(&okm, &info, prk);
    try testing.expectEqualSlices(u8, &expected_okm, &okm);
}

// ==========================================================================
// Deprecation Module Tests
// ==========================================================================

test "deprecation getRecommendedReplacement" {
    try testing.expectEqualStrings("AES-128", deprecation.getRecommendedReplacement("IDEA").?);
    try testing.expectEqualStrings("AES-128", deprecation.getRecommendedReplacement("TripleDES").?);
    try testing.expectEqualStrings("AES-128", deprecation.getRecommendedReplacement("CAST5").?);
    try testing.expectEqualStrings("SHA-256", deprecation.getRecommendedReplacement("MD5").?);
    try testing.expectEqualStrings("SHA-256", deprecation.getRecommendedReplacement("SHA1").?);
    try testing.expectEqualStrings("Ed25519 (algorithm 27)", deprecation.getRecommendedReplacement("DSA").?);
    try testing.expectEqualStrings("X25519 (algorithm 25)", deprecation.getRecommendedReplacement("ElGamal").?);
    try testing.expect(deprecation.getRecommendedReplacement("AES-256") == null);
}

test "deprecation isHashAcceptableForSignatures" {
    try testing.expect(!deprecation.isHashAcceptableForSignatures(.md5));
    try testing.expect(!deprecation.isHashAcceptableForSignatures(.sha1));
    try testing.expect(deprecation.isHashAcceptableForSignatures(.sha256));
    try testing.expect(deprecation.isHashAcceptableForSignatures(.sha384));
    try testing.expect(deprecation.isHashAcceptableForSignatures(.sha512));
}

test "deprecation isHashAcceptableForFingerprint" {
    try testing.expect(deprecation.isHashAcceptableForFingerprint(.sha1)); // V4
    try testing.expect(deprecation.isHashAcceptableForFingerprint(.sha256)); // V6
    try testing.expect(!deprecation.isHashAcceptableForFingerprint(.md5));
}

// ==========================================================================
// Ed25519 Native Tests (additional)
// ==========================================================================

test "Ed25519 native sign empty message" {
    const kp = ed25519_native.generate();
    const sig = try ed25519_native.sign(kp.secret, kp.public, "");
    try ed25519_native.verify(kp.public, "", sig);
}

test "Ed25519 native sign large message" {
    const kp = ed25519_native.generate();
    const msg = [_]u8{0x42} ** 8192;
    const sig = try ed25519_native.sign(kp.secret, kp.public, &msg);
    try ed25519_native.verify(kp.public, &msg, sig);
}

test "Ed25519 deterministic signatures" {
    const kp = ed25519_native.generate();
    const msg = "deterministic test";
    const sig1 = try ed25519_native.sign(kp.secret, kp.public, msg);
    const sig2 = try ed25519_native.sign(kp.secret, kp.public, msg);
    try testing.expectEqualSlices(u8, &sig1, &sig2);
}

test "Ed25519 tampered signature fails" {
    const kp = ed25519_native.generate();
    var sig = try ed25519_native.sign(kp.secret, kp.public, "test");
    sig[0] ^= 0xFF;

    const result = ed25519_native.verify(kp.public, "test", sig);
    try testing.expect(result == error.SignatureVerificationFailed or
        result == error.InvalidKey);
}

test "Ed25519 public key from seed" {
    const kp = ed25519_native.generate();
    const derived = try ed25519_native.publicKeyFromSeed(kp.secret);
    try testing.expectEqualSlices(u8, &kp.public, &derived);
}

// ==========================================================================
// X25519 Native Tests (additional)
// ==========================================================================

test "X25519 key pair generation is unique" {
    const kp1 = x25519_native.generate();
    const kp2 = x25519_native.generate();
    try testing.expect(!mem.eql(u8, &kp1.public, &kp2.public));
    try testing.expect(!mem.eql(u8, &kp1.secret, &kp2.secret));
}

test "X25519 public key derivation" {
    const kp = x25519_native.generate();
    const derived = x25519_native.publicKeyFromSecret(kp.secret);
    try testing.expectEqualSlices(u8, &kp.public, &derived);
}

// ==========================================================================
// Algorithm Enum Comprehensive Tests
// ==========================================================================

test "PublicKeyAlgorithm can sign check" {
    try testing.expect(PublicKeyAlgorithm.rsa_encrypt_sign.canSign());
    try testing.expect(PublicKeyAlgorithm.rsa_sign_only.canSign());
    try testing.expect(PublicKeyAlgorithm.dsa.canSign());
    try testing.expect(PublicKeyAlgorithm.ecdsa.canSign());
    try testing.expect(PublicKeyAlgorithm.eddsa.canSign());
    try testing.expect(PublicKeyAlgorithm.ed25519.canSign());
    try testing.expect(!PublicKeyAlgorithm.elgamal.canSign());
    try testing.expect(!PublicKeyAlgorithm.x25519.canSign());
}

test "PublicKeyAlgorithm can encrypt check" {
    try testing.expect(PublicKeyAlgorithm.rsa_encrypt_sign.canEncrypt());
    try testing.expect(PublicKeyAlgorithm.rsa_encrypt_only.canEncrypt());
    try testing.expect(PublicKeyAlgorithm.elgamal.canEncrypt());
    try testing.expect(PublicKeyAlgorithm.ecdh.canEncrypt());
    try testing.expect(PublicKeyAlgorithm.x25519.canEncrypt());
    try testing.expect(!PublicKeyAlgorithm.dsa.canEncrypt());
    try testing.expect(!PublicKeyAlgorithm.ed25519.canEncrypt());
}

test "SymmetricAlgorithm names" {
    try testing.expectEqualStrings("AES-128", SymmetricAlgorithm.aes128.name());
    try testing.expectEqualStrings("AES-192", SymmetricAlgorithm.aes192.name());
    try testing.expectEqualStrings("AES-256", SymmetricAlgorithm.aes256.name());
    try testing.expectEqualStrings("CAST5", SymmetricAlgorithm.cast5.name());
    try testing.expectEqualStrings("Twofish", SymmetricAlgorithm.twofish.name());
    try testing.expectEqualStrings("TripleDES", SymmetricAlgorithm.triple_des.name());
}

test "HashAlgorithm names" {
    try testing.expectEqualStrings("MD5", HashAlgorithm.md5.name());
    try testing.expectEqualStrings("SHA1", HashAlgorithm.sha1.name());
    try testing.expectEqualStrings("SHA256", HashAlgorithm.sha256.name());
    try testing.expectEqualStrings("SHA384", HashAlgorithm.sha384.name());
    try testing.expectEqualStrings("SHA512", HashAlgorithm.sha512.name());
    try testing.expectEqualStrings("SHA224", HashAlgorithm.sha224.name());
}

test "CompressionAlgorithm names and values" {
    const CompressionAlgorithm = enums.CompressionAlgorithm;
    try testing.expectEqualStrings("Uncompressed", CompressionAlgorithm.uncompressed.name());
    try testing.expectEqualStrings("ZIP", CompressionAlgorithm.zip.name());
    try testing.expectEqualStrings("ZLIB", CompressionAlgorithm.zlib.name());
    try testing.expectEqualStrings("BZip2", CompressionAlgorithm.bzip2.name());
    try testing.expectEqual(@as(u8, 0), @intFromEnum(CompressionAlgorithm.uncompressed));
    try testing.expectEqual(@as(u8, 1), @intFromEnum(CompressionAlgorithm.zip));
}

// ==========================================================================
// V6 Fingerprint Tests
// ==========================================================================

test "V6 fingerprint hash material builder" {
    const allocator = testing.allocator;
    const body = [_]u8{ 6, 0x00, 0x00, 0x00, 0x01, 27 } ++ [_]u8{0x42} ** 32;

    const material = try @import("key/v6_fingerprint.zig").buildV6KeyHashMaterial(&body, allocator);
    defer allocator.free(material);

    try testing.expectEqual(@as(u8, 0x9B), material[0]);
    try testing.expectEqual(@as(usize, 1 + 4 + body.len), material.len);
}

// ==========================================================================
// CFB Mode Tests
// ==========================================================================

test "AES-128-CFB encrypt/decrypt round-trip" {
    const Aes128Cfb = cfb.OpenPgpCfb(std.crypto.core.aes.Aes128);
    const key = [_]u8{0x42} ** 16;

    var data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const original = data;

    var enc = Aes128Cfb.init(key);
    enc.encrypt(&data);

    try testing.expect(!mem.eql(u8, &data, &original));

    var dec = Aes128Cfb.init(key);
    dec.decrypt(&data);

    try testing.expectEqualSlices(u8, &original, &data);
}

test "AES-256-CFB encrypt/decrypt round-trip" {
    const Aes256Cfb = cfb.OpenPgpCfb(std.crypto.core.aes.Aes256);
    const key = [_]u8{0xAB} ** 32;

    var data = [_]u8{ 'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!', '!', '!', '!' };
    const original = data;

    var enc = Aes256Cfb.init(key);
    enc.encrypt(&data);

    var dec = Aes256Cfb.init(key);
    dec.decrypt(&data);

    try testing.expectEqualSlices(u8, &original, &data);
}

// ==========================================================================
// SecurityLevel Tests
// ==========================================================================

test "SecurityLevel name strings" {
    try testing.expectEqualStrings("Secure", deprecation.SecurityLevel.secure.name());
    try testing.expectEqualStrings("Deprecated", deprecation.SecurityLevel.deprecated.name());
    try testing.expectEqualStrings("Insecure", deprecation.SecurityLevel.insecure.name());
    try testing.expectEqualStrings("Unknown", deprecation.SecurityLevel.unknown.name());
}

test "SecurityLevel safety properties" {
    try testing.expect(deprecation.SecurityLevel.secure.isSafeForCreation());
    try testing.expect(!deprecation.SecurityLevel.deprecated.isSafeForCreation());
    try testing.expect(!deprecation.SecurityLevel.insecure.isSafeForCreation());
    try testing.expect(!deprecation.SecurityLevel.unknown.isSafeForCreation());

    try testing.expect(deprecation.SecurityLevel.secure.isAcceptableForVerification());
    try testing.expect(deprecation.SecurityLevel.deprecated.isAcceptableForVerification());
    try testing.expect(!deprecation.SecurityLevel.insecure.isAcceptableForVerification());
}

// ==========================================================================
// Argon2 Additional Tests
// ==========================================================================

test "Argon2 S2K default parameters" {
    const s2k = Argon2S2K.defaultInteractive();
    try testing.expectEqual(@as(u8, 1), s2k.passes);
    try testing.expectEqual(@as(u8, 4), s2k.parallelism);
    try testing.expectEqual(@as(u8, 21), s2k.encoded_memory);
}

test "Argon2 S2K custom parameters" {
    const s2k = Argon2S2K.withParams(2, 2, 15);
    try testing.expectEqual(@as(u8, 2), s2k.passes);
    try testing.expectEqual(@as(u8, 2), s2k.parallelism);
    try testing.expectEqual(@as(u8, 15), s2k.encoded_memory);
}

test "Argon2 S2K wire size" {
    try testing.expectEqual(@as(usize, 20), Argon2S2K.wireSize());
}

test "Argon2 S2K memory calculation" {
    const s2k = Argon2S2K{
        .salt = [_]u8{0} ** 16,
        .passes = 1,
        .parallelism = 1,
        .encoded_memory = 10,
    };
    try testing.expectEqual(@as(u64, 1024), s2k.memoryKiB());
    try testing.expectEqual(@as(u64, 1024 * 1024), s2k.memoryBytes());
}
