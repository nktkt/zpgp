// SPDX-License-Identifier: MIT
//! Tests for AES-192 block cipher, CFB mode, SEIPD integration,
//! and passphrase-protected secret key decryption.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

const Aes192 = @import("crypto/aes192.zig").Aes192;
const cfb_mod = @import("crypto/cfb.zig");
const Aes192Cfb = cfb_mod.Aes192Cfb;
const seipd = @import("crypto/seipd.zig");
const secret_key_decrypt = @import("crypto/secret_key_decrypt.zig");

// ===========================================================================
// Section 1: NIST AES-192 test vectors (FIPS 197 Appendix C.2)
// ===========================================================================

test "NIST FIPS 197 C.2 - AES-192 encrypt" {
    const key: [24]u8 = .{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    };
    const plaintext: [16]u8 = .{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const expected_ct: [16]u8 = .{
        0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
        0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
    };

    const cipher = Aes192.initEnc(key);
    var ct: [16]u8 = undefined;
    cipher.encrypt(&ct, &plaintext);
    try testing.expectEqualSlices(u8, &expected_ct, &ct);
}

test "NIST FIPS 197 C.2 - AES-192 decrypt" {
    const key: [24]u8 = .{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    };
    const ciphertext: [16]u8 = .{
        0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
        0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
    };
    const expected_pt: [16]u8 = .{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };

    const cipher = Aes192.initEnc(key);
    var pt: [16]u8 = undefined;
    cipher.decrypt(&pt, &ciphertext);
    try testing.expectEqualSlices(u8, &expected_pt, &pt);
}

test "AES-192 encrypt/decrypt round-trip multiple patterns" {
    const keys = [_][24]u8{
        [_]u8{0x00} ** 24,
        [_]u8{0xFF} ** 24,
        [_]u8{0x42} ** 24,
        .{
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
            0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
            0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
        },
    };

    const blocks = [_][16]u8{
        [_]u8{0x00} ** 16,
        [_]u8{0xFF} ** 16,
        .{
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        },
    };

    for (keys) |key| {
        const cipher = Aes192.initEnc(key);
        for (blocks) |block| {
            var encrypted: [16]u8 = undefined;
            cipher.encrypt(&encrypted, &block);

            var decrypted: [16]u8 = undefined;
            cipher.decrypt(&decrypted, &encrypted);

            try testing.expectEqualSlices(u8, &block, &decrypted);
        }
    }
}

// ===========================================================================
// Section 2: AES-192 CFB encrypt/decrypt roundtrip
// ===========================================================================

test "AES-192 CFB non-resyncing encrypt/decrypt round-trip" {
    const key = [_]u8{0x42} ** 24;
    const plaintext = "Hello, OpenPGP AES-192-CFB mode! This is a longer message to test multiple blocks.";
    var buf: [plaintext.len]u8 = undefined;
    @memcpy(&buf, plaintext);

    var enc = Aes192Cfb.init(key);
    enc.encryptData(&buf);

    try testing.expect(!mem.eql(u8, &buf, plaintext));

    var dec = Aes192Cfb.init(key);
    dec.decrypt(&buf);

    try testing.expectEqualSlices(u8, plaintext, &buf);
}

test "AES-192 CFB resyncing encrypt/decrypt round-trip" {
    const key = [_]u8{0x77} ** 24;

    const bs = Aes192Cfb.block_size;
    const prefix = [_]u8{0xDE} ** bs ++ [_]u8{ 0xDE, 0xDE };
    const body = "AES-192 resyncing CFB test message for SED packets";
    const plaintext = prefix ++ body.*;
    var buf: [plaintext.len]u8 = undefined;
    @memcpy(&buf, &plaintext);

    var enc = Aes192Cfb.init(key);
    enc.encryptResync(&buf);

    try testing.expect(!mem.eql(u8, &buf, &plaintext));

    var dec = Aes192Cfb.init(key);
    dec.decryptResync(&buf);

    try testing.expectEqualSlices(u8, &plaintext, &buf);
}

test "AES-192 CFB incremental vs one-shot" {
    const key = [_]u8{0x55} ** 24;
    const plaintext = "Incremental vs one-shot AES-192 CFB test message!!!";

    // One-shot
    var buf1: [plaintext.len]u8 = undefined;
    @memcpy(&buf1, plaintext);
    var enc1 = Aes192Cfb.init(key);
    enc1.encryptData(&buf1);

    // Incremental (byte at a time)
    var buf2: [plaintext.len]u8 = undefined;
    @memcpy(&buf2, plaintext);
    var enc2 = Aes192Cfb.init(key);
    for (&buf2) |*byte| {
        enc2.encryptData(@as(*[1]u8, byte));
    }

    try testing.expectEqualSlices(u8, &buf1, &buf2);
}

test "AES-192 CFB block size is 16" {
    try testing.expectEqual(@as(usize, 16), Aes192Cfb.block_size);
}

// ===========================================================================
// Section 3: SEIPD encrypt/decrypt with AES-192
// ===========================================================================

test "SEIPD AES-192 encrypt/decrypt round-trip" {
    const allocator = testing.allocator;
    const key = [_]u8{0x42} ** 24;
    const plaintext = "Hello, SEIPD v1 with AES-192!";

    const encrypted = try seipd.seipdEncrypt(allocator, plaintext, &key, .aes192);
    defer allocator.free(encrypted);

    try testing.expectEqual(@as(u8, 1), encrypted[0]);

    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, &key, .aes192);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "SEIPD AES-192 empty plaintext" {
    const allocator = testing.allocator;
    const key = [_]u8{0x01} ** 24;

    const encrypted = try seipd.seipdEncrypt(allocator, "", &key, .aes192);
    defer allocator.free(encrypted);

    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, &key, .aes192);
    defer allocator.free(decrypted);

    try testing.expectEqual(@as(usize, 0), decrypted.len);
}

test "SEIPD AES-192 wrong key fails" {
    const allocator = testing.allocator;
    const key = [_]u8{0x42} ** 24;
    const wrong_key = [_]u8{0x99} ** 24;
    const plaintext = "Sensitive AES-192 data";

    const encrypted = try seipd.seipdEncrypt(allocator, plaintext, &key, .aes192);
    defer allocator.free(encrypted);

    if (seipd.seipdDecrypt(allocator, encrypted, &wrong_key, .aes192)) |decrypted| {
        allocator.free(decrypted);
        try testing.expect(false);
    } else |err| {
        try testing.expect(err == seipd.SeipdError.QuickCheckFailed or
            err == seipd.SeipdError.MdcMismatch or
            err == seipd.SeipdError.MdcMissing);
    }
}

test "SEIPD AES-192 large plaintext" {
    const allocator = testing.allocator;
    const key = [_]u8{0x55} ** 24;

    const plaintext = try allocator.alloc(u8, 4096);
    defer allocator.free(plaintext);
    @memset(plaintext, 0x42);

    const encrypted = try seipd.seipdEncrypt(allocator, plaintext, &key, .aes192);
    defer allocator.free(encrypted);

    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, &key, .aes192);
    defer allocator.free(decrypted);

    try testing.expectEqualSlices(u8, plaintext, decrypted);
}

test "SEIPD AES-192 key size mismatch" {
    const allocator = testing.allocator;
    const short_key = [_]u8{0x42} ** 16; // 16 bytes, not 24

    const result = seipd.seipdEncrypt(allocator, "test", &short_key, .aes192);
    try testing.expectError(seipd.SeipdError.KeySizeMismatch, result);
}

// ===========================================================================
// Section 4: Secret key decryption with known passphrase
// ===========================================================================

test "Secret key decrypt AES-192 SHA-1 check round-trip" {
    const allocator = testing.allocator;

    // S2K: iterated, SHA-256, salt, count=65536
    const s2k_bytes = [_]u8{
        3, 8,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        96,
    };
    const iv = [_]u8{0xAA} ** 16;
    const plaintext_mpis = [_]u8{
        0x00, 0x10, 0xCA, 0xFE,
        0x00, 0x08, 0xBE,
        0x00, 0x20, 0xDE, 0xAD, 0xBE, 0xEF,
    };

    const encrypted = try secret_key_decrypt.encryptSecretKey(
        allocator,
        &plaintext_mpis,
        "aes192-secret-test",
        .aes192,
        &iv,
        &s2k_bytes,
        254,
    );
    defer allocator.free(encrypted);

    const decrypted = try secret_key_decrypt.decryptSecretKey(
        allocator,
        encrypted,
        "aes192-secret-test",
        .aes192,
        &iv,
        &s2k_bytes,
        254,
    );
    defer allocator.free(decrypted);

    try testing.expectEqualSlices(u8, &plaintext_mpis, decrypted);
}

test "Secret key decrypt AES-128 checksum (usage 255) round-trip" {
    const allocator = testing.allocator;

    const s2k_bytes = [_]u8{
        1, 2,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
    };
    const iv = [_]u8{0x55} ** 16;
    const plaintext_mpis = [_]u8{
        0x00, 0x40,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };

    const encrypted = try secret_key_decrypt.encryptSecretKey(
        allocator,
        &plaintext_mpis,
        "checksum-test",
        .aes128,
        &iv,
        &s2k_bytes,
        255,
    );
    defer allocator.free(encrypted);

    const decrypted = try secret_key_decrypt.decryptSecretKey(
        allocator,
        encrypted,
        "checksum-test",
        .aes128,
        &iv,
        &s2k_bytes,
        255,
    );
    defer allocator.free(decrypted);

    try testing.expectEqualSlices(u8, &plaintext_mpis, decrypted);
}

test "Secret key decrypt wrong passphrase detected" {
    const allocator = testing.allocator;

    const s2k_bytes = [_]u8{
        3, 8,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
        96,
    };
    const iv = [_]u8{0x42} ** 16;
    const plaintext_mpis = [_]u8{ 0x00, 0x08, 0xAB, 0x00, 0x10, 0xCD, 0xEF };

    const encrypted = try secret_key_decrypt.encryptSecretKey(
        allocator,
        &plaintext_mpis,
        "correct",
        .aes256,
        &iv,
        &s2k_bytes,
        254,
    );
    defer allocator.free(encrypted);

    const result = secret_key_decrypt.decryptSecretKey(
        allocator,
        encrypted,
        "wrong",
        .aes256,
        &iv,
        &s2k_bytes,
        254,
    );
    try testing.expectError(secret_key_decrypt.SecretKeyDecryptError.Sha1Mismatch, result);
}

test "Secret key decrypt with TripleDES" {
    const allocator = testing.allocator;

    const s2k_bytes = [_]u8{
        0, 2, // simple, SHA-1
    };
    const iv = [_]u8{0xCC} ** 8; // TripleDES block = 8

    const plaintext_mpis = [_]u8{
        0x00, 0x08, 0xFF,
        0x00, 0x10, 0xDE, 0xAD,
    };

    const encrypted = try secret_key_decrypt.encryptSecretKey(
        allocator,
        &plaintext_mpis,
        "3des-test",
        .triple_des,
        &iv,
        &s2k_bytes,
        254,
    );
    defer allocator.free(encrypted);

    const decrypted = try secret_key_decrypt.decryptSecretKey(
        allocator,
        encrypted,
        "3des-test",
        .triple_des,
        &iv,
        &s2k_bytes,
        254,
    );
    defer allocator.free(decrypted);

    try testing.expectEqualSlices(u8, &plaintext_mpis, decrypted);
}
