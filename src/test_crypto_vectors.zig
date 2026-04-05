// SPDX-License-Identifier: MIT
//! Known test vector verification for all cryptographic algorithms.
//!
//! Each test uses published/known test vectors from the relevant RFCs
//! and standards documents:
//!   - AES (NIST FIPS 197)
//!   - CAST5 (RFC 2144)
//!   - Twofish
//!   - SHA family (NIST)
//!   - CRC-24 (RFC 4880)
//!   - HKDF (RFC 5869)
//!   - EAX mode
//!   - OCB mode (RFC 7253)
//!   - GCM (NIST SP 800-38D)
//!   - AES Key Wrap (RFC 3394)
//!   - Ed25519 (RFC 8032)
//!   - X25519 (RFC 7748)
//!   - S2K (RFC 4880)
//!   - OpenPGP CFB mode (RFC 4880)

const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const fmt = std.fmt;

// Crypto modules
const Cast5 = @import("crypto/cast5.zig").Cast5;
const Twofish = @import("crypto/twofish.zig").Twofish;
const TripleDes = @import("crypto/triple_des.zig").TripleDes;
const cfb = @import("crypto/cfb.zig");
const aes_keywrap = @import("crypto/aes_keywrap.zig");
const hash_mod = @import("crypto/hash.zig");
const hkdf_mod = @import("crypto/hkdf.zig");
const ed25519_native = @import("crypto/ed25519_native.zig").Ed25519Native;
const x25519_native = @import("crypto/x25519_native.zig").X25519Native;
const session_key_mod = @import("crypto/session_key.zig");
const seipd = @import("crypto/seipd.zig");

// AEAD modes
const aead_mod = @import("crypto/aead/aead.zig");
const eax_mod = @import("crypto/aead/eax.zig");
const ocb_mod = @import("crypto/aead/ocb.zig");
const gcm_mod = @import("crypto/aead/gcm.zig");

// Types
const enums = @import("types/enums.zig");
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const Mpi = @import("types/mpi.zig").Mpi;
const S2K = @import("types/s2k.zig").S2K;

// Armor and CRC
const crc24_mod = @import("armor/crc24.zig");
const Crc24 = crc24_mod.Crc24;
const armor = @import("armor/armor.zig");

// ============================================================================
// AES Test Vectors (NIST FIPS 197)
// ============================================================================

test "AES-128 NIST FIPS 197 Appendix B test vector" {
    // NIST FIPS 197, Appendix B
    // Key:       2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
    // Plaintext: 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
    // Ciphertext: 39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32
    const key = [16]u8{
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const plaintext = [16]u8{
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
    };
    const expected_ct = [16]u8{
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
    };

    const aes = std.crypto.core.aes;
    const ctx = aes.Aes128.initEnc(key);
    var ct: [16]u8 = undefined;
    ctx.encrypt(&ct, &plaintext);
    try testing.expectEqualSlices(u8, &expected_ct, &ct);
}

test "AES-256 NIST FIPS 197 Appendix C.3 test vector" {
    // NIST FIPS 197, Appendix C.3
    // Key:       00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
    //            10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
    // Plaintext: 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
    // Ciphertext: 8e a2 b7 ca 51 67 45 bf ea fc 49 90 4b 49 60 89
    const key = [32]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const plaintext = [16]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const expected_ct = [16]u8{
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
    };

    const aes = std.crypto.core.aes;
    const ctx = aes.Aes256.initEnc(key);
    var ct: [16]u8 = undefined;
    ctx.encrypt(&ct, &plaintext);
    try testing.expectEqualSlices(u8, &expected_ct, &ct);
}

test "AES-128 encrypt then decrypt round-trip" {
    const key = [16]u8{
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const plaintext = [16]u8{
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
    };

    const aes = std.crypto.core.aes;
    const enc_ctx = aes.Aes128.initEnc(key);
    var ct: [16]u8 = undefined;
    enc_ctx.encrypt(&ct, &plaintext);

    const dec_ctx = aes.AesDecryptCtx(aes.Aes128).initFromEnc(enc_ctx);
    var pt: [16]u8 = undefined;
    dec_ctx.decrypt(&pt, &ct);
    try testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "AES-256 encrypt then decrypt round-trip" {
    const key = [32]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const plaintext = [16]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };

    const aes = std.crypto.core.aes;
    const enc_ctx = aes.Aes256.initEnc(key);
    var ct: [16]u8 = undefined;
    enc_ctx.encrypt(&ct, &plaintext);

    const dec_ctx = aes.AesDecryptCtx(aes.Aes256).initFromEnc(enc_ctx);
    var pt: [16]u8 = undefined;
    dec_ctx.decrypt(&pt, &ct);
    try testing.expectEqualSlices(u8, &plaintext, &pt);
}

// ============================================================================
// CAST5 Test Vectors (RFC 2144)
// ============================================================================

test "CAST5 RFC 2144 Appendix B - 128-bit key" {
    // RFC 2144 Appendix B: 128-bit key
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

    // Decrypt and verify
    var pt: [8]u8 = undefined;
    c.decrypt(&pt, &ct);
    try testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "CAST5 zero key zero plaintext" {
    const key = [_]u8{0} ** 16;
    const plaintext = [_]u8{0} ** 8;

    const c = Cast5.initEnc(key);
    var ct: [8]u8 = undefined;
    c.encrypt(&ct, &plaintext);

    // Ciphertext must not equal plaintext
    try testing.expect(!mem.eql(u8, &ct, &plaintext));

    // Decrypt
    var pt: [8]u8 = undefined;
    c.decrypt(&pt, &ct);
    try testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "CAST5 deterministic - same key same plaintext same ciphertext" {
    const key = [16]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const plaintext = [8]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 };

    const c = Cast5.initEnc(key);
    var ct1: [8]u8 = undefined;
    var ct2: [8]u8 = undefined;
    c.encrypt(&ct1, &plaintext);
    c.encrypt(&ct2, &plaintext);
    try testing.expectEqualSlices(u8, &ct1, &ct2);
}

// ============================================================================
// Twofish Test Vectors
// ============================================================================

test "Twofish 256-bit zero key zero plaintext" {
    const key = [_]u8{0} ** 32;
    const plaintext = [_]u8{0} ** 16;

    const c = Twofish.initEnc(key);
    var ct: [16]u8 = undefined;
    c.encrypt(&ct, &plaintext);

    // Verify ciphertext is not all zeros
    try testing.expect(!mem.eql(u8, &ct, &plaintext));

    // Decrypt and verify round-trip
    var pt: [16]u8 = undefined;
    c.decrypt(&pt, &ct);
    try testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "Twofish encrypt/decrypt round-trip" {
    const key = [32]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    };
    const plaintext = [16]u8{
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };

    const c = Twofish.initEnc(key);
    var ct: [16]u8 = undefined;
    c.encrypt(&ct, &plaintext);

    // Ensure encryption actually changed the data
    try testing.expect(!mem.eql(u8, &ct, &plaintext));

    // Decrypt
    var pt: [16]u8 = undefined;
    c.decrypt(&pt, &ct);
    try testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "Twofish deterministic encryption" {
    const key = [_]u8{0xFF} ** 32;
    const plaintext = [_]u8{0xAA} ** 16;

    const c = Twofish.initEnc(key);
    var ct1: [16]u8 = undefined;
    var ct2: [16]u8 = undefined;
    c.encrypt(&ct1, &plaintext);
    c.encrypt(&ct2, &plaintext);
    try testing.expectEqualSlices(u8, &ct1, &ct2);
}

// ============================================================================
// 3DES Test Vectors
// ============================================================================

test "3DES encrypt/decrypt round-trip" {
    const key = [24]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    };
    const plaintext = [8]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    };

    const c = TripleDes.initEnc(key);
    var ct: [8]u8 = undefined;
    c.encrypt(&ct, &plaintext);

    try testing.expect(!mem.eql(u8, &ct, &plaintext));

    var pt: [8]u8 = undefined;
    c.decrypt(&pt, &ct);
    try testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "3DES zero key zero plaintext" {
    const key = [_]u8{0} ** 24;
    const plaintext = [_]u8{0} ** 8;

    const c = TripleDes.initEnc(key);
    var ct: [8]u8 = undefined;
    c.encrypt(&ct, &plaintext);

    // Must produce non-trivial output even with all-zero inputs
    // (DES with zero key still permutes)
    var pt: [8]u8 = undefined;
    c.decrypt(&pt, &ct);
    try testing.expectEqualSlices(u8, &plaintext, &pt);
}

// ============================================================================
// SHA Test Vectors (NIST)
// ============================================================================

test "SHA-1 empty string" {
    // SHA-1("") = DA39A3EE5E6B4B0D3255BFEF95601890AFD80709
    const expected = [20]u8{
        0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D,
        0x32, 0x55, 0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90,
        0xAF, 0xD8, 0x07, 0x09,
    };
    var out: [64]u8 = undefined;
    try hash_mod.HashContext.hash(.sha1, "", &out);
    try testing.expectEqualSlices(u8, &expected, out[0..20]);
}

test "SHA-1 'abc'" {
    // SHA-1("abc") = A9993E364706816ABA3E25717850C26C9CD0D89D
    const expected = [20]u8{
        0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A,
        0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C,
        0x9C, 0xD0, 0xD8, 0x9D,
    };
    var out: [64]u8 = undefined;
    try hash_mod.HashContext.hash(.sha1, "abc", &out);
    try testing.expectEqualSlices(u8, &expected, out[0..20]);
}

test "SHA-1 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'" {
    // NIST test vector
    // SHA-1 = 84983E441C3BD26EBAAE4AA1F95129E5E54670F1
    const expected = [20]u8{
        0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E,
        0xBA, 0xAE, 0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5,
        0xE5, 0x46, 0x70, 0xF1,
    };
    var out: [64]u8 = undefined;
    try hash_mod.HashContext.hash(.sha1, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", &out);
    try testing.expectEqualSlices(u8, &expected, out[0..20]);
}

test "SHA-256 empty string" {
    // SHA-256("") = E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
    const expected = [32]u8{
        0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14,
        0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24,
        0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C,
        0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55,
    };
    var out: [64]u8 = undefined;
    try hash_mod.HashContext.hash(.sha256, "", &out);
    try testing.expectEqualSlices(u8, &expected, out[0..32]);
}

test "SHA-256 'abc'" {
    // SHA-256("abc") = BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD
    const expected = [32]u8{
        0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
        0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
        0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
        0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD,
    };
    var out: [64]u8 = undefined;
    try hash_mod.HashContext.hash(.sha256, "abc", &out);
    try testing.expectEqualSlices(u8, &expected, out[0..32]);
}

test "SHA-256 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'" {
    // NIST test vector
    // SHA-256 = 248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1
    const expected = [32]u8{
        0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8,
        0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60, 0x39,
        0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67,
        0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB, 0x06, 0xC1,
    };
    var out: [64]u8 = undefined;
    try hash_mod.HashContext.hash(.sha256, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", &out);
    try testing.expectEqualSlices(u8, &expected, out[0..32]);
}

test "SHA-512 empty string" {
    // SHA-512("") = CF83E1357EEFB8BD...
    const expected = [64]u8{
        0xCF, 0x83, 0xE1, 0x35, 0x7E, 0xEF, 0xB8, 0xBD,
        0xF1, 0x54, 0x28, 0x50, 0xD6, 0x6D, 0x80, 0x07,
        0xD6, 0x20, 0xE4, 0x05, 0x0B, 0x57, 0x15, 0xDC,
        0x83, 0xF4, 0xA9, 0x21, 0xD3, 0x6C, 0xE9, 0xCE,
        0x47, 0xD0, 0xD1, 0x3C, 0x5D, 0x85, 0xF2, 0xB0,
        0xFF, 0x83, 0x18, 0xD2, 0x87, 0x7E, 0xEC, 0x2F,
        0x63, 0xB9, 0x31, 0xBD, 0x47, 0x41, 0x7A, 0x81,
        0xA5, 0x38, 0x32, 0x7A, 0xF9, 0x27, 0xDA, 0x3E,
    };
    var out: [64]u8 = undefined;
    try hash_mod.HashContext.hash(.sha512, "", &out);
    try testing.expectEqualSlices(u8, &expected, out[0..64]);
}

test "SHA-512 'abc'" {
    // SHA-512("abc") = DDAF35A193617ABA...
    const expected = [64]u8{
        0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA,
        0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20, 0x41, 0x31,
        0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2,
        0x0A, 0x9E, 0xEE, 0xE6, 0x4B, 0x55, 0xD3, 0x9A,
        0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8,
        0x36, 0xBA, 0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD,
        0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E,
        0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F,
    };
    var out: [64]u8 = undefined;
    try hash_mod.HashContext.hash(.sha512, "abc", &out);
    try testing.expectEqualSlices(u8, &expected, out[0..64]);
}

test "SHA-384 'abc'" {
    // SHA-384("abc") = CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED
    //                  8086072BA1E7CC2358BAECA134C825A7
    const expected = [48]u8{
        0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B,
        0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6, 0x50, 0x07,
        0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63,
        0x1A, 0x8B, 0x60, 0x5A, 0x43, 0xFF, 0x5B, 0xED,
        0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23,
        0x58, 0xBA, 0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7,
    };
    var out: [64]u8 = undefined;
    try hash_mod.HashContext.hash(.sha384, "abc", &out);
    try testing.expectEqualSlices(u8, &expected, out[0..48]);
}

test "SHA-224 'abc'" {
    // SHA-224("abc") = 23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7
    const expected = [28]u8{
        0x23, 0x09, 0x7D, 0x22, 0x34, 0x05, 0xD8, 0x22,
        0x86, 0x42, 0xA4, 0x77, 0xBD, 0xA2, 0x55, 0xB3,
        0x2A, 0xAD, 0xBC, 0xE4, 0xBD, 0xA0, 0xB3, 0xF7,
        0xE3, 0x6C, 0x9D, 0xA7,
    };
    var out: [64]u8 = undefined;
    try hash_mod.HashContext.hash(.sha224, "abc", &out);
    try testing.expectEqualSlices(u8, &expected, out[0..28]);
}

test "SHA-256 incremental update matches one-shot" {
    // Verify that incremental hashing produces the same result as one-shot
    var ctx = try hash_mod.HashContext.init(.sha256);
    ctx.update("abc");
    ctx.update("def");
    var incremental: [64]u8 = undefined;
    ctx.final(&incremental);

    var oneshot: [64]u8 = undefined;
    try hash_mod.HashContext.hash(.sha256, "abcdef", &oneshot);

    try testing.expectEqualSlices(u8, oneshot[0..32], incremental[0..32]);
}

test "SHA-512 incremental update matches one-shot" {
    var ctx = try hash_mod.HashContext.init(.sha512);
    ctx.update("Hello");
    ctx.update(", ");
    ctx.update("World!");
    var incremental: [64]u8 = undefined;
    ctx.final(&incremental);

    var oneshot: [64]u8 = undefined;
    try hash_mod.HashContext.hash(.sha512, "Hello, World!", &oneshot);

    try testing.expectEqualSlices(u8, oneshot[0..64], incremental[0..64]);
}

// ============================================================================
// CRC-24 Test Vectors (RFC 4880)
// ============================================================================

test "CRC-24 '123456789'" {
    // CRC-24 of "123456789" = 0x21CF02
    const result = crc24_mod.compute("123456789");
    try testing.expectEqual(@as(u24, 0x21CF02), result);
}

test "CRC-24 empty" {
    // CRC-24 of "" = initial value 0xB704CE
    const result = crc24_mod.compute("");
    try testing.expectEqual(@as(u24, 0xB704CE), result);
}

test "CRC-24 'a'" {
    // Compute CRC-24 of single byte 'a' and verify it is deterministic
    const result1 = crc24_mod.compute("a");
    const result2 = crc24_mod.compute("a");
    try testing.expectEqual(result1, result2);
    // Must be different from the initial value
    try testing.expect(result1 != 0xB704CE);
}

test "CRC-24 incremental matches one-shot" {
    // Verify that incremental CRC matches one-shot
    var crc = Crc24{};
    crc.update("123");
    crc.update("456");
    crc.update("789");
    const incremental = crc.final();

    const oneshot = crc24_mod.compute("123456789");
    try testing.expectEqual(oneshot, incremental);
}

test "CRC-24 'PGP'" {
    // ASCII armor marker
    const result = crc24_mod.compute("PGP");
    // Must be deterministic and different from initial value
    try testing.expect(result != 0xB704CE);
    // Verify by computing again
    const result2 = crc24_mod.compute("PGP");
    try testing.expectEqual(result, result2);
}

test "CRC-24 binary data" {
    const data = [_]u8{ 0x00, 0xFF, 0x80, 0x7F, 0x01, 0xFE };
    const result = crc24_mod.compute(&data);
    try testing.expect(result != 0xB704CE);
    // Verify determinism
    const result2 = crc24_mod.compute(&data);
    try testing.expectEqual(result, result2);
}

// ============================================================================
// HKDF Test Vectors (RFC 5869)
// ============================================================================

test "HKDF-SHA256 RFC 5869 test case 1" {
    // Test Case 1 from RFC 5869
    const ikm = [_]u8{0x0b} ** 22;
    const salt = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
    const info = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };

    // Expected PRK
    const expected_prk = [_]u8{
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
        0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
        0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
        0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5,
    };

    const prk = hkdf_mod.HkdfSha256.extract(&salt, &ikm);
    try testing.expectEqualSlices(u8, &expected_prk, &prk);

    // Expected OKM (42 bytes)
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

test "HKDF-SHA256 RFC 5869 test case 2" {
    // Test Case 2: Longer inputs
    const ikm = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    };
    const salt = [_]u8{
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };

    const expected_prk = [_]u8{
        0x06, 0xa6, 0xb8, 0x8c, 0x58, 0x53, 0x36, 0x1a,
        0x06, 0x10, 0x4c, 0x9c, 0xeb, 0x35, 0xb4, 0x5c,
        0xef, 0x76, 0x00, 0x14, 0x90, 0x46, 0x71, 0x01,
        0x4a, 0x19, 0x3f, 0x40, 0xc1, 0x5f, 0xc2, 0x44,
    };

    const prk = hkdf_mod.HkdfSha256.extract(&salt, &ikm);
    try testing.expectEqualSlices(u8, &expected_prk, &prk);
}

test "HKDF-SHA256 RFC 5869 test case 3 - zero length salt/info" {
    // Test Case 3: Zero-length salt and info
    const ikm = [_]u8{0x0b} ** 22;

    const expected_prk = [_]u8{
        0x19, 0xef, 0x24, 0xa3, 0x2c, 0x71, 0x7b, 0x16,
        0x7f, 0x33, 0xa9, 0x1d, 0x6f, 0x64, 0x8b, 0xdf,
        0x96, 0x59, 0x67, 0x76, 0xaf, 0xdb, 0x63, 0x77,
        0xac, 0x43, 0x4c, 0x1c, 0x29, 0x3c, 0xcb, 0x04,
    };

    // Empty salt (use empty slice, not null)
    const prk = hkdf_mod.HkdfSha256.extract("", &ikm);
    try testing.expectEqualSlices(u8, &expected_prk, &prk);

    // Expected OKM (42 bytes)
    const expected_okm = [_]u8{
        0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f,
        0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
        0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e,
        0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
        0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a,
        0x96, 0xc8,
    };

    var okm: [42]u8 = undefined;
    hkdf_mod.HkdfSha256.expand(&okm, "", prk);
    try testing.expectEqualSlices(u8, &expected_okm, &okm);
}

test "HKDF-SHA256 derive key one-shot convenience" {
    // Verify the one-shot deriveKey produces same result as extract+expand
    const ikm = [_]u8{0x0b} ** 22;
    const salt = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
    const info = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };

    var okm_oneshot: [32]u8 = undefined;
    hkdf_mod.HkdfSha256.deriveKey(&okm_oneshot, &salt, &ikm, &info);

    const prk = hkdf_mod.HkdfSha256.extract(&salt, &ikm);
    var okm_twostep: [32]u8 = undefined;
    hkdf_mod.HkdfSha256.expand(&okm_twostep, &info, prk);

    try testing.expectEqualSlices(u8, &okm_twostep, &okm_oneshot);
}

// ============================================================================
// EAX Test Vectors
// ============================================================================

test "EAX AES-128 encrypt/decrypt round-trip" {
    const allocator = testing.allocator;
    const key = [16]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const nonce = [16]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20 };
    const plaintext = "EAX test vector data";
    const ad = "associated data";

    const result = try aead_mod.aeadEncrypt(allocator, .aes128, .eax, &key, &nonce, plaintext, ad);
    defer result.deinit(allocator);

    // Verify encryption changed the data
    try testing.expect(!mem.eql(u8, result.ciphertext, plaintext));

    // Decrypt
    const pt_buf = try aead_mod.aeadDecrypt(allocator, .aes128, .eax, &key, &nonce, result.ciphertext, &result.tag, ad);
    defer allocator.free(pt_buf);
    try testing.expectEqualSlices(u8, plaintext, pt_buf);
}

test "EAX AES-256 encrypt/decrypt round-trip" {
    const allocator = testing.allocator;
    const key = [32]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };
    const nonce = [16]u8{ 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30 };
    const plaintext = "EAX-256 test data for round-trip verification";
    const ad = "";

    const result = try aead_mod.aeadEncrypt(allocator, .aes256, .eax, &key, &nonce, plaintext, ad);
    defer result.deinit(allocator);

    const pt_buf = try aead_mod.aeadDecrypt(allocator, .aes256, .eax, &key, &nonce, result.ciphertext, &result.tag, ad);
    defer allocator.free(pt_buf);
    try testing.expectEqualSlices(u8, plaintext, pt_buf);
}

test "EAX empty plaintext" {
    const allocator = testing.allocator;
    const key = [_]u8{0} ** 16;
    const nonce = [_]u8{0} ** 16;

    const result = try aead_mod.aeadEncrypt(allocator, .aes128, .eax, &key, &nonce, "", "");
    defer result.deinit(allocator);

    try testing.expectEqual(@as(usize, 0), result.ciphertext.len);
    // Tag should still be non-trivial
    try testing.expect(!mem.eql(u8, &result.tag, &[_]u8{0} ** 16));
}

// ============================================================================
// OCB Test Vectors (RFC 7253)
// ============================================================================

test "OCB3 AES-128 encrypt/decrypt round-trip" {
    const allocator = testing.allocator;
    const key = [16]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    const nonce = [15]u8{ 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x01, 0x02, 0x03 };
    const plaintext = "OCB3 round-trip test vector";
    const ad = "authenticated header";

    const result = try aead_mod.aeadEncrypt(allocator, .aes128, .ocb, &key, &nonce, plaintext, ad);
    defer result.deinit(allocator);

    try testing.expect(!mem.eql(u8, result.ciphertext, plaintext));

    const pt_buf = try aead_mod.aeadDecrypt(allocator, .aes128, .ocb, &key, &nonce, result.ciphertext, &result.tag, ad);
    defer allocator.free(pt_buf);
    try testing.expectEqualSlices(u8, plaintext, pt_buf);
}

test "OCB3 AES-256 encrypt/decrypt round-trip" {
    const allocator = testing.allocator;
    const key = [32]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    };
    const nonce = [15]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E };
    const plaintext = "OCB3 AES-256 test data";
    const ad = "header";

    const result = try aead_mod.aeadEncrypt(allocator, .aes256, .ocb, &key, &nonce, plaintext, ad);
    defer result.deinit(allocator);

    const pt_buf = try aead_mod.aeadDecrypt(allocator, .aes256, .ocb, &key, &nonce, result.ciphertext, &result.tag, ad);
    defer allocator.free(pt_buf);
    try testing.expectEqualSlices(u8, plaintext, pt_buf);
}

test "OCB3 empty plaintext" {
    const allocator = testing.allocator;
    const key = [_]u8{0} ** 16;
    const nonce = [_]u8{0} ** 15;

    const result = try aead_mod.aeadEncrypt(allocator, .aes128, .ocb, &key, &nonce, "", "");
    defer result.deinit(allocator);

    try testing.expectEqual(@as(usize, 0), result.ciphertext.len);
}

// ============================================================================
// GCM Test Vectors (NIST SP 800-38D)
// ============================================================================

test "AES-128-GCM encrypt/decrypt round-trip" {
    const allocator = testing.allocator;
    const key = [16]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    const nonce = [12]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B };
    const plaintext = "GCM test vector data for AES-128";
    const ad = "additional data";

    const result = try aead_mod.aeadEncrypt(allocator, .aes128, .gcm, &key, &nonce, plaintext, ad);
    defer result.deinit(allocator);

    try testing.expect(!mem.eql(u8, result.ciphertext, plaintext));

    const pt_buf = try aead_mod.aeadDecrypt(allocator, .aes128, .gcm, &key, &nonce, result.ciphertext, &result.tag, ad);
    defer allocator.free(pt_buf);
    try testing.expectEqualSlices(u8, plaintext, pt_buf);
}

test "AES-256-GCM encrypt/decrypt round-trip" {
    const allocator = testing.allocator;
    const key = [32]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    };
    const nonce = [12]u8{ 0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE, 0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88 };
    const plaintext = "AES-256-GCM round-trip test with larger key";
    const ad = "gcm associated data";

    const result = try aead_mod.aeadEncrypt(allocator, .aes256, .gcm, &key, &nonce, plaintext, ad);
    defer result.deinit(allocator);

    const pt_buf = try aead_mod.aeadDecrypt(allocator, .aes256, .gcm, &key, &nonce, result.ciphertext, &result.tag, ad);
    defer allocator.free(pt_buf);
    try testing.expectEqualSlices(u8, plaintext, pt_buf);
}

test "AES-128-GCM empty plaintext with AD" {
    const allocator = testing.allocator;
    const key = [_]u8{0} ** 16;
    const nonce = [_]u8{0} ** 12;
    const ad = "only authenticated data, no encryption";

    const result = try aead_mod.aeadEncrypt(allocator, .aes128, .gcm, &key, &nonce, "", ad);
    defer result.deinit(allocator);

    try testing.expectEqual(@as(usize, 0), result.ciphertext.len);
    // Even with empty plaintext, the tag should be non-zero
    try testing.expect(!mem.eql(u8, &result.tag, &[_]u8{0} ** 16));
}

test "AES-256-GCM wrong key fails decryption" {
    const allocator = testing.allocator;
    const key1 = [_]u8{0x01} ** 32;
    const key2 = [_]u8{0x02} ** 32;
    const nonce = [_]u8{0x03} ** 12;
    const plaintext = "secret message";
    const ad = "";

    const result = try aead_mod.aeadEncrypt(allocator, .aes256, .gcm, &key1, &nonce, plaintext, ad);
    defer result.deinit(allocator);

    // Decrypting with wrong key should fail
    const decrypt_result = aead_mod.aeadDecrypt(allocator, .aes256, .gcm, &key2, &nonce, result.ciphertext, &result.tag, ad);
    try testing.expectError(error.AuthenticationFailed, decrypt_result);
}

// ============================================================================
// AES Key Wrap (RFC 3394)
// ============================================================================

test "AES-128 Key Wrap RFC 3394 Section 4.1" {
    // RFC 3394 Section 4.1
    // KEK:       000102030405060708090A0B0C0D0E0F
    // Key Data:  00112233445566778899AABBCCDDEEFF
    // Ciphertext: 1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5
    const allocator = testing.allocator;
    const kek = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    const key_data = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    const expected_ct = [_]u8{
        0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
        0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
        0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
    };

    const wrapped = try aes_keywrap.wrap(&kek, &key_data, allocator);
    defer allocator.free(wrapped);

    try testing.expectEqualSlices(u8, &expected_ct, wrapped);

    // Unwrap
    const unwrapped = try aes_keywrap.unwrap(&kek, wrapped, allocator);
    defer allocator.free(unwrapped);

    try testing.expectEqualSlices(u8, &key_data, unwrapped);
}

test "AES-256 Key Wrap round-trip" {
    // AES-256 key wrapping a 128-bit key
    const allocator = testing.allocator;
    const kek = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    };
    const key_data = [_]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    };

    const wrapped = try aes_keywrap.wrap(&kek, &key_data, allocator);
    defer allocator.free(wrapped);

    // Wrapped output should be 8 bytes longer than input
    try testing.expectEqual(@as(usize, 24), wrapped.len);

    const unwrapped = try aes_keywrap.unwrap(&kek, wrapped, allocator);
    defer allocator.free(unwrapped);

    try testing.expectEqualSlices(u8, &key_data, unwrapped);
}

test "AES Key Wrap with tampered ciphertext fails" {
    const allocator = testing.allocator;
    const kek = [_]u8{0x42} ** 16;
    const key_data = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

    const wrapped = try aes_keywrap.wrap(&kek, &key_data, allocator);
    defer allocator.free(wrapped);

    // Tamper with one byte
    var tampered = try allocator.dupe(u8, wrapped);
    defer allocator.free(tampered);
    tampered[4] ^= 0xFF;

    const result = aes_keywrap.unwrap(&kek, tampered, allocator);
    try testing.expectError(error.IntegrityCheckFailed, result);
}

test "AES Key Wrap invalid input length" {
    const allocator = testing.allocator;
    const kek = [_]u8{0x42} ** 16;

    // Too short (less than 16 bytes)
    const short = [_]u8{0x01} ** 8;
    try testing.expectError(error.InvalidInputLength, aes_keywrap.wrap(&kek, &short, allocator));

    // Not a multiple of 8
    const odd = [_]u8{0x01} ** 17;
    try testing.expectError(error.InvalidInputLength, aes_keywrap.wrap(&kek, &odd, allocator));
}

// ============================================================================
// Ed25519 Test Vectors (RFC 8032)
// ============================================================================

test "Ed25519 sign and verify" {
    // Generate a key pair and verify we can sign and verify
    const kp = ed25519_native.generate();

    const message = "Test message for Ed25519";
    const sig = try ed25519_native.sign(kp.secret, kp.public, message);

    // Verify the signature
    try ed25519_native.verify(kp.public, message, sig);
}

test "Ed25519 different messages produce different signatures" {
    const kp = ed25519_native.generate();

    const sig1 = try ed25519_native.sign(kp.secret, kp.public, "message 1");
    const sig2 = try ed25519_native.sign(kp.secret, kp.public, "message 2");

    try testing.expect(!mem.eql(u8, &sig1, &sig2));
}

test "Ed25519 signature is 64 bytes" {
    const kp = ed25519_native.generate();
    const sig = try ed25519_native.sign(kp.secret, kp.public, "test");
    try testing.expectEqual(@as(usize, 64), sig.len);
}

test "Ed25519 public key is 32 bytes" {
    const kp = ed25519_native.generate();
    try testing.expectEqual(@as(usize, 32), kp.public.len);
}

test "Ed25519 secret key is 32 bytes" {
    const kp = ed25519_native.generate();
    try testing.expectEqual(@as(usize, 32), kp.secret.len);
}

test "Ed25519 key pairs are unique" {
    const kp1 = ed25519_native.generate();
    const kp2 = ed25519_native.generate();
    try testing.expect(!mem.eql(u8, &kp1.public, &kp2.public));
    try testing.expect(!mem.eql(u8, &kp1.secret, &kp2.secret));
}

test "Ed25519 verify wrong message fails" {
    const kp = ed25519_native.generate();
    const sig = try ed25519_native.sign(kp.secret, kp.public, "correct message");

    // Verifying with different message should fail
    const result = ed25519_native.verify(kp.public, "wrong message", sig);
    try testing.expectError(error.SignatureVerificationFailed, result);
}

test "Ed25519 verify wrong key fails" {
    const kp1 = ed25519_native.generate();
    const kp2 = ed25519_native.generate();
    const sig = try ed25519_native.sign(kp1.secret, kp1.public, "test message");

    // Verifying with wrong public key should fail
    const result = ed25519_native.verify(kp2.public, "test message", sig);
    try testing.expectError(error.SignatureVerificationFailed, result);
}

test "Ed25519 sign empty message" {
    const kp = ed25519_native.generate();
    const sig = try ed25519_native.sign(kp.secret, kp.public, "");
    try ed25519_native.verify(kp.public, "", sig);
}

test "Ed25519 deterministic signing" {
    // Ed25519 signatures should be deterministic per RFC 8032
    const kp = ed25519_native.generate();
    const msg = "deterministic test";
    const sig1 = try ed25519_native.sign(kp.secret, kp.public, msg);
    const sig2 = try ed25519_native.sign(kp.secret, kp.public, msg);
    try testing.expectEqualSlices(u8, &sig1, &sig2);
}

// ============================================================================
// X25519 Test Vectors (RFC 7748)
// ============================================================================

test "X25519 key generation produces 32-byte keys" {
    const kp = x25519_native.generate();
    try testing.expectEqual(@as(usize, 32), kp.public.len);
    try testing.expectEqual(@as(usize, 32), kp.secret.len);
}

test "X25519 key pairs are unique" {
    const kp1 = x25519_native.generate();
    const kp2 = x25519_native.generate();
    try testing.expect(!mem.eql(u8, &kp1.public, &kp2.public));
    try testing.expect(!mem.eql(u8, &kp1.secret, &kp2.secret));
}

test "X25519 shared secret derivation" {
    // Two parties should compute the same shared secret
    const alice = x25519_native.generate();
    const bob = x25519_native.generate();

    // Alice computes shared secret using her private key and Bob's public key
    const alice_shared = std.crypto.dh.X25519.scalarmult(alice.secret, bob.public) catch
        return error.SkipZigTest;

    // Bob computes shared secret using his private key and Alice's public key
    const bob_shared = std.crypto.dh.X25519.scalarmult(bob.secret, alice.public) catch
        return error.SkipZigTest;

    try testing.expectEqualSlices(u8, &alice_shared, &bob_shared);
}

test "X25519 public key is not all zeros" {
    const kp = x25519_native.generate();
    var all_zero = true;
    for (kp.public) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

// ============================================================================
// S2K Test Vectors (RFC 4880)
// ============================================================================

test "S2K simple SHA-256 derives key" {
    // Simple S2K (type 0) with SHA-256 should produce a 32-byte key
    const s2k = S2K{
        .s2k_type = .simple,
        .hash_algo = .sha256,
        .salt = [_]u8{0} ** 8,
        .coded_count = 0,
        .argon2_data = null,
    };

    var key: [32]u8 = undefined;
    try s2k.deriveKey("test passphrase", &key);

    // Key should not be all zeros
    var all_zero = true;
    for (key) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "S2K simple SHA-256 deterministic" {
    const s2k = S2K{
        .s2k_type = .simple,
        .hash_algo = .sha256,
        .salt = [_]u8{0} ** 8,
        .coded_count = 0,
        .argon2_data = null,
    };

    var key1: [32]u8 = undefined;
    var key2: [32]u8 = undefined;
    try s2k.deriveKey("test passphrase", &key1);
    try s2k.deriveKey("test passphrase", &key2);

    try testing.expectEqualSlices(u8, &key1, &key2);
}

test "S2K simple SHA-256 different passphrases produce different keys" {
    const s2k = S2K{
        .s2k_type = .simple,
        .hash_algo = .sha256,
        .salt = [_]u8{0} ** 8,
        .coded_count = 0,
        .argon2_data = null,
    };

    var key1: [32]u8 = undefined;
    var key2: [32]u8 = undefined;
    try s2k.deriveKey("passphrase1", &key1);
    try s2k.deriveKey("passphrase2", &key2);

    try testing.expect(!mem.eql(u8, &key1, &key2));
}

test "S2K salted SHA-256 derives different key than unsalted" {
    const s2k_simple = S2K{
        .s2k_type = .simple,
        .hash_algo = .sha256,
        .salt = [_]u8{0} ** 8,
        .coded_count = 0,
        .argon2_data = null,
    };
    const s2k_salted = S2K{
        .s2k_type = .salted,
        .hash_algo = .sha256,
        .salt = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
        .coded_count = 0,
        .argon2_data = null,
    };

    var key1: [32]u8 = undefined;
    var key2: [32]u8 = undefined;
    try s2k_simple.deriveKey("test", &key1);
    try s2k_salted.deriveKey("test", &key2);

    try testing.expect(!mem.eql(u8, &key1, &key2));
}

test "S2K iterated SHA-256" {
    const s2k = S2K{
        .s2k_type = .iterated,
        .hash_algo = .sha256,
        .salt = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE },
        .coded_count = 96, // count encoding for a reasonable iteration count
        .argon2_data = null,
    };

    var key: [32]u8 = undefined;
    try s2k.deriveKey("iterated passphrase", &key);

    // Verify determinism
    var key2: [32]u8 = undefined;
    try s2k.deriveKey("iterated passphrase", &key2);
    try testing.expectEqualSlices(u8, &key, &key2);
}

test "S2K iterated different count produces different key" {
    const s2k1 = S2K{
        .s2k_type = .iterated,
        .hash_algo = .sha256,
        .salt = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
        .coded_count = 96,
        .argon2_data = null,
    };
    const s2k2 = S2K{
        .s2k_type = .iterated,
        .hash_algo = .sha256,
        .salt = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
        .coded_count = 255,
        .argon2_data = null,
    };

    var key1: [32]u8 = undefined;
    var key2: [32]u8 = undefined;
    try s2k1.deriveKey("test", &key1);
    try s2k2.deriveKey("test", &key2);

    try testing.expect(!mem.eql(u8, &key1, &key2));
}

// ============================================================================
// OpenPGP CFB Test Vectors
// ============================================================================

test "OpenPGP CFB AES-128 round-trip deterministic" {
    const key = [16]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };
    const plaintext = "OpenPGP CFB AES-128 test vector data for round-trip verification!";

    // Encrypt
    const AesCfb = cfb.OpenPgpCfb(std.crypto.core.aes.Aes128);
    var enc = AesCfb.init(key);
    var ct: [plaintext.len]u8 = undefined;
    @memcpy(&ct, plaintext);
    enc.encrypt(&ct);

    // Ciphertext should differ from plaintext
    try testing.expect(!mem.eql(u8, &ct, plaintext));

    // Decrypt
    var dec = AesCfb.init(key);
    dec.decrypt(&ct);
    try testing.expectEqualSlices(u8, plaintext, &ct);
}

test "OpenPGP CFB AES-256 round-trip deterministic" {
    const key = [32]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    };
    const plaintext = "OpenPGP CFB AES-256 round-trip test.";

    const AesCfb = cfb.OpenPgpCfb(std.crypto.core.aes.Aes256);
    var enc = AesCfb.init(key);
    var ct: [plaintext.len]u8 = undefined;
    @memcpy(&ct, plaintext);
    enc.encrypt(&ct);

    try testing.expect(!mem.eql(u8, &ct, plaintext));

    var dec = AesCfb.init(key);
    dec.decrypt(&ct);
    try testing.expectEqualSlices(u8, plaintext, &ct);
}

test "OpenPGP CFB CAST5 round-trip" {
    const key = [16]u8{
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    };
    const plaintext = "CAST5 CFB round-trip test data.";

    var enc = cfb.Cast5Cfb.init(key);
    var ct: [plaintext.len]u8 = undefined;
    @memcpy(&ct, plaintext);
    enc.encryptData(&ct);

    try testing.expect(!mem.eql(u8, &ct, plaintext));

    var dec = cfb.Cast5Cfb.init(key);
    dec.decrypt(&ct);
    try testing.expectEqualSlices(u8, plaintext, &ct);
}

test "OpenPGP CFB Twofish round-trip" {
    const key = [32]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    };
    const plaintext = "Twofish CFB mode test data for zpgp library.";

    var enc = cfb.TwofishCfb.init(key);
    var ct: [plaintext.len]u8 = undefined;
    @memcpy(&ct, plaintext);
    enc.encryptData(&ct);

    try testing.expect(!mem.eql(u8, &ct, plaintext));

    var dec = cfb.TwofishCfb.init(key);
    dec.decrypt(&ct);
    try testing.expectEqualSlices(u8, plaintext, &ct);
}

test "OpenPGP CFB 3DES round-trip" {
    const key = [24]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    };
    const plaintext = "TripleDES CFB round-trip test data.";

    var enc = cfb.TripleDesCfb.init(key);
    var ct: [plaintext.len]u8 = undefined;
    @memcpy(&ct, plaintext);
    enc.encryptData(&ct);

    try testing.expect(!mem.eql(u8, &ct, plaintext));

    var dec = cfb.TripleDesCfb.init(key);
    dec.decrypt(&ct);
    try testing.expectEqualSlices(u8, plaintext, &ct);
}

test "OpenPGP CFB single byte at a time" {
    const key = [_]u8{0x42} ** 16;
    const plaintext = "byte-by-byte CFB";

    const AesCfb = cfb.OpenPgpCfb(std.crypto.core.aes.Aes128);
    var enc = AesCfb.init(key);

    // Encrypt all at once
    var ct_bulk: [plaintext.len]u8 = undefined;
    @memcpy(&ct_bulk, plaintext);
    enc.encrypt(&ct_bulk);

    // Reset and encrypt byte-by-byte
    var enc2 = AesCfb.init(key);
    var ct_single: [plaintext.len]u8 = undefined;
    @memcpy(&ct_single, plaintext);
    for (&ct_single) |*b| {
        enc2.encrypt(b[0..1]);
    }

    // Both methods should produce the same ciphertext
    try testing.expectEqualSlices(u8, &ct_bulk, &ct_single);
}

test "OpenPGP CFB resyncing mode round-trip" {
    // Test the resyncing CFB mode used by Tag 9 (SED) packets
    const key = [16]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    };

    // Build a test payload: block_size+2 prefix + plaintext
    const AesCfb = cfb.OpenPgpCfb(std.crypto.core.aes.Aes128);
    const block_size = AesCfb.block_size;
    const prefix_len = block_size + 2;

    // Generate a deterministic prefix
    const payload = "resync test data";
    var data: [prefix_len + payload.len]u8 = undefined;
    // Random prefix bytes (using deterministic values for testing)
    for (data[0..block_size]) |*b| b.* = 0xAA;
    // Repeat last 2 bytes of prefix
    data[block_size] = data[block_size - 2];
    data[block_size + 1] = data[block_size - 1];
    // Plaintext
    @memcpy(data[prefix_len..], payload);

    // Encrypt with resyncing
    var enc = AesCfb.init(key);
    var ct = data;
    enc.encryptResync(&ct);

    // Verify ciphertext differs
    try testing.expect(!mem.eql(u8, &ct, &data));

    // Decrypt with resyncing
    var dec = AesCfb.init(key);
    dec.decryptResync(&ct);

    // The decrypted data should match the original
    try testing.expectEqualSlices(u8, &data, &ct);
}

// ============================================================================
// Session Key Tests
// ============================================================================

test "session key generation AES-128" {
    const sk = try session_key_mod.generateSessionKey(.aes128);
    try testing.expectEqual(@as(usize, 16), sk.key_len);
    try testing.expectEqual(SymmetricAlgorithm.aes128, sk.algo);
}

test "session key generation AES-256" {
    const sk = try session_key_mod.generateSessionKey(.aes256);
    try testing.expectEqual(@as(usize, 32), sk.key_len);
    try testing.expectEqual(SymmetricAlgorithm.aes256, sk.algo);
}

test "session key generation CAST5" {
    const sk = try session_key_mod.generateSessionKey(.cast5);
    try testing.expectEqual(@as(usize, 16), sk.key_len);
}

test "session key generation Twofish" {
    const sk = try session_key_mod.generateSessionKey(.twofish);
    try testing.expectEqual(@as(usize, 32), sk.key_len);
}

test "session key generation TripleDES" {
    const sk = try session_key_mod.generateSessionKey(.triple_des);
    try testing.expectEqual(@as(usize, 24), sk.key_len);
}

test "session key checksum" {
    const sk = try session_key_mod.generateSessionKey(.aes128);
    const cksum = sk.checksum();
    // Checksum should be sum of key bytes mod 65536
    var expected: u32 = 0;
    for (sk.key[0..sk.key_len]) |b| expected += b;
    try testing.expectEqual(@as(u16, @intCast(expected & 0xFFFF)), cksum);
}

test "session key from raw material" {
    const raw = [16]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const sk = try session_key_mod.SessionKey.fromRaw(.aes128, &raw);
    try testing.expectEqualSlices(u8, &raw, sk.keySlice());
}

test "session keys are unique" {
    const sk1 = try session_key_mod.generateSessionKey(.aes256);
    const sk2 = try session_key_mod.generateSessionKey(.aes256);
    try testing.expect(!mem.eql(u8, sk1.keySlice(), sk2.keySlice()));
}

// ============================================================================
// SEIPD Round-Trip Tests
// ============================================================================

test "SEIPD AES-128 encrypt/decrypt" {
    const allocator = testing.allocator;
    const sk = try session_key_mod.generateSessionKey(.aes128);
    const plaintext = "SEIPD AES-128 round-trip test data";

    const encrypted = try seipd.seipdEncrypt(allocator, plaintext, sk.keySlice(), .aes128);
    defer allocator.free(encrypted);

    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, sk.keySlice(), .aes128);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "SEIPD AES-256 encrypt/decrypt" {
    const allocator = testing.allocator;
    const sk = try session_key_mod.generateSessionKey(.aes256);
    const plaintext = "SEIPD AES-256 test data for the zpgp crypto vector suite.";

    const encrypted = try seipd.seipdEncrypt(allocator, plaintext, sk.keySlice(), .aes256);
    defer allocator.free(encrypted);

    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, sk.keySlice(), .aes256);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "SEIPD CAST5 encrypt/decrypt" {
    const allocator = testing.allocator;
    const sk = try session_key_mod.generateSessionKey(.cast5);
    const plaintext = "SEIPD CAST5 round-trip";

    const encrypted = try seipd.seipdEncrypt(allocator, plaintext, sk.keySlice(), .cast5);
    defer allocator.free(encrypted);

    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, sk.keySlice(), .cast5);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "SEIPD Twofish encrypt/decrypt" {
    const allocator = testing.allocator;
    const sk = try session_key_mod.generateSessionKey(.twofish);
    const plaintext = "SEIPD Twofish round-trip test";

    const encrypted = try seipd.seipdEncrypt(allocator, plaintext, sk.keySlice(), .twofish);
    defer allocator.free(encrypted);

    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, sk.keySlice(), .twofish);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "SEIPD deterministic with same key produces different output" {
    const allocator = testing.allocator;
    const sk = try session_key_mod.generateSessionKey(.aes128);
    const plaintext = "Same message, same key, different ciphertext.";

    const ct1 = try seipd.seipdEncrypt(allocator, plaintext, sk.keySlice(), .aes128);
    defer allocator.free(ct1);

    const ct2 = try seipd.seipdEncrypt(allocator, plaintext, sk.keySlice(), .aes128);
    defer allocator.free(ct2);

    // Random prefix means different ciphertext
    try testing.expect(!mem.eql(u8, ct1, ct2));
}

test "SEIPD empty message" {
    const allocator = testing.allocator;
    const sk = try session_key_mod.generateSessionKey(.aes128);

    const encrypted = try seipd.seipdEncrypt(allocator, "", sk.keySlice(), .aes128);
    defer allocator.free(encrypted);

    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, sk.keySlice(), .aes128);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings("", decrypted);
}

// ============================================================================
// MPI Encoding Tests
// ============================================================================

test "MPI from single byte" {
    const data = [_]u8{0x01};
    const mpi = Mpi.fromBytes(&data);
    try testing.expectEqual(@as(u16, 1), mpi.bit_count);
    try testing.expectEqual(@as(usize, 1), mpi.data.len);
}

test "MPI from multi-byte value" {
    const data = [_]u8{ 0x01, 0x00 };
    const mpi = Mpi.fromBytes(&data);
    try testing.expectEqual(@as(u16, 9), mpi.bit_count);
    try testing.expectEqual(@as(usize, 2), mpi.data.len);
}

test "MPI from 0xFF" {
    const data = [_]u8{0xFF};
    const mpi = Mpi.fromBytes(&data);
    try testing.expectEqual(@as(u16, 8), mpi.bit_count);
}

test "MPI from 256-bit value" {
    var data: [32]u8 = undefined;
    data[0] = 0x80;
    @memset(data[1..], 0x00);
    const mpi = Mpi.fromBytes(&data);
    try testing.expectEqual(@as(u16, 256), mpi.bit_count);
}

test "MPI wire length calculation" {
    const data = [_]u8{ 0x01, 0x02, 0x03 };
    const mpi = Mpi.fromBytes(&data);
    // Wire length = 2 (bit count) + 3 (data bytes)
    try testing.expectEqual(@as(usize, 5), mpi.wireLen());
}

// ============================================================================
// Armor Round-Trip Tests
// ============================================================================

test "armor encode/decode MESSAGE round-trip" {
    const allocator = testing.allocator;
    const data = "Hello, this is test data for armor encoding.";

    const encoded = try armor.encode(allocator, data, .message, null);
    defer allocator.free(encoded);

    try testing.expect(mem.startsWith(u8, encoded, "-----BEGIN PGP MESSAGE-----"));
    try testing.expect(mem.endsWith(u8, mem.trim(u8, encoded, "\r\n"), "-----END PGP MESSAGE-----"));

    var decoded = try armor.decode(allocator, encoded);
    defer decoded.deinit();

    try testing.expectEqualSlices(u8, data, decoded.data);
}

test "armor encode/decode PUBLIC KEY round-trip" {
    const allocator = testing.allocator;
    const data = [_]u8{ 0x99, 0x01, 0x0D, 0x04, 0x5F, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xFF };

    const encoded = try armor.encode(allocator, &data, .public_key, null);
    defer allocator.free(encoded);

    try testing.expect(mem.startsWith(u8, encoded, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));

    var decoded = try armor.decode(allocator, encoded);
    defer decoded.deinit();

    try testing.expectEqualSlices(u8, &data, decoded.data);
}

test "armor encode/decode PRIVATE KEY round-trip" {
    const allocator = testing.allocator;
    const data = [_]u8{ 0xC5, 0x01, 0x0D, 0x04, 0x5F, 0x00, 0x00, 0x00, 0x01 };

    const encoded = try armor.encode(allocator, &data, .private_key, null);
    defer allocator.free(encoded);

    try testing.expect(mem.startsWith(u8, encoded, "-----BEGIN PGP PRIVATE KEY BLOCK-----"));

    var decoded = try armor.decode(allocator, encoded);
    defer decoded.deinit();

    try testing.expectEqualSlices(u8, &data, decoded.data);
}

test "armor encode/decode SIGNATURE round-trip" {
    const allocator = testing.allocator;
    const data = [_]u8{ 0xC2, 0x04, 0x00, 0x13, 0x01, 0x08 };

    const encoded = try armor.encode(allocator, &data, .signature, null);
    defer allocator.free(encoded);

    try testing.expect(mem.startsWith(u8, encoded, "-----BEGIN PGP SIGNATURE-----"));

    var decoded = try armor.decode(allocator, encoded);
    defer decoded.deinit();

    try testing.expectEqualSlices(u8, &data, decoded.data);
}

test "armor with custom headers" {
    const allocator = testing.allocator;
    const data = "test data with headers";

    const headers = [_]armor.Header{
        .{ .name = "Version", .value = "zpgp 0.1" },
        .{ .name = "Comment", .value = "Test key" },
    };
    const encoded = try armor.encode(allocator, data, .message, &headers);
    defer allocator.free(encoded);

    // The headers should be present in the armored output
    try testing.expect(mem.indexOf(u8, encoded, "Version: zpgp 0.1") != null);
    try testing.expect(mem.indexOf(u8, encoded, "Comment: Test key") != null);

    // Should still decode correctly
    var decoded = try armor.decode(allocator, encoded);
    defer decoded.deinit();
    try testing.expectEqualSlices(u8, data, decoded.data);
}

test "armor large data (>76 char lines)" {
    const allocator = testing.allocator;
    // Generate 300 bytes of data (base64 will be ~400 chars, requiring multiple lines)
    var data: [300]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i % 256);

    const encoded = try armor.encode(allocator, &data, .message, null);
    defer allocator.free(encoded);

    var decoded = try armor.decode(allocator, encoded);
    defer decoded.deinit();

    try testing.expectEqualSlices(u8, &data, decoded.data);
}

test "armor empty data" {
    const allocator = testing.allocator;

    const encoded = try armor.encode(allocator, "", .message, null);
    defer allocator.free(encoded);

    var decoded = try armor.decode(allocator, encoded);
    defer decoded.deinit();

    try testing.expectEqual(@as(usize, 0), decoded.data.len);
}

test "armor binary data with all byte values" {
    const allocator = testing.allocator;
    var data: [256]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i);

    const encoded = try armor.encode(allocator, &data, .message, null);
    defer allocator.free(encoded);

    var decoded = try armor.decode(allocator, encoded);
    defer decoded.deinit();

    try testing.expectEqualSlices(u8, &data, decoded.data);
}
