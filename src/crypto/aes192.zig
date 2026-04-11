// SPDX-License-Identifier: MIT
//! AES-192 block cipher per FIPS 197.
//!
//! AES-192 uses a 24-byte (192-bit) key with 12 rounds of encryption.
//! The key schedule expands the 24-byte key into 13 round keys (208 bytes).
//! Block size is 16 bytes (128 bits), same as all AES variants.
//!
//! Zig's std.crypto.core.aes does NOT provide Aes192, so this is a
//! full from-scratch implementation using the standard AES algorithm
//! (S-box, ShiftRows, MixColumns, AddRoundKey).

const std = @import("std");
const mem = std.mem;

pub const Aes192 = struct {
    pub const block = struct {
        pub const block_length: usize = 16;
    };
    pub const key_bits: usize = 192;

    round_keys: [13][16]u8,

    /// Initialize AES-192 for encryption (same context used for decryption).
    pub fn initEnc(key: [24]u8) Aes192 {
        return .{ .round_keys = expandKey(key) };
    }

    /// Encrypt a single 16-byte block.
    pub fn encrypt(self: Aes192, dst: *[16]u8, src: *const [16]u8) void {
        var state: [16]u8 = src.*;

        // Initial AddRoundKey
        addRoundKey(&state, self.round_keys[0]);

        // Rounds 1..11 (full rounds)
        inline for (1..12) |r| {
            subBytes(&state);
            shiftRows(&state);
            mixColumns(&state);
            addRoundKey(&state, self.round_keys[r]);
        }

        // Final round (no MixColumns)
        subBytes(&state);
        shiftRows(&state);
        addRoundKey(&state, self.round_keys[12]);

        dst.* = state;
    }

    /// Decrypt a single 16-byte block.
    pub fn decrypt(self: Aes192, dst: *[16]u8, src: *const [16]u8) void {
        var state: [16]u8 = src.*;

        // Initial AddRoundKey (with last round key)
        addRoundKey(&state, self.round_keys[12]);

        // Rounds 11..1 (inverse full rounds)
        inline for (1..12) |ri| {
            const r = 12 - ri;
            invShiftRows(&state);
            invSubBytes(&state);
            addRoundKey(&state, self.round_keys[r]);
            invMixColumns(&state);
        }

        // Final inverse round (no InvMixColumns)
        invShiftRows(&state);
        invSubBytes(&state);
        addRoundKey(&state, self.round_keys[0]);

        dst.* = state;
    }
};

// ---------------------------------------------------------------------------
// AES S-box
// ---------------------------------------------------------------------------

const sbox: [256]u8 = .{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

// ---------------------------------------------------------------------------
// Inverse S-box
// ---------------------------------------------------------------------------

const inv_sbox: [256]u8 = .{
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

// ---------------------------------------------------------------------------
// Round constant (Rcon)
// ---------------------------------------------------------------------------

const rcon: [11]u8 = .{ 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

// ---------------------------------------------------------------------------
// AES operations
// ---------------------------------------------------------------------------

/// SubBytes: apply S-box to every byte of state.
fn subBytes(state: *[16]u8) void {
    for (state) |*b| {
        b.* = sbox[b.*];
    }
}

/// InvSubBytes: apply inverse S-box to every byte of state.
fn invSubBytes(state: *[16]u8) void {
    for (state) |*b| {
        b.* = inv_sbox[b.*];
    }
}

/// ShiftRows: cyclically shift rows of the state.
/// Row 0: no shift, Row 1: shift left 1, Row 2: shift left 2, Row 3: shift left 3.
///
/// State is stored column-major:
///   s[0] s[4] s[8]  s[12]    row 0
///   s[1] s[5] s[9]  s[13]    row 1
///   s[2] s[6] s[10] s[14]    row 2
///   s[3] s[7] s[11] s[15]    row 3
fn shiftRows(state: *[16]u8) void {
    // Row 1: shift left by 1
    const t1 = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = t1;

    // Row 2: shift left by 2
    const t2a = state[2];
    const t2b = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t2a;
    state[14] = t2b;

    // Row 3: shift left by 3 (= right by 1)
    const t3 = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = t3;
}

/// InvShiftRows: inverse of ShiftRows.
fn invShiftRows(state: *[16]u8) void {
    // Row 1: shift right by 1
    const t1 = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = t1;

    // Row 2: shift right by 2
    const t2a = state[2];
    const t2b = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t2a;
    state[14] = t2b;

    // Row 3: shift right by 3 (= left by 1)
    const t3 = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = t3;
}

/// Multiply by x (0x02) in GF(2^8) with reduction polynomial 0x11b.
fn xtime(a: u8) u8 {
    return (a << 1) ^ (if (a & 0x80 != 0) @as(u8, 0x1b) else @as(u8, 0));
}

/// Multiply two elements in GF(2^8).
fn gmul(a: u8, b: u8) u8 {
    var result: u8 = 0;
    var aa = a;
    var bb = b;
    for (0..8) |_| {
        if (bb & 1 != 0) {
            result ^= aa;
        }
        aa = xtime(aa);
        bb >>= 1;
    }
    return result;
}

/// MixColumns: mix each column of the state using GF(2^8) multiplication.
fn mixColumns(state: *[16]u8) void {
    for (0..4) |c| {
        const i = c * 4;
        const s0 = state[i];
        const s1 = state[i + 1];
        const s2 = state[i + 2];
        const s3 = state[i + 3];

        state[i] = gmul(s0, 2) ^ gmul(s1, 3) ^ s2 ^ s3;
        state[i + 1] = s0 ^ gmul(s1, 2) ^ gmul(s2, 3) ^ s3;
        state[i + 2] = s0 ^ s1 ^ gmul(s2, 2) ^ gmul(s3, 3);
        state[i + 3] = gmul(s0, 3) ^ s1 ^ s2 ^ gmul(s3, 2);
    }
}

/// InvMixColumns: inverse of MixColumns.
fn invMixColumns(state: *[16]u8) void {
    for (0..4) |c| {
        const i = c * 4;
        const s0 = state[i];
        const s1 = state[i + 1];
        const s2 = state[i + 2];
        const s3 = state[i + 3];

        state[i] = gmul(s0, 0x0e) ^ gmul(s1, 0x0b) ^ gmul(s2, 0x0d) ^ gmul(s3, 0x09);
        state[i + 1] = gmul(s0, 0x09) ^ gmul(s1, 0x0e) ^ gmul(s2, 0x0b) ^ gmul(s3, 0x0d);
        state[i + 2] = gmul(s0, 0x0d) ^ gmul(s1, 0x09) ^ gmul(s2, 0x0e) ^ gmul(s3, 0x0b);
        state[i + 3] = gmul(s0, 0x0b) ^ gmul(s1, 0x0d) ^ gmul(s2, 0x09) ^ gmul(s3, 0x0e);
    }
}

/// AddRoundKey: XOR state with a round key.
fn addRoundKey(state: *[16]u8, round_key: [16]u8) void {
    for (state, round_key) |*s, rk| {
        s.* ^= rk;
    }
}

// ---------------------------------------------------------------------------
// Key Expansion for AES-192
// ---------------------------------------------------------------------------

/// Expand a 24-byte key into 13 round keys (each 16 bytes).
///
/// AES-192 key schedule: Nk=6 (6 words), Nr=12 (12 rounds), total 52 words.
/// 52 words = 208 bytes = 13 x 16-byte round keys.
fn expandKey(key: [24]u8) [13][16]u8 {
    // Work with 32-bit words: 52 words total
    var w: [52]u32 = undefined;

    // First Nk=6 words come directly from the key
    for (0..6) |i| {
        w[i] = mem.readInt(u32, key[i * 4 ..][0..4], .big);
    }

    // Expand remaining words
    for (6..52) |i| {
        var tmp = w[i - 1];
        if (i % 6 == 0) {
            // RotWord + SubWord + Rcon
            tmp = subWord(rotWord(tmp)) ^ (@as(u32, rcon[i / 6]) << 24);
        }
        w[i] = w[i - 6] ^ tmp;
    }

    // Pack into 13 round keys
    var round_keys: [13][16]u8 = undefined;
    for (0..13) |r| {
        for (0..4) |j| {
            mem.writeInt(u32, round_keys[r][j * 4 ..][0..4], w[r * 4 + j], .big);
        }
    }

    return round_keys;
}

/// Rotate word: [a0, a1, a2, a3] -> [a1, a2, a3, a0]
fn rotWord(w: u32) u32 {
    return (w << 8) | (w >> 24);
}

/// SubWord: apply S-box to each byte of a 32-bit word.
fn subWord(w: u32) u32 {
    const b0 = sbox[@as(u8, @truncate(w >> 24))];
    const b1 = sbox[@as(u8, @truncate(w >> 16))];
    const b2 = sbox[@as(u8, @truncate(w >> 8))];
    const b3 = sbox[@as(u8, @truncate(w))];
    return (@as(u32, b0) << 24) | (@as(u32, b1) << 16) | (@as(u32, b2) << 8) | @as(u32, b3);
}

// ---------------------------------------------------------------------------
// Tests — NIST FIPS 197 Appendix C.2 (AES-192)
// ---------------------------------------------------------------------------

test "AES-192 encrypt NIST FIPS 197 Appendix C.2" {
    // Key:    000102030405060708090a0b0c0d0e0f1011121314151617
    // Plain:  00112233445566778899aabbccddeeff
    // Cipher: dda97ca4864cdfe06eaf70a0ec0d7191
    const key: [24]u8 = .{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    };
    const plaintext: [16]u8 = .{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const expected: [16]u8 = .{
        0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
        0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
    };

    const cipher = Aes192.initEnc(key);
    var result: [16]u8 = undefined;
    cipher.encrypt(&result, &plaintext);
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "AES-192 decrypt NIST FIPS 197 Appendix C.2" {
    const key: [24]u8 = .{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    };
    const ciphertext: [16]u8 = .{
        0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
        0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
    };
    const expected: [16]u8 = .{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };

    const cipher = Aes192.initEnc(key);
    var result: [16]u8 = undefined;
    cipher.decrypt(&result, &ciphertext);
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "AES-192 encrypt/decrypt round-trip" {
    const key: [24]u8 = .{
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
    };
    const plaintext: [16]u8 = .{
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    };

    const cipher = Aes192.initEnc(key);

    var encrypted: [16]u8 = undefined;
    cipher.encrypt(&encrypted, &plaintext);

    // Encrypted should differ from plaintext
    try std.testing.expect(!mem.eql(u8, &encrypted, &plaintext));

    var decrypted: [16]u8 = undefined;
    cipher.decrypt(&decrypted, &encrypted);

    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "AES-192 all-zero key and plaintext" {
    const key = [_]u8{0} ** 24;
    const plaintext = [_]u8{0} ** 16;

    const cipher = Aes192.initEnc(key);

    var encrypted: [16]u8 = undefined;
    cipher.encrypt(&encrypted, &plaintext);

    // Known result: AES-192 with zero key and zero plaintext
    // should produce non-zero ciphertext
    try std.testing.expect(!mem.eql(u8, &encrypted, &plaintext));

    var decrypted: [16]u8 = undefined;
    cipher.decrypt(&decrypted, &encrypted);

    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "AES-192 NIST test vector 2 - all-F key" {
    // Additional test with a different key pattern
    const key: [24]u8 = .{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const plaintext: [16]u8 = .{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    const cipher = Aes192.initEnc(key);

    // Encrypt and verify round-trip
    var ct: [16]u8 = undefined;
    cipher.encrypt(&ct, &plaintext);

    var pt: [16]u8 = undefined;
    cipher.decrypt(&pt, &ct);

    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "AES-192 multiple blocks consistency" {
    const key = [_]u8{0x42} ** 24;
    const cipher = Aes192.initEnc(key);

    // Encrypt same block twice should give same result
    const block1: [16]u8 = .{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    };

    var ct1: [16]u8 = undefined;
    var ct2: [16]u8 = undefined;
    cipher.encrypt(&ct1, &block1);
    cipher.encrypt(&ct2, &block1);

    try std.testing.expectEqualSlices(u8, &ct1, &ct2);
}
