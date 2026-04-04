// SPDX-License-Identifier: MIT
//! Twofish block cipher per the Twofish specification.
//!
//! Twofish is a 128-bit block cipher supporting 128, 192, and 256-bit keys.
//! OpenPGP uses Twofish with 256-bit keys (symmetric algorithm ID 10).
//! Ported from the Go x/crypto/twofish package (LibTom origin, public domain).

const std = @import("std");
const mem = std.mem;
const math = std.math;

pub const Twofish = struct {
    pub const block = struct {
        pub const block_length: usize = 16;
    };
    pub const key_bits: usize = 256;

    s: [4][256]u32,
    k: [40]u32,

    /// Initialise for encryption with a 256-bit key.
    pub fn initEnc(key: [32]u8) Twofish {
        return newCipher(&key);
    }

    /// Encrypt a single 16-byte block.
    pub fn encrypt(self: Twofish, dst: *[16]u8, src: *const [16]u8) void {
        const s1 = self.s[0];
        const s2 = self.s[1];
        const s3 = self.s[2];
        const s4 = self.s[3];

        // Load input (little-endian)
        var ia = mem.readInt(u32, src[0..4], .little);
        var ib = mem.readInt(u32, src[4..8], .little);
        var ic = mem.readInt(u32, src[8..12], .little);
        var id = mem.readInt(u32, src[12..16], .little);

        // Pre-whitening
        ia ^= self.k[0];
        ib ^= self.k[1];
        ic ^= self.k[2];
        id ^= self.k[3];

        for (0..8) |i| {
            const ki = 8 + i * 4;
            var t2 = s2[@as(u8, @truncate(ib))] ^ s3[@as(u8, @truncate(ib >> 8))] ^ s4[@as(u8, @truncate(ib >> 16))] ^ s1[@as(u8, @truncate(ib >> 24))];
            var t1 = s1[@as(u8, @truncate(ia))] ^ s2[@as(u8, @truncate(ia >> 8))] ^ s3[@as(u8, @truncate(ia >> 16))] ^ s4[@as(u8, @truncate(ia >> 24))];
            t1 +%= t2;
            ic = math.rotr(u32, ic ^ (t1 +% self.k[ki + 0]), 1);
            id = math.rotl(u32, id, 1) ^ (t2 +% t1 +% self.k[ki + 1]);

            t2 = s2[@as(u8, @truncate(id))] ^ s3[@as(u8, @truncate(id >> 8))] ^ s4[@as(u8, @truncate(id >> 16))] ^ s1[@as(u8, @truncate(id >> 24))];
            t1 = s1[@as(u8, @truncate(ic))] ^ s2[@as(u8, @truncate(ic >> 8))] ^ s3[@as(u8, @truncate(ic >> 16))] ^ s4[@as(u8, @truncate(ic >> 24))];
            t1 +%= t2;
            ia = math.rotr(u32, ia ^ (t1 +% self.k[ki + 2]), 1);
            ib = math.rotl(u32, ib, 1) ^ (t2 +% t1 +% self.k[ki + 3]);
        }

        // Output with "undo last swap"
        mem.writeInt(u32, dst[0..4], ic ^ self.k[4], .little);
        mem.writeInt(u32, dst[4..8], id ^ self.k[5], .little);
        mem.writeInt(u32, dst[8..12], ia ^ self.k[6], .little);
        mem.writeInt(u32, dst[12..16], ib ^ self.k[7], .little);
    }

    /// Decrypt a single 16-byte block.
    pub fn decrypt(self: Twofish, dst: *[16]u8, src: *const [16]u8) void {
        const s1 = self.s[0];
        const s2 = self.s[1];
        const s3 = self.s[2];
        const s4 = self.s[3];

        // Load input (little-endian)
        const ta = mem.readInt(u32, src[0..4], .little);
        const tb = mem.readInt(u32, src[4..8], .little);
        const tc = mem.readInt(u32, src[8..12], .little);
        const td = mem.readInt(u32, src[12..16], .little);

        // Undo final swap
        var ia = tc ^ self.k[6];
        var ib = td ^ self.k[7];
        var ic = ta ^ self.k[4];
        var id = tb ^ self.k[5];

        var i: usize = 8;
        while (i > 0) : (i -= 1) {
            const ki = 4 + i * 4;
            var t2 = s2[@as(u8, @truncate(id))] ^ s3[@as(u8, @truncate(id >> 8))] ^ s4[@as(u8, @truncate(id >> 16))] ^ s1[@as(u8, @truncate(id >> 24))];
            var t1 = s1[@as(u8, @truncate(ic))] ^ s2[@as(u8, @truncate(ic >> 8))] ^ s3[@as(u8, @truncate(ic >> 16))] ^ s4[@as(u8, @truncate(ic >> 24))];
            t1 +%= t2;
            ia = math.rotl(u32, ia, 1) ^ (t1 +% self.k[ki + 2]);
            ib = math.rotr(u32, ib ^ (t2 +% t1 +% self.k[ki + 3]), 1);

            t2 = s2[@as(u8, @truncate(ib))] ^ s3[@as(u8, @truncate(ib >> 8))] ^ s4[@as(u8, @truncate(ib >> 16))] ^ s1[@as(u8, @truncate(ib >> 24))];
            t1 = s1[@as(u8, @truncate(ia))] ^ s2[@as(u8, @truncate(ia >> 8))] ^ s3[@as(u8, @truncate(ia >> 16))] ^ s4[@as(u8, @truncate(ia >> 24))];
            t1 +%= t2;
            ic = math.rotl(u32, ic, 1) ^ (t1 +% self.k[ki + 0]);
            id = math.rotr(u32, id ^ (t2 +% t1 +% self.k[ki + 1]), 1);
        }

        // Undo pre-whitening
        ia ^= self.k[0];
        ib ^= self.k[1];
        ic ^= self.k[2];
        id ^= self.k[3];

        mem.writeInt(u32, dst[0..4], ia, .little);
        mem.writeInt(u32, dst[4..8], ib, .little);
        mem.writeInt(u32, dst[8..12], ic, .little);
        mem.writeInt(u32, dst[12..16], id, .little);
    }

    fn newCipher(key: *const [32]u8) Twofish {
        var c: Twofish = undefined;
        const keylen = 32;
        const k_words = keylen / 8; // 4

        // Create the S[..] words using Reed-Solomon
        var S: [4 * 4]u8 = [_]u8{0} ** 16;
        for (0..k_words) |i| {
            for (0..4) |j| {
                for (0..8) |kk| {
                    S[4 * i + j] ^= gfMult(key[8 * i + kk], rs[j][kk], rsPolynomial);
                }
            }
        }

        // Calculate subkeys
        var tmp: [4]u8 = undefined;
        for (0..20) |i| {
            const ii: u8 = @intCast(i);
            // A = h(p * 2x, Me)
            for (0..4) |j| {
                tmp[j] = 2 * ii;
            }
            const A = h(&tmp, key, 0);

            // B = rotl(h(p * (2x + 1), Mo), 8)
            for (0..4) |j| {
                tmp[j] = 2 * ii + 1;
            }
            const B = math.rotl(u32, h(&tmp, key, 1), 8);

            c.k[2 * i] = A +% B;
            c.k[2 * i + 1] = math.rotl(u32, 2 *% B +% A, 9);
        }

        // Calculate sboxes (k=4 case for 256-bit key)
        for (0..256) |i| {
            const ib: u8 = @intCast(i);
            c.s[0][i] = mdsColumnMult(sbox[1][sbox[0][sbox[0][sbox[1][sbox[1][ib] ^ S[0]] ^ S[4]] ^ S[8]] ^ S[12]], 0);
            c.s[1][i] = mdsColumnMult(sbox[0][sbox[0][sbox[1][sbox[1][sbox[0][ib] ^ S[1]] ^ S[5]] ^ S[9]] ^ S[13]], 1);
            c.s[2][i] = mdsColumnMult(sbox[1][sbox[1][sbox[0][sbox[0][sbox[0][ib] ^ S[2]] ^ S[6]] ^ S[10]] ^ S[14]], 2);
            c.s[3][i] = mdsColumnMult(sbox[0][sbox[1][sbox[1][sbox[0][sbox[1][ib] ^ S[3]] ^ S[7]] ^ S[11]] ^ S[15]], 3);
        }

        return c;
    }
};

const mdsPolynomial: u32 = 0x169;
const rsPolynomial: u32 = 0x14d;

/// GF(2^8) multiplication with given polynomial.
fn gfMult(a_in: u8, b_in: u8, p: u32) u8 {
    var a = a_in;
    const B = [2]u32{ 0, @as(u32, b_in) };
    const P = [2]u32{ 0, p };
    var result: u32 = 0;
    var bv: u32 = B[1];

    for (0..7) |_| {
        result ^= if (a & 1 != 0) bv else 0;
        a >>= 1;
        bv = (if (bv >> 7 != 0) P[1] else @as(u32, 0)) ^ (bv << 1);
    }
    result ^= if (a & 1 != 0) bv else 0;
    return @truncate(result);
}

/// MDS column multiplication.
fn mdsColumnMult(in: u8, col: usize) u32 {
    const mul01 = in;
    const mul5B = gfMult(in, 0x5B, mdsPolynomial);
    const mulEF = gfMult(in, 0xEF, mdsPolynomial);

    return switch (col) {
        0 => @as(u32, mul01) | @as(u32, mul5B) << 8 | @as(u32, mulEF) << 16 | @as(u32, mulEF) << 24,
        1 => @as(u32, mulEF) | @as(u32, mulEF) << 8 | @as(u32, mul5B) << 16 | @as(u32, mul01) << 24,
        2 => @as(u32, mul5B) | @as(u32, mulEF) << 8 | @as(u32, mul01) << 16 | @as(u32, mulEF) << 24,
        3 => @as(u32, mul5B) | @as(u32, mul01) << 8 | @as(u32, mulEF) << 16 | @as(u32, mul5B) << 24,
        else => unreachable,
    };
}

/// The h function for subkey generation. See Twofish spec Section 4.3.5.
fn h(in: *const [4]u8, key: *const [32]u8, offset: usize) u32 {
    var y: [4]u8 = in.*;

    // k=4 case (256-bit key): apply all 4 layers
    y[0] = sbox[1][y[0]] ^ key[4 * (6 + offset) + 0];
    y[1] = sbox[0][y[1]] ^ key[4 * (6 + offset) + 1];
    y[2] = sbox[0][y[2]] ^ key[4 * (6 + offset) + 2];
    y[3] = sbox[1][y[3]] ^ key[4 * (6 + offset) + 3];

    y[0] = sbox[1][y[0]] ^ key[4 * (4 + offset) + 0];
    y[1] = sbox[1][y[1]] ^ key[4 * (4 + offset) + 1];
    y[2] = sbox[0][y[2]] ^ key[4 * (4 + offset) + 2];
    y[3] = sbox[0][y[3]] ^ key[4 * (4 + offset) + 3];

    y[0] = sbox[1][sbox[0][sbox[0][y[0]] ^ key[4 * (2 + offset) + 0]] ^ key[4 * (0 + offset) + 0]];
    y[1] = sbox[0][sbox[0][sbox[1][y[1]] ^ key[4 * (2 + offset) + 1]] ^ key[4 * (0 + offset) + 1]];
    y[2] = sbox[1][sbox[1][sbox[0][y[2]] ^ key[4 * (2 + offset) + 2]] ^ key[4 * (0 + offset) + 2]];
    y[3] = sbox[0][sbox[1][sbox[1][y[3]] ^ key[4 * (2 + offset) + 3]] ^ key[4 * (0 + offset) + 3]];

    // MDS multiply
    var mdsMult: u32 = 0;
    for (0..4) |i| {
        mdsMult ^= mdsColumnMult(y[i], i);
    }
    return mdsMult;
}

/// The RS matrix. See Twofish spec Section 4.3.
const rs = [4][8]u8{
    .{ 0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E },
    .{ 0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5 },
    .{ 0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19 },
    .{ 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03 },
};

/// Twofish S-boxes (q0 and q1 permutations).
const sbox = [2][256]u8{
    .{
        0xa9, 0x67, 0xb3, 0xe8, 0x04, 0xfd, 0xa3, 0x76, 0x9a, 0x92, 0x80, 0x78, 0xe4, 0xdd, 0xd1, 0x38,
        0x0d, 0xc6, 0x35, 0x98, 0x18, 0xf7, 0xec, 0x6c, 0x43, 0x75, 0x37, 0x26, 0xfa, 0x13, 0x94, 0x48,
        0xf2, 0xd0, 0x8b, 0x30, 0x84, 0x54, 0xdf, 0x23, 0x19, 0x5b, 0x3d, 0x59, 0xf3, 0xae, 0xa2, 0x82,
        0x63, 0x01, 0x83, 0x2e, 0xd9, 0x51, 0x9b, 0x7c, 0xa6, 0xeb, 0xa5, 0xbe, 0x16, 0x0c, 0xe3, 0x61,
        0xc0, 0x8c, 0x3a, 0xf5, 0x73, 0x2c, 0x25, 0x0b, 0xbb, 0x4e, 0x89, 0x6b, 0x53, 0x6a, 0xb4, 0xf1,
        0xe1, 0xe6, 0xbd, 0x45, 0xe2, 0xf4, 0xb6, 0x66, 0xcc, 0x95, 0x03, 0x56, 0xd4, 0x1c, 0x1e, 0xd7,
        0xfb, 0xc3, 0x8e, 0xb5, 0xe9, 0xcf, 0xbf, 0xba, 0xea, 0x77, 0x39, 0xaf, 0x33, 0xc9, 0x62, 0x71,
        0x81, 0x79, 0x09, 0xad, 0x24, 0xcd, 0xf9, 0xd8, 0xe5, 0xc5, 0xb9, 0x4d, 0x44, 0x08, 0x86, 0xe7,
        0xa1, 0x1d, 0xaa, 0xed, 0x06, 0x70, 0xb2, 0xd2, 0x41, 0x7b, 0xa0, 0x11, 0x31, 0xc2, 0x27, 0x90,
        0x20, 0xf6, 0x60, 0xff, 0x96, 0x5c, 0xb1, 0xab, 0x9e, 0x9c, 0x52, 0x1b, 0x5f, 0x93, 0x0a, 0xef,
        0x91, 0x85, 0x49, 0xee, 0x2d, 0x4f, 0x8f, 0x3b, 0x47, 0x87, 0x6d, 0x46, 0xd6, 0x3e, 0x69, 0x64,
        0x2a, 0xce, 0xcb, 0x2f, 0xfc, 0x97, 0x05, 0x7a, 0xac, 0x7f, 0xd5, 0x1a, 0x4b, 0x0e, 0xa7, 0x5a,
        0x28, 0x14, 0x3f, 0x29, 0x88, 0x3c, 0x4c, 0x02, 0xb8, 0xda, 0xb0, 0x17, 0x55, 0x1f, 0x8a, 0x7d,
        0x57, 0xc7, 0x8d, 0x74, 0xb7, 0xc4, 0x9f, 0x72, 0x7e, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
        0x6e, 0x50, 0xde, 0x68, 0x65, 0xbc, 0xdb, 0xf8, 0xc8, 0xa8, 0x2b, 0x40, 0xdc, 0xfe, 0x32, 0xa4,
        0xca, 0x10, 0x21, 0xf0, 0xd3, 0x5d, 0x0f, 0x00, 0x6f, 0x9d, 0x36, 0x42, 0x4a, 0x5e, 0xc1, 0xe0,
    },
    .{
        0x75, 0xf3, 0xc6, 0xf4, 0xdb, 0x7b, 0xfb, 0xc8, 0x4a, 0xd3, 0xe6, 0x6b, 0x45, 0x7d, 0xe8, 0x4b,
        0xd6, 0x32, 0xd8, 0xfd, 0x37, 0x71, 0xf1, 0xe1, 0x30, 0x0f, 0xf8, 0x1b, 0x87, 0xfa, 0x06, 0x3f,
        0x5e, 0xba, 0xae, 0x5b, 0x8a, 0x00, 0xbc, 0x9d, 0x6d, 0xc1, 0xb1, 0x0e, 0x80, 0x5d, 0xd2, 0xd5,
        0xa0, 0x84, 0x07, 0x14, 0xb5, 0x90, 0x2c, 0xa3, 0xb2, 0x73, 0x4c, 0x54, 0x92, 0x74, 0x36, 0x51,
        0x38, 0xb0, 0xbd, 0x5a, 0xfc, 0x60, 0x62, 0x96, 0x6c, 0x42, 0xf7, 0x10, 0x7c, 0x28, 0x27, 0x8c,
        0x13, 0x95, 0x9c, 0xc7, 0x24, 0x46, 0x3b, 0x70, 0xca, 0xe3, 0x85, 0xcb, 0x11, 0xd0, 0x93, 0xb8,
        0xa6, 0x83, 0x20, 0xff, 0x9f, 0x77, 0xc3, 0xcc, 0x03, 0x6f, 0x08, 0xbf, 0x40, 0xe7, 0x2b, 0xe2,
        0x79, 0x0c, 0xaa, 0x82, 0x41, 0x3a, 0xea, 0xb9, 0xe4, 0x9a, 0xa4, 0x97, 0x7e, 0xda, 0x7a, 0x17,
        0x66, 0x94, 0xa1, 0x1d, 0x3d, 0xf0, 0xde, 0xb3, 0x0b, 0x72, 0xa7, 0x1c, 0xef, 0xd1, 0x53, 0x3e,
        0x8f, 0x33, 0x26, 0x5f, 0xec, 0x76, 0x2a, 0x49, 0x81, 0x88, 0xee, 0x21, 0xc4, 0x1a, 0xeb, 0xd9,
        0xc5, 0x39, 0x99, 0xcd, 0xad, 0x31, 0x8b, 0x01, 0x18, 0x23, 0xdd, 0x1f, 0x4e, 0x2d, 0xf9, 0x48,
        0x4f, 0xf2, 0x65, 0x8e, 0x78, 0x5c, 0x58, 0x19, 0x8d, 0xe5, 0x98, 0x57, 0x67, 0x7f, 0x05, 0x64,
        0xaf, 0x63, 0xb6, 0xfe, 0xf5, 0xb7, 0x3c, 0xa5, 0xce, 0xe9, 0x68, 0x44, 0xe0, 0x4d, 0x43, 0x69,
        0x29, 0x2e, 0xac, 0x15, 0x59, 0xa8, 0x0a, 0x9e, 0x6e, 0x47, 0xdf, 0x34, 0x35, 0x6a, 0xcf, 0xdc,
        0x22, 0xc9, 0xc0, 0x9b, 0x89, 0xd4, 0xed, 0xab, 0x12, 0xa2, 0x0d, 0x52, 0xbb, 0x02, 0x2f, 0xa9,
        0xd7, 0x61, 0x1e, 0xb4, 0x50, 0x04, 0xf6, 0xc2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xbe, 0x91,
    },
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Twofish 256-bit key - all zeros" {
    // Known test vector: 256-bit all-zero key, all-zero plaintext
    // Expected ciphertext: 57 FF 73 9D 4D C9 2C 1B D7 FC 01 70 0C C8 21 6F
    const key = [_]u8{0x00} ** 32;
    const plaintext = [_]u8{0x00} ** 16;
    const expected_ct = [_]u8{ 0x57, 0xFF, 0x73, 0x9D, 0x4D, 0xC9, 0x2C, 0x1B, 0xD7, 0xFC, 0x01, 0x70, 0x0C, 0xC8, 0x21, 0x6F };

    const c = Twofish.initEnc(key);

    var ct: [16]u8 = undefined;
    c.encrypt(&ct, &plaintext);
    try std.testing.expectEqualSlices(u8, &expected_ct, &ct);

    // Decrypt should recover plaintext
    var pt: [16]u8 = undefined;
    c.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "Twofish encrypt/decrypt round-trip" {
    const key = [_]u8{0xAB} ** 32;
    const plaintext = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

    const c = Twofish.initEnc(key);

    var ct: [16]u8 = undefined;
    c.encrypt(&ct, &plaintext);

    // Ciphertext should differ from plaintext
    try std.testing.expect(!std.mem.eql(u8, &ct, &plaintext));

    var pt: [16]u8 = undefined;
    c.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "Twofish gfMult basic" {
    // gfMult(0, x) = 0
    try std.testing.expectEqual(@as(u8, 0), gfMult(0, 0x5B, mdsPolynomial));
    // gfMult(1, x) = x
    try std.testing.expectEqual(@as(u8, 0x5B), gfMult(1, 0x5B, mdsPolynomial));
}
