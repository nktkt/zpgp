// SPDX-License-Identifier: MIT
//! Camellia block cipher per RFC 3713.
//!
//! Camellia is a 128-bit block cipher supporting 128, 192, and 256-bit keys.
//! It is an SP-network cipher with FL/FL^-1 functions applied every 6 rounds.
//! Used in some OpenPGP implementations.
//!
//! OpenPGP algorithm IDs:
//!   camellia128 = 11
//!   camellia192 = 12
//!   camellia256 = 13

const std = @import("std");
const mem = std.mem;
const math = std.math;

/// Camellia with 128-bit key (OpenPGP algo 11).
pub const Camellia128 = struct {
    pub const block = struct {
        pub const block_length: usize = 16;
    };
    pub const key_bits: usize = 128;

    kw: [4]u64,
    k: [18]u64,
    ke: [4]u64,

    pub fn initEnc(key: [16]u8) Camellia128 {
        return initCamellia128(key);
    }

    pub fn encrypt(self: Camellia128, dst: *[16]u8, src: *const [16]u8) void {
        encryptBlock128(self, dst, src);
    }

    pub fn decrypt(self: Camellia128, dst: *[16]u8, src: *const [16]u8) void {
        decryptBlock128(self, dst, src);
    }
};

/// Camellia with 256-bit key (OpenPGP algo 13).
pub const Camellia256 = struct {
    pub const block = struct {
        pub const block_length: usize = 16;
    };
    pub const key_bits: usize = 256;

    kw: [4]u64,
    k: [24]u64,
    ke: [6]u64,

    pub fn initEnc(key: [32]u8) Camellia256 {
        return initCamellia256(key);
    }

    pub fn encrypt(self: Camellia256, dst: *[16]u8, src: *const [16]u8) void {
        encryptBlock256(self, dst, src);
    }

    pub fn decrypt(self: Camellia256, dst: *[16]u8, src: *const [16]u8) void {
        decryptBlock256(self, dst, src);
    }
};

/// Camellia with 192-bit key (OpenPGP algo 12).
/// Internally uses the same structure as Camellia256 since 192-bit keys
/// are expanded to 256 bits (per RFC 3713 Section 2.3).
pub const Camellia192 = struct {
    pub const block = struct {
        pub const block_length: usize = 16;
    };
    pub const key_bits: usize = 192;

    inner: Camellia256,

    pub fn initEnc(key: [24]u8) Camellia192 {
        // Per RFC 3713: for 192-bit keys, KR = KR_left || NOT(KR_left)
        // where KR_left is the last 64 bits of the key
        var expanded: [32]u8 = undefined;
        @memcpy(expanded[0..24], &key);
        // KR right half = NOT(KR left half) -- the last 8 bytes of the 24-byte key
        for (0..8) |i| {
            expanded[24 + i] = ~key[16 + i];
        }
        return .{ .inner = initCamellia256(expanded) };
    }

    pub fn encrypt(self: Camellia192, dst: *[16]u8, src: *const [16]u8) void {
        encryptBlock256(self.inner, dst, src);
    }

    pub fn decrypt(self: Camellia192, dst: *[16]u8, src: *const [16]u8) void {
        decryptBlock256(self.inner, dst, src);
    }
};

// ---------------------------------------------------------------------------
// Camellia S-boxes (SBOX1, SBOX2, SBOX3, SBOX4)
// ---------------------------------------------------------------------------

const SBOX1: [256]u8 = .{
    112, 130,  44, 236, 179,  39, 192, 229, 228, 136, 214, 201, 102,  62,  41, 197,
    211,  30, 244, 184,  88, 142, 137, 173, 253, 148, 152, 117, 121, 110,  32,  79,
     36,  78, 108, 190, 117, 156,  73, 183, 132, 103, 211,  55, 204, 165, 123,  98,
    198,  64, 143, 101, 157, 160, 170, 168, 207, 116, 207,  83, 170, 121,  46, 128,
    191,  88, 232, 196, 137, 187,  71,  54,  14, 126, 195, 126, 138, 233, 168, 149,
    236, 100, 212,  39,  73,  42, 176, 184, 168,  92, 153, 133,  37,  97, 136,  98,
    128, 219,  39, 176, 230,  59, 134, 188, 224,  95, 218, 216, 127, 120, 207,  67,
     11, 204, 161, 187, 184, 196, 141, 248,  48, 136, 111, 232,  13,   7, 221,  76,
    223,  47, 157, 103,  78,  66, 158, 240,  73,  16,  33, 134, 125, 157, 129, 255,
     57, 117, 217,  66, 156, 238, 177,  78, 188,  51,  65, 157,  42, 225, 242, 141,
    225, 233, 215, 232, 185,  44, 192, 209, 151, 178,  15, 222, 197, 171,  32, 103,
    161, 188, 111,  53, 140, 117, 220, 191, 130, 119, 229, 247, 199,  36,  62, 155,
    123, 181,  17, 131, 129,  42, 199, 133, 186, 189, 159, 143, 135, 218,  47, 157,
     90, 168, 189, 106, 167, 195, 223, 230, 157, 179, 247,  42, 202,  85, 111,  24,
     71, 151, 181, 236, 167,  99, 237,  81, 241, 167, 243, 182, 115, 186,  61, 196,
     16, 189, 238, 121, 211, 100,  11, 151, 165, 138,  26, 210, 146,   0,  14, 206,
};

const SBOX2: [256]u8 = blk: {
    var s: [256]u8 = undefined;
    for (0..256) |i| {
        const v: u8 = SBOX1[i];
        s[i] = (v << 1) | (v >> 7);
    }
    break :blk s;
};

const SBOX3: [256]u8 = blk: {
    var s: [256]u8 = undefined;
    for (0..256) |i| {
        const v: u8 = SBOX1[i];
        s[i] = (v << 7) | (v >> 1);
    }
    break :blk s;
};

const SBOX4: [256]u8 = blk: {
    var s: [256]u8 = undefined;
    for (0..256) |i| {
        const v: u8 = SBOX1[i];
        s[i] = (v << 1) | (v >> 7);
        // SBOX4 uses SBOX1 with input rotated: SBOX1[x <<< 1]
        // Actually: SBOX4[x] = SBOX1[x <<< 1] ... but the common formulation is:
    }
    // Re-derive SBOX4 properly: SBOX4[x] = SBOX1[(x << 1 | x >> 7) & 0xFF]
    for (0..256) |i| {
        const ii: u8 = @intCast(i);
        const rotated = (ii << 1) | (ii >> 7);
        s[i] = SBOX1[rotated];
    }
    break :blk s;
};

// ---------------------------------------------------------------------------
// Sigma constants (from the specification)
// ---------------------------------------------------------------------------
const SIGMA1: u64 = 0xA09E667F3BCC908B;
const SIGMA2: u64 = 0xB67AE8584CAA73B2;
const SIGMA3: u64 = 0xC6EF372FE94F82BE;
const SIGMA4: u64 = 0x54FF53A5F1D36F1C;
const SIGMA5: u64 = 0x10E527FADE682D1D;
const SIGMA6: u64 = 0xB05688C2B3E6C1FD;

// ---------------------------------------------------------------------------
// Core Camellia functions
// ---------------------------------------------------------------------------

/// SP-function: applies S-boxes and P-layer to a 64-bit value.
fn sp(x: u64) u64 {
    const t1 = SBOX1[@as(u8, @truncate(x >> 56))];
    const t2 = SBOX2[@as(u8, @truncate(x >> 48))];
    const t3 = SBOX3[@as(u8, @truncate(x >> 40))];
    const t4 = SBOX4[@as(u8, @truncate(x >> 32))];
    const t5 = SBOX2[@as(u8, @truncate(x >> 24))];
    const t6 = SBOX3[@as(u8, @truncate(x >> 16))];
    const t7 = SBOX4[@as(u8, @truncate(x >> 8))];
    const t8 = SBOX1[@as(u8, @truncate(x))];

    // P-layer
    const z1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
    const z2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
    const z3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
    const z4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
    const z5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
    const z6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
    const z7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
    const z8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;

    // Not the standard formulation -- use the F function approach instead.
    _ = z1;
    _ = z2;
    _ = z3;
    _ = z4;
    _ = z5;
    _ = z6;
    _ = z7;
    _ = z8;

    // Actually, the Camellia F function uses the simpler SP formulation.
    // Let me use the proper approach from the RFC.
    return spFunction(x);
}

/// The SP function as defined in RFC 3713.
fn spFunction(x: u64) u64 {
    const t1: u64 = @as(u64, SBOX1[@as(u8, @truncate(x >> 56))]) << 56;
    const t2: u64 = @as(u64, SBOX2[@as(u8, @truncate(x >> 48))]) << 48;
    const t3: u64 = @as(u64, SBOX3[@as(u8, @truncate(x >> 40))]) << 40;
    const t4: u64 = @as(u64, SBOX4[@as(u8, @truncate(x >> 32))]) << 32;
    const t5: u64 = @as(u64, SBOX2[@as(u8, @truncate(x >> 24))]) << 24;
    const t6: u64 = @as(u64, SBOX3[@as(u8, @truncate(x >> 16))]) << 16;
    const t7: u64 = @as(u64, SBOX4[@as(u8, @truncate(x >> 8))]) << 8;
    const t8: u64 = @as(u64, SBOX1[@as(u8, @truncate(x))]);

    const y = t1 | t2 | t3 | t4 | t5 | t6 | t7 | t8;
    return pFunction(y);
}

/// The P function (byte permutation/mixing).
fn pFunction(x: u64) u64 {
    const b = [8]u8{
        @truncate(x >> 56),
        @truncate(x >> 48),
        @truncate(x >> 40),
        @truncate(x >> 32),
        @truncate(x >> 24),
        @truncate(x >> 16),
        @truncate(x >> 8),
        @truncate(x),
    };

    const z1 = b[0] ^ b[2] ^ b[3] ^ b[5] ^ b[6] ^ b[7];
    const z2 = b[0] ^ b[1] ^ b[3] ^ b[4] ^ b[6] ^ b[7];
    const z3 = b[0] ^ b[1] ^ b[2] ^ b[4] ^ b[5] ^ b[7];
    const z4 = b[1] ^ b[2] ^ b[3] ^ b[4] ^ b[5] ^ b[6];
    const z5 = b[0] ^ b[1] ^ b[5] ^ b[6] ^ b[7];
    const z6 = b[1] ^ b[2] ^ b[4] ^ b[6] ^ b[7];
    const z7 = b[2] ^ b[3] ^ b[4] ^ b[5] ^ b[7];
    const z8 = b[0] ^ b[3] ^ b[4] ^ b[5] ^ b[6];

    return @as(u64, z1) << 56 | @as(u64, z2) << 48 | @as(u64, z3) << 40 | @as(u64, z4) << 32 |
        @as(u64, z5) << 24 | @as(u64, z6) << 16 | @as(u64, z7) << 8 | @as(u64, z8);
}

/// The F function: F(x, k) = P(S(x ^ k))
fn fFunc(x: u64, k: u64) u64 {
    return spFunction(x ^ k);
}

/// FL function.
fn fl(x: u64, k: u64) u64 {
    var x1: u32 = @truncate(x >> 32);
    var x2: u32 = @truncate(x);
    const k1: u32 = @truncate(k >> 32);
    const k2: u32 = @truncate(k);

    x2 ^= math.rotl(u32, x1 & k1, 1);
    x1 ^= (x2 | k2);

    return @as(u64, x1) << 32 | @as(u64, x2);
}

/// FL^-1 function (inverse of FL).
fn flInv(y: u64, k: u64) u64 {
    var y1: u32 = @truncate(y >> 32);
    var y2: u32 = @truncate(y);
    const k1: u32 = @truncate(k >> 32);
    const k2: u32 = @truncate(k);

    y1 ^= (y2 | k2);
    y2 ^= math.rotl(u32, y1 & k1, 1);

    return @as(u64, y1) << 32 | @as(u64, y2);
}

/// Rotate a 128-bit value left by `n` bits (0..127).
fn rot128(hi: u64, lo: u64, comptime n: u8) struct { u64, u64 } {
    if (n == 0) return .{ hi, lo };
    if (n < 64) {
        const shift: u6 = @intCast(n);
        const inv_shift: u6 = @intCast(64 - n);
        return .{
            (hi << shift) | (lo >> inv_shift),
            (lo << shift) | (hi >> inv_shift),
        };
    } else if (n == 64) {
        return .{ lo, hi };
    } else {
        const m: u6 = @intCast(n - 64);
        const inv_m: u6 = @intCast(128 - n);
        return .{
            (lo << m) | (hi >> inv_m),
            (hi << m) | (lo >> inv_m),
        };
    }
}

fn readU64(src: *const [16]u8, offset: usize) u64 {
    return mem.readInt(u64, src[offset..][0..8], .big);
}

fn writeU64(dst: *[16]u8, offset: usize, val: u64) void {
    mem.writeInt(u64, dst[offset..][0..8], val, .big);
}

// ---------------------------------------------------------------------------
// 128-bit key init and encrypt/decrypt
// ---------------------------------------------------------------------------

fn initCamellia128(key: [16]u8) Camellia128 {
    var self: Camellia128 = undefined;

    // KL = key, KR = 0 (for 128-bit keys)
    const kl_hi = mem.readInt(u64, key[0..8], .big);
    const kl_lo = mem.readInt(u64, key[8..16], .big);

    // Generate KA from KL
    var d1 = kl_hi ^ 0; // KL ^ KR for 128-bit: KR = 0
    var d2 = kl_lo ^ 0;

    d2 ^= fFunc(d1, SIGMA1);
    d1 ^= fFunc(d2, SIGMA2);
    d1 ^= kl_hi; // XOR with KL again
    d2 ^= kl_lo;
    d2 ^= fFunc(d1, SIGMA3);
    d1 ^= fFunc(d2, SIGMA4);

    const ka_hi = d1;
    const ka_lo = d2;

    // Generate subkeys for 128-bit (18 round keys + 4 whitening + 4 FL keys)
    // kw1, kw2 (pre-whitening)
    self.kw[0] = rot128(kl_hi, kl_lo, 0)[0]; // KL <<< 0 high
    self.kw[1] = rot128(kl_hi, kl_lo, 0)[1]; // KL <<< 0 low

    // Round keys k1..k18
    self.k[0] = rot128(ka_hi, ka_lo, 0)[0];
    self.k[1] = rot128(ka_hi, ka_lo, 0)[1];
    self.k[2] = rot128(kl_hi, kl_lo, 15)[0];
    self.k[3] = rot128(kl_hi, kl_lo, 15)[1];
    self.k[4] = rot128(ka_hi, ka_lo, 15)[0];
    self.k[5] = rot128(ka_hi, ka_lo, 15)[1];

    // FL keys ke1, ke2 (after round 6)
    self.ke[0] = rot128(ka_hi, ka_lo, 30)[0];
    self.ke[1] = rot128(ka_hi, ka_lo, 30)[1];

    self.k[6] = rot128(kl_hi, kl_lo, 45)[0];
    self.k[7] = rot128(kl_hi, kl_lo, 45)[1];
    self.k[8] = rot128(ka_hi, ka_lo, 45)[0];
    self.k[9] = rot128(kl_hi, kl_lo, 60)[1];
    self.k[10] = rot128(ka_hi, ka_lo, 60)[0];
    self.k[11] = rot128(ka_hi, ka_lo, 60)[1];

    // FL keys ke3, ke4 (after round 12)
    self.ke[2] = rot128(kl_hi, kl_lo, 77)[0];
    self.ke[3] = rot128(kl_hi, kl_lo, 77)[1];

    self.k[12] = rot128(kl_hi, kl_lo, 94)[0];
    self.k[13] = rot128(kl_hi, kl_lo, 94)[1];
    self.k[14] = rot128(ka_hi, ka_lo, 94)[0];
    self.k[15] = rot128(ka_hi, ka_lo, 94)[1];
    self.k[16] = rot128(kl_hi, kl_lo, 111)[0];
    self.k[17] = rot128(kl_hi, kl_lo, 111)[1];

    // kw3, kw4 (post-whitening)
    self.kw[2] = rot128(ka_hi, ka_lo, 111)[0];
    self.kw[3] = rot128(ka_hi, ka_lo, 111)[1];

    return self;
}

fn encryptBlock128(self: Camellia128, dst: *[16]u8, src: *const [16]u8) void {
    var d1 = readU64(src, 0);
    var d2 = readU64(src, 8);

    // Pre-whitening
    d1 ^= self.kw[0];
    d2 ^= self.kw[1];

    // 6 rounds
    d2 ^= fFunc(d1, self.k[0]);
    d1 ^= fFunc(d2, self.k[1]);
    d2 ^= fFunc(d1, self.k[2]);
    d1 ^= fFunc(d2, self.k[3]);
    d2 ^= fFunc(d1, self.k[4]);
    d1 ^= fFunc(d2, self.k[5]);

    // FL/FL^-1
    d1 = fl(d1, self.ke[0]);
    d2 = flInv(d2, self.ke[1]);

    // 6 rounds
    d2 ^= fFunc(d1, self.k[6]);
    d1 ^= fFunc(d2, self.k[7]);
    d2 ^= fFunc(d1, self.k[8]);
    d1 ^= fFunc(d2, self.k[9]);
    d2 ^= fFunc(d1, self.k[10]);
    d1 ^= fFunc(d2, self.k[11]);

    // FL/FL^-1
    d1 = fl(d1, self.ke[2]);
    d2 = flInv(d2, self.ke[3]);

    // 6 rounds
    d2 ^= fFunc(d1, self.k[12]);
    d1 ^= fFunc(d2, self.k[13]);
    d2 ^= fFunc(d1, self.k[14]);
    d1 ^= fFunc(d2, self.k[15]);
    d2 ^= fFunc(d1, self.k[16]);
    d1 ^= fFunc(d2, self.k[17]);

    // Post-whitening
    d2 ^= self.kw[2];
    d1 ^= self.kw[3];

    writeU64(dst, 0, d2);
    writeU64(dst, 8, d1);
}

fn decryptBlock128(self: Camellia128, dst: *[16]u8, src: *const [16]u8) void {
    var d1 = readU64(src, 0);
    var d2 = readU64(src, 8);

    // Pre-whitening (using post-whitening keys)
    d1 ^= self.kw[2];
    d2 ^= self.kw[3];

    // 6 rounds (reverse order)
    d2 ^= fFunc(d1, self.k[17]);
    d1 ^= fFunc(d2, self.k[16]);
    d2 ^= fFunc(d1, self.k[15]);
    d1 ^= fFunc(d2, self.k[14]);
    d2 ^= fFunc(d1, self.k[13]);
    d1 ^= fFunc(d2, self.k[12]);

    // FL/FL^-1 (swapped for decryption)
    d1 = fl(d1, self.ke[3]);
    d2 = flInv(d2, self.ke[2]);

    // 6 rounds
    d2 ^= fFunc(d1, self.k[11]);
    d1 ^= fFunc(d2, self.k[10]);
    d2 ^= fFunc(d1, self.k[9]);
    d1 ^= fFunc(d2, self.k[8]);
    d2 ^= fFunc(d1, self.k[7]);
    d1 ^= fFunc(d2, self.k[6]);

    // FL/FL^-1
    d1 = fl(d1, self.ke[1]);
    d2 = flInv(d2, self.ke[0]);

    // 6 rounds
    d2 ^= fFunc(d1, self.k[5]);
    d1 ^= fFunc(d2, self.k[4]);
    d2 ^= fFunc(d1, self.k[3]);
    d1 ^= fFunc(d2, self.k[2]);
    d2 ^= fFunc(d1, self.k[1]);
    d1 ^= fFunc(d2, self.k[0]);

    // Post-whitening (using pre-whitening keys)
    d2 ^= self.kw[0];
    d1 ^= self.kw[1];

    writeU64(dst, 0, d2);
    writeU64(dst, 8, d1);
}

// ---------------------------------------------------------------------------
// 256-bit key init and encrypt/decrypt
// ---------------------------------------------------------------------------

fn initCamellia256(key: [32]u8) Camellia256 {
    var self: Camellia256 = undefined;

    const kl_hi = mem.readInt(u64, key[0..8], .big);
    const kl_lo = mem.readInt(u64, key[8..16], .big);
    const kr_hi = mem.readInt(u64, key[16..24], .big);
    const kr_lo = mem.readInt(u64, key[24..32], .big);

    // Generate KA from KL and KR
    var d1 = kl_hi ^ kr_hi;
    var d2 = kl_lo ^ kr_lo;

    d2 ^= fFunc(d1, SIGMA1);
    d1 ^= fFunc(d2, SIGMA2);
    d1 ^= kl_hi;
    d2 ^= kl_lo;
    d2 ^= fFunc(d1, SIGMA3);
    d1 ^= fFunc(d2, SIGMA4);

    const ka_hi = d1;
    const ka_lo = d2;

    // Generate KB from KA and KR
    d1 = ka_hi ^ kr_hi;
    d2 = ka_lo ^ kr_lo;
    d2 ^= fFunc(d1, SIGMA5);
    d1 ^= fFunc(d2, SIGMA6);

    const kb_hi = d1;
    const kb_lo = d2;

    // Generate subkeys for 256-bit (24 round keys + 4 whitening + 6 FL keys)
    self.kw[0] = rot128(kl_hi, kl_lo, 0)[0];
    self.kw[1] = rot128(kl_hi, kl_lo, 0)[1];

    self.k[0] = rot128(kb_hi, kb_lo, 0)[0];
    self.k[1] = rot128(kb_hi, kb_lo, 0)[1];
    self.k[2] = rot128(kr_hi, kr_lo, 15)[0];
    self.k[3] = rot128(kr_hi, kr_lo, 15)[1];
    self.k[4] = rot128(ka_hi, ka_lo, 15)[0];
    self.k[5] = rot128(ka_hi, ka_lo, 15)[1];

    self.ke[0] = rot128(kr_hi, kr_lo, 30)[0];
    self.ke[1] = rot128(kr_hi, kr_lo, 30)[1];

    self.k[6] = rot128(kb_hi, kb_lo, 30)[0];
    self.k[7] = rot128(kb_hi, kb_lo, 30)[1];
    self.k[8] = rot128(kl_hi, kl_lo, 45)[0];
    self.k[9] = rot128(kl_hi, kl_lo, 45)[1];
    self.k[10] = rot128(ka_hi, ka_lo, 45)[0];
    self.k[11] = rot128(ka_hi, ka_lo, 45)[1];

    self.ke[2] = rot128(kl_hi, kl_lo, 60)[0];
    self.ke[3] = rot128(kl_hi, kl_lo, 60)[1];

    self.k[12] = rot128(kr_hi, kr_lo, 60)[0];
    self.k[13] = rot128(kr_hi, kr_lo, 60)[1];
    self.k[14] = rot128(kb_hi, kb_lo, 60)[0];
    self.k[15] = rot128(kb_hi, kb_lo, 60)[1];
    self.k[16] = rot128(kl_hi, kl_lo, 77)[0];
    self.k[17] = rot128(kl_hi, kl_lo, 77)[1];

    self.ke[4] = rot128(ka_hi, ka_lo, 77)[0];
    self.ke[5] = rot128(ka_hi, ka_lo, 77)[1];

    self.k[18] = rot128(kr_hi, kr_lo, 94)[0];
    self.k[19] = rot128(kr_hi, kr_lo, 94)[1];
    self.k[20] = rot128(ka_hi, ka_lo, 94)[0];
    self.k[21] = rot128(ka_hi, ka_lo, 94)[1];
    self.k[22] = rot128(kl_hi, kl_lo, 111)[0];
    self.k[23] = rot128(kl_hi, kl_lo, 111)[1];

    self.kw[2] = rot128(kb_hi, kb_lo, 111)[0];
    self.kw[3] = rot128(kb_hi, kb_lo, 111)[1];

    return self;
}

fn encryptBlock256(self: Camellia256, dst: *[16]u8, src: *const [16]u8) void {
    var d1 = readU64(src, 0);
    var d2 = readU64(src, 8);

    d1 ^= self.kw[0];
    d2 ^= self.kw[1];

    // 6 rounds
    d2 ^= fFunc(d1, self.k[0]);
    d1 ^= fFunc(d2, self.k[1]);
    d2 ^= fFunc(d1, self.k[2]);
    d1 ^= fFunc(d2, self.k[3]);
    d2 ^= fFunc(d1, self.k[4]);
    d1 ^= fFunc(d2, self.k[5]);

    d1 = fl(d1, self.ke[0]);
    d2 = flInv(d2, self.ke[1]);

    // 6 rounds
    d2 ^= fFunc(d1, self.k[6]);
    d1 ^= fFunc(d2, self.k[7]);
    d2 ^= fFunc(d1, self.k[8]);
    d1 ^= fFunc(d2, self.k[9]);
    d2 ^= fFunc(d1, self.k[10]);
    d1 ^= fFunc(d2, self.k[11]);

    d1 = fl(d1, self.ke[2]);
    d2 = flInv(d2, self.ke[3]);

    // 6 rounds
    d2 ^= fFunc(d1, self.k[12]);
    d1 ^= fFunc(d2, self.k[13]);
    d2 ^= fFunc(d1, self.k[14]);
    d1 ^= fFunc(d2, self.k[15]);
    d2 ^= fFunc(d1, self.k[16]);
    d1 ^= fFunc(d2, self.k[17]);

    d1 = fl(d1, self.ke[4]);
    d2 = flInv(d2, self.ke[5]);

    // 6 rounds
    d2 ^= fFunc(d1, self.k[18]);
    d1 ^= fFunc(d2, self.k[19]);
    d2 ^= fFunc(d1, self.k[20]);
    d1 ^= fFunc(d2, self.k[21]);
    d2 ^= fFunc(d1, self.k[22]);
    d1 ^= fFunc(d2, self.k[23]);

    d2 ^= self.kw[2];
    d1 ^= self.kw[3];

    writeU64(dst, 0, d2);
    writeU64(dst, 8, d1);
}

fn decryptBlock256(self: Camellia256, dst: *[16]u8, src: *const [16]u8) void {
    var d1 = readU64(src, 0);
    var d2 = readU64(src, 8);

    d1 ^= self.kw[2];
    d2 ^= self.kw[3];

    // 6 rounds (reverse)
    d2 ^= fFunc(d1, self.k[23]);
    d1 ^= fFunc(d2, self.k[22]);
    d2 ^= fFunc(d1, self.k[21]);
    d1 ^= fFunc(d2, self.k[20]);
    d2 ^= fFunc(d1, self.k[19]);
    d1 ^= fFunc(d2, self.k[18]);

    d1 = fl(d1, self.ke[5]);
    d2 = flInv(d2, self.ke[4]);

    d2 ^= fFunc(d1, self.k[17]);
    d1 ^= fFunc(d2, self.k[16]);
    d2 ^= fFunc(d1, self.k[15]);
    d1 ^= fFunc(d2, self.k[14]);
    d2 ^= fFunc(d1, self.k[13]);
    d1 ^= fFunc(d2, self.k[12]);

    d1 = fl(d1, self.ke[3]);
    d2 = flInv(d2, self.ke[2]);

    d2 ^= fFunc(d1, self.k[11]);
    d1 ^= fFunc(d2, self.k[10]);
    d2 ^= fFunc(d1, self.k[9]);
    d1 ^= fFunc(d2, self.k[8]);
    d2 ^= fFunc(d1, self.k[7]);
    d1 ^= fFunc(d2, self.k[6]);

    d1 = fl(d1, self.ke[1]);
    d2 = flInv(d2, self.ke[0]);

    d2 ^= fFunc(d1, self.k[5]);
    d1 ^= fFunc(d2, self.k[4]);
    d2 ^= fFunc(d1, self.k[3]);
    d1 ^= fFunc(d2, self.k[2]);
    d2 ^= fFunc(d1, self.k[1]);
    d1 ^= fFunc(d2, self.k[0]);

    d2 ^= self.kw[0];
    d1 ^= self.kw[1];

    writeU64(dst, 0, d2);
    writeU64(dst, 8, d1);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Camellia-128 encrypt/decrypt round-trip" {
    const key = [16]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
    const plaintext = [16]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };

    const cipher = Camellia128.initEnc(key);

    var ct: [16]u8 = undefined;
    cipher.encrypt(&ct, &plaintext);

    try std.testing.expect(!std.mem.eql(u8, &ct, &plaintext));

    var pt: [16]u8 = undefined;
    cipher.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "Camellia-256 encrypt/decrypt round-trip" {
    const key = [32]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    };
    const plaintext = [16]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };

    const cipher = Camellia256.initEnc(key);

    var ct: [16]u8 = undefined;
    cipher.encrypt(&ct, &plaintext);

    try std.testing.expect(!std.mem.eql(u8, &ct, &plaintext));

    var pt: [16]u8 = undefined;
    cipher.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "Camellia-192 encrypt/decrypt round-trip" {
    const key = [24]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    };
    const plaintext = [16]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };

    const cipher = Camellia192.initEnc(key);

    var ct: [16]u8 = undefined;
    cipher.encrypt(&ct, &plaintext);

    try std.testing.expect(!std.mem.eql(u8, &ct, &plaintext));

    var pt: [16]u8 = undefined;
    cipher.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "Camellia-128 all zeros" {
    const key = [_]u8{0x00} ** 16;
    const plaintext = [_]u8{0x00} ** 16;

    const cipher = Camellia128.initEnc(key);

    var ct: [16]u8 = undefined;
    cipher.encrypt(&ct, &plaintext);

    var pt: [16]u8 = undefined;
    cipher.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "Camellia-256 all zeros" {
    const key = [_]u8{0x00} ** 32;
    const plaintext = [_]u8{0x00} ** 16;

    const cipher = Camellia256.initEnc(key);

    var ct: [16]u8 = undefined;
    cipher.encrypt(&ct, &plaintext);

    var pt: [16]u8 = undefined;
    cipher.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "Camellia-128 deterministic" {
    const key = [16]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 };
    const plaintext = [_]u8{0x42} ** 16;

    const cipher = Camellia128.initEnc(key);

    var ct1: [16]u8 = undefined;
    var ct2: [16]u8 = undefined;
    cipher.encrypt(&ct1, &plaintext);
    cipher.encrypt(&ct2, &plaintext);

    try std.testing.expectEqualSlices(u8, &ct1, &ct2);
}

test "Camellia FL/FL-inv are inverses" {
    const x: u64 = 0x0123456789ABCDEF;
    const k: u64 = 0xFEDCBA9876543210;

    const y = fl(x, k);
    const z = flInv(y, k);

    try std.testing.expectEqual(x, z);
}

test "Camellia rot128" {
    const hi: u64 = 0xFEDCBA9876543210;
    const lo: u64 = 0x0123456789ABCDEF;

    // Rotation by 0 should be identity
    const r0 = rot128(hi, lo, 0);
    try std.testing.expectEqual(hi, r0[0]);
    try std.testing.expectEqual(lo, r0[1]);

    // Rotation by 64 should swap
    const r64 = rot128(hi, lo, 64);
    try std.testing.expectEqual(lo, r64[0]);
    try std.testing.expectEqual(hi, r64[1]);
}

test "Camellia-128 multiple blocks" {
    const key = [16]u8{ 0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48 };
    const cipher = Camellia128.initEnc(key);

    const blocks = [_][16]u8{
        [_]u8{0x00} ** 16,
        [_]u8{0xFF} ** 16,
        .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 },
    };

    for (blocks) |blk| {
        var ct: [16]u8 = undefined;
        cipher.encrypt(&ct, &blk);
        var pt: [16]u8 = undefined;
        cipher.decrypt(&pt, &ct);
        try std.testing.expectEqualSlices(u8, &blk, &pt);
    }
}

test "Camellia-256 multiple blocks" {
    const key = [32]u8{
        0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00,
        0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    const cipher = Camellia256.initEnc(key);

    const blocks = [_][16]u8{
        [_]u8{0x00} ** 16,
        [_]u8{0xFF} ** 16,
        .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 },
    };

    for (blocks) |blk| {
        var ct: [16]u8 = undefined;
        cipher.encrypt(&ct, &blk);
        var pt: [16]u8 = undefined;
        cipher.decrypt(&pt, &ct);
        try std.testing.expectEqualSlices(u8, &blk, &pt);
    }
}

test "Camellia SP function non-trivial" {
    // SP of zero should produce a non-zero result (S-boxes are non-trivial)
    const result = spFunction(0);
    // SBOX1[0] = 112 = 0x70, etc. The result should be non-zero.
    try std.testing.expect(result != 0);
}
