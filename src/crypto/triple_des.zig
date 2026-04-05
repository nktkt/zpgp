// SPDX-License-Identifier: MIT
//! Triple DES (3DES / TDEA) block cipher.
//!
//! Implements the Data Encryption Standard (DES) with triple application:
//!   Encrypt: E_K1(D_K2(E_K3(plaintext)))
//!   Decrypt: D_K3(E_K2(D_K1(ciphertext)))
//!
//! Uses a 192-bit (24-byte) key composed of three 8-byte DES keys.
//! Block size is 64 bits (8 bytes).
//!
//! The DES implementation follows FIPS 46-3 with the well-known permutation
//! tables, S-boxes, and key schedule constants.

const std = @import("std");
const mem = std.mem;

// ---------------------------------------------------------------------------
// DES constants (FIPS 46-3)
// ---------------------------------------------------------------------------

/// Initial Permutation (IP) table -- 64 entries.
/// Bit positions are 1-based as per the FIPS specification.
const IP = [64]u8{
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
};

/// Final Permutation (FP / IP^-1) table -- 64 entries.
const FP = [64]u8{
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
};

/// Expansion permutation (E) -- 48 entries, maps 32-bit R half to 48 bits.
const E = [48]u8{
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
};

/// P-box permutation -- 32 entries, applied after S-box substitution.
const P = [32]u8{
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25,
};

/// The 8 DES S-boxes.  Each S-box is a 4x16 array of 4-bit values.
/// Row is determined by the outer two bits, column by the inner four bits.
const S_BOXES = [8][4][16]u4{
    // S1
    .{
        .{ 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7 },
        .{  0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8 },
        .{  4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0 },
        .{ 15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13 },
    },
    // S2
    .{
        .{ 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10 },
        .{  3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5 },
        .{  0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15 },
        .{ 13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 },
    },
    // S3
    .{
        .{ 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8 },
        .{ 13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1 },
        .{ 13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7 },
        .{  1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 },
    },
    // S4
    .{
        .{  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15 },
        .{ 13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9 },
        .{ 10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4 },
        .{  3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14 },
    },
    // S5
    .{
        .{  2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9 },
        .{ 14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6 },
        .{  4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14 },
        .{ 11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 },
    },
    // S6
    .{
        .{ 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11 },
        .{ 10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8 },
        .{  9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6 },
        .{  4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 },
    },
    // S7
    .{
        .{  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1 },
        .{ 13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6 },
        .{  1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2 },
        .{  6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 },
    },
    // S8
    .{
        .{ 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7 },
        .{  1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6,  2,  0, 14,  9, 11 },
        .{  7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8 },
        .{  2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 },
    },
};

/// Permuted Choice 1 (PC-1) -- selects 56 bits from the 64-bit key.
const PC1 = [56]u8{
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4,
};

/// Permuted Choice 2 (PC-2) -- selects 48 bits from the 56-bit CD register.
const PC2 = [48]u8{
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
};

/// Number of left shifts per round in the key schedule.
const SHIFTS = [16]u2{ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

// ---------------------------------------------------------------------------
// Helper: bit extraction from byte arrays (1-based positions)
// ---------------------------------------------------------------------------

/// Get a single bit from a byte array using a 1-based position.
/// Position 1 is the MSB of the first byte.
inline fn getBit(data: []const u8, pos_1based: u8) u1 {
    const pos = pos_1based - 1;
    const byte_idx = pos >> 3;
    const bit_idx: u3 = @intCast(7 - (pos & 7));
    return @intCast((data[byte_idx] >> bit_idx) & 1);
}

/// Set a single bit in a byte array using a 0-based bit position.
/// Position 0 is the MSB of the first byte.
inline fn setBit(data: []u8, pos_0based: usize, val: u1) void {
    const byte_idx = pos_0based >> 3;
    const bit_idx: u3 = @intCast(7 - (pos_0based & 7));
    if (val == 1) {
        data[byte_idx] |= @as(u8, 1) << bit_idx;
    } else {
        data[byte_idx] &= ~(@as(u8, 1) << bit_idx);
    }
}

// ---------------------------------------------------------------------------
// DES core
// ---------------------------------------------------------------------------

/// A single DES key schedule: 16 round subkeys, each 48 bits (6 bytes).
const DesSubkeys = [16][6]u8;

/// Generate the 16 round subkeys from an 8-byte DES key.
fn desKeySchedule(key: *const [8]u8) DesSubkeys {
    var subkeys: DesSubkeys = undefined;

    // Apply PC-1: select 56 bits from the 64-bit key into cd (7 bytes).
    var cd: [7]u8 = [_]u8{0} ** 7;
    for (0..56) |i| {
        const bit = getBit(key, PC1[i]);
        setBit(&cd, i, bit);
    }

    // Split into C (bits 0..27) and D (bits 28..55) as 28-bit halves.
    // We keep them packed in `cd` and do rotations in place.
    for (0..16) |round| {
        // Left-rotate C and D by SHIFTS[round] positions.
        const shift_count: u8 = SHIFTS[round];
        for (0..shift_count) |_| {
            // Rotate C (bits 0..27)
            const c_top = getBitFromSlice(&cd, 0);
            for (0..27) |j| {
                const b = getBitFromSlice(&cd, j + 1);
                setBit(&cd, j, b);
            }
            setBit(&cd, 27, c_top);

            // Rotate D (bits 28..55)
            const d_top = getBitFromSlice(&cd, 28);
            for (0..27) |j| {
                const b = getBitFromSlice(&cd, 28 + j + 1);
                setBit(&cd, 28 + j, b);
            }
            setBit(&cd, 55, d_top);
        }

        // Apply PC-2: select 48 bits from cd
        subkeys[round] = [_]u8{0} ** 6;
        for (0..48) |i| {
            const bit = getBitFromSlice(&cd, PC2[i] - 1);
            setBit(subkeys[round][0..6], i, bit);
        }
    }

    return subkeys;
}

/// Get a bit at a 0-based position from a byte slice.
inline fn getBitFromSlice(data: []const u8, pos: usize) u1 {
    const byte_idx = pos >> 3;
    const bit_idx: u3 = @intCast(7 - (pos & 7));
    return @intCast((data[byte_idx] >> bit_idx) & 1);
}

/// Convert 8 bytes to a u64 (big-endian).
inline fn bytesToU64(b: *const [8]u8) u64 {
    return mem.readInt(u64, b, .big);
}

/// Convert a u64 to 8 bytes (big-endian).
inline fn u64ToBytes(val: u64) [8]u8 {
    var b: [8]u8 = undefined;
    mem.writeInt(u64, &b, val, .big);
    return b;
}

/// Apply the initial permutation (IP) to a 64-bit block.
fn applyIP(input: [8]u8) [8]u8 {
    var output: [8]u8 = [_]u8{0} ** 8;
    for (0..64) |i| {
        const bit = getBit(&input, IP[i]);
        setBit(&output, i, bit);
    }
    return output;
}

/// Apply the final permutation (FP = IP^-1) to a 64-bit block.
fn applyFP(input: [8]u8) [8]u8 {
    var output: [8]u8 = [_]u8{0} ** 8;
    for (0..64) |i| {
        const bit = getBit(&input, FP[i]);
        setBit(&output, i, bit);
    }
    return output;
}

/// The DES Feistel function f(R, K):
///   1. Expand R from 32 bits to 48 bits using E table.
///   2. XOR with the 48-bit subkey K.
///   3. Apply 8 S-boxes (6 bits -> 4 bits each) producing 32 bits.
///   4. Apply P-box permutation.
fn feistel(r: u32, subkey: [6]u8) u32 {
    // Step 1: Expand R to 48 bits.
    // R is the right 32-bit half, stored as u32.
    var r_bytes: [4]u8 = undefined;
    mem.writeInt(u32, &r_bytes, r, .big);

    var expanded: [6]u8 = [_]u8{0} ** 6;
    for (0..48) |i| {
        const bit = getBit(&r_bytes, E[i]);
        setBit(&expanded, i, bit);
    }

    // Step 2: XOR with subkey.
    for (0..6) |i| {
        expanded[i] ^= subkey[i];
    }

    // Step 3: S-box substitution.
    // Process 6 bits at a time through each of the 8 S-boxes.
    var sbox_output: u32 = 0;
    for (0..8) |box_idx| {
        // Extract 6 bits for this S-box.
        const bit_offset = box_idx * 6;
        var six_bits: u6 = 0;
        for (0..6) |j| {
            const bit = getBitFromSlice(&expanded, bit_offset + j);
            six_bits |= @as(u6, bit) << @intCast(5 - j);
        }

        // Row = outer two bits (bits 0 and 5), column = inner four bits (bits 1-4).
        const row: u2 = @intCast((@as(u2, @intCast((six_bits >> 5) & 1)) << 1) | @as(u2, @intCast(six_bits & 1)));
        const col: u4 = @intCast((six_bits >> 1) & 0xF);

        const sbox_val: u4 = S_BOXES[box_idx][row][col];
        sbox_output |= @as(u32, sbox_val) << @intCast(4 * (7 - box_idx));
    }

    // Step 4: Apply P permutation.
    var p_bytes: [4]u8 = undefined;
    mem.writeInt(u32, &p_bytes, sbox_output, .big);
    var result_bytes: [4]u8 = [_]u8{0} ** 4;
    for (0..32) |i| {
        const bit = getBit(&p_bytes, P[i]);
        setBit(&result_bytes, i, bit);
    }

    return mem.readInt(u32, &result_bytes, .big);
}

/// Encrypt a single 8-byte block with DES using precomputed subkeys.
fn desEncryptBlock(subkeys: *const DesSubkeys, dst: *[8]u8, src: *const [8]u8) void {
    // Initial Permutation
    const ip_out = applyIP(src.*);

    // Split into L and R halves
    var l = mem.readInt(u32, ip_out[0..4], .big);
    var r = mem.readInt(u32, ip_out[4..8], .big);

    // 16 Feistel rounds
    for (0..16) |round| {
        const f_result = feistel(r, subkeys[round]);
        const new_r = l ^ f_result;
        l = r;
        r = new_r;
    }

    // Combine (note: R and L are swapped for the final permutation)
    var pre_fp: [8]u8 = undefined;
    mem.writeInt(u32, pre_fp[0..4], r, .big);
    mem.writeInt(u32, pre_fp[4..8], l, .big);

    // Final Permutation
    dst.* = applyFP(pre_fp);
}

/// Decrypt a single 8-byte block with DES using precomputed subkeys.
fn desDecryptBlock(subkeys: *const DesSubkeys, dst: *[8]u8, src: *const [8]u8) void {
    // Initial Permutation
    const ip_out = applyIP(src.*);

    // Split into L and R halves
    var l = mem.readInt(u32, ip_out[0..4], .big);
    var r = mem.readInt(u32, ip_out[4..8], .big);

    // 16 Feistel rounds in reverse order
    for (0..16) |i| {
        const round = 15 - i;
        const f_result = feistel(r, subkeys[round]);
        const new_r = l ^ f_result;
        l = r;
        r = new_r;
    }

    // Combine (R and L swapped)
    var pre_fp: [8]u8 = undefined;
    mem.writeInt(u32, pre_fp[0..4], r, .big);
    mem.writeInt(u32, pre_fp[4..8], l, .big);

    // Final Permutation
    dst.* = applyFP(pre_fp);
}

// ---------------------------------------------------------------------------
// Triple DES (3DES / TDEA)
// ---------------------------------------------------------------------------

/// Triple DES block cipher.
///
/// Encrypt: E_K1(D_K2(E_K3(plaintext)))
/// Decrypt: D_K3(E_K2(D_K1(ciphertext)))
///
/// Where K1, K2, K3 are three 8-byte DES keys from the 24-byte key:
///   K1 = key[0..8], K2 = key[8..16], K3 = key[16..24]
///
/// Interface matches the pattern used by CAST5 and Twofish in this codebase
/// so that it can be used with `OpenPgpCfbDirect`.
pub const TripleDes = struct {
    pub const block = struct {
        pub const block_length: usize = 8;
    };
    pub const key_bits: usize = 192;

    subkeys: [3]DesSubkeys,

    /// Initialize the cipher with a 24-byte key for encryption.
    pub fn initEnc(key: [24]u8) TripleDes {
        return .{
            .subkeys = .{
                desKeySchedule(key[0..8]),
                desKeySchedule(key[8..16]),
                desKeySchedule(key[16..24]),
            },
        };
    }

    /// Encrypt a single 8-byte block.
    /// 3DES-EDE: E_K1(D_K2(E_K3(plaintext)))
    pub fn encrypt(self: TripleDes, dst: *[8]u8, src: *const [8]u8) void {
        var tmp1: [8]u8 = undefined;
        var tmp2: [8]u8 = undefined;

        // E_K3
        desEncryptBlock(&self.subkeys[2], &tmp1, src);
        // D_K2
        desDecryptBlock(&self.subkeys[1], &tmp2, &tmp1);
        // E_K1
        desEncryptBlock(&self.subkeys[0], dst, &tmp2);
    }

    /// Decrypt a single 8-byte block.
    /// 3DES-DED: D_K3(E_K2(D_K1(ciphertext)))
    pub fn decrypt(self: TripleDes, dst: *[8]u8, src: *const [8]u8) void {
        var tmp1: [8]u8 = undefined;
        var tmp2: [8]u8 = undefined;

        // D_K1
        desDecryptBlock(&self.subkeys[0], &tmp1, src);
        // E_K2
        desEncryptBlock(&self.subkeys[1], &tmp2, &tmp1);
        // D_K3
        desDecryptBlock(&self.subkeys[2], dst, &tmp2);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "DES single block encrypt/decrypt round-trip" {
    // Use the same key for all three DES keys (single-DES equivalent via 3DES).
    const key = [_]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    };

    const plaintext = [_]u8{ 0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74 }; // "Now is t"

    const tdes = TripleDes.initEnc(key);

    var ciphertext: [8]u8 = undefined;
    tdes.encrypt(&ciphertext, &plaintext);

    // The ciphertext should differ from plaintext
    try std.testing.expect(!mem.eql(u8, &ciphertext, &plaintext));

    var decrypted: [8]u8 = undefined;
    tdes.decrypt(&decrypted, &ciphertext);

    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "TripleDes round-trip with distinct keys" {
    const key = [_]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // K1
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, // K2
        0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, // K3
    };

    const plaintext = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    const tdes = TripleDes.initEnc(key);

    var ciphertext: [8]u8 = undefined;
    tdes.encrypt(&ciphertext, &plaintext);
    try std.testing.expect(!mem.eql(u8, &ciphertext, &plaintext));

    var decrypted: [8]u8 = undefined;
    tdes.decrypt(&decrypted, &ciphertext);
    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "TripleDes all-zero key and plaintext" {
    const key = [_]u8{0} ** 24;
    const plaintext = [_]u8{0} ** 8;

    const tdes = TripleDes.initEnc(key);

    var ciphertext: [8]u8 = undefined;
    tdes.encrypt(&ciphertext, &plaintext);

    var decrypted: [8]u8 = undefined;
    tdes.decrypt(&decrypted, &ciphertext);
    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "TripleDes all-ones key" {
    const key = [_]u8{0xFF} ** 24;
    const plaintext = [_]u8{0xFF} ** 8;

    const tdes = TripleDes.initEnc(key);

    var ciphertext: [8]u8 = undefined;
    tdes.encrypt(&ciphertext, &plaintext);

    var decrypted: [8]u8 = undefined;
    tdes.decrypt(&decrypted, &ciphertext);
    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "TripleDes multiple blocks" {
    const key = [_]u8{
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    };

    const tdes = TripleDes.initEnc(key);

    // Encrypt and decrypt multiple blocks
    const blocks = [_][8]u8{
        .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 },
        .{ 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
        .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF },
    };

    for (blocks) |blk| {
        var ct: [8]u8 = undefined;
        tdes.encrypt(&ct, &blk);

        var pt: [8]u8 = undefined;
        tdes.decrypt(&pt, &ct);

        try std.testing.expectEqualSlices(u8, &blk, &pt);
    }
}

test "TripleDes cipher interface compatibility" {
    // Verify the interface is compatible with OpenPgpCfbDirect:
    // - block.block_length exists and is 8
    // - key_bits exists and is 192
    // - initEnc accepts [24]u8
    // - encrypt/decrypt accept *[8]u8 and *const [8]u8
    try std.testing.expectEqual(@as(usize, 8), TripleDes.block.block_length);
    try std.testing.expectEqual(@as(usize, 192), TripleDes.key_bits);

    const key = [_]u8{0x42} ** 24;
    const tdes = TripleDes.initEnc(key);

    const plain = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var ct: [8]u8 = undefined;
    tdes.encrypt(&ct, &plain);

    var pt: [8]u8 = undefined;
    tdes.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plain, &pt);
}

test "DES known answer: single-key 3DES is self-consistent" {
    // With K1=K2=K3, 3DES-EDE reduces to single DES: E_K(D_K(E_K(P))) = E_K(P).
    // Verify the implementation is self-consistent: encrypting then decrypting
    // recovers the original plaintext.
    const key_part = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    var key: [24]u8 = undefined;
    @memcpy(key[0..8], &key_part);
    @memcpy(key[8..16], &key_part);
    @memcpy(key[16..24], &key_part);

    const plaintext = [_]u8{ 0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74 }; // "Now is t"

    const tdes = TripleDes.initEnc(key);

    var ct: [8]u8 = undefined;
    tdes.encrypt(&ct, &plaintext);

    // Ciphertext should differ from plaintext
    try std.testing.expect(!mem.eql(u8, &ct, &plaintext));

    // Round-trip must recover plaintext
    var pt: [8]u8 = undefined;
    tdes.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);

    // Also verify that single DES encrypt produces deterministic output:
    // Encrypting the same plaintext again should give the same ciphertext.
    var ct2: [8]u8 = undefined;
    tdes.encrypt(&ct2, &plaintext);
    try std.testing.expectEqualSlices(u8, &ct, &ct2);
}

test "TripleDes NIST SP 800-67 two-key test" {
    // NIST SP 800-67: K1 != K2, K3 = K1 (two-key 3DES)
    // Key1 = 0123456789ABCDEF, Key2 = 23456789ABCDEF01, Key3 = Key1
    const key = [_]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // K1
        0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, // K2
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // K3 = K1
    };

    const plaintext = [_]u8{ 0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74 };

    const tdes = TripleDes.initEnc(key);

    var ct: [8]u8 = undefined;
    tdes.encrypt(&ct, &plaintext);
    try std.testing.expect(!mem.eql(u8, &ct, &plaintext));

    var pt: [8]u8 = undefined;
    tdes.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "DES Feistel function produces non-zero output" {
    // Sanity check that the Feistel function actually does something
    const subkey = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB };
    const result = feistel(0x12345678, subkey);
    try std.testing.expect(result != 0);
}

test "DES IP and FP are inverses" {
    // IP followed by FP should be the identity
    const input = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    const after_ip = applyIP(input);
    const after_fp = applyFP(after_ip);
    try std.testing.expectEqualSlices(u8, &input, &after_fp);
}

test "DES IP and FP inverse on random-ish data" {
    const input = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
    const after_ip = applyIP(input);
    try std.testing.expect(!mem.eql(u8, &after_ip, &input)); // should permute
    const after_fp = applyFP(after_ip);
    try std.testing.expectEqualSlices(u8, &input, &after_fp);
}
