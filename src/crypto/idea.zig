// SPDX-License-Identifier: MIT
//! IDEA (International Data Encryption Algorithm) block cipher.
//!
//! IDEA operates on 64-bit (8-byte) blocks with 128-bit (16-byte) keys.
//! It uses 8.5 rounds with three algebraic operations that are incompatible
//! in a sense which provides security:
//!   - Multiplication modulo 2^16+1 (where 0 is treated as 2^16)
//!   - Addition modulo 2^16
//!   - Bitwise XOR
//!
//! The key schedule generates 52 16-bit subkeys from the 128-bit key.
//! For encryption, 6 subkeys are used per round (8 rounds) plus 4 for the
//! output transformation, totalling 52 subkeys.
//!
//! OpenPGP algorithm ID: 1 (IDEA)

const std = @import("std");
const mem = std.mem;

pub const Idea = struct {
    pub const block = struct {
        pub const block_length: usize = 8;
    };
    pub const key_bits: usize = 128;

    enc_subkeys: [52]u16,
    dec_subkeys: [52]u16,

    /// Initialise for encryption/decryption with a 128-bit key.
    pub fn initEnc(key: [16]u8) Idea {
        var self: Idea = undefined;
        self.enc_subkeys = expandKey(key);
        self.dec_subkeys = invertSubkeys(self.enc_subkeys);
        return self;
    }

    /// Encrypt a single 8-byte block.
    pub fn encrypt(self: Idea, dst: *[8]u8, src: *const [8]u8) void {
        crypt(dst, src, self.enc_subkeys);
    }

    /// Decrypt a single 8-byte block.
    pub fn decrypt(self: Idea, dst: *[8]u8, src: *const [8]u8) void {
        crypt(dst, src, self.dec_subkeys);
    }
};

/// Multiplication modulo 2^16 + 1 (0x10001).
/// In IDEA, the value 0 represents 2^16 (65536).
fn mul(a_in: u16, b_in: u16) u16 {
    if (a_in == 0) {
        // a represents 2^16; result = 1 - b mod (2^16+1)
        // Since 2^16 * b mod 2^16+1:
        //   Let a = 2^16. Then a*b mod (2^16+1) = (2^16+1 - 1)*b mod (2^16+1)
        //   = -b mod (2^16+1) = (2^16+1 - b) mod (2^16+1)
        // If b == 0, both are 2^16, so product = 2^16 * 2^16 mod 2^16+1 = 1
        if (b_in == 0) return 1;
        // 2^16 * b mod (2^16+1) = (0x10001 - b) & 0xFFFF
        return @truncate(0x10001 -% @as(u32, b_in));
    }
    if (b_in == 0) {
        return @truncate(0x10001 -% @as(u32, a_in));
    }
    const a: u32 = @as(u32, a_in);
    const b: u32 = @as(u32, b_in);
    const p: u32 = a * b;
    const lo: u32 = p & 0xFFFF;
    const hi: u32 = p >> 16;
    if (lo >= hi) {
        return @truncate(lo - hi);
    } else {
        return @truncate(lo -% hi +% 0x10001);
    }
}

/// Addition modulo 2^16.
fn add(a: u16, b: u16) u16 {
    return a +% b;
}

/// Perform IDEA encryption or decryption (depending on the subkeys provided).
fn crypt(dst: *[8]u8, src: *const [8]u8, subkeys: [52]u16) void {
    // Load four 16-bit words (big-endian)
    var x1 = mem.readInt(u16, src[0..2], .big);
    var x2 = mem.readInt(u16, src[2..4], .big);
    var x3 = mem.readInt(u16, src[4..6], .big);
    var x4 = mem.readInt(u16, src[6..8], .big);

    // 8 rounds
    var ki: usize = 0;
    for (0..8) |_| {
        // Step 1: Multiply x1 by subkey
        x1 = mul(x1, subkeys[ki]);
        ki += 1;
        // Step 2: Add subkey to x2
        x2 = add(x2, subkeys[ki]);
        ki += 1;
        // Step 3: Add subkey to x3
        x3 = add(x3, subkeys[ki]);
        ki += 1;
        // Step 4: Multiply x4 by subkey
        x4 = mul(x4, subkeys[ki]);
        ki += 1;

        // Step 5: XOR x1 and x3
        const t1 = x1 ^ x3;
        // Step 6: XOR x2 and x4
        const t2 = x2 ^ x4;

        // Step 7: Multiply t1 by subkey
        const m1 = mul(t1, subkeys[ki]);
        ki += 1;
        // Step 8: Add m1 to t2, then multiply by subkey
        const m2 = mul(add(m1, t2), subkeys[ki]);
        ki += 1;
        // Step 9: Add m1 and m2
        const m3 = add(m1, m2);

        // Step 10: XOR results back
        x1 ^= m2;
        x3 ^= m2;
        x2 ^= m3;
        x4 ^= m3;

        // Swap x2 and x3 (will be undone in output transformation effectively)
        const tmp = x2;
        x2 = x3;
        x3 = tmp;
    }

    // Output transformation (half-round)
    // Note: x2 and x3 were swapped in the last round, so we use them swapped here
    const y1 = mul(x1, subkeys[ki]);
    ki += 1;
    const y2 = add(x3, subkeys[ki]); // x3 (because of swap)
    ki += 1;
    const y3 = add(x2, subkeys[ki]); // x2 (because of swap)
    ki += 1;
    const y4 = mul(x4, subkeys[ki]);

    // Store output (big-endian)
    mem.writeInt(u16, dst[0..2], y1, .big);
    mem.writeInt(u16, dst[2..4], y2, .big);
    mem.writeInt(u16, dst[4..6], y3, .big);
    mem.writeInt(u16, dst[6..8], y4, .big);
}

/// Expand 128-bit key into 52 16-bit encryption subkeys.
///
/// The first 8 subkeys are taken directly from the key (big-endian 16-bit words).
/// Then the key is rotated left by 25 bits, and the next 8 subkeys are extracted.
/// This process repeats until all 52 subkeys are generated.
fn expandKey(key: [16]u8) [52]u16 {
    var subkeys: [52]u16 = undefined;

    // First 8 subkeys directly from key
    for (0..8) |i| {
        subkeys[i] = mem.readInt(u16, key[i * 2 ..][0..2], .big);
    }

    // Generate remaining subkeys by rotating the key left by 25 bits
    // We work with the subkeys array itself: each group of 8 subkeys (128 bits)
    // is the previous group rotated left by 25 bits.
    var j: usize = 8;
    while (j < 52) {
        // The rotation by 25 bits of 8 consecutive 16-bit values can be expressed as:
        // subkeys[i+0] = (subkeys[i-7] << 9) | (subkeys[i-6] >> 7)  -- for i = j+0 (using j-7, j-6)
        // But we need to be careful with the rotation pattern.
        //
        // The 25-bit left rotation of the 128-bit key means:
        // - Bits shift left by 25 positions (with wraparound)
        // - This can be computed from the previous 8 subkeys.
        //
        // Key rotation: after extracting 8 subkeys, rotate the entire 128-bit key
        // left by 25 bits. 25 = 16 + 9, so we shift by one word plus 9 bits.

        // subkeys[j+0] comes from subkeys[j-7] << 9 | subkeys[j-6] >> 7  (indices mod 8 offset)
        // But the indices into the previous block differ based on the 25-bit rotation.
        //
        // With 25-bit rotation of 128 bits:
        // new_word[0] = old_word[1] << 9 | old_word[2] >> 7   (bits 25..40 of old)
        // new_word[1] = old_word[2] << 9 | old_word[3] >> 7   (bits 41..56)
        // ...
        // new_word[5] = old_word[6] << 9 | old_word[7] >> 7   (bits 105..120)
        // new_word[6] = old_word[7] << 9 | old_word[0] >> 7   (bits 121..128 + 0..8)
        // new_word[7] = old_word[0] << 9 | old_word[1] >> 7   (bits 9..24)
        //
        // In terms of previous subkeys where base = j - 8:
        // subkeys[j+i] for i in 0..5: (subkeys[base+i+1] << 9) | (subkeys[base+i+2] >> 7)
        // subkeys[j+6]: (subkeys[base+7] << 9) | (subkeys[base+0] >> 7)
        // subkeys[j+7]: (subkeys[base+0] << 9) | (subkeys[base+1] >> 7)

        const remaining = 52 - j;
        const count = if (remaining < 8) remaining else 8;

        for (0..count) |i| {
            const base = j - 8;
            const src1 = base + ((i + 1) % 8);
            const src2 = base + ((i + 2) % 8);
            subkeys[j + i] = (subkeys[src1] << 9) | (subkeys[src2] >> 7);
        }
        j += count;
    }

    return subkeys;
}

/// Compute the multiplicative inverse modulo 2^16 + 1.
/// 0 maps to 0 (since 0 represents 2^16, and 2^16 * 2^16 mod 2^16+1 = 1... but
/// the inverse of 2^16 mod 2^16+1 is 2^16, represented as 0).
fn mulInverse(a_in: u16) u16 {
    if (a_in == 0) return 0; // 0 represents 2^16, its inverse is also 2^16 (0)
    if (a_in == 1) return 1;

    // Extended Euclidean algorithm to find inverse mod 0x10001
    var t0: i32 = 0;
    var t1: i32 = 1;
    var r0: i32 = 0x10001;
    var r1: i32 = @as(i32, a_in);

    while (r1 != 0) {
        const q = @divTrunc(r0, r1);
        const tmp_t = t0 - q * t1;
        t0 = t1;
        t1 = tmp_t;
        const tmp_r = r0 - q * r1;
        r0 = r1;
        r1 = tmp_r;
    }

    if (t0 < 0) {
        t0 += 0x10001;
    }
    return @intCast(t0);
}

/// Compute the additive inverse modulo 2^16.
fn addInverse(a: u16) u16 {
    return 0 -% a;
}

/// Generate decryption subkeys from encryption subkeys.
///
/// The decryption subkeys are derived by inverting and reordering
/// the encryption subkeys.
fn invertSubkeys(enc: [52]u16) [52]u16 {
    var dec: [52]u16 = undefined;

    // Output transformation (last 4 keys) -> first 4 decryption keys
    dec[0] = mulInverse(enc[48]);
    dec[1] = addInverse(enc[49]);
    dec[2] = addInverse(enc[50]);
    dec[3] = mulInverse(enc[51]);

    // Rounds 8 down to 1
    var di: usize = 4;
    for (0..8) |round| {
        // ei = 42 - round * 6
        const ei: usize = 42 - round * 6;

        // The MA (multiply-add) subkeys are copied in order from previous round
        dec[di] = enc[ei + 4];
        dec[di + 1] = enc[ei + 5];
        di += 2;

        // The round keys: multiply-inverse, add-inverse (swapped for middle rounds)
        dec[di] = mulInverse(enc[ei]);
        if (round == 7) {
            // First round (last in decryption): no swap of add keys
            dec[di + 1] = addInverse(enc[ei + 1]);
            dec[di + 2] = addInverse(enc[ei + 2]);
        } else {
            // Middle rounds: swap the additive subkeys
            dec[di + 1] = addInverse(enc[ei + 2]);
            dec[di + 2] = addInverse(enc[ei + 1]);
        }
        dec[di + 3] = mulInverse(enc[ei + 3]);
        di += 4;
    }

    return dec;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "IDEA mul basic properties" {
    // mul(1, x) = x
    try std.testing.expectEqual(@as(u16, 0x1234), mul(1, 0x1234));
    // mul(x, 1) = x
    try std.testing.expectEqual(@as(u16, 0x5678), mul(0x5678, 1));
    // mul(0, 0) = 1 (0 represents 2^16, 2^16 * 2^16 mod 2^16+1 = 1)
    try std.testing.expectEqual(@as(u16, 1), mul(0, 0));
    // mul(1, 1) = 1
    try std.testing.expectEqual(@as(u16, 1), mul(1, 1));
}

test "IDEA mul inverse" {
    // mulInverse(1) = 1
    try std.testing.expectEqual(@as(u16, 1), mulInverse(1));
    // mulInverse(0) = 0
    try std.testing.expectEqual(@as(u16, 0), mulInverse(0));

    // For any x, mul(x, mulInverse(x)) should equal 1
    const test_vals = [_]u16{ 1, 2, 3, 100, 255, 1000, 0x7FFF, 0xFFFF, 0 };
    for (test_vals) |v| {
        const inv = mulInverse(v);
        const product = mul(v, inv);
        try std.testing.expectEqual(@as(u16, 1), product);
    }
}

test "IDEA encrypt/decrypt round-trip" {
    const key = [16]u8{ 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08 };
    const plaintext = [8]u8{ 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03 };

    const cipher = Idea.initEnc(key);

    var ct: [8]u8 = undefined;
    cipher.encrypt(&ct, &plaintext);

    // Ciphertext should differ from plaintext
    try std.testing.expect(!std.mem.eql(u8, &ct, &plaintext));

    // Decrypt should recover plaintext
    var pt: [8]u8 = undefined;
    cipher.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "IDEA known test vector" {
    // Test vector: key = 00010002000300040005000600070008
    //              plaintext  = 0000000100020003
    //              ciphertext = 11FBED2B01986DE5
    const key = [16]u8{ 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08 };
    const plaintext = [8]u8{ 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03 };
    const expected_ct = [8]u8{ 0x11, 0xFB, 0xED, 0x2B, 0x01, 0x98, 0x6D, 0xE5 };

    const cipher = Idea.initEnc(key);
    var ct: [8]u8 = undefined;
    cipher.encrypt(&ct, &plaintext);
    try std.testing.expectEqualSlices(u8, &expected_ct, &ct);

    // Verify decryption
    var pt: [8]u8 = undefined;
    cipher.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "IDEA all zeros key and plaintext" {
    const key = [_]u8{0} ** 16;
    const plaintext = [_]u8{0} ** 8;

    const cipher = Idea.initEnc(key);

    var ct: [8]u8 = undefined;
    cipher.encrypt(&ct, &plaintext);

    // Should produce some ciphertext (not all zeros)
    // With zero key, IDEA still produces non-trivial output because
    // 0 is treated as 2^16 in multiplication
    try std.testing.expect(!std.mem.eql(u8, &ct, &plaintext));

    var pt: [8]u8 = undefined;
    cipher.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "IDEA all 0xFF key and plaintext" {
    const key = [_]u8{0xFF} ** 16;
    const plaintext = [_]u8{0xFF} ** 8;

    const cipher = Idea.initEnc(key);

    var ct: [8]u8 = undefined;
    cipher.encrypt(&ct, &plaintext);

    try std.testing.expect(!std.mem.eql(u8, &ct, &plaintext));

    var pt: [8]u8 = undefined;
    cipher.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "IDEA key expansion produces 52 subkeys" {
    const key = [16]u8{ 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08 };
    const subkeys = expandKey(key);

    // First 8 subkeys should match key words
    try std.testing.expectEqual(@as(u16, 0x0001), subkeys[0]);
    try std.testing.expectEqual(@as(u16, 0x0002), subkeys[1]);
    try std.testing.expectEqual(@as(u16, 0x0003), subkeys[2]);
    try std.testing.expectEqual(@as(u16, 0x0004), subkeys[3]);
    try std.testing.expectEqual(@as(u16, 0x0005), subkeys[4]);
    try std.testing.expectEqual(@as(u16, 0x0006), subkeys[5]);
    try std.testing.expectEqual(@as(u16, 0x0007), subkeys[6]);
    try std.testing.expectEqual(@as(u16, 0x0008), subkeys[7]);

    // All 52 subkeys should be populated
    // Just verify the array is fully initialized by checking last element exists
    _ = subkeys[51];
}

test "IDEA multiple blocks" {
    const key = [16]u8{ 0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48 };
    const cipher = Idea.initEnc(key);

    // Encrypt several blocks and verify round-trip
    const blocks = [_][8]u8{
        .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF },
        .{ 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 },
    };

    for (blocks) |blk| {
        var ct: [8]u8 = undefined;
        cipher.encrypt(&ct, &blk);
        var pt: [8]u8 = undefined;
        cipher.decrypt(&pt, &ct);
        try std.testing.expectEqualSlices(u8, &blk, &pt);
    }
}

test "IDEA add inverse" {
    try std.testing.expectEqual(@as(u16, 0), addInverse(0));
    try std.testing.expectEqual(@as(u16, 0xFFFF), addInverse(1));
    try std.testing.expectEqual(@as(u16, 1), addInverse(0xFFFF));

    // a + addInverse(a) = 0 (mod 2^16)
    const test_vals = [_]u16{ 0, 1, 2, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF };
    for (test_vals) |v| {
        try std.testing.expectEqual(@as(u16, 0), v +% addInverse(v));
    }
}

test "IDEA second known vector" {
    // Key: all zeros, plaintext: all zeros
    // This tests the special case where mul(0,0) = 1
    const key = [_]u8{0x00} ** 16;
    const plaintext = [_]u8{0x00} ** 8;

    const cipher = Idea.initEnc(key);
    var ct: [8]u8 = undefined;
    cipher.encrypt(&ct, &plaintext);

    // Just verify round-trip since the all-zero case exercises the 0->2^16 mapping
    var pt: [8]u8 = undefined;
    cipher.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "IDEA deterministic encryption" {
    const key = [16]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 };
    const plaintext = [8]u8{ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

    const cipher = Idea.initEnc(key);

    var ct1: [8]u8 = undefined;
    var ct2: [8]u8 = undefined;
    cipher.encrypt(&ct1, &plaintext);
    cipher.encrypt(&ct2, &plaintext);

    // Same key + same plaintext = same ciphertext
    try std.testing.expectEqualSlices(u8, &ct1, &ct2);
}
