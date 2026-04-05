// SPDX-License-Identifier: MIT
//! OCB3 (Offset Codebook) authenticated encryption mode per RFC 7253.
//!
//! OCB is a single-pass authenticated encryption mode that provides both
//! confidentiality and authenticity with minimal overhead.
//!
//! Key concepts:
//! - L_* = AES(K, zeros)
//! - L_$ = double(L_*)
//! - L_i = double(L_{i-1}) for i >= 0, L_0 = double(L_$)
//! - double() = shift left in GF(2^128) with polynomial x^128 + x^7 + x^2 + x + 1
//! - ntz(i) = number of trailing zeros in binary representation of i

const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const aes = crypto.core.aes;

/// OCB3 authenticated encryption mode for 128-bit block ciphers.
pub fn Ocb(comptime Aes: type) type {
    return struct {
        const Self = @This();
        pub const block_size: usize = 16;
        pub const tag_size: usize = 16;
        pub const key_size: usize = Aes.key_bits / 8;
        pub const max_nonce_size: usize = 15;

        /// Precomputed L table depth. Supports messages up to 2^32 blocks.
        const L_TABLE_SIZE = 32;

        cipher: aes.AesEncryptCtx(Aes),
        decipher: aes.AesDecryptCtx(Aes),
        l_star: [16]u8,
        l_dollar: [16]u8,
        l_table: [L_TABLE_SIZE][16]u8,

        pub fn init(key: [key_size]u8) Self {
            const ctx = Aes.initEnc(key);

            // L_* = AES(K, 0^128)
            const zero_block = [_]u8{0} ** 16;
            var l_star: [16]u8 = undefined;
            ctx.encrypt(&l_star, &zero_block);

            // L_$ = double(L_*)
            const l_dollar = gfDouble(l_star);

            // L_0 = double(L_$), L_i = double(L_{i-1})
            var l_table: [L_TABLE_SIZE][16]u8 = undefined;
            l_table[0] = gfDouble(l_dollar);
            for (1..L_TABLE_SIZE) |i| {
                l_table[i] = gfDouble(l_table[i - 1]);
            }

            return .{
                .cipher = ctx,
                .decipher = aes.AesDecryptCtx(Aes).initFromEnc(ctx),
                .l_star = l_star,
                .l_dollar = l_dollar,
                .l_table = l_table,
            };
        }

        /// Encrypt plaintext and produce authentication tag.
        /// nonce must be at most 15 bytes (120 bits). For OpenPGP, it is 15 bytes.
        /// tag_len: number of bytes to use from the tag (OpenPGP uses 16).
        pub fn encrypt(
            self: Self,
            ciphertext: []u8,
            tag: *[tag_size]u8,
            plaintext: []const u8,
            nonce: []const u8,
            ad: []const u8,
        ) void {
            std.debug.assert(ciphertext.len == plaintext.len);
            std.debug.assert(nonce.len >= 1 and nonce.len <= max_nonce_size);

            // Compute initial offset from nonce
            var offset = self.computeInitialOffset(nonce);

            // Process full blocks
            const full_blocks = plaintext.len / 16;
            var checksum = [_]u8{0} ** 16;

            for (0..full_blocks) |i| {
                const block_num: u32 = @intCast(i + 1);
                const ntz_val = ntz(block_num);

                // Offset_i = Offset_{i-1} XOR L_{ntz(i)}
                xorBlock(&offset, &self.l_table[ntz_val]);

                // Checksum_i = Checksum_{i-1} XOR M_i
                var m_i: [16]u8 = undefined;
                @memcpy(&m_i, plaintext[i * 16 ..][0..16]);
                xorBlock(&checksum, &m_i);

                // C_i = Offset_i XOR AES(K, M_i XOR Offset_i)
                var input: [16]u8 = undefined;
                for (&input, 0..) |*b, j| {
                    b.* = m_i[j] ^ offset[j];
                }
                var encrypted: [16]u8 = undefined;
                self.cipher.encrypt(&encrypted, &input);
                for (0..16) |j| {
                    ciphertext[i * 16 + j] = encrypted[j] ^ offset[j];
                }
            }

            // Process final partial block (if any)
            const remaining = plaintext.len - full_blocks * 16;
            if (remaining > 0) {
                // Offset_* = Offset_m XOR L_*
                xorBlock(&offset, &self.l_star);

                // Pad = AES(K, Offset_*)
                var pad: [16]u8 = undefined;
                self.cipher.encrypt(&pad, &offset);

                // C_* = M_* XOR Pad[1..len(M_*)]
                const final_start = full_blocks * 16;
                for (0..remaining) |j| {
                    ciphertext[final_start + j] = plaintext[final_start + j] ^ pad[j];
                }

                // Checksum_* = Checksum_m XOR (M_* || 1 || 0^...)
                var padded_last: [16]u8 = [_]u8{0} ** 16;
                @memcpy(padded_last[0..remaining], plaintext[final_start..][0..remaining]);
                padded_last[remaining] = 0x80;
                xorBlock(&checksum, &padded_last);
            }

            // Tag = AES(K, Checksum XOR Offset_* XOR L_$) XOR HASH(K, A)
            var tag_input: [16]u8 = undefined;
            for (&tag_input, 0..) |*b, j| {
                b.* = checksum[j] ^ offset[j] ^ self.l_dollar[j];
            }
            var raw_tag: [16]u8 = undefined;
            self.cipher.encrypt(&raw_tag, &tag_input);

            // XOR with HASH(K, ad)
            const ad_hash = self.hashAd(ad);
            for (tag, 0..) |*t, j| {
                t.* = raw_tag[j] ^ ad_hash[j];
            }
        }

        /// Decrypt ciphertext and verify authentication tag.
        pub fn decrypt(
            self: Self,
            plaintext: []u8,
            ciphertext: []const u8,
            tag: [tag_size]u8,
            nonce: []const u8,
            ad: []const u8,
        ) !void {
            std.debug.assert(plaintext.len == ciphertext.len);
            std.debug.assert(nonce.len >= 1 and nonce.len <= max_nonce_size);

            // Compute initial offset from nonce
            var offset = self.computeInitialOffset(nonce);

            // Process full blocks
            const full_blocks = ciphertext.len / 16;
            var checksum = [_]u8{0} ** 16;

            for (0..full_blocks) |i| {
                const block_num: u32 = @intCast(i + 1);
                const ntz_val = ntz(block_num);

                // Offset_i = Offset_{i-1} XOR L_{ntz(i)}
                xorBlock(&offset, &self.l_table[ntz_val]);

                // M_i = Offset_i XOR AES^{-1}(K, C_i XOR Offset_i)
                // Since we only have encryption context, we use the trick:
                // We stored the encrypt context, but OCB decryption needs
                // the AES decrypt for the main blocks. However, we can use
                // the property that OCB works with just encrypt for the tag.
                //
                // Actually, OCB3 decryption requires AES decrypt for full blocks.
                // We'll use a different approach: since we only have the encrypt
                // context, we recompute using the encrypt direction.
                //
                // The standard OCB decrypt uses AES^{-1} for full blocks.
                // For our implementation, we'll use the Zig AES decrypt context.
                var c_i: [16]u8 = undefined;
                @memcpy(&c_i, ciphertext[i * 16 ..][0..16]);

                var input: [16]u8 = undefined;
                for (&input, 0..) |*b, j| {
                    b.* = c_i[j] ^ offset[j];
                }

                // Decrypt using the precomputed decrypt context
                var dec_block: [16]u8 = undefined;
                self.decipher.decrypt(&dec_block, &input);

                for (0..16) |j| {
                    plaintext[i * 16 + j] = dec_block[j] ^ offset[j];
                }

                // Checksum
                var m_i: [16]u8 = undefined;
                @memcpy(&m_i, plaintext[i * 16 ..][0..16]);
                xorBlock(&checksum, &m_i);
            }

            // Process final partial block (if any)
            const remaining = ciphertext.len - full_blocks * 16;
            if (remaining > 0) {
                // Offset_* = Offset_m XOR L_*
                xorBlock(&offset, &self.l_star);

                // Pad = AES(K, Offset_*)
                var pad: [16]u8 = undefined;
                self.cipher.encrypt(&pad, &offset);

                // M_* = C_* XOR Pad[1..len(C_*)]
                const final_start = full_blocks * 16;
                for (0..remaining) |j| {
                    plaintext[final_start + j] = ciphertext[final_start + j] ^ pad[j];
                }

                // Checksum_* = Checksum_m XOR (M_* || 1 || 0^...)
                var padded_last: [16]u8 = [_]u8{0} ** 16;
                @memcpy(padded_last[0..remaining], plaintext[final_start..][0..remaining]);
                padded_last[remaining] = 0x80;
                xorBlock(&checksum, &padded_last);
            }

            // Tag = AES(K, Checksum XOR Offset_* XOR L_$) XOR HASH(K, A)
            var tag_input: [16]u8 = undefined;
            for (&tag_input, 0..) |*b, j| {
                b.* = checksum[j] ^ offset[j] ^ self.l_dollar[j];
            }
            var expected_tag: [16]u8 = undefined;
            self.cipher.encrypt(&expected_tag, &tag_input);

            const ad_hash = self.hashAd(ad);
            for (&expected_tag, 0..) |*t, j| {
                t.* ^= ad_hash[j];
            }

            // Verify tag
            if (!crypto.timing_safe.eql([tag_size]u8, expected_tag, tag)) {
                // Zero plaintext on failure
                @memset(plaintext, 0);
                return error.AuthenticationFailed;
            }
        }

        /// Compute the OCB HASH function for associated data.
        fn hashAd(self: Self, ad: []const u8) [16]u8 {
            var sum = [_]u8{0} ** 16;
            var offset = [_]u8{0} ** 16;

            const full_blocks = ad.len / 16;

            for (0..full_blocks) |i| {
                const block_num: u32 = @intCast(i + 1);
                const ntz_val = ntz(block_num);

                xorBlock(&offset, &self.l_table[ntz_val]);

                var input: [16]u8 = undefined;
                for (&input, 0..) |*b, j| {
                    b.* = ad[i * 16 + j] ^ offset[j];
                }
                var encrypted: [16]u8 = undefined;
                self.cipher.encrypt(&encrypted, &input);
                xorBlock(&sum, &encrypted);
            }

            // Final partial block
            const remaining = ad.len - full_blocks * 16;
            if (remaining > 0) {
                // Offset_* = Offset_m XOR L_*
                xorBlock(&offset, &self.l_star);

                // Sum = Sum XOR AES(K, (A_* || 1 || 0^...) XOR Offset_*)
                var padded: [16]u8 = [_]u8{0} ** 16;
                @memcpy(padded[0..remaining], ad[full_blocks * 16 ..][0..remaining]);
                padded[remaining] = 0x80;

                var input: [16]u8 = undefined;
                for (&input, 0..) |*b, j| {
                    b.* = padded[j] ^ offset[j];
                }
                var encrypted: [16]u8 = undefined;
                self.cipher.encrypt(&encrypted, &input);
                xorBlock(&sum, &encrypted);
            }

            return sum;
        }

        /// Compute the initial offset (Offset_0) from the nonce per RFC 7253.
        ///
        /// Nonce = num2str(TAGLEN mod 128, 7) || zeros(120 - bitlen(N)) || 1 || N
        /// (all packed into a 128-bit string)
        ///
        /// bottom = Nonce[123..128] (last 6 bits)
        /// Ktop = AES(K, Nonce[0..122] || zeros(6))
        /// Stretch = Ktop || (Ktop[0..63] XOR Ktop[8..71])
        /// Offset_0 = Stretch[bottom..bottom+127]
        fn computeInitialOffset(self: Self, nonce: []const u8) [16]u8 {
            // Build the full 128-bit nonce per RFC 7253 Section 3.2
            // tag_len is always 16 bytes (128 bits) for OpenPGP
            // So TAGLEN mod 128 = 0, meaning the first 7 bits are 0
            var nonce_block = [_]u8{0} ** 16;

            // Place the nonce at the end, right-aligned
            const nonce_start = 16 - nonce.len;
            @memcpy(nonce_block[nonce_start..], nonce);

            // Set the bit just before the nonce: the "1" separator
            // This is bit (120 - nonce.len*8), counting from bit 7 (MSB of first byte)
            // The byte is at position (nonce_start - 1) if nonce_start > 0
            if (nonce_start > 0) {
                nonce_block[nonce_start - 1] |= 0x01;
            }

            // Set the tag-length indicator in the first byte
            // TAGLEN mod 128 = 0 for 16-byte tags, so first 7 bits are 0
            // (already zero from initialization)

            // bottom = last 6 bits of the nonce block
            const bottom: u6 = @truncate(nonce_block[15] & 0x3F);

            // Clear bottom 6 bits to form the block to encrypt
            nonce_block[15] &= 0xC0;

            // Ktop = AES(K, nonce_block)
            var ktop: [16]u8 = undefined;
            self.cipher.encrypt(&ktop, &nonce_block);

            // Stretch = Ktop || (Ktop[0..7] XOR Ktop[1..8])
            var stretch: [24]u8 = undefined;
            @memcpy(stretch[0..16], &ktop);
            for (0..8) |i| {
                stretch[16 + i] = ktop[i] ^ ktop[i + 1];
            }

            // Offset_0 = Stretch[bottom..bottom+127] (bit extraction)
            return extractBits(&stretch, bottom);
        }
    };
}

/// Extract 128 bits starting at bit position `bit_offset` from a byte array.
fn extractBits(stretch: *const [24]u8, bit_offset: u6) [16]u8 {
    var result: [16]u8 = undefined;
    const byte_offset: usize = @as(usize, bit_offset) / 8;
    const bit_shift: u3 = @truncate(@as(usize, bit_offset) % 8);

    if (bit_shift == 0) {
        @memcpy(&result, stretch[byte_offset..][0..16]);
    } else {
        for (0..16) |i| {
            const hi: u8 = stretch[byte_offset + i];
            const lo: u8 = stretch[byte_offset + i + 1];
            result[i] = (hi << bit_shift) | (lo >> (@as(u3, 7) - bit_shift + 1));
        }
    }

    return result;
}

/// Double a value in GF(2^128) with polynomial x^128 + x^7 + x^2 + x + 1.
fn gfDouble(input: [16]u8) [16]u8 {
    var output: [16]u8 = undefined;
    const carry = input[0] >> 7;

    for (0..15) |i| {
        output[i] = (input[i] << 1) | (input[i + 1] >> 7);
    }
    output[15] = input[15] << 1;

    if (carry == 1) {
        output[15] ^= 0x87;
    }

    return output;
}

/// Number of trailing zeros in a u32 value.
/// Returns at most 31, which fits in u5.
fn ntz(n: u32) u5 {
    if (n == 0) return 0;
    const result: u6 = @ctz(n);
    return @intCast(result);
}

/// XOR block b into block a in-place.
fn xorBlock(a: *[16]u8, b: *const [16]u8) void {
    for (a, 0..) |*byte, i| {
        byte.* ^= b[i];
    }
}

pub const AesOcb128 = Ocb(aes.Aes128);
pub const AesOcb256 = Ocb(aes.Aes256);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "OCB AES-128 encrypt/decrypt round-trip" {
    const key = [_]u8{0x01} ** 16;
    const nonce = [_]u8{0x02} ** 15;
    const ad = "associated data";
    const plaintext = "Hello, OCB mode!";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    const ocb = AesOcb128.init(key);
    ocb.encrypt(&ciphertext, &tag, plaintext, &nonce, ad);

    try std.testing.expect(!mem.eql(u8, &ciphertext, plaintext));

    var decrypted: [plaintext.len]u8 = undefined;
    try ocb.decrypt(&decrypted, &ciphertext, tag, &nonce, ad);
    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "OCB AES-256 encrypt/decrypt round-trip" {
    const key = [_]u8{0xAB} ** 32;
    const nonce = [_]u8{0xCD} ** 15;
    const ad = "AES-256 OCB associated data";
    const plaintext = "AES-256 OCB encryption test data spanning several blocks.";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    const ocb = AesOcb256.init(key);
    ocb.encrypt(&ciphertext, &tag, plaintext, &nonce, ad);

    var decrypted: [plaintext.len]u8 = undefined;
    try ocb.decrypt(&decrypted, &ciphertext, tag, &nonce, ad);
    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "OCB wrong tag fails" {
    const key = [_]u8{0x42} ** 16;
    const nonce = [_]u8{0x33} ** 12;
    const plaintext = "sensitive data";
    const ad = "header";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    const ocb = AesOcb128.init(key);
    ocb.encrypt(&ciphertext, &tag, plaintext, &nonce, ad);

    tag[0] ^= 0xFF;

    var decrypted: [plaintext.len]u8 = undefined;
    const result = ocb.decrypt(&decrypted, &ciphertext, tag, &nonce, ad);
    try std.testing.expectError(error.AuthenticationFailed, result);
}

test "OCB empty plaintext" {
    const key = [_]u8{0x01} ** 16;
    const nonce = [_]u8{0x02} ** 15;
    const ad = "only associated data";

    var ciphertext: [0]u8 = .{};
    var tag: [16]u8 = undefined;

    const ocb = AesOcb128.init(key);
    ocb.encrypt(&ciphertext, &tag, "", &nonce, ad);

    try std.testing.expect(!mem.eql(u8, &tag, &([_]u8{0} ** 16)));

    var decrypted: [0]u8 = .{};
    try ocb.decrypt(&decrypted, &ciphertext, tag, &nonce, ad);
}

test "OCB empty ad" {
    const key = [_]u8{0x77} ** 16;
    const nonce = [_]u8{0x88} ** 12;
    const plaintext = "data with no associated data";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    const ocb = AesOcb128.init(key);
    ocb.encrypt(&ciphertext, &tag, plaintext, &nonce, "");

    var decrypted: [plaintext.len]u8 = undefined;
    try ocb.decrypt(&decrypted, &ciphertext, tag, &nonce, "");
    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "OCB exactly one block" {
    const key = [_]u8{0x42} ** 16;
    const nonce = [_]u8{0x01} ** 12;
    const plaintext = [_]u8{0xAA} ** 16;
    const ad = "";

    var ciphertext: [16]u8 = undefined;
    var tag: [16]u8 = undefined;

    const ocb = AesOcb128.init(key);
    ocb.encrypt(&ciphertext, &tag, &plaintext, &nonce, ad);

    var decrypted: [16]u8 = undefined;
    try ocb.decrypt(&decrypted, &ciphertext, tag, &nonce, ad);
    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "OCB exactly two blocks" {
    const key = [_]u8{0x42} ** 16;
    const nonce = [_]u8{0x01} ** 12;
    const plaintext = [_]u8{0xBB} ** 32;
    const ad = "two blocks";

    var ciphertext: [32]u8 = undefined;
    var tag: [16]u8 = undefined;

    const ocb = AesOcb128.init(key);
    ocb.encrypt(&ciphertext, &tag, &plaintext, &nonce, ad);

    var decrypted: [32]u8 = undefined;
    try ocb.decrypt(&decrypted, &ciphertext, tag, &nonce, ad);
    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "OCB tampered ciphertext fails" {
    const key = [_]u8{0x42} ** 16;
    const nonce = [_]u8{0x33} ** 12;
    const plaintext = "integrity check";
    const ad = "";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    const ocb = AesOcb128.init(key);
    ocb.encrypt(&ciphertext, &tag, plaintext, &nonce, ad);

    ciphertext[0] ^= 0x01;

    var decrypted: [plaintext.len]u8 = undefined;
    const result = ocb.decrypt(&decrypted, &ciphertext, tag, &nonce, ad);
    try std.testing.expectError(error.AuthenticationFailed, result);
}

test "OCB deterministic" {
    const key = [_]u8{0x42} ** 16;
    const nonce = [_]u8{0x33} ** 12;
    const plaintext = "deterministic test";
    const ad = "header";

    var ct1: [plaintext.len]u8 = undefined;
    var tag1: [16]u8 = undefined;
    var ct2: [plaintext.len]u8 = undefined;
    var tag2: [16]u8 = undefined;

    const ocb = AesOcb128.init(key);
    ocb.encrypt(&ct1, &tag1, plaintext, &nonce, ad);
    ocb.encrypt(&ct2, &tag2, plaintext, &nonce, ad);

    try std.testing.expectEqualSlices(u8, &ct1, &ct2);
    try std.testing.expectEqualSlices(u8, &tag1, &tag2);
}

test "OCB RFC 7253 test vector 1 (TAGLEN=128, empty)" {
    // RFC 7253, Appendix A, test case with all-zero key, 3-byte nonce,
    // empty plaintext, empty associated data.
    // Key = 000102030405060708090A0B0C0D0E0F
    const key = [16]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };
    // Nonce = BBAA99887766554433221100
    const nonce = [12]u8{
        0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44,
        0x33, 0x22, 0x11, 0x00,
    };

    var ciphertext: [0]u8 = .{};
    var tag: [16]u8 = undefined;

    const ocb = AesOcb128.init(key);
    ocb.encrypt(&ciphertext, &tag, "", &nonce, "");

    // Expected tag: 785407BFFFC8AD9EDCC5520AC9111EE6
    const expected_tag = [16]u8{
        0x78, 0x54, 0x07, 0xBF, 0xFF, 0xC8, 0xAD, 0x9E,
        0xDC, 0xC5, 0x52, 0x0A, 0xC9, 0x11, 0x1E, 0xE6,
    };
    try std.testing.expectEqualSlices(u8, &expected_tag, &tag);
}

test "ntz function" {
    try std.testing.expectEqual(@as(u5, 0), ntz(1));
    try std.testing.expectEqual(@as(u5, 1), ntz(2));
    try std.testing.expectEqual(@as(u5, 0), ntz(3));
    try std.testing.expectEqual(@as(u5, 2), ntz(4));
    try std.testing.expectEqual(@as(u5, 0), ntz(5));
    try std.testing.expectEqual(@as(u5, 3), ntz(8));
    try std.testing.expectEqual(@as(u5, 4), ntz(16));
}

test "gfDouble" {
    const zero = [_]u8{0} ** 16;
    const doubled_zero = gfDouble(zero);
    try std.testing.expectEqualSlices(u8, &zero, &doubled_zero);

    var input = [_]u8{0} ** 16;
    input[0] = 0x80;
    const result = gfDouble(input);
    var expected = [_]u8{0} ** 16;
    expected[15] = 0x87;
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "extractBits aligned" {
    var stretch = [_]u8{0} ** 24;
    stretch[0] = 0xFF;
    stretch[15] = 0xAA;
    const result = extractBits(&stretch, 0);
    try std.testing.expectEqual(@as(u8, 0xFF), result[0]);
    try std.testing.expectEqual(@as(u8, 0xAA), result[15]);
}
