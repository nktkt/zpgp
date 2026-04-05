// SPDX-License-Identifier: MIT
//! EAX mode (Encrypt-then-Authenticate-then-Translate) per RFC 9580.
//!
//! EAX is a two-pass AEAD scheme built on CMAC (OMAC1) and CTR mode.
//!
//! EAX(K, N, H, M):
//!   1. tag_nonce = CMAC_K(0 || N)   -- tweak byte 0
//!   2. tag_ad    = CMAC_K(1 || H)   -- tweak byte 1
//!   3. C = CTR_K(M, tag_nonce)       -- encrypt with tag_nonce as IV
//!   4. tag_ct    = CMAC_K(2 || C)   -- tweak byte 2
//!   5. Tag = tag_nonce XOR tag_ad XOR tag_ct

const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const aes = crypto.core.aes;

/// EAX authenticated encryption mode built on top of a 128-bit block cipher.
pub fn Eax(comptime Aes: type) type {
    return struct {
        const Self = @This();
        pub const block_size: usize = 16;
        pub const tag_size: usize = 16;
        pub const key_size: usize = Aes.key_bits / 8;

        cipher: aes.AesEncryptCtx(Aes),

        // CMAC subkeys K1, K2 derived from cipher
        k1: [16]u8,
        k2: [16]u8,

        pub fn init(key: [key_size]u8) Self {
            const ctx = Aes.initEnc(key);

            // Derive CMAC subkeys
            // L = AES(K, 0^128)
            const zero_block = [_]u8{0} ** 16;
            var l: [16]u8 = undefined;
            ctx.encrypt(&l, &zero_block);

            const k1 = gfDouble(l);
            const k2 = gfDouble(k1);

            return .{
                .cipher = ctx,
                .k1 = k1,
                .k2 = k2,
            };
        }

        /// Encrypt plaintext and produce authentication tag.
        pub fn encrypt(
            self: Self,
            ciphertext: []u8,
            tag: *[tag_size]u8,
            plaintext: []const u8,
            nonce: []const u8,
            ad: []const u8,
        ) void {
            std.debug.assert(ciphertext.len == plaintext.len);

            // Step 1: N = CMAC(0 || nonce)
            const tag_nonce = self.cmacWithTweak(0, nonce);

            // Step 2: Encrypt plaintext with CTR mode using tag_nonce as IV
            self.ctrProcess(ciphertext, plaintext, tag_nonce);

            // Step 3: H = CMAC(1 || ad)
            const tag_ad = self.cmacWithTweak(1, ad);

            // Step 4: C' = CMAC(2 || ciphertext)
            const tag_ct = self.cmacWithTweak(2, ciphertext);

            // Step 5: Tag = N XOR H XOR C'
            for (tag, 0..) |*t, i| {
                t.* = tag_nonce[i] ^ tag_ad[i] ^ tag_ct[i];
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

            // Step 1: N = CMAC(0 || nonce)
            const tag_nonce = self.cmacWithTweak(0, nonce);

            // Step 2: H = CMAC(1 || ad)
            const tag_ad = self.cmacWithTweak(1, ad);

            // Step 3: C' = CMAC(2 || ciphertext)
            const tag_ct = self.cmacWithTweak(2, ciphertext);

            // Step 4: Verify tag
            var expected_tag: [16]u8 = undefined;
            for (&expected_tag, 0..) |*t, i| {
                t.* = tag_nonce[i] ^ tag_ad[i] ^ tag_ct[i];
            }

            if (!crypto.timing_safe.eql([tag_size]u8, expected_tag, tag)) {
                return error.AuthenticationFailed;
            }

            // Step 5: Decrypt with CTR mode
            self.ctrProcess(plaintext, ciphertext, tag_nonce);
        }

        /// CTR mode encryption/decryption.
        /// EAX uses big-endian counter increment starting from the given IV.
        fn ctrProcess(self: Self, dst: []u8, src: []const u8, iv: [16]u8) void {
            std.debug.assert(dst.len == src.len);

            var counter = iv;
            var i: usize = 0;

            while (i < src.len) {
                var keystream: [16]u8 = undefined;
                self.cipher.encrypt(&keystream, &counter);

                const remaining = src.len - i;
                const chunk = @min(remaining, 16);
                for (0..chunk) |j| {
                    dst[i + j] = src[i + j] ^ keystream[j];
                }

                // Increment counter (big-endian)
                ctrIncrement(&counter);
                i += chunk;
            }
        }

        /// CMAC with a tweak byte prepended.
        /// Computes CMAC_K(tweak_byte || 0^(block_size-1) followed by data),
        /// where the tweak_byte is the first byte of a zero-padded block.
        ///
        /// Per the EAX spec: the tweak is a full block of zeros except the
        /// last byte which is the tweak value (big-endian encoding of tweak).
        fn cmacWithTweak(self: Self, tweak: u8, data: []const u8) [16]u8 {
            // The "tweak block" for EAX: 15 zero bytes + tweak value
            var tweak_block = [_]u8{0} ** 16;
            tweak_block[15] = tweak;

            // Process tweak block first through CBC-MAC, then the data
            // Start with encrypting the tweak block
            var state: [16]u8 = undefined;
            self.cipher.encrypt(&state, &tweak_block);

            if (data.len == 0) {
                // The tweak block is the only block; it was a complete block,
                // so we XOR K1 and re-encrypt
                for (&tweak_block, 0..) |*b, j| {
                    b.* ^= self.k1[j];
                }
                self.cipher.encrypt(&state, &tweak_block);
                return state;
            }

            // Process data in 16-byte blocks (CBC-MAC continuing from state)
            var offset: usize = 0;
            while (offset + 16 <= data.len) {
                if (offset + 16 == data.len) {
                    // Last complete block: XOR with K1
                    var block: [16]u8 = undefined;
                    for (&block, 0..) |*b, j| {
                        b.* = state[j] ^ data[offset + j] ^ self.k1[j];
                    }
                    self.cipher.encrypt(&state, &block);
                    return state;
                } else {
                    // Intermediate block: just XOR and encrypt
                    var block: [16]u8 = undefined;
                    for (&block, 0..) |*b, j| {
                        b.* = state[j] ^ data[offset + j];
                    }
                    self.cipher.encrypt(&state, &block);
                }
                offset += 16;
            }

            // Remaining incomplete block: pad with 10*
            const remaining = data.len - offset;
            if (remaining > 0) {
                var block: [16]u8 = [_]u8{0} ** 16;
                @memcpy(block[0..remaining], data[offset..][0..remaining]);
                block[remaining] = 0x80;

                for (&block, 0..) |*b, j| {
                    b.* ^= state[j] ^ self.k2[j];
                }
                self.cipher.encrypt(&state, &block);
            }

            return state;
        }
    };
}

/// Double a value in GF(2^128) with the polynomial x^128 + x^7 + x^2 + x + 1.
/// Used for CMAC subkey derivation.
fn gfDouble(input: [16]u8) [16]u8 {
    var output: [16]u8 = undefined;
    const carry = input[0] >> 7; // MSB carry

    // Shift left by 1
    for (0..15) |i| {
        output[i] = (input[i] << 1) | (input[i + 1] >> 7);
    }
    output[15] = input[15] << 1;

    // If carry, XOR with R_b = 0x87 (the reduction polynomial)
    if (carry == 1) {
        output[15] ^= 0x87;
    }

    return output;
}

/// Increment a 128-bit big-endian counter by 1.
fn ctrIncrement(counter: *[16]u8) void {
    var carry: u8 = 1;
    var i: usize = 16;
    while (i > 0) {
        i -= 1;
        const sum: u16 = @as(u16, counter[i]) + carry;
        counter[i] = @truncate(sum);
        carry = @truncate(sum >> 8);
        if (carry == 0) break;
    }
}

pub const AesEax128 = Eax(aes.Aes128);
pub const AesEax256 = Eax(aes.Aes256);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "EAX AES-128 encrypt/decrypt round-trip" {
    const key = [_]u8{0x01} ** 16;
    const nonce = [_]u8{0x02} ** 16;
    const ad = "associated data";
    const plaintext = "Hello, EAX mode!";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    const eax = AesEax128.init(key);
    eax.encrypt(&ciphertext, &tag, plaintext, &nonce, ad);

    // Ciphertext should differ from plaintext
    try std.testing.expect(!mem.eql(u8, &ciphertext, plaintext));

    // Decrypt
    var decrypted: [plaintext.len]u8 = undefined;
    try eax.decrypt(&decrypted, &ciphertext, tag, &nonce, ad);
    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "EAX AES-256 encrypt/decrypt round-trip" {
    const key = [_]u8{0xAB} ** 32;
    const nonce = [_]u8{0xCD} ** 16;
    const ad = "some associated data for AES-256 EAX";
    const plaintext = "AES-256 EAX encryption test spanning multiple blocks of data for verification.";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    const eax = AesEax256.init(key);
    eax.encrypt(&ciphertext, &tag, plaintext, &nonce, ad);

    try std.testing.expect(!mem.eql(u8, &ciphertext, plaintext));

    var decrypted: [plaintext.len]u8 = undefined;
    try eax.decrypt(&decrypted, &ciphertext, tag, &nonce, ad);
    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "EAX wrong tag fails" {
    const key = [_]u8{0x42} ** 16;
    const nonce = [_]u8{0x33} ** 16;
    const plaintext = "sensitive data";
    const ad = "header";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    const eax = AesEax128.init(key);
    eax.encrypt(&ciphertext, &tag, plaintext, &nonce, ad);

    // Tamper with tag
    tag[0] ^= 0xFF;

    var decrypted: [plaintext.len]u8 = undefined;
    const result = eax.decrypt(&decrypted, &ciphertext, tag, &nonce, ad);
    try std.testing.expectError(error.AuthenticationFailed, result);
}

test "EAX wrong ad fails" {
    const key = [_]u8{0x42} ** 16;
    const nonce = [_]u8{0x33} ** 16;
    const plaintext = "sensitive data";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    const eax = AesEax128.init(key);
    eax.encrypt(&ciphertext, &tag, plaintext, &nonce, "correct ad");

    var decrypted: [plaintext.len]u8 = undefined;
    const result = eax.decrypt(&decrypted, &ciphertext, tag, &nonce, "wrong ad");
    try std.testing.expectError(error.AuthenticationFailed, result);
}

test "EAX empty plaintext" {
    const key = [_]u8{0x01} ** 16;
    const nonce = [_]u8{0x02} ** 16;
    const ad = "only ad, no plaintext";

    var ciphertext: [0]u8 = .{};
    var tag: [16]u8 = undefined;

    const eax = AesEax128.init(key);
    eax.encrypt(&ciphertext, &tag, "", &nonce, ad);

    // Tag should be non-zero
    try std.testing.expect(!mem.eql(u8, &tag, &([_]u8{0} ** 16)));

    var decrypted: [0]u8 = .{};
    try eax.decrypt(&decrypted, &ciphertext, tag, &nonce, ad);
}

test "EAX empty ad" {
    const key = [_]u8{0x77} ** 16;
    const nonce = [_]u8{0x88} ** 16;
    const plaintext = "data with no associated data";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    const eax = AesEax128.init(key);
    eax.encrypt(&ciphertext, &tag, plaintext, &nonce, "");

    var decrypted: [plaintext.len]u8 = undefined;
    try eax.decrypt(&decrypted, &ciphertext, tag, &nonce, "");
    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "EAX two encryptions of same data produce same ciphertext" {
    const key = [_]u8{0x42} ** 16;
    const nonce = [_]u8{0x33} ** 16;
    const plaintext = "deterministic test";
    const ad = "header";

    var ct1: [plaintext.len]u8 = undefined;
    var tag1: [16]u8 = undefined;
    var ct2: [plaintext.len]u8 = undefined;
    var tag2: [16]u8 = undefined;

    const eax = AesEax128.init(key);
    eax.encrypt(&ct1, &tag1, plaintext, &nonce, ad);
    eax.encrypt(&ct2, &tag2, plaintext, &nonce, ad);

    // Same key+nonce+ad+plaintext => same ciphertext+tag (deterministic)
    try std.testing.expectEqualSlices(u8, &ct1, &ct2);
    try std.testing.expectEqualSlices(u8, &tag1, &tag2);
}

test "EAX tampered ciphertext fails" {
    const key = [_]u8{0x42} ** 16;
    const nonce = [_]u8{0x33} ** 16;
    const plaintext = "integrity check";
    const ad = "";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    const eax = AesEax128.init(key);
    eax.encrypt(&ciphertext, &tag, plaintext, &nonce, ad);

    // Tamper with ciphertext
    ciphertext[0] ^= 0x01;

    var decrypted: [plaintext.len]u8 = undefined;
    const result = eax.decrypt(&decrypted, &ciphertext, tag, &nonce, ad);
    try std.testing.expectError(error.AuthenticationFailed, result);
}

test "EAX known vector: AES-128 from EAX spec" {
    // Test vector from the EAX paper (Bellare, Rogaway, Wagner)
    // Test case 1: empty message, empty header, empty nonce
    // Key = 233952DEE4D5ED5F9B9C6D6FF80FF478
    const key = [16]u8{
        0x23, 0x39, 0x52, 0xDE, 0xE4, 0xD5, 0xED, 0x5F,
        0x9B, 0x9C, 0x6D, 0x6F, 0xF8, 0x0F, 0xF4, 0x78,
    };
    // Nonce = 62EC67F9C3A4A407FCB2A8C49031A8B3
    const nonce = [16]u8{
        0x62, 0xEC, 0x67, 0xF9, 0xC3, 0xA4, 0xA4, 0x07,
        0xFC, 0xB2, 0xA8, 0xC4, 0x90, 0x31, 0xA8, 0xB3,
    };
    // Header = 6BFB914FD07EAE6B
    const header = [8]u8{
        0x6B, 0xFB, 0x91, 0x4F, 0xD0, 0x7E, 0xAE, 0x6B,
    };
    // Plaintext = (empty)
    const plaintext = "";
    // Expected tag = E037830E8389F27B025A2D6527E79D01
    const expected_tag = [16]u8{
        0xE0, 0x37, 0x83, 0x0E, 0x83, 0x89, 0xF2, 0x7B,
        0x02, 0x5A, 0x2D, 0x65, 0x27, 0xE7, 0x9D, 0x01,
    };

    var ciphertext: [0]u8 = .{};
    var tag: [16]u8 = undefined;

    const eax = AesEax128.init(key);
    eax.encrypt(&ciphertext, &tag, plaintext, &nonce, &header);

    try std.testing.expectEqualSlices(u8, &expected_tag, &tag);
}

test "gfDouble known value" {
    // GF(2^128) doubling of zero should be zero
    const zero = [_]u8{0} ** 16;
    const result = gfDouble(zero);
    try std.testing.expectEqualSlices(u8, &zero, &result);
}

test "gfDouble carry bit" {
    // If MSB is set, carry triggers XOR with 0x87
    var input = [_]u8{0} ** 16;
    input[0] = 0x80; // MSB set
    const result = gfDouble(input);

    var expected = [_]u8{0} ** 16;
    expected[15] = 0x87; // reduction polynomial
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "ctrIncrement" {
    var counter = [_]u8{0} ** 16;
    counter[15] = 0xFE;
    ctrIncrement(&counter);
    try std.testing.expectEqual(@as(u8, 0xFF), counter[15]);

    ctrIncrement(&counter);
    try std.testing.expectEqual(@as(u8, 0x00), counter[15]);
    try std.testing.expectEqual(@as(u8, 0x01), counter[14]);
}
