// SPDX-License-Identifier: MIT
//! OpenPGP CFB mode per RFC 4880 Section 13.9.
//!
//! OpenPGP uses a unique variant of CFB with two sub-modes:
//! - **Resyncing CFB** (legacy Tag 9 / SED packets): After encrypting the
//!   `block_size + 2` byte prefix, the feedback register is resynced.
//! - **Non-resyncing CFB** (Tag 18 / SEIPD packets): Standard CFB throughout.

const std = @import("std");
const aes = std.crypto.core.aes;

/// Generic OpenPGP CFB mode built on top of any AES block cipher.
///
/// CFB algorithm (per byte):
///   1. FRE = AES_Encrypt(FR)
///   2. ciphertext = plaintext XOR FRE[pos]
///   3. FR[pos] = ciphertext
///   4. Advance pos; when pos reaches block_size, reset to 0.
pub fn OpenPgpCfb(comptime BlockCipher: type) type {
    return struct {
        const Self = @This();
        pub const block_size: usize = BlockCipher.block.block_length;

        cipher: aes.AesEncryptCtx(BlockCipher),
        fr: [block_size]u8, // feedback register
        fre: [block_size]u8, // encrypted feedback register
        pos: usize, // position within current FRE block

        /// Create a new CFB context. The feedback register is initialised to
        /// all zeroes, matching the OpenPGP convention.
        pub fn init(key: [BlockCipher.key_bits / 8]u8) Self {
            return .{
                .cipher = BlockCipher.initEnc(key),
                .fr = [_]u8{0} ** block_size,
                .fre = undefined,
                .pos = 0,
            };
        }

        /// Encrypt the current feedback register into FRE.
        fn encryptFR(self: *Self) void {
            self.cipher.encrypt(&self.fre, &self.fr);
        }

        // ---- Non-resyncing (SEIPD / Tag 18) ----------------------------------

        /// Encrypt `data` in-place using standard (non-resyncing) CFB.
        pub fn encrypt(self: *Self, data: []u8) void {
            for (data) |*byte| {
                if (self.pos == 0) self.encryptFR();
                byte.* ^= self.fre[self.pos];
                self.fr[self.pos] = byte.*;
                self.pos += 1;
                if (self.pos == block_size) self.pos = 0;
            }
        }

        /// Decrypt `data` in-place using standard (non-resyncing) CFB.
        pub fn decrypt(self: *Self, data: []u8) void {
            for (data) |*byte| {
                if (self.pos == 0) self.encryptFR();
                const ct = byte.*;
                byte.* = ct ^ self.fre[self.pos];
                self.fr[self.pos] = ct;
                self.pos += 1;
                if (self.pos == block_size) self.pos = 0;
            }
        }

        // ---- Resyncing (SED / Tag 9) -----------------------------------------

        /// Encrypt `data` in-place using resyncing CFB (legacy SED packets).
        ///
        /// `data` must contain the full plaintext including the `block_size + 2`
        /// byte random prefix that the caller has already prepended.
        ///
        /// After encrypting the prefix, the feedback register is resynced to
        /// `ciphertext[2 .. block_size + 2]`.
        pub fn encryptResync(self: *Self, data: []u8) void {
            const prefix_len = block_size + 2;

            // Phase 1: encrypt the prefix with standard CFB
            const phase1_end = @min(prefix_len, data.len);
            for (data[0..phase1_end]) |*byte| {
                if (self.pos == 0) self.encryptFR();
                byte.* ^= self.fre[self.pos];
                self.fr[self.pos] = byte.*;
                self.pos += 1;
                if (self.pos == block_size) self.pos = 0;
            }

            if (data.len <= prefix_len) return;

            // Phase 2: resync FR to ciphertext[2..prefix_len]
            @memcpy(&self.fr, data[2..prefix_len]);
            self.pos = 0;

            // Phase 3: encrypt the remaining data with standard CFB
            for (data[prefix_len..]) |*byte| {
                if (self.pos == 0) self.encryptFR();
                byte.* ^= self.fre[self.pos];
                self.fr[self.pos] = byte.*;
                self.pos += 1;
                if (self.pos == block_size) self.pos = 0;
            }
        }

        /// Decrypt `data` in-place using resyncing CFB (legacy SED packets).
        ///
        /// `data` must contain the full ciphertext including the
        /// `block_size + 2` byte encrypted prefix.
        pub fn decryptResync(self: *Self, data: []u8) void {
            const prefix_len = block_size + 2;
            const phase1_end = @min(prefix_len, data.len);

            // Save the ciphertext of the prefix for resync before decrypting
            // in-place.
            var saved_ct: [block_size + 2]u8 = undefined;
            @memcpy(saved_ct[0..phase1_end], data[0..phase1_end]);

            // Phase 1: decrypt the prefix with standard CFB
            for (data[0..phase1_end]) |*byte| {
                if (self.pos == 0) self.encryptFR();
                const ct = byte.*;
                byte.* = ct ^ self.fre[self.pos];
                self.fr[self.pos] = ct;
                self.pos += 1;
                if (self.pos == block_size) self.pos = 0;
            }

            if (data.len <= prefix_len) return;

            // Phase 2: resync FR to original ciphertext[2..prefix_len]
            @memcpy(&self.fr, saved_ct[2..prefix_len]);
            self.pos = 0;

            // Phase 3: decrypt the remaining data with standard CFB
            for (data[prefix_len..]) |*byte| {
                if (self.pos == 0) self.encryptFR();
                const ct = byte.*;
                byte.* = ct ^ self.fre[self.pos];
                self.fr[self.pos] = ct;
                self.pos += 1;
                if (self.pos == block_size) self.pos = 0;
            }
        }
    };
}

pub const Aes128Cfb = OpenPgpCfb(aes.Aes128);
pub const Aes256Cfb = OpenPgpCfb(aes.Aes256);

// Additional cipher support (CAST5, Twofish) using direct encrypt context.

const Cast5 = @import("cast5.zig").Cast5;
const Twofish = @import("twofish.zig").Twofish;
const TripleDes = @import("triple_des.zig").TripleDes;

pub const Cast5Cfb = OpenPgpCfbDirect(Cast5);
pub const TwofishCfb = OpenPgpCfbDirect(Twofish);
pub const TripleDesCfb = OpenPgpCfbDirect(TripleDes);

/// Generic OpenPGP CFB mode for ciphers that are their own encrypt context
/// (i.e. `initEnc` returns the cipher itself, which has an `encrypt` method).
///
/// This mirrors `OpenPgpCfb` but does not wrap in `aes.AesEncryptCtx`.
pub fn OpenPgpCfbDirect(comptime CipherCtx: type) type {
    return struct {
        const Self = @This();
        pub const block_size: usize = CipherCtx.block.block_length;

        cipher: CipherCtx,
        fr: [block_size]u8,
        fre: [block_size]u8,
        pos: usize,

        pub fn init(key: [CipherCtx.key_bits / 8]u8) Self {
            return .{
                .cipher = CipherCtx.initEnc(key),
                .fr = [_]u8{0} ** block_size,
                .fre = undefined,
                .pos = 0,
            };
        }

        fn encryptFR(self: *Self) void {
            self.cipher.encrypt(&self.fre, &self.fr);
        }

        pub fn encryptData(self: *Self, data: []u8) void {
            for (data) |*byte| {
                if (self.pos == 0) self.encryptFR();
                byte.* ^= self.fre[self.pos];
                self.fr[self.pos] = byte.*;
                self.pos += 1;
                if (self.pos == block_size) self.pos = 0;
            }
        }

        pub fn decrypt(self: *Self, data: []u8) void {
            for (data) |*byte| {
                if (self.pos == 0) self.encryptFR();
                const ct = byte.*;
                byte.* = ct ^ self.fre[self.pos];
                self.fr[self.pos] = ct;
                self.pos += 1;
                if (self.pos == block_size) self.pos = 0;
            }
        }

        pub fn encryptResync(self: *Self, data: []u8) void {
            const prefix_len = block_size + 2;
            const phase1_end = @min(prefix_len, data.len);
            for (data[0..phase1_end]) |*byte| {
                if (self.pos == 0) self.encryptFR();
                byte.* ^= self.fre[self.pos];
                self.fr[self.pos] = byte.*;
                self.pos += 1;
                if (self.pos == block_size) self.pos = 0;
            }
            if (data.len <= prefix_len) return;
            @memcpy(&self.fr, data[2..prefix_len]);
            self.pos = 0;
            for (data[prefix_len..]) |*byte| {
                if (self.pos == 0) self.encryptFR();
                byte.* ^= self.fre[self.pos];
                self.fr[self.pos] = byte.*;
                self.pos += 1;
                if (self.pos == block_size) self.pos = 0;
            }
        }

        pub fn decryptResync(self: *Self, data: []u8) void {
            const prefix_len = block_size + 2;
            const phase1_end = @min(prefix_len, data.len);
            var saved_ct: [block_size + 2]u8 = undefined;
            @memcpy(saved_ct[0..phase1_end], data[0..phase1_end]);
            for (data[0..phase1_end]) |*byte| {
                if (self.pos == 0) self.encryptFR();
                const ct = byte.*;
                byte.* = ct ^ self.fre[self.pos];
                self.fr[self.pos] = ct;
                self.pos += 1;
                if (self.pos == block_size) self.pos = 0;
            }
            if (data.len <= prefix_len) return;
            @memcpy(&self.fr, saved_ct[2..prefix_len]);
            self.pos = 0;
            for (data[prefix_len..]) |*byte| {
                if (self.pos == 0) self.encryptFR();
                const ct = byte.*;
                byte.* = ct ^ self.fre[self.pos];
                self.fr[self.pos] = ct;
                self.pos += 1;
                if (self.pos == block_size) self.pos = 0;
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "AES-128 CFB non-resyncing encrypt/decrypt round-trip" {
    const key = [_]u8{0x01} ** 16;
    const plaintext = "Hello, OpenPGP CFB mode! This is a longer message to test multiple blocks.";
    var buf: [plaintext.len]u8 = undefined;
    @memcpy(&buf, plaintext);

    var enc = Aes128Cfb.init(key);
    enc.encrypt(&buf);

    try std.testing.expect(!std.mem.eql(u8, &buf, plaintext));

    var dec = Aes128Cfb.init(key);
    dec.decrypt(&buf);

    try std.testing.expectEqualSlices(u8, plaintext, &buf);
}

test "AES-256 CFB non-resyncing encrypt/decrypt round-trip" {
    const key = [_]u8{0xAB} ** 32;
    const plaintext = "AES-256 CFB test data spanning several AES blocks for verification.";
    var buf: [plaintext.len]u8 = undefined;
    @memcpy(&buf, plaintext);

    var enc = Aes256Cfb.init(key);
    enc.encrypt(&buf);

    try std.testing.expect(!std.mem.eql(u8, &buf, plaintext));

    var dec = Aes256Cfb.init(key);
    dec.decrypt(&buf);

    try std.testing.expectEqualSlices(u8, plaintext, &buf);
}

test "AES-128 CFB resyncing encrypt/decrypt round-trip" {
    const key = [_]u8{0x42} ** 16;

    // Simulate OpenPGP prefix: block_size random bytes + 2 check bytes,
    // followed by the actual plaintext.
    const block_size = Aes128Cfb.block_size;
    const prefix = [_]u8{0xDE} ** block_size ++ [_]u8{ 0xDE, 0xDE };
    const body = "The quick brown fox jumps over the lazy dog";
    const plaintext = prefix ++ body.*;
    var buf: [plaintext.len]u8 = undefined;
    @memcpy(&buf, &plaintext);

    var enc = Aes128Cfb.init(key);
    enc.encryptResync(&buf);

    try std.testing.expect(!std.mem.eql(u8, &buf, &plaintext));

    var dec = Aes128Cfb.init(key);
    dec.decryptResync(&buf);

    try std.testing.expectEqualSlices(u8, &plaintext, &buf);
}

test "AES-256 CFB resyncing encrypt/decrypt round-trip" {
    const key = [_]u8{0x77} ** 32;

    const block_size = Aes256Cfb.block_size;
    const prefix = [_]u8{0xAA} ** block_size ++ [_]u8{ 0xAA, 0xAA };
    const body = "SED resync test with AES-256 key material, multiple blocks of data here.";
    const plaintext = prefix ++ body.*;
    var buf: [plaintext.len]u8 = undefined;
    @memcpy(&buf, &plaintext);

    var enc = Aes256Cfb.init(key);
    enc.encryptResync(&buf);

    try std.testing.expect(!std.mem.eql(u8, &buf, &plaintext));

    var dec = Aes256Cfb.init(key);
    dec.decryptResync(&buf);

    try std.testing.expectEqualSlices(u8, &plaintext, &buf);
}

test "CFB incremental encrypt matches one-shot" {
    const key = [_]u8{0x55} ** 16;
    const plaintext = "Incremental vs one-shot CFB test message!!!";

    // One-shot
    var buf1: [plaintext.len]u8 = undefined;
    @memcpy(&buf1, plaintext);
    var enc1 = Aes128Cfb.init(key);
    enc1.encrypt(&buf1);

    // Incremental (byte at a time)
    var buf2: [plaintext.len]u8 = undefined;
    @memcpy(&buf2, plaintext);
    var enc2 = Aes128Cfb.init(key);
    for (&buf2) |*byte| {
        enc2.encrypt(@as(*[1]u8, byte));
    }

    try std.testing.expectEqualSlices(u8, &buf1, &buf2);
}

test "CFB empty data is a no-op" {
    const key = [_]u8{0x00} ** 16;
    var enc = Aes128Cfb.init(key);
    var empty: [0]u8 = .{};
    enc.encrypt(&empty);
}

test "CAST5 CFB non-resyncing encrypt/decrypt round-trip" {
    const key = [_]u8{0x42} ** 16;
    const plaintext = "Hello, OpenPGP CAST5-CFB mode! Testing multiple blocks.";
    var buf: [plaintext.len]u8 = undefined;
    @memcpy(&buf, plaintext);

    var enc = Cast5Cfb.init(key);
    enc.encryptData(&buf);

    try std.testing.expect(!std.mem.eql(u8, &buf, plaintext));

    var dec = Cast5Cfb.init(key);
    dec.decrypt(&buf);

    try std.testing.expectEqualSlices(u8, plaintext, &buf);
}

test "Twofish CFB non-resyncing encrypt/decrypt round-trip" {
    const key = [_]u8{0x77} ** 32;
    const plaintext = "Twofish CFB test data spanning several blocks for verification.";
    var buf: [plaintext.len]u8 = undefined;
    @memcpy(&buf, plaintext);

    var enc = TwofishCfb.init(key);
    enc.encryptData(&buf);

    try std.testing.expect(!std.mem.eql(u8, &buf, plaintext));

    var dec = TwofishCfb.init(key);
    dec.decrypt(&buf);

    try std.testing.expectEqualSlices(u8, plaintext, &buf);
}

test "CAST5 CFB resyncing encrypt/decrypt round-trip" {
    const key = [_]u8{0xDE} ** 16;
    const bs = Cast5Cfb.block_size;
    const prefix = [_]u8{0xAA} ** bs ++ [_]u8{ 0xAA, 0xAA };
    const body = "CAST5 resyncing CFB test message";
    const plaintext = prefix ++ body.*;
    var buf: [plaintext.len]u8 = undefined;
    @memcpy(&buf, &plaintext);

    var enc = Cast5Cfb.init(key);
    enc.encryptResync(&buf);

    try std.testing.expect(!std.mem.eql(u8, &buf, &plaintext));

    var dec = Cast5Cfb.init(key);
    dec.decryptResync(&buf);

    try std.testing.expectEqualSlices(u8, &plaintext, &buf);
}

test "TripleDES CFB non-resyncing encrypt/decrypt round-trip" {
    const key = [_]u8{0x42} ** 24;
    const plaintext = "Hello, OpenPGP TripleDES-CFB mode! Testing multiple blocks of data.";
    var buf: [plaintext.len]u8 = undefined;
    @memcpy(&buf, plaintext);

    var enc = TripleDesCfb.init(key);
    enc.encryptData(&buf);

    try std.testing.expect(!std.mem.eql(u8, &buf, plaintext));

    var dec = TripleDesCfb.init(key);
    dec.decrypt(&buf);

    try std.testing.expectEqualSlices(u8, plaintext, &buf);
}

test "TripleDES CFB resyncing encrypt/decrypt round-trip" {
    const key = [_]u8{0xDE} ** 24;
    const bs = TripleDesCfb.block_size;
    const prefix = [_]u8{0xAA} ** bs ++ [_]u8{ 0xAA, 0xAA };
    const body = "TripleDES resyncing CFB test message";
    const plaintext = prefix ++ body.*;
    var buf: [plaintext.len]u8 = undefined;
    @memcpy(&buf, &plaintext);

    var enc = TripleDesCfb.init(key);
    enc.encryptResync(&buf);

    try std.testing.expect(!std.mem.eql(u8, &buf, &plaintext));

    var dec = TripleDesCfb.init(key);
    dec.decryptResync(&buf);

    try std.testing.expectEqualSlices(u8, &plaintext, &buf);
}
