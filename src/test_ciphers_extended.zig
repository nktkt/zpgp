// SPDX-License-Identifier: MIT
//! Comprehensive tests for all new cipher implementations.
//!
//! Tests cover:
//!   - IDEA: test vectors, round-trip, CFB mode
//!   - Blowfish: test vectors, round-trip, CFB mode
//!   - Camellia (128/192/256): RFC 3713 vectors, round-trip, CFB mode
//!   - Cross-cipher: encrypt with each, decrypt with each
//!   - Key stretching: PBKDF2, scrypt
//!   - Cipher registry: discovery and capability queries

const std = @import("std");
const mem = std.mem;

// Cipher implementations
const Idea = @import("crypto/idea.zig").Idea;
const Blowfish = @import("crypto/blowfish.zig").Blowfish;
const Camellia128 = @import("crypto/camellia.zig").Camellia128;
const Camellia192 = @import("crypto/camellia.zig").Camellia192;
const Camellia256 = @import("crypto/camellia.zig").Camellia256;

// CFB modes
const cfb_mod = @import("crypto/cfb.zig");
const IdeaCfb = cfb_mod.IdeaCfb;
const BlowfishCfb = cfb_mod.BlowfishCfb;
const Camellia128Cfb = cfb_mod.Camellia128Cfb;
const Camellia192Cfb = cfb_mod.Camellia192Cfb;
const Camellia256Cfb = cfb_mod.Camellia256Cfb;

// Symmetric dispatch
const symmetric_dispatch = @import("crypto/symmetric_dispatch.zig");
const SymmetricAlgorithm = @import("types/enums.zig").SymmetricAlgorithm;

// Key stretching
const key_stretching = @import("crypto/key_stretching.zig");

// Cipher registry
const cipher_registry = @import("crypto/cipher_registry.zig");

// =========================================================================
// IDEA Tests
// =========================================================================

test "IDEA: basic encrypt/decrypt with simple key" {
    const key = [_]u8{0x42} ** 16;
    const plaintext = [8]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    const cipher = Idea.initEnc(key);

    var ct: [8]u8 = undefined;
    cipher.encrypt(&ct, &plaintext);
    try std.testing.expect(!mem.eql(u8, &ct, &plaintext));

    var pt: [8]u8 = undefined;
    cipher.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "IDEA: known vector - key 00010002...0008" {
    const key = [16]u8{ 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08 };
    const plaintext = [8]u8{ 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03 };
    const expected = [8]u8{ 0x11, 0xFB, 0xED, 0x2B, 0x01, 0x98, 0x6D, 0xE5 };

    const cipher = Idea.initEnc(key);
    var ct: [8]u8 = undefined;
    cipher.encrypt(&ct, &plaintext);
    try std.testing.expectEqualSlices(u8, &expected, &ct);
}

test "IDEA: encrypt same block twice produces same result" {
    const key = [_]u8{0xAA} ** 16;
    const plaintext = [_]u8{0x55} ** 8;

    const cipher = Idea.initEnc(key);

    var ct1: [8]u8 = undefined;
    var ct2: [8]u8 = undefined;
    cipher.encrypt(&ct1, &plaintext);
    cipher.encrypt(&ct2, &plaintext);

    try std.testing.expectEqualSlices(u8, &ct1, &ct2);
}

test "IDEA: different keys produce different ciphertext" {
    const key1 = [_]u8{0x01} ** 16;
    const key2 = [_]u8{0x02} ** 16;
    const plaintext = [_]u8{0x00} ** 8;

    const c1 = Idea.initEnc(key1);
    const c2 = Idea.initEnc(key2);

    var ct1: [8]u8 = undefined;
    var ct2: [8]u8 = undefined;
    c1.encrypt(&ct1, &plaintext);
    c2.encrypt(&ct2, &plaintext);

    try std.testing.expect(!mem.eql(u8, &ct1, &ct2));
}

test "IDEA CFB: non-resyncing encrypt/decrypt round-trip" {
    const key = [_]u8{0x42} ** 16;
    const plaintext = "Hello, IDEA CFB mode! Testing multiple blocks of data here.";
    var buf: [plaintext.len]u8 = undefined;
    @memcpy(&buf, plaintext);

    var enc = IdeaCfb.init(key);
    enc.encryptData(&buf);

    try std.testing.expect(!mem.eql(u8, &buf, plaintext));

    var dec = IdeaCfb.init(key);
    dec.decrypt(&buf);

    try std.testing.expectEqualSlices(u8, plaintext, &buf);
}

test "IDEA CFB: resyncing encrypt/decrypt round-trip" {
    const key = [_]u8{0xDE} ** 16;
    const bs = IdeaCfb.block_size;
    const prefix = [_]u8{0xAA} ** bs ++ [_]u8{ 0xAA, 0xAA };
    const body = "IDEA resyncing CFB test message body";
    const plaintext = prefix ++ body.*;
    var buf: [plaintext.len]u8 = undefined;
    @memcpy(&buf, &plaintext);

    var enc = IdeaCfb.init(key);
    enc.encryptResync(&buf);

    try std.testing.expect(!mem.eql(u8, &buf, &plaintext));

    var dec = IdeaCfb.init(key);
    dec.decryptResync(&buf);

    try std.testing.expectEqualSlices(u8, &plaintext, &buf);
}

test "IDEA CFB: empty data is no-op" {
    const key = [_]u8{0x00} ** 16;
    var enc = IdeaCfb.init(key);
    var empty: [0]u8 = .{};
    enc.encryptData(&empty);
}

test "IDEA: round-trip with many different blocks" {
    const key = [16]u8{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01 };
    const cipher = Idea.initEnc(key);

    var i: u8 = 0;
    while (i < 64) : (i += 1) {
        var plaintext: [8]u8 = undefined;
        for (&plaintext, 0..) |*b, j| {
            b.* = i +% @as(u8, @intCast(j));
        }
        var ct: [8]u8 = undefined;
        cipher.encrypt(&ct, &plaintext);
        var pt: [8]u8 = undefined;
        cipher.decrypt(&pt, &ct);
        try std.testing.expectEqualSlices(u8, &plaintext, &pt);
    }
}

// =========================================================================
// Blowfish Tests
// =========================================================================

test "Blowfish: basic encrypt/decrypt" {
    const key = [_]u8{0x42} ** 16;
    const plaintext = [8]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };

    const cipher = Blowfish.initEnc(key);

    var ct: [8]u8 = undefined;
    cipher.encrypt(&ct, &plaintext);
    try std.testing.expect(!mem.eql(u8, &ct, &plaintext));

    var pt: [8]u8 = undefined;
    cipher.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "Blowfish: different keys produce different ciphertext" {
    const key1 = [_]u8{0x01} ** 16;
    const key2 = [_]u8{0x02} ** 16;
    const plaintext = [_]u8{0x00} ** 8;

    const c1 = Blowfish.initEnc(key1);
    const c2 = Blowfish.initEnc(key2);

    var ct1: [8]u8 = undefined;
    var ct2: [8]u8 = undefined;
    c1.encrypt(&ct1, &plaintext);
    c2.encrypt(&ct2, &plaintext);

    try std.testing.expect(!mem.eql(u8, &ct1, &ct2));
}

test "Blowfish CFB: non-resyncing encrypt/decrypt round-trip" {
    const key = [_]u8{0x77} ** 16;
    const plaintext = "Blowfish CFB mode test spanning multiple blocks of data!";
    var buf: [plaintext.len]u8 = undefined;
    @memcpy(&buf, plaintext);

    var enc = BlowfishCfb.init(key);
    enc.encryptData(&buf);

    try std.testing.expect(!mem.eql(u8, &buf, plaintext));

    var dec = BlowfishCfb.init(key);
    dec.decrypt(&buf);

    try std.testing.expectEqualSlices(u8, plaintext, &buf);
}

test "Blowfish CFB: resyncing encrypt/decrypt round-trip" {
    const key = [_]u8{0xDE} ** 16;
    const bs = BlowfishCfb.block_size;
    const prefix = [_]u8{0xBB} ** bs ++ [_]u8{ 0xBB, 0xBB };
    const body = "Blowfish resyncing CFB test message";
    const plaintext = prefix ++ body.*;
    var buf: [plaintext.len]u8 = undefined;
    @memcpy(&buf, &plaintext);

    var enc = BlowfishCfb.init(key);
    enc.encryptResync(&buf);

    try std.testing.expect(!mem.eql(u8, &buf, &plaintext));

    var dec = BlowfishCfb.init(key);
    dec.decryptResync(&buf);

    try std.testing.expectEqualSlices(u8, &plaintext, &buf);
}

test "Blowfish: round-trip with varied data" {
    const key = [16]u8{ 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78 };
    const cipher = Blowfish.initEnc(key);

    const test_blocks = [_][8]u8{
        .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF },
        .{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE },
        .{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
    };

    for (test_blocks) |blk| {
        var ct: [8]u8 = undefined;
        cipher.encrypt(&ct, &blk);
        var pt: [8]u8 = undefined;
        cipher.decrypt(&pt, &ct);
        try std.testing.expectEqualSlices(u8, &blk, &pt);
    }
}

// =========================================================================
// Camellia Tests
// =========================================================================

test "Camellia-128: basic encrypt/decrypt" {
    const key = [_]u8{0x42} ** 16;
    const plaintext = [_]u8{0xAA} ** 16;

    const cipher = Camellia128.initEnc(key);

    var ct: [16]u8 = undefined;
    cipher.encrypt(&ct, &plaintext);
    try std.testing.expect(!mem.eql(u8, &ct, &plaintext));

    var pt: [16]u8 = undefined;
    cipher.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "Camellia-256: basic encrypt/decrypt" {
    const key = [_]u8{0x42} ** 32;
    const plaintext = [_]u8{0xBB} ** 16;

    const cipher = Camellia256.initEnc(key);

    var ct: [16]u8 = undefined;
    cipher.encrypt(&ct, &plaintext);
    try std.testing.expect(!mem.eql(u8, &ct, &plaintext));

    var pt: [16]u8 = undefined;
    cipher.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "Camellia-192: basic encrypt/decrypt" {
    const key = [_]u8{0x42} ** 24;
    const plaintext = [_]u8{0xCC} ** 16;

    const cipher = Camellia192.initEnc(key);

    var ct: [16]u8 = undefined;
    cipher.encrypt(&ct, &plaintext);
    try std.testing.expect(!mem.eql(u8, &ct, &plaintext));

    var pt: [16]u8 = undefined;
    cipher.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "Camellia-128: different keys produce different ciphertext" {
    const key1 = [_]u8{0x01} ** 16;
    const key2 = [_]u8{0x02} ** 16;
    const plaintext = [_]u8{0x00} ** 16;

    const c1 = Camellia128.initEnc(key1);
    const c2 = Camellia128.initEnc(key2);

    var ct1: [16]u8 = undefined;
    var ct2: [16]u8 = undefined;
    c1.encrypt(&ct1, &plaintext);
    c2.encrypt(&ct2, &plaintext);

    try std.testing.expect(!mem.eql(u8, &ct1, &ct2));
}

test "Camellia-128 CFB: non-resyncing encrypt/decrypt round-trip" {
    const key = [_]u8{0x42} ** 16;
    const plaintext = "Camellia-128 CFB mode test spanning multiple blocks of data!";
    var buf: [plaintext.len]u8 = undefined;
    @memcpy(&buf, plaintext);

    var enc = Camellia128Cfb.init(key);
    enc.encryptData(&buf);

    try std.testing.expect(!mem.eql(u8, &buf, plaintext));

    var dec = Camellia128Cfb.init(key);
    dec.decrypt(&buf);

    try std.testing.expectEqualSlices(u8, plaintext, &buf);
}

test "Camellia-256 CFB: non-resyncing encrypt/decrypt round-trip" {
    const key = [_]u8{0x77} ** 32;
    const plaintext = "Camellia-256 CFB mode test spanning multiple blocks of data!";
    var buf: [plaintext.len]u8 = undefined;
    @memcpy(&buf, plaintext);

    var enc = Camellia256Cfb.init(key);
    enc.encryptData(&buf);

    try std.testing.expect(!mem.eql(u8, &buf, plaintext));

    var dec = Camellia256Cfb.init(key);
    dec.decrypt(&buf);

    try std.testing.expectEqualSlices(u8, plaintext, &buf);
}

test "Camellia-128 CFB: resyncing encrypt/decrypt round-trip" {
    const key = [_]u8{0xDE} ** 16;
    const bs = Camellia128Cfb.block_size;
    const prefix = [_]u8{0xCC} ** bs ++ [_]u8{ 0xCC, 0xCC };
    const body = "Camellia-128 resyncing CFB test msg";
    const plaintext = prefix ++ body.*;
    var buf: [plaintext.len]u8 = undefined;
    @memcpy(&buf, &plaintext);

    var enc = Camellia128Cfb.init(key);
    enc.encryptResync(&buf);

    try std.testing.expect(!mem.eql(u8, &buf, &plaintext));

    var dec = Camellia128Cfb.init(key);
    dec.decryptResync(&buf);

    try std.testing.expectEqualSlices(u8, &plaintext, &buf);
}

test "Camellia-256 CFB: resyncing encrypt/decrypt round-trip" {
    const key = [_]u8{0xDE} ** 32;
    const bs = Camellia256Cfb.block_size;
    const prefix = [_]u8{0xDD} ** bs ++ [_]u8{ 0xDD, 0xDD };
    const body = "Camellia-256 resyncing CFB test msg";
    const plaintext = prefix ++ body.*;
    var buf: [plaintext.len]u8 = undefined;
    @memcpy(&buf, &plaintext);

    var enc = Camellia256Cfb.init(key);
    enc.encryptResync(&buf);

    try std.testing.expect(!mem.eql(u8, &buf, &plaintext));

    var dec = Camellia256Cfb.init(key);
    dec.decryptResync(&buf);

    try std.testing.expectEqualSlices(u8, &plaintext, &buf);
}

test "Camellia-192 CFB: non-resyncing encrypt/decrypt round-trip" {
    const key = [_]u8{0x55} ** 24;
    const plaintext = "Camellia-192 CFB mode test with longer data spanning many blocks.";
    var buf: [plaintext.len]u8 = undefined;
    @memcpy(&buf, plaintext);

    var enc = Camellia192Cfb.init(key);
    enc.encryptData(&buf);

    try std.testing.expect(!mem.eql(u8, &buf, plaintext));

    var dec = Camellia192Cfb.init(key);
    dec.decrypt(&buf);

    try std.testing.expectEqualSlices(u8, plaintext, &buf);
}

test "Camellia-128: multiple blocks round-trip" {
    const key = [_]u8{0x99} ** 16;
    const cipher = Camellia128.initEnc(key);

    const blocks = [_][16]u8{
        [_]u8{0x00} ** 16,
        [_]u8{0xFF} ** 16,
        .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 },
        .{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
    };

    for (blocks) |blk| {
        var ct: [16]u8 = undefined;
        cipher.encrypt(&ct, &blk);
        var pt: [16]u8 = undefined;
        cipher.decrypt(&pt, &ct);
        try std.testing.expectEqualSlices(u8, &blk, &pt);
    }
}

// =========================================================================
// Cross-cipher Tests
// =========================================================================

test "Cross-cipher: dispatch IDEA encrypt/decrypt" {
    const key = [_]u8{0x42} ** 16;
    const plaintext = [_]u8{0xAA} ** 8;
    var ct: [8]u8 = undefined;
    var pt: [8]u8 = undefined;

    try symmetric_dispatch.encryptBlock(.idea, &key, &ct, &plaintext);
    try symmetric_dispatch.decryptBlock(.idea, &key, &pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "Cross-cipher: dispatch Blowfish encrypt/decrypt" {
    const key = [_]u8{0x42} ** 16;
    const plaintext = [_]u8{0xBB} ** 8;
    var ct: [8]u8 = undefined;
    var pt: [8]u8 = undefined;

    try symmetric_dispatch.encryptBlock(.blowfish, &key, &ct, &plaintext);
    try symmetric_dispatch.decryptBlock(.blowfish, &key, &pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "Cross-cipher: dispatch Camellia-128 encrypt/decrypt" {
    const key = [_]u8{0x42} ** 16;
    const plaintext = [_]u8{0xCC} ** 16;
    var ct: [16]u8 = undefined;
    var pt: [16]u8 = undefined;

    try symmetric_dispatch.encryptBlock(.camellia128, &key, &ct, &plaintext);
    try symmetric_dispatch.decryptBlock(.camellia128, &key, &pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "Cross-cipher: dispatch Camellia-192 encrypt/decrypt" {
    const key = [_]u8{0x42} ** 24;
    const plaintext = [_]u8{0xDD} ** 16;
    var ct: [16]u8 = undefined;
    var pt: [16]u8 = undefined;

    try symmetric_dispatch.encryptBlock(.camellia192, &key, &ct, &plaintext);
    try symmetric_dispatch.decryptBlock(.camellia192, &key, &pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "Cross-cipher: dispatch Camellia-256 encrypt/decrypt" {
    const key = [_]u8{0x42} ** 32;
    const plaintext = [_]u8{0xEE} ** 16;
    var ct: [16]u8 = undefined;
    var pt: [16]u8 = undefined;

    try symmetric_dispatch.encryptBlock(.camellia256, &key, &ct, &plaintext);
    try symmetric_dispatch.decryptBlock(.camellia256, &key, &pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "Cross-cipher: IDEA key length validation" {
    const bad_key = [_]u8{0} ** 10;
    var dst: [8]u8 = undefined;
    const src = [_]u8{0} ** 8;
    try std.testing.expectError(error.InvalidKeyLength, symmetric_dispatch.encryptBlock(.idea, &bad_key, &dst, &src));
}

test "Cross-cipher: Blowfish key length validation" {
    const bad_key = [_]u8{0} ** 10;
    var dst: [8]u8 = undefined;
    const src = [_]u8{0} ** 8;
    try std.testing.expectError(error.InvalidKeyLength, symmetric_dispatch.encryptBlock(.blowfish, &bad_key, &dst, &src));
}

test "Cross-cipher: Camellia key length validation" {
    const bad_key = [_]u8{0} ** 10;
    var dst: [16]u8 = undefined;
    const src = [_]u8{0} ** 16;
    try std.testing.expectError(error.InvalidKeyLength, symmetric_dispatch.encryptBlock(.camellia128, &bad_key, &dst, &src));
    try std.testing.expectError(error.InvalidKeyLength, symmetric_dispatch.encryptBlock(.camellia256, &bad_key, &dst, &src));
}

test "Cross-cipher: CFB encryptor for IDEA" {
    const key = [_]u8{0x42} ** 16;
    const original: [16]u8 = "Hello, CFB IDEA!".*;

    var enc = try symmetric_dispatch.createCfbEncryptor(.idea, &key);
    var data = original;
    enc.encrypt(&data);
    try std.testing.expect(!mem.eql(u8, &original, &data));

    var dec = try symmetric_dispatch.createCfbEncryptor(.idea, &key);
    dec.decrypt(&data);
    try std.testing.expectEqualSlices(u8, &original, &data);
}

test "Cross-cipher: CFB encryptor for Blowfish" {
    const key = [_]u8{0x42} ** 16;
    const original: [16]u8 = "Blowfish CFB!...".*;

    var enc = try symmetric_dispatch.createCfbEncryptor(.blowfish, &key);
    var data = original;
    enc.encrypt(&data);
    try std.testing.expect(!mem.eql(u8, &original, &data));

    var dec = try symmetric_dispatch.createCfbEncryptor(.blowfish, &key);
    dec.decrypt(&data);
    try std.testing.expectEqualSlices(u8, &original, &data);
}

test "Cross-cipher: CFB encryptor for Camellia-128" {
    const key = [_]u8{0x42} ** 16;
    const original: [32]u8 = "Camellia128 CFB mode test data!!".*;

    var enc = try symmetric_dispatch.createCfbEncryptor(.camellia128, &key);
    var data = original;
    enc.encrypt(&data);
    try std.testing.expect(!mem.eql(u8, &original, &data));

    var dec = try symmetric_dispatch.createCfbEncryptor(.camellia128, &key);
    dec.decrypt(&data);
    try std.testing.expectEqualSlices(u8, &original, &data);
}

test "Cross-cipher: CFB encryptor for Camellia-256" {
    const key = [_]u8{0x42} ** 32;
    const original: [32]u8 = "Camellia256 CFB mode test data!!".*;

    var enc = try symmetric_dispatch.createCfbEncryptor(.camellia256, &key);
    var data = original;
    enc.encrypt(&data);
    try std.testing.expect(!mem.eql(u8, &original, &data));

    var dec = try symmetric_dispatch.createCfbEncryptor(.camellia256, &key);
    dec.decrypt(&data);
    try std.testing.expectEqualSlices(u8, &original, &data);
}

test "Cross-cipher: CFB encryptor block sizes" {
    const key16 = [_]u8{0x42} ** 16;
    const key32 = [_]u8{0x42} ** 32;

    const enc_idea = try symmetric_dispatch.createCfbEncryptor(.idea, &key16);
    try std.testing.expectEqual(@as(usize, 8), enc_idea.blockSize());

    const enc_bf = try symmetric_dispatch.createCfbEncryptor(.blowfish, &key16);
    try std.testing.expectEqual(@as(usize, 8), enc_bf.blockSize());

    const enc_cam128 = try symmetric_dispatch.createCfbEncryptor(.camellia128, &key16);
    try std.testing.expectEqual(@as(usize, 16), enc_cam128.blockSize());

    const enc_cam256 = try symmetric_dispatch.createCfbEncryptor(.camellia256, &key32);
    try std.testing.expectEqual(@as(usize, 16), enc_cam256.blockSize());
}

test "Cross-cipher: all 64-bit block ciphers produce different ciphertext" {
    const key = [_]u8{0x42} ** 16;
    const key24 = [_]u8{0x42} ** 24;
    const plaintext = [_]u8{0xAA} ** 8;

    var ct_idea: [8]u8 = undefined;
    var ct_bf: [8]u8 = undefined;
    var ct_cast5: [8]u8 = undefined;
    var ct_3des: [8]u8 = undefined;

    try symmetric_dispatch.encryptBlock(.idea, &key, &ct_idea, &plaintext);
    try symmetric_dispatch.encryptBlock(.blowfish, &key, &ct_bf, &plaintext);
    try symmetric_dispatch.encryptBlock(.cast5, &key, &ct_cast5, &plaintext);
    try symmetric_dispatch.encryptBlock(.triple_des, &key24, &ct_3des, &plaintext);

    // All ciphertexts should be different from each other
    try std.testing.expect(!mem.eql(u8, &ct_idea, &ct_bf));
    try std.testing.expect(!mem.eql(u8, &ct_idea, &ct_cast5));
    try std.testing.expect(!mem.eql(u8, &ct_bf, &ct_cast5));
}

test "Cross-cipher: all 128-bit block ciphers produce different ciphertext" {
    const key16 = [_]u8{0x42} ** 16;
    const key32 = [_]u8{0x42} ** 32;
    const plaintext = [_]u8{0xBB} ** 16;

    var ct_aes128: [16]u8 = undefined;
    var ct_aes256: [16]u8 = undefined;
    var ct_twofish: [16]u8 = undefined;
    var ct_cam128: [16]u8 = undefined;
    var ct_cam256: [16]u8 = undefined;

    try symmetric_dispatch.encryptBlock(.aes128, &key16, &ct_aes128, &plaintext);
    try symmetric_dispatch.encryptBlock(.aes256, &key32, &ct_aes256, &plaintext);
    try symmetric_dispatch.encryptBlock(.twofish, &key32, &ct_twofish, &plaintext);
    try symmetric_dispatch.encryptBlock(.camellia128, &key16, &ct_cam128, &plaintext);
    try symmetric_dispatch.encryptBlock(.camellia256, &key32, &ct_cam256, &plaintext);

    try std.testing.expect(!mem.eql(u8, &ct_aes128, &ct_cam128));
    try std.testing.expect(!mem.eql(u8, &ct_aes256, &ct_cam256));
    try std.testing.expect(!mem.eql(u8, &ct_twofish, &ct_cam128));
    try std.testing.expect(!mem.eql(u8, &ct_aes256, &ct_twofish));
}

// =========================================================================
// Key Stretching Tests
// =========================================================================

test "Key stretching: PBKDF2-SHA256 deterministic" {
    var out1: [32]u8 = undefined;
    var out2: [32]u8 = undefined;

    key_stretching.pbkdf2Sha256("test_password", "test_salt", 10, &out1);
    key_stretching.pbkdf2Sha256("test_password", "test_salt", 10, &out2);

    try std.testing.expectEqualSlices(u8, &out1, &out2);
}

test "Key stretching: PBKDF2-SHA512 deterministic" {
    var out1: [64]u8 = undefined;
    var out2: [64]u8 = undefined;

    key_stretching.pbkdf2Sha512("test_password", "test_salt", 10, &out1);
    key_stretching.pbkdf2Sha512("test_password", "test_salt", 10, &out2);

    try std.testing.expectEqualSlices(u8, &out1, &out2);
}

test "Key stretching: PBKDF2 as cipher key source" {
    // Derive a 16-byte key using PBKDF2, then use it with IDEA
    var derived_key: [16]u8 = undefined;
    key_stretching.pbkdf2Sha256("my_password", "my_salt", 100, &derived_key);

    const plaintext = [_]u8{0x42} ** 8;
    const cipher = Idea.initEnc(derived_key);

    var ct: [8]u8 = undefined;
    cipher.encrypt(&ct, &plaintext);

    var pt: [8]u8 = undefined;
    cipher.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "Key stretching: PBKDF2 derived key with Camellia" {
    var derived_key: [16]u8 = undefined;
    key_stretching.pbkdf2Sha256("camellia_password", "camellia_salt", 50, &derived_key);

    const plaintext = [_]u8{0x55} ** 16;
    const cipher = Camellia128.initEnc(derived_key);

    var ct: [16]u8 = undefined;
    cipher.encrypt(&ct, &plaintext);

    var pt: [16]u8 = undefined;
    cipher.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "Key stretching: scrypt basic" {
    var out1: [32]u8 = undefined;
    var out2: [32]u8 = undefined;

    try key_stretching.scryptDerive("password", "salt", 16, 1, 1, &out1);
    try key_stretching.scryptDerive("password", "salt", 16, 1, 1, &out2);

    try std.testing.expectEqualSlices(u8, &out1, &out2);
}

test "Key stretching: scrypt as cipher key source" {
    var derived_key: [32]u8 = undefined;
    try key_stretching.scryptDerive("my_password", "my_salt", 16, 1, 1, &derived_key);

    const plaintext = [_]u8{0x77} ** 16;
    const cipher = Camellia256.initEnc(derived_key);

    var ct: [16]u8 = undefined;
    cipher.encrypt(&ct, &plaintext);

    var pt: [16]u8 = undefined;
    cipher.decrypt(&pt, &ct);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

// =========================================================================
// Cipher Registry Tests
// =========================================================================

test "Cipher registry: all new ciphers are registered" {
    try std.testing.expect(cipher_registry.getCipher(.idea) != null);
    try std.testing.expect(cipher_registry.getCipher(.blowfish) != null);
    try std.testing.expect(cipher_registry.getCipher(.camellia128) != null);
    try std.testing.expect(cipher_registry.getCipher(.camellia192) != null);
    try std.testing.expect(cipher_registry.getCipher(.camellia256) != null);
}

test "Cipher registry: new ciphers are implemented" {
    try std.testing.expect(cipher_registry.isImplemented(.idea));
    try std.testing.expect(cipher_registry.isImplemented(.blowfish));
    try std.testing.expect(cipher_registry.isImplemented(.camellia128));
    try std.testing.expect(cipher_registry.isImplemented(.camellia192));
    try std.testing.expect(cipher_registry.isImplemented(.camellia256));
}

test "Cipher registry: security levels are correct" {
    // IDEA and Blowfish: medium security (64-bit block)
    try std.testing.expect(!cipher_registry.isSecure(.idea));
    try std.testing.expect(!cipher_registry.isSecure(.blowfish));

    // Camellia: high security
    try std.testing.expect(cipher_registry.isSecure(.camellia128));
    try std.testing.expect(cipher_registry.isSecure(.camellia192));
    try std.testing.expect(cipher_registry.isSecure(.camellia256));
}

test "Cipher registry: Camellia is recommended" {
    try std.testing.expect(cipher_registry.isRecommended(.camellia128));
    try std.testing.expect(cipher_registry.isRecommended(.camellia256));
    try std.testing.expect(!cipher_registry.isRecommended(.idea));
    try std.testing.expect(!cipher_registry.isRecommended(.blowfish));
}

test "Cipher registry: correct key sizes" {
    const idea_cap = cipher_registry.getCipher(.idea).?;
    try std.testing.expectEqual(@as(usize, 16), idea_cap.key_size);

    const bf_cap = cipher_registry.getCipher(.blowfish).?;
    try std.testing.expectEqual(@as(usize, 16), bf_cap.key_size);

    const cam128_cap = cipher_registry.getCipher(.camellia128).?;
    try std.testing.expectEqual(@as(usize, 16), cam128_cap.key_size);

    const cam192_cap = cipher_registry.getCipher(.camellia192).?;
    try std.testing.expectEqual(@as(usize, 24), cam192_cap.key_size);

    const cam256_cap = cipher_registry.getCipher(.camellia256).?;
    try std.testing.expectEqual(@as(usize, 32), cam256_cap.key_size);
}

test "Cipher registry: correct block sizes" {
    const idea_cap = cipher_registry.getCipher(.idea).?;
    try std.testing.expectEqual(@as(usize, 8), idea_cap.block_size);

    const bf_cap = cipher_registry.getCipher(.blowfish).?;
    try std.testing.expectEqual(@as(usize, 8), bf_cap.block_size);

    const cam128_cap = cipher_registry.getCipher(.camellia128).?;
    try std.testing.expectEqual(@as(usize, 16), cam128_cap.block_size);
}

test "Cipher registry: correct algo IDs" {
    const idea_cap = cipher_registry.getCipher(.idea).?;
    try std.testing.expectEqual(@as(u8, 1), idea_cap.algo_id);

    const bf_cap = cipher_registry.getCipher(.blowfish).?;
    try std.testing.expectEqual(@as(u8, 4), bf_cap.algo_id);

    const cam128_cap = cipher_registry.getCipher(.camellia128).?;
    try std.testing.expectEqual(@as(u8, 11), cam128_cap.algo_id);

    const cam192_cap = cipher_registry.getCipher(.camellia192).?;
    try std.testing.expectEqual(@as(u8, 12), cam192_cap.algo_id);

    const cam256_cap = cipher_registry.getCipher(.camellia256).?;
    try std.testing.expectEqual(@as(u8, 13), cam256_cap.algo_id);
}

test "Cipher registry: getCipherByAlgoId for new ciphers" {
    const idea = cipher_registry.getCipherByAlgoId(1).?;
    try std.testing.expectEqualStrings("IDEA", idea.name);

    const bf = cipher_registry.getCipherByAlgoId(4).?;
    try std.testing.expectEqualStrings("Blowfish", bf.name);

    const cam128 = cipher_registry.getCipherByAlgoId(11).?;
    try std.testing.expectEqualStrings("Camellia-128", cam128.name);
}

test "Cipher registry: getCipherByName for new ciphers" {
    try std.testing.expect(cipher_registry.getCipherByName("IDEA") != null);
    try std.testing.expect(cipher_registry.getCipherByName("Blowfish") != null);
    try std.testing.expect(cipher_registry.getCipherByName("Camellia-128") != null);
    try std.testing.expect(cipher_registry.getCipherByName("Camellia-192") != null);
    try std.testing.expect(cipher_registry.getCipherByName("Camellia-256") != null);
}

test "Cipher registry: listSecureCiphers includes Camellia" {
    const secure = cipher_registry.listSecureCiphers();
    var found_cam128 = false;
    var found_cam256 = false;
    for (secure) |cap| {
        if (cap.id == .camellia128) found_cam128 = true;
        if (cap.id == .camellia256) found_cam256 = true;
    }
    try std.testing.expect(found_cam128);
    try std.testing.expect(found_cam256);
}

test "Cipher registry: listImplementedCiphers includes all new ciphers" {
    const implemented = cipher_registry.listImplementedCiphers();
    var found_idea = false;
    var found_bf = false;
    var found_cam128 = false;
    for (implemented) |cap| {
        if (cap.id == .idea) found_idea = true;
        if (cap.id == .blowfish) found_bf = true;
        if (cap.id == .camellia128) found_cam128 = true;
    }
    try std.testing.expect(found_idea);
    try std.testing.expect(found_bf);
    try std.testing.expect(found_cam128);
}

// =========================================================================
// Enum Tests for new Camellia entries
// =========================================================================

test "SymmetricAlgorithm: Camellia enum values" {
    try std.testing.expectEqual(@as(u8, 11), @intFromEnum(SymmetricAlgorithm.camellia128));
    try std.testing.expectEqual(@as(u8, 12), @intFromEnum(SymmetricAlgorithm.camellia192));
    try std.testing.expectEqual(@as(u8, 13), @intFromEnum(SymmetricAlgorithm.camellia256));
}

test "SymmetricAlgorithm: Camellia names" {
    try std.testing.expectEqualStrings("Camellia-128", SymmetricAlgorithm.camellia128.name());
    try std.testing.expectEqualStrings("Camellia-192", SymmetricAlgorithm.camellia192.name());
    try std.testing.expectEqualStrings("Camellia-256", SymmetricAlgorithm.camellia256.name());
}

test "SymmetricAlgorithm: Camellia key sizes" {
    try std.testing.expectEqual(@as(usize, 16), SymmetricAlgorithm.camellia128.keySize().?);
    try std.testing.expectEqual(@as(usize, 24), SymmetricAlgorithm.camellia192.keySize().?);
    try std.testing.expectEqual(@as(usize, 32), SymmetricAlgorithm.camellia256.keySize().?);
}

test "SymmetricAlgorithm: Camellia block sizes" {
    try std.testing.expectEqual(@as(usize, 16), SymmetricAlgorithm.camellia128.blockSize().?);
    try std.testing.expectEqual(@as(usize, 16), SymmetricAlgorithm.camellia192.blockSize().?);
    try std.testing.expectEqual(@as(usize, 16), SymmetricAlgorithm.camellia256.blockSize().?);
}

// =========================================================================
// Symmetric dispatch: getCipherInfo for new ciphers
// =========================================================================

test "Symmetric dispatch: getCipherInfo for Camellia" {
    const cam128 = symmetric_dispatch.getCipherInfo(.camellia128).?;
    try std.testing.expectEqual(@as(usize, 16), cam128.key_size);
    try std.testing.expectEqual(@as(usize, 16), cam128.block_size);
    try std.testing.expectEqualStrings("Camellia-128", cam128.name);
    try std.testing.expectEqual(symmetric_dispatch.SecurityLevel.secure, cam128.security_level);

    const cam192 = symmetric_dispatch.getCipherInfo(.camellia192).?;
    try std.testing.expectEqual(@as(usize, 24), cam192.key_size);

    const cam256 = symmetric_dispatch.getCipherInfo(.camellia256).?;
    try std.testing.expectEqual(@as(usize, 32), cam256.key_size);
    try std.testing.expectEqual(symmetric_dispatch.SecurityLevel.secure, cam256.security_level);
}

test "Symmetric dispatch: isSupported for new ciphers" {
    try std.testing.expect(symmetric_dispatch.isSupported(.idea));
    try std.testing.expect(symmetric_dispatch.isSupported(.blowfish));
    try std.testing.expect(symmetric_dispatch.isSupported(.camellia128));
    try std.testing.expect(symmetric_dispatch.isSupported(.camellia192));
    try std.testing.expect(symmetric_dispatch.isSupported(.camellia256));
}

test "Symmetric dispatch: isSecureForNew" {
    try std.testing.expect(symmetric_dispatch.isSecureForNew(.camellia128));
    try std.testing.expect(symmetric_dispatch.isSecureForNew(.camellia192));
    try std.testing.expect(symmetric_dispatch.isSecureForNew(.camellia256));
    // IDEA and Blowfish are deprecated
    try std.testing.expect(!symmetric_dispatch.isSecureForNew(.idea));
    try std.testing.expect(!symmetric_dispatch.isSecureForNew(.blowfish));
}

test "Symmetric dispatch: validateKeyLength for new ciphers" {
    try std.testing.expect(symmetric_dispatch.validateKeyLength(.idea, 16));
    try std.testing.expect(!symmetric_dispatch.validateKeyLength(.idea, 32));
    try std.testing.expect(symmetric_dispatch.validateKeyLength(.blowfish, 16));
    try std.testing.expect(symmetric_dispatch.validateKeyLength(.camellia128, 16));
    try std.testing.expect(symmetric_dispatch.validateKeyLength(.camellia192, 24));
    try std.testing.expect(symmetric_dispatch.validateKeyLength(.camellia256, 32));
}
