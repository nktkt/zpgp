// SPDX-License-Identifier: MIT
//! Performance tests for the zpgp library.
//!
//! These tests verify that cryptographic operations complete successfully
//! on moderately large inputs. They serve as both correctness checks
//! for large data and as baseline performance benchmarks.
//!
//! Each test logs the wall-clock time for the operation using
//! std.log so that performance regressions can be detected.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Timer = std.time.Timer;

// Crypto
const seipd = @import("crypto/seipd.zig");
const seipd_v2 = @import("crypto/seipd_v2.zig");
const aead_mod = @import("crypto/aead/aead.zig");
const hash_mod = @import("crypto/hash.zig");
const HashContext = hash_mod.HashContext;
const cfb_mod = @import("crypto/cfb.zig");
const ed25519_native = @import("crypto/ed25519_native.zig");
const Ed25519Native = ed25519_native.Ed25519Native;
const x25519_native = @import("crypto/x25519_native.zig");
const X25519Native = x25519_native.X25519Native;
const s2k_mod = @import("types/s2k.zig");
const S2K = s2k_mod.S2K;

// Armor
const armor = @import("armor/armor.zig");
const crc24 = @import("armor/crc24.zig");

// Packet
const header_mod = @import("packet/header.zig");
const PacketTag = @import("packet/tags.zig").PacketTag;

// Types
const SymmetricAlgorithm = @import("types/enums.zig").SymmetricAlgorithm;

// ==========================================================================
// Symmetric Encryption Performance
// ==========================================================================

test "perf: AES-128 encrypt 1MB" {
    const allocator = testing.allocator;
    const size: usize = 1024 * 1024;
    const key = [_]u8{0x42} ** 16;

    const plaintext = try allocator.alloc(u8, size);
    defer allocator.free(plaintext);
    @memset(plaintext, 0xAB);

    var timer = try Timer.start();
    const encrypted = try seipd.seipdEncrypt(allocator, plaintext, &key, .aes128);
    defer allocator.free(encrypted);
    const elapsed_enc = timer.read();

    timer.reset();
    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, &key, .aes128);
    defer allocator.free(decrypted);
    const elapsed_dec = timer.read();

    try testing.expectEqualSlices(u8, plaintext, decrypted);
    std.log.info("AES-128 SEIPD encrypt 1MB: {d:.2}ms, decrypt: {d:.2}ms", .{
        @as(f64, @floatFromInt(elapsed_enc)) / 1_000_000.0,
        @as(f64, @floatFromInt(elapsed_dec)) / 1_000_000.0,
    });
}

test "perf: AES-256 encrypt 1MB" {
    const allocator = testing.allocator;
    const size: usize = 1024 * 1024;
    const key = [_]u8{0xAB} ** 32;

    const plaintext = try allocator.alloc(u8, size);
    defer allocator.free(plaintext);
    @memset(plaintext, 0x42);

    var timer = try Timer.start();
    const encrypted = try seipd.seipdEncrypt(allocator, plaintext, &key, .aes256);
    defer allocator.free(encrypted);
    const elapsed_enc = timer.read();

    timer.reset();
    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, &key, .aes256);
    defer allocator.free(decrypted);
    const elapsed_dec = timer.read();

    try testing.expectEqualSlices(u8, plaintext, decrypted);
    std.log.info("AES-256 SEIPD encrypt 1MB: {d:.2}ms, decrypt: {d:.2}ms", .{
        @as(f64, @floatFromInt(elapsed_enc)) / 1_000_000.0,
        @as(f64, @floatFromInt(elapsed_dec)) / 1_000_000.0,
    });
}

test "perf: SHA-256 hash 1MB" {
    const size: usize = 1024 * 1024;
    var data: [1024]u8 = undefined;
    @memset(&data, 0x42);

    var timer = try Timer.start();
    var ctx = try HashContext.init(.sha256);
    var remaining: usize = size;
    while (remaining > 0) {
        const chunk = @min(remaining, data.len);
        ctx.update(data[0..chunk]);
        remaining -= chunk;
    }
    var digest: [32]u8 = undefined;
    ctx.final(&digest);
    const elapsed = timer.read();

    // Verify it's deterministic
    var ctx2 = try HashContext.init(.sha256);
    remaining = size;
    while (remaining > 0) {
        const chunk = @min(remaining, data.len);
        ctx2.update(data[0..chunk]);
        remaining -= chunk;
    }
    var digest2: [32]u8 = undefined;
    ctx2.final(&digest2);
    try testing.expectEqualSlices(u8, &digest, &digest2);

    std.log.info("SHA-256 hash 1MB: {d:.2}ms", .{
        @as(f64, @floatFromInt(elapsed)) / 1_000_000.0,
    });
}

test "perf: SHA-512 hash 1MB" {
    const size: usize = 1024 * 1024;
    var data: [1024]u8 = undefined;
    @memset(&data, 0xAB);

    var timer = try Timer.start();
    var ctx = try HashContext.init(.sha512);
    var remaining: usize = size;
    while (remaining > 0) {
        const chunk = @min(remaining, data.len);
        ctx.update(data[0..chunk]);
        remaining -= chunk;
    }
    var digest: [64]u8 = undefined;
    ctx.final(&digest);
    const elapsed = timer.read();

    std.log.info("SHA-512 hash 1MB: {d:.2}ms", .{
        @as(f64, @floatFromInt(elapsed)) / 1_000_000.0,
    });
}

test "perf: CAST5 encrypt 1MB" {
    const allocator = testing.allocator;
    const size: usize = 1024 * 1024;
    const key = [_]u8{0xDE} ** 16;

    const plaintext = try allocator.alloc(u8, size);
    defer allocator.free(plaintext);
    @memset(plaintext, 0x33);

    var timer = try Timer.start();
    const encrypted = try seipd.seipdEncrypt(allocator, plaintext, &key, .cast5);
    defer allocator.free(encrypted);
    const elapsed = timer.read();

    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, &key, .cast5);
    defer allocator.free(decrypted);
    try testing.expectEqualSlices(u8, plaintext, decrypted);

    std.log.info("CAST5 SEIPD encrypt 1MB: {d:.2}ms", .{
        @as(f64, @floatFromInt(elapsed)) / 1_000_000.0,
    });
}

test "perf: Twofish encrypt 1MB" {
    const allocator = testing.allocator;
    const size: usize = 1024 * 1024;
    const key = [_]u8{0x77} ** 32;

    const plaintext = try allocator.alloc(u8, size);
    defer allocator.free(plaintext);
    @memset(plaintext, 0x55);

    var timer = try Timer.start();
    const encrypted = try seipd.seipdEncrypt(allocator, plaintext, &key, .twofish);
    defer allocator.free(encrypted);
    const elapsed = timer.read();

    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, &key, .twofish);
    defer allocator.free(decrypted);
    try testing.expectEqualSlices(u8, plaintext, decrypted);

    std.log.info("Twofish SEIPD encrypt 1MB: {d:.2}ms", .{
        @as(f64, @floatFromInt(elapsed)) / 1_000_000.0,
    });
}

// ==========================================================================
// SEIPD v2 / AEAD Performance
// ==========================================================================

test "perf: SEIPD v1 encrypt/decrypt 100KB" {
    const allocator = testing.allocator;
    const size: usize = 100 * 1024;
    const key = [_]u8{0x42} ** 16;

    const plaintext = try allocator.alloc(u8, size);
    defer allocator.free(plaintext);
    @memset(plaintext, 0xAA);

    var timer = try Timer.start();
    const encrypted = try seipd.seipdEncrypt(allocator, plaintext, &key, .aes128);
    defer allocator.free(encrypted);
    const elapsed_enc = timer.read();

    timer.reset();
    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, &key, .aes128);
    defer allocator.free(decrypted);
    const elapsed_dec = timer.read();

    try testing.expectEqualSlices(u8, plaintext, decrypted);
    std.log.info("SEIPD v1 100KB: enc {d:.2}ms, dec {d:.2}ms", .{
        @as(f64, @floatFromInt(elapsed_enc)) / 1_000_000.0,
        @as(f64, @floatFromInt(elapsed_dec)) / 1_000_000.0,
    });
}

test "perf: SEIPDv2 EAX encrypt/decrypt 100KB" {
    const allocator = testing.allocator;
    const size: usize = 100 * 1024;
    const key = [_]u8{0x42} ** 16;

    const plaintext = try allocator.alloc(u8, size);
    defer allocator.free(plaintext);
    @memset(plaintext, 0xBB);

    var timer = try Timer.start();
    const encrypted = try seipd_v2.seipdV2Encrypt(allocator, plaintext, &key, .aes128, .eax, 6);
    defer allocator.free(encrypted);
    const elapsed_enc = timer.read();

    timer.reset();
    const decrypted = try seipd_v2.seipdV2Decrypt(allocator, encrypted, &key);
    defer allocator.free(decrypted);
    const elapsed_dec = timer.read();

    try testing.expectEqualSlices(u8, plaintext, decrypted);
    std.log.info("SEIPDv2 EAX 100KB: enc {d:.2}ms, dec {d:.2}ms", .{
        @as(f64, @floatFromInt(elapsed_enc)) / 1_000_000.0,
        @as(f64, @floatFromInt(elapsed_dec)) / 1_000_000.0,
    });
}

test "perf: SEIPDv2 OCB encrypt/decrypt 100KB" {
    const allocator = testing.allocator;
    const size: usize = 100 * 1024;
    const key = [_]u8{0x77} ** 16;

    const plaintext = try allocator.alloc(u8, size);
    defer allocator.free(plaintext);
    @memset(plaintext, 0xCC);

    var timer = try Timer.start();
    const encrypted = try seipd_v2.seipdV2Encrypt(allocator, plaintext, &key, .aes128, .ocb, 6);
    defer allocator.free(encrypted);
    const elapsed_enc = timer.read();

    timer.reset();
    const decrypted = try seipd_v2.seipdV2Decrypt(allocator, encrypted, &key);
    defer allocator.free(decrypted);
    const elapsed_dec = timer.read();

    try testing.expectEqualSlices(u8, plaintext, decrypted);
    std.log.info("SEIPDv2 OCB 100KB: enc {d:.2}ms, dec {d:.2}ms", .{
        @as(f64, @floatFromInt(elapsed_enc)) / 1_000_000.0,
        @as(f64, @floatFromInt(elapsed_dec)) / 1_000_000.0,
    });
}

test "perf: SEIPDv2 GCM encrypt/decrypt 100KB" {
    const allocator = testing.allocator;
    const size: usize = 100 * 1024;
    const key = [_]u8{0xAB} ** 32;

    const plaintext = try allocator.alloc(u8, size);
    defer allocator.free(plaintext);
    @memset(plaintext, 0xDD);

    var timer = try Timer.start();
    const encrypted = try seipd_v2.seipdV2Encrypt(allocator, plaintext, &key, .aes256, .gcm, 6);
    defer allocator.free(encrypted);
    const elapsed_enc = timer.read();

    timer.reset();
    const decrypted = try seipd_v2.seipdV2Decrypt(allocator, encrypted, &key);
    defer allocator.free(decrypted);
    const elapsed_dec = timer.read();

    try testing.expectEqualSlices(u8, plaintext, decrypted);
    std.log.info("SEIPDv2 GCM 100KB: enc {d:.2}ms, dec {d:.2}ms", .{
        @as(f64, @floatFromInt(elapsed_enc)) / 1_000_000.0,
        @as(f64, @floatFromInt(elapsed_dec)) / 1_000_000.0,
    });
}

// ==========================================================================
// Armor and CRC Performance
// ==========================================================================

test "perf: armor encode/decode 100KB" {
    const allocator = testing.allocator;
    const size: usize = 100 * 1024;

    const data = try allocator.alloc(u8, size);
    defer allocator.free(data);
    @memset(data, 0x42);

    var timer = try Timer.start();
    const armored = try armor.encode(allocator, data, .message, null);
    defer allocator.free(armored);
    const elapsed_enc = timer.read();

    timer.reset();
    var result = try armor.decode(allocator, armored);
    defer result.deinit();
    const elapsed_dec = timer.read();

    try testing.expectEqualSlices(u8, data, result.data);
    std.log.info("Armor 100KB: encode {d:.2}ms, decode {d:.2}ms", .{
        @as(f64, @floatFromInt(elapsed_enc)) / 1_000_000.0,
        @as(f64, @floatFromInt(elapsed_dec)) / 1_000_000.0,
    });
}

test "perf: CRC-24 compute 1MB" {
    const size: usize = 1024 * 1024;
    var data: [4096]u8 = undefined;
    @memset(&data, 0xAB);

    var timer = try Timer.start();
    var crc = crc24.Crc24{};
    var remaining: usize = size;
    while (remaining > 0) {
        const chunk = @min(remaining, data.len);
        crc.update(data[0..chunk]);
        remaining -= chunk;
    }
    const result = crc.final();
    const elapsed = timer.read();

    // Just verify it's a valid 24-bit value
    try testing.expect(@as(u32, result) <= 0xFFFFFF);
    std.log.info("CRC-24 1MB: {d:.2}ms", .{
        @as(f64, @floatFromInt(elapsed)) / 1_000_000.0,
    });
}

test "perf: packet parse stream of 1000 small packets" {
    // Build a stream of 1000 new-format literal data packet headers
    var buf: [3000]u8 = undefined;
    var offset: usize = 0;

    for (0..1000) |_| {
        var fbs = std.io.fixedBufferStream(buf[offset..]);
        header_mod.writeHeader(fbs.writer(), PacketTag.literal_data, 0) catch break;
        offset += fbs.pos;
    }

    var timer = try Timer.start();
    var parse_offset: usize = 0;
    var count: usize = 0;
    while (parse_offset < offset) {
        var fbs = std.io.fixedBufferStream(buf[parse_offset..offset]);
        const hdr = header_mod.readHeader(fbs.reader()) catch break;
        _ = hdr;
        parse_offset += fbs.pos;
        count += 1;
    }
    const elapsed = timer.read();

    try testing.expectEqual(@as(usize, 1000), count);
    std.log.info("Parse 1000 packet headers: {d:.2}us", .{
        @as(f64, @floatFromInt(elapsed)) / 1_000.0,
    });
}

test "perf: S2K iterated derivation" {
    const s2k = S2K{
        .s2k_type = .iterated,
        .hash_algo = .sha256,
        .salt = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 },
        .coded_count = 96, // 65536 bytes
        .argon2_data = null,
    };

    var key: [32]u8 = undefined;

    var timer = try Timer.start();
    try s2k.deriveKey("passphrase123", &key);
    const elapsed = timer.read();

    // Verify determinism
    var key2: [32]u8 = undefined;
    try s2k.deriveKey("passphrase123", &key2);
    try testing.expectEqualSlices(u8, &key, &key2);

    std.log.info("S2K iterated (65536 bytes): {d:.2}ms", .{
        @as(f64, @floatFromInt(elapsed)) / 1_000_000.0,
    });
}

// ==========================================================================
// Ed25519 and X25519 Performance
// ==========================================================================

test "perf: Ed25519 sign 1000 messages" {
    const kp = Ed25519Native.generate();
    const msg = "Performance test message for Ed25519 signing operations";

    var timer = try Timer.start();
    for (0..1000) |_| {
        _ = try Ed25519Native.sign(kp.secret, kp.public, msg);
    }
    const elapsed = timer.read();

    // Verify one signature
    const sig = try Ed25519Native.sign(kp.secret, kp.public, msg);
    try Ed25519Native.verify(kp.public, msg, sig);

    std.log.info("Ed25519 sign 1000 messages: {d:.2}ms ({d:.2}us/sig)", .{
        @as(f64, @floatFromInt(elapsed)) / 1_000_000.0,
        @as(f64, @floatFromInt(elapsed)) / 1_000_000.0,
    });
}

test "perf: X25519 key agreement 100 times" {
    var timer = try Timer.start();
    for (0..100) |_| {
        const kp1 = X25519Native.generate();
        _ = kp1;
    }
    const elapsed = timer.read();

    // Verify key generation works
    const kp = X25519Native.generate();
    try testing.expectEqual(@as(usize, 32), kp.public.len);
    try testing.expectEqual(@as(usize, 32), kp.secret.len);

    std.log.info("X25519 keygen 100 times: {d:.2}ms ({d:.2}us/keygen)", .{
        @as(f64, @floatFromInt(elapsed)) / 1_000_000.0,
        @as(f64, @floatFromInt(elapsed)) / 100_000.0,
    });
}
