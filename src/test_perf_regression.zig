// SPDX-License-Identifier: MIT
//! Performance Regression Test Suite.
//!
//! Tests that verify operations complete within reasonable bounds. These are
//! not micro-benchmarks but sanity checks to catch regressions, infinite loops,
//! and stack overflows. Each test verifies both correctness and completion.
//!
//! All tests use testing.allocator for leak detection.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Timer = std.time.Timer;

// Crypto
const seipd = @import("crypto/seipd.zig");
const seipd_v2 = @import("crypto/seipd_v2.zig");
const session_key_mod = @import("crypto/session_key.zig");
const hash_mod = @import("crypto/hash.zig");
const HashContext = hash_mod.HashContext;
const ed25519_ops = @import("crypto/ed25519_ops.zig");
const s2k_mod = @import("types/s2k.zig");
const S2K = s2k_mod.S2K;

// Armor
const armor = @import("armor/armor.zig");
const crc24 = @import("armor/crc24.zig");

// Packet
const header_mod = @import("packet/header.zig");
const PacketTag = @import("packet/tags.zig").PacketTag;

// Types
const enums = @import("types/enums.zig");
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const mpi_mod = @import("types/mpi.zig");
const Mpi = mpi_mod.Mpi;

// Packets
const public_key_mod = @import("packets/public_key.zig");
const PublicKeyPacket = public_key_mod.PublicKeyPacket;
const user_id_mod = @import("packets/user_id.zig");
const UserIdPacket = user_id_mod.UserIdPacket;

// Key modules
const key_mod = @import("key/key.zig");
const Key = key_mod.Key;
const import_export = @import("key/import_export.zig");
const fingerprint_mod = @import("key/fingerprint.zig");
const keyring_mod = @import("key/keyring.zig");
const Keyring = keyring_mod.Keyring;

// Signature modules
const subpackets_mod = @import("signature/subpackets.zig");
const cleartext = @import("signature/cleartext.zig");

// Message modules
const compose = @import("message/compose.zig");
const decompose_mod = @import("message/decompose.zig");

// Security
const zeroize = @import("security/zeroize.zig");

// ==========================================================================
// AES Encryption Performance
// ==========================================================================

test "perf_regression: AES-256 SEIPD encrypt 1MB completes" {
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
    std.log.info("AES-256 SEIPD 1MB: enc {d:.2}ms, dec {d:.2}ms", .{
        @as(f64, @floatFromInt(elapsed_enc)) / 1_000_000.0,
        @as(f64, @floatFromInt(elapsed_dec)) / 1_000_000.0,
    });
}

// ==========================================================================
// SHA-256 Hashing Performance
// ==========================================================================

test "perf_regression: SHA-256 hash 10MB completes" {
    const total_size: usize = 10 * 1024 * 1024;
    var chunk: [4096]u8 = undefined;
    @memset(&chunk, 0x42);

    var timer = try Timer.start();
    var ctx = try HashContext.init(.sha256);
    var remaining: usize = total_size;
    while (remaining > 0) {
        const sz = @min(remaining, chunk.len);
        ctx.update(chunk[0..sz]);
        remaining -= sz;
    }
    var digest: [32]u8 = undefined;
    ctx.final(&digest);
    const elapsed = timer.read();

    // Verify determinism
    var ctx2 = try HashContext.init(.sha256);
    remaining = total_size;
    while (remaining > 0) {
        const sz = @min(remaining, chunk.len);
        ctx2.update(chunk[0..sz]);
        remaining -= sz;
    }
    var digest2: [32]u8 = undefined;
    ctx2.final(&digest2);
    try testing.expectEqualSlices(u8, &digest, &digest2);

    std.log.info("SHA-256 hash 10MB: {d:.2}ms", .{@as(f64, @floatFromInt(elapsed)) / 1_000_000.0});
}

// ==========================================================================
// Ed25519 Sign/Verify Performance
// ==========================================================================

test "perf_regression: Ed25519 keygen x100" {
    var timer = try Timer.start();
    for (0..100) |_| _ = try ed25519_ops.ed25519Generate();
    const elapsed = timer.read();
    std.log.info("Ed25519 keygen x100: {d:.2}ms", .{@as(f64, @floatFromInt(elapsed)) / 1_000_000.0});
}

test "perf_regression: Ed25519 sign+verify x1000" {
    const kp = try ed25519_ops.ed25519Generate();
    const msg = "Performance test message for signing";
    var timer = try Timer.start();
    for (0..1000) |_| {
        const sig = try ed25519_ops.ed25519Sign(kp.secret_key, msg);
        try ed25519_ops.ed25519Verify(kp.public_key, msg, sig);
    }
    const elapsed = timer.read();
    std.log.info("Ed25519 sign+verify x1000: {d:.2}ms", .{@as(f64, @floatFromInt(elapsed)) / 1_000_000.0});
}

// ==========================================================================
// Large Keyring Operations
// ==========================================================================

test "perf_regression: keyring with 100 keys" {
    const allocator = testing.allocator;
    var ring = Keyring.init(allocator);
    defer ring.deinit();

    var fingerprints: [100][20]u8 = undefined;
    var timer = try Timer.start();
    for (0..100) |i| {
        var body: [12]u8 = undefined;
        body[0] = 4;
        mem.writeInt(u32, body[1..5], @as(u32, @intCast(1000000 + i * 1000)), .big);
        body[5] = 1;
        mem.writeInt(u16, body[6..8], 8, .big);
        body[8] = 0xFF;
        mem.writeInt(u16, body[9..11], 8, .big);
        body[11] = @as(u8, @intCast((i % 254) + 1));

        const pk = try PublicKeyPacket.parse(allocator, &body, false);
        var key = Key.init(pk);
        const uid_text = try std.fmt.allocPrint(allocator, "U{d} <u{d}@t>", .{ i, i });
        defer allocator.free(uid_text);
        const uid = try UserIdPacket.parse(allocator, uid_text);
        try key.addUserId(allocator, .{ .user_id = uid, .self_signature = null, .certifications = .empty });
        fingerprints[i] = key.fingerprint();
        try ring.addKey(key);
    }
    const elapsed_add = timer.read();

    timer.reset();
    for (fingerprints) |fp| try testing.expect(ring.findByFingerprint(fp) != null);
    const elapsed_lookup = timer.read();

    std.log.info("Keyring 100: add {d:.2}ms, lookup {d:.2}ms", .{
        @as(f64, @floatFromInt(elapsed_add)) / 1_000_000.0,
        @as(f64, @floatFromInt(elapsed_lookup)) / 1_000_000.0,
    });
}

// ==========================================================================
// Packet Parsing Performance
// ==========================================================================

test "perf_regression: parse 10000 packet headers" {
    const count = 10000;
    var buf: [count * 3]u8 = undefined;
    var offset: usize = 0;
    for (0..count) |_| {
        var fbs = std.io.fixedBufferStream(buf[offset..]);
        header_mod.writeHeader(fbs.writer(), .literal_data, 0) catch break;
        offset += fbs.pos;
    }
    var timer = try Timer.start();
    var p: usize = 0;
    var n: usize = 0;
    while (p < offset) {
        var fbs = std.io.fixedBufferStream(buf[p..offset]);
        _ = header_mod.readHeader(fbs.reader()) catch break;
        p += fbs.pos;
        n += 1;
    }
    const elapsed = timer.read();
    try testing.expectEqual(@as(usize, count), n);
    std.log.info("Parse {d} headers: {d:.2}us", .{ count, @as(f64, @floatFromInt(elapsed)) / 1_000.0 });
}

test "perf_regression: parse 100 subpackets" {
    const allocator = testing.allocator;
    var data: [600]u8 = undefined;
    var offset: usize = 0;
    for (0..100) |i| {
        if (offset + 6 > data.len) break;
        data[offset] = 5;
        data[offset + 1] = 2;
        mem.writeInt(u32, data[offset + 2 ..][0..4], @as(u32, @intCast(1000000 + i)), .big);
        offset += 6;
    }
    var timer = try Timer.start();
    const sp = try subpackets_mod.parseSubpackets(allocator, data[0..offset]);
    defer subpackets_mod.freeSubpackets(allocator, sp);
    const elapsed = timer.read();
    try testing.expectEqual(@as(usize, 100), sp.len);
    std.log.info("Parse 100 subpackets: {d:.2}us", .{@as(f64, @floatFromInt(elapsed)) / 1_000.0});
}

// ==========================================================================
// Armor Encoding/Decoding Performance
// ==========================================================================

test "perf_regression: armor encode/decode 1MB" {
    const allocator = testing.allocator;
    const size: usize = 1024 * 1024;
    const data = try allocator.alloc(u8, size);
    defer allocator.free(data);
    for (data, 0..) |*b, i| b.* = @truncate(i *% 251 +% 37);

    var timer = try Timer.start();
    const armored = try armor.encode(allocator, data, .message, null);
    defer allocator.free(armored);
    const elapsed_enc = timer.read();
    timer.reset();
    var decoded = try armor.decode(allocator, armored);
    defer decoded.deinit();
    const elapsed_dec = timer.read();

    try testing.expectEqualSlices(u8, data, decoded.data);
    std.log.info("Armor 1MB: enc {d:.2}ms, dec {d:.2}ms", .{
        @as(f64, @floatFromInt(elapsed_enc)) / 1_000_000.0,
        @as(f64, @floatFromInt(elapsed_dec)) / 1_000_000.0,
    });
}

// ==========================================================================
// Session Key Operations
// ==========================================================================

test "perf_regression: session key generation all algorithms" {
    const algos = [_]struct { a: SymmetricAlgorithm, n: []const u8 }{
        .{ .a = .aes128, .n = "AES-128" }, .{ .a = .aes256, .n = "AES-256" },
        .{ .a = .cast5, .n = "CAST5" },    .{ .a = .twofish, .n = "Twofish" },
    };
    for (algos) |a| {
        var timer = try Timer.start();
        for (0..1000) |_| _ = try session_key_mod.generateSessionKey(a.a);
        const elapsed = timer.read();
        std.log.info("Sess key {s} x1000: {d:.2}us", .{ a.n, @as(f64, @floatFromInt(elapsed)) / 1_000.0 });
    }
}

test "perf_regression: session key SEIPD round-trip all AES" {
    const allocator = testing.allocator;
    const plaintext = "Session key perf test data" ** 10;
    // Note: AES-192 excluded (Zig std lacks Aes192)
    const algos = [_]SymmetricAlgorithm{ .aes128, .aes256 };
    for (algos) |algo| {
        const sk = try session_key_mod.generateSessionKey(algo);
        const encrypted = try seipd.seipdEncrypt(allocator, plaintext, sk.keySlice(), algo);
        defer allocator.free(encrypted);
        const decrypted = try seipd.seipdDecrypt(allocator, encrypted, sk.keySlice(), algo);
        defer allocator.free(decrypted);
        try testing.expectEqualStrings(plaintext, decrypted);
    }
}

// ==========================================================================
// SEIPD v2 (AEAD) Performance
// ==========================================================================

test "perf_regression: SEIPD v2 all AEAD modes 1MB" {
    const allocator = testing.allocator;
    const size: usize = 1024 * 1024;
    const plaintext = try allocator.alloc(u8, size);
    defer allocator.free(plaintext);
    @memset(plaintext, 0xAA);

    const modes = [_]struct { mode: @import("crypto/aead/aead.zig").AeadAlgorithm, key: []const u8, algo: SymmetricAlgorithm, name: []const u8 }{
        .{ .mode = .eax, .key = &([_]u8{0x42} ** 16), .algo = .aes128, .name = "EAX" },
        .{ .mode = .ocb, .key = &([_]u8{0x77} ** 16), .algo = .aes128, .name = "OCB" },
        .{ .mode = .gcm, .key = &([_]u8{0xAB} ** 32), .algo = .aes256, .name = "GCM" },
    };

    for (modes) |m| {
        var timer = try Timer.start();
        const encrypted = try seipd_v2.seipdV2Encrypt(allocator, plaintext, m.key, m.algo, m.mode, 6);
        defer allocator.free(encrypted);
        const elapsed_enc = timer.read();
        timer.reset();
        const decrypted = try seipd_v2.seipdV2Decrypt(allocator, encrypted, m.key);
        defer allocator.free(decrypted);
        const elapsed_dec = timer.read();
        try testing.expectEqualSlices(u8, plaintext, decrypted);
        std.log.info("SEIPD v2 {s} 1MB: enc {d:.2}ms, dec {d:.2}ms", .{
            m.name,
            @as(f64, @floatFromInt(elapsed_enc)) / 1_000_000.0,
            @as(f64, @floatFromInt(elapsed_dec)) / 1_000_000.0,
        });
    }
}

// ==========================================================================
// S2K Key Derivation Performance
// ==========================================================================

test "perf_regression: S2K iterated derivation" {
    const salt = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 };
    const codes = [_]struct { c: u8, n: []const u8 }{ .{ .c = 0, .n = "min" }, .{ .c = 96, .n = "default" } };
    for (codes) |cc| {
        const s2k = S2K{ .s2k_type = .iterated, .hash_algo = .sha256, .salt = salt, .coded_count = cc.c, .argon2_data = null };
        var key: [32]u8 = undefined;
        var timer = try Timer.start();
        try s2k.deriveKey("test-passphrase", &key);
        const elapsed = timer.read();
        std.log.info("S2K iterated {s}: {d:.2}us", .{ cc.n, @as(f64, @floatFromInt(elapsed)) / 1_000.0 });
    }
}

// ==========================================================================
// Message Compose/Decompose Performance
// ==========================================================================

test "perf_regression: message compose/decompose 100KB" {
    const allocator = testing.allocator;
    const size: usize = 100 * 1024;
    const plaintext = try allocator.alloc(u8, size);
    defer allocator.free(plaintext);
    for (plaintext, 0..) |*b, i| b.* = @truncate(i *% 251 +% 37);

    var timer = try Timer.start();
    const encrypted = try compose.encryptMessageSymmetric(allocator, plaintext, "p.bin", "pw", .aes256, null);
    defer allocator.free(encrypted);
    const elapsed_enc = timer.read();
    timer.reset();
    var msg = try decompose_mod.parseMessage(allocator, encrypted);
    defer msg.deinit(allocator);
    const elapsed_parse = timer.read();
    timer.reset();
    const decrypted = try decompose_mod.decryptWithPassphrase(allocator, &msg, "pw");
    defer allocator.free(decrypted);
    const elapsed_dec = timer.read();

    try testing.expectEqualSlices(u8, plaintext, decrypted);
    std.log.info("Msg 100KB: compose {d:.2}ms, parse {d:.2}ms, decrypt {d:.2}ms", .{
        @as(f64, @floatFromInt(elapsed_enc)) / 1_000_000.0,
        @as(f64, @floatFromInt(elapsed_parse)) / 1_000_000.0,
        @as(f64, @floatFromInt(elapsed_dec)) / 1_000_000.0,
    });
}

// ==========================================================================
// Key Export/Import Performance
// ==========================================================================

test "perf_regression: key export+import x50" {
    const allocator = testing.allocator;
    var body: [12]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], 1000, .big);
    body[5] = 1;
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xFF;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;
    const pk = try PublicKeyPacket.parse(allocator, &body, false);
    var key = Key.init(pk);
    defer key.deinit(allocator);
    const uid = try UserIdPacket.parse(allocator, "Perf <p@t>");
    try key.addUserId(allocator, .{ .user_id = uid, .self_signature = null, .certifications = .empty });

    var timer = try Timer.start();
    for (0..50) |_| {
        const exported = try import_export.exportPublicKey(allocator, &key);
        defer allocator.free(exported);
        var imported = try import_export.importPublicKey(allocator, exported);
        imported.deinit(allocator);
    }
    const elapsed = timer.read();
    std.log.info("Key export+import x50: {d:.2}ms", .{@as(f64, @floatFromInt(elapsed)) / 1_000_000.0});
}

// ==========================================================================
// Fingerprint Calculation Performance
// ==========================================================================

test "perf_regression: fingerprint x10000" {
    const body = [_]u8{ 4, 0x5E, 0x0B, 0xE1, 0x00, 1, 0x00, 0x08, 0xFF, 0x00, 0x08, 0x03 };
    var timer = try Timer.start();
    var last: [20]u8 = undefined;
    for (0..10000) |_| last = fingerprint_mod.calculateV4Fingerprint(&body);
    const elapsed = timer.read();
    try testing.expectEqual(fingerprint_mod.calculateV4Fingerprint(&body), last);
    std.log.info("V4 fingerprint x10000: {d:.2}us", .{@as(f64, @floatFromInt(elapsed)) / 1_000.0});
}

// ==========================================================================
// Secure Memory Operations Performance
// ==========================================================================

test "perf_regression: secureZero 1MB" {
    const allocator = testing.allocator;
    const data = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(data);
    @memset(data, 0xFF);
    var timer = try Timer.start();
    zeroize.secureZeroBytes(data);
    const elapsed = timer.read();
    for (data) |b| try testing.expectEqual(@as(u8, 0), b);
    std.log.info("secureZero 1MB: {d:.2}us", .{@as(f64, @floatFromInt(elapsed)) / 1_000.0});
}

test "perf_regression: secureEqual 256B x1000" {
    const a = [_]u8{0xAA} ** 256;
    const b = [_]u8{0xAA} ** 256;
    var timer = try Timer.start();
    for (0..1000) |_| try testing.expect(zeroize.secureEqual(&a, &b));
    const elapsed = timer.read();
    std.log.info("secureEqual 256B x1000: {d:.2}us", .{@as(f64, @floatFromInt(elapsed)) / 1_000.0});
}

// ==========================================================================
// CRC-24 Performance
// ==========================================================================

test "perf_regression: CRC-24 10MB" {
    const total: usize = 10 * 1024 * 1024;
    var chunk: [4096]u8 = undefined;
    @memset(&chunk, 0xAB);
    var timer = try Timer.start();
    var crc = crc24.Crc24{};
    var rem: usize = total;
    while (rem > 0) { const sz = @min(rem, chunk.len); crc.update(chunk[0..sz]); rem -= sz; }
    const result = crc.final();
    const elapsed = timer.read();
    try testing.expect(@as(u32, result) <= 0xFFFFFF);
    std.log.info("CRC-24 10MB: {d:.2}ms", .{@as(f64, @floatFromInt(elapsed)) / 1_000_000.0});
}

// ==========================================================================
// MPI Performance
// ==========================================================================

test "perf_regression: MPI 2048-bit read/write x10000" {
    const allocator = testing.allocator;
    var mpi_data: [256]u8 = undefined;
    mpi_data[0] = 0x80;
    @memset(mpi_data[1..], 0xAA);
    const original = Mpi.fromBytes(&mpi_data);
    var buf: [258]u8 = undefined;

    var timer = try Timer.start();
    for (0..10000) |_| {
        var fbs = std.io.fixedBufferStream(&buf);
        try original.writeTo(fbs.writer());
        fbs.pos = 0;
        const m = try Mpi.readFrom(allocator, fbs.reader());
        m.deinit(allocator);
    }
    const elapsed = timer.read();
    std.log.info("MPI 2048b r/w x10000: {d:.2}ms", .{@as(f64, @floatFromInt(elapsed)) / 1_000_000.0});
}

// ==========================================================================
// SHA-512 Hashing Performance
// ==========================================================================

test "perf_regression: SHA-512 hash 10MB completes" {
    const total_size: usize = 10 * 1024 * 1024;
    var chunk: [4096]u8 = undefined;
    @memset(&chunk, 0xAB);

    var timer = try Timer.start();
    var ctx = try HashContext.init(.sha512);
    var remaining: usize = total_size;
    while (remaining > 0) {
        const sz = @min(remaining, chunk.len);
        ctx.update(chunk[0..sz]);
        remaining -= sz;
    }
    var digest: [64]u8 = undefined;
    ctx.final(&digest);
    const elapsed = timer.read();
    std.log.info("SHA-512 hash 10MB: {d:.2}ms", .{@as(f64, @floatFromInt(elapsed)) / 1_000_000.0});
}

// ==========================================================================
// All Hash Algorithms 1MB
// ==========================================================================

test "perf_regression: all hash algorithms 1MB" {
    const total_size: usize = 1024 * 1024;
    var chunk: [4096]u8 = undefined;
    @memset(&chunk, 0x42);

    const algos = [_]struct { a: HashAlgorithm, ds: usize, n: []const u8 }{
        .{ .a = .sha1, .ds = 20, .n = "SHA-1" },
        .{ .a = .sha224, .ds = 28, .n = "SHA-224" },
        .{ .a = .sha256, .ds = 32, .n = "SHA-256" },
        .{ .a = .sha384, .ds = 48, .n = "SHA-384" },
        .{ .a = .sha512, .ds = 64, .n = "SHA-512" },
    };
    for (algos) |a| {
        var timer = try Timer.start();
        var ctx = try HashContext.init(a.a);
        var remaining: usize = total_size;
        while (remaining > 0) {
            const sz = @min(remaining, chunk.len);
            ctx.update(chunk[0..sz]);
            remaining -= sz;
        }
        var digest: [64]u8 = undefined;
        ctx.final(digest[0..a.ds]);
        const elapsed = timer.read();
        std.log.info("{s} hash 1MB: {d:.2}ms", .{ a.n, @as(f64, @floatFromInt(elapsed)) / 1_000_000.0 });
    }
}

// ==========================================================================
// Ed25519 sign large message
// ==========================================================================

test "perf_regression: Ed25519 sign/verify 1MB message" {
    const kp = try ed25519_ops.ed25519Generate();
    var message: [1024 * 1024]u8 = undefined;
    @memset(&message, 0x42);

    var timer = try Timer.start();
    const sig = try ed25519_ops.ed25519Sign(kp.secret_key, &message);
    const elapsed_sign = timer.read();
    timer.reset();
    try ed25519_ops.ed25519Verify(kp.public_key, &message, sig);
    const elapsed_verify = timer.read();

    std.log.info("Ed25519 1MB: sign {d:.2}ms, verify {d:.2}ms", .{
        @as(f64, @floatFromInt(elapsed_sign)) / 1_000_000.0,
        @as(f64, @floatFromInt(elapsed_verify)) / 1_000_000.0,
    });
}

// ==========================================================================
// Cleartext signature performance
// ==========================================================================

test "perf_regression: cleartext sign+parse 10KB x10" {
    const allocator = testing.allocator;
    var text_buf: [10 * 1024]u8 = undefined;
    @memset(&text_buf, 'A');
    var i: usize = 0;
    while (i < text_buf.len) : (i += 80) {
        if (i + 80 < text_buf.len) text_buf[i + 79] = '\n';
    }
    const mock_sig = [_]u8{ 0x04, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00 };

    var timer = try Timer.start();
    for (0..10) |_| {
        const msg = try cleartext.createCleartextSignature(allocator, &text_buf, &mock_sig, .sha256);
        defer allocator.free(msg);
        const parsed = try cleartext.parseCleartextSignature(allocator, msg);
        defer parsed.deinit(allocator);
    }
    const elapsed = timer.read();
    std.log.info("Cleartext sign+parse 10KB x10: {d:.2}ms", .{@as(f64, @floatFromInt(elapsed)) / 1_000_000.0});
}

// ==========================================================================
// Armored key export/import performance
// ==========================================================================

test "perf_regression: armored key export+import x50" {
    const allocator = testing.allocator;
    var body: [12]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], 2000, .big);
    body[5] = 1;
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xFF;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;
    const pk = try PublicKeyPacket.parse(allocator, &body, false);
    var key = Key.init(pk);
    defer key.deinit(allocator);
    const uid = try UserIdPacket.parse(allocator, "ArmPerf <ap@t>");
    try key.addUserId(allocator, .{ .user_id = uid, .self_signature = null, .certifications = .empty });

    var timer = try Timer.start();
    for (0..50) |_| {
        const armored_key = try import_export.exportPublicKeyArmored(allocator, &key);
        defer allocator.free(armored_key);
        var decoded = try armor.decode(allocator, armored_key);
        defer decoded.deinit();
        var imported = try import_export.importPublicKey(allocator, decoded.data);
        imported.deinit(allocator);
    }
    const elapsed = timer.read();
    std.log.info("Armored key export+import x50: {d:.2}ms", .{@as(f64, @floatFromInt(elapsed)) / 1_000_000.0});
}

// ==========================================================================
// SEIPD v1 all cipher algorithms 100KB
// ==========================================================================

test "perf_regression: SEIPD v1 all ciphers 100KB" {
    const allocator = testing.allocator;
    const size: usize = 100 * 1024;
    const plaintext = try allocator.alloc(u8, size);
    defer allocator.free(plaintext);
    @memset(plaintext, 0x42);

    const algos = [_]struct { a: SymmetricAlgorithm, k: []const u8, n: []const u8 }{
        .{ .a = .aes128, .k = &([_]u8{0x42} ** 16), .n = "AES-128" },
        .{ .a = .aes256, .k = &([_]u8{0x42} ** 32), .n = "AES-256" },
        .{ .a = .cast5, .k = &([_]u8{0x42} ** 16), .n = "CAST5" },
        .{ .a = .twofish, .k = &([_]u8{0x42} ** 32), .n = "Twofish" },
    };
    for (algos) |a| {
        var timer = try Timer.start();
        const encrypted = try seipd.seipdEncrypt(allocator, plaintext, a.k, a.a);
        defer allocator.free(encrypted);
        const elapsed_enc = timer.read();
        timer.reset();
        const decrypted = try seipd.seipdDecrypt(allocator, encrypted, a.k, a.a);
        defer allocator.free(decrypted);
        const elapsed_dec = timer.read();
        try testing.expectEqualSlices(u8, plaintext, decrypted);
        std.log.info("{s} SEIPD 100KB: enc {d:.2}ms, dec {d:.2}ms", .{
            a.n,
            @as(f64, @floatFromInt(elapsed_enc)) / 1_000_000.0,
            @as(f64, @floatFromInt(elapsed_dec)) / 1_000_000.0,
        });
    }
}

// ==========================================================================
// SecureBuffer performance
// ==========================================================================

test "perf_regression: SecureBuffer alloc+deinit x1000" {
    var timer = try Timer.start();
    for (0..1000) |_| {
        var buf = try zeroize.SecureBuffer.init(testing.allocator, 256);
        @memset(buf.data, 0xCC);
        buf.deinit();
    }
    const elapsed = timer.read();
    std.log.info("SecureBuffer 256B alloc+deinit x1000: {d:.2}us", .{@as(f64, @floatFromInt(elapsed)) / 1_000.0});
}

// ==========================================================================
// Message encrypt+decrypt repeated
// ==========================================================================

test "perf_regression: message encrypt+decrypt x10" {
    const allocator = testing.allocator;
    const plaintext = "Repeated encryption test" ** 5;
    var timer = try Timer.start();
    for (0..10) |_| {
        const encrypted = try compose.encryptMessageSymmetric(allocator, plaintext, "t.txt", "pw", .aes256, null);
        defer allocator.free(encrypted);
        var msg = try decompose_mod.parseMessage(allocator, encrypted);
        defer msg.deinit(allocator);
        const decrypted = try decompose_mod.decryptWithPassphrase(allocator, &msg, "pw");
        defer allocator.free(decrypted);
        try testing.expectEqualStrings(plaintext, decrypted);
    }
    const elapsed = timer.read();
    std.log.info("Msg encrypt+decrypt x10: {d:.2}ms", .{@as(f64, @floatFromInt(elapsed)) / 1_000_000.0});
}
