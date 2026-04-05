// SPDX-License-Identifier: MIT
//! Integration tests for the zpgp library.
//!
//! Tests full round-trips for:
//! - Symmetric encryption and decryption (passphrase)
//! - SEIPD encrypt/decrypt at the crypto layer
//! - Message compose/decompose with symmetric encryption
//! - Multiple algorithms (AES-128, AES-256, CAST5, Twofish)

const std = @import("std");
const mem = std.mem;

// Crypto layer
const seipd = @import("crypto/seipd.zig");
const session_key_mod = @import("crypto/session_key.zig");
const cfb = @import("crypto/cfb.zig");
const ed25519_ops = @import("crypto/ed25519_ops.zig");

// Message layer
const compose = @import("message/compose.zig");
const decompose_mod = @import("message/decompose.zig");

// Packet layer
const header_mod = @import("packet/header.zig");
const PacketTag = @import("packet/tags.zig").PacketTag;

// Types
const SymmetricAlgorithm = @import("types/enums.zig").SymmetricAlgorithm;
const S2K = @import("types/s2k.zig").S2K;

// ---------------------------------------------------------------------------
// SEIPD round-trip tests across all algorithms
// ---------------------------------------------------------------------------

test "interop: SEIPD AES-128 round-trip with random key" {
    const allocator = std.testing.allocator;
    const sk = try session_key_mod.generateSessionKey(.aes128);
    const plaintext = "Integration test: AES-128 SEIPD with random session key";

    const encrypted = try seipd.seipdEncrypt(allocator, plaintext, sk.keySlice(), .aes128);
    defer allocator.free(encrypted);

    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, sk.keySlice(), .aes128);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "interop: SEIPD AES-256 round-trip with random key" {
    const allocator = std.testing.allocator;
    const sk = try session_key_mod.generateSessionKey(.aes256);
    const plaintext = "Integration test: AES-256 SEIPD round-trip with random session key data";

    const encrypted = try seipd.seipdEncrypt(allocator, plaintext, sk.keySlice(), .aes256);
    defer allocator.free(encrypted);

    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, sk.keySlice(), .aes256);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "interop: SEIPD CAST5 round-trip with random key" {
    const allocator = std.testing.allocator;
    const sk = try session_key_mod.generateSessionKey(.cast5);
    const plaintext = "Integration test: CAST5 SEIPD";

    const encrypted = try seipd.seipdEncrypt(allocator, plaintext, sk.keySlice(), .cast5);
    defer allocator.free(encrypted);

    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, sk.keySlice(), .cast5);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "interop: SEIPD Twofish round-trip with random key" {
    const allocator = std.testing.allocator;
    const sk = try session_key_mod.generateSessionKey(.twofish);
    const plaintext = "Integration test: Twofish SEIPD";

    const encrypted = try seipd.seipdEncrypt(allocator, plaintext, sk.keySlice(), .twofish);
    defer allocator.free(encrypted);

    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, sk.keySlice(), .twofish);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

// ---------------------------------------------------------------------------
// Symmetric message encrypt/decrypt round-trips
// ---------------------------------------------------------------------------

test "interop: symmetric encrypt then decrypt with AES-128" {
    const allocator = std.testing.allocator;
    const plaintext = "Secret message encrypted with AES-128 passphrase";
    const passphrase = "test-passphrase-128";

    // Encrypt
    const encrypted = try compose.encryptMessageSymmetric(
        allocator,
        plaintext,
        "test.txt",
        passphrase,
        .aes128,
        null,
    );
    defer allocator.free(encrypted);

    // Parse the encrypted message
    var msg = try decompose_mod.parseMessage(allocator, encrypted);
    defer msg.deinit(allocator);

    try std.testing.expect(msg.isEncrypted());
    try std.testing.expectEqual(@as(usize, 1), msg.skesk_packets.items.len);

    // Decrypt
    const decrypted = try decompose_mod.decryptWithPassphrase(allocator, &msg, passphrase);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "interop: symmetric encrypt then decrypt with AES-256" {
    const allocator = std.testing.allocator;
    const plaintext = "Secret message encrypted with AES-256 passphrase";
    const passphrase = "strong-passphrase-256";

    const encrypted = try compose.encryptMessageSymmetric(
        allocator,
        plaintext,
        "secret.bin",
        passphrase,
        .aes256,
        null,
    );
    defer allocator.free(encrypted);

    var msg = try decompose_mod.parseMessage(allocator, encrypted);
    defer msg.deinit(allocator);

    const decrypted = try decompose_mod.decryptWithPassphrase(allocator, &msg, passphrase);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "interop: symmetric encrypt wrong passphrase fails" {
    const allocator = std.testing.allocator;
    const plaintext = "This should not be recoverable with wrong password";

    const encrypted = try compose.encryptMessageSymmetric(
        allocator,
        plaintext,
        "file.txt",
        "correct-password",
        .aes128,
        null,
    );
    defer allocator.free(encrypted);

    var msg = try decompose_mod.parseMessage(allocator, encrypted);
    defer msg.deinit(allocator);

    // Decrypting with wrong passphrase should fail
    const result = decompose_mod.decryptWithPassphrase(allocator, &msg, "wrong-password");
    try std.testing.expect(result == error.IntegrityCheckFailed or
        result == error.DecryptionFailed or
        result == error.MalformedMessage);
}

test "interop: symmetric encrypt empty plaintext" {
    const allocator = std.testing.allocator;

    const encrypted = try compose.encryptMessageSymmetric(
        allocator,
        "",
        "",
        "password",
        .aes128,
        null,
    );
    defer allocator.free(encrypted);

    var msg = try decompose_mod.parseMessage(allocator, encrypted);
    defer msg.deinit(allocator);

    const decrypted = try decompose_mod.decryptWithPassphrase(allocator, &msg, "password");
    defer allocator.free(decrypted);

    try std.testing.expectEqual(@as(usize, 0), decrypted.len);
}

// ---------------------------------------------------------------------------
// Literal data round-trip
// ---------------------------------------------------------------------------

test "interop: create and parse literal data" {
    const allocator = std.testing.allocator;
    const data = "Hello, OpenPGP literal data!";

    const pkt = try compose.createLiteralData(allocator, data, "hello.txt", true);
    defer allocator.free(pkt);

    // Parse it back as a message
    var msg = try decompose_mod.parseMessage(allocator, pkt);
    defer msg.deinit(allocator);

    try std.testing.expect(msg.literal_data != null);
    try std.testing.expectEqualStrings(data, msg.literal_data.?.data);
    try std.testing.expectEqualStrings("hello.txt", msg.literal_data.?.filename);
}

// ---------------------------------------------------------------------------
// Ed25519 integration tests
// ---------------------------------------------------------------------------

test "interop: Ed25519 key generation and sign/verify" {
    const kp = try ed25519_ops.ed25519Generate();
    const message = "OpenPGP Ed25519 integration test message";

    const sig = try ed25519_ops.ed25519Sign(kp.secret_key, message);
    try ed25519_ops.ed25519Verify(kp.public_key, message, sig);
}

test "interop: Ed25519 cross-key verification fails" {
    const kp1 = try ed25519_ops.ed25519Generate();
    const kp2 = try ed25519_ops.ed25519Generate();
    const message = "Cross-key test";

    const sig = try ed25519_ops.ed25519Sign(kp1.secret_key, message);
    const result = ed25519_ops.ed25519Verify(kp2.public_key, message, sig);
    try std.testing.expectError(ed25519_ops.Ed25519Error.SignatureVerificationFailed, result);
}

// ---------------------------------------------------------------------------
// Session key + SEIPD end-to-end
// ---------------------------------------------------------------------------

test "interop: session key generate, wrap in SEIPD, decrypt" {
    const allocator = std.testing.allocator;

    // Generate a session key
    const sk = try session_key_mod.generateSessionKey(.aes256);

    // Verify checksum
    const checksum = sk.checksum();
    var computed: u32 = 0;
    for (sk.key[0..sk.key_len]) |b| computed += b;
    try std.testing.expectEqual(checksum, @as(u16, @truncate(computed)));

    // Use it for SEIPD
    const data = "Session key integration test";
    const encrypted = try seipd.seipdEncrypt(allocator, data, sk.keySlice(), .aes256);
    defer allocator.free(encrypted);

    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, sk.keySlice(), .aes256);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(data, decrypted);
}

// ---------------------------------------------------------------------------
// S2K key derivation + SEIPD round-trip
// ---------------------------------------------------------------------------

test "interop: S2K derive key then SEIPD encrypt/decrypt" {
    const allocator = std.testing.allocator;

    // Set up S2K
    const s2k = S2K{
        .s2k_type = .iterated,
        .hash_algo = .sha256,
        .salt = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
        .coded_count = 96,
        .argon2_data = null,
    };

    // Derive a 16-byte key for AES-128
    var key: [16]u8 = undefined;
    try s2k.deriveKey("my-passphrase", &key);

    // Use it for SEIPD
    const plaintext = "S2K + SEIPD integration test data";
    const encrypted = try seipd.seipdEncrypt(allocator, plaintext, &key, .aes128);
    defer allocator.free(encrypted);

    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, &key, .aes128);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

// ---------------------------------------------------------------------------
// Large data tests
// ---------------------------------------------------------------------------

test "interop: symmetric encrypt/decrypt large data (64KB)" {
    const allocator = std.testing.allocator;

    // Generate 64KB of test data
    const data = try allocator.alloc(u8, 65536);
    defer allocator.free(data);
    for (data, 0..) |*b, i| b.* = @truncate(i *% 251 +% 37);

    const encrypted = try compose.encryptMessageSymmetric(
        allocator,
        data,
        "large.bin",
        "passphrase",
        .aes256,
        null,
    );
    defer allocator.free(encrypted);

    var msg = try decompose_mod.parseMessage(allocator, encrypted);
    defer msg.deinit(allocator);

    const decrypted = try decompose_mod.decryptWithPassphrase(allocator, &msg, "passphrase");
    defer allocator.free(decrypted);

    try std.testing.expectEqualSlices(u8, data, decrypted);
}

// ---------------------------------------------------------------------------
// Packet structure validation
// ---------------------------------------------------------------------------

test "interop: encrypted message packet structure" {
    const allocator = std.testing.allocator;

    const encrypted = try compose.encryptMessageSymmetric(
        allocator,
        "test data",
        "test.txt",
        "password",
        .aes128,
        null,
    );
    defer allocator.free(encrypted);

    // Parse and verify structure
    var fbs = std.io.fixedBufferStream(encrypted);
    const reader = fbs.reader();

    // First packet: SKESK (tag 3)
    const hdr1 = try header_mod.readHeader(reader);
    try std.testing.expectEqual(PacketTag.symmetric_key_encrypted_session_key, hdr1.tag);
    const len1 = switch (hdr1.body_length) {
        .fixed => |l| l,
        else => unreachable,
    };
    fbs.pos += len1;

    // Second packet: SEIPD (tag 18)
    const hdr2 = try header_mod.readHeader(reader);
    try std.testing.expectEqual(PacketTag.sym_encrypted_integrity_protected_data, hdr2.tag);
}
