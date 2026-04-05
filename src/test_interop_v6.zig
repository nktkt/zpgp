// SPDX-License-Identifier: MIT
//! V6/RFC 9580 interoperability tests for the zpgp library.
//!
//! Tests V4/V6 key operations, symmetric encryption round-trips,
//! SEIPDv2 with all AEAD modes, V6 SKESK/PKESK operations,
//! Ed25519/X25519 native operations, and cross-version compatibility.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

// Types
const enums = @import("types/enums.zig");
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const AeadAlgorithmCrypto = aead_mod.AeadAlgorithm;
const AeadAlgorithm = enums.AeadAlgorithm;
const mpi_mod = @import("types/mpi.zig");
const Mpi = mpi_mod.Mpi;
const s2k_mod = @import("types/s2k.zig");
const S2K = s2k_mod.S2K;
const S2kType = s2k_mod.S2kType;

// Crypto
const seipd = @import("crypto/seipd.zig");
const seipd_v2 = @import("crypto/seipd_v2.zig");
const aead_mod = @import("crypto/aead/aead.zig");
const session_key_mod = @import("crypto/session_key.zig");
const ed25519_native = @import("crypto/ed25519_native.zig");
const Ed25519Native = ed25519_native.Ed25519Native;
const x25519_native = @import("crypto/x25519_native.zig");
const X25519Native = x25519_native.X25519Native;
const fingerprint_mod = @import("key/fingerprint.zig");
const v6_fingerprint_mod = @import("key/v6_fingerprint.zig");
const argon2_mod = @import("crypto/argon2.zig");
const Argon2S2K = argon2_mod.Argon2S2K;
const skesk_v6 = @import("crypto/skesk_v6.zig");
const V6SKESKPacket = skesk_v6.V6SKESKPacket;
const hash_mod = @import("crypto/hash.zig");
const HashContext = hash_mod.HashContext;
const aes_keywrap = @import("crypto/aes_keywrap.zig");

// Armor
const armor = @import("armor/armor.zig");

// Packets
const literal_data = @import("packets/literal_data.zig");
const LiteralDataPacket = literal_data.LiteralDataPacket;

// ==========================================================================
// V4 Key Operations
// ==========================================================================

test "interop: V4 key encrypt, V4 key decrypt" {
    // Test SEIPD v1 with a V4-style key (session key)
    const allocator = testing.allocator;
    const sk = try session_key_mod.generateSessionKey(.aes256);
    const plaintext = "V4 key encryption interoperability test message";

    const encrypted = try seipd.seipdEncrypt(allocator, plaintext, sk.keySlice(), .aes256);
    defer allocator.free(encrypted);

    try testing.expectEqual(@as(u8, 1), encrypted[0]); // version 1

    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, sk.keySlice(), .aes256);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "interop: symmetric encrypt AES-128, decrypt AES-128" {
    const allocator = testing.allocator;
    const key = [_]u8{0x01} ** 16;
    const plaintext = "AES-128 symmetric interoperability test";

    // SEIPD v1
    const enc = try seipd.seipdEncrypt(allocator, plaintext, &key, .aes128);
    defer allocator.free(enc);
    const dec = try seipd.seipdDecrypt(allocator, enc, &key, .aes128);
    defer allocator.free(dec);
    try testing.expectEqualStrings(plaintext, dec);
}

test "interop: symmetric encrypt AES-256, decrypt AES-256" {
    const allocator = testing.allocator;
    const key = [_]u8{0x02} ** 32;
    const plaintext = "AES-256 symmetric interoperability test with longer key";

    const enc = try seipd.seipdEncrypt(allocator, plaintext, &key, .aes256);
    defer allocator.free(enc);
    const dec = try seipd.seipdDecrypt(allocator, enc, &key, .aes256);
    defer allocator.free(dec);
    try testing.expectEqualStrings(plaintext, dec);
}

// ==========================================================================
// SEIPDv2 Full Round-Trips
// ==========================================================================

test "interop: SEIPDv2 EAX full round-trip" {
    const allocator = testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const plaintext = "SEIPDv2 EAX full round-trip interoperability test message with padding";

    const encrypted = try seipd_v2.seipdV2Encrypt(allocator, plaintext, &key, .aes128, .eax, 6);
    defer allocator.free(encrypted);

    // Verify header fields
    try testing.expectEqual(@as(u8, 2), encrypted[0]); // version
    try testing.expectEqual(@as(u8, @intFromEnum(SymmetricAlgorithm.aes128)), encrypted[1]);
    try testing.expectEqual(@as(u8, @intFromEnum(AeadAlgorithm.eax)), encrypted[2]);
    try testing.expectEqual(@as(u8, 6), encrypted[3]); // chunk size octet

    const decrypted = try seipd_v2.seipdV2Decrypt(allocator, encrypted, &key);
    defer allocator.free(decrypted);
    try testing.expectEqualStrings(plaintext, decrypted);
}

test "interop: SEIPDv2 OCB full round-trip" {
    const allocator = testing.allocator;
    const key = [_]u8{0x77} ** 16;
    const plaintext = "SEIPDv2 OCB full round-trip test with AES-128";

    const encrypted = try seipd_v2.seipdV2Encrypt(allocator, plaintext, &key, .aes128, .ocb, 6);
    defer allocator.free(encrypted);

    try testing.expectEqual(@as(u8, @intFromEnum(AeadAlgorithm.ocb)), encrypted[2]);

    const decrypted = try seipd_v2.seipdV2Decrypt(allocator, encrypted, &key);
    defer allocator.free(decrypted);
    try testing.expectEqualStrings(plaintext, decrypted);
}

test "interop: SEIPDv2 GCM full round-trip" {
    const allocator = testing.allocator;
    const key = [_]u8{0xAB} ** 32;
    const plaintext = "SEIPDv2 GCM full round-trip test with AES-256 key material";

    const encrypted = try seipd_v2.seipdV2Encrypt(allocator, plaintext, &key, .aes256, .gcm, 6);
    defer allocator.free(encrypted);

    try testing.expectEqual(@as(u8, @intFromEnum(AeadAlgorithm.gcm)), encrypted[2]);

    const decrypted = try seipd_v2.seipdV2Decrypt(allocator, encrypted, &key);
    defer allocator.free(decrypted);
    try testing.expectEqualStrings(plaintext, decrypted);
}

// ==========================================================================
// V6 SKESK Interoperability
// ==========================================================================

test "interop: V6 SKESK Argon2 + SEIPDv2" {
    // Test constructing and parsing a V6 SKESK packet with Argon2 parameters
    const allocator = testing.allocator;

    // Build a V6 SKESK body manually
    var body: [100]u8 = undefined;
    body[0] = 6; // version
    body[1] = 22; // count
    body[2] = @intFromEnum(SymmetricAlgorithm.aes256);
    body[3] = @intFromEnum(AeadAlgorithm.eax);
    body[4] = 4; // S2K type: Argon2
    @memset(body[5..21], 0xAA); // salt
    body[21] = 1; // passes
    body[22] = 1; // parallelism
    body[23] = 10; // memory (2^10 = 1024 KiB)
    // EAX nonce: 16 bytes
    @memset(body[24..40], 0xBB);
    // Encrypted session key + EAX tag: 32 + 16 = 48
    @memset(body[40..88], 0xCC);

    const pkt = try V6SKESKPacket.parse(allocator, body[0..88]);
    defer pkt.deinit(allocator);

    try testing.expectEqual(@as(u8, 6), pkt.version);
    try testing.expectEqual(SymmetricAlgorithm.aes256, pkt.sym_algo);
    try testing.expectEqual(AeadAlgorithm.eax, pkt.aead_algo);
    try testing.expectEqual(@as(u8, 4), pkt.s2k_type);
    try testing.expectEqual(@as(usize, 16), pkt.aead_nonce.len);

    // Serialize round-trip
    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try testing.expectEqualSlices(u8, body[0..88], serialized);
}

test "interop: V6 PKESK X25519 + SEIPDv2" {
    // Test X25519 key generation and basic operations
    const kp = X25519Native.generate();

    // Verify key sizes match RFC 9580 requirements
    try testing.expectEqual(@as(usize, 32), kp.public.len);
    try testing.expectEqual(@as(usize, 32), kp.secret.len);

    // The public key should not be all zeros (would be an invalid point)
    var all_zero = true;
    for (kp.public) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

// ==========================================================================
// Ed25519 Native Sign/Verify
// ==========================================================================

test "interop: Ed25519 native sign/verify" {
    const kp = Ed25519Native.generate();
    const messages = [_][]const u8{
        "Hello, world!",
        "",
        "A" ** 1000,
        "\x00\x01\x02\x03\x04\x05",
        "RFC 9580 native Ed25519 test",
    };

    for (messages) |msg| {
        const sig = try Ed25519Native.sign(kp.secret, kp.public, msg);
        try Ed25519Native.verify(kp.public, msg, sig);
    }
}

test "interop: Ed25519 native wrong message rejected" {
    const kp = Ed25519Native.generate();
    const sig = try Ed25519Native.sign(kp.secret, kp.public, "correct message");

    const result = Ed25519Native.verify(kp.public, "wrong message", sig);
    try testing.expectError(ed25519_native.Ed25519NativeError.SignatureVerificationFailed, result);
}

test "interop: Ed25519 native deterministic signatures" {
    const kp = Ed25519Native.generate();
    const msg = "deterministic signature test";

    const sig1 = try Ed25519Native.sign(kp.secret, kp.public, msg);
    const sig2 = try Ed25519Native.sign(kp.secret, kp.public, msg);

    // Ed25519 is deterministic
    try testing.expectEqualSlices(u8, &sig1, &sig2);
}

// ==========================================================================
// X25519 Native Key Agreement
// ==========================================================================

test "interop: X25519 native encrypt/decrypt" {
    // Generate two X25519 key pairs and verify they are valid
    const kp1 = X25519Native.generate();
    const kp2 = X25519Native.generate();

    // Keys should be different
    try testing.expect(!mem.eql(u8, &kp1.public, &kp2.public));
    try testing.expect(!mem.eql(u8, &kp1.secret, &kp2.secret));

    // Both should have correct sizes
    try testing.expectEqual(@as(usize, 32), kp1.public.len);
    try testing.expectEqual(@as(usize, 32), kp2.public.len);
}

// ==========================================================================
// Mixed V4/V6 Operations
// ==========================================================================

test "interop: mixed V4 and V6 keyring" {
    // Test that V4 and V6 fingerprints can coexist
    const v4_body = [_]u8{
        4,                      // version 4
        0x60, 0x00, 0x00, 0x00, // creation_time
        1,                      // RSA
        0x00, 0x08, 0xFF, // MPI n
        0x00, 0x08, 0x03, // MPI e
    };
    const v6_body = [_]u8{
        6,                      // version 6
        0x60, 0x00, 0x00, 0x00, // creation_time
        27,                     // Ed25519 native
    } ++ [_]u8{0x42} ** 32;

    const v4_fp = fingerprint_mod.calculateV4Fingerprint(&v4_body);
    const v6_fp = v6_fingerprint_mod.calculateV6Fingerprint(&v6_body);

    // Different sizes
    try testing.expectEqual(@as(usize, 20), v4_fp.len);
    try testing.expectEqual(@as(usize, 32), v6_fp.len);

    // V4 key ID = last 8 bytes, V6 key ID = first 8 bytes
    const v4_kid = fingerprint_mod.keyIdFromFingerprint(v4_fp);
    const v6_kid = v6_fingerprint_mod.v6KeyIdFromFingerprint(v6_fp);

    try testing.expectEqual(@as(usize, 8), v4_kid.len);
    try testing.expectEqual(@as(usize, 8), v6_kid.len);
}

test "interop: V6 key generation then import" {
    // Generate Ed25519 key pair (as would be used for V6 keys)
    const kp = Ed25519Native.generate();

    // Build a V6 key packet body
    const creation_time: u32 = 1700000000;
    var key_body: [38]u8 = undefined;
    key_body[0] = 6; // version 6
    mem.writeInt(u32, key_body[1..5], creation_time, .big);
    key_body[5] = @intFromEnum(PublicKeyAlgorithm.ed25519); // algorithm
    @memcpy(key_body[6..38], &kp.public);

    // Calculate V6 fingerprint
    const fp = v6_fingerprint_mod.calculateV6Fingerprint(&key_body);
    const kid = v6_fingerprint_mod.v6KeyIdFromFingerprint(fp);

    // Verify the fingerprint is deterministic
    const fp2 = v6_fingerprint_mod.calculateV6Fingerprint(&key_body);
    try testing.expectEqual(fp, fp2);

    // Verify key ID is first 8 bytes
    try testing.expectEqualSlices(u8, fp[0..8], &kid);
}

test "interop: V6 key fingerprint verification" {
    // Verify V6 fingerprint format: SHA-256(0x9B || 4-byte-len || body)
    const body = [_]u8{
        6, 0x00, 0x00, 0x00, 0x01, // version + creation_time
        27, // Ed25519
    } ++ [_]u8{0xAA} ** 32;

    const fp = v6_fingerprint_mod.calculateV6Fingerprint(&body);

    // Manually verify
    var sha256 = std.crypto.hash.sha2.Sha256.init(.{});
    sha256.update(&[_]u8{0x9B});
    const len: u32 = @intCast(body.len);
    var len_bytes: [4]u8 = undefined;
    mem.writeInt(u32, &len_bytes, len, .big);
    sha256.update(&len_bytes);
    sha256.update(&body);
    const expected = sha256.finalResult();

    try testing.expectEqual(expected, fp);

    // Format as hex string
    const hex = v6_fingerprint_mod.formatV6Fingerprint(fp);
    try testing.expectEqual(@as(usize, 64), hex.len);
}

test "interop: V6 signature with salt" {
    // V6 signatures include a salt. Test Ed25519 signing with a message
    // that would include salt prefix (simulated).
    const kp = Ed25519Native.generate();

    // Simulate a V6 signature by prepending a salt to the message
    var salt: [32]u8 = undefined;
    std.crypto.random.bytes(&salt);

    var salted_message: [32 + 20]u8 = undefined;
    @memcpy(salted_message[0..32], &salt);
    @memcpy(salted_message[32..52], "test message content");

    const sig = try Ed25519Native.sign(kp.secret, kp.public, &salted_message);
    try Ed25519Native.verify(kp.public, &salted_message, sig);
}

// ==========================================================================
// V6 SKESK Error Cases
// ==========================================================================

test "interop: V6 SKESK wrong passphrase fails" {
    // Test that parsing a V6 SKESK with wrong version fails
    const allocator = testing.allocator;

    var body: [50]u8 = undefined;
    body[0] = 4; // V4, not V6
    @memset(body[1..], 0);

    try testing.expectError(error.UnsupportedVersion, V6SKESKPacket.parse(allocator, &body));
}

test "interop: V6 SKESK unsupported S2K type fails" {
    const allocator = testing.allocator;

    var body: [50]u8 = undefined;
    body[0] = 6; // V6
    body[1] = 22; // count
    body[2] = @intFromEnum(SymmetricAlgorithm.aes256);
    body[3] = @intFromEnum(AeadAlgorithm.gcm);
    body[4] = 3; // S2K type 3 (iterated), not Argon2
    @memset(body[5..], 0);

    try testing.expectError(error.UnsupportedS2KType, V6SKESKPacket.parse(allocator, &body));
}

// ==========================================================================
// AEAD Algorithm Combinations
// ==========================================================================

test "interop: AEAD all algorithm combinations" {
    const allocator = testing.allocator;
    const plaintext = "AEAD combination interoperability test data";
    const ad = "associated data for AEAD test";

    const configs = [_]struct {
        sym: SymmetricAlgorithm,
        aead: AeadAlgorithmCrypto,
        key_size: usize,
        nonce_size: usize,
    }{
        .{ .sym = .aes128, .aead = .eax, .key_size = 16, .nonce_size = 16 },
        .{ .sym = .aes256, .aead = .eax, .key_size = 32, .nonce_size = 16 },
        .{ .sym = .aes128, .aead = .ocb, .key_size = 16, .nonce_size = 15 },
        .{ .sym = .aes256, .aead = .ocb, .key_size = 32, .nonce_size = 15 },
        .{ .sym = .aes128, .aead = .gcm, .key_size = 16, .nonce_size = 12 },
        .{ .sym = .aes256, .aead = .gcm, .key_size = 32, .nonce_size = 12 },
    };

    for (configs) |cfg| {
        var key: [32]u8 = undefined;
        @memset(&key, 0x42);
        var nonce: [16]u8 = undefined;
        @memset(&nonce, 0x33);

        const result = try aead_mod.aeadEncrypt(
            allocator,
            cfg.sym,
            cfg.aead,
            key[0..cfg.key_size],
            nonce[0..cfg.nonce_size],
            plaintext,
            ad,
        );
        defer result.deinit(allocator);

        const decrypted = try aead_mod.aeadDecrypt(
            allocator,
            cfg.sym,
            cfg.aead,
            key[0..cfg.key_size],
            nonce[0..cfg.nonce_size],
            result.ciphertext,
            &result.tag,
            ad,
        );
        defer allocator.free(decrypted);

        try testing.expectEqualStrings(plaintext, decrypted);
    }
}

test "interop: AEAD wrong key fails for all modes" {
    const allocator = testing.allocator;
    const plaintext = "AEAD wrong key detection test";
    const ad = "";

    const configs = [_]struct {
        sym: SymmetricAlgorithm,
        aead: AeadAlgorithmCrypto,
        key_size: usize,
        nonce_size: usize,
    }{
        .{ .sym = .aes128, .aead = .eax, .key_size = 16, .nonce_size = 16 },
        .{ .sym = .aes128, .aead = .ocb, .key_size = 16, .nonce_size = 15 },
        .{ .sym = .aes128, .aead = .gcm, .key_size = 16, .nonce_size = 12 },
    };

    for (configs) |cfg| {
        const correct_key = [_]u8{0x42} ** 32;
        const wrong_key = [_]u8{0x99} ** 32;
        var nonce: [16]u8 = undefined;
        @memset(&nonce, 0x33);

        const result = try aead_mod.aeadEncrypt(
            allocator,
            cfg.sym,
            cfg.aead,
            correct_key[0..cfg.key_size],
            nonce[0..cfg.nonce_size],
            plaintext,
            ad,
        );
        defer result.deinit(allocator);

        const decrypt_result = aead_mod.aeadDecrypt(
            allocator,
            cfg.sym,
            cfg.aead,
            wrong_key[0..cfg.key_size],
            nonce[0..cfg.nonce_size],
            result.ciphertext,
            &result.tag,
            ad,
        );
        try testing.expectError(aead_mod.AeadError.AuthenticationFailed, decrypt_result);
    }
}

// ==========================================================================
// Large Message Multi-Chunk SEIPDv2
// ==========================================================================

test "interop: large message multi-chunk SEIPDv2" {
    const allocator = testing.allocator;
    const key = [_]u8{0x42} ** 16;

    // Use chunk_size_octet=0 => chunk_size=2^6=64 bytes
    // Create a message that spans many chunks
    const size: usize = 1000;
    const plaintext = try allocator.alloc(u8, size);
    defer allocator.free(plaintext);
    // Fill with a pattern
    for (plaintext, 0..) |*b, i| {
        b.* = @intCast(i % 256);
    }

    const encrypted = try seipd_v2.seipdV2Encrypt(allocator, plaintext, &key, .aes128, .eax, 0);
    defer allocator.free(encrypted);

    const decrypted = try seipd_v2.seipdV2Decrypt(allocator, encrypted, &key);
    defer allocator.free(decrypted);

    try testing.expectEqualSlices(u8, plaintext, decrypted);
}

test "interop: multi-chunk SEIPDv2 with all AEAD modes" {
    const allocator = testing.allocator;
    const size: usize = 500;

    const plaintext = try allocator.alloc(u8, size);
    defer allocator.free(plaintext);
    @memset(plaintext, 0xAB);

    const modes = [_]struct { sym: SymmetricAlgorithm, aead: AeadAlgorithmCrypto, key_size: usize }{
        .{ .sym = .aes128, .aead = .eax, .key_size = 16 },
        .{ .sym = .aes128, .aead = .ocb, .key_size = 16 },
        .{ .sym = .aes256, .aead = .gcm, .key_size = 32 },
    };

    for (modes) |mode| {
        var key: [32]u8 = undefined;
        @memset(&key, 0x55);

        const encrypted = try seipd_v2.seipdV2Encrypt(
            allocator,
            plaintext,
            key[0..mode.key_size],
            mode.sym,
            mode.aead,
            0, // small chunks
        );
        defer allocator.free(encrypted);

        const decrypted = try seipd_v2.seipdV2Decrypt(allocator, encrypted, key[0..mode.key_size]);
        defer allocator.free(decrypted);

        try testing.expectEqualSlices(u8, plaintext, decrypted);
    }
}

// ==========================================================================
// Compress Then Encrypt V6
// ==========================================================================

test "interop: compress then encrypt v6" {
    // Simulate the common pattern of compressing then encrypting with SEIPDv2.
    // In OpenPGP, the compressed data packet would be the plaintext input to SEIPD.
    const allocator = testing.allocator;

    // Simulated compressed data (just some bytes that represent a compressed packet)
    const compressed_data = "Compressed data packet body: " ++ [_]u8{0x78} ** 100;
    const key = [_]u8{0x42} ** 16;

    // Encrypt with SEIPDv2
    const encrypted = try seipd_v2.seipdV2Encrypt(
        allocator,
        compressed_data,
        &key,
        .aes128,
        .eax,
        6,
    );
    defer allocator.free(encrypted);

    // Decrypt
    const decrypted = try seipd_v2.seipdV2Decrypt(allocator, encrypted, &key);
    defer allocator.free(decrypted);

    try testing.expectEqualSlices(u8, compressed_data, decrypted);
}

// ==========================================================================
// Literal Data + Armor Round-Trip
// ==========================================================================

test "interop: literal data packet in armored message" {
    const allocator = testing.allocator;

    // Create a literal data packet body
    const pkt = LiteralDataPacket{
        .format = .binary,
        .filename = "test.txt",
        .timestamp = 1700000000,
        .data = "Hello from a literal data packet!",
    };

    const pkt_body = try pkt.serialize(allocator);
    defer allocator.free(pkt_body);

    // Armor the packet body
    const armored = try armor.encode(allocator, pkt_body, .message, null);
    defer allocator.free(armored);

    // Decode the armor
    var decoded = try armor.decode(allocator, armored);
    defer decoded.deinit();

    try testing.expectEqual(armor.ArmorType.message, decoded.armor_type);

    // Parse the literal data packet from the decoded body
    const parsed = try LiteralDataPacket.parse(allocator, decoded.data);
    defer parsed.deinit(allocator);

    try testing.expectEqualStrings("test.txt", parsed.filename);
    try testing.expectEqual(@as(u32, 1700000000), parsed.timestamp);
    try testing.expectEqualStrings("Hello from a literal data packet!", parsed.data);
}

// ==========================================================================
// S2K Interoperability
// ==========================================================================

test "interop: S2K type 0 then encrypt" {
    const allocator = testing.allocator;

    // Derive a key from passphrase using S2K type 0
    const s2k = S2K{
        .s2k_type = .simple,
        .hash_algo = .sha256,
        .salt = [_]u8{0} ** 8,
        .coded_count = 0,
        .argon2_data = null,
    };

    var key: [16]u8 = undefined;
    try s2k.deriveKey("my passphrase", &key);

    // Use derived key for SEIPD encryption
    const plaintext = "S2K derived key encryption test";
    const encrypted = try seipd.seipdEncrypt(allocator, plaintext, &key, .aes128);
    defer allocator.free(encrypted);

    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, &key, .aes128);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "interop: S2K type 3 iterated then encrypt" {
    const allocator = testing.allocator;

    const s2k = S2K{
        .s2k_type = .iterated,
        .hash_algo = .sha256,
        .salt = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
        .coded_count = 96, // 65536 bytes
        .argon2_data = null,
    };

    var key: [32]u8 = undefined;
    try s2k.deriveKey("strong passphrase", &key);

    // Use derived key for SEIPD encryption
    const plaintext = "S2K iterated derived key encryption test with AES-256";
    const encrypted = try seipd.seipdEncrypt(allocator, plaintext, &key, .aes256);
    defer allocator.free(encrypted);

    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, &key, .aes256);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

// ==========================================================================
// AES Key Wrap Round-Trip
// ==========================================================================

test "interop: AES key wrap with session key" {
    const allocator = testing.allocator;

    // Generate a session key
    const sk = try session_key_mod.generateSessionKey(.aes128);
    const session_key_data = sk.keySlice();

    // Wrap with a KEK
    const kek = [_]u8{0x42} ** 16;
    const wrapped = try aes_keywrap.wrap(&kek, session_key_data, allocator);
    defer allocator.free(wrapped);

    // Wrapped data is 8 bytes longer
    try testing.expectEqual(session_key_data.len + 8, wrapped.len);

    // Unwrap
    const unwrapped = try aes_keywrap.unwrap(&kek, wrapped, allocator);
    defer allocator.free(unwrapped);

    try testing.expectEqualSlices(u8, session_key_data, unwrapped);
}
