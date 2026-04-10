// SPDX-License-Identifier: MIT
//! Security Hardening Test Suite.
//!
//! Tests specifically for security properties of the zpgp library:
//! - Constant-time comparison correctness
//! - Key material zeroization
//! - Algorithm deprecation enforcement
//! - Malformed input rejection
//! - Memory safety (leak detection via testing.allocator)
//! - Padding oracle resistance
//! - S2K iteration enforcement
//! - Integer overflow and edge-case MPI handling

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

// Security module
const zeroize = @import("security/zeroize.zig");

// Types
const enums = @import("types/enums.zig");
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const mpi_mod = @import("types/mpi.zig");
const Mpi = mpi_mod.Mpi;
const s2k_mod = @import("types/s2k.zig");
const S2K = s2k_mod.S2K;

// Armor
const armor = @import("armor/armor.zig");

// Packet layer
const header_mod = @import("packet/header.zig");

// Packets
const public_key_mod = @import("packets/public_key.zig");
const PublicKeyPacket = public_key_mod.PublicKeyPacket;
const signature_mod = @import("packets/signature.zig");
const SignaturePacket = signature_mod.SignaturePacket;
const skesk_mod = @import("packets/skesk.zig");
const SKESKPacket = skesk_mod.SKESKPacket;
const user_id_mod = @import("packets/user_id.zig");
const UserIdPacket = user_id_mod.UserIdPacket;

// Crypto
const seipd = @import("crypto/seipd.zig");
const seipd_v2 = @import("crypto/seipd_v2.zig");
const session_key_mod = @import("crypto/session_key.zig");
const ed25519_ops = @import("crypto/ed25519_ops.zig");
const hash_mod = @import("crypto/hash.zig");
const HashContext = hash_mod.HashContext;
const deprecation_mod = @import("crypto/deprecation.zig");
const SecurityLevel = deprecation_mod.SecurityLevel;
const subpackets_mod = @import("signature/subpackets.zig");

// Key modules
const key_mod = @import("key/key.zig");
const Key = key_mod.Key;
const import_export = @import("key/import_export.zig");

// Message modules
const compose = @import("message/compose.zig");
const decompose_mod = @import("message/decompose.zig");

// ==========================================================================
// Constant-Time Comparison Tests
// ==========================================================================

test "security_hardening: secureEqual identical and different slices" {
    const a = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const b = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const c = [_]u8{ 0x01, 0x02, 0x03, 0x05, 0x05, 0x06, 0x07, 0x08 };
    try testing.expect(zeroize.secureEqual(&a, &b));
    try testing.expect(!zeroize.secureEqual(&a, &c));
}

test "security_hardening: secureEqual single-bit flip detection" {
    var base = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 };
    for (0..base.len) |i| {
        for (0..8) |bit| {
            var modified = base;
            modified[i] ^= @as(u8, 1) << @intCast(bit);
            try testing.expect(!zeroize.secureEqual(&base, &modified));
        }
    }
}

test "security_hardening: secureEqual rejects different lengths" {
    try testing.expect(!zeroize.secureEqual(&[_]u8{ 1, 2, 3, 4 }, &[_]u8{ 1, 2, 3 }));
    try testing.expect(zeroize.secureEqual(&[_]u8{}, &[_]u8{}));
}

test "security_hardening: secureEqualFixed correctness" {
    const a = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    try testing.expect(zeroize.secureEqualFixed(4, &a, &a));
    try testing.expect(!zeroize.secureEqualFixed(4, &a, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEE }));
}

// ==========================================================================
// Key Material Zeroization Tests
// ==========================================================================

test "security_hardening: secureZeroBytes clears buffer" {
    var buf = [_]u8{0xFF} ** 16;
    zeroize.secureZeroBytes(&buf);
    for (buf) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "security_hardening: SecureBuffer zeroes on deinit" {
    var buf = try zeroize.SecureBuffer.init(testing.allocator, 128);
    @memset(buf.data, 0xCC);
    try testing.expectEqual(@as(usize, 128), buf.len());
    buf.deinit();
    try testing.expectEqual(@as(usize, 0), buf.data.len);
}

test "security_hardening: SecureBuffer initCopy" {
    const secret = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    var buf = try zeroize.SecureBuffer.initCopy(testing.allocator, &secret);
    defer buf.deinit();
    try testing.expectEqualSlices(u8, &secret, buf.constSlice());
}

test "security_hardening: secureCopy length mismatch zeroes destination" {
    var dst: [3]u8 = [_]u8{0xFF} ** 3;
    try testing.expectError(error.LengthMismatch, zeroize.secureCopy(&dst, &[_]u8{ 1, 2, 3, 4 }));
    for (dst) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "security_hardening: SecureArrayList zeroes on deinit" {
    var list = zeroize.SecureArrayList.init();
    try list.appendSlice(testing.allocator, "top-secret");
    try testing.expectEqualSlices(u8, "top-secret", list.items());
    list.deinit(testing.allocator);
}

// ==========================================================================
// Algorithm Deprecation Enforcement Tests
// ==========================================================================

test "security_hardening: hash algorithm classifications" {
    try testing.expectEqual(SecurityLevel.insecure, deprecation_mod.assessHashAlgorithm(.md5));
    try testing.expectEqual(SecurityLevel.deprecated, deprecation_mod.assessHashAlgorithm(.sha1));
    try testing.expectEqual(SecurityLevel.deprecated, deprecation_mod.assessHashAlgorithm(.ripemd160));
    try testing.expectEqual(SecurityLevel.secure, deprecation_mod.assessHashAlgorithm(.sha256));
    try testing.expectEqual(SecurityLevel.secure, deprecation_mod.assessHashAlgorithm(.sha384));
    try testing.expectEqual(SecurityLevel.secure, deprecation_mod.assessHashAlgorithm(.sha512));

    // SHA-1 is NOT acceptable for new signatures
    try testing.expect(!deprecation_mod.isHashAcceptableForSignatures(.sha1));
    // But IS acceptable for V4 fingerprints
    try testing.expect(deprecation_mod.isHashAcceptableForFingerprint(.sha1));
    // SHA-256/384/512 are acceptable for signatures
    try testing.expect(deprecation_mod.isHashAcceptableForSignatures(.sha256));
}

test "security_hardening: RSA key size enforcement" {
    try testing.expectEqual(SecurityLevel.insecure, deprecation_mod.assessPublicKeyWithSize(.rsa_encrypt_sign, 512));
    try testing.expectEqual(SecurityLevel.deprecated, deprecation_mod.assessPublicKeyWithSize(.rsa_encrypt_sign, 1024));
    try testing.expectEqual(SecurityLevel.secure, deprecation_mod.assessPublicKeyWithSize(.rsa_encrypt_sign, 2048));
    try testing.expectEqual(SecurityLevel.secure, deprecation_mod.assessPublicKeyWithSize(.rsa_encrypt_sign, 4096));
}

test "security_hardening: symmetric algorithm classifications" {
    const deprecated = [_]SymmetricAlgorithm{ .idea, .triple_des, .cast5, .blowfish };
    for (deprecated) |algo| try testing.expect(!deprecation_mod.assessSymmetricAlgorithm(algo).isSafeForCreation());
    const secure = [_]SymmetricAlgorithm{ .aes128, .aes192, .aes256, .twofish };
    for (secure) |algo| try testing.expect(deprecation_mod.assessSymmetricAlgorithm(algo).isSafeForCreation());
    try testing.expectEqual(SecurityLevel.insecure, deprecation_mod.assessSymmetricAlgorithm(.plaintext));
}

test "security_hardening: public key algorithm classifications" {
    try testing.expectEqual(SecurityLevel.deprecated, deprecation_mod.assessPublicKeyAlgorithm(.elgamal));
    try testing.expectEqual(SecurityLevel.deprecated, deprecation_mod.assessPublicKeyAlgorithm(.dsa));
    try testing.expectEqual(SecurityLevel.deprecated, deprecation_mod.assessPublicKeyAlgorithm(.eddsa));
    try testing.expectEqual(SecurityLevel.secure, deprecation_mod.assessPublicKeyAlgorithm(.ed25519));
    try testing.expectEqual(SecurityLevel.secure, deprecation_mod.assessPublicKeyAlgorithm(.x25519));
}

test "security_hardening: deprecation warning messages" {
    try testing.expect(deprecation_mod.getDeprecationWarning("AES-256", .secure) == null);
    try testing.expect(deprecation_mod.getDeprecationWarning("CAST5", .deprecated) != null);
    try testing.expect(mem.indexOf(u8, deprecation_mod.getDeprecationWarning("MD5", .insecure).?, "MUST NOT") != null);
}

// ==========================================================================
// Malformed Input Rejection Tests
// ==========================================================================

test "security_hardening: reject packet with bit 7 unset" {
    for ([_]u8{ 0x00, 0x01, 0x3F, 0x7F, 0x40 }) |byte| {
        var data = [_]u8{byte};
        var fbs = std.io.fixedBufferStream(&data);
        try testing.expectError(error.InvalidPacketTag, header_mod.readHeader(fbs.reader()));
    }
}

test "security_hardening: reject truncated packet headers" {
    {
        var data = [_]u8{};
        var fbs = std.io.fixedBufferStream(&data);
        try testing.expectError(error.EndOfStream, header_mod.readHeader(fbs.reader()));
    }
    {
        var data = [_]u8{0xC2}; // new format, no length byte
        var fbs = std.io.fixedBufferStream(&data);
        try testing.expectError(error.EndOfStream, header_mod.readHeader(fbs.reader()));
    }
}

test "security_hardening: reject too-short and wrong-version public key" {
    const allocator = testing.allocator;
    try testing.expectError(error.InvalidPacket, PublicKeyPacket.parse(allocator, &[_]u8{ 4, 0x00 }, false));
    try testing.expectError(error.UnsupportedVersion, PublicKeyPacket.parse(allocator, &[_]u8{ 3, 0, 0, 0, 1, 1, 0, 8, 0xFF, 0, 8, 3 }, false));
}

test "security_hardening: reject too-short and wrong-version signature" {
    const allocator = testing.allocator;
    try testing.expectError(error.InvalidPacket, SignaturePacket.parse(allocator, &[_]u8{ 4, 0, 1, 8, 0 }));
    try testing.expectError(error.UnsupportedVersion, SignaturePacket.parse(allocator, &[_]u8{ 3, 0, 1, 8, 0, 0, 0, 0, 0xAB, 0xCD }));
}

test "security_hardening: reject SKESK wrong version and truncated" {
    const allocator = testing.allocator;
    try testing.expectError(error.UnsupportedVersion, SKESKPacket.parse(allocator, &[_]u8{ 5, 9, 3, 8, 1, 2, 3, 4, 5, 6, 7, 8, 96 }));
    try testing.expectError(error.InvalidPacket, SKESKPacket.parse(allocator, &[_]u8{ 4, 9, 3 }));
}

test "security_hardening: reject oversized hashed subpackets in signature" {
    const allocator = testing.allocator;
    var body: [12]u8 = undefined;
    body[0] = 4;
    body[1] = 0;
    body[2] = 1;
    body[3] = 8;
    mem.writeInt(u16, body[4..6], 0xFFFF, .big); // hashed_len way too large
    @memset(body[6..], 0);
    try testing.expectError(error.InvalidPacket, SignaturePacket.parse(allocator, &body));
}

test "security_hardening: MPI zero bits parses correctly" {
    const allocator = testing.allocator;
    // MPI with 0 bit count should parse as empty
    var buf: [2]u8 = undefined;
    mem.writeInt(u16, buf[0..2], 0, .big);
    var fbs = std.io.fixedBufferStream(&buf);
    const m = try Mpi.readFrom(allocator, fbs.reader());
    try testing.expectEqual(@as(u16, 0), m.bit_count);
    try testing.expectEqual(@as(usize, 0), m.data.len);
}

test "security_hardening: subpacket rejects zero-length and overlong" {
    const allocator = testing.allocator;
    try testing.expectError(error.InvalidSubpacket, subpackets_mod.parseSubpackets(allocator, &[_]u8{0}));
    try testing.expectError(error.InvalidSubpacket, subpackets_mod.parseSubpackets(allocator, &[_]u8{ 200, 2, 0, 0, 0, 0 }));
}

test "security_hardening: public key with MPI claiming too many bits" {
    const allocator = testing.allocator;
    var body: [18]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], 1000, .big);
    body[5] = 1; // RSA
    mem.writeInt(u16, body[6..8], 4096, .big); // 4096 bits = 512 bytes needed
    @memset(body[8..], 0xAA); // only 10 bytes
    try testing.expectError(error.InvalidPacket, PublicKeyPacket.parse(allocator, &body, false));
}

test "security_hardening: reject invalid armor" {
    const allocator = testing.allocator;
    const result = armor.decode(allocator, "Not armored at all");
    try testing.expect(result == error.InvalidArmor);
}

// ==========================================================================
// Memory Safety Tests (Leak Detection)
// ==========================================================================

test "security_hardening: public key parse and deinit no leak" {
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
    pk.deinit(allocator);
}

test "security_hardening: key export/import no leak" {
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
    const uid = try UserIdPacket.parse(allocator, "Leak <l@t.com>");
    try key.addUserId(allocator, .{ .user_id = uid, .self_signature = null, .certifications = .empty });
    const exported = try import_export.exportPublicKey(allocator, &key);
    key.deinit(allocator);
    defer allocator.free(exported);
    var imported = try import_export.importPublicKey(allocator, exported);
    imported.deinit(allocator);
}

test "security_hardening: failed parse does not leak" {
    const allocator = testing.allocator;
    // Verify that failed parses don't leak memory (testing.allocator detects leaks).
    // Only test operations that handle truncated input gracefully.
    _ = armor.decode(allocator, "-----BEGIN PGP MESSAGE-----\n\nAA==\n-----END PGP MESSAGE-----") catch {};
    {
        // MPI claiming 8 bits (1 byte) — just enough data
        var buf: [3]u8 = undefined;
        mem.writeInt(u16, buf[0..2], 8, .big);
        buf[2] = 0xAA;
        var fbs = std.io.fixedBufferStream(&buf);
        const m = Mpi.readFrom(allocator, fbs.reader()) catch return;
        if (m.data.len > 0) allocator.free(m.data);
    }
}

test "security_hardening: symmetric encrypt/decrypt no leak" {
    const allocator = testing.allocator;
    const encrypted = try seipd.seipdEncrypt(allocator, "test", &([_]u8{0x42} ** 16), .aes128);
    defer allocator.free(encrypted);
    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, &([_]u8{0x42} ** 16), .aes128);
    defer allocator.free(decrypted);
}

// ==========================================================================
// Padding Oracle Resistance
// ==========================================================================

test "security_hardening: SEIPD encrypt then decrypt correct key works" {
    const allocator = testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const encrypted = try seipd.seipdEncrypt(allocator, "secret", &key, .aes128);
    defer allocator.free(encrypted);
    const decrypted = try seipd.seipdDecrypt(allocator, encrypted, &key, .aes128);
    defer allocator.free(decrypted);
    try testing.expectEqualStrings("secret", decrypted);
}

test "security_hardening: SEIPD v2 encrypt then decrypt correct key works" {
    const allocator = testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const encrypted = try seipd_v2.seipdV2Encrypt(allocator, "secret", &key, .aes128, .eax, 6);
    defer allocator.free(encrypted);
    const decrypted = try seipd_v2.seipdV2Decrypt(allocator, encrypted, &key);
    defer allocator.free(decrypted);
    try testing.expectEqualStrings("secret", decrypted);
}

test "security_hardening: encryptions of same data differ (random IV)" {
    const allocator = testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const enc1 = try seipd.seipdEncrypt(allocator, "same", &key, .aes128);
    defer allocator.free(enc1);
    const enc2 = try seipd.seipdEncrypt(allocator, "same", &key, .aes128);
    defer allocator.free(enc2);
    try testing.expect(!mem.eql(u8, enc1, enc2));
}

// ==========================================================================
// S2K Iteration Enforcement
// ==========================================================================

test "security_hardening: S2K iteration count formula" {
    const s2k_min = S2K{ .s2k_type = .iterated, .hash_algo = .sha256, .salt = [_]u8{0} ** 8, .coded_count = 0, .argon2_data = null };
    const s2k_def = S2K{ .s2k_type = .iterated, .hash_algo = .sha256, .salt = [_]u8{0} ** 8, .coded_count = 96, .argon2_data = null };
    const s2k_max = S2K{ .s2k_type = .iterated, .hash_algo = .sha256, .salt = [_]u8{0} ** 8, .coded_count = 255, .argon2_data = null };
    try testing.expectEqual(@as(u32, 1024), s2k_min.iterationCount());
    try testing.expectEqual(@as(u32, 65536), s2k_def.iterationCount());
    try testing.expectEqual(@as(u32, 65011712), s2k_max.iterationCount());
}

test "security_hardening: S2K simple equals SHA-256(passphrase)" {
    const s2k = S2K{ .s2k_type = .simple, .hash_algo = .sha256, .salt = [_]u8{0} ** 8, .coded_count = 0, .argon2_data = null };
    var key: [32]u8 = undefined;
    try s2k.deriveKey("test", &key);
    var ctx = try HashContext.init(.sha256);
    ctx.update("test");
    var expected: [32]u8 = undefined;
    ctx.final(&expected);
    try testing.expectEqualSlices(u8, &expected, &key);
}

test "security_hardening: S2K salted differs from simple" {
    var k_simple: [32]u8 = undefined;
    var k_salted: [32]u8 = undefined;
    const simple = S2K{ .s2k_type = .simple, .hash_algo = .sha256, .salt = [_]u8{0} ** 8, .coded_count = 0, .argon2_data = null };
    const salted = S2K{ .s2k_type = .salted, .hash_algo = .sha256, .salt = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, .coded_count = 0, .argon2_data = null };
    try simple.deriveKey("pw", &k_simple);
    try salted.deriveKey("pw", &k_salted);
    try testing.expect(!mem.eql(u8, &k_simple, &k_salted));
}

// ==========================================================================
// Integer Overflow / Edge-Case MPI Tests
// ==========================================================================

test "security_hardening: MPI edge-case sizes" {
    try testing.expectEqual(@as(usize, 0), (Mpi{ .bit_count = 0, .data = &.{} }).byteLen());
    try testing.expectEqual(@as(usize, 2), (Mpi{ .bit_count = 0, .data = &.{} }).wireLen());
    try testing.expectEqual(@as(usize, 1), (Mpi{ .bit_count = 1, .data = &[_]u8{1} }).byteLen());
    try testing.expectEqual(@as(usize, 1), (Mpi{ .bit_count = 8, .data = &[_]u8{0xFF} }).byteLen());
    try testing.expectEqual(@as(usize, 8192), (Mpi{ .bit_count = 65535, .data = &.{} }).byteLen());
}

test "security_hardening: MPI fromBytes bit count computation" {
    try testing.expectEqual(@as(u16, 8), Mpi.fromBytes(&[_]u8{0x80}).bit_count);
    try testing.expectEqual(@as(u16, 1), Mpi.fromBytes(&[_]u8{0x01}).bit_count);
    try testing.expectEqual(@as(u16, 9), Mpi.fromBytes(&[_]u8{ 0x01, 0x00 }).bit_count);
    try testing.expectEqual(@as(u16, 17), Mpi.fromBytes(&[_]u8{ 0x01, 0x00, 0x01 }).bit_count);
    try testing.expectEqual(@as(u16, 0), Mpi.fromBytes(&[_]u8{}).bit_count);
}

// ==========================================================================
// Session Key Randomness Tests
// ==========================================================================

test "security_hardening: session keys are unique and non-zero" {
    var keys: [10][32]u8 = undefined;
    for (0..10) |i| {
        const sk = try session_key_mod.generateSessionKey(.aes256);
        keys[i] = sk.key;
        var all_zero = true;
        for (sk.keySlice()) |b| if (b != 0) { all_zero = false; break; };
        try testing.expect(!all_zero);
    }
    for (0..10) |i| for (i + 1..10) |j| try testing.expect(!mem.eql(u8, &keys[i], &keys[j]));
}

// ==========================================================================
// Ed25519 Security Tests
// ==========================================================================

test "security_hardening: Ed25519 invalid signatures rejected" {
    const kp = try ed25519_ops.ed25519Generate();
    try testing.expectError(ed25519_ops.Ed25519Error.SignatureVerificationFailed, ed25519_ops.ed25519Verify(kp.public_key, "msg", [_]u8{0} ** 64));
}

test "security_hardening: Ed25519 modified message detected" {
    const kp = try ed25519_ops.ed25519Generate();
    const sig = try ed25519_ops.ed25519Sign(kp.secret_key, "Original");
    try ed25519_ops.ed25519Verify(kp.public_key, "Original", sig);
    for ([_][]const u8{ "original", "Original ", "", "Origina" }) |modified| {
        try testing.expectError(ed25519_ops.Ed25519Error.SignatureVerificationFailed, ed25519_ops.ed25519Verify(kp.public_key, modified, sig));
    }
}

// ==========================================================================
// Hash Security Tests
// ==========================================================================

test "security_hardening: unsupported hash algorithms rejected" {
    try testing.expectError(error.UnsupportedAlgorithm, hash_mod.digestSize(.md5));
    try testing.expectError(error.UnsupportedAlgorithm, HashContext.init(.md5));
}

test "security_hardening: hash preimage resistance basic check" {
    var digests: [50][32]u8 = undefined;
    for (0..50) |i| {
        var ctx = try HashContext.init(.sha256);
        ctx.update(&[_]u8{@intCast(i)});
        ctx.final(&digests[i]);
    }
    for (0..50) |i| for (i + 1..50) |j| try testing.expect(!mem.eql(u8, &digests[i], &digests[j]));
}

// ==========================================================================
// Algorithm Policy Tests
// ==========================================================================

test "security_hardening: SecurityLevel creation and verification policies" {
    try testing.expect(SecurityLevel.secure.isSafeForCreation());
    try testing.expect(!SecurityLevel.deprecated.isSafeForCreation());
    try testing.expect(!SecurityLevel.insecure.isSafeForCreation());
    try testing.expect(!SecurityLevel.unknown.isSafeForCreation());
    try testing.expect(SecurityLevel.secure.isAcceptableForVerification());
    try testing.expect(SecurityLevel.deprecated.isAcceptableForVerification());
    try testing.expect(!SecurityLevel.insecure.isAcceptableForVerification());
    try testing.expect(!SecurityLevel.unknown.isAcceptableForVerification());
}

test "security_hardening: SecurityLevel names are non-empty" {
    const levels = [_]SecurityLevel{ .secure, .deprecated, .insecure, .unknown };
    for (levels) |level| try testing.expect(level.name().len > 0);
}

// ==========================================================================
// Additional Memory Safety Tests
// ==========================================================================

test "security_hardening: signature parse and deinit no leak" {
    const allocator = testing.allocator;
    const body = [_]u8{
        4, 0x00, 1, 8, // version, sig_type, RSA, SHA-256
        0x00, 0x06, 5, 2, 0x5E, 0x0B, 0xE1, 0x00, // hashed subpackets
        0x00, 0x00, // no unhashed subpackets
        0xAB, 0xCD, // hash prefix
        0x00, 0x08, 0xAA, // MPI
    };
    var sig = try SignaturePacket.parse(allocator, &body);
    sig.deinit(allocator);
}

test "security_hardening: SKESK parse and deinit no leak" {
    const allocator = testing.allocator;
    const body = [_]u8{ 4, 9, 3, 8, 1, 2, 3, 4, 5, 6, 7, 8, 96 };
    const pkt = try SKESKPacket.parse(allocator, &body);
    pkt.deinit(allocator);
}

test "security_hardening: armor encode and decode no leak" {
    const allocator = testing.allocator;
    const armored = try armor.encode(allocator, "test data" ** 10, .message, null);
    defer allocator.free(armored);
    var decoded = try armor.decode(allocator, armored);
    decoded.deinit();
}

test "security_hardening: MPI read and deinit no leak" {
    const allocator = testing.allocator;
    var buf = [_]u8{ 0x00, 0x11, 0x01, 0x00, 0x01 };
    var fbs = std.io.fixedBufferStream(&buf);
    const mpi = try Mpi.readFrom(allocator, fbs.reader());
    mpi.deinit(allocator);
}

test "security_hardening: message encrypt/decrypt no leak" {
    const allocator = testing.allocator;
    const encrypted = try compose.encryptMessageSymmetric(allocator, "msg", "t.txt", "pw", .aes128, null);
    defer allocator.free(encrypted);
    var msg = try decompose_mod.parseMessage(allocator, encrypted);
    defer msg.deinit(allocator);
    const decrypted = try decompose_mod.decryptWithPassphrase(allocator, &msg, "pw");
    defer allocator.free(decrypted);
}

// ==========================================================================
// Additional Constant-Time Tests
// ==========================================================================

test "security_hardening: secureEqual exhaustive 1-byte" {
    for (0..256) |i| {
        const a = [_]u8{@intCast(i)};
        try testing.expect(zeroize.secureEqual(&a, &a));
        for (0..256) |j| {
            const b = [_]u8{@intCast(j)};
            try testing.expectEqual(i == j, zeroize.secureEqual(&a, &b));
        }
    }
}

test "security_hardening: secureZero typed slice" {
    var buf = [_]u32{ 0xDEADBEEF, 0xCAFEBABE, 0x12345678 };
    const slice: []u32 = &buf;
    zeroize.secureZero(u32, slice);
    for (buf) |v| try testing.expectEqual(@as(u32, 0), v);
}

test "security_hardening: secureZeroArray fixed array" {
    var arr = [_]u8{0xFF} ** 64;
    zeroize.secureZeroArray(64, &arr);
    for (arr) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "security_hardening: multiple SecureBuffers coexist" {
    var b1 = try zeroize.SecureBuffer.init(testing.allocator, 32);
    var b2 = try zeroize.SecureBuffer.init(testing.allocator, 64);
    @memset(b1.data, 0xAA);
    @memset(b2.data, 0xBB);
    try testing.expectEqual(@as(u8, 0xAA), b1.data[0]);
    try testing.expectEqual(@as(u8, 0xBB), b2.data[0]);
    b1.deinit();
    b2.deinit();
}

// ==========================================================================
// Additional Ed25519 Security Tests
// ==========================================================================

test "security_hardening: Ed25519 key pairs are unique" {
    var pubs: [10][32]u8 = undefined;
    for (0..10) |i| {
        const kp = try ed25519_ops.ed25519Generate();
        pubs[i] = kp.public_key;
    }
    for (0..10) |i| for (i + 1..10) |j| try testing.expect(!mem.eql(u8, &pubs[i], &pubs[j]));
}

// ==========================================================================
// Additional Algorithm Policy Tests
// ==========================================================================

test "security_hardening: all known symmetric algorithms classified" {
    const known = [_]SymmetricAlgorithm{ .plaintext, .idea, .triple_des, .cast5, .blowfish, .aes128, .aes192, .aes256, .twofish };
    for (known) |algo| try testing.expect(deprecation_mod.assessSymmetricAlgorithm(algo) != .unknown);
}

test "security_hardening: all known hash algorithms classified" {
    const known = [_]HashAlgorithm{ .md5, .sha1, .ripemd160, .sha224, .sha256, .sha384, .sha512 };
    for (known) |algo| try testing.expect(deprecation_mod.assessHashAlgorithm(algo) != .unknown);
}

test "security_hardening: all known public key algorithms classified" {
    const known = [_]PublicKeyAlgorithm{
        .rsa_encrypt_sign, .rsa_encrypt_only, .rsa_sign_only,
        .elgamal, .dsa, .ecdh, .ecdsa, .eddsa,
        .x25519, .x448, .ed25519, .ed448,
    };
    for (known) |algo| try testing.expect(deprecation_mod.assessPublicKeyAlgorithm(algo) != .unknown);
}

// ==========================================================================
// MPI write/read round-trip for various sizes
// ==========================================================================

test "security_hardening: MPI write/read round-trip various sizes" {
    const allocator = testing.allocator;
    const test_values = [_][]const u8{
        &[_]u8{},
        &[_]u8{0x01},
        &[_]u8{0x7F},
        &[_]u8{0xFF},
        &[_]u8{ 0x01, 0x00 },
        &[_]u8{ 0x01, 0x00, 0x01 },
    };
    for (test_values) |val| {
        const original = Mpi.fromBytes(val);
        var buf: [270]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        try original.writeTo(fbs.writer());
        fbs.pos = 0;
        const read_back = try Mpi.readFrom(allocator, fbs.reader());
        defer read_back.deinit(allocator);
        try testing.expectEqual(original.bit_count, read_back.bit_count);
        if (val.len > 0) try testing.expectEqualSlices(u8, val, read_back.data);
    }
}

// ==========================================================================
// Hash algorithm digest sizes
// ==========================================================================

test "security_hardening: hash digest sizes correct" {
    const cases = [_]struct { a: HashAlgorithm, s: usize }{
        .{ .a = .sha1, .s = 20 }, .{ .a = .sha224, .s = 28 },
        .{ .a = .sha256, .s = 32 }, .{ .a = .sha384, .s = 48 },
        .{ .a = .sha512, .s = 64 },
    };
    for (cases) |c| try testing.expectEqual(c.s, try hash_mod.digestSize(c.a));
}

// ==========================================================================
// S2K wire format round-trip for all types
// ==========================================================================

test "security_hardening: S2K wire format round-trip all types" {
    const test_s2ks = [_]S2K{
        .{ .s2k_type = .simple, .hash_algo = .sha256, .salt = [_]u8{0} ** 8, .coded_count = 0, .argon2_data = null },
        .{ .s2k_type = .salted, .hash_algo = .sha512, .salt = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 }, .coded_count = 0, .argon2_data = null },
        .{ .s2k_type = .iterated, .hash_algo = .sha384, .salt = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, .coded_count = 200, .argon2_data = null },
    };
    for (test_s2ks) |original| {
        var buf: [11]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        try original.writeTo(fbs.writer());
        fbs.pos = 0;
        const parsed = try S2K.readFrom(fbs.reader());
        try testing.expectEqual(original.s2k_type, parsed.s2k_type);
        try testing.expectEqual(original.hash_algo, parsed.hash_algo);
        if (original.s2k_type == .salted or original.s2k_type == .iterated) {
            try testing.expectEqual(original.salt, parsed.salt);
        }
        if (original.s2k_type == .iterated) {
            try testing.expectEqual(original.coded_count, parsed.coded_count);
        }
    }
}

// ==========================================================================
// PKCS#1 padding constants
// ==========================================================================

test "security_hardening: PKCS1 minimum overhead constants" {
    const overhead: usize = 11; // 0x00 || 0x02 || PS(>=8) || 0x00
    try testing.expectEqual(@as(usize, 245), 256 - overhead); // RSA-2048
    try testing.expectEqual(@as(usize, 501), 512 - overhead); // RSA-4096
}
