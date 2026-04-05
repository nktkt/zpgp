// SPDX-License-Identifier: MIT
//! Tests for policy modules (algorithm_policy, compliance).
//!
//! Exercises the policy engine with comprehensive algorithm combinations
//! and compliance checking scenarios.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

const algo_policy = @import("policy/algorithm_policy.zig");
const AlgorithmPolicy = algo_policy.AlgorithmPolicy;
const PolicyLevel = algo_policy.PolicyLevel;

const compliance = @import("policy/compliance.zig");
const ComplianceStandard = compliance.ComplianceStandard;
const ComplianceReport = compliance.ComplianceReport;
const Severity = compliance.Severity;

const enums = @import("types/enums.zig");
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const AeadAlgorithm = enums.AeadAlgorithm;

const Key = @import("key/key.zig").Key;
const PublicKeyPacket = @import("packets/public_key.zig").PublicKeyPacket;
const UserIdPacket = @import("packets/user_id.zig").UserIdPacket;

// =========================================================================
// AlgorithmPolicy tests — symmetric algorithms
// =========================================================================

test "policy: rfc4880 symmetric — accepts all standard ciphers" {
    const policy = AlgorithmPolicy.init(.rfc4880);
    try testing.expect(policy.isAcceptableSymmetric(.idea));
    try testing.expect(policy.isAcceptableSymmetric(.triple_des));
    try testing.expect(policy.isAcceptableSymmetric(.cast5));
    try testing.expect(policy.isAcceptableSymmetric(.blowfish));
    try testing.expect(policy.isAcceptableSymmetric(.aes128));
    try testing.expect(policy.isAcceptableSymmetric(.aes192));
    try testing.expect(policy.isAcceptableSymmetric(.aes256));
    try testing.expect(policy.isAcceptableSymmetric(.twofish));
}

test "policy: rfc4880 symmetric — rejects plaintext and unknown" {
    const policy = AlgorithmPolicy.init(.rfc4880);
    try testing.expect(!policy.isAcceptableSymmetric(.plaintext));
    const unknown: SymmetricAlgorithm = @enumFromInt(99);
    try testing.expect(!policy.isAcceptableSymmetric(unknown));
}

test "policy: strict symmetric — only modern ciphers" {
    const policy = AlgorithmPolicy.init(.strict);
    try testing.expect(policy.isAcceptableSymmetric(.aes128));
    try testing.expect(policy.isAcceptableSymmetric(.aes192));
    try testing.expect(policy.isAcceptableSymmetric(.aes256));
    try testing.expect(policy.isAcceptableSymmetric(.twofish));
    try testing.expect(!policy.isAcceptableSymmetric(.idea));
    try testing.expect(!policy.isAcceptableSymmetric(.triple_des));
    try testing.expect(!policy.isAcceptableSymmetric(.cast5));
    try testing.expect(!policy.isAcceptableSymmetric(.blowfish));
    try testing.expect(!policy.isAcceptableSymmetric(.plaintext));
}

// =========================================================================
// AlgorithmPolicy tests — hash algorithms
// =========================================================================

test "policy: rfc4880 hash — accepts all standard hashes" {
    const policy = AlgorithmPolicy.init(.rfc4880);
    try testing.expect(policy.isAcceptableHash(.md5));
    try testing.expect(policy.isAcceptableHash(.sha1));
    try testing.expect(policy.isAcceptableHash(.ripemd160));
    try testing.expect(policy.isAcceptableHash(.sha256));
    try testing.expect(policy.isAcceptableHash(.sha384));
    try testing.expect(policy.isAcceptableHash(.sha512));
    try testing.expect(policy.isAcceptableHash(.sha224));
}

test "policy: rfc9580 hash — rejects MD5 but allows others" {
    const policy = AlgorithmPolicy.init(.rfc9580);
    try testing.expect(!policy.isAcceptableHash(.md5));
    try testing.expect(policy.isAcceptableHash(.sha1));
    try testing.expect(policy.isAcceptableHash(.sha256));
    try testing.expect(policy.isAcceptableHash(.sha512));
}

test "policy: strict hash — only SHA-2 family (256+)" {
    const policy = AlgorithmPolicy.init(.strict);
    try testing.expect(!policy.isAcceptableHash(.md5));
    try testing.expect(!policy.isAcceptableHash(.sha1));
    try testing.expect(!policy.isAcceptableHash(.ripemd160));
    try testing.expect(!policy.isAcceptableHash(.sha224));
    try testing.expect(policy.isAcceptableHash(.sha256));
    try testing.expect(policy.isAcceptableHash(.sha384));
    try testing.expect(policy.isAcceptableHash(.sha512));
}

// =========================================================================
// AlgorithmPolicy tests — public key algorithms
// =========================================================================

test "policy: rfc4880 public key — accepts all with min bits" {
    const policy = AlgorithmPolicy.init(.rfc4880);
    try testing.expect(policy.isAcceptablePublicKey(.rsa_encrypt_sign, 2048));
    try testing.expect(policy.isAcceptablePublicKey(.rsa_encrypt_sign, 1024));
    try testing.expect(!policy.isAcceptablePublicKey(.rsa_encrypt_sign, 512));
    try testing.expect(policy.isAcceptablePublicKey(.dsa, null));
    try testing.expect(policy.isAcceptablePublicKey(.elgamal, null));
    try testing.expect(policy.isAcceptablePublicKey(.ecdh, null));
    try testing.expect(policy.isAcceptablePublicKey(.ecdsa, null));
    try testing.expect(policy.isAcceptablePublicKey(.eddsa, null));
}

test "policy: rfc9580 public key — requires RSA 2048+" {
    const policy = AlgorithmPolicy.init(.rfc9580);
    try testing.expect(!policy.isAcceptablePublicKey(.rsa_encrypt_sign, 1024));
    try testing.expect(policy.isAcceptablePublicKey(.rsa_encrypt_sign, 2048));
    try testing.expect(policy.isAcceptablePublicKey(.rsa_encrypt_sign, 4096));
    try testing.expect(policy.isAcceptablePublicKey(.ed25519, null));
    try testing.expect(policy.isAcceptablePublicKey(.x25519, null));
}

test "policy: strict public key — requires RSA 3072+" {
    const policy = AlgorithmPolicy.init(.strict);
    try testing.expect(!policy.isAcceptablePublicKey(.rsa_encrypt_sign, 2048));
    try testing.expect(policy.isAcceptablePublicKey(.rsa_encrypt_sign, 3072));
    try testing.expect(policy.isAcceptablePublicKey(.rsa_encrypt_sign, 4096));
    try testing.expect(!policy.isAcceptablePublicKey(.dsa, null));
    try testing.expect(!policy.isAcceptablePublicKey(.elgamal, null));
    try testing.expect(!policy.isAcceptablePublicKey(.eddsa, null));
    try testing.expect(policy.isAcceptablePublicKey(.ed25519, null));
    try testing.expect(policy.isAcceptablePublicKey(.ed448, null));
    try testing.expect(policy.isAcceptablePublicKey(.x25519, null));
    try testing.expect(policy.isAcceptablePublicKey(.x448, null));
}

// =========================================================================
// AlgorithmPolicy tests — AEAD
// =========================================================================

test "policy: AEAD support by level" {
    const rfc4880 = AlgorithmPolicy.init(.rfc4880);
    try testing.expect(!rfc4880.isAcceptableAead(.gcm));
    try testing.expect(!rfc4880.isAcceptableAead(.ocb));
    try testing.expect(!rfc4880.isAcceptableAead(.eax));

    const rfc9580 = AlgorithmPolicy.init(.rfc9580);
    try testing.expect(rfc9580.isAcceptableAead(.gcm));
    try testing.expect(rfc9580.isAcceptableAead(.ocb));
    try testing.expect(rfc9580.isAcceptableAead(.eax));

    const strict = AlgorithmPolicy.init(.strict);
    try testing.expect(strict.isAcceptableAead(.gcm));
    try testing.expect(strict.isAcceptableAead(.ocb));
    try testing.expect(strict.isAcceptableAead(.eax));
}

// =========================================================================
// AlgorithmPolicy tests — preferred selections
// =========================================================================

test "policy: preferred algorithms match expectations" {
    const rfc4880 = AlgorithmPolicy.init(.rfc4880);
    try testing.expectEqual(SymmetricAlgorithm.aes128, rfc4880.preferredSymmetric());
    try testing.expectEqual(HashAlgorithm.sha256, rfc4880.preferredHash());
    try testing.expect(rfc4880.preferredAead() == null);

    const rfc9580 = AlgorithmPolicy.init(.rfc9580);
    try testing.expectEqual(SymmetricAlgorithm.aes256, rfc9580.preferredSymmetric());
    try testing.expectEqual(HashAlgorithm.sha256, rfc9580.preferredHash());
    try testing.expectEqual(AeadAlgorithm.gcm, rfc9580.preferredAead().?);

    const strict = AlgorithmPolicy.init(.strict);
    try testing.expectEqual(SymmetricAlgorithm.aes256, strict.preferredSymmetric());
    try testing.expectEqual(AeadAlgorithm.gcm, strict.preferredAead().?);
}

// =========================================================================
// AlgorithmPolicy tests — validation
// =========================================================================

test "policy: validateKey DSA warnings under rfc9580" {
    const policy = AlgorithmPolicy.init(.rfc9580);
    const result = policy.validateKey(.dsa, null);
    try testing.expect(result.accepted);
    try testing.expect(result.warnings.len > 0);
    try testing.expect(result.recommendation != null);
}

test "policy: validateKey Ed25519 clean under strict" {
    const policy = AlgorithmPolicy.init(.strict);
    const result = policy.validateKey(.ed25519, null);
    try testing.expect(result.accepted);
    try testing.expectEqual(@as(usize, 0), result.warnings.len);
    try testing.expect(result.recommendation == null);
}

test "policy: validateKey small RSA warning under rfc9580" {
    const policy = AlgorithmPolicy.init(.rfc9580);
    const result = policy.validateKey(.rsa_encrypt_sign, 2048);
    try testing.expect(result.accepted);
    try testing.expect(result.warnings.len > 0); // < 3072 warning
}

test "policy: validateSignature strict rejects md5+dsa" {
    const policy = AlgorithmPolicy.init(.strict);
    const result = policy.validateSignature(.md5, .dsa);
    try testing.expect(!result.accepted);
    try testing.expect(result.warnings.len > 0);
}

test "policy: validateSignature rfc9580 sha1 warning" {
    const policy = AlgorithmPolicy.init(.rfc9580);
    const result = policy.validateSignature(.sha1, .rsa_encrypt_sign);
    try testing.expect(result.accepted);
    try testing.expect(result.warnings.len > 0);
}

test "policy: validateSuite all good" {
    const policy = AlgorithmPolicy.init(.strict);
    const result = policy.validateSuite(.aes256, .sha512, .ed25519, null);
    try testing.expect(result.accepted);
    try testing.expectEqual(@as(usize, 0), result.warnings.len);
}

test "policy: validateSuite mixed bad" {
    const policy = AlgorithmPolicy.init(.strict);
    const result = policy.validateSuite(.cast5, .sha256, .ed25519, null);
    try testing.expect(!result.accepted);
}

// =========================================================================
// Compliance report tests
// =========================================================================

test "compliance: report error and warning counts" {
    const allocator = testing.allocator;
    var report = ComplianceReport.init(allocator);
    defer report.deinit();

    try report.addIssue(.error_level, "E1", "error 1");
    try report.addIssue(.warning, "W1", "warning 1");
    try report.addIssue(.info, "I1", "info 1");
    try report.addIssue(.error_level, "E2", "error 2");
    try report.addIssue(.warning, "W2", "warning 2");

    try testing.expect(!report.compliant);
    try testing.expectEqual(@as(usize, 2), report.errorCount());
    try testing.expectEqual(@as(usize, 2), report.warningCount());
    try testing.expectEqual(@as(usize, 5), report.issues.items.len);
}

test "compliance: report with only warnings stays compliant" {
    const allocator = testing.allocator;
    var report = ComplianceReport.init(allocator);
    defer report.deinit();

    try report.addIssue(.warning, "W1", "just a warning");
    try report.addIssue(.info, "I1", "just info");

    try testing.expect(report.compliant);
}

// =========================================================================
// Message compliance tests
// =========================================================================

test "compliance: empty message" {
    const allocator = testing.allocator;
    var report = try compliance.checkMessageCompliance("", .openpgp_rfc4880, allocator);
    defer report.deinit();
    try testing.expect(!report.compliant);
}

test "compliance: non-openpgp data" {
    const allocator = testing.allocator;
    var report = try compliance.checkMessageCompliance("plain text", .openpgp_rfc4880, allocator);
    defer report.deinit();
    try testing.expect(!report.compliant);
}

test "compliance: old-format packet with rfc9580" {
    const allocator = testing.allocator;
    // Old-format packet: bit 7 set, bit 6 clear
    const data = [_]u8{ 0x84, 0x02, 0x01, 0x02 };
    var report = try compliance.checkMessageCompliance(&data, .openpgp_rfc9580, allocator);
    defer report.deinit();
    // Should have info about old-format headers
    var has_old_format_note = false;
    for (report.issues.items) |issue| {
        if (mem.eql(u8, issue.code, "OLD_FORMAT")) {
            has_old_format_note = true;
        }
    }
    try testing.expect(has_old_format_note);
}

// =========================================================================
// Key compliance tests
// =========================================================================

test "compliance: minimal key rfc4880" {
    const allocator = testing.allocator;

    var body: [12]u8 = undefined;
    body[0] = 4; // V4
    mem.writeInt(u32, body[1..5], 1000, .big);
    body[5] = 1; // RSA
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xFF;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;

    const pk = try PublicKeyPacket.parse(allocator, &body, false);
    var key = Key.init(pk);
    defer key.deinit(allocator);

    var report = try compliance.checkKeyCompliance(&key, .openpgp_rfc4880, allocator);
    defer report.deinit();

    // Should warn about missing user IDs
    try testing.expect(report.warningCount() > 0);
}

test "compliance: key with user id rfc4880" {
    const allocator = testing.allocator;

    var body: [12]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], 1000, .big);
    body[5] = 1; // RSA
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xFF;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;

    const pk = try PublicKeyPacket.parse(allocator, &body, false);
    var key = Key.init(pk);
    defer key.deinit(allocator);

    const uid = UserIdPacket{ .id = try allocator.dupe(u8, "Test <test@example.com>") };
    try key.addUserId(allocator, .{
        .user_id = uid,
        .self_signature = null,
        .certifications = .empty,
    });

    var report = try compliance.checkKeyCompliance(&key, .openpgp_rfc4880, allocator);
    defer report.deinit();

    // Should still warn about missing self-signature
    var has_self_sig_warning = false;
    for (report.issues.items) |issue| {
        if (mem.eql(u8, issue.code, "NO_SELF_SIG")) {
            has_self_sig_warning = true;
        }
    }
    try testing.expect(has_self_sig_warning);
}

test "compliance: key version info for rfc9580" {
    const allocator = testing.allocator;

    var body: [12]u8 = undefined;
    body[0] = 4; // V4 key
    mem.writeInt(u32, body[1..5], 1000, .big);
    body[5] = 1; // RSA
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xFF;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;

    const pk = try PublicKeyPacket.parse(allocator, &body, false);
    var key = Key.init(pk);
    defer key.deinit(allocator);

    var report = try compliance.checkKeyCompliance(&key, .openpgp_rfc9580, allocator);
    defer report.deinit();

    // Should have info about V4 vs V6
    var has_version_info = false;
    for (report.issues.items) |issue| {
        if (mem.eql(u8, issue.code, "KEY_VERSION")) {
            has_version_info = true;
        }
    }
    try testing.expect(has_version_info);
}

// =========================================================================
// Custom policy tests
// =========================================================================

test "policy: custom accepts everything" {
    const policy = AlgorithmPolicy.init(.custom);
    try testing.expect(policy.isAcceptableSymmetric(.idea));
    try testing.expect(policy.isAcceptableHash(.md5));
    try testing.expect(policy.isAcceptablePublicKey(.dsa, null));
    try testing.expect(policy.isAcceptableAead(.gcm));
}
