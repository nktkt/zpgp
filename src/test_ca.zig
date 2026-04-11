// SPDX-License-Identifier: MIT
//! Integration tests for OpenPGP Certification Authority (CA).
//!
//! Tests cover:
//!   - CA initialization and key setup
//!   - Certification issuance and verification
//!   - Policy enforcement (algorithms, key sizes, domains, expiration)
//!   - Certification revocation
//!   - Database serialization and deserialization
//!   - Key vetting workflow

const std = @import("std");
const testing = std.testing;

const ca = @import("ca/openpgp_ca.zig");
const CertificationAuthority = ca.CertificationAuthority;
const CaDatabase = ca.CaDatabase;
const CaPolicy = ca.CaPolicy;
const CertificationLevel = ca.CertificationLevel;
const CertificationRecord = ca.CertificationRecord;
const TrustDepth = ca.TrustDepth;
const VettingResult = ca.VettingResult;
const KeyParams = ca.KeyParams;
const CaError = ca.CaError;

const enums = @import("types/enums.zig");
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;

// =========================================================================
// Helper: create test key params
// =========================================================================

fn makeTestKeyParams(algo: PublicKeyAlgorithm, key_bits: u16, has_exp: bool) KeyParams {
    return .{
        .algorithm = algo,
        .key_bits = key_bits,
        .has_expiration = has_exp,
        .validity_secs = if (has_exp) 365 * 24 * 3600 else 0,
        .fingerprint = std.mem.zeroes([32]u8),
        .fingerprint_len = 20,
        .creation_time = 1000000,
    };
}

// =========================================================================
// CA Initialization Tests
// =========================================================================

test "CA: init with default policy" {
    const allocator = testing.allocator;
    var authority = CertificationAuthority.init(allocator, CaPolicy.default());
    defer authority.deinit();

    try testing.expect(!authority.initialized);
}

test "CA: initialize with key" {
    const allocator = testing.allocator;
    var authority = CertificationAuthority.init(allocator, CaPolicy.default());
    defer authority.deinit();

    const fp: [20]u8 = .{0xAA} ** 20;
    try authority.initializeWithKey(&fp, .ed25519, "Test CA <ca@example.com>");

    try testing.expect(authority.initialized);
    try testing.expectEqual(PublicKeyAlgorithm.ed25519, authority.ca_algorithm);
    try testing.expectEqualStrings("Test CA <ca@example.com>", authority.ca_name);
    try testing.expectEqual(@as(u8, 20), authority.ca_fingerprint_len);
}

test "CA: operations fail before initialization" {
    const allocator = testing.allocator;
    var authority = CertificationAuthority.init(allocator, CaPolicy.default());
    defer authority.deinit();

    const params = makeTestKeyParams(.ed25519, 256, false);
    try testing.expectError(CaError.NotInitialized,
        authority.issueCertification(params, "alice@example.com", null, null, 1000000));
}

// =========================================================================
// Certification Issuance Tests
// =========================================================================

test "CA: issue certification with default policy" {
    const allocator = testing.allocator;
    var authority = CertificationAuthority.init(allocator, CaPolicy.default());
    defer authority.deinit();

    try authority.initializeWithKey(&(.{0xBB} ** 20), .ed25519, "CA <ca@test.com>");

    const params = makeTestKeyParams(.ed25519, 256, false);
    const cert_id = try authority.issueCertification(params, "user@test.com", null, null, 1000000);

    try testing.expectEqual(@as(u64, 1), cert_id);

    const stats = authority.getStats(1000000);
    try testing.expectEqual(@as(usize, 1), stats.total_certifications);
    try testing.expectEqual(@as(usize, 1), stats.active_certifications);
    try testing.expectEqual(@as(usize, 0), stats.revoked_certifications);
}

test "CA: issue certification with custom level and depth" {
    const allocator = testing.allocator;
    var authority = CertificationAuthority.init(allocator, CaPolicy.default());
    defer authority.deinit();

    try authority.initializeWithKey(&(.{0xCC} ** 20), .ed25519, "CA <ca@test.com>");

    const params = makeTestKeyParams(.rsa_encrypt_sign, 4096, false);
    const depth = TrustDepth.introducer("example.com");

    const cert_id = try authority.issueCertification(
        params,
        "admin@example.com",
        .casual,
        depth,
        2000000,
    );

    try testing.expectEqual(@as(u64, 1), cert_id);

    const record = authority.database.findById(cert_id);
    try testing.expect(record != null);
    try testing.expectEqual(CertificationLevel.casual, record.?.cert_level);
    try testing.expectEqual(@as(u8, 1), record.?.trust_depth.depth);
}

test "CA: issue multiple certifications" {
    const allocator = testing.allocator;
    var authority = CertificationAuthority.init(allocator, CaPolicy.default());
    defer authority.deinit();

    try authority.initializeWithKey(&(.{0xDD} ** 20), .ed25519, "CA");

    const params = makeTestKeyParams(.ed25519, 256, false);

    const id1 = try authority.issueCertification(params, "user1@test.com", null, null, 1000000);
    const id2 = try authority.issueCertification(params, "user2@test.com", null, null, 1000001);
    const id3 = try authority.issueCertification(params, "user3@test.com", null, null, 1000002);

    try testing.expectEqual(@as(u64, 1), id1);
    try testing.expectEqual(@as(u64, 2), id2);
    try testing.expectEqual(@as(u64, 3), id3);

    const stats = authority.getStats(1000000);
    try testing.expectEqual(@as(usize, 3), stats.total_certifications);
}

// =========================================================================
// Revocation Tests
// =========================================================================

test "CA: revoke certification" {
    const allocator = testing.allocator;
    var authority = CertificationAuthority.init(allocator, CaPolicy.default());
    defer authority.deinit();

    try authority.initializeWithKey(&(.{0xEE} ** 20), .ed25519, "CA");

    const params = makeTestKeyParams(.ed25519, 256, false);
    const cert_id = try authority.issueCertification(params, "user@test.com", null, null, 1000000);

    try authority.revokeCertification(cert_id, "Key compromised", 2000000);

    const stats = authority.getStats(2000000);
    try testing.expectEqual(@as(usize, 1), stats.revoked_certifications);
    try testing.expectEqual(@as(usize, 0), stats.active_certifications);

    // Record should show revocation details
    const record = authority.database.findById(cert_id);
    try testing.expect(record != null);
    try testing.expect(record.?.revoked);
    try testing.expectEqual(@as(u64, 2000000), record.?.revoked_at);
}

test "CA: double revocation fails" {
    const allocator = testing.allocator;
    var authority = CertificationAuthority.init(allocator, CaPolicy.default());
    defer authority.deinit();

    try authority.initializeWithKey(&(.{0xFF} ** 20), .ed25519, "CA");

    const params = makeTestKeyParams(.ed25519, 256, false);
    const cert_id = try authority.issueCertification(params, "user@test.com", null, null, 1000000);

    try authority.revokeCertification(cert_id, null, 2000000);
    try testing.expectError(CaError.AlreadyRevoked,
        authority.revokeCertification(cert_id, null, 3000000));
}

test "CA: revoke nonexistent certification fails" {
    const allocator = testing.allocator;
    var authority = CertificationAuthority.init(allocator, CaPolicy.default());
    defer authority.deinit();

    try authority.initializeWithKey(&(.{0x11} ** 20), .ed25519, "CA");

    try testing.expectError(CaError.CertificationNotFound,
        authority.revokeCertification(999, null, 1000000));
}

// =========================================================================
// Policy Enforcement Tests
// =========================================================================

test "CA: strict policy rejects weak RSA" {
    const allocator = testing.allocator;
    var authority = CertificationAuthority.init(allocator, CaPolicy.strict("example.com"));
    defer authority.deinit();

    try authority.initializeWithKey(&(.{0x22} ** 20), .ed25519, "Strict CA");

    // RSA-2048 should be rejected (minimum is 3072)
    const weak_params = makeTestKeyParams(.rsa_encrypt_sign, 2048, true);
    try testing.expectError(CaError.KeyTooSmall,
        authority.issueCertification(weak_params, "alice@example.com", null, null, 1000000));

    // RSA-4096 should pass
    const strong_params = makeTestKeyParams(.rsa_encrypt_sign, 4096, true);
    _ = try authority.issueCertification(strong_params, "alice@example.com", null, null, 1000000);
}

test "CA: strict policy rejects wrong domain" {
    const allocator = testing.allocator;
    var authority = CertificationAuthority.init(allocator, CaPolicy.strict("example.com"));
    defer authority.deinit();

    try authority.initializeWithKey(&(.{0x33} ** 20), .ed25519, "Domain CA");

    const params = makeTestKeyParams(.ed25519, 256, true);

    // Wrong domain
    try testing.expectError(CaError.InvalidUserIdDomain,
        authority.issueCertification(params, "Bob <bob@other.org>", null, null, 1000000));

    // Correct domain
    _ = try authority.issueCertification(params, "Alice <alice@example.com>", null, null, 1000000);
}

test "CA: strict policy requires expiration" {
    const allocator = testing.allocator;
    var authority = CertificationAuthority.init(allocator, CaPolicy.strict("test.com"));
    defer authority.deinit();

    try authority.initializeWithKey(&(.{0x44} ** 20), .ed25519, "Exp CA");

    // No expiration should be rejected
    const no_exp = makeTestKeyParams(.ed25519, 256, false);
    try testing.expectError(CaError.ExpirationPolicyViolation,
        authority.issueCertification(no_exp, "user@test.com", null, null, 1000000));

    // With expiration should pass
    const with_exp = makeTestKeyParams(.ed25519, 256, true);
    _ = try authority.issueCertification(with_exp, "user@test.com", null, null, 1000000);
}

test "CA: default policy allows DSA-free algorithm set" {
    const policy = CaPolicy.default();

    try testing.expect(policy.isAlgorithmAllowed(.rsa_encrypt_sign));
    try testing.expect(policy.isAlgorithmAllowed(.ed25519));
    try testing.expect(policy.isAlgorithmAllowed(.ecdsa));
    try testing.expect(policy.isAlgorithmAllowed(.x25519));
    try testing.expect(!policy.isAlgorithmAllowed(.dsa));
    try testing.expect(!policy.isAlgorithmAllowed(.elgamal));
}

// =========================================================================
// Key Vetting Tests
// =========================================================================

test "CA: vet good Ed25519 key" {
    const allocator = testing.allocator;
    var authority = CertificationAuthority.init(allocator, CaPolicy.default());
    defer authority.deinit();

    try authority.initializeWithKey(&(.{0x55} ** 20), .ed25519, "CA");

    const params = makeTestKeyParams(.ed25519, 256, false);
    var result = try authority.vetKey(params, "user@example.com");
    defer result.deinit(allocator);

    try testing.expect(result.approved);
    // Should have an info note about Ed25519
    try testing.expect(result.issues.items.len > 0);
}

test "CA: vet weak RSA key with strict policy" {
    const allocator = testing.allocator;
    var authority = CertificationAuthority.init(allocator, CaPolicy.strict("example.com"));
    defer authority.deinit();

    try authority.initializeWithKey(&(.{0x66} ** 20), .ed25519, "CA");

    const params = makeTestKeyParams(.rsa_encrypt_sign, 1024, true);
    var result = try authority.vetKey(params, "user@example.com");
    defer result.deinit(allocator);

    try testing.expect(!result.approved);
}

test "CA: vet key with wrong domain" {
    const allocator = testing.allocator;
    var authority = CertificationAuthority.init(allocator, CaPolicy.strict("example.com"));
    defer authority.deinit();

    try authority.initializeWithKey(&(.{0x77} ** 20), .ed25519, "CA");

    const params = makeTestKeyParams(.ed25519, 256, true);
    var result = try authority.vetKey(params, "user@other.com");
    defer result.deinit(allocator);

    try testing.expect(!result.approved);
}

test "CA: VettingResult format" {
    const allocator = testing.allocator;
    var result = VettingResult.init();
    defer result.deinit(allocator);

    try result.addIssue(allocator, .info, "Key uses Ed25519");
    try result.addIssue(allocator, .warning, "Key expires soon");

    const formatted = try result.format(allocator);
    defer allocator.free(formatted);

    try testing.expect(formatted.len > 0);
    try testing.expect(std.mem.indexOf(u8, formatted, "APPROVED") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "Ed25519") != null);
}

// =========================================================================
// Database Tests
// =========================================================================

test "CaDatabase: add and find records" {
    const allocator = testing.allocator;
    var db = CaDatabase.init();
    defer db.deinit(allocator);

    const uid = try allocator.dupe(u8, "test@example.com");
    const id = try db.addRecord(allocator, .{
        .id = 0,
        .key_fingerprint = std.mem.zeroes([32]u8),
        .fingerprint_len = 20,
        .user_id = uid,
        .cert_level = .positive,
        .trust_depth = TrustDepth.orgDefault(),
        .issued_at = 1000,
        .expires_at = 5000,
        .revoked = false,
        .revoked_at = 0,
        .revocation_reason = null,
    });

    const found = db.findById(id);
    try testing.expect(found != null);
    try testing.expectEqual(CertificationLevel.positive, found.?.cert_level);

    // Not found
    try testing.expect(db.findById(999) == null);
}

test "CaDatabase: list certified users" {
    const allocator = testing.allocator;
    var db = CaDatabase.init();
    defer db.deinit(allocator);

    const uid1 = try allocator.dupe(u8, "alice@example.com");
    _ = try db.addRecord(allocator, .{
        .id = 0,
        .key_fingerprint = std.mem.zeroes([32]u8),
        .fingerprint_len = 20,
        .user_id = uid1,
        .cert_level = .positive,
        .trust_depth = TrustDepth.orgDefault(),
        .issued_at = 1000,
        .expires_at = 5000,
        .revoked = false,
        .revoked_at = 0,
        .revocation_reason = null,
    });

    const uid2 = try allocator.dupe(u8, "bob@example.com");
    _ = try db.addRecord(allocator, .{
        .id = 0,
        .key_fingerprint = std.mem.zeroes([32]u8),
        .fingerprint_len = 20,
        .user_id = uid2,
        .cert_level = .casual,
        .trust_depth = TrustDepth.orgDefault(),
        .issued_at = 2000,
        .expires_at = 6000,
        .revoked = false,
        .revoked_at = 0,
        .revocation_reason = null,
    });

    const users = try db.listCertifiedUsers(allocator);
    defer {
        for (users) |u| allocator.free(u);
        allocator.free(users);
    }

    try testing.expectEqual(@as(usize, 2), users.len);
}

test "CaDatabase: export/import roundtrip preserves data" {
    const allocator = testing.allocator;
    var db = CaDatabase.init();
    defer db.deinit(allocator);

    // Add a few records
    for (0..5) |i| {
        const uid = try std.fmt.allocPrint(allocator, "user{d}@example.com", .{i});
        _ = try db.addRecord(allocator, .{
            .id = 0,
            .key_fingerprint = std.mem.zeroes([32]u8),
            .fingerprint_len = 20,
            .user_id = uid,
            .cert_level = .positive,
            .trust_depth = TrustDepth.orgDefault(),
            .issued_at = 1000 + i * 100,
            .expires_at = 5000 + i * 100,
            .revoked = false,
            .revoked_at = 0,
            .revocation_reason = null,
        });
    }

    // Revoke one
    try db.revoke(3, 2000, null);

    // Export
    const exported = try db.exportToBytes(allocator);
    defer allocator.free(exported);

    // Should start with header
    try testing.expect(std.mem.startsWith(u8, exported, "OPGPCA01"));

    // Import
    var db2 = try CaDatabase.importFromBytes(allocator, exported);
    defer db2.deinit(allocator);

    try testing.expectEqual(@as(usize, 5), db2.totalCount());
    try testing.expectEqual(@as(usize, 1), db2.revokedCount());
    try testing.expectEqual(@as(usize, 4), db2.activeCount(3000));
}

test "CaDatabase: import invalid data fails" {
    const allocator = testing.allocator;

    // Too short
    try testing.expectError(CaError.InvalidFormat, CaDatabase.importFromBytes(allocator, "short"));

    // Wrong header
    try testing.expectError(CaError.InvalidFormat,
        CaDatabase.importFromBytes(allocator, "NOTVALID0000"));
}

// =========================================================================
// CertificationRecord Tests
// =========================================================================

test "CertificationRecord: validity with expiration" {
    const record = CertificationRecord{
        .id = 1,
        .key_fingerprint = std.mem.zeroes([32]u8),
        .fingerprint_len = 20,
        .user_id = "",
        .cert_level = .positive,
        .trust_depth = TrustDepth.orgDefault(),
        .issued_at = 1000,
        .expires_at = 2000,
        .revoked = false,
        .revoked_at = 0,
        .revocation_reason = null,
    };

    try testing.expect(record.isValid(1500)); // Before expiry
    try testing.expect(!record.isValid(2000)); // At expiry
    try testing.expect(!record.isValid(3000)); // After expiry
    try testing.expect(!record.isExpired(1500));
    try testing.expect(record.isExpired(2500));
}

test "CertificationRecord: no expiration" {
    const record = CertificationRecord{
        .id = 1,
        .key_fingerprint = std.mem.zeroes([32]u8),
        .fingerprint_len = 20,
        .user_id = "",
        .cert_level = .positive,
        .trust_depth = TrustDepth.orgDefault(),
        .issued_at = 1000,
        .expires_at = 0, // No expiration
        .revoked = false,
        .revoked_at = 0,
        .revocation_reason = null,
    };

    try testing.expect(record.isValid(1000000));
    try testing.expect(!record.isExpired(1000000));
}
