// SPDX-License-Identifier: MIT
//! Tests for key migration utilities.
//!
//! Exercises key version detection, preference analysis and upgrade,
//! migration planning and reporting, SSH format compatibility checks,
//! and risk estimation.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

const key_migrate = @import("migrate/key_migrate.zig");
const MigrationReport = key_migrate.MigrationReport;
const MigrationTarget = key_migrate.MigrationTarget;
const KeyFormat = key_migrate.KeyFormat;
const AlgorithmChange = key_migrate.AlgorithmChange;
const PreferenceAnalysis = key_migrate.PreferenceAnalysis;

const preferences_mod = @import("config/preferences.zig");
const Preferences = preferences_mod.Preferences;
const Features = preferences_mod.Features;

const enums = @import("types/enums.zig");
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const CompressionAlgorithm = enums.CompressionAlgorithm;
const AeadAlgorithm = enums.AeadAlgorithm;
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;

// =========================================================================
// KeyFormat
// =========================================================================

test "migrate: key format names" {
    try testing.expectEqualStrings("Binary (OpenPGP)", KeyFormat.binary.name());
    try testing.expectEqualStrings("Armored Public Key", KeyFormat.armored_public.name());
    try testing.expectEqualStrings("Armored Secret Key", KeyFormat.armored_secret.name());
    try testing.expectEqualStrings("SSH authorized_keys", KeyFormat.ssh_authorized_keys.name());
    try testing.expectEqualStrings("SSH Private Key", KeyFormat.ssh_private.name());
}

test "migrate: key format extensions" {
    try testing.expectEqualStrings(".gpg", KeyFormat.binary.extension());
    try testing.expectEqualStrings(".asc", KeyFormat.armored_public.extension());
    try testing.expectEqualStrings(".asc", KeyFormat.armored_secret.extension());
    try testing.expectEqualStrings(".pub", KeyFormat.ssh_authorized_keys.extension());
    try testing.expectEqualStrings("", KeyFormat.ssh_private.extension());
}

// =========================================================================
// MigrationTarget
// =========================================================================

test "migrate: migration target names" {
    try testing.expectEqualStrings("RFC 4880 (Legacy)", MigrationTarget.rfc4880.name());
    try testing.expectEqualStrings("RFC 9580 (Modern)", MigrationTarget.rfc9580.name());
    try testing.expectEqualStrings("Strict Security", MigrationTarget.strict.name());
}

// =========================================================================
// MigrationReport
// =========================================================================

test "migrate: report — empty" {
    const allocator = testing.allocator;
    var report = MigrationReport.init(allocator, 4, 6);
    defer report.deinit();

    try testing.expect(report.success);
    try testing.expect(report.changeCount() == 0);
    try testing.expect(!report.hasWarnings());
    try testing.expect(report.original_version == 4);
    try testing.expect(report.target_version == 6);
}

test "migrate: report — with changes" {
    const allocator = testing.allocator;
    var report = MigrationReport.init(allocator, 4, 6);
    defer report.deinit();

    try report.addChange(.{
        .component = "symmetric preference",
        .from = "CAST5",
        .to = "AES-256",
        .reason = "CAST5 deprecated",
    });
    try report.addChange(.{
        .component = "hash preference",
        .from = "MD5",
        .to = "SHA-256",
        .reason = "MD5 insecure",
    });

    try testing.expect(report.changeCount() == 2);
}

test "migrate: report — with warnings" {
    const allocator = testing.allocator;
    var report = MigrationReport.init(allocator, 4, 6);
    defer report.deinit();

    try report.addWarning("Key uses legacy V4 format");
    try report.addWarning("Some recipients may not support V6");

    try testing.expect(report.hasWarnings());
    try testing.expect(report.warnings.items.len == 2);
}

test "migrate: report — with info messages" {
    const allocator = testing.allocator;
    var report = MigrationReport.init(allocator, 4, 6);
    defer report.deinit();

    try report.addInfo("AEAD support enabled");
    try report.addInfo("Feature flags updated");

    try testing.expect(report.info_messages.items.len == 2);
}

test "migrate: report — failed" {
    const allocator = testing.allocator;
    var report = MigrationReport.init(allocator, 4, 6);
    defer report.deinit();

    report.fail();
    try testing.expect(!report.success);
}

test "migrate: report — format" {
    const allocator = testing.allocator;
    var report = MigrationReport.init(allocator, 4, 6);
    defer report.deinit();

    try report.addChange(.{
        .component = "cipher",
        .from = "3DES",
        .to = "AES-256",
        .reason = "deprecated",
    });
    try report.addWarning("Test warning");
    try report.addInfo("Test info");

    const formatted = try report.format(allocator);
    defer allocator.free(formatted);

    try testing.expect(mem.indexOf(u8, formatted, "Migration Report") != null);
    try testing.expect(mem.indexOf(u8, formatted, "V4 -> V6") != null);
    try testing.expect(mem.indexOf(u8, formatted, "SUCCESS") != null);
    try testing.expect(mem.indexOf(u8, formatted, "3DES") != null);
    try testing.expect(mem.indexOf(u8, formatted, "AES-256") != null);
    try testing.expect(mem.indexOf(u8, formatted, "Test warning") != null);
    try testing.expect(mem.indexOf(u8, formatted, "Test info") != null);
}

test "migrate: report — format summary" {
    const allocator = testing.allocator;
    var report = MigrationReport.init(allocator, 4, 6);
    defer report.deinit();

    try report.addChange(.{ .component = "a", .from = "b", .to = "c", .reason = "d" });
    try report.addWarning("w");

    const summary = try report.formatSummary(allocator);
    defer allocator.free(summary);

    try testing.expect(mem.indexOf(u8, summary, "V4->V6") != null);
    try testing.expect(mem.indexOf(u8, summary, "1 changes") != null);
    try testing.expect(mem.indexOf(u8, summary, "1 warnings") != null);
    try testing.expect(mem.indexOf(u8, summary, "OK") != null);
}

test "migrate: report — format failed summary" {
    const allocator = testing.allocator;
    var report = MigrationReport.init(allocator, 4, 6);
    defer report.deinit();
    report.fail();

    const summary = try report.formatSummary(allocator);
    defer allocator.free(summary);

    try testing.expect(mem.indexOf(u8, summary, "FAILED") != null);
}

// =========================================================================
// Preference analysis
// =========================================================================

test "migrate: analyze V4 defaults for rfc9580" {
    const allocator = testing.allocator;
    const prefs = Preferences.default();

    var analysis = try key_migrate.analyzePreferences(allocator, prefs, .rfc9580);
    defer analysis.deinit();

    try testing.expect(analysis.needsChanges());
    // V4 defaults include CAST5 and 3DES
    try testing.expect(analysis.deprecated_symmetric.items.len >= 1);
    try testing.expect(analysis.needs_aead);
    try testing.expect(analysis.needs_feature_update);
}

test "migrate: analyze V6 defaults for rfc9580 — no changes needed" {
    const allocator = testing.allocator;
    const prefs = Preferences.defaultV6();

    var analysis = try key_migrate.analyzePreferences(allocator, prefs, .rfc9580);
    defer analysis.deinit();

    // V6 defaults should already be RFC 9580 compliant
    try testing.expect(analysis.deprecated_symmetric.items.len == 0);
    try testing.expect(analysis.deprecated_hash.items.len == 0);
    // AEAD is already present
    try testing.expect(!analysis.needs_aead);
}

test "migrate: analyze for strict — SHA-1 removed" {
    const allocator = testing.allocator;

    const sym = [_]SymmetricAlgorithm{.aes256};
    const hash = [_]HashAlgorithm{ .sha256, .sha1 };
    const comp = [_]CompressionAlgorithm{.zlib};
    const prefs = Preferences{
        .symmetric = @constCast(&sym),
        .hash = @constCast(&hash),
        .compression = @constCast(&comp),
        .aead = null,
        .features = Features.v4Default(),
    };

    var analysis = try key_migrate.analyzePreferences(allocator, prefs, .strict);
    defer analysis.deinit();

    // SHA-1 should be deprecated in strict mode
    try testing.expect(analysis.deprecated_hash.items.len == 1);
    try testing.expect(analysis.deprecated_hash.items[0] == .sha1);
}

test "migrate: analyze for rfc4880 — minimal changes" {
    const allocator = testing.allocator;

    const prefs = Preferences{
        .symmetric = &.{},
        .hash = &.{},
        .compression = &.{},
        .aead = null,
        .features = .{ .modification_detection = false },
    };

    var analysis = try key_migrate.analyzePreferences(allocator, prefs, .rfc4880);
    defer analysis.deinit();

    // Only MDC feature flag should need updating
    try testing.expect(analysis.needs_feature_update);
    try testing.expect(analysis.deprecated_symmetric.items.len == 0);
    try testing.expect(!analysis.needs_aead);
}

// =========================================================================
// Preference upgrade
// =========================================================================

test "migrate: upgrade to rfc9580" {
    const allocator = testing.allocator;
    const prefs = Preferences.default();

    const upgraded = try key_migrate.upgradePreferences(allocator, prefs, .rfc9580);

    // AES-256 should be present
    var has_aes256 = false;
    for (upgraded.symmetric) |algo| {
        if (algo == .aes256) has_aes256 = true;
    }
    try testing.expect(has_aes256);

    // CAST5 should be removed
    for (upgraded.symmetric) |algo| {
        try testing.expect(algo != .cast5);
    }

    // MD5 should be removed
    for (upgraded.hash) |algo| {
        try testing.expect(algo != .md5);
    }

    // AEAD should be present
    try testing.expect(upgraded.aead != null);
    try testing.expect(upgraded.features.aead);

    // Cleanup
    allocator.free(upgraded.symmetric);
    allocator.free(upgraded.hash);
    if (upgraded.aead) |a| allocator.free(a);
}

test "migrate: upgrade to strict" {
    const allocator = testing.allocator;
    const prefs = Preferences.default();

    const upgraded = try key_migrate.upgradePreferences(allocator, prefs, .strict);

    // Strict should have exactly AES-256 and AES-128
    try testing.expect(upgraded.symmetric.len == 2);
    try testing.expect(upgraded.symmetric[0] == .aes256);
    try testing.expect(upgraded.symmetric[1] == .aes128);

    // Strict should have SHA-512 and SHA-256
    try testing.expect(upgraded.hash.len == 2);
    try testing.expect(upgraded.hash[0] == .sha512);
    try testing.expect(upgraded.hash[1] == .sha256);

    // AEAD should be OCB and GCM
    try testing.expect(upgraded.aead.?.len == 2);
    try testing.expect(upgraded.aead.?[0] == .ocb);
    try testing.expect(upgraded.aead.?[1] == .gcm);

    allocator.free(upgraded.symmetric);
    allocator.free(upgraded.hash);
    allocator.free(upgraded.compression);
    if (upgraded.aead) |a| allocator.free(a);
}

test "migrate: upgrade to rfc4880 — MDC only" {
    const allocator = testing.allocator;
    const prefs = Preferences{
        .symmetric = @constCast(&[_]SymmetricAlgorithm{.cast5}),
        .hash = @constCast(&[_]HashAlgorithm{.sha1}),
        .compression = @constCast(&[_]CompressionAlgorithm{.zip}),
        .aead = null,
        .features = .{},
    };

    const upgraded = try key_migrate.upgradePreferences(allocator, prefs, .rfc4880);

    // Should keep CAST5 (rfc4880 allows it)
    try testing.expect(upgraded.symmetric.len == 1);
    try testing.expect(upgraded.symmetric[0] == .cast5);
    // MDC should be enabled
    try testing.expect(upgraded.features.modification_detection);
    // AEAD should still be null
    try testing.expect(upgraded.aead == null);
}

// =========================================================================
// Key version detection
// =========================================================================

test "migrate: detect V4 key version" {
    // New-format public key packet, version 4
    const data = [_]u8{ 0xC6, 10, 4, 0, 0, 0, 0, 1 };
    try testing.expect(key_migrate.detectKeyVersion(&data) == 4);
}

test "migrate: detect V6 key version" {
    // New-format public key packet, version 6
    const data = [_]u8{ 0xC6, 14, 6, 0, 0, 0, 0, 0, 0, 0, 0, 27 };
    try testing.expect(key_migrate.detectKeyVersion(&data) == 6);
}

test "migrate: detect version — old format packet" {
    // Old-format public key packet (tag 6, 1-byte length)
    // 10 011000 = 0x98 (old format, tag 6, 1-byte length)
    const data = [_]u8{ 0x98, 10, 4, 0, 0, 0, 0, 1 };
    try testing.expect(key_migrate.detectKeyVersion(&data) == 4);
}

test "migrate: detect version — too short" {
    const data = [_]u8{0xC6};
    try testing.expect(key_migrate.detectKeyVersion(&data) == 0);
}

test "migrate: detect version — not a packet" {
    const data = [_]u8{ 0x00, 0x00, 0x04 };
    try testing.expect(key_migrate.detectKeyVersion(&data) == 0);
}

test "migrate: detect key algorithm" {
    // New-format, tag 6, V4, creation time 0, algorithm RSA (1)
    const data = [_]u8{ 0xC6, 10, 4, 0, 0, 0, 0, 1 };
    const algo = key_migrate.detectKeyAlgorithm(&data);
    try testing.expect(algo != null);
    try testing.expect(algo.? == .rsa_encrypt_sign);
}

test "migrate: detect key algorithm — EdDSA" {
    const data = [_]u8{ 0xC6, 10, 4, 0, 0, 0, 0, 22 };
    const algo = key_migrate.detectKeyAlgorithm(&data);
    try testing.expect(algo != null);
    try testing.expect(algo.? == .eddsa);
}

// =========================================================================
// SSH compatibility
// =========================================================================

test "migrate: SSH compatible algorithms" {
    try testing.expect(key_migrate.isSshCompatible(.rsa_encrypt_sign));
    try testing.expect(key_migrate.isSshCompatible(.rsa_sign_only));
    try testing.expect(key_migrate.isSshCompatible(.ed25519));
    try testing.expect(key_migrate.isSshCompatible(.ecdsa));
    try testing.expect(key_migrate.isSshCompatible(.eddsa));
}

test "migrate: SSH incompatible algorithms" {
    try testing.expect(!key_migrate.isSshCompatible(.x25519));
    try testing.expect(!key_migrate.isSshCompatible(.x448));
    try testing.expect(!key_migrate.isSshCompatible(.elgamal));
    try testing.expect(!key_migrate.isSshCompatible(.dsa));
    try testing.expect(!key_migrate.isSshCompatible(.ed448));
}

test "migrate: SSH key type names" {
    try testing.expectEqualStrings("ssh-rsa", key_migrate.sshKeyTypeName(.rsa_encrypt_sign).?);
    try testing.expectEqualStrings("ssh-rsa", key_migrate.sshKeyTypeName(.rsa_sign_only).?);
    try testing.expectEqualStrings("ssh-ed25519", key_migrate.sshKeyTypeName(.ed25519).?);
    try testing.expectEqualStrings("ssh-ed25519", key_migrate.sshKeyTypeName(.eddsa).?);
    try testing.expectEqualStrings("ecdsa-sha2-nistp256", key_migrate.sshKeyTypeName(.ecdsa).?);
    try testing.expect(key_migrate.sshKeyTypeName(.x25519) == null);
    try testing.expect(key_migrate.sshKeyTypeName(.elgamal) == null);
}

test "migrate: SSH comment generation" {
    const allocator = testing.allocator;

    const comment1 = try key_migrate.generateSshComment(allocator, .ed25519, "DEADBEEF01234567");
    defer allocator.free(comment1);
    try testing.expectEqualStrings("openpgp:DEADBEEF01234567 (Ed25519)", comment1);

    const comment2 = try key_migrate.generateSshComment(allocator, .rsa_encrypt_sign, "ABCD");
    defer allocator.free(comment2);
    try testing.expectEqualStrings("openpgp:ABCD (RSA (Encrypt or Sign))", comment2);
}

// =========================================================================
// Migration planning
// =========================================================================

test "migrate: plan V4 RSA to rfc9580" {
    const allocator = testing.allocator;
    const steps = try key_migrate.planMigration(allocator, 4, .rfc9580, .rsa_encrypt_sign);
    defer allocator.free(steps);

    // Should have multiple steps
    try testing.expect(steps.len >= 4);

    // First step: preference update
    try testing.expect(steps[0].mandatory);
    try testing.expect(steps[0].requires_private_key);

    // Should include V6 generation step
    var has_v6_step = false;
    for (steps) |step| {
        if (mem.indexOf(u8, step.description, "V6") != null) {
            has_v6_step = true;
        }
    }
    try testing.expect(has_v6_step);
}

test "migrate: plan V4 DSA to strict" {
    const allocator = testing.allocator;
    const steps = try key_migrate.planMigration(allocator, 4, .strict, .dsa);
    defer allocator.free(steps);

    // Should include step about replacing DSA
    var has_algo_step = false;
    for (steps) |step| {
        if (mem.indexOf(u8, step.description, "modern algorithm") != null) {
            has_algo_step = true;
            try testing.expect(step.mandatory);
        }
    }
    try testing.expect(has_algo_step);
}

test "migrate: plan V4 Ed25519 to rfc9580" {
    const allocator = testing.allocator;
    const steps = try key_migrate.planMigration(allocator, 4, .rfc9580, .ed25519);
    defer allocator.free(steps);

    // Ed25519 is modern, so no algorithm upgrade step needed
    for (steps) |step| {
        try testing.expect(mem.indexOf(u8, step.description, "modern algorithm") == null);
    }
}

test "migrate: plan V4 RSA to rfc4880 — minimal steps" {
    const allocator = testing.allocator;
    const steps = try key_migrate.planMigration(allocator, 4, .rfc4880, .rsa_encrypt_sign);
    defer allocator.free(steps);

    // Should not include V6 generation step
    for (steps) |step| {
        try testing.expect(mem.indexOf(u8, step.description, "V6") == null);
    }

    // Should not include AEAD feature step
    for (steps) |step| {
        try testing.expect(mem.indexOf(u8, step.description, "AEAD") == null);
    }
}

// =========================================================================
// Risk estimation
// =========================================================================

test "migrate: risk estimation — low risk scenarios" {
    // V4 RSA to rfc4880 = minimal changes
    const risk1 = key_migrate.estimateMigrationRisk(4, .rfc4880, .rsa_encrypt_sign);
    try testing.expect(risk1 <= 3);

    // V6 Ed25519 to rfc9580 = already modern
    const risk2 = key_migrate.estimateMigrationRisk(6, .rfc9580, .ed25519);
    try testing.expect(risk2 <= 3);
}

test "migrate: risk estimation — moderate risk" {
    // V4 RSA to rfc9580
    const risk = key_migrate.estimateMigrationRisk(4, .rfc9580, .rsa_encrypt_sign);
    try testing.expect(risk >= 3 and risk <= 7);
}

test "migrate: risk estimation — high risk" {
    // V4 DSA to strict = must change algorithm + version
    const risk = key_migrate.estimateMigrationRisk(4, .strict, .dsa);
    try testing.expect(risk >= 7);

    // V4 ElGamal to strict
    const risk2 = key_migrate.estimateMigrationRisk(4, .strict, .elgamal);
    try testing.expect(risk2 >= 7);
}

test "migrate: risk estimation — legacy EdDSA" {
    // V4 legacy EdDSA to rfc9580
    const risk = key_migrate.estimateMigrationRisk(4, .rfc9580, .eddsa);
    try testing.expect(risk >= 4); // Version change + legacy algo
}

test "migrate: risk capped at 10" {
    // Worst case scenario
    const risk = key_migrate.estimateMigrationRisk(4, .strict, .dsa);
    try testing.expect(risk <= 10);
}

// =========================================================================
// PreferenceAnalysis
// =========================================================================

test "migrate: preference analysis — no changes needed" {
    const allocator = testing.allocator;
    var analysis = PreferenceAnalysis.init(allocator);
    defer analysis.deinit();

    try testing.expect(!analysis.needsChanges());
}

test "migrate: preference analysis — changes needed" {
    const allocator = testing.allocator;
    var analysis = PreferenceAnalysis.init(allocator);
    defer analysis.deinit();

    try analysis.deprecated_symmetric.append(allocator, .cast5);
    try testing.expect(analysis.needsChanges());
}
