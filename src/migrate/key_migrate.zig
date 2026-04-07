// SPDX-License-Identifier: MIT
//! Key migration utilities for upgrading OpenPGP keys between versions
//! and formats.
//!
//! Provides tools for:
//!   - Migrating V4 keys to V6 format (RFC 9580)
//!   - Upgrading algorithm preferences on existing keys
//!   - Converting between key formats (binary, armored, SSH)
//!   - Generating migration reports
//!
//! Key migration is a critical operation for organizations transitioning
//! from legacy OpenPGP implementations to RFC 9580-compliant systems.
//! The migration process preserves the key's identity while upgrading
//! its metadata and preferences.
//!
//! Note: Actual cryptographic key material migration (e.g., re-signing
//! with new algorithms) requires the private key and is beyond the scope
//! of format conversion. This module handles the structural/metadata
//! aspects of migration.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const enums = @import("../types/enums.zig");
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const CompressionAlgorithm = enums.CompressionAlgorithm;
const AeadAlgorithm = enums.AeadAlgorithm;
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;

const preferences = @import("../config/preferences.zig");
const Preferences = preferences.Preferences;
const Features = preferences.Features;

// ---------------------------------------------------------------------------
// Key format enum
// ---------------------------------------------------------------------------

/// Target format for key conversion.
pub const KeyFormat = enum {
    /// Raw binary OpenPGP packets.
    binary,
    /// ASCII-armored public key block.
    armored_public,
    /// ASCII-armored secret key block.
    armored_secret,
    /// SSH authorized_keys format (single line).
    ssh_authorized_keys,
    /// SSH private key format (PEM-like).
    ssh_private,

    /// Human-readable name.
    pub fn name(self: KeyFormat) []const u8 {
        return switch (self) {
            .binary => "Binary (OpenPGP)",
            .armored_public => "Armored Public Key",
            .armored_secret => "Armored Secret Key",
            .ssh_authorized_keys => "SSH authorized_keys",
            .ssh_private => "SSH Private Key",
        };
    }

    /// File extension for this format.
    pub fn extension(self: KeyFormat) []const u8 {
        return switch (self) {
            .binary => ".gpg",
            .armored_public => ".asc",
            .armored_secret => ".asc",
            .ssh_authorized_keys => ".pub",
            .ssh_private => "",
        };
    }
};

// ---------------------------------------------------------------------------
// Migration policy levels (maps to algorithm_policy.PolicyLevel)
// ---------------------------------------------------------------------------

/// Target security level for migration.
pub const MigrationTarget = enum {
    /// RFC 4880 compatibility (minimal changes).
    rfc4880,
    /// RFC 9580 compliance (modern algorithms).
    rfc9580,
    /// Maximum security (strictest algorithm choices).
    strict,

    pub fn name(self: MigrationTarget) []const u8 {
        return switch (self) {
            .rfc4880 => "RFC 4880 (Legacy)",
            .rfc9580 => "RFC 9580 (Modern)",
            .strict => "Strict Security",
        };
    }
};

// ---------------------------------------------------------------------------
// Algorithm change record
// ---------------------------------------------------------------------------

/// Records a single algorithm change made during migration.
pub const AlgorithmChange = struct {
    /// What was changed (e.g., "symmetric preference", "hash algorithm").
    component: []const u8,
    /// The original algorithm name.
    from: []const u8,
    /// The new algorithm name.
    to: []const u8,
    /// Reason for the change.
    reason: []const u8,
};

// ---------------------------------------------------------------------------
// Migration report
// ---------------------------------------------------------------------------

/// Detailed report of changes made during a key migration.
pub const MigrationReport = struct {
    /// Original key version (e.g., 4).
    original_version: u8,
    /// Target key version (e.g., 6).
    target_version: u8,
    /// Algorithm changes applied.
    algorithm_changes: std.ArrayList(AlgorithmChange),
    /// Warning messages.
    warnings: std.ArrayList([]const u8),
    /// Informational messages.
    info_messages: std.ArrayList([]const u8),
    /// Whether the migration was successful.
    success: bool,
    /// Allocator for cleanup.
    _allocator: Allocator,

    /// Create an empty migration report.
    pub fn init(allocator: Allocator, original_version: u8, target_version: u8) MigrationReport {
        return .{
            .original_version = original_version,
            .target_version = target_version,
            .algorithm_changes = .empty,
            .warnings = .empty,
            .info_messages = .empty,
            .success = true,
            ._allocator = allocator,
        };
    }

    /// Free all memory.
    pub fn deinit(self: *MigrationReport) void {
        self.algorithm_changes.deinit(self._allocator);
        self.warnings.deinit(self._allocator);
        self.info_messages.deinit(self._allocator);
    }

    /// Record an algorithm change.
    pub fn addChange(self: *MigrationReport, change: AlgorithmChange) !void {
        try self.algorithm_changes.append(self._allocator, change);
    }

    /// Record a warning.
    pub fn addWarning(self: *MigrationReport, msg: []const u8) !void {
        try self.warnings.append(self._allocator, msg);
    }

    /// Record an info message.
    pub fn addInfo(self: *MigrationReport, msg: []const u8) !void {
        try self.info_messages.append(self._allocator, msg);
    }

    /// Mark the migration as failed.
    pub fn fail(self: *MigrationReport) void {
        self.success = false;
    }

    /// Return the number of algorithm changes.
    pub fn changeCount(self: *const MigrationReport) usize {
        return self.algorithm_changes.items.len;
    }

    /// Check if any warnings were generated.
    pub fn hasWarnings(self: *const MigrationReport) bool {
        return self.warnings.items.len > 0;
    }

    /// Format the report as a human-readable string.
    pub fn format(self: *const MigrationReport, allocator: Allocator) ![]u8 {
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(allocator);

        try output.appendSlice(allocator, "=== Key Migration Report ===\n");

        // Version info
        var buf: [64]u8 = undefined;
        var str = std.fmt.bufPrint(&buf, "Version: V{d} -> V{d}\n", .{
            self.original_version,
            self.target_version,
        }) catch "Version: ? -> ?\n";
        try output.appendSlice(allocator, str);

        str = std.fmt.bufPrint(&buf, "Status: {s}\n", .{
            if (self.success) "SUCCESS" else "FAILED",
        }) catch "Status: ?\n";
        try output.appendSlice(allocator, str);

        // Algorithm changes
        if (self.algorithm_changes.items.len > 0) {
            try output.appendSlice(allocator, "\nAlgorithm Changes:\n");
            for (self.algorithm_changes.items) |change| {
                try output.appendSlice(allocator, "  - ");
                try output.appendSlice(allocator, change.component);
                try output.appendSlice(allocator, ": ");
                try output.appendSlice(allocator, change.from);
                try output.appendSlice(allocator, " -> ");
                try output.appendSlice(allocator, change.to);
                try output.appendSlice(allocator, " (");
                try output.appendSlice(allocator, change.reason);
                try output.appendSlice(allocator, ")\n");
            }
        }

        // Warnings
        if (self.warnings.items.len > 0) {
            try output.appendSlice(allocator, "\nWarnings:\n");
            for (self.warnings.items) |warning| {
                try output.appendSlice(allocator, "  ! ");
                try output.appendSlice(allocator, warning);
                try output.append(allocator, '\n');
            }
        }

        // Info messages
        if (self.info_messages.items.len > 0) {
            try output.appendSlice(allocator, "\nInfo:\n");
            for (self.info_messages.items) |info| {
                try output.appendSlice(allocator, "  * ");
                try output.appendSlice(allocator, info);
                try output.append(allocator, '\n');
            }
        }

        return output.toOwnedSlice(allocator);
    }

    /// Format a compact summary.
    pub fn formatSummary(self: *const MigrationReport, allocator: Allocator) ![]u8 {
        var buf: [256]u8 = undefined;
        const summary = std.fmt.bufPrint(&buf, "V{d}->V{d}: {d} changes, {d} warnings, {s}", .{
            self.original_version,
            self.target_version,
            self.algorithm_changes.items.len,
            self.warnings.items.len,
            if (self.success) "OK" else "FAILED",
        }) catch "Migration summary unavailable";
        return allocator.dupe(u8, summary);
    }
};

// ---------------------------------------------------------------------------
// Preference analysis
// ---------------------------------------------------------------------------

/// Analyze existing preferences and determine what needs to change.
pub const PreferenceAnalysis = struct {
    /// Symmetric algorithms that should be removed (deprecated/insecure).
    deprecated_symmetric: std.ArrayList(SymmetricAlgorithm),
    /// Hash algorithms that should be removed.
    deprecated_hash: std.ArrayList(HashAlgorithm),
    /// Symmetric algorithms that should be added.
    missing_symmetric: std.ArrayList(SymmetricAlgorithm),
    /// Hash algorithms that should be added.
    missing_hash: std.ArrayList(HashAlgorithm),
    /// Whether AEAD support should be enabled.
    needs_aead: bool,
    /// Whether features flags need updating.
    needs_feature_update: bool,
    /// Allocator.
    _allocator: Allocator,

    pub fn init(allocator: Allocator) PreferenceAnalysis {
        return .{
            .deprecated_symmetric = .empty,
            .deprecated_hash = .empty,
            .missing_symmetric = .empty,
            .missing_hash = .empty,
            .needs_aead = false,
            .needs_feature_update = false,
            ._allocator = allocator,
        };
    }

    pub fn deinit(self: *PreferenceAnalysis) void {
        self.deprecated_symmetric.deinit(self._allocator);
        self.deprecated_hash.deinit(self._allocator);
        self.missing_symmetric.deinit(self._allocator);
        self.missing_hash.deinit(self._allocator);
    }

    /// Whether any changes are needed.
    pub fn needsChanges(self: *const PreferenceAnalysis) bool {
        return self.deprecated_symmetric.items.len > 0 or
            self.deprecated_hash.items.len > 0 or
            self.missing_symmetric.items.len > 0 or
            self.missing_hash.items.len > 0 or
            self.needs_aead or
            self.needs_feature_update;
    }
};

/// Analyze preferences against a target migration level.
pub fn analyzePreferences(
    allocator: Allocator,
    current: Preferences,
    target: MigrationTarget,
) !PreferenceAnalysis {
    var analysis = PreferenceAnalysis.init(allocator);
    errdefer analysis.deinit();

    switch (target) {
        .rfc9580, .strict => {
            // Check for deprecated symmetric algorithms
            for (current.symmetric) |algo| {
                switch (algo) {
                    .idea, .triple_des, .cast5, .blowfish => {
                        try analysis.deprecated_symmetric.append(allocator, algo);
                    },
                    else => {},
                }
            }

            // Check for deprecated hash algorithms
            for (current.hash) |algo| {
                switch (algo) {
                    .md5 => try analysis.deprecated_hash.append(allocator, algo),
                    .sha1 => {
                        if (target == .strict) {
                            try analysis.deprecated_hash.append(allocator, algo);
                        }
                    },
                    .ripemd160 => try analysis.deprecated_hash.append(allocator, algo),
                    else => {},
                }
            }

            // Check if AES-256 is missing from preferences
            var has_aes256 = false;
            for (current.symmetric) |algo| {
                if (algo == .aes256) has_aes256 = true;
            }
            if (!has_aes256) {
                try analysis.missing_symmetric.append(allocator, .aes256);
            }

            // Check if SHA-256 is missing
            var has_sha256 = false;
            for (current.hash) |algo| {
                if (algo == .sha256) has_sha256 = true;
            }
            if (!has_sha256) {
                try analysis.missing_hash.append(allocator, .sha256);
            }

            // Check AEAD support
            if (current.aead == null) {
                analysis.needs_aead = true;
            }

            // Check features
            if (!current.features.aead and target != .rfc4880) {
                analysis.needs_feature_update = true;
            }
        },
        .rfc4880 => {
            // Minimal changes for RFC 4880 compatibility
            // Just ensure MDC support is indicated
            if (!current.features.modification_detection) {
                analysis.needs_feature_update = true;
            }
        },
    }

    return analysis;
}

// ---------------------------------------------------------------------------
// Preference upgrade
// ---------------------------------------------------------------------------

/// Generate upgraded preferences based on the target migration level.
pub fn upgradePreferences(
    allocator: Allocator,
    current: Preferences,
    target: MigrationTarget,
) !Preferences {
    return switch (target) {
        .rfc4880 => upgradeToRfc4880(allocator, current),
        .rfc9580 => upgradeToRfc9580(allocator, current),
        .strict => upgradeToStrict(allocator, current),
    };
}

fn upgradeToRfc4880(allocator: Allocator, current: Preferences) !Preferences {
    _ = allocator;
    // Minimal upgrade: just ensure MDC is enabled
    var result = current;
    result.features.modification_detection = true;
    return result;
}

fn upgradeToRfc9580(allocator: Allocator, current: Preferences) !Preferences {
    // Remove deprecated algorithms, add modern ones, enable AEAD
    var sym_list: std.ArrayList(SymmetricAlgorithm) = .empty;
    errdefer sym_list.deinit(allocator);

    // Add AES-256 first if not present
    var has_aes256 = false;
    for (current.symmetric) |algo| {
        if (algo == .aes256) has_aes256 = true;
    }
    if (!has_aes256) {
        try sym_list.append(allocator, .aes256);
    }

    // Keep non-deprecated algorithms
    for (current.symmetric) |algo| {
        switch (algo) {
            .idea, .triple_des, .cast5, .blowfish => continue,
            else => try sym_list.append(allocator, algo),
        }
    }

    // Ensure AES-128 is present
    var has_aes128 = false;
    for (sym_list.items) |algo| {
        if (algo == .aes128) has_aes128 = true;
    }
    if (!has_aes128) {
        try sym_list.append(allocator, .aes128);
    }

    // Hash preferences
    var hash_list: std.ArrayList(HashAlgorithm) = .empty;
    errdefer hash_list.deinit(allocator);

    var has_sha256 = false;
    for (current.hash) |algo| {
        if (algo == .sha256) has_sha256 = true;
    }
    if (!has_sha256) {
        try hash_list.append(allocator, .sha256);
    }

    for (current.hash) |algo| {
        switch (algo) {
            .md5, .ripemd160 => continue,
            else => try hash_list.append(allocator, algo),
        }
    }

    // Ensure SHA-512 is present
    var has_sha512 = false;
    for (hash_list.items) |algo| {
        if (algo == .sha512) has_sha512 = true;
    }
    if (!has_sha512) {
        try hash_list.append(allocator, .sha512);
    }

    // AEAD preferences
    var aead_list = try allocator.alloc(AeadAlgorithm, 3);
    aead_list[0] = .ocb;
    aead_list[1] = .gcm;
    aead_list[2] = .eax;

    return .{
        .symmetric = try sym_list.toOwnedSlice(allocator),
        .hash = try hash_list.toOwnedSlice(allocator),
        .compression = current.compression,
        .aead = aead_list,
        .features = Features.v6Default(),
    };
}

fn upgradeToStrict(allocator: Allocator, current: Preferences) !Preferences {
    _ = current;
    // Strict: only the strongest algorithms
    var sym_list = try allocator.alloc(SymmetricAlgorithm, 2);
    sym_list[0] = .aes256;
    sym_list[1] = .aes128;

    var hash_list = try allocator.alloc(HashAlgorithm, 2);
    hash_list[0] = .sha512;
    hash_list[1] = .sha256;

    var comp_list = try allocator.alloc(CompressionAlgorithm, 2);
    comp_list[0] = .zlib;
    comp_list[1] = .uncompressed;

    var aead_list = try allocator.alloc(AeadAlgorithm, 2);
    aead_list[0] = .ocb;
    aead_list[1] = .gcm;

    return .{
        .symmetric = sym_list,
        .hash = hash_list,
        .compression = comp_list,
        .aead = aead_list,
        .features = Features.v6Default(),
    };
}

// ---------------------------------------------------------------------------
// Version detection and analysis
// ---------------------------------------------------------------------------

/// Detect the key version from raw packet data.
///
/// Examines the first few bytes to determine the OpenPGP key version.
/// Returns 0 if the version cannot be determined.
pub fn detectKeyVersion(data: []const u8) u8 {
    if (data.len < 3) return 0;

    // Check for packet tag
    const tag_byte = data[0];
    if (tag_byte & 0x80 == 0) return 0; // Not an OpenPGP packet

    // Determine packet tag and find body
    var body_offset: usize = 0;
    if (tag_byte & 0x40 != 0) {
        // New format packet
        const tag = (tag_byte & 0x3F);
        if (tag != 6 and tag != 5 and tag != 14) return 0; // Not a key packet
        // Skip length bytes
        if (data.len < 2) return 0;
        const first_len = data[1];
        if (first_len < 192) {
            body_offset = 2;
        } else if (first_len < 224) {
            body_offset = 3;
        } else if (first_len == 255) {
            body_offset = 6;
        } else {
            return 0;
        }
    } else {
        // Old format packet
        const tag = (tag_byte & 0x3C) >> 2;
        if (tag != 6 and tag != 5 and tag != 14) return 0;
        const len_type = tag_byte & 0x03;
        body_offset = switch (len_type) {
            0 => 2,
            1 => 3,
            2 => 5,
            else => return 0,
        };
    }

    if (body_offset >= data.len) return 0;
    return data[body_offset]; // Version byte
}

/// Determine the primary key algorithm from raw packet data.
pub fn detectKeyAlgorithm(data: []const u8) ?PublicKeyAlgorithm {
    const version = detectKeyVersion(data);
    if (version == 0) return null;

    // Find algorithm byte position based on version
    var body_offset: usize = 0;
    const tag_byte = data[0];
    if (tag_byte & 0x40 != 0) {
        const first_len = data[1];
        if (first_len < 192) {
            body_offset = 2;
        } else if (first_len < 224) {
            body_offset = 3;
        } else if (first_len == 255) {
            body_offset = 6;
        } else {
            return null;
        }
    } else {
        const len_type = tag_byte & 0x03;
        body_offset = switch (len_type) {
            0 => 2,
            1 => 3,
            2 => 5,
            else => return null,
        };
    }

    // V4: version(1) + creation_time(4) + algorithm(1)
    // V6: version(1) + creation_time(4) + key_material_length(4) + algorithm(1)
    const algo_offset = body_offset + switch (version) {
        4 => @as(usize, 5),
        6 => @as(usize, 9),
        else => return null,
    };

    if (algo_offset >= data.len) return null;
    return @enumFromInt(data[algo_offset]);
}

// ---------------------------------------------------------------------------
// SSH format conversion helpers
// ---------------------------------------------------------------------------

/// Generate an SSH public key comment from key metadata.
pub fn generateSshComment(
    allocator: Allocator,
    algo: PublicKeyAlgorithm,
    key_id_hex: []const u8,
) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    try output.appendSlice(allocator, "openpgp:");
    try output.appendSlice(allocator, key_id_hex);
    try output.appendSlice(allocator, " (");
    try output.appendSlice(allocator, algo.name());
    try output.append(allocator, ')');

    return output.toOwnedSlice(allocator);
}

/// Check if a public key algorithm can be exported to SSH format.
pub fn isSshCompatible(algo: PublicKeyAlgorithm) bool {
    return switch (algo) {
        .rsa_encrypt_sign, .rsa_sign_only => true,
        .ed25519 => true,
        .ecdsa => true,
        .eddsa => true, // Legacy EdDSA (Ed25519 via ECDSA OID)
        else => false,
    };
}

/// Get the SSH key type string for an algorithm.
pub fn sshKeyTypeName(algo: PublicKeyAlgorithm) ?[]const u8 {
    return switch (algo) {
        .rsa_encrypt_sign, .rsa_sign_only => "ssh-rsa",
        .ed25519, .eddsa => "ssh-ed25519",
        .ecdsa => "ecdsa-sha2-nistp256",
        else => null,
    };
}

// ---------------------------------------------------------------------------
// Migration planning
// ---------------------------------------------------------------------------

/// A planned migration step.
pub const MigrationStep = struct {
    /// Description of the step.
    description: []const u8,
    /// Whether this step requires the private key.
    requires_private_key: bool,
    /// Whether this step is mandatory for the target level.
    mandatory: bool,
    /// Risk level (0-10, where 0 is no risk).
    risk_level: u8,
};

/// Generate a migration plan for upgrading a key.
pub fn planMigration(
    allocator: Allocator,
    current_version: u8,
    target: MigrationTarget,
    current_algo: PublicKeyAlgorithm,
) ![]MigrationStep {
    var steps: std.ArrayList(MigrationStep) = .empty;
    errdefer steps.deinit(allocator);

    // Step 1: Preference upgrade (always)
    try steps.append(allocator, .{
        .description = "Update algorithm preferences in self-signature",
        .requires_private_key = true,
        .mandatory = true,
        .risk_level = 2,
    });

    // Step 2: Feature flags
    if (target != .rfc4880) {
        try steps.append(allocator, .{
            .description = "Enable AEAD feature flag",
            .requires_private_key = true,
            .mandatory = true,
            .risk_level = 1,
        });
    }

    // Step 3: Version upgrade
    if (current_version < 6 and target != .rfc4880) {
        try steps.append(allocator, .{
            .description = "Generate new V6 key (V4 keys cannot be directly converted)",
            .requires_private_key = false,
            .mandatory = false,
            .risk_level = 5,
        });
    }

    // Step 4: Algorithm upgrade
    switch (current_algo) {
        .dsa, .elgamal => {
            try steps.append(allocator, .{
                .description = "Generate new key with modern algorithm (DSA/ElGamal deprecated)",
                .requires_private_key = false,
                .mandatory = target == .strict,
                .risk_level = 7,
            });
        },
        .rsa_encrypt_sign, .rsa_sign_only => {
            if (target == .rfc9580 or target == .strict) {
                try steps.append(allocator, .{
                    .description = "Consider migrating to Ed25519/X25519 for better performance",
                    .requires_private_key = false,
                    .mandatory = false,
                    .risk_level = 6,
                });
            }
        },
        else => {},
    }

    // Step 5: Re-sign user IDs
    try steps.append(allocator, .{
        .description = "Re-sign user IDs with updated preferences",
        .requires_private_key = true,
        .mandatory = true,
        .risk_level = 3,
    });

    // Step 6: Distribute updated key
    try steps.append(allocator, .{
        .description = "Upload updated key to keyservers",
        .requires_private_key = false,
        .mandatory = false,
        .risk_level = 1,
    });

    return steps.toOwnedSlice(allocator);
}

/// Estimate the risk level of a migration (0-10).
pub fn estimateMigrationRisk(
    current_version: u8,
    target: MigrationTarget,
    current_algo: PublicKeyAlgorithm,
) u8 {
    var risk: u8 = 0;

    // Version change risk
    if (current_version < 6 and target != .rfc4880) {
        risk += 3; // V4->V6 is significant
    }

    // Algorithm change risk
    switch (current_algo) {
        .dsa, .elgamal => risk += 4, // Must change algorithm
        .eddsa => risk += 2, // Legacy EdDSA -> native Ed25519
        else => {},
    }

    // Target strictness
    switch (target) {
        .strict => risk += 2,
        .rfc9580 => risk += 1,
        .rfc4880 => {},
    }

    return @min(risk, 10);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "migrate: key format names" {
    try std.testing.expectEqualStrings("Binary (OpenPGP)", KeyFormat.binary.name());
    try std.testing.expectEqualStrings("Armored Public Key", KeyFormat.armored_public.name());
    try std.testing.expectEqualStrings(".gpg", KeyFormat.binary.extension());
    try std.testing.expectEqualStrings(".asc", KeyFormat.armored_public.extension());
}

test "migrate: migration target names" {
    try std.testing.expectEqualStrings("RFC 4880 (Legacy)", MigrationTarget.rfc4880.name());
    try std.testing.expectEqualStrings("RFC 9580 (Modern)", MigrationTarget.rfc9580.name());
    try std.testing.expectEqualStrings("Strict Security", MigrationTarget.strict.name());
}

test "migrate: migration report" {
    const allocator = std.testing.allocator;
    var report = MigrationReport.init(allocator, 4, 6);
    defer report.deinit();

    try report.addChange(.{
        .component = "symmetric preference",
        .from = "CAST5",
        .to = "AES-256",
        .reason = "CAST5 deprecated in RFC 9580",
    });
    try report.addWarning("Key uses legacy V4 format");
    try report.addInfo("AEAD support enabled");

    try std.testing.expect(report.changeCount() == 1);
    try std.testing.expect(report.hasWarnings());
    try std.testing.expect(report.success);

    const formatted = try report.format(allocator);
    defer allocator.free(formatted);
    try std.testing.expect(mem.indexOf(u8, formatted, "V4 -> V6") != null);
    try std.testing.expect(mem.indexOf(u8, formatted, "CAST5") != null);
    try std.testing.expect(mem.indexOf(u8, formatted, "AES-256") != null);
}

test "migrate: migration report summary" {
    const allocator = std.testing.allocator;
    var report = MigrationReport.init(allocator, 4, 6);
    defer report.deinit();

    try report.addChange(.{
        .component = "hash",
        .from = "MD5",
        .to = "SHA-256",
        .reason = "MD5 insecure",
    });

    const summary = try report.formatSummary(allocator);
    defer allocator.free(summary);
    try std.testing.expect(mem.indexOf(u8, summary, "V4->V6") != null);
    try std.testing.expect(mem.indexOf(u8, summary, "1 changes") != null);
}

test "migrate: analyze preferences for rfc9580" {
    const allocator = std.testing.allocator;

    // Create V4-style preferences with some deprecated algos
    const sym = [_]SymmetricAlgorithm{ .cast5, .aes128 };
    const hash = [_]HashAlgorithm{ .sha1, .md5 };
    const comp = [_]CompressionAlgorithm{.zlib};
    const prefs = Preferences{
        .symmetric = @constCast(&sym),
        .hash = @constCast(&hash),
        .compression = @constCast(&comp),
        .aead = null,
        .features = Features.v4Default(),
    };

    var analysis = try analyzePreferences(allocator, prefs, .rfc9580);
    defer analysis.deinit();

    try std.testing.expect(analysis.needsChanges());
    try std.testing.expect(analysis.deprecated_symmetric.items.len == 1); // CAST5
    try std.testing.expect(analysis.deprecated_hash.items.len == 1); // MD5
    try std.testing.expect(analysis.missing_symmetric.items.len == 1); // AES-256
    try std.testing.expect(analysis.needs_aead);
    try std.testing.expect(analysis.needs_feature_update);
}

test "migrate: analyze preferences for strict" {
    const allocator = std.testing.allocator;

    const sym = [_]SymmetricAlgorithm{ .aes256, .cast5, .triple_des };
    const hash = [_]HashAlgorithm{ .sha256, .sha1, .ripemd160 };
    const comp = [_]CompressionAlgorithm{.zlib};
    const prefs = Preferences{
        .symmetric = @constCast(&sym),
        .hash = @constCast(&hash),
        .compression = @constCast(&comp),
        .aead = null,
        .features = Features.v4Default(),
    };

    var analysis = try analyzePreferences(allocator, prefs, .strict);
    defer analysis.deinit();

    try std.testing.expect(analysis.needsChanges());
    try std.testing.expect(analysis.deprecated_symmetric.items.len == 2); // CAST5, 3DES
    try std.testing.expect(analysis.deprecated_hash.items.len == 2); // SHA-1, RIPEMD160
}

test "migrate: upgrade preferences to rfc9580" {
    const allocator = std.testing.allocator;

    const sym = [_]SymmetricAlgorithm{ .cast5, .aes128 };
    const hash = [_]HashAlgorithm{ .sha1, .md5 };
    const comp = [_]CompressionAlgorithm{.zlib};
    const prefs = Preferences{
        .symmetric = @constCast(&sym),
        .hash = @constCast(&hash),
        .compression = @constCast(&comp),
        .aead = null,
        .features = Features.v4Default(),
    };

    const upgraded = try upgradePreferences(allocator, prefs, .rfc9580);

    // AES-256 should be first, CAST5 removed
    try std.testing.expect(upgraded.symmetric.len >= 2);
    try std.testing.expect(upgraded.symmetric[0] == .aes256);
    // CAST5 should not be in the list
    for (upgraded.symmetric) |algo| {
        try std.testing.expect(algo != .cast5);
    }

    // MD5 should be removed
    for (upgraded.hash) |algo| {
        try std.testing.expect(algo != .md5);
    }

    // AEAD should be enabled
    try std.testing.expect(upgraded.aead != null);
    try std.testing.expect(upgraded.features.aead);

    // Cleanup
    allocator.free(upgraded.symmetric);
    allocator.free(upgraded.hash);
    if (upgraded.aead) |aead_list| allocator.free(aead_list);
}

test "migrate: upgrade preferences to strict" {
    const allocator = std.testing.allocator;

    const prefs = Preferences.default(); // V4 defaults

    const upgraded = try upgradePreferences(allocator, prefs, .strict);

    try std.testing.expect(upgraded.symmetric.len == 2);
    try std.testing.expect(upgraded.symmetric[0] == .aes256);
    try std.testing.expect(upgraded.symmetric[1] == .aes128);

    try std.testing.expect(upgraded.hash.len == 2);
    try std.testing.expect(upgraded.hash[0] == .sha512);
    try std.testing.expect(upgraded.hash[1] == .sha256);

    try std.testing.expect(upgraded.aead != null);

    allocator.free(upgraded.symmetric);
    allocator.free(upgraded.hash);
    allocator.free(upgraded.compression);
    if (upgraded.aead) |aead_list| allocator.free(aead_list);
}

test "migrate: detect key version from V4 packet" {
    // Simulate a V4 public key packet (old format, tag 6)
    // Tag byte: 0xC6 = 1100 0110 (new format, tag 6)
    // Length: 10
    // Version: 4
    const data = [_]u8{
        0xC6, // New format, tag 6 (public key)
        10, // Length
        4, // Version 4
        0x00, 0x00, 0x00, 0x00, // Creation time
        1, // Algorithm (RSA encrypt+sign)
    };
    try std.testing.expect(detectKeyVersion(&data) == 4);
}

test "migrate: detect key algorithm" {
    const data = [_]u8{
        0xC6, 10, 4, 0x00, 0x00, 0x00, 0x00,
        22, // EdDSA
    };
    const algo = detectKeyAlgorithm(&data);
    try std.testing.expect(algo != null);
    try std.testing.expect(algo.? == .eddsa);
}

test "migrate: SSH compatibility" {
    try std.testing.expect(isSshCompatible(.rsa_encrypt_sign));
    try std.testing.expect(isSshCompatible(.ed25519));
    try std.testing.expect(isSshCompatible(.ecdsa));
    try std.testing.expect(!isSshCompatible(.x25519));
    try std.testing.expect(!isSshCompatible(.elgamal));
}

test "migrate: SSH key type names" {
    try std.testing.expectEqualStrings("ssh-rsa", sshKeyTypeName(.rsa_encrypt_sign).?);
    try std.testing.expectEqualStrings("ssh-ed25519", sshKeyTypeName(.ed25519).?);
    try std.testing.expect(sshKeyTypeName(.x25519) == null);
}

test "migrate: SSH comment generation" {
    const allocator = std.testing.allocator;
    const comment = try generateSshComment(allocator, .ed25519, "DEADBEEF");
    defer allocator.free(comment);
    try std.testing.expectEqualStrings("openpgp:DEADBEEF (Ed25519)", comment);
}

test "migrate: plan migration V4 to rfc9580" {
    const allocator = std.testing.allocator;
    const steps = try planMigration(allocator, 4, .rfc9580, .rsa_encrypt_sign);
    defer allocator.free(steps);

    try std.testing.expect(steps.len >= 4);

    // First step should be preference update
    try std.testing.expect(steps[0].requires_private_key);
    try std.testing.expect(steps[0].mandatory);
}

test "migrate: plan migration DSA key" {
    const allocator = std.testing.allocator;
    const steps = try planMigration(allocator, 4, .strict, .dsa);
    defer allocator.free(steps);

    // Should include a step about replacing DSA
    var has_algo_change = false;
    for (steps) |step| {
        if (mem.indexOf(u8, step.description, "modern algorithm") != null) {
            has_algo_change = true;
            try std.testing.expect(step.mandatory);
        }
    }
    try std.testing.expect(has_algo_change);
}

test "migrate: estimate migration risk" {
    // V4 RSA to strict = moderate risk
    const risk1 = estimateMigrationRisk(4, .strict, .rsa_encrypt_sign);
    try std.testing.expect(risk1 >= 4 and risk1 <= 8);

    // V4 DSA to strict = high risk
    const risk2 = estimateMigrationRisk(4, .strict, .dsa);
    try std.testing.expect(risk2 >= 7);

    // V4 RSA to rfc4880 = low risk
    const risk3 = estimateMigrationRisk(4, .rfc4880, .rsa_encrypt_sign);
    try std.testing.expect(risk3 <= 3);
}

test "migrate: preference analysis for rfc4880 target" {
    const allocator = std.testing.allocator;

    // Preferences without MDC feature
    const prefs = Preferences{
        .symmetric = &.{},
        .hash = &.{},
        .compression = &.{},
        .aead = null,
        .features = .{ .modification_detection = false },
    };

    var analysis = try analyzePreferences(allocator, prefs, .rfc4880);
    defer analysis.deinit();

    try std.testing.expect(analysis.needs_feature_update);
    try std.testing.expect(analysis.deprecated_symmetric.items.len == 0);
}

test "migrate: failed migration report" {
    const allocator = std.testing.allocator;
    var report = MigrationReport.init(allocator, 4, 6);
    defer report.deinit();

    report.fail();
    try std.testing.expect(!report.success);

    const formatted = try report.format(allocator);
    defer allocator.free(formatted);
    try std.testing.expect(mem.indexOf(u8, formatted, "FAILED") != null);
}
