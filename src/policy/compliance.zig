// SPDX-License-Identifier: MIT
//! Compliance checking for OpenPGP messages and keys.
//!
//! Verifies that keys and messages conform to a particular OpenPGP standard
//! (RFC 4880, RFC 9580, or GnuPG defaults). Produces a detailed report
//! listing any compliance issues found.
//!
//! This is useful for:
//!   - Migration planning (finding keys that need upgrading)
//!   - Policy enforcement (rejecting non-compliant messages)
//!   - Audit reporting (documenting algorithm usage)

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const Key = @import("../key/key.zig").Key;
const enums = @import("../types/enums.zig");
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const AeadAlgorithm = enums.AeadAlgorithm;
const algo_policy = @import("algorithm_policy.zig");
const AlgorithmPolicy = algo_policy.AlgorithmPolicy;
const PolicyLevel = algo_policy.PolicyLevel;

/// The compliance standard to check against.
pub const ComplianceStandard = enum {
    /// RFC 4880 (OpenPGP, original).
    openpgp_rfc4880,
    /// RFC 9580 (OpenPGP, revised).
    openpgp_rfc9580,
    /// GnuPG default settings.
    gnupg_default,
};

/// Severity level for compliance issues.
pub const Severity = enum {
    /// Hard failure: the key/message is non-compliant.
    error_level,
    /// The key/message works but uses deprecated algorithms.
    warning,
    /// Informational note (e.g., a recommendation).
    info,
};

/// A single compliance issue found during checking.
pub const ComplianceIssue = struct {
    severity: Severity,
    code: []const u8,
    description: []const u8,
};

/// The result of a compliance check.
pub const ComplianceReport = struct {
    /// Whether the key/message is fully compliant.
    compliant: bool,
    /// List of issues found.
    issues: std.ArrayList(ComplianceIssue),
    /// The allocator used (for deinit).
    allocator: Allocator,

    /// Initialize an empty report.
    pub fn init(allocator: Allocator) ComplianceReport {
        return .{
            .compliant = true,
            .issues = .empty,
            .allocator = allocator,
        };
    }

    /// Free all memory associated with this report.
    pub fn deinit(self: *ComplianceReport) void {
        self.issues.deinit(self.allocator);
    }

    /// Add an issue to the report.
    pub fn addIssue(self: *ComplianceReport, severity: Severity, code: []const u8, description: []const u8) !void {
        if (severity == .error_level) {
            self.compliant = false;
        }
        try self.issues.append(self.allocator, .{
            .severity = severity,
            .code = code,
            .description = description,
        });
    }

    /// Return the number of errors (not counting warnings or info).
    pub fn errorCount(self: *const ComplianceReport) usize {
        var count: usize = 0;
        for (self.issues.items) |issue| {
            if (issue.severity == .error_level) count += 1;
        }
        return count;
    }

    /// Return the number of warnings.
    pub fn warningCount(self: *const ComplianceReport) usize {
        var count: usize = 0;
        for (self.issues.items) |issue| {
            if (issue.severity == .warning) count += 1;
        }
        return count;
    }
};

/// Check a key's compliance with a given standard.
///
/// Examines the primary key algorithm, key size (if applicable),
/// user ID presence, and subkey algorithms.
///
/// Returns a ComplianceReport. Caller must call `deinit()` on it.
pub fn checkKeyCompliance(
    key: *const Key,
    standard: ComplianceStandard,
    allocator: Allocator,
) !ComplianceReport {
    var report = ComplianceReport.init(allocator);
    errdefer report.deinit();

    const policy = policyForStandard(standard);

    // Check primary key algorithm
    const pk_algo = key.primary_key.algorithm;
    if (!policy.isAcceptablePublicKey(pk_algo, null)) {
        try report.addIssue(
            .error_level,
            "KEY_ALGO",
            "Primary key algorithm is not accepted under the target standard",
        );
    } else {
        // Check for warnings on the algorithm
        const validation = policy.validateKey(pk_algo, null);
        for (validation.warnings) |warning| {
            try report.addIssue(.warning, "KEY_ALGO_WARN", warning);
        }
    }

    // Check key version
    if (standard == .openpgp_rfc9580) {
        if (key.primary_key.version < 6) {
            try report.addIssue(
                .info,
                "KEY_VERSION",
                "Key is V4; RFC 9580 defines V6 keys for enhanced security",
            );
        }
    }

    // Check user IDs
    if (key.user_ids.items.len == 0) {
        try report.addIssue(
            .warning,
            "NO_USER_ID",
            "Key has no User ID packets",
        );
    }

    // Check for self-signatures
    var has_self_sig = false;
    for (key.user_ids.items) |uid_binding| {
        if (uid_binding.self_signature != null) {
            has_self_sig = true;

            // Check hash algorithm in self-signature
            const sig = uid_binding.self_signature.?;
            if (!policy.isAcceptableHash(sig.hash_algo)) {
                try report.addIssue(
                    .error_level,
                    "SIG_HASH",
                    "Self-signature uses a hash algorithm not accepted under the target standard",
                );
            }
        }
    }

    if (!has_self_sig and key.user_ids.items.len > 0) {
        try report.addIssue(
            .warning,
            "NO_SELF_SIG",
            "No self-signature found on any User ID",
        );
    }

    // Check subkey algorithms
    for (key.subkeys.items) |sub| {
        const sub_algo = sub.key.algorithm;
        if (!policy.isAcceptablePublicKey(sub_algo, null)) {
            try report.addIssue(
                .error_level,
                "SUBKEY_ALGO",
                "Subkey algorithm is not accepted under the target standard",
            );
        }
    }

    return report;
}

/// Check message data for compliance with a given standard.
///
/// This performs a lightweight structural check by examining the packet
/// headers visible in the data without full decryption. It checks:
///   - Packet version numbers
///   - Algorithm identifiers in PKESK/SKESK packets
///   - SEIPD version (v1 vs v2)
///
/// For a full compliance check of decrypted content, the message should
/// be decrypted first and the inner packets checked separately.
///
/// Returns a ComplianceReport. Caller must call `deinit()` on it.
pub fn checkMessageCompliance(
    msg_data: []const u8,
    standard: ComplianceStandard,
    allocator: Allocator,
) !ComplianceReport {
    var report = ComplianceReport.init(allocator);
    errdefer report.deinit();

    if (msg_data.len == 0) {
        try report.addIssue(.error_level, "EMPTY", "Message data is empty");
        return report;
    }

    const policy = policyForStandard(standard);

    // Quick structural scan of packet headers.
    // We look at the first byte to determine if it's a valid OpenPGP packet.
    const first_byte = msg_data[0];

    // Check for new-format vs old-format packets
    if (first_byte & 0x80 == 0) {
        try report.addIssue(
            .error_level,
            "NOT_OPENPGP",
            "Data does not start with a valid OpenPGP packet header",
        );
        return report;
    }

    const is_new_format = (first_byte & 0x40) != 0;

    if (standard == .openpgp_rfc9580 and !is_new_format) {
        try report.addIssue(
            .info,
            "OLD_FORMAT",
            "Message uses old-format packet headers; RFC 9580 recommends new-format",
        );
    }

    // If we can identify a PKESK or SKESK packet, check its version
    if (is_new_format) {
        const tag = first_byte & 0x3F;
        switch (tag) {
            1 => {
                // PKESK packet - check version and algorithm
                if (msg_data.len >= 4) {
                    checkPkeskCompliance(msg_data, standard, policy, &report) catch {};
                }
            },
            3 => {
                // SKESK packet - check version and algorithm
                if (msg_data.len >= 4) {
                    checkSkeskCompliance(msg_data, standard, &report) catch {};
                }
            },
            18 => {
                // SEIPD packet - check version
                checkSeipdCompliance(msg_data, standard, &report) catch {};
            },
            else => {},
        }
    }

    return report;
}

/// Map a compliance standard to the corresponding algorithm policy.
fn policyForStandard(standard: ComplianceStandard) AlgorithmPolicy {
    return switch (standard) {
        .openpgp_rfc4880 => AlgorithmPolicy.init(.rfc4880),
        .openpgp_rfc9580 => AlgorithmPolicy.init(.rfc9580),
        .gnupg_default => AlgorithmPolicy.init(.rfc9580),
    };
}

/// Check PKESK packet compliance.
fn checkPkeskCompliance(
    data: []const u8,
    standard: ComplianceStandard,
    policy: AlgorithmPolicy,
    report: *ComplianceReport,
) !void {
    // Skip the packet header to find the version byte
    // New-format: tag(1) + length(1-5) + body
    if (data.len < 3) return;

    // Simple length decode (1-byte length)
    const body_start: usize = if (data[1] < 192) @as(usize, 2) else 3;
    if (body_start >= data.len) return;

    const version = data[body_start];
    if (standard == .openpgp_rfc9580 and version < 6) {
        try report.addIssue(
            .info,
            "PKESK_VERSION",
            "PKESK is version 3; RFC 9580 defines version 6",
        );
    }

    // Check algorithm if we can reach it (version 3: byte at offset +10)
    if (version == 3 and body_start + 10 < data.len) {
        const algo: PublicKeyAlgorithm = @enumFromInt(data[body_start + 10]);
        if (!policy.isAcceptablePublicKey(algo, null)) {
            try report.addIssue(
                .error_level,
                "PKESK_ALGO",
                "PKESK uses an unacceptable public key algorithm",
            );
        }
    }
}

/// Check SKESK packet compliance.
fn checkSkeskCompliance(
    data: []const u8,
    standard: ComplianceStandard,
    report: *ComplianceReport,
) !void {
    if (data.len < 3) return;

    const body_start: usize = if (data[1] < 192) @as(usize, 2) else 3;
    if (body_start >= data.len) return;

    const version = data[body_start];
    if (standard == .openpgp_rfc9580 and version < 6) {
        try report.addIssue(
            .info,
            "SKESK_VERSION",
            "SKESK is version 4; RFC 9580 defines version 6 with AEAD",
        );
    }
}

/// Check SEIPD packet compliance.
fn checkSeipdCompliance(
    data: []const u8,
    standard: ComplianceStandard,
    report: *ComplianceReport,
) !void {
    if (data.len < 3) return;

    const body_start: usize = if (data[1] < 192) @as(usize, 2) else 3;
    if (body_start >= data.len) return;

    const version = data[body_start];
    if (standard == .openpgp_rfc9580 and version < 2) {
        try report.addIssue(
            .warning,
            "SEIPD_VERSION",
            "Message uses SEIPD v1 (CFB+MDC); RFC 9580 recommends v2 (AEAD)",
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ComplianceReport init and deinit" {
    const allocator = std.testing.allocator;
    var report = ComplianceReport.init(allocator);
    defer report.deinit();
    try std.testing.expect(report.compliant);
    try std.testing.expectEqual(@as(usize, 0), report.issues.items.len);
}

test "ComplianceReport addIssue error sets non-compliant" {
    const allocator = std.testing.allocator;
    var report = ComplianceReport.init(allocator);
    defer report.deinit();

    try report.addIssue(.error_level, "TEST", "test error");
    try std.testing.expect(!report.compliant);
    try std.testing.expectEqual(@as(usize, 1), report.errorCount());
}

test "ComplianceReport addIssue warning keeps compliant" {
    const allocator = std.testing.allocator;
    var report = ComplianceReport.init(allocator);
    defer report.deinit();

    try report.addIssue(.warning, "TEST", "test warning");
    try std.testing.expect(report.compliant);
    try std.testing.expectEqual(@as(usize, 1), report.warningCount());
}

test "checkMessageCompliance empty" {
    const allocator = std.testing.allocator;
    var report = try checkMessageCompliance("", .openpgp_rfc4880, allocator);
    defer report.deinit();
    try std.testing.expect(!report.compliant);
}

test "checkMessageCompliance non-openpgp data" {
    const allocator = std.testing.allocator;
    var report = try checkMessageCompliance("Hello, World!", .openpgp_rfc4880, allocator);
    defer report.deinit();
    try std.testing.expect(!report.compliant);
}

test "checkMessageCompliance valid new-format header" {
    const allocator = std.testing.allocator;
    // 0xC0 | tag 18 (SEIPD) = 0xD2, followed by a length byte and version 2
    const data = [_]u8{ 0xD2, 0x05, 0x02, 0x09, 0x03, 0x00, 0x00 };
    var report = try checkMessageCompliance(&data, .openpgp_rfc9580, allocator);
    defer report.deinit();
    // Should not have hard errors (version 2 is good for rfc9580)
    try std.testing.expect(report.compliant);
}

test "policyForStandard" {
    const p4880 = policyForStandard(.openpgp_rfc4880);
    try std.testing.expect(p4880.isAcceptableHash(.md5));

    const p9580 = policyForStandard(.openpgp_rfc9580);
    try std.testing.expect(!p9580.isAcceptableHash(.md5));
}

test "checkKeyCompliance basic structure" {
    // We just test the report structure here since building a full Key
    // requires many packet components.
    const allocator = std.testing.allocator;
    const PublicKeyPacket = @import("../packets/public_key.zig").PublicKeyPacket;

    // Build a minimal RSA public key packet
    var body: [12]u8 = undefined;
    body[0] = 4; // version
    mem.writeInt(u32, body[1..5], 1000, .big);
    body[5] = 1; // RSA
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xFF;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;

    const pk = try PublicKeyPacket.parse(allocator, &body, false);
    var key = Key.init(pk);
    defer key.deinit(allocator);

    var report = try checkKeyCompliance(&key, .openpgp_rfc4880, allocator);
    defer report.deinit();

    // Should warn about no user IDs
    try std.testing.expect(report.warningCount() > 0);
}
