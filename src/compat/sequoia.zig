// SPDX-License-Identifier: MIT
//! Sequoia-PGP compatibility layer.
//!
//! Sequoia-PGP is a modern Rust implementation that is fully RFC 9580 native.
//! It has stricter requirements than GnuPG for key and message formats.
//!
//! This module provides:
//!   - Compatibility checking (will a key/message work with Sequoia?)
//!   - RFC 9580 compliance verification (Sequoia's native format)
//!   - Guidance on migrating keys to Sequoia-compatible formats
//!
//! Key differences between Sequoia-PGP and GnuPG:
//!   - Sequoia requires self-signatures on all user IDs
//!   - Sequoia prefers V6 keys with native Ed25519/X25519
//!   - Sequoia uses AEAD (OCB) by default for encryption
//!   - Sequoia rejects deprecated algorithms (MD5, SHA-1 for sigs)
//!   - Sequoia does not support the legacy S2K types (simple, salted)

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const enums = @import("../types/enums.zig");
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const AeadAlgorithm = enums.AeadAlgorithm;
const header_mod = @import("../packet/header.zig");
const PacketTag = @import("../packet/tags.zig").PacketTag;

// =========================================================================
// Compatibility report
// =========================================================================

/// Severity level for compatibility issues.
pub const IssueSeverity = enum {
    /// Informational note; may not cause problems.
    info,
    /// May cause interoperability issues.
    warning,
    /// Will cause failures with Sequoia-PGP.
    error_level,

    pub fn name(self: IssueSeverity) []const u8 {
        return switch (self) {
            .info => "INFO",
            .warning => "WARNING",
            .error_level => "ERROR",
        };
    }
};

/// A single compatibility issue found during checking.
pub const CompatIssue = struct {
    severity: IssueSeverity,
    description: []const u8,

    pub fn deinit(self: CompatIssue, allocator: Allocator) void {
        allocator.free(self.description);
    }
};

/// Result of checking compatibility with Sequoia-PGP.
pub const CompatReport = struct {
    /// Whether the data is fully compatible with Sequoia-PGP.
    compatible: bool,
    /// List of issues found.
    issues: std.ArrayList(CompatIssue),

    /// Free all memory associated with this report.
    pub fn deinit(self: *CompatReport, allocator: Allocator) void {
        for (self.issues.items) |issue| issue.deinit(allocator);
        self.issues.deinit(allocator);
    }

    /// Count issues of a specific severity.
    pub fn countBySeverity(self: *const CompatReport, severity: IssueSeverity) usize {
        var count: usize = 0;
        for (self.issues.items) |issue| {
            if (issue.severity == severity) count += 1;
        }
        return count;
    }

    /// Format the report as a human-readable string.
    pub fn format(self: *const CompatReport, allocator: Allocator) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);
        const w = buf.writer(allocator);

        try w.print("Sequoia-PGP Compatibility Report\n", .{});
        try w.writeAll("========================================\n");
        try w.print("Compatible: {s}\n\n", .{if (self.compatible) "yes" else "no"});

        if (self.issues.items.len == 0) {
            try w.writeAll("No issues found.\n");
        } else {
            try w.print("Issues ({d}):\n", .{self.issues.items.len});
            for (self.issues.items, 0..) |issue, i| {
                try w.print("  {d}. [{s}] {s}\n", .{ i + 1, issue.severity.name(), issue.description });
            }
        }

        return buf.toOwnedSlice(allocator);
    }
};

/// Check if a key (in raw packet form) is compatible with Sequoia-PGP.
///
/// Performs a structural analysis of the key data looking for patterns
/// that would cause issues with Sequoia-PGP.
pub fn checkSequoiaCompatibility(allocator: Allocator, key_data: []const u8) !CompatReport {
    var report = CompatReport{
        .compatible = true,
        .issues = .empty,
    };
    errdefer report.deinit(allocator);

    if (key_data.len == 0) {
        report.compatible = false;
        try report.issues.append(allocator, .{
            .severity = .error_level,
            .description = try allocator.dupe(u8, "Key data is empty"),
        });
        return report;
    }

    // Check if data starts with a valid OpenPGP packet.
    if (key_data[0] & 0x80 == 0) {
        report.compatible = false;
        try report.issues.append(allocator, .{
            .severity = .error_level,
            .description = try allocator.dupe(u8, "Data does not begin with a valid OpenPGP packet"),
        });
        return report;
    }

    const is_new_format = (key_data[0] & 0x40) != 0;

    // Sequoia strongly prefers new-format packets.
    if (!is_new_format) {
        try report.issues.append(allocator, .{
            .severity = .warning,
            .description = try allocator.dupe(u8, "Uses old-format packet headers; Sequoia prefers new-format"),
        });
    }

    // Check the key packet tag.
    const tag: u8 = if (is_new_format) (key_data[0] & 0x3F) else ((key_data[0] & 0x3C) >> 2);

    if (tag != @intFromEnum(PacketTag.public_key) and
        tag != @intFromEnum(PacketTag.secret_key))
    {
        report.compatible = false;
        try report.issues.append(allocator, .{
            .severity = .error_level,
            .description = try allocator.dupe(u8, "Data does not start with a key packet (expected tag 6 or 5)"),
        });
        return report;
    }

    // Try to find the version byte of the key packet.
    const body_offset = getBodyOffset(key_data, is_new_format);
    if (body_offset) |offset| {
        if (offset < key_data.len) {
            const version = key_data[offset];

            if (version < 4) {
                report.compatible = false;
                try report.issues.append(allocator, .{
                    .severity = .error_level,
                    .description = try allocator.dupe(u8, "V3 keys are not supported by Sequoia-PGP"),
                });
            } else if (version == 4) {
                try report.issues.append(allocator, .{
                    .severity = .info,
                    .description = try allocator.dupe(u8, "V4 key; Sequoia supports V4 but V6 is recommended"),
                });

                // Check the algorithm byte.
                if (offset + 5 < key_data.len) {
                    const algo: PublicKeyAlgorithm = @enumFromInt(key_data[offset + 5]);
                    try checkAlgorithmCompat(allocator, algo, &report);
                }
            } else if (version == 6) {
                try report.issues.append(allocator, .{
                    .severity = .info,
                    .description = try allocator.dupe(u8, "V6 key; fully compatible with Sequoia-PGP"),
                });
            }
        }
    }

    // Scan for deprecated packets and algorithms.
    try scanPacketsForCompat(allocator, key_data, &report);

    return report;
}

/// Check a specific algorithm for Sequoia compatibility.
fn checkAlgorithmCompat(allocator: Allocator, algo: PublicKeyAlgorithm, report: *CompatReport) !void {
    switch (algo) {
        .dsa => {
            try report.issues.append(allocator, .{
                .severity = .warning,
                .description = try allocator.dupe(u8, "DSA keys are deprecated; Sequoia supports but discourages them"),
            });
        },
        .elgamal => {
            try report.issues.append(allocator, .{
                .severity = .warning,
                .description = try allocator.dupe(u8, "ElGamal keys are deprecated; consider X25519 or ECDH"),
            });
        },
        .eddsa => {
            try report.issues.append(allocator, .{
                .severity = .info,
                .description = try allocator.dupe(u8, "Legacy EdDSA encoding; Sequoia prefers native Ed25519 (algo 27)"),
            });
        },
        .rsa_encrypt_sign, .rsa_encrypt_only, .rsa_sign_only => {
            try report.issues.append(allocator, .{
                .severity = .info,
                .description = try allocator.dupe(u8, "RSA key; Sequoia supports RSA but prefers Ed25519/X25519"),
            });
        },
        else => {},
    }
}

/// Scan through packet stream looking for compatibility issues.
fn scanPacketsForCompat(allocator: Allocator, data: []const u8, report: *CompatReport) !void {
    var offset: usize = 0;
    var found_uid = false;
    var found_sig = false;

    while (offset < data.len) {
        if (data[offset] & 0x80 == 0) break; // Not a packet

        const is_new = (data[offset] & 0x40) != 0;
        const tag_val: u8 = if (is_new) (data[offset] & 0x3F) else ((data[offset] & 0x3C) >> 2);

        // Track whether we find user IDs and signatures.
        if (tag_val == @intFromEnum(PacketTag.user_id)) found_uid = true;
        if (tag_val == @intFromEnum(PacketTag.signature)) found_sig = true;

        // Check for deprecated packet types.
        if (tag_val == @intFromEnum(PacketTag.symmetrically_encrypted_data)) {
            try report.issues.append(allocator, .{
                .severity = .error_level,
                .description = try allocator.dupe(u8, "Uses SED (tag 9) which Sequoia rejects; use SEIPD instead"),
            });
            report.compatible = false;
        }

        // Advance past this packet.
        const pkt_len = getPacketLength(data[offset..], is_new);
        if (pkt_len == 0) break;
        offset += pkt_len;
    }

    // Sequoia requires at least one user ID with a self-signature for keys.
    if (!found_uid and data.len > 20) {
        try report.issues.append(allocator, .{
            .severity = .warning,
            .description = try allocator.dupe(u8, "No User ID packet found; Sequoia requires at least one"),
        });
    }
}

/// Get the offset of the packet body (after header and length).
fn getBodyOffset(data: []const u8, is_new_format: bool) ?usize {
    if (data.len < 2) return null;

    if (is_new_format) {
        // New format: 1 byte tag + variable length
        const len_byte = data[1];
        if (len_byte < 192) return 2;
        if (len_byte < 224) return 3;
        if (len_byte == 255) return 6;
        return null;
    } else {
        // Old format: length type in bits 0-1 of tag byte
        const len_type = data[0] & 0x03;
        return switch (len_type) {
            0 => 2,
            1 => 3,
            2 => 5,
            3 => null, // indeterminate
            else => null,
        };
    }
}

/// Get the total length of a packet (header + body).
fn getPacketLength(data: []const u8, is_new_format: bool) usize {
    if (data.len < 2) return 0;

    if (is_new_format) {
        const len_byte = data[1];
        if (len_byte < 192) {
            const body_len = @as(usize, len_byte);
            return 2 + body_len;
        }
        if (len_byte < 224 and data.len >= 3) {
            const body_len = (@as(usize, len_byte - 192) << 8) + @as(usize, data[2]) + 192;
            return 3 + body_len;
        }
        if (len_byte == 255 and data.len >= 6) {
            const body_len = @as(usize, mem.readInt(u32, data[2..6], .big));
            return 6 + body_len;
        }
        return 0; // Cannot determine
    } else {
        const len_type = data[0] & 0x03;
        switch (len_type) {
            0 => {
                if (data.len < 2) return 0;
                return 2 + @as(usize, data[1]);
            },
            1 => {
                if (data.len < 3) return 0;
                return 3 + @as(usize, mem.readInt(u16, data[1..3], .big));
            },
            2 => {
                if (data.len < 5) return 0;
                return 5 + @as(usize, mem.readInt(u32, data[1..5], .big));
            },
            else => return 0,
        }
    }
}

// =========================================================================
// RFC 9580 compliance checking
// =========================================================================

/// Result of an RFC 9580 compliance check.
pub const Rfc9580Report = struct {
    /// Whether the data is fully RFC 9580 compliant.
    compliant: bool,
    /// Detected key/packet version.
    version: u8,
    /// Whether AEAD encryption is used.
    uses_aead: bool,
    /// Whether V6 keys are present.
    has_v6_keys: bool,
    /// List of deprecated algorithms found.
    deprecated_algorithms: std.ArrayList([]const u8),
    /// Detailed issues.
    issues: std.ArrayList(CompatIssue),

    /// Free all memory.
    pub fn deinit(self: *Rfc9580Report, allocator: Allocator) void {
        for (self.deprecated_algorithms.items) |da| allocator.free(da);
        self.deprecated_algorithms.deinit(allocator);
        for (self.issues.items) |issue| issue.deinit(allocator);
        self.issues.deinit(allocator);
    }

    /// Format the report as a human-readable string.
    pub fn format(self: *const Rfc9580Report, allocator: Allocator) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);
        const w = buf.writer(allocator);

        try w.print("RFC 9580 Compliance Report\n", .{});
        try w.writeAll("========================================\n");
        try w.print("Compliant:  {s}\n", .{if (self.compliant) "yes" else "no"});
        try w.print("Version:    {d}\n", .{self.version});
        try w.print("AEAD:       {s}\n", .{if (self.uses_aead) "yes" else "no"});
        try w.print("V6 Keys:    {s}\n", .{if (self.has_v6_keys) "yes" else "no"});

        if (self.deprecated_algorithms.items.len > 0) {
            try w.print("\nDeprecated Algorithms ({d}):\n", .{self.deprecated_algorithms.items.len});
            for (self.deprecated_algorithms.items, 0..) |algo, i| {
                try w.print("  {d}. {s}\n", .{ i + 1, algo });
            }
        }

        if (self.issues.items.len > 0) {
            try w.print("\nIssues ({d}):\n", .{self.issues.items.len});
            for (self.issues.items, 0..) |issue, i| {
                try w.print("  {d}. [{s}] {s}\n", .{ i + 1, issue.severity.name(), issue.description });
            }
        }

        return buf.toOwnedSlice(allocator);
    }
};

/// Check data for RFC 9580 compliance.
///
/// RFC 9580 defines:
///   - V6 key format with extended key material
///   - AEAD encryption (SEIPDv2)
///   - Native Ed25519/X25519/Ed448/X448 key types
///   - Deprecation of MD5, SHA-1 (for signatures), 3DES, CAST5
pub fn checkRfc9580Compliance(allocator: Allocator, data: []const u8) !Rfc9580Report {
    var report = Rfc9580Report{
        .compliant = true,
        .version = 0,
        .uses_aead = false,
        .has_v6_keys = false,
        .deprecated_algorithms = .empty,
        .issues = .empty,
    };
    errdefer report.deinit(allocator);

    if (data.len == 0) {
        report.compliant = false;
        try report.issues.append(allocator, .{
            .severity = .error_level,
            .description = try allocator.dupe(u8, "Data is empty"),
        });
        return report;
    }

    // Check packet format.
    if (data[0] & 0x80 == 0) {
        report.compliant = false;
        try report.issues.append(allocator, .{
            .severity = .error_level,
            .description = try allocator.dupe(u8, "Not valid OpenPGP data"),
        });
        return report;
    }

    const is_new_format = (data[0] & 0x40) != 0;

    // RFC 9580 requires new-format packets.
    if (!is_new_format) {
        report.compliant = false;
        try report.issues.append(allocator, .{
            .severity = .error_level,
            .description = try allocator.dupe(u8, "Old-format packets are not RFC 9580 compliant"),
        });
    }

    // Scan for key version and algorithms.
    var offset: usize = 0;
    while (offset < data.len) {
        if (data[offset] & 0x80 == 0) break;

        const pkt_new = (data[offset] & 0x40) != 0;
        const tag_val: u8 = if (pkt_new) (data[offset] & 0x3F) else ((data[offset] & 0x3C) >> 2);

        // Check key packets for version.
        if (tag_val == @intFromEnum(PacketTag.public_key) or
            tag_val == @intFromEnum(PacketTag.secret_key) or
            tag_val == @intFromEnum(PacketTag.public_subkey) or
            tag_val == @intFromEnum(PacketTag.secret_subkey))
        {
            const body_off = getBodyOffset(data[offset..], pkt_new);
            if (body_off) |bo| {
                const abs_offset = offset + bo;
                if (abs_offset < data.len) {
                    const version = data[abs_offset];
                    if (report.version == 0) report.version = version;

                    if (version == 6) {
                        report.has_v6_keys = true;
                    } else if (version < 6) {
                        try report.issues.append(allocator, .{
                            .severity = .warning,
                            .description = try std.fmt.allocPrint(
                                allocator,
                                "V{d} key found; RFC 9580 defines V6 keys",
                                .{version},
                            ),
                        });
                    }

                    // Check algorithm.
                    if (abs_offset + 5 < data.len) {
                        const algo: PublicKeyAlgorithm = @enumFromInt(data[abs_offset + 5]);
                        try checkRfc9580Algorithm(allocator, algo, &report);
                    }
                }
            }
        }

        // Check for SEIPD v2 (AEAD).
        if (tag_val == @intFromEnum(PacketTag.sym_encrypted_integrity_protected_data)) {
            const body_off = getBodyOffset(data[offset..], pkt_new);
            if (body_off) |bo| {
                const abs_offset = offset + bo;
                if (abs_offset < data.len) {
                    if (data[abs_offset] == 2) {
                        report.uses_aead = true;
                    }
                }
            }
        }

        // Check for SED (tag 9) — deprecated.
        if (tag_val == @intFromEnum(PacketTag.symmetrically_encrypted_data)) {
            report.compliant = false;
            try report.issues.append(allocator, .{
                .severity = .error_level,
                .description = try allocator.dupe(u8, "SED packets (tag 9) are forbidden by RFC 9580"),
            });
        }

        const pkt_len = getPacketLength(data[offset..], pkt_new);
        if (pkt_len == 0) break;
        offset += pkt_len;
    }

    return report;
}

/// Check a public key algorithm for RFC 9580 compliance.
fn checkRfc9580Algorithm(allocator: Allocator, algo: PublicKeyAlgorithm, report: *Rfc9580Report) !void {
    switch (algo) {
        .dsa => {
            try report.deprecated_algorithms.append(
                allocator,
                try allocator.dupe(u8, "DSA (deprecated by RFC 9580)"),
            );
        },
        .elgamal => {
            try report.deprecated_algorithms.append(
                allocator,
                try allocator.dupe(u8, "ElGamal (deprecated by RFC 9580)"),
            );
        },
        .eddsa => {
            try report.deprecated_algorithms.append(
                allocator,
                try allocator.dupe(u8, "Legacy EdDSA (use native Ed25519, algo 27)"),
            );
        },
        else => {},
    }
}

// =========================================================================
// Migration guidance
// =========================================================================

/// Guidance for migrating a key to be Sequoia-compatible.
pub const MigrationGuide = struct {
    steps: std.ArrayList([]const u8),

    pub fn deinit(self: *MigrationGuide, allocator: Allocator) void {
        for (self.steps.items) |step| allocator.free(step);
        self.steps.deinit(allocator);
    }

    pub fn format(self: *const MigrationGuide, allocator: Allocator) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);
        const w = buf.writer(allocator);

        try w.writeAll("Migration Guide for Sequoia-PGP Compatibility\n");
        try w.writeAll("==============================================\n\n");

        if (self.steps.items.len == 0) {
            try w.writeAll("No migration steps needed. Key is already compatible.\n");
        } else {
            for (self.steps.items, 0..) |step, i| {
                try w.print("{d}. {s}\n", .{ i + 1, step });
            }
        }

        return buf.toOwnedSlice(allocator);
    }
};

/// Generate migration guidance based on a compatibility report.
pub fn generateMigrationGuide(allocator: Allocator, report: *const CompatReport) !MigrationGuide {
    var guide = MigrationGuide{ .steps = .empty };
    errdefer guide.deinit(allocator);

    for (report.issues.items) |issue| {
        switch (issue.severity) {
            .error_level => {
                const step = try std.fmt.allocPrint(
                    allocator,
                    "[REQUIRED] Fix: {s}",
                    .{issue.description},
                );
                try guide.steps.append(allocator, step);
            },
            .warning => {
                const step = try std.fmt.allocPrint(
                    allocator,
                    "[RECOMMENDED] Address: {s}",
                    .{issue.description},
                );
                try guide.steps.append(allocator, step);
            },
            .info => {
                const step = try std.fmt.allocPrint(
                    allocator,
                    "[OPTIONAL] Consider: {s}",
                    .{issue.description},
                );
                try guide.steps.append(allocator, step);
            },
        }
    }

    return guide;
}

// =========================================================================
// Tests
// =========================================================================

test "sequoia: empty data returns error" {
    const allocator = std.testing.allocator;

    var report = try checkSequoiaCompatibility(allocator, "");
    defer report.deinit(allocator);

    try std.testing.expect(!report.compatible);
    try std.testing.expect(report.issues.items.len > 0);
}

test "sequoia: invalid packet header" {
    const allocator = std.testing.allocator;

    const data = [_]u8{ 0x00, 0x01, 0x02 }; // Not a valid packet
    var report = try checkSequoiaCompatibility(allocator, &data);
    defer report.deinit(allocator);

    try std.testing.expect(!report.compatible);
}

test "sequoia: V4 RSA key produces info" {
    const allocator = std.testing.allocator;

    // Minimal V4 public key packet (new format): tag=6, len=12
    var data: [14]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.public_key); // new format, tag 6
    data[1] = 12; // body length
    data[2] = 4; // version 4
    data[3] = 0x60;
    data[4] = 0x00;
    data[5] = 0x00;
    data[6] = 0x00; // creation time
    data[7] = @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign); // algorithm
    @memset(data[8..], 0); // padding

    var report = try checkSequoiaCompatibility(allocator, &data);
    defer report.deinit(allocator);

    // Should have info-level issues about V4 and RSA.
    try std.testing.expect(report.issues.items.len > 0);
    try std.testing.expect(report.countBySeverity(.info) > 0);
}

test "sequoia: old format packet produces warning" {
    const allocator = std.testing.allocator;

    // Old format public key packet: tag 6 in old format = 10011000
    var data: [14]u8 = undefined;
    data[0] = 0x80 | (6 << 2) | 0; // old format, tag 6, 1-byte length
    data[1] = 12; // body length
    data[2] = 4; // version 4
    data[3] = 0x60;
    data[4] = 0x00;
    data[5] = 0x00;
    data[6] = 0x00;
    data[7] = @intFromEnum(PublicKeyAlgorithm.ed25519);
    @memset(data[8..], 0);

    var report = try checkSequoiaCompatibility(allocator, &data);
    defer report.deinit(allocator);

    try std.testing.expect(report.countBySeverity(.warning) > 0);
}

test "sequoia: RFC 9580 compliance empty data" {
    const allocator = std.testing.allocator;

    var report = try checkRfc9580Compliance(allocator, "");
    defer report.deinit(allocator);

    try std.testing.expect(!report.compliant);
}

test "sequoia: RFC 9580 compliance non-openpgp" {
    const allocator = std.testing.allocator;

    const data = [_]u8{ 0x00, 0x01 };
    var report = try checkRfc9580Compliance(allocator, &data);
    defer report.deinit(allocator);

    try std.testing.expect(!report.compliant);
}

test "sequoia: RFC 9580 compliance old format rejected" {
    const allocator = std.testing.allocator;

    // Old format packet
    var data: [14]u8 = undefined;
    data[0] = 0x80 | (6 << 2) | 0;
    data[1] = 12;
    data[2] = 4;
    @memset(data[3..], 0);

    var report = try checkRfc9580Compliance(allocator, &data);
    defer report.deinit(allocator);

    try std.testing.expect(!report.compliant);
}

test "sequoia: CompatReport format" {
    const allocator = std.testing.allocator;

    var report = CompatReport{
        .compatible = true,
        .issues = .empty,
    };
    defer report.deinit(allocator);

    try report.issues.append(allocator, .{
        .severity = .info,
        .description = try allocator.dupe(u8, "Test issue"),
    });

    const formatted = try report.format(allocator);
    defer allocator.free(formatted);

    try std.testing.expect(mem.indexOf(u8, formatted, "Compatible: yes") != null);
    try std.testing.expect(mem.indexOf(u8, formatted, "Test issue") != null);
}

test "sequoia: IssueSeverity names" {
    try std.testing.expectEqualStrings("INFO", IssueSeverity.info.name());
    try std.testing.expectEqualStrings("WARNING", IssueSeverity.warning.name());
    try std.testing.expectEqualStrings("ERROR", IssueSeverity.error_level.name());
}

test "sequoia: generateMigrationGuide from empty report" {
    const allocator = std.testing.allocator;

    var report = CompatReport{
        .compatible = true,
        .issues = .empty,
    };
    defer report.deinit(allocator);

    var guide = try generateMigrationGuide(allocator, &report);
    defer guide.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), guide.steps.items.len);
}

test "sequoia: generateMigrationGuide from report with issues" {
    const allocator = std.testing.allocator;

    var report = CompatReport{
        .compatible = false,
        .issues = .empty,
    };
    defer report.deinit(allocator);

    try report.issues.append(allocator, .{
        .severity = .error_level,
        .description = try allocator.dupe(u8, "Uses SED packet"),
    });
    try report.issues.append(allocator, .{
        .severity = .warning,
        .description = try allocator.dupe(u8, "Old format headers"),
    });

    var guide = try generateMigrationGuide(allocator, &report);
    defer guide.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), guide.steps.items.len);
    try std.testing.expect(mem.indexOf(u8, guide.steps.items[0], "[REQUIRED]") != null);
    try std.testing.expect(mem.indexOf(u8, guide.steps.items[1], "[RECOMMENDED]") != null);
}

test "sequoia: Rfc9580Report format" {
    const allocator = std.testing.allocator;

    var report = Rfc9580Report{
        .compliant = true,
        .version = 6,
        .uses_aead = true,
        .has_v6_keys = true,
        .deprecated_algorithms = .empty,
        .issues = .empty,
    };
    defer report.deinit(allocator);

    const formatted = try report.format(allocator);
    defer allocator.free(formatted);

    try std.testing.expect(mem.indexOf(u8, formatted, "Compliant:  yes") != null);
    try std.testing.expect(mem.indexOf(u8, formatted, "AEAD:       yes") != null);
    try std.testing.expect(mem.indexOf(u8, formatted, "V6 Keys:    yes") != null);
}
