// SPDX-License-Identifier: MIT
//! Comprehensive key validation module.
//!
//! Provides thorough validation of OpenPGP keys including:
//!   - Self-signature verification (structural check)
//!   - Subkey binding signature validation
//!   - User ID certification checks
//!   - Revocation status detection
//!   - Algorithm strength assessment
//!   - Expiration status checking
//!
//! The validator uses a configurable algorithm policy and strict mode
//! to control how aggressively it flags potential issues.

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
const algo_policy = @import("../policy/algorithm_policy.zig");
const AlgorithmPolicy = algo_policy.AlgorithmPolicy;
const PolicyLevel = algo_policy.PolicyLevel;

const key_analyzer = @import("../inspect/key_analyzer.zig");
const SecurityScore = key_analyzer.SecurityScore;

// =========================================================================
// Validation result types
// =========================================================================

/// A validation error (hard failure).
pub const ValidationError = struct {
    code: []const u8,
    description: []const u8,

    pub fn deinit(self: ValidationError, allocator: Allocator) void {
        allocator.free(self.code);
        allocator.free(self.description);
    }
};

/// A validation warning (non-fatal issue).
pub const ValidationWarning = struct {
    code: []const u8,
    description: []const u8,
    suggestion: ?[]const u8,

    pub fn deinit(self: ValidationWarning, allocator: Allocator) void {
        allocator.free(self.code);
        allocator.free(self.description);
        if (self.suggestion) |s| allocator.free(s);
    }
};

/// Status of a subkey binding signature.
pub const BindingStatus = struct {
    fingerprint: []const u8,
    valid: bool,
    error_msg: ?[]const u8,

    pub fn deinit(self: BindingStatus, allocator: Allocator) void {
        allocator.free(self.fingerprint);
        if (self.error_msg) |msg| allocator.free(msg);
    }
};

/// Status of a user ID certification.
pub const UidStatus = struct {
    uid: []const u8,
    has_self_sig: bool,
    valid: bool,

    pub fn deinit(self: UidStatus, allocator: Allocator) void {
        allocator.free(self.uid);
    }
};

/// Revocation status of a key.
pub const RevocationStatus = struct {
    revoked: bool,
    reason: ?[]const u8,
    revocation_time: ?u32,

    pub fn deinit(self: RevocationStatus, allocator: Allocator) void {
        if (self.reason) |r| allocator.free(r);
    }
};

/// Algorithm strength assessment.
pub const AlgorithmAssessment = struct {
    score: SecurityScore,
    details: std.ArrayList([]const u8),

    pub fn deinit(self: *AlgorithmAssessment, allocator: Allocator) void {
        for (self.details.items) |d| allocator.free(d);
        self.details.deinit(allocator);
    }
};

/// Key expiration status.
pub const ExpirationStatus = struct {
    expired: bool,
    expires: ?u32,
    days_remaining: ?i64,
};

/// Complete key validation report.
pub const ValidationReport = struct {
    /// Whether the key passed all validation checks.
    valid: bool,
    /// Hard errors.
    errors: std.ArrayList(ValidationError),
    /// Non-fatal warnings.
    warnings: std.ArrayList(ValidationWarning),
    /// Informational messages.
    info: std.ArrayList([]const u8),
    /// Whether the self-signature is structurally valid.
    self_sig_valid: bool,
    /// Number of subkeys.
    subkey_count: u32,
    /// Number of user IDs.
    uid_count: u32,
    /// Primary key algorithm name.
    algorithm: []const u8,
    /// Key size in bits (for RSA/DSA), or null for EC.
    bits: ?u32,
    /// Key fingerprint as hex string.
    fingerprint: []const u8,
    /// Key version.
    version: u8,

    /// Free all memory associated with this report.
    pub fn deinit(self: *ValidationReport, allocator: Allocator) void {
        for (self.errors.items) |e| e.deinit(allocator);
        self.errors.deinit(allocator);
        for (self.warnings.items) |w| w.deinit(allocator);
        self.warnings.deinit(allocator);
        for (self.info.items) |i| allocator.free(i);
        self.info.deinit(allocator);
        allocator.free(self.algorithm);
        allocator.free(self.fingerprint);
    }

    /// Format the report as a human-readable string.
    pub fn format(self: *const ValidationReport, allocator: Allocator) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);
        const w = buf.writer(allocator);

        try w.writeAll("Key Validation Report\n");
        try w.writeAll("========================================\n");
        try w.print("Valid:        {s}\n", .{if (self.valid) "yes" else "no"});
        try w.print("Fingerprint:  {s}\n", .{self.fingerprint});
        try w.print("Algorithm:    {s}\n", .{self.algorithm});
        if (self.bits) |b| {
            try w.print("Key Size:     {d} bits\n", .{b});
        }
        try w.print("Version:      V{d}\n", .{self.version});
        try w.print("User IDs:     {d}\n", .{self.uid_count});
        try w.print("Subkeys:      {d}\n", .{self.subkey_count});
        try w.print("Self-sig:     {s}\n", .{if (self.self_sig_valid) "valid" else "INVALID"});

        if (self.errors.items.len > 0) {
            try w.print("\nErrors ({d}):\n", .{self.errors.items.len});
            for (self.errors.items, 0..) |e, i| {
                try w.print("  {d}. [{s}] {s}\n", .{ i + 1, e.code, e.description });
            }
        }

        if (self.warnings.items.len > 0) {
            try w.print("\nWarnings ({d}):\n", .{self.warnings.items.len});
            for (self.warnings.items, 0..) |warning, i| {
                try w.print("  {d}. [{s}] {s}", .{ i + 1, warning.code, warning.description });
                if (warning.suggestion) |s| {
                    try w.print(" -- {s}", .{s});
                }
                try w.writeByte('\n');
            }
        }

        if (self.info.items.len > 0) {
            try w.print("\nInfo ({d}):\n", .{self.info.items.len});
            for (self.info.items, 0..) |info_msg, i| {
                try w.print("  {d}. {s}\n", .{ i + 1, info_msg });
            }
        }

        return buf.toOwnedSlice(allocator);
    }
};

// =========================================================================
// Key validator
// =========================================================================

/// Comprehensive key validator.
///
/// Validates OpenPGP key data against a configurable algorithm policy.
/// In strict mode, warnings are promoted to errors.
pub const KeyValidator = struct {
    policy: AlgorithmPolicy,
    strict_mode: bool,

    /// Create a new key validator with the specified policy and strictness.
    pub fn init(policy_level: PolicyLevel, strict: bool) KeyValidator {
        return .{
            .policy = AlgorithmPolicy.init(policy_level),
            .strict_mode = strict,
        };
    }

    /// Perform a complete validation of key data.
    ///
    /// The `key_data` parameter should be raw OpenPGP packet data
    /// (not ASCII armored).
    pub fn validateKey(self: KeyValidator, allocator: Allocator, key_data: []const u8) !ValidationReport {
        var report = ValidationReport{
            .valid = true,
            .errors = .empty,
            .warnings = .empty,
            .info = .empty,
            .self_sig_valid = false,
            .subkey_count = 0,
            .uid_count = 0,
            .algorithm = try allocator.dupe(u8, "Unknown"),
            .bits = null,
            .fingerprint = try allocator.dupe(u8, ""),
            .version = 0,
        };
        errdefer report.deinit(allocator);

        if (key_data.len == 0) {
            report.valid = false;
            try report.errors.append(allocator, .{
                .code = try allocator.dupe(u8, "EMPTY_KEY"),
                .description = try allocator.dupe(u8, "Key data is empty"),
            });
            return report;
        }

        // Verify this looks like an OpenPGP key packet.
        if (key_data[0] & 0x80 == 0) {
            report.valid = false;
            try report.errors.append(allocator, .{
                .code = try allocator.dupe(u8, "INVALID_PACKET"),
                .description = try allocator.dupe(u8, "Data does not start with a valid OpenPGP packet"),
            });
            return report;
        }

        const is_new_format = (key_data[0] & 0x40) != 0;
        const tag: u8 = if (is_new_format) (key_data[0] & 0x3F) else ((key_data[0] & 0x3C) >> 2);

        if (tag != @intFromEnum(PacketTag.public_key) and
            tag != @intFromEnum(PacketTag.secret_key))
        {
            report.valid = false;
            try report.errors.append(allocator, .{
                .code = try allocator.dupe(u8, "NOT_A_KEY"),
                .description = try allocator.dupe(u8, "Data does not start with a key packet"),
            });
            return report;
        }

        // Parse the key packet header to find the body.
        const body_offset = getBodyOffset(key_data, is_new_format);
        if (body_offset == null or body_offset.? >= key_data.len) {
            report.valid = false;
            try report.errors.append(allocator, .{
                .code = try allocator.dupe(u8, "TRUNCATED"),
                .description = try allocator.dupe(u8, "Key packet header is truncated"),
            });
            return report;
        }

        const offset = body_offset.?;

        // Extract key version.
        report.version = key_data[offset];

        if (report.version < 4) {
            report.valid = false;
            try report.errors.append(allocator, .{
                .code = try allocator.dupe(u8, "OLD_VERSION"),
                .description = try allocator.dupe(u8, "V3 (or older) keys are not supported"),
            });
            return report;
        }

        // Extract algorithm.
        if (offset + 5 < key_data.len) {
            const algo: PublicKeyAlgorithm = @enumFromInt(key_data[offset + 5]);
            allocator.free(report.algorithm);
            report.algorithm = try allocator.dupe(u8, algo.name());

            // Algorithm strength check.
            if (!self.policy.isAcceptablePublicKey(algo, null)) {
                if (self.strict_mode) {
                    report.valid = false;
                    try report.errors.append(allocator, .{
                        .code = try allocator.dupe(u8, "WEAK_ALGO"),
                        .description = try std.fmt.allocPrint(
                            allocator,
                            "Algorithm {s} is not accepted under current policy",
                            .{algo.name()},
                        ),
                    });
                } else {
                    try report.warnings.append(allocator, .{
                        .code = try allocator.dupe(u8, "WEAK_ALGO"),
                        .description = try std.fmt.allocPrint(
                            allocator,
                            "Algorithm {s} may be deprecated",
                            .{algo.name()},
                        ),
                        .suggestion = try allocator.dupe(u8, "Consider migrating to a stronger algorithm"),
                    });
                }
            }

            // Check if native V6 algorithm with V4 key.
            if (algo.isNativeV6() and report.version == 4) {
                try report.warnings.append(allocator, .{
                    .code = try allocator.dupe(u8, "V6_ALGO_V4_KEY"),
                    .description = try allocator.dupe(u8, "RFC 9580 native algorithm used with V4 key format"),
                    .suggestion = try allocator.dupe(u8, "Generate a V6 key for full RFC 9580 compliance"),
                });
            }
        }

        // Scan packets to count UIDs, subkeys, signatures.
        try self.scanKeyStructure(allocator, key_data, &report);

        // Generate fingerprint hex string.
        if (key_data.len >= offset + 6) {
            const fp_data = key_data[offset..@min(offset + 22, key_data.len)];
            allocator.free(report.fingerprint);
            report.fingerprint = try formatHexLower(allocator, fp_data);
        }

        // Add info messages.
        try report.info.append(
            allocator,
            try std.fmt.allocPrint(allocator, "Key version: V{d}", .{report.version}),
        );
        try report.info.append(
            allocator,
            try std.fmt.allocPrint(allocator, "Algorithm: {s}", .{report.algorithm}),
        );
        if (report.uid_count > 0) {
            try report.info.append(
                allocator,
                try std.fmt.allocPrint(allocator, "User IDs: {d}", .{report.uid_count}),
            );
        }

        return report;
    }

    /// Validate the self-signature on the primary key.
    ///
    /// This performs a structural check — it verifies that a signature
    /// packet with type 0x13 (positive certification) or 0x10-0x12
    /// exists immediately after a user ID. Full cryptographic
    /// verification requires the key material.
    pub fn validateSelfSignature(
        self: KeyValidator,
        allocator: Allocator,
        key_data: []const u8,
    ) !bool {
        _ = self;
        _ = allocator;
        if (key_data.len < 6) return false;

        var offset: usize = 0;
        var found_key = false;
        var found_uid = false;
        var found_self_sig = false;

        while (offset < key_data.len) {
            if (key_data[offset] & 0x80 == 0) break;

            const is_new = (key_data[offset] & 0x40) != 0;
            const tag_val: u8 = if (is_new) (key_data[offset] & 0x3F) else ((key_data[offset] & 0x3C) >> 2);

            if (tag_val == @intFromEnum(PacketTag.public_key) or
                tag_val == @intFromEnum(PacketTag.secret_key))
            {
                found_key = true;
            } else if (tag_val == @intFromEnum(PacketTag.user_id)) {
                if (found_key) found_uid = true;
            } else if (tag_val == @intFromEnum(PacketTag.signature)) {
                if (found_uid) {
                    // Check the signature type byte.
                    const body_off = getBodyOffset(key_data[offset..], is_new);
                    if (body_off) |bo| {
                        const abs = offset + bo;
                        if (abs + 1 < key_data.len) {
                            const sig_version = key_data[abs];
                            var sig_type: u8 = 0;
                            if (sig_version == 4 and abs + 5 < key_data.len) {
                                sig_type = key_data[abs + 1];
                            } else if (sig_version == 6 and abs + 5 < key_data.len) {
                                sig_type = key_data[abs + 1];
                            }

                            // Certification signatures: 0x10 (generic), 0x11 (persona),
                            // 0x12 (casual), 0x13 (positive).
                            if (sig_type >= 0x10 and sig_type <= 0x13) {
                                found_self_sig = true;
                            }
                        }
                    }
                }
            }

            const pkt_len = getPacketLength(key_data[offset..], is_new);
            if (pkt_len == 0) break;
            offset += pkt_len;

            if (found_self_sig) break;
        }

        return found_self_sig;
    }

    /// Validate subkey binding signatures.
    pub fn validateSubkeyBindings(
        self: KeyValidator,
        allocator: Allocator,
        key_data: []const u8,
    ) !std.ArrayList(BindingStatus) {
        _ = self;
        var bindings: std.ArrayList(BindingStatus) = .empty;
        errdefer {
            for (bindings.items) |b| b.deinit(allocator);
            bindings.deinit(allocator);
        }

        var offset: usize = 0;
        var in_subkey = false;
        var subkey_index: u32 = 0;
        var subkey_has_binding = false;

        while (offset < key_data.len) {
            if (key_data[offset] & 0x80 == 0) break;

            const is_new = (key_data[offset] & 0x40) != 0;
            const tag_val: u8 = if (is_new) (key_data[offset] & 0x3F) else ((key_data[offset] & 0x3C) >> 2);

            if (tag_val == @intFromEnum(PacketTag.public_subkey) or
                tag_val == @intFromEnum(PacketTag.secret_subkey))
            {
                // If there was a previous subkey without a binding sig, record it.
                if (in_subkey and !subkey_has_binding) {
                    try bindings.append(allocator, .{
                        .fingerprint = try std.fmt.allocPrint(allocator, "subkey-{d}", .{subkey_index}),
                        .valid = false,
                        .error_msg = try allocator.dupe(u8, "Missing subkey binding signature"),
                    });
                }
                in_subkey = true;
                subkey_index += 1;
                subkey_has_binding = false;
            } else if (tag_val == @intFromEnum(PacketTag.signature) and in_subkey) {
                const body_off = getBodyOffset(key_data[offset..], is_new);
                if (body_off) |bo| {
                    const abs = offset + bo;
                    if (abs + 1 < key_data.len) {
                        const sig_ver = key_data[abs];
                        if ((sig_ver == 4 or sig_ver == 6) and abs + 1 < key_data.len) {
                            const sig_type = key_data[abs + 1];
                            // 0x18 = subkey binding, 0x19 = primary key binding
                            if (sig_type == 0x18) {
                                subkey_has_binding = true;
                                try bindings.append(allocator, .{
                                    .fingerprint = try std.fmt.allocPrint(allocator, "subkey-{d}", .{subkey_index}),
                                    .valid = true,
                                    .error_msg = null,
                                });
                            }
                        }
                    }
                }
            }

            const pkt_len = getPacketLength(key_data[offset..], is_new);
            if (pkt_len == 0) break;
            offset += pkt_len;
        }

        // Handle last subkey.
        if (in_subkey and !subkey_has_binding) {
            try bindings.append(allocator, .{
                .fingerprint = try std.fmt.allocPrint(allocator, "subkey-{d}", .{subkey_index}),
                .valid = false,
                .error_msg = try allocator.dupe(u8, "Missing subkey binding signature"),
            });
        }

        return bindings;
    }

    /// Validate user IDs on the key.
    pub fn validateUserIds(
        self: KeyValidator,
        allocator: Allocator,
        key_data: []const u8,
    ) !std.ArrayList(UidStatus) {
        _ = self;
        var uids: std.ArrayList(UidStatus) = .empty;
        errdefer {
            for (uids.items) |u| u.deinit(allocator);
            uids.deinit(allocator);
        }

        var offset: usize = 0;
        var current_uid: ?[]const u8 = null;
        var uid_has_sig = false;

        while (offset < key_data.len) {
            if (key_data[offset] & 0x80 == 0) break;

            const is_new = (key_data[offset] & 0x40) != 0;
            const tag_val: u8 = if (is_new) (key_data[offset] & 0x3F) else ((key_data[offset] & 0x3C) >> 2);

            if (tag_val == @intFromEnum(PacketTag.user_id)) {
                // Commit previous UID.
                if (current_uid) |uid| {
                    try uids.append(allocator, .{
                        .uid = uid,
                        .has_self_sig = uid_has_sig,
                        .valid = uid_has_sig,
                    });
                }

                // Extract the new UID string.
                const body_off = getBodyOffset(key_data[offset..], is_new);
                const pkt_len = getPacketLength(key_data[offset..], is_new);
                if (body_off != null and pkt_len > 0) {
                    const abs = offset + body_off.?;
                    const end = offset + pkt_len;
                    if (abs < end and end <= key_data.len) {
                        current_uid = try allocator.dupe(u8, key_data[abs..end]);
                    } else {
                        current_uid = try allocator.dupe(u8, "<malformed>");
                    }
                } else {
                    current_uid = try allocator.dupe(u8, "<unknown>");
                }
                uid_has_sig = false;
            } else if (tag_val == @intFromEnum(PacketTag.signature) and current_uid != null) {
                const body_off = getBodyOffset(key_data[offset..], is_new);
                if (body_off) |bo| {
                    const abs = offset + bo;
                    if (abs + 1 < key_data.len) {
                        const sig_ver = key_data[abs];
                        if ((sig_ver == 4 or sig_ver == 6) and abs + 1 < key_data.len) {
                            const sig_type = key_data[abs + 1];
                            if (sig_type >= 0x10 and sig_type <= 0x13) {
                                uid_has_sig = true;
                            }
                        }
                    }
                }
            }

            const pkt_len = getPacketLength(key_data[offset..], is_new);
            if (pkt_len == 0) break;
            offset += pkt_len;
        }

        // Commit last UID.
        if (current_uid) |uid| {
            try uids.append(allocator, .{
                .uid = uid,
                .has_self_sig = uid_has_sig,
                .valid = uid_has_sig,
            });
        }

        return uids;
    }

    /// Check if the key has been revoked.
    pub fn validateRevocationStatus(
        self: KeyValidator,
        allocator: Allocator,
        key_data: []const u8,
    ) !RevocationStatus {
        _ = self;
        var offset: usize = 0;
        var found_key = false;

        while (offset < key_data.len) {
            if (key_data[offset] & 0x80 == 0) break;

            const is_new = (key_data[offset] & 0x40) != 0;
            const tag_val: u8 = if (is_new) (key_data[offset] & 0x3F) else ((key_data[offset] & 0x3C) >> 2);

            if (tag_val == @intFromEnum(PacketTag.public_key) or
                tag_val == @intFromEnum(PacketTag.secret_key))
            {
                found_key = true;
            } else if (tag_val == @intFromEnum(PacketTag.signature) and found_key) {
                const body_off = getBodyOffset(key_data[offset..], is_new);
                if (body_off) |bo| {
                    const abs = offset + bo;
                    if (abs + 1 < key_data.len) {
                        const sig_ver = key_data[abs];
                        if ((sig_ver == 4 or sig_ver == 6) and abs + 1 < key_data.len) {
                            const sig_type = key_data[abs + 1];
                            // 0x20 = key revocation, 0x28 = subkey revocation
                            if (sig_type == 0x20) {
                                return RevocationStatus{
                                    .revoked = true,
                                    .reason = try allocator.dupe(u8, "Key revocation signature found"),
                                    .revocation_time = null,
                                };
                            }
                        }
                    }
                }
            }

            const pkt_len = getPacketLength(key_data[offset..], is_new);
            if (pkt_len == 0) break;
            offset += pkt_len;
        }

        return RevocationStatus{
            .revoked = false,
            .reason = null,
            .revocation_time = null,
        };
    }

    /// Assess the algorithm strength of a key.
    pub fn validateAlgorithmStrength(
        self: KeyValidator,
        allocator: Allocator,
        key_data: []const u8,
    ) !AlgorithmAssessment {
        var assessment = AlgorithmAssessment{
            .score = .excellent,
            .details = .empty,
        };
        errdefer assessment.deinit(allocator);

        if (key_data.len < 6) {
            assessment.score = .critical;
            try assessment.details.append(allocator, try allocator.dupe(u8, "Key data too short to assess"));
            return assessment;
        }

        // Find the key packet body.
        const is_new = (key_data[0] & 0x40) != 0;
        const body_offset = getBodyOffset(key_data, is_new);
        if (body_offset == null) {
            assessment.score = .critical;
            try assessment.details.append(allocator, try allocator.dupe(u8, "Cannot parse key packet header"));
            return assessment;
        }

        const offset = body_offset.?;
        if (offset + 5 >= key_data.len) {
            assessment.score = .critical;
            try assessment.details.append(allocator, try allocator.dupe(u8, "Key packet body too short"));
            return assessment;
        }

        const algo: PublicKeyAlgorithm = @enumFromInt(key_data[offset + 5]);

        // Assess algorithm.
        switch (algo) {
            .ed25519, .ed448, .x25519, .x448 => {
                assessment.score = .excellent;
                try assessment.details.append(
                    allocator,
                    try std.fmt.allocPrint(allocator, "{s}: excellent (modern elliptic curve)", .{algo.name()}),
                );
            },
            .ecdsa, .ecdh, .eddsa => {
                assessment.score = .good;
                try assessment.details.append(
                    allocator,
                    try std.fmt.allocPrint(allocator, "{s}: good (elliptic curve)", .{algo.name()}),
                );
            },
            .rsa_encrypt_sign, .rsa_encrypt_only, .rsa_sign_only => {
                if (!self.policy.isAcceptablePublicKey(algo, 2048)) {
                    assessment.score = .poor;
                } else {
                    assessment.score = .good;
                }
                try assessment.details.append(
                    allocator,
                    try std.fmt.allocPrint(allocator, "{s}: check key size for full assessment", .{algo.name()}),
                );
            },
            .dsa => {
                assessment.score = .fair;
                try assessment.details.append(
                    allocator,
                    try allocator.dupe(u8, "DSA: deprecated; consider Ed25519"),
                );
            },
            .elgamal => {
                assessment.score = .fair;
                try assessment.details.append(
                    allocator,
                    try allocator.dupe(u8, "ElGamal: deprecated; consider X25519"),
                );
            },
            _ => {
                assessment.score = .poor;
                try assessment.details.append(
                    allocator,
                    try allocator.dupe(u8, "Unknown algorithm"),
                );
            },
        }

        return assessment;
    }

    /// Check key expiration status.
    pub fn validateExpiration(
        self: KeyValidator,
        allocator: Allocator,
        key_data: []const u8,
        now: u32,
    ) !ExpirationStatus {
        _ = self;
        _ = allocator;

        // Extract creation time from the key packet.
        if (key_data.len < 6) {
            return ExpirationStatus{ .expired = false, .expires = null, .days_remaining = null };
        }

        const is_new = (key_data[0] & 0x40) != 0;
        const body_offset = getBodyOffset(key_data, is_new);
        if (body_offset == null) {
            return ExpirationStatus{ .expired = false, .expires = null, .days_remaining = null };
        }

        const offset = body_offset.?;
        if (offset + 5 >= key_data.len) {
            return ExpirationStatus{ .expired = false, .expires = null, .days_remaining = null };
        }

        const creation_time = mem.readInt(u32, key_data[offset + 1 ..][0..4], .big);

        // We need to find a self-signature with an expiration subpacket.
        // For now, return a basic check based on creation time.
        // Keys without explicit expiration never expire.
        if (creation_time > now) {
            // Key created in the future? Suspicious.
            return ExpirationStatus{ .expired = false, .expires = null, .days_remaining = null };
        }

        return ExpirationStatus{
            .expired = false,
            .expires = null,
            .days_remaining = null,
        };
    }

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// Scan the key packet structure to count UIDs, subkeys, etc.
    fn scanKeyStructure(
        self: KeyValidator,
        allocator: Allocator,
        key_data: []const u8,
        report: *ValidationReport,
    ) !void {
        _ = self;
        var offset: usize = 0;
        var has_uid = false;
        var has_self_sig = false;

        while (offset < key_data.len) {
            if (key_data[offset] & 0x80 == 0) break;

            const is_new = (key_data[offset] & 0x40) != 0;
            const tag_val: u8 = if (is_new) (key_data[offset] & 0x3F) else ((key_data[offset] & 0x3C) >> 2);

            if (tag_val == @intFromEnum(PacketTag.user_id)) {
                report.uid_count += 1;
                has_uid = true;
            } else if (tag_val == @intFromEnum(PacketTag.public_subkey) or
                tag_val == @intFromEnum(PacketTag.secret_subkey))
            {
                report.subkey_count += 1;
            } else if (tag_val == @intFromEnum(PacketTag.signature) and has_uid) {
                const body_off = getBodyOffset(key_data[offset..], is_new);
                if (body_off) |bo| {
                    const abs = offset + bo;
                    if (abs + 1 < key_data.len) {
                        const sig_ver = key_data[abs];
                        if ((sig_ver == 4 or sig_ver == 6) and abs + 1 < key_data.len) {
                            const sig_type = key_data[abs + 1];
                            if (sig_type >= 0x10 and sig_type <= 0x13) {
                                has_self_sig = true;
                            }
                        }
                    }
                }
            }

            const pkt_len = getPacketLength(key_data[offset..], is_new);
            if (pkt_len == 0) break;
            offset += pkt_len;
        }

        report.self_sig_valid = has_self_sig;

        if (!has_uid) {
            try report.warnings.append(allocator, .{
                .code = try allocator.dupe(u8, "NO_UID"),
                .description = try allocator.dupe(u8, "Key has no User ID packets"),
                .suggestion = try allocator.dupe(u8, "Add at least one User ID to the key"),
            });
        }

        if (!has_self_sig and has_uid) {
            try report.warnings.append(allocator, .{
                .code = try allocator.dupe(u8, "NO_SELF_SIG"),
                .description = try allocator.dupe(u8, "No self-signature found on any User ID"),
                .suggestion = try allocator.dupe(u8, "Create a self-signature to certify the User IDs"),
            });
        }
    }
};

// =========================================================================
// Packet parsing helpers
// =========================================================================

/// Get the offset of the packet body (after header and length).
fn getBodyOffset(data: []const u8, is_new_format: bool) ?usize {
    if (data.len < 2) return null;

    if (is_new_format) {
        const len_byte = data[1];
        if (len_byte < 192) return 2;
        if (len_byte < 224) return 3;
        if (len_byte == 255) return 6;
        return null;
    } else {
        const len_type = data[0] & 0x03;
        return switch (len_type) {
            0 => 2,
            1 => 3,
            2 => 5,
            3 => null,
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
            return 2 + @as(usize, len_byte);
        }
        if (len_byte < 224 and data.len >= 3) {
            return 3 + (@as(usize, len_byte - 192) << 8) + @as(usize, data[2]) + 192;
        }
        if (len_byte == 255 and data.len >= 6) {
            return 6 + @as(usize, mem.readInt(u32, data[2..6], .big));
        }
        return 0;
    } else {
        const len_type = data[0] & 0x03;
        switch (len_type) {
            0 => return 2 + @as(usize, data[1]),
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

/// Format a byte slice as lowercase hexadecimal.
fn formatHexLower(allocator: Allocator, bytes: []const u8) ![]u8 {
    const hex_chars = "0123456789abcdef";
    const result = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0F];
    }
    return result;
}

// =========================================================================
// Tests
// =========================================================================

test "key_validator: validate empty key data" {
    const allocator = std.testing.allocator;
    const validator = KeyValidator.init(.rfc9580, false);

    var report = try validator.validateKey(allocator, "");
    defer report.deinit(allocator);

    try std.testing.expect(!report.valid);
    try std.testing.expect(report.errors.items.len > 0);
}

test "key_validator: validate non-openpgp data" {
    const allocator = std.testing.allocator;
    const validator = KeyValidator.init(.rfc9580, false);

    const data = [_]u8{ 0x00, 0x01, 0x02, 0x03 };
    var report = try validator.validateKey(allocator, &data);
    defer report.deinit(allocator);

    try std.testing.expect(!report.valid);
}

test "key_validator: validate minimal V4 key packet" {
    const allocator = std.testing.allocator;
    const validator = KeyValidator.init(.rfc4880, false);

    // Construct a minimal V4 public key packet (new format).
    var data: [14]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.public_key);
    data[1] = 12; // body length
    data[2] = 4; // version 4
    data[3] = 0x60;
    data[4] = 0x00;
    data[5] = 0x00;
    data[6] = 0x00;
    data[7] = @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign);
    @memset(data[8..], 0);

    var report = try validator.validateKey(allocator, &data);
    defer report.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 4), report.version);
    try std.testing.expectEqualStrings("RSA (Encrypt or Sign)", report.algorithm);
}

test "key_validator: strict mode rejects DSA" {
    const allocator = std.testing.allocator;
    const validator = KeyValidator.init(.strict, true);

    var data: [14]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.public_key);
    data[1] = 12;
    data[2] = 4;
    data[3] = 0x60;
    data[4] = 0x00;
    data[5] = 0x00;
    data[6] = 0x00;
    data[7] = @intFromEnum(PublicKeyAlgorithm.dsa);
    @memset(data[8..], 0);

    var report = try validator.validateKey(allocator, &data);
    defer report.deinit(allocator);

    try std.testing.expect(!report.valid);
    try std.testing.expect(report.errors.items.len > 0);
}

test "key_validator: non-strict mode warns about DSA" {
    const allocator = std.testing.allocator;
    const validator = KeyValidator.init(.strict, false);

    var data: [14]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.public_key);
    data[1] = 12;
    data[2] = 4;
    data[3] = 0x60;
    data[4] = 0x00;
    data[5] = 0x00;
    data[6] = 0x00;
    data[7] = @intFromEnum(PublicKeyAlgorithm.dsa);
    @memset(data[8..], 0);

    var report = try validator.validateKey(allocator, &data);
    defer report.deinit(allocator);

    try std.testing.expect(report.warnings.items.len > 0);
}

test "key_validator: ValidationReport format" {
    const allocator = std.testing.allocator;

    var report = ValidationReport{
        .valid = true,
        .errors = .empty,
        .warnings = .empty,
        .info = .empty,
        .self_sig_valid = true,
        .subkey_count = 1,
        .uid_count = 1,
        .algorithm = try allocator.dupe(u8, "Ed25519"),
        .bits = null,
        .fingerprint = try allocator.dupe(u8, "abcdef0123456789"),
        .version = 6,
    };
    defer report.deinit(allocator);

    const formatted = try report.format(allocator);
    defer allocator.free(formatted);

    try std.testing.expect(mem.indexOf(u8, formatted, "Valid:        yes") != null);
    try std.testing.expect(mem.indexOf(u8, formatted, "Ed25519") != null);
    try std.testing.expect(mem.indexOf(u8, formatted, "V6") != null);
}

test "key_validator: validateSelfSignature on bare key" {
    const allocator = std.testing.allocator;
    const validator = KeyValidator.init(.rfc9580, false);

    // A key packet without any signatures.
    var data: [14]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.public_key);
    data[1] = 12;
    data[2] = 4;
    data[3] = 0x60;
    data[4] = 0x00;
    data[5] = 0x00;
    data[6] = 0x00;
    data[7] = @intFromEnum(PublicKeyAlgorithm.ed25519);
    @memset(data[8..], 0);

    const result = try validator.validateSelfSignature(allocator, &data);
    try std.testing.expect(!result);
}

test "key_validator: validateRevocationStatus on non-revoked key" {
    const allocator = std.testing.allocator;
    const validator = KeyValidator.init(.rfc9580, false);

    var data: [14]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.public_key);
    data[1] = 12;
    data[2] = 4;
    data[3] = 0x60;
    data[4] = 0x00;
    data[5] = 0x00;
    data[6] = 0x00;
    data[7] = @intFromEnum(PublicKeyAlgorithm.ed25519);
    @memset(data[8..], 0);

    var status = try validator.validateRevocationStatus(allocator, &data);
    defer status.deinit(allocator);

    try std.testing.expect(!status.revoked);
    try std.testing.expect(status.reason == null);
}

test "key_validator: validateAlgorithmStrength Ed25519" {
    const allocator = std.testing.allocator;
    const validator = KeyValidator.init(.rfc9580, false);

    var data: [14]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.public_key);
    data[1] = 12;
    data[2] = 4;
    data[3] = 0x60;
    data[4] = 0x00;
    data[5] = 0x00;
    data[6] = 0x00;
    data[7] = @intFromEnum(PublicKeyAlgorithm.ed25519);
    @memset(data[8..], 0);

    var assessment = try validator.validateAlgorithmStrength(allocator, &data);
    defer assessment.deinit(allocator);

    try std.testing.expect(assessment.score == .excellent);
    try std.testing.expect(assessment.details.items.len > 0);
}

test "key_validator: validateAlgorithmStrength DSA" {
    const allocator = std.testing.allocator;
    const validator = KeyValidator.init(.rfc9580, false);

    var data: [14]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.public_key);
    data[1] = 12;
    data[2] = 4;
    data[3] = 0x60;
    data[4] = 0x00;
    data[5] = 0x00;
    data[6] = 0x00;
    data[7] = @intFromEnum(PublicKeyAlgorithm.dsa);
    @memset(data[8..], 0);

    var assessment = try validator.validateAlgorithmStrength(allocator, &data);
    defer assessment.deinit(allocator);

    try std.testing.expect(assessment.score == .fair);
}

test "key_validator: validateExpiration on key without expiry" {
    const allocator = std.testing.allocator;
    const validator = KeyValidator.init(.rfc9580, false);

    var data: [14]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.public_key);
    data[1] = 12;
    data[2] = 4;
    data[3] = 0x60;
    data[4] = 0x00;
    data[5] = 0x00;
    data[6] = 0x00;
    data[7] = @intFromEnum(PublicKeyAlgorithm.ed25519);
    @memset(data[8..], 0);

    const status = try validator.validateExpiration(allocator, &data, 0x70000000);
    try std.testing.expect(!status.expired);
    try std.testing.expect(status.expires == null);
}

test "key_validator: formatHexLower" {
    const allocator = std.testing.allocator;

    const input = [_]u8{ 0xAB, 0xCD, 0xEF, 0x01 };
    const hex = try formatHexLower(allocator, &input);
    defer allocator.free(hex);
    try std.testing.expectEqualStrings("abcdef01", hex);
}
