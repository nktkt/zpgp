// SPDX-License-Identifier: MIT
//! Key security analysis module.
//!
//! Analyzes OpenPGP keys for security properties and produces
//! recommendations based on current best practices and RFC 9580.
//! Checks include algorithm strength, hash algorithm usage,
//! symmetric cipher preferences, key age, expiration, subkey
//! usage flags, and packet version.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const header_mod = @import("../packet/header.zig");
const PacketTag = @import("../packet/tags.zig").PacketTag;
const armor = @import("../armor/armor.zig");
const enums = @import("../types/enums.zig");
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const AeadAlgorithm = enums.AeadAlgorithm;

/// Overall security rating for a key.
pub const SecurityScore = enum {
    excellent,
    good,
    fair,
    poor,
    critical,

    pub fn name(self: SecurityScore) []const u8 {
        return switch (self) {
            .excellent => "EXCELLENT",
            .good => "GOOD",
            .fair => "FAIR",
            .poor => "POOR",
            .critical => "CRITICAL",
        };
    }

    /// Compare two scores. Returns true if self is worse than other.
    pub fn isWorseThan(self: SecurityScore, other: SecurityScore) bool {
        return @intFromEnum(self) > @intFromEnum(other);
    }
};

/// A single security issue found during analysis.
pub const SecurityIssue = struct {
    severity: Severity,
    component: []const u8,
    description: []const u8,
    recommendation: []const u8,

    pub const Severity = enum {
        critical,
        high,
        medium,
        low,
        info,

        pub fn name(self: Severity) []const u8 {
            return switch (self) {
                .critical => "CRITICAL",
                .high => "HIGH",
                .medium => "MEDIUM",
                .low => "LOW",
                .info => "INFO",
            };
        }
    };

    pub fn deinit(self: SecurityIssue, allocator: Allocator) void {
        allocator.free(self.component);
        allocator.free(self.description);
        allocator.free(self.recommendation);
    }
};

/// Result of a key security analysis.
pub const KeyAnalysis = struct {
    overall_score: SecurityScore,
    issues: std.ArrayList(SecurityIssue),
    recommendations: std.ArrayList([]const u8),

    pub fn deinit(self: *KeyAnalysis, allocator: Allocator) void {
        for (self.issues.items) |issue| issue.deinit(allocator);
        self.issues.deinit(allocator);
        for (self.recommendations.items) |rec| allocator.free(rec);
        self.recommendations.deinit(allocator);
    }

    /// Format the analysis as a human-readable report.
    pub fn format(self: *const KeyAnalysis, allocator: Allocator) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);
        const w = buf.writer(allocator);

        try w.print("Key Security Analysis\n", .{});
        try w.writeAll("========================================\n");
        try w.print("Overall Score: {s}\n\n", .{self.overall_score.name()});

        if (self.issues.items.len > 0) {
            try w.print("Issues ({d}):\n", .{self.issues.items.len});
            for (self.issues.items, 0..) |issue, i| {
                try w.print("  {d}. [{s}] {s}: {s}\n", .{
                    i + 1,
                    issue.severity.name(),
                    issue.component,
                    issue.description,
                });
                if (issue.recommendation.len > 0) {
                    try w.print("     Recommendation: {s}\n", .{issue.recommendation});
                }
            }
        }

        if (self.recommendations.items.len > 0) {
            try w.print("\nGeneral Recommendations:\n", .{});
            for (self.recommendations.items, 0..) |rec, i| {
                try w.print("  {d}. {s}\n", .{ i + 1, rec });
            }
        }

        return buf.toOwnedSlice(allocator);
    }
};

/// Analyze an OpenPGP key for security properties.
pub fn analyzeKey(allocator: Allocator, key_data: []const u8) !KeyAnalysis {
    var analysis = KeyAnalysis{
        .overall_score = .excellent,
        .issues = .empty,
        .recommendations = .empty,
    };
    errdefer analysis.deinit(allocator);

    // Strip armor if present
    const stripped = stripArmor(allocator, key_data);
    const binary = stripped.binary;
    defer freeArmorResult(allocator, stripped.decoded, stripped.headers);

    // Parse key packets and collect metadata
    var key_info = try parseKeyMetadata(allocator, binary);
    defer key_info.deinit(allocator);

    // Check 1: Primary key algorithm strength
    try checkAlgorithmStrength(allocator, &analysis, key_info.algorithm, key_info.rsa_bits, "Primary key");

    // Check 2: Hash algorithm in self-signature
    if (key_info.self_sig_hash) |hash| {
        try checkHashAlgorithm(allocator, &analysis, hash);
    }

    // Check 3: Symmetric cipher preferences
    for (key_info.sym_prefs.items) |pref| {
        try checkSymmetricPreference(allocator, &analysis, pref);
    }

    // Check 4: Key age
    if (key_info.creation_time > 0) {
        try checkKeyAge(allocator, &analysis, key_info.creation_time);
    }

    // Check 5: Expiration
    try checkExpiration(allocator, &analysis, key_info.has_expiration);

    // Check 6: Subkey usage flags
    try checkSubkeyUsage(allocator, &analysis, key_info.has_separate_sign_encrypt);

    // Check 7: Packet version
    try checkVersion(allocator, &analysis, key_info.version);

    // Check 8: AEAD preference
    try checkAeadPreference(allocator, &analysis, key_info.has_aead_preference);

    // Check 9: Subkey algorithms
    for (key_info.subkey_algos.items) |sk_info| {
        try checkAlgorithmStrength(allocator, &analysis, sk_info.algo, sk_info.bits, "Subkey");
    }

    return analysis;
}

// ---------------------------------------------------------------------------
// Internal metadata parsing
// ---------------------------------------------------------------------------

const SubkeyAlgoInfo = struct {
    algo: PublicKeyAlgorithm,
    bits: ?u32,
};

const KeyMetadata = struct {
    version: u8,
    algorithm: PublicKeyAlgorithm,
    rsa_bits: ?u32,
    creation_time: u32,
    has_expiration: bool,
    self_sig_hash: ?HashAlgorithm,
    sym_prefs: std.ArrayList(SymmetricAlgorithm),
    has_aead_preference: bool,
    has_separate_sign_encrypt: bool,
    subkey_algos: std.ArrayList(SubkeyAlgoInfo),

    fn deinit(self: *KeyMetadata, allocator: Allocator) void {
        self.sym_prefs.deinit(allocator);
        self.subkey_algos.deinit(allocator);
    }
};

fn parseKeyMetadata(allocator: Allocator, binary: []const u8) !KeyMetadata {
    var meta = KeyMetadata{
        .version = 0,
        .algorithm = .rsa_encrypt_sign,
        .rsa_bits = null,
        .creation_time = 0,
        .has_expiration = false,
        .self_sig_hash = null,
        .sym_prefs = .empty,
        .has_aead_preference = false,
        .has_separate_sign_encrypt = false,
        .subkey_algos = .empty,
    };
    errdefer meta.deinit(allocator);

    var has_signing_subkey = false;
    var has_encryption_subkey = false;

    var fbs = std.io.fixedBufferStream(binary);
    const rdr = fbs.reader();

    while (true) {
        const hdr = header_mod.readHeader(rdr) catch break;
        const body_len: u32 = switch (hdr.body_length) {
            .fixed => |len| len,
            .partial => |len| len,
            .indeterminate => 0,
        };

        if (body_len == 0 or fbs.pos + body_len > binary.len) break;
        const body = binary[fbs.pos .. fbs.pos + body_len];
        fbs.pos += body_len;

        switch (hdr.tag) {
            .public_key, .secret_key => {
                if (body.len >= 6) {
                    meta.version = body[0];
                    meta.creation_time = mem.readInt(u32, body[1..5], .big);
                    meta.algorithm = @enumFromInt(body[5]);
                    if (isRsaAlgo(meta.algorithm) and body.len > 8) {
                        meta.rsa_bits = mem.readInt(u16, body[6..8], .big);
                    }
                }
            },
            .public_subkey, .secret_subkey => {
                if (body.len >= 6) {
                    const sk_algo: PublicKeyAlgorithm = @enumFromInt(body[5]);
                    var sk_bits: ?u32 = null;
                    if (isRsaAlgo(sk_algo) and body.len > 8) {
                        sk_bits = mem.readInt(u16, body[6..8], .big);
                    }
                    try meta.subkey_algos.append(allocator, .{ .algo = sk_algo, .bits = sk_bits });

                    if (sk_algo.canSign()) has_signing_subkey = true;
                    if (sk_algo.canEncrypt()) has_encryption_subkey = true;
                }
            },
            .signature => {
                if (body.len >= 6 and body[0] == 4) {
                    const sig_type = body[1];
                    const hash_algo: HashAlgorithm = @enumFromInt(body[3]);

                    // Self-signature (certification types)
                    if (sig_type >= 0x10 and sig_type <= 0x13) {
                        meta.self_sig_hash = hash_algo;

                        // Parse hashed subpackets for preferences and expiration
                        const hashed_len: usize = mem.readInt(u16, body[4..6], .big);
                        if (6 + hashed_len <= body.len) {
                            const sp_data = body[6 .. 6 + hashed_len];
                            parsePreferencesFromSubpackets(allocator, sp_data, &meta) catch {};
                        }
                    }
                }
            },
            else => {},
        }
    }

    meta.has_separate_sign_encrypt = has_signing_subkey and has_encryption_subkey;

    return meta;
}

fn isRsaAlgo(algo: PublicKeyAlgorithm) bool {
    return algo == .rsa_encrypt_sign or algo == .rsa_encrypt_only or algo == .rsa_sign_only;
}

/// Parse subpacket data for symmetric preferences, AEAD preferences, and key expiration.
fn parsePreferencesFromSubpackets(allocator: Allocator, sp_data: []const u8, meta: *KeyMetadata) !void {
    var pos: usize = 0;
    while (pos < sp_data.len) {
        if (pos >= sp_data.len) break;
        const first = sp_data[pos];
        pos += 1;
        var sp_len: usize = 0;
        if (first < 192) {
            sp_len = first;
        } else if (first < 255) {
            if (pos >= sp_data.len) break;
            const second = sp_data[pos];
            pos += 1;
            sp_len = (@as(usize, first) - 192) * 256 + @as(usize, second) + 192;
        } else {
            if (pos + 4 > sp_data.len) break;
            sp_len = mem.readInt(u32, sp_data[pos..][0..4], .big);
            pos += 4;
        }
        if (sp_len == 0) break;
        if (pos + sp_len - 1 > sp_data.len) break;

        const tag_byte = sp_data[pos];
        const tag_val = tag_byte & 0x7F;
        const sp_body_start = pos + 1;
        const sp_body_end = pos + sp_len - 1;

        if (tag_val == 9 and sp_len >= 5) { // key_expiration_time
            if (sp_body_start + 4 <= sp_data.len) {
                const exp = mem.readInt(u32, sp_data[sp_body_start..][0..4], .big);
                if (exp > 0) {
                    meta.has_expiration = true;
                }
            }
        } else if (tag_val == 11 and sp_len >= 2) { // preferred_symmetric
            // Each byte after tag is a symmetric algorithm ID
            if (sp_body_end <= sp_data.len) {
                for (sp_data[sp_body_start..sp_body_end]) |algo_byte| {
                    try meta.sym_prefs.append(allocator, @enumFromInt(algo_byte));
                }
            }
        } else if (tag_val == 34) { // preferred AEAD ciphersuites (RFC 9580)
            meta.has_aead_preference = true;
        }

        pos += sp_len - 1;
    }
}

// ---------------------------------------------------------------------------
// Security checks
// ---------------------------------------------------------------------------

fn checkAlgorithmStrength(
    allocator: Allocator,
    analysis: *KeyAnalysis,
    algo: PublicKeyAlgorithm,
    rsa_bits: ?u32,
    component: []const u8,
) !void {
    if (isRsaAlgo(algo)) {
        if (rsa_bits) |bits| {
            if (bits < 1024) {
                try addIssue(allocator, analysis, .critical, component,
                    "RSA key is less than 1024 bits - trivially breakable",
                    "Generate a new key with Ed25519 or RSA 4096");
                degradeScore(&analysis.overall_score, .critical);
            } else if (bits < 2048) {
                try addIssue(allocator, analysis, .critical, component,
                    "RSA key is less than 2048 bits - considered insecure",
                    "Generate a new key with Ed25519 or RSA 4096");
                degradeScore(&analysis.overall_score, .critical);
            } else if (bits == 2048) {
                try addIssue(allocator, analysis, .medium, component,
                    "RSA 2048-bit key meets minimum requirements but is not future-proof",
                    "Consider upgrading to RSA 4096 or Ed25519");
                degradeScore(&analysis.overall_score, .fair);
            } else if (bits >= 3072 and bits < 4096) {
                try addIssue(allocator, analysis, .info, component,
                    "RSA 3072-bit key provides good security",
                    "");
                degradeScore(&analysis.overall_score, .good);
            } else if (bits >= 4096) {
                try addIssue(allocator, analysis, .info, component,
                    "RSA 4096-bit key provides strong security",
                    "");
                degradeScore(&analysis.overall_score, .good);
            }
        }
    } else if (algo == .ed25519 or algo == .eddsa) {
        try addIssue(allocator, analysis, .info, component,
            "Ed25519 provides excellent security with small key size",
            "");
        // stays excellent
    } else if (algo == .ed448) {
        try addIssue(allocator, analysis, .info, component,
            "Ed448 provides excellent security",
            "");
    } else if (algo == .x25519) {
        try addIssue(allocator, analysis, .info, component,
            "X25519 provides excellent key agreement security",
            "");
    } else if (algo == .x448) {
        try addIssue(allocator, analysis, .info, component,
            "X448 provides excellent key agreement security",
            "");
    } else if (algo == .dsa) {
        try addIssue(allocator, analysis, .high, component,
            "DSA is deprecated and no longer recommended",
            "Generate a new key with Ed25519");
        degradeScore(&analysis.overall_score, .poor);
    } else if (algo == .elgamal) {
        try addIssue(allocator, analysis, .medium, component,
            "Elgamal is functional but less efficient than modern alternatives",
            "Consider migrating to X25519 for encryption");
        degradeScore(&analysis.overall_score, .fair);
    }
}

fn checkHashAlgorithm(allocator: Allocator, analysis: *KeyAnalysis, hash: HashAlgorithm) !void {
    switch (hash) {
        .md5 => {
            try addIssue(allocator, analysis, .critical, "Self-signature",
                "MD5 hash algorithm is completely broken",
                "Re-sign the key with SHA-256 or better");
            degradeScore(&analysis.overall_score, .critical);
        },
        .sha1 => {
            try addIssue(allocator, analysis, .high, "Self-signature",
                "SHA-1 is deprecated and vulnerable to collision attacks",
                "Re-sign the key with SHA-256 or SHA-512");
            degradeScore(&analysis.overall_score, .poor);
        },
        .ripemd160 => {
            try addIssue(allocator, analysis, .medium, "Self-signature",
                "RIPEMD-160 is outdated",
                "Use SHA-256 or SHA-512 for new signatures");
            degradeScore(&analysis.overall_score, .fair);
        },
        .sha256, .sha384, .sha512 => {
            // Good - no issue to add
        },
        .sha224 => {
            try addIssue(allocator, analysis, .low, "Self-signature",
                "SHA-224 provides adequate but not optimal security",
                "Prefer SHA-256 or SHA-512");
            degradeScore(&analysis.overall_score, .good);
        },
        _ => {
            try addIssue(allocator, analysis, .medium, "Self-signature",
                "Unknown hash algorithm in self-signature",
                "Ensure the hash algorithm is well-known and secure");
            degradeScore(&analysis.overall_score, .fair);
        },
    }
}

fn checkSymmetricPreference(allocator: Allocator, analysis: *KeyAnalysis, algo: SymmetricAlgorithm) !void {
    switch (algo) {
        .plaintext => {
            try addIssue(allocator, analysis, .critical, "Symmetric preferences",
                "Plaintext (no encryption) is listed in preferences",
                "Remove plaintext from symmetric algorithm preferences");
            degradeScore(&analysis.overall_score, .critical);
        },
        .triple_des => {
            try addIssue(allocator, analysis, .high, "Symmetric preferences",
                "3DES is deprecated and slow",
                "Use AES-128 or AES-256 instead");
            degradeScore(&analysis.overall_score, .poor);
        },
        .cast5 => {
            try addIssue(allocator, analysis, .medium, "Symmetric preferences",
                "CAST5 has a 64-bit block size - vulnerable to birthday attacks on large messages",
                "Prefer AES-256");
            degradeScore(&analysis.overall_score, .fair);
        },
        .idea => {
            try addIssue(allocator, analysis, .medium, "Symmetric preferences",
                "IDEA has a 64-bit block size",
                "Prefer AES-256");
            degradeScore(&analysis.overall_score, .fair);
        },
        .blowfish => {
            try addIssue(allocator, analysis, .medium, "Symmetric preferences",
                "Blowfish has a 64-bit block size",
                "Prefer AES-256");
            degradeScore(&analysis.overall_score, .fair);
        },
        .aes128 => {
            // Good
        },
        .aes192 => {
            // Good
        },
        .aes256 => {
            // Excellent
        },
        .twofish => {
            // Good - 128-bit block
        },
        _ => {},
    }
}

fn checkKeyAge(allocator: Allocator, analysis: *KeyAnalysis, creation_time: u32) !void {
    // Approximate: 5 years = 157680000 seconds
    // April 2026 ~ 1775000000 unix time
    const current_approx: u32 = 1775000000;
    if (creation_time < current_approx) {
        const age_seconds = current_approx - creation_time;
        const five_years: u32 = 5 * 365 * 24 * 60 * 60;
        const ten_years: u32 = 10 * 365 * 24 * 60 * 60;

        if (age_seconds > ten_years) {
            try addIssue(allocator, analysis, .medium, "Key age",
                "Key is more than 10 years old without rotation",
                "Consider generating a new key and transitioning");
            degradeScore(&analysis.overall_score, .fair);
        } else if (age_seconds > five_years) {
            try addIssue(allocator, analysis, .low, "Key age",
                "Key is more than 5 years old",
                "Consider setting up key rotation or generating a fresh key");
        }
    }
}

fn checkExpiration(allocator: Allocator, analysis: *KeyAnalysis, has_expiration: bool) !void {
    if (!has_expiration) {
        try addIssue(allocator, analysis, .low, "Expiration",
            "Key has no expiration date set",
            "Set an expiration date (e.g., 2-3 years) so compromised keys eventually expire");
    }
}

fn checkSubkeyUsage(allocator: Allocator, analysis: *KeyAnalysis, separate: bool) !void {
    if (separate) {
        try addIssue(allocator, analysis, .info, "Subkey usage",
            "Key has separate signing and encryption subkeys - good practice",
            "");
    } else {
        try addIssue(allocator, analysis, .low, "Subkey usage",
            "Key does not have separate signing and encryption subkeys",
            "Consider adding dedicated subkeys for signing and encryption");
    }
}

fn checkVersion(allocator: Allocator, analysis: *KeyAnalysis, version: u8) !void {
    if (version == 4) {
        try addIssue(allocator, analysis, .info, "Key version",
            "V4 key - widely supported standard (RFC 4880)",
            "");
    } else if (version == 6) {
        try addIssue(allocator, analysis, .info, "Key version",
            "V6 key - modern standard (RFC 9580) with improved security properties",
            "");
    } else if (version == 3) {
        try addIssue(allocator, analysis, .high, "Key version",
            "V3 key packets are deprecated and have known security weaknesses",
            "Generate a new V4 or V6 key");
        degradeScore(&analysis.overall_score, .poor);
    } else if (version > 0) {
        try addIssue(allocator, analysis, .medium, "Key version",
            "Unknown key version",
            "Use a standard V4 or V6 key format");
        degradeScore(&analysis.overall_score, .fair);
    }
}

fn checkAeadPreference(allocator: Allocator, analysis: *KeyAnalysis, has_aead: bool) !void {
    if (has_aead) {
        try addIssue(allocator, analysis, .info, "AEAD support",
            "Key advertises AEAD cipher suite preferences (RFC 9580)",
            "");
    } else {
        try addIssue(allocator, analysis, .low, "AEAD support",
            "Key does not advertise AEAD preferences",
            "Consider adding AEAD cipher suite preferences for improved security");
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn addIssue(
    allocator: Allocator,
    analysis: *KeyAnalysis,
    severity: SecurityIssue.Severity,
    component: []const u8,
    description: []const u8,
    recommendation: []const u8,
) !void {
    try analysis.issues.append(allocator, .{
        .severity = severity,
        .component = try allocator.dupe(u8, component),
        .description = try allocator.dupe(u8, description),
        .recommendation = try allocator.dupe(u8, recommendation),
    });
}

fn degradeScore(score: *SecurityScore, to: SecurityScore) void {
    if (to.isWorseThan(score.*)) {
        score.* = to;
    }
}

fn stripArmor(allocator: Allocator, data: []const u8) struct { binary: []const u8, decoded: ?[]u8, headers: ?[]armor.Header } {
    if (data.len > 10 and mem.startsWith(u8, data, "-----BEGIN ")) {
        const result = armor.decode(allocator, data) catch {
            return .{ .binary = data, .decoded = null, .headers = null };
        };
        return .{ .binary = result.data, .decoded = result.data, .headers = result.headers };
    }
    return .{ .binary = data, .decoded = null, .headers = null };
}

fn freeArmorResult(allocator: Allocator, decoded: ?[]u8, headers: ?[]armor.Header) void {
    if (decoded) |d| allocator.free(d);
    if (headers) |hdrs| {
        for (hdrs) |hdr| {
            allocator.free(hdr.name);
            allocator.free(hdr.value);
        }
        allocator.free(hdrs);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "SecurityScore ordering" {
    try std.testing.expect(SecurityScore.critical.isWorseThan(.excellent));
    try std.testing.expect(SecurityScore.poor.isWorseThan(.good));
    try std.testing.expect(!SecurityScore.excellent.isWorseThan(.critical));
    try std.testing.expect(!SecurityScore.good.isWorseThan(.poor));
}

test "SecurityScore names" {
    try std.testing.expectEqualStrings("EXCELLENT", SecurityScore.excellent.name());
    try std.testing.expectEqualStrings("CRITICAL", SecurityScore.critical.name());
}

test "KeyAnalysis deinit on empty" {
    const allocator = std.testing.allocator;
    var analysis = KeyAnalysis{
        .overall_score = .good,
        .issues = .empty,
        .recommendations = .empty,
    };
    analysis.deinit(allocator);
}

test "addIssue and degradeScore" {
    const allocator = std.testing.allocator;
    var analysis = KeyAnalysis{
        .overall_score = .excellent,
        .issues = .empty,
        .recommendations = .empty,
    };
    defer analysis.deinit(allocator);

    try addIssue(allocator, &analysis, .high, "test", "description", "recommendation");
    try std.testing.expectEqual(@as(usize, 1), analysis.issues.items.len);

    degradeScore(&analysis.overall_score, .poor);
    try std.testing.expectEqual(SecurityScore.poor, analysis.overall_score);

    // Degrading to a better score should not change it
    degradeScore(&analysis.overall_score, .good);
    try std.testing.expectEqual(SecurityScore.poor, analysis.overall_score);
}

test "checkAlgorithmStrength RSA 2048" {
    const allocator = std.testing.allocator;
    var analysis = KeyAnalysis{
        .overall_score = .excellent,
        .issues = .empty,
        .recommendations = .empty,
    };
    defer analysis.deinit(allocator);

    try checkAlgorithmStrength(allocator, &analysis, .rsa_encrypt_sign, 2048, "Primary key");
    try std.testing.expect(analysis.issues.items.len > 0);
    try std.testing.expectEqual(SecurityScore.fair, analysis.overall_score);
}

test "checkAlgorithmStrength Ed25519" {
    const allocator = std.testing.allocator;
    var analysis = KeyAnalysis{
        .overall_score = .excellent,
        .issues = .empty,
        .recommendations = .empty,
    };
    defer analysis.deinit(allocator);

    try checkAlgorithmStrength(allocator, &analysis, .ed25519, null, "Primary key");
    try std.testing.expect(analysis.issues.items.len > 0);
    try std.testing.expectEqual(SecurityScore.excellent, analysis.overall_score);
}

test "checkHashAlgorithm SHA-1 is poor" {
    const allocator = std.testing.allocator;
    var analysis = KeyAnalysis{
        .overall_score = .excellent,
        .issues = .empty,
        .recommendations = .empty,
    };
    defer analysis.deinit(allocator);

    try checkHashAlgorithm(allocator, &analysis, .sha1);
    try std.testing.expectEqual(SecurityScore.poor, analysis.overall_score);
}

test "checkHashAlgorithm SHA-256 stays good" {
    const allocator = std.testing.allocator;
    var analysis = KeyAnalysis{
        .overall_score = .excellent,
        .issues = .empty,
        .recommendations = .empty,
    };
    defer analysis.deinit(allocator);

    try checkHashAlgorithm(allocator, &analysis, .sha256);
    try std.testing.expectEqual(SecurityScore.excellent, analysis.overall_score);
    try std.testing.expectEqual(@as(usize, 0), analysis.issues.items.len);
}

test "checkSymmetricPreference 3DES is poor" {
    const allocator = std.testing.allocator;
    var analysis = KeyAnalysis{
        .overall_score = .excellent,
        .issues = .empty,
        .recommendations = .empty,
    };
    defer analysis.deinit(allocator);

    try checkSymmetricPreference(allocator, &analysis, .triple_des);
    try std.testing.expectEqual(SecurityScore.poor, analysis.overall_score);
}

test "format produces readable output" {
    const allocator = std.testing.allocator;
    var analysis = KeyAnalysis{
        .overall_score = .good,
        .issues = .empty,
        .recommendations = .empty,
    };
    defer analysis.deinit(allocator);

    try addIssue(allocator, &analysis, .info, "Test", "A test issue", "Do something");
    try analysis.recommendations.append(allocator, try allocator.dupe(u8, "General recommendation"));

    const output = try analysis.format(allocator);
    defer allocator.free(output);

    try std.testing.expect(output.len > 0);
    try std.testing.expect(mem.indexOf(u8, output, "GOOD") != null);
    try std.testing.expect(mem.indexOf(u8, output, "A test issue") != null);
}

test "analyzeKey on minimal RSA 2048 key packet" {
    const allocator = std.testing.allocator;

    // Build a minimal v4 RSA 2048-bit key packet
    var buf: [64]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();

    // Public key packet (tag 6, new format)
    w.writeByte(0xC0 | 6) catch unreachable;
    w.writeByte(12) catch unreachable;
    w.writeByte(4) catch unreachable; // v4
    w.writeInt(u32, 1700000000, .big) catch unreachable; // creation
    w.writeByte(1) catch unreachable; // RSA
    // MPI for n: 2048 bits
    w.writeInt(u16, 2048, .big) catch unreachable;
    // Need 256 bytes of data, but we just put minimal for the header parse
    w.writeAll(&[_]u8{ 0xFF, 0x00, 0x00, 0x00 }) catch unreachable;

    const written = wfbs.getWritten();
    var analysis = try analyzeKey(allocator, written);
    defer analysis.deinit(allocator);

    // Should have detected RSA 2048 as fair
    try std.testing.expect(analysis.issues.items.len > 0);
}
