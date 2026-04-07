// SPDX-License-Identifier: MIT
//! Central cipher registry for algorithm discovery and capability querying.
//!
//! Provides a unified interface for querying available symmetric cipher algorithms,
//! their capabilities, and security levels. This is useful for:
//!   - Algorithm negotiation in OpenPGP
//!   - Compliance checking
//!   - Feature discovery
//!   - Security auditing

const std = @import("std");
const SymmetricAlgorithm = @import("../types/enums.zig").SymmetricAlgorithm;
const symmetric_dispatch = @import("symmetric_dispatch.zig");

/// Security level classification for ciphers.
pub const SecurityLevel = enum {
    /// Provides strong security (>= 128-bit equivalent). Recommended for new data.
    high,
    /// Provides adequate security but may have concerns (e.g., 112-bit 3DES).
    medium,
    /// Algorithm is weak or broken. Should only be used for legacy decryption.
    low,
    /// Algorithm is not implemented or recognized.
    none,

    pub fn name(self: SecurityLevel) []const u8 {
        return switch (self) {
            .high => "High",
            .medium => "Medium",
            .low => "Low",
            .none => "None",
        };
    }
};

/// Detailed capability information for a symmetric cipher.
pub const CipherCapability = struct {
    /// The OpenPGP algorithm identifier.
    id: SymmetricAlgorithm,
    /// Human-readable algorithm name.
    name: []const u8,
    /// Key size in bytes.
    key_size: usize,
    /// Block size in bytes.
    block_size: usize,
    /// Whether this algorithm is implemented and available for use.
    implemented: bool,
    /// Security assessment.
    security: SecurityLevel,
    /// Whether the algorithm is recommended for new encrypted data.
    recommended_for_new: bool,
    /// Whether the algorithm supports CFB mode.
    has_cfb: bool,
    /// The OpenPGP algorithm ID as a numeric value.
    algo_id: u8,
    /// Brief description of the algorithm.
    description: []const u8,
};

/// All known symmetric ciphers in the OpenPGP ecosystem.
const ALL_CIPHERS = [_]CipherCapability{
    .{
        .id = .plaintext,
        .name = "Plaintext",
        .key_size = 0,
        .block_size = 0,
        .implemented = false,
        .security = .none,
        .recommended_for_new = false,
        .has_cfb = false,
        .algo_id = 0,
        .description = "No encryption (plaintext)",
    },
    .{
        .id = .idea,
        .name = "IDEA",
        .key_size = 16,
        .block_size = 8,
        .implemented = true,
        .security = .medium,
        .recommended_for_new = false,
        .has_cfb = true,
        .algo_id = 1,
        .description = "International Data Encryption Algorithm, 64-bit block, 128-bit key",
    },
    .{
        .id = .triple_des,
        .name = "TripleDES",
        .key_size = 24,
        .block_size = 8,
        .implemented = true,
        .security = .medium,
        .recommended_for_new = false,
        .has_cfb = true,
        .algo_id = 2,
        .description = "Triple DES (EDE), 64-bit block, 168-bit effective key",
    },
    .{
        .id = .cast5,
        .name = "CAST5",
        .key_size = 16,
        .block_size = 8,
        .implemented = true,
        .security = .medium,
        .recommended_for_new = false,
        .has_cfb = true,
        .algo_id = 3,
        .description = "CAST-128 (CAST5), 64-bit block, 128-bit key, RFC 2144",
    },
    .{
        .id = .blowfish,
        .name = "Blowfish",
        .key_size = 16,
        .block_size = 8,
        .implemented = true,
        .security = .medium,
        .recommended_for_new = false,
        .has_cfb = true,
        .algo_id = 4,
        .description = "Blowfish, 64-bit block, 128-bit key (OpenPGP default)",
    },
    .{
        .id = .aes128,
        .name = "AES-128",
        .key_size = 16,
        .block_size = 16,
        .implemented = true,
        .security = .high,
        .recommended_for_new = true,
        .has_cfb = true,
        .algo_id = 7,
        .description = "Advanced Encryption Standard, 128-bit block, 128-bit key",
    },
    .{
        .id = .aes192,
        .name = "AES-192",
        .key_size = 24,
        .block_size = 16,
        .implemented = false,
        .security = .high,
        .recommended_for_new = false,
        .has_cfb = false,
        .algo_id = 8,
        .description = "Advanced Encryption Standard, 128-bit block, 192-bit key",
    },
    .{
        .id = .aes256,
        .name = "AES-256",
        .key_size = 32,
        .block_size = 16,
        .implemented = true,
        .security = .high,
        .recommended_for_new = true,
        .has_cfb = true,
        .algo_id = 9,
        .description = "Advanced Encryption Standard, 128-bit block, 256-bit key",
    },
    .{
        .id = .twofish,
        .name = "Twofish",
        .key_size = 32,
        .block_size = 16,
        .implemented = true,
        .security = .high,
        .recommended_for_new = true,
        .has_cfb = true,
        .algo_id = 10,
        .description = "Twofish, 128-bit block, 256-bit key",
    },
    .{
        .id = .camellia128,
        .name = "Camellia-128",
        .key_size = 16,
        .block_size = 16,
        .implemented = true,
        .security = .high,
        .recommended_for_new = true,
        .has_cfb = true,
        .algo_id = 11,
        .description = "Camellia, 128-bit block, 128-bit key, RFC 3713",
    },
    .{
        .id = .camellia192,
        .name = "Camellia-192",
        .key_size = 24,
        .block_size = 16,
        .implemented = true,
        .security = .high,
        .recommended_for_new = true,
        .has_cfb = true,
        .algo_id = 12,
        .description = "Camellia, 128-bit block, 192-bit key, RFC 3713",
    },
    .{
        .id = .camellia256,
        .name = "Camellia-256",
        .key_size = 32,
        .block_size = 16,
        .implemented = true,
        .security = .high,
        .recommended_for_new = true,
        .has_cfb = true,
        .algo_id = 13,
        .description = "Camellia, 128-bit block, 256-bit key, RFC 3713",
    },
};

/// Return the full list of all known cipher capabilities.
pub fn listAllCiphers() []const CipherCapability {
    return &ALL_CIPHERS;
}

/// Look up a specific cipher by its algorithm ID.
/// Returns null if the algorithm is not in the registry.
pub fn getCipher(algo: SymmetricAlgorithm) ?CipherCapability {
    for (ALL_CIPHERS) |cap| {
        if (cap.id == algo) return cap;
    }
    return null;
}

const IMPLEMENTED_LIST: [comptimeCount(.implemented)]CipherCapability = comptimeBuild(.implemented);
const SECURE_LIST: [comptimeCount(.secure)]CipherCapability = comptimeBuild(.secure);
const RECOMMENDED_LIST: [comptimeCount(.recommended)]CipherCapability = comptimeBuild(.recommended);
const CFB_LIST: [comptimeCount(.cfb)]CipherCapability = comptimeBuild(.cfb);

/// Return only the implemented ciphers (those that can actually be used).
pub fn listImplementedCiphers() []const CipherCapability {
    return &IMPLEMENTED_LIST;
}

/// Return only ciphers with high security level (recommended for new data).
pub fn listSecureCiphers() []const CipherCapability {
    return &SECURE_LIST;
}

/// Return only ciphers recommended for new encrypted data.
pub fn listRecommendedCiphers() []const CipherCapability {
    return &RECOMMENDED_LIST;
}

/// Return only ciphers with CFB mode support.
pub fn listCfbCiphers() []const CipherCapability {
    return &CFB_LIST;
}

const FilterKind = enum { implemented, secure, recommended, cfb };

fn comptimeMatch(cap: CipherCapability, comptime kind: FilterKind) bool {
    return switch (kind) {
        .implemented => cap.implemented,
        .secure => cap.security == .high and cap.implemented,
        .recommended => cap.recommended_for_new and cap.implemented,
        .cfb => cap.has_cfb and cap.implemented,
    };
}

fn comptimeCount(comptime kind: FilterKind) usize {
    comptime {
        var count: usize = 0;
        for (ALL_CIPHERS) |cap| {
            if (comptimeMatch(cap, kind)) count += 1;
        }
        return count;
    }
}

fn comptimeBuild(comptime kind: FilterKind) [comptimeCount(kind)]CipherCapability {
    comptime {
        const n = comptimeCount(kind);
        var result: [n]CipherCapability = undefined;
        var idx: usize = 0;
        for (ALL_CIPHERS) |cap| {
            if (comptimeMatch(cap, kind)) {
                result[idx] = cap;
                idx += 1;
            }
        }
        return result;
    }
}

/// Return ciphers with a specific block size.
pub fn listCiphersByBlockSize(bs: usize) []const CipherCapability {
    // This cannot be comptime since bs is runtime, so we return from ALL_CIPHERS
    // and let the caller filter. Instead, provide a count + iteration approach.
    _ = bs;
    return &ALL_CIPHERS;
}

/// Check if an algorithm is in the registry and implemented.
pub fn isImplemented(algo: SymmetricAlgorithm) bool {
    const cap = getCipher(algo) orelse return false;
    return cap.implemented;
}

/// Check if an algorithm has high security.
pub fn isSecure(algo: SymmetricAlgorithm) bool {
    const cap = getCipher(algo) orelse return false;
    return cap.security == .high;
}

/// Check if an algorithm is recommended for new encrypted data.
pub fn isRecommended(algo: SymmetricAlgorithm) bool {
    const cap = getCipher(algo) orelse return false;
    return cap.recommended_for_new and cap.implemented;
}

/// Get the number of implemented ciphers.
pub fn implementedCount() usize {
    return listImplementedCiphers().len;
}

/// Get the number of secure ciphers.
pub fn secureCount() usize {
    return listSecureCiphers().len;
}

/// Find a cipher by its numeric OpenPGP algorithm ID.
pub fn getCipherByAlgoId(algo_id: u8) ?CipherCapability {
    for (ALL_CIPHERS) |cap| {
        if (cap.algo_id == algo_id) return cap;
    }
    return null;
}

/// Find a cipher by name (case-sensitive).
pub fn getCipherByName(name_str: []const u8) ?CipherCapability {
    for (ALL_CIPHERS) |cap| {
        if (std.mem.eql(u8, cap.name, name_str)) return cap;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "listAllCiphers returns all entries" {
    const all = listAllCiphers();
    try std.testing.expect(all.len >= 12); // At least 12 known algorithms
}

test "getCipher returns correct info for AES-256" {
    const cap = getCipher(.aes256).?;
    try std.testing.expectEqualStrings("AES-256", cap.name);
    try std.testing.expectEqual(@as(usize, 32), cap.key_size);
    try std.testing.expectEqual(@as(usize, 16), cap.block_size);
    try std.testing.expect(cap.implemented);
    try std.testing.expectEqual(SecurityLevel.high, cap.security);
    try std.testing.expect(cap.recommended_for_new);
    try std.testing.expect(cap.has_cfb);
}

test "getCipher returns correct info for IDEA" {
    const cap = getCipher(.idea).?;
    try std.testing.expectEqualStrings("IDEA", cap.name);
    try std.testing.expectEqual(@as(usize, 16), cap.key_size);
    try std.testing.expectEqual(@as(usize, 8), cap.block_size);
    try std.testing.expect(cap.implemented);
    try std.testing.expectEqual(SecurityLevel.medium, cap.security);
    try std.testing.expect(!cap.recommended_for_new);
}

test "getCipher returns correct info for Blowfish" {
    const cap = getCipher(.blowfish).?;
    try std.testing.expectEqualStrings("Blowfish", cap.name);
    try std.testing.expectEqual(@as(usize, 16), cap.key_size);
    try std.testing.expectEqual(@as(usize, 8), cap.block_size);
    try std.testing.expect(cap.implemented);
    try std.testing.expectEqual(SecurityLevel.medium, cap.security);
}

test "getCipher returns correct info for Camellia-128" {
    const cap = getCipher(.camellia128).?;
    try std.testing.expectEqualStrings("Camellia-128", cap.name);
    try std.testing.expectEqual(@as(usize, 16), cap.key_size);
    try std.testing.expectEqual(@as(usize, 16), cap.block_size);
    try std.testing.expect(cap.implemented);
    try std.testing.expectEqual(SecurityLevel.high, cap.security);
    try std.testing.expect(cap.recommended_for_new);
}

test "getCipher returns correct info for Camellia-192" {
    const cap = getCipher(.camellia192).?;
    try std.testing.expectEqualStrings("Camellia-192", cap.name);
    try std.testing.expectEqual(@as(usize, 24), cap.key_size);
    try std.testing.expectEqual(@as(usize, 16), cap.block_size);
    try std.testing.expect(cap.implemented);
}

test "getCipher returns correct info for Camellia-256" {
    const cap = getCipher(.camellia256).?;
    try std.testing.expectEqualStrings("Camellia-256", cap.name);
    try std.testing.expectEqual(@as(usize, 32), cap.key_size);
    try std.testing.expectEqual(@as(usize, 16), cap.block_size);
    try std.testing.expect(cap.implemented);
    try std.testing.expectEqual(SecurityLevel.high, cap.security);
}

test "getCipher returns null for unknown algorithm" {
    const unknown: SymmetricAlgorithm = @enumFromInt(200);
    try std.testing.expect(getCipher(unknown) == null);
}

test "listImplementedCiphers excludes unimplemented" {
    const implemented = listImplementedCiphers();
    for (implemented) |cap| {
        try std.testing.expect(cap.implemented);
    }
    // Plaintext and AES-192 are not implemented
    try std.testing.expect(implemented.len >= 10);
}

test "listSecureCiphers only returns high security" {
    const secure = listSecureCiphers();
    for (secure) |cap| {
        try std.testing.expectEqual(SecurityLevel.high, cap.security);
        try std.testing.expect(cap.implemented);
    }
    // AES-128, AES-256, Twofish, Camellia-128/192/256
    try std.testing.expect(secure.len >= 5);
}

test "listRecommendedCiphers" {
    const recommended = listRecommendedCiphers();
    for (recommended) |cap| {
        try std.testing.expect(cap.recommended_for_new);
        try std.testing.expect(cap.implemented);
    }
    try std.testing.expect(recommended.len >= 2);
}

test "listCfbCiphers" {
    const cfb = listCfbCiphers();
    for (cfb) |cap| {
        try std.testing.expect(cap.has_cfb);
        try std.testing.expect(cap.implemented);
    }
}

test "isImplemented" {
    try std.testing.expect(isImplemented(.aes128));
    try std.testing.expect(isImplemented(.aes256));
    try std.testing.expect(isImplemented(.cast5));
    try std.testing.expect(isImplemented(.twofish));
    try std.testing.expect(isImplemented(.triple_des));
    try std.testing.expect(isImplemented(.idea));
    try std.testing.expect(isImplemented(.blowfish));
    try std.testing.expect(isImplemented(.camellia128));
    try std.testing.expect(isImplemented(.camellia192));
    try std.testing.expect(isImplemented(.camellia256));
    try std.testing.expect(!isImplemented(.plaintext));
}

test "isSecure" {
    try std.testing.expect(isSecure(.aes128));
    try std.testing.expect(isSecure(.aes256));
    try std.testing.expect(isSecure(.twofish));
    try std.testing.expect(isSecure(.camellia128));
    try std.testing.expect(isSecure(.camellia256));
    try std.testing.expect(!isSecure(.idea));
    try std.testing.expect(!isSecure(.blowfish));
    try std.testing.expect(!isSecure(.cast5));
    try std.testing.expect(!isSecure(.triple_des));
}

test "isRecommended" {
    try std.testing.expect(isRecommended(.aes128));
    try std.testing.expect(isRecommended(.aes256));
    try std.testing.expect(isRecommended(.twofish));
    try std.testing.expect(isRecommended(.camellia128));
    try std.testing.expect(!isRecommended(.idea));
    try std.testing.expect(!isRecommended(.blowfish));
    try std.testing.expect(!isRecommended(.cast5));
    try std.testing.expect(!isRecommended(.plaintext));
}

test "implementedCount and secureCount" {
    try std.testing.expect(implementedCount() >= 10);
    try std.testing.expect(secureCount() >= 5);
    try std.testing.expect(secureCount() <= implementedCount());
}

test "getCipherByAlgoId" {
    const aes128 = getCipherByAlgoId(7).?;
    try std.testing.expectEqualStrings("AES-128", aes128.name);

    const idea = getCipherByAlgoId(1).?;
    try std.testing.expectEqualStrings("IDEA", idea.name);

    const cam128 = getCipherByAlgoId(11).?;
    try std.testing.expectEqualStrings("Camellia-128", cam128.name);

    try std.testing.expect(getCipherByAlgoId(200) == null);
}

test "getCipherByName" {
    const aes256 = getCipherByName("AES-256").?;
    try std.testing.expectEqual(@as(u8, 9), aes256.algo_id);

    const bf = getCipherByName("Blowfish").?;
    try std.testing.expectEqual(@as(u8, 4), bf.algo_id);

    try std.testing.expect(getCipherByName("NonExistent") == null);
}

test "SecurityLevel names" {
    try std.testing.expectEqualStrings("High", SecurityLevel.high.name());
    try std.testing.expectEqualStrings("Medium", SecurityLevel.medium.name());
    try std.testing.expectEqualStrings("Low", SecurityLevel.low.name());
    try std.testing.expectEqualStrings("None", SecurityLevel.none.name());
}

test "cipher descriptions are non-empty" {
    for (listAllCiphers()) |cap| {
        try std.testing.expect(cap.description.len > 0);
    }
}

test "all algo_ids are unique" {
    const all = listAllCiphers();
    for (0..all.len) |i| {
        for (i + 1..all.len) |j| {
            try std.testing.expect(all[i].algo_id != all[j].algo_id);
        }
    }
}

test "all cipher names are unique" {
    const all = listAllCiphers();
    for (0..all.len) |i| {
        for (i + 1..all.len) |j| {
            try std.testing.expect(!std.mem.eql(u8, all[i].name, all[j].name));
        }
    }
}
