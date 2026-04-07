// SPDX-License-Identifier: MIT
//! Algorithm deprecation warnings per RFC 9580.
//!
//! RFC 9580 Section 9 specifies which algorithms are MUST, SHOULD, MAY,
//! or MUST NOT implement. This module classifies algorithms by security
//! level and provides advisory warnings for deprecated/insecure choices.
//!
//! Security levels:
//! - secure:     Algorithm is recommended for current use
//! - deprecated: Algorithm should not be used for new data, but may be
//!               encountered in existing messages
//! - insecure:   Algorithm has known weaknesses and MUST NOT be used
//! - unknown:    Algorithm is not recognized

const std = @import("std");
const PublicKeyAlgorithm = @import("../types/enums.zig").PublicKeyAlgorithm;
const SymmetricAlgorithm = @import("../types/enums.zig").SymmetricAlgorithm;
const HashAlgorithm = @import("../types/enums.zig").HashAlgorithm;

/// Security classification for an algorithm.
pub const SecurityLevel = enum {
    secure,
    deprecated,
    insecure,
    unknown,

    pub fn name(self: SecurityLevel) []const u8 {
        return switch (self) {
            .secure => "Secure",
            .deprecated => "Deprecated",
            .insecure => "Insecure",
            .unknown => "Unknown",
        };
    }

    /// Whether this level is considered safe for new message creation.
    pub fn isSafeForCreation(self: SecurityLevel) bool {
        return self == .secure;
    }

    /// Whether this level is acceptable for verification/decryption
    /// of existing messages (more permissive).
    pub fn isAcceptableForVerification(self: SecurityLevel) bool {
        return self == .secure or self == .deprecated;
    }
};

/// Assess the security level of a public key algorithm.
///
/// RFC 9580 deprecations:
/// - RSA < 2048 bits is deprecated (checked separately with key size)
/// - ElGamal is deprecated
/// - DSA is deprecated
/// - Legacy EdDSA (22) is deprecated in favor of native Ed25519 (27)
/// - Native Ed25519 (27) and X25519 (25) are secure
pub fn assessPublicKeyAlgorithm(algo: PublicKeyAlgorithm) SecurityLevel {
    return switch (algo) {
        .rsa_encrypt_sign, .rsa_encrypt_only, .rsa_sign_only => .secure,
        .ecdh => .secure,
        .ecdsa => .secure,
        .eddsa => .deprecated, // Legacy EdDSA; use native Ed25519 (27) instead
        .elgamal => .deprecated,
        .dsa => .deprecated,
        .x25519, .x448, .ed25519, .ed448 => .secure, // RFC 9580 native
        _ => .unknown,
    };
}

/// Assess the security level of a public key algorithm with key size context.
///
/// RSA keys smaller than 2048 bits are deprecated per RFC 9580.
/// RSA keys smaller than 1024 bits are considered insecure.
pub fn assessPublicKeyWithSize(algo: PublicKeyAlgorithm, key_bits: u32) SecurityLevel {
    const base = assessPublicKeyAlgorithm(algo);
    if (base != .secure) return base;

    switch (algo) {
        .rsa_encrypt_sign, .rsa_encrypt_only, .rsa_sign_only => {
            if (key_bits < 1024) return .insecure;
            if (key_bits < 2048) return .deprecated;
            return .secure;
        },
        else => return base,
    }
}

/// Assess the security level of a symmetric algorithm.
///
/// RFC 9580 deprecations:
/// - IDEA: deprecated
/// - TripleDES: deprecated
/// - CAST5: deprecated
/// - Blowfish: deprecated (never was in the standard, implementation-defined)
/// - AES-128/192/256: secure
/// - Twofish: secure
pub fn assessSymmetricAlgorithm(algo: SymmetricAlgorithm) SecurityLevel {
    return switch (algo) {
        .plaintext => .insecure, // No encryption
        .idea => .deprecated,
        .triple_des => .deprecated,
        .cast5 => .deprecated,
        .blowfish => .deprecated,
        .aes128 => .secure,
        .aes192 => .secure,
        .aes256 => .secure,
        .twofish => .secure,
        .camellia128 => .secure,
        .camellia192 => .secure,
        .camellia256 => .secure,
        _ => .unknown,
    };
}

/// Assess the security level of a hash algorithm.
///
/// RFC 9580 deprecations:
/// - MD5: insecure (collision attacks since 2004)
/// - SHA-1: deprecated for signatures (still acceptable for fingerprints)
/// - RIPEMD-160: deprecated
/// - SHA-224: deprecated (truncated SHA-256, rarely used in OpenPGP)
/// - SHA-256/384/512: secure
pub fn assessHashAlgorithm(algo: HashAlgorithm) SecurityLevel {
    return switch (algo) {
        .md5 => .insecure,
        .sha1 => .deprecated,
        .ripemd160 => .deprecated,
        .sha224 => .deprecated,
        .sha256 => .secure,
        .sha384 => .secure,
        .sha512 => .secure,
        _ => .unknown,
    };
}

/// Get a human-readable deprecation warning message.
///
/// Returns null if the algorithm is secure (no warning needed).
pub fn getDeprecationWarning(algo_name: []const u8, level: SecurityLevel) ?[]const u8 {
    return switch (level) {
        .secure => null,
        .deprecated => blk: {
            _ = algo_name;
            break :blk "This algorithm is deprecated and should not be used for new messages. Consider upgrading to a more secure alternative.";
        },
        .insecure => blk: {
            _ = algo_name;
            break :blk "This algorithm is insecure and MUST NOT be used. It has known cryptographic weaknesses.";
        },
        .unknown => blk: {
            _ = algo_name;
            break :blk "This algorithm is not recognized. It may not be interoperable with other implementations.";
        },
    };
}

/// Check if a hash algorithm is acceptable for digital signatures.
///
/// SHA-1 is deprecated for signatures per RFC 9580, but still acceptable
/// for V4 fingerprint calculation (where it's mandatory).
pub fn isHashAcceptableForSignatures(algo: HashAlgorithm) bool {
    return switch (algo) {
        .sha256, .sha384, .sha512 => true,
        else => false,
    };
}

/// Check if a hash algorithm is acceptable for V4 fingerprint calculation.
///
/// V4 fingerprints always use SHA-1 per RFC 4880, so SHA-1 is acceptable here.
pub fn isHashAcceptableForFingerprint(algo: HashAlgorithm) bool {
    return switch (algo) {
        .sha1 => true, // Required for V4 fingerprints
        .sha256 => true, // Used for V6 fingerprints
        else => false,
    };
}

/// Get the recommended replacement for a deprecated algorithm.
pub fn getRecommendedReplacement(algo_name: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, algo_name, "IDEA")) return "AES-128";
    if (std.mem.eql(u8, algo_name, "TripleDES")) return "AES-128";
    if (std.mem.eql(u8, algo_name, "CAST5")) return "AES-128";
    if (std.mem.eql(u8, algo_name, "Blowfish")) return "AES-128";
    if (std.mem.eql(u8, algo_name, "MD5")) return "SHA-256";
    if (std.mem.eql(u8, algo_name, "SHA1")) return "SHA-256";
    if (std.mem.eql(u8, algo_name, "RIPEMD160")) return "SHA-256";
    if (std.mem.eql(u8, algo_name, "DSA")) return "Ed25519 (algorithm 27)";
    if (std.mem.eql(u8, algo_name, "ElGamal")) return "X25519 (algorithm 25)";
    if (std.mem.eql(u8, algo_name, "EdDSA")) return "Ed25519 (algorithm 27)";
    return null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "SecurityLevel names" {
    try std.testing.expectEqualStrings("Secure", SecurityLevel.secure.name());
    try std.testing.expectEqualStrings("Deprecated", SecurityLevel.deprecated.name());
    try std.testing.expectEqualStrings("Insecure", SecurityLevel.insecure.name());
    try std.testing.expectEqualStrings("Unknown", SecurityLevel.unknown.name());
}

test "SecurityLevel safety checks" {
    try std.testing.expect(SecurityLevel.secure.isSafeForCreation());
    try std.testing.expect(!SecurityLevel.deprecated.isSafeForCreation());
    try std.testing.expect(!SecurityLevel.insecure.isSafeForCreation());
    try std.testing.expect(!SecurityLevel.unknown.isSafeForCreation());

    try std.testing.expect(SecurityLevel.secure.isAcceptableForVerification());
    try std.testing.expect(SecurityLevel.deprecated.isAcceptableForVerification());
    try std.testing.expect(!SecurityLevel.insecure.isAcceptableForVerification());
    try std.testing.expect(!SecurityLevel.unknown.isAcceptableForVerification());
}

test "assessPublicKeyAlgorithm" {
    try std.testing.expectEqual(SecurityLevel.secure, assessPublicKeyAlgorithm(.rsa_encrypt_sign));
    try std.testing.expectEqual(SecurityLevel.secure, assessPublicKeyAlgorithm(.ecdh));
    try std.testing.expectEqual(SecurityLevel.secure, assessPublicKeyAlgorithm(.ecdsa));
    try std.testing.expectEqual(SecurityLevel.deprecated, assessPublicKeyAlgorithm(.eddsa));
    try std.testing.expectEqual(SecurityLevel.deprecated, assessPublicKeyAlgorithm(.elgamal));
    try std.testing.expectEqual(SecurityLevel.deprecated, assessPublicKeyAlgorithm(.dsa));

    // Native RFC 9580 algorithms
    const x25519: PublicKeyAlgorithm = @enumFromInt(25);
    try std.testing.expectEqual(SecurityLevel.secure, assessPublicKeyAlgorithm(x25519));
    const ed25519: PublicKeyAlgorithm = @enumFromInt(27);
    try std.testing.expectEqual(SecurityLevel.secure, assessPublicKeyAlgorithm(ed25519));
    const x448: PublicKeyAlgorithm = @enumFromInt(26);
    try std.testing.expectEqual(SecurityLevel.secure, assessPublicKeyAlgorithm(x448));
    const ed448: PublicKeyAlgorithm = @enumFromInt(28);
    try std.testing.expectEqual(SecurityLevel.secure, assessPublicKeyAlgorithm(ed448));

    // Unknown
    const unknown: PublicKeyAlgorithm = @enumFromInt(99);
    try std.testing.expectEqual(SecurityLevel.unknown, assessPublicKeyAlgorithm(unknown));
}

test "assessPublicKeyWithSize RSA" {
    try std.testing.expectEqual(SecurityLevel.insecure, assessPublicKeyWithSize(.rsa_encrypt_sign, 512));
    try std.testing.expectEqual(SecurityLevel.deprecated, assessPublicKeyWithSize(.rsa_encrypt_sign, 1024));
    try std.testing.expectEqual(SecurityLevel.secure, assessPublicKeyWithSize(.rsa_encrypt_sign, 2048));
    try std.testing.expectEqual(SecurityLevel.secure, assessPublicKeyWithSize(.rsa_encrypt_sign, 4096));

    // Non-RSA algorithms ignore key size
    try std.testing.expectEqual(SecurityLevel.deprecated, assessPublicKeyWithSize(.dsa, 4096));
}

test "assessSymmetricAlgorithm" {
    try std.testing.expectEqual(SecurityLevel.insecure, assessSymmetricAlgorithm(.plaintext));
    try std.testing.expectEqual(SecurityLevel.deprecated, assessSymmetricAlgorithm(.idea));
    try std.testing.expectEqual(SecurityLevel.deprecated, assessSymmetricAlgorithm(.triple_des));
    try std.testing.expectEqual(SecurityLevel.deprecated, assessSymmetricAlgorithm(.cast5));
    try std.testing.expectEqual(SecurityLevel.deprecated, assessSymmetricAlgorithm(.blowfish));
    try std.testing.expectEqual(SecurityLevel.secure, assessSymmetricAlgorithm(.aes128));
    try std.testing.expectEqual(SecurityLevel.secure, assessSymmetricAlgorithm(.aes192));
    try std.testing.expectEqual(SecurityLevel.secure, assessSymmetricAlgorithm(.aes256));
    try std.testing.expectEqual(SecurityLevel.secure, assessSymmetricAlgorithm(.twofish));
}

test "assessHashAlgorithm" {
    try std.testing.expectEqual(SecurityLevel.insecure, assessHashAlgorithm(.md5));
    try std.testing.expectEqual(SecurityLevel.deprecated, assessHashAlgorithm(.sha1));
    try std.testing.expectEqual(SecurityLevel.deprecated, assessHashAlgorithm(.ripemd160));
    try std.testing.expectEqual(SecurityLevel.deprecated, assessHashAlgorithm(.sha224));
    try std.testing.expectEqual(SecurityLevel.secure, assessHashAlgorithm(.sha256));
    try std.testing.expectEqual(SecurityLevel.secure, assessHashAlgorithm(.sha384));
    try std.testing.expectEqual(SecurityLevel.secure, assessHashAlgorithm(.sha512));
}

test "getDeprecationWarning" {
    try std.testing.expect(getDeprecationWarning("AES-256", .secure) == null);
    try std.testing.expect(getDeprecationWarning("CAST5", .deprecated) != null);
    try std.testing.expect(getDeprecationWarning("MD5", .insecure) != null);
    try std.testing.expect(getDeprecationWarning("Unknown", .unknown) != null);
}

test "isHashAcceptableForSignatures" {
    try std.testing.expect(!isHashAcceptableForSignatures(.md5));
    try std.testing.expect(!isHashAcceptableForSignatures(.sha1));
    try std.testing.expect(!isHashAcceptableForSignatures(.ripemd160));
    try std.testing.expect(isHashAcceptableForSignatures(.sha256));
    try std.testing.expect(isHashAcceptableForSignatures(.sha384));
    try std.testing.expect(isHashAcceptableForSignatures(.sha512));
}

test "isHashAcceptableForFingerprint" {
    try std.testing.expect(isHashAcceptableForFingerprint(.sha1));
    try std.testing.expect(isHashAcceptableForFingerprint(.sha256));
    try std.testing.expect(!isHashAcceptableForFingerprint(.md5));
    try std.testing.expect(!isHashAcceptableForFingerprint(.sha512));
}

test "getRecommendedReplacement" {
    try std.testing.expectEqualStrings("AES-128", getRecommendedReplacement("IDEA").?);
    try std.testing.expectEqualStrings("AES-128", getRecommendedReplacement("TripleDES").?);
    try std.testing.expectEqualStrings("AES-128", getRecommendedReplacement("CAST5").?);
    try std.testing.expectEqualStrings("SHA-256", getRecommendedReplacement("MD5").?);
    try std.testing.expectEqualStrings("SHA-256", getRecommendedReplacement("SHA1").?);
    try std.testing.expectEqualStrings("Ed25519 (algorithm 27)", getRecommendedReplacement("DSA").?);
    try std.testing.expectEqualStrings("X25519 (algorithm 25)", getRecommendedReplacement("ElGamal").?);
    try std.testing.expectEqualStrings("Ed25519 (algorithm 27)", getRecommendedReplacement("EdDSA").?);
    try std.testing.expect(getRecommendedReplacement("AES-256") == null);
}
