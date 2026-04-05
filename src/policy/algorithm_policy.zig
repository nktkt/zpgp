// SPDX-License-Identifier: MIT
//! Algorithm selection policy engine for OpenPGP.
//!
//! Different deployments and standards require different levels of algorithm
//! acceptance. This module provides a configurable policy engine that can
//! evaluate whether particular algorithms meet the requirements of a given
//! security level.
//!
//! Policy levels:
//!   - **rfc4880**: Accept all algorithms defined in RFC 4880. This includes
//!     legacy algorithms like 3DES, CAST5, and SHA-1 for maximum compatibility.
//!   - **rfc9580**: Prefer RFC 9580 algorithms (AES, SHA-256+, AEAD) but
//!     still accept RFC 4880 algorithms with warnings.
//!   - **strict**: Only accept algorithms considered secure by RFC 9580.
//!     Rejects MD5, SHA-1, 3DES, CAST5, Blowfish, IDEA, and small RSA keys.
//!   - **custom**: User-defined policy (for future extensibility).

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const enums = @import("../types/enums.zig");
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const AeadAlgorithm = enums.AeadAlgorithm;

/// The security policy level governing algorithm acceptance.
pub const PolicyLevel = enum {
    /// Accept all RFC 4880 algorithms (maximum compatibility).
    rfc4880,
    /// Prefer RFC 9580, allow legacy with warnings.
    rfc9580,
    /// Only RFC 9580 secure algorithms (maximum security).
    strict,
    /// User-defined custom policy.
    custom,
};

/// Result of validating an algorithm or key against the policy.
pub const ValidationResult = struct {
    /// Whether the algorithm/key is accepted under this policy.
    accepted: bool,
    /// Warning messages (e.g., "SHA-1 is deprecated"). Static strings.
    warnings: []const []const u8,
    /// An optional recommendation (e.g., "Consider upgrading to AES-256").
    recommendation: ?[]const u8,
};

/// Algorithm selection and validation policy.
///
/// Use `init` to create a policy at a given level, then call the
/// `isAcceptable*` methods to check individual algorithms or the
/// `validate*` methods for detailed reports.
pub const AlgorithmPolicy = struct {
    level: PolicyLevel,

    /// Create a new policy at the specified level.
    pub fn init(level: PolicyLevel) AlgorithmPolicy {
        return .{ .level = level };
    }

    // -----------------------------------------------------------------
    // Symmetric algorithm checks
    // -----------------------------------------------------------------

    /// Check if a symmetric algorithm is acceptable under this policy.
    pub fn isAcceptableSymmetric(self: AlgorithmPolicy, algo: SymmetricAlgorithm) bool {
        return switch (self.level) {
            .rfc4880 => switch (algo) {
                .idea, .triple_des, .cast5, .blowfish => true,
                .aes128, .aes192, .aes256 => true,
                .twofish => true,
                .plaintext => false,
                _ => false,
            },
            .rfc9580 => switch (algo) {
                .aes128, .aes192, .aes256 => true,
                .twofish => true,
                // Legacy allowed with warnings
                .triple_des, .cast5, .blowfish, .idea => true,
                .plaintext => false,
                _ => false,
            },
            .strict => switch (algo) {
                .aes128, .aes192, .aes256 => true,
                .twofish => true,
                else => false,
            },
            .custom => true,
        };
    }

    /// Check if a symmetric algorithm has warnings under this policy.
    fn symmetricWarnings(self: AlgorithmPolicy, algo: SymmetricAlgorithm) []const []const u8 {
        if (self.level == .rfc9580) {
            return switch (algo) {
                .triple_des => &[_][]const u8{"3DES is deprecated; use AES-256"},
                .cast5 => &[_][]const u8{"CAST5 is deprecated; use AES-256"},
                .blowfish => &[_][]const u8{"Blowfish is deprecated; use AES-256"},
                .idea => &[_][]const u8{"IDEA is deprecated; use AES-256"},
                else => &[_][]const u8{},
            };
        }
        return &[_][]const u8{};
    }

    // -----------------------------------------------------------------
    // Hash algorithm checks
    // -----------------------------------------------------------------

    /// Check if a hash algorithm is acceptable under this policy.
    pub fn isAcceptableHash(self: AlgorithmPolicy, algo: HashAlgorithm) bool {
        return switch (self.level) {
            .rfc4880 => switch (algo) {
                .md5, .sha1, .ripemd160 => true,
                .sha256, .sha384, .sha512, .sha224 => true,
                _ => false,
            },
            .rfc9580 => switch (algo) {
                .sha256, .sha384, .sha512 => true,
                // Legacy allowed with warnings
                .sha1, .sha224, .ripemd160 => true,
                .md5 => false,
                _ => false,
            },
            .strict => switch (algo) {
                .sha256, .sha384, .sha512 => true,
                else => false,
            },
            .custom => true,
        };
    }

    /// Check if a hash algorithm has warnings under this policy.
    fn hashWarnings(self: AlgorithmPolicy, algo: HashAlgorithm) []const []const u8 {
        if (self.level == .rfc9580) {
            return switch (algo) {
                .sha1 => &[_][]const u8{"SHA-1 is deprecated for signatures; use SHA-256 or SHA-512"},
                .sha224 => &[_][]const u8{"SHA-224 offers limited security margin; consider SHA-256"},
                .ripemd160 => &[_][]const u8{"RIPEMD-160 is deprecated; use SHA-256"},
                else => &[_][]const u8{},
            };
        }
        return &[_][]const u8{};
    }

    // -----------------------------------------------------------------
    // Public key algorithm checks
    // -----------------------------------------------------------------

    /// Check if a public key algorithm (with optional bit size) is acceptable.
    ///
    /// `bits` is the key size in bits, relevant for RSA and DSA.
    /// For elliptic curve algorithms, `bits` is ignored.
    pub fn isAcceptablePublicKey(self: AlgorithmPolicy, algo: PublicKeyAlgorithm, bits: ?u32) bool {
        return switch (self.level) {
            .rfc4880 => switch (algo) {
                .rsa_encrypt_sign, .rsa_encrypt_only, .rsa_sign_only => {
                    if (bits) |b| return b >= 1024;
                    return true;
                },
                .dsa, .elgamal => true,
                .ecdh, .ecdsa, .eddsa => true,
                .x25519, .x448, .ed25519, .ed448 => true,
                _ => false,
            },
            .rfc9580 => switch (algo) {
                .rsa_encrypt_sign, .rsa_encrypt_only, .rsa_sign_only => {
                    if (bits) |b| return b >= 2048;
                    return true;
                },
                .dsa => true, // Allowed with warnings
                .elgamal => true,
                .ecdh, .ecdsa, .eddsa => true,
                .x25519, .x448, .ed25519, .ed448 => true,
                _ => false,
            },
            .strict => switch (algo) {
                .rsa_encrypt_sign, .rsa_encrypt_only, .rsa_sign_only => {
                    if (bits) |b| return b >= 3072;
                    return true;
                },
                .ecdh, .ecdsa => true,
                .x25519, .x448, .ed25519, .ed448 => true,
                // DSA, ElGamal, legacy EdDSA rejected
                else => false,
            },
            .custom => true,
        };
    }

    // -----------------------------------------------------------------
    // AEAD algorithm checks
    // -----------------------------------------------------------------

    /// Check if an AEAD algorithm is acceptable under this policy.
    pub fn isAcceptableAead(self: AlgorithmPolicy, algo: AeadAlgorithm) bool {
        return switch (self.level) {
            .rfc4880 => false, // RFC 4880 has no AEAD
            .rfc9580, .strict => switch (algo) {
                .eax, .ocb, .gcm => true,
                _ => false,
            },
            .custom => true,
        };
    }

    // -----------------------------------------------------------------
    // Preferred algorithm selection
    // -----------------------------------------------------------------

    /// Return the preferred symmetric algorithm for this policy level.
    pub fn preferredSymmetric(self: AlgorithmPolicy) SymmetricAlgorithm {
        return switch (self.level) {
            .rfc4880 => .aes128,
            .rfc9580, .strict => .aes256,
            .custom => .aes256,
        };
    }

    /// Return the preferred hash algorithm for this policy level.
    pub fn preferredHash(self: AlgorithmPolicy) HashAlgorithm {
        return switch (self.level) {
            .rfc4880 => .sha256,
            .rfc9580, .strict => .sha256,
            .custom => .sha256,
        };
    }

    /// Return the preferred AEAD algorithm, or null if AEAD is not supported.
    pub fn preferredAead(self: AlgorithmPolicy) ?AeadAlgorithm {
        return switch (self.level) {
            .rfc4880 => null,
            .rfc9580 => .gcm,
            .strict => .gcm,
            .custom => .gcm,
        };
    }

    // -----------------------------------------------------------------
    // Detailed validation
    // -----------------------------------------------------------------

    /// Validate a public key algorithm and size, returning a detailed report.
    pub fn validateKey(self: AlgorithmPolicy, key_algo: PublicKeyAlgorithm, bits: ?u32) ValidationResult {
        const accepted = self.isAcceptablePublicKey(key_algo, bits);

        if (self.level == .rfc9580) {
            // Check for warnings
            switch (key_algo) {
                .dsa => return .{
                    .accepted = accepted,
                    .warnings = &[_][]const u8{"DSA is deprecated; consider Ed25519"},
                    .recommendation = "Migrate to Ed25519 or Ed448",
                },
                .rsa_encrypt_sign, .rsa_encrypt_only, .rsa_sign_only => {
                    if (bits) |b| {
                        if (b < 3072) {
                            return .{
                                .accepted = accepted,
                                .warnings = &[_][]const u8{"RSA keys smaller than 3072 bits are not recommended"},
                                .recommendation = "Use RSA-3072 or RSA-4096",
                            };
                        }
                    }
                },
                .eddsa => return .{
                    .accepted = accepted,
                    .warnings = &[_][]const u8{"Legacy EdDSA encoding; prefer native Ed25519 (algo 27)"},
                    .recommendation = "Generate a V6 Ed25519 key",
                },
                else => {},
            }
        }

        if (!accepted) {
            return .{
                .accepted = false,
                .warnings = &[_][]const u8{},
                .recommendation = "Algorithm not accepted under current policy",
            };
        }

        return .{
            .accepted = true,
            .warnings = &[_][]const u8{},
            .recommendation = null,
        };
    }

    /// Validate a signature's algorithm combination.
    pub fn validateSignature(
        self: AlgorithmPolicy,
        hash_algo: HashAlgorithm,
        pub_algo: PublicKeyAlgorithm,
    ) ValidationResult {
        const hash_ok = self.isAcceptableHash(hash_algo);
        const pub_ok = self.isAcceptablePublicKey(pub_algo, null);

        if (!hash_ok or !pub_ok) {
            var warnings_buf: [2][]const u8 = undefined;
            var warning_count: usize = 0;

            if (!hash_ok) {
                warnings_buf[warning_count] = "Hash algorithm not accepted";
                warning_count += 1;
            }
            if (!pub_ok) {
                warnings_buf[warning_count] = "Public key algorithm not accepted";
                warning_count += 1;
            }

            // Return static warnings based on what failed
            if (!hash_ok and !pub_ok) {
                return .{
                    .accepted = false,
                    .warnings = &[_][]const u8{ "Hash algorithm not accepted", "Public key algorithm not accepted" },
                    .recommendation = "Upgrade both hash and key algorithms",
                };
            } else if (!hash_ok) {
                return .{
                    .accepted = false,
                    .warnings = &[_][]const u8{"Hash algorithm not accepted"},
                    .recommendation = "Use SHA-256 or SHA-512",
                };
            } else {
                return .{
                    .accepted = false,
                    .warnings = &[_][]const u8{"Public key algorithm not accepted"},
                    .recommendation = "Upgrade key algorithm",
                };
            }
        }

        // Both accepted, but check for warnings
        const hash_warns = self.hashWarnings(hash_algo);
        const sym_warns = self.symmetricWarnings(.aes256); // placeholder
        _ = sym_warns;

        if (hash_warns.len > 0) {
            return .{
                .accepted = true,
                .warnings = hash_warns,
                .recommendation = null,
            };
        }

        return .{
            .accepted = true,
            .warnings = &[_][]const u8{},
            .recommendation = null,
        };
    }

    /// Check if a complete algorithm suite is acceptable.
    ///
    /// This validates the combination of symmetric, hash, and public key
    /// algorithms that would be used in a message.
    pub fn validateSuite(
        self: AlgorithmPolicy,
        sym_algo: SymmetricAlgorithm,
        hash_algo: HashAlgorithm,
        pub_algo: PublicKeyAlgorithm,
        key_bits: ?u32,
    ) ValidationResult {
        const sym_ok = self.isAcceptableSymmetric(sym_algo);
        const hash_ok = self.isAcceptableHash(hash_algo);
        const pub_ok = self.isAcceptablePublicKey(pub_algo, key_bits);

        if (!sym_ok or !hash_ok or !pub_ok) {
            return .{
                .accepted = false,
                .warnings = &[_][]const u8{"One or more algorithms in the suite are not accepted"},
                .recommendation = "Review algorithm choices against the current policy level",
            };
        }

        return .{
            .accepted = true,
            .warnings = &[_][]const u8{},
            .recommendation = null,
        };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "AlgorithmPolicy rfc4880 accepts legacy" {
    const policy = AlgorithmPolicy.init(.rfc4880);
    try std.testing.expect(policy.isAcceptableSymmetric(.cast5));
    try std.testing.expect(policy.isAcceptableSymmetric(.triple_des));
    try std.testing.expect(policy.isAcceptableHash(.md5));
    try std.testing.expect(policy.isAcceptableHash(.sha1));
    try std.testing.expect(policy.isAcceptablePublicKey(.dsa, null));
    try std.testing.expect(!policy.isAcceptableAead(.gcm)); // No AEAD in 4880
}

test "AlgorithmPolicy rfc9580 rejects md5" {
    const policy = AlgorithmPolicy.init(.rfc9580);
    try std.testing.expect(!policy.isAcceptableHash(.md5));
    try std.testing.expect(policy.isAcceptableHash(.sha256));
    try std.testing.expect(policy.isAcceptableHash(.sha1)); // Allowed with warning
    try std.testing.expect(policy.isAcceptableAead(.gcm));
}

test "AlgorithmPolicy strict rejects legacy" {
    const policy = AlgorithmPolicy.init(.strict);
    try std.testing.expect(!policy.isAcceptableSymmetric(.cast5));
    try std.testing.expect(!policy.isAcceptableSymmetric(.triple_des));
    try std.testing.expect(!policy.isAcceptableSymmetric(.idea));
    try std.testing.expect(!policy.isAcceptableHash(.sha1));
    try std.testing.expect(!policy.isAcceptableHash(.md5));
    try std.testing.expect(!policy.isAcceptablePublicKey(.dsa, null));
    try std.testing.expect(policy.isAcceptableSymmetric(.aes256));
    try std.testing.expect(policy.isAcceptableHash(.sha256));
}

test "AlgorithmPolicy strict RSA minimum bits" {
    const policy = AlgorithmPolicy.init(.strict);
    try std.testing.expect(!policy.isAcceptablePublicKey(.rsa_encrypt_sign, 2048));
    try std.testing.expect(policy.isAcceptablePublicKey(.rsa_encrypt_sign, 3072));
    try std.testing.expect(policy.isAcceptablePublicKey(.rsa_encrypt_sign, 4096));
}

test "AlgorithmPolicy preferred algorithms" {
    const rfc4880 = AlgorithmPolicy.init(.rfc4880);
    try std.testing.expectEqual(SymmetricAlgorithm.aes128, rfc4880.preferredSymmetric());
    try std.testing.expect(rfc4880.preferredAead() == null);

    const strict = AlgorithmPolicy.init(.strict);
    try std.testing.expectEqual(SymmetricAlgorithm.aes256, strict.preferredSymmetric());
    try std.testing.expectEqual(AeadAlgorithm.gcm, strict.preferredAead().?);
}

test "AlgorithmPolicy validateKey with warnings" {
    const policy = AlgorithmPolicy.init(.rfc9580);
    const result = policy.validateKey(.dsa, null);
    try std.testing.expect(result.accepted);
    try std.testing.expect(result.warnings.len > 0);
    try std.testing.expect(result.recommendation != null);
}

test "AlgorithmPolicy validateKey strict rejection" {
    const policy = AlgorithmPolicy.init(.strict);
    const result = policy.validateKey(.dsa, null);
    try std.testing.expect(!result.accepted);
}

test "AlgorithmPolicy validateSignature" {
    const policy = AlgorithmPolicy.init(.strict);

    const good = policy.validateSignature(.sha256, .ed25519);
    try std.testing.expect(good.accepted);

    const bad = policy.validateSignature(.md5, .rsa_encrypt_sign);
    try std.testing.expect(!bad.accepted);
}

test "AlgorithmPolicy validateSuite" {
    const policy = AlgorithmPolicy.init(.strict);

    const good = policy.validateSuite(.aes256, .sha256, .ed25519, null);
    try std.testing.expect(good.accepted);

    const bad = policy.validateSuite(.cast5, .md5, .dsa, null);
    try std.testing.expect(!bad.accepted);
}

test "AlgorithmPolicy isAcceptableAead" {
    const rfc9580 = AlgorithmPolicy.init(.rfc9580);
    try std.testing.expect(rfc9580.isAcceptableAead(.eax));
    try std.testing.expect(rfc9580.isAcceptableAead(.ocb));
    try std.testing.expect(rfc9580.isAcceptableAead(.gcm));
    const unknown_aead: AeadAlgorithm = @enumFromInt(99);
    try std.testing.expect(!rfc9580.isAcceptableAead(unknown_aead));
}

test "AlgorithmPolicy native v6 algorithms accepted" {
    const policy = AlgorithmPolicy.init(.strict);
    try std.testing.expect(policy.isAcceptablePublicKey(.x25519, null));
    try std.testing.expect(policy.isAcceptablePublicKey(.x448, null));
    try std.testing.expect(policy.isAcceptablePublicKey(.ed25519, null));
    try std.testing.expect(policy.isAcceptablePublicKey(.ed448, null));
}
