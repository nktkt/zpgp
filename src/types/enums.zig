// SPDX-License-Identifier: MIT
//! OpenPGP algorithm enums per RFC 4880.

const std = @import("std");

/// RFC 4880 Section 9.1 - Public-Key Algorithms
pub const PublicKeyAlgorithm = enum(u8) {
    rsa_encrypt_sign = 1,
    rsa_encrypt_only = 2,
    rsa_sign_only = 3,
    elgamal = 16,
    dsa = 17,
    ecdh = 18,
    ecdsa = 19,
    eddsa = 22,
    _,

    pub fn name(self: PublicKeyAlgorithm) []const u8 {
        return switch (self) {
            .rsa_encrypt_sign => "RSA (Encrypt or Sign)",
            .rsa_encrypt_only => "RSA Encrypt-Only",
            .rsa_sign_only => "RSA Sign-Only",
            .elgamal => "Elgamal (Encrypt-Only)",
            .dsa => "DSA",
            .ecdh => "ECDH",
            .ecdsa => "ECDSA",
            .eddsa => "EdDSA",
            _ => "Unknown",
        };
    }

    /// Whether this algorithm can be used for signing.
    pub fn canSign(self: PublicKeyAlgorithm) bool {
        return switch (self) {
            .rsa_encrypt_sign, .rsa_sign_only, .dsa, .ecdsa, .eddsa => true,
            else => false,
        };
    }

    /// Whether this algorithm can be used for encryption.
    pub fn canEncrypt(self: PublicKeyAlgorithm) bool {
        return switch (self) {
            .rsa_encrypt_sign, .rsa_encrypt_only, .elgamal, .ecdh => true,
            else => false,
        };
    }
};

/// RFC 4880 Section 9.2 - Symmetric-Key Algorithms
pub const SymmetricAlgorithm = enum(u8) {
    plaintext = 0,
    idea = 1,
    triple_des = 2,
    cast5 = 3,
    blowfish = 4,
    aes128 = 7,
    aes192 = 8,
    aes256 = 9,
    twofish = 10,
    _,

    pub fn name(self: SymmetricAlgorithm) []const u8 {
        return switch (self) {
            .plaintext => "Plaintext",
            .idea => "IDEA",
            .triple_des => "TripleDES",
            .cast5 => "CAST5",
            .blowfish => "Blowfish",
            .aes128 => "AES-128",
            .aes192 => "AES-192",
            .aes256 => "AES-256",
            .twofish => "Twofish",
            _ => "Unknown",
        };
    }

    /// Key size in bytes. Returns null for plaintext or unknown algorithms.
    pub fn keySize(self: SymmetricAlgorithm) ?usize {
        return switch (self) {
            .plaintext => null,
            .idea => 16,
            .triple_des => 24,
            .cast5 => 16,
            .blowfish => 16,
            .aes128 => 16,
            .aes192 => 24,
            .aes256 => 32,
            .twofish => 32,
            _ => null,
        };
    }

    /// Block size in bytes. Returns null for plaintext or unknown algorithms.
    pub fn blockSize(self: SymmetricAlgorithm) ?usize {
        return switch (self) {
            .plaintext => null,
            .idea => 8,
            .triple_des => 8,
            .cast5 => 8,
            .blowfish => 8,
            .aes128 => 16,
            .aes192 => 16,
            .aes256 => 16,
            .twofish => 16,
            _ => null,
        };
    }
};

/// RFC 4880 Section 9.4 - Hash Algorithms
pub const HashAlgorithm = enum(u8) {
    md5 = 1,
    sha1 = 2,
    ripemd160 = 3,
    sha256 = 8,
    sha384 = 9,
    sha512 = 10,
    sha224 = 11,
    _,

    pub fn name(self: HashAlgorithm) []const u8 {
        return switch (self) {
            .md5 => "MD5",
            .sha1 => "SHA1",
            .ripemd160 => "RIPEMD160",
            .sha256 => "SHA256",
            .sha384 => "SHA384",
            .sha512 => "SHA512",
            .sha224 => "SHA224",
            _ => "Unknown",
        };
    }

    /// Digest size in bytes. Returns null for unknown algorithms.
    pub fn digestSize(self: HashAlgorithm) ?usize {
        return switch (self) {
            .md5 => 16,
            .sha1 => 20,
            .ripemd160 => 20,
            .sha256 => 32,
            .sha384 => 48,
            .sha512 => 64,
            .sha224 => 28,
            _ => null,
        };
    }
};

/// RFC 4880 Section 9.3 - Compression Algorithms
pub const CompressionAlgorithm = enum(u8) {
    uncompressed = 0,
    zip = 1,
    zlib = 2,
    bzip2 = 3,
    _,

    pub fn name(self: CompressionAlgorithm) []const u8 {
        return switch (self) {
            .uncompressed => "Uncompressed",
            .zip => "ZIP",
            .zlib => "ZLIB",
            .bzip2 => "BZip2",
            _ => "Unknown",
        };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "PublicKeyAlgorithm basic properties" {
    const rsa = PublicKeyAlgorithm.rsa_encrypt_sign;
    try std.testing.expectEqualStrings("RSA (Encrypt or Sign)", rsa.name());
    try std.testing.expect(rsa.canSign());
    try std.testing.expect(rsa.canEncrypt());

    const elgamal = PublicKeyAlgorithm.elgamal;
    try std.testing.expect(!elgamal.canSign());
    try std.testing.expect(elgamal.canEncrypt());

    const dsa = PublicKeyAlgorithm.dsa;
    try std.testing.expect(dsa.canSign());
    try std.testing.expect(!dsa.canEncrypt());
}

test "PublicKeyAlgorithm unknown value" {
    const unknown: PublicKeyAlgorithm = @enumFromInt(99);
    try std.testing.expectEqualStrings("Unknown", unknown.name());
    try std.testing.expect(!unknown.canSign());
    try std.testing.expect(!unknown.canEncrypt());
}

test "PublicKeyAlgorithm integer round-trip" {
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign));
    try std.testing.expectEqual(@as(u8, 22), @intFromEnum(PublicKeyAlgorithm.eddsa));
    try std.testing.expectEqual(PublicKeyAlgorithm.ecdh, @as(PublicKeyAlgorithm, @enumFromInt(18)));
}

test "SymmetricAlgorithm key and block sizes" {
    const aes256 = SymmetricAlgorithm.aes256;
    try std.testing.expectEqualStrings("AES-256", aes256.name());
    try std.testing.expectEqual(@as(usize, 32), aes256.keySize().?);
    try std.testing.expectEqual(@as(usize, 16), aes256.blockSize().?);

    const cast5 = SymmetricAlgorithm.cast5;
    try std.testing.expectEqual(@as(usize, 16), cast5.keySize().?);
    try std.testing.expectEqual(@as(usize, 8), cast5.blockSize().?);

    const tdes = SymmetricAlgorithm.triple_des;
    try std.testing.expectEqual(@as(usize, 24), tdes.keySize().?);
    try std.testing.expectEqual(@as(usize, 8), tdes.blockSize().?);
}

test "SymmetricAlgorithm plaintext and unknown" {
    try std.testing.expect(SymmetricAlgorithm.plaintext.keySize() == null);
    try std.testing.expect(SymmetricAlgorithm.plaintext.blockSize() == null);

    const unknown: SymmetricAlgorithm = @enumFromInt(200);
    try std.testing.expectEqualStrings("Unknown", unknown.name());
    try std.testing.expect(unknown.keySize() == null);
    try std.testing.expect(unknown.blockSize() == null);
}

test "HashAlgorithm digest sizes" {
    try std.testing.expectEqual(@as(usize, 16), HashAlgorithm.md5.digestSize().?);
    try std.testing.expectEqual(@as(usize, 20), HashAlgorithm.sha1.digestSize().?);
    try std.testing.expectEqual(@as(usize, 32), HashAlgorithm.sha256.digestSize().?);
    try std.testing.expectEqual(@as(usize, 48), HashAlgorithm.sha384.digestSize().?);
    try std.testing.expectEqual(@as(usize, 64), HashAlgorithm.sha512.digestSize().?);
    try std.testing.expectEqual(@as(usize, 28), HashAlgorithm.sha224.digestSize().?);
    try std.testing.expectEqual(@as(usize, 20), HashAlgorithm.ripemd160.digestSize().?);
}

test "HashAlgorithm names" {
    try std.testing.expectEqualStrings("SHA256", HashAlgorithm.sha256.name());
    try std.testing.expectEqualStrings("SHA512", HashAlgorithm.sha512.name());

    const unknown: HashAlgorithm = @enumFromInt(42);
    try std.testing.expectEqualStrings("Unknown", unknown.name());
    try std.testing.expect(unknown.digestSize() == null);
}

test "CompressionAlgorithm names" {
    try std.testing.expectEqualStrings("Uncompressed", CompressionAlgorithm.uncompressed.name());
    try std.testing.expectEqualStrings("ZIP", CompressionAlgorithm.zip.name());
    try std.testing.expectEqualStrings("ZLIB", CompressionAlgorithm.zlib.name());
    try std.testing.expectEqualStrings("BZip2", CompressionAlgorithm.bzip2.name());

    const unknown: CompressionAlgorithm = @enumFromInt(255);
    try std.testing.expectEqualStrings("Unknown", unknown.name());
}

test "CompressionAlgorithm integer values" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(CompressionAlgorithm.uncompressed));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(CompressionAlgorithm.zip));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(CompressionAlgorithm.zlib));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(CompressionAlgorithm.bzip2));
}
