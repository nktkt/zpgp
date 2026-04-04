// SPDX-License-Identifier: MIT
//! Session key generation and management for OpenPGP.
//!
//! A session key is the random symmetric key used to encrypt message data.
//! It is typically wrapped (encrypted) to each recipient using their public
//! key algorithm (RSA, ECDH, etc.) and stored in PKESK packets, or derived
//! from a passphrase and stored in SKESK packets.

const std = @import("std");
const SymmetricAlgorithm = @import("../types/enums.zig").SymmetricAlgorithm;

pub const SessionKeyError = error{
    UnsupportedAlgorithm,
};

pub const SessionKey = struct {
    algo: SymmetricAlgorithm,
    key: [32]u8, // max key size (AES-256 = 32 bytes)
    key_len: usize,

    /// Compute the OpenPGP session key checksum.
    ///
    /// This is the sum of all key bytes, modulo 65536. It is appended to the
    /// session key in PKESK packets for integrity verification.
    pub fn checksum(self: SessionKey) u16 {
        var sum: u32 = 0;
        for (self.key[0..self.key_len]) |byte| {
            sum += byte;
        }
        return @intCast(sum & 0xFFFF);
    }

    /// Return the key bytes as a slice.
    pub fn keySlice(self: *const SessionKey) []const u8 {
        return self.key[0..self.key_len];
    }

    /// Create a SessionKey from raw key material.
    pub fn fromRaw(algo: SymmetricAlgorithm, key_material: []const u8) SessionKeyError!SessionKey {
        const expected_len = algo.keySize() orelse return SessionKeyError.UnsupportedAlgorithm;
        if (key_material.len != expected_len) return SessionKeyError.UnsupportedAlgorithm;

        var sk = SessionKey{
            .algo = algo,
            .key = [_]u8{0} ** 32,
            .key_len = expected_len,
        };
        @memcpy(sk.key[0..expected_len], key_material);
        return sk;
    }
};

/// Generate a random session key for the given symmetric algorithm.
pub fn generateSessionKey(algo: SymmetricAlgorithm) SessionKeyError!SessionKey {
    const key_len = algo.keySize() orelse return SessionKeyError.UnsupportedAlgorithm;

    var sk = SessionKey{
        .algo = algo,
        .key = [_]u8{0} ** 32,
        .key_len = key_len,
    };

    std.crypto.random.bytes(sk.key[0..key_len]);
    return sk;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "generateSessionKey AES-128" {
    const sk = try generateSessionKey(.aes128);
    try std.testing.expectEqual(SymmetricAlgorithm.aes128, sk.algo);
    try std.testing.expectEqual(@as(usize, 16), sk.key_len);

    // The remaining bytes should be zero
    for (sk.key[16..]) |b| {
        try std.testing.expectEqual(@as(u8, 0), b);
    }
}

test "generateSessionKey AES-256" {
    const sk = try generateSessionKey(.aes256);
    try std.testing.expectEqual(SymmetricAlgorithm.aes256, sk.algo);
    try std.testing.expectEqual(@as(usize, 32), sk.key_len);
}

test "generateSessionKey rejects plaintext" {
    try std.testing.expectError(
        SessionKeyError.UnsupportedAlgorithm,
        generateSessionKey(.plaintext),
    );
}

test "session key checksum" {
    const sk = SessionKey{
        .algo = .aes128,
        .key = [_]u8{
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        },
        .key_len = 16,
    };

    // Sum of 0x01..0x10 = (16 * 17) / 2 = 136 = 0x0088
    try std.testing.expectEqual(@as(u16, 0x0088), sk.checksum());
}

test "session key checksum wraps at 16 bits" {
    // All 0xFF bytes: 32 * 255 = 8160 = 0x1FE0
    const sk = SessionKey{
        .algo = .aes256,
        .key = [_]u8{0xFF} ** 32,
        .key_len = 32,
    };

    // 32 * 255 = 8160 = 0x1FE0
    try std.testing.expectEqual(@as(u16, 0x1FE0), sk.checksum());
}

test "session key fromRaw" {
    const material = [_]u8{0xAB} ** 16;
    const sk = try SessionKey.fromRaw(.aes128, &material);
    try std.testing.expectEqual(SymmetricAlgorithm.aes128, sk.algo);
    try std.testing.expectEqual(@as(usize, 16), sk.key_len);
    try std.testing.expectEqualSlices(u8, &material, sk.keySlice());
}

test "session key fromRaw rejects wrong size" {
    const material = [_]u8{0xAB} ** 24; // 24 bytes != AES-128's 16 bytes
    try std.testing.expectError(
        SessionKeyError.UnsupportedAlgorithm,
        SessionKey.fromRaw(.aes128, &material),
    );
}

test "two generated keys are different" {
    const sk1 = try generateSessionKey(.aes256);
    const sk2 = try generateSessionKey(.aes256);

    // Extremely unlikely to be equal (2^-256 probability)
    try std.testing.expect(!std.mem.eql(u8, &sk1.key, &sk2.key));
}
