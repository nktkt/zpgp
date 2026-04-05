// SPDX-License-Identifier: MIT
//! RFC 9580 native X25519 key agreement (algorithm ID 25).
//!
//! This implements the native X25519 key type introduced in RFC 9580.
//! Unlike legacy ECDH (algorithm ID 18), native X25519 uses:
//!   - Algorithm ID 25 (not 18)
//!   - Raw 32-byte public key (no OID prefix, no KDF parameters)
//!   - Raw 32-byte secret key
//!   - HKDF-SHA256 for key derivation (not the RFC 6637 KDF)
//!   - AES Key Wrap for session key wrapping
//!
//! Key derivation per RFC 9580 Section 5.5.5.6:
//!   ikm  = shared_secret (32 bytes from X25519 DH)
//!   salt = (empty)
//!   info = ephemeral_public (32) || recipient_public (32) || algo_id (1)
//!   key  = HKDF-SHA256(ikm, info) truncated to symmetric key size

const std = @import("std");
const Allocator = std.mem.Allocator;
const X25519 = std.crypto.dh.X25519;
const HkdfSha256 = @import("hkdf.zig").HkdfSha256;
const aes_keywrap = @import("aes_keywrap.zig");
const SymmetricAlgorithm = @import("../types/enums.zig").SymmetricAlgorithm;

pub const X25519NativeError = error{
    InvalidPublicKey,
    KeyAgreementFailed,
    UnwrapFailed,
    UnsupportedAlgorithm,
    OutOfMemory,
};

/// Result of X25519 native encryption.
pub const X25519EncryptedKey = struct {
    /// The ephemeral public key (32 bytes).
    ephemeral_public: [32]u8,
    /// The wrapped session key.
    wrapped_key: []u8,
    allocator: Allocator,

    pub fn deinit(self: X25519EncryptedKey) void {
        self.allocator.free(self.wrapped_key);
    }
};

/// RFC 9580 native X25519 key type.
pub const X25519Native = struct {
    /// Public key size in bytes.
    pub const public_key_size = 32;
    /// Secret key size in bytes.
    pub const secret_key_size = 32;

    /// Generate an X25519 key pair.
    pub fn generate() struct { public: [32]u8, secret: [32]u8 } {
        const kp = X25519.KeyPair.generate();
        return .{
            .public = kp.public_key,
            .secret = kp.secret_key,
        };
    }

    /// Build the HKDF info parameter for RFC 9580 X25519.
    ///
    /// info = ephemeral_public (32) || recipient_public (32) || algo_id (1)
    fn buildInfo(
        ephemeral_public: [32]u8,
        recipient_public: [32]u8,
        sym_algo_id: u8,
    ) [65]u8 {
        var info: [65]u8 = undefined;
        @memcpy(info[0..32], &ephemeral_public);
        @memcpy(info[32..64], &recipient_public);
        info[64] = sym_algo_id;
        return info;
    }

    /// Derive the key-encryption key using HKDF-SHA256 per RFC 9580.
    fn deriveKek(
        shared_secret: [32]u8,
        ephemeral_public: [32]u8,
        recipient_public: [32]u8,
        sym_algo_id: u8,
        kek_out: []u8,
    ) void {
        const info = buildInfo(ephemeral_public, recipient_public, sym_algo_id);
        const empty_salt = [_]u8{};
        HkdfSha256.deriveKey(kek_out, &empty_salt, &shared_secret, &info);
    }

    /// Encrypt a session key for an X25519 recipient (RFC 9580).
    ///
    /// Generates an ephemeral X25519 key pair, computes the shared secret
    /// with the recipient's public key, derives a KEK using HKDF-SHA256,
    /// and wraps the session key using AES Key Wrap.
    ///
    /// `recipient_public` - 32-byte X25519 public key of the recipient
    /// `session_key` - The plaintext session key to wrap
    /// `sym_algo_id` - The symmetric algorithm identifier (used in HKDF info)
    pub fn encryptSessionKey(
        allocator: Allocator,
        recipient_public: [32]u8,
        session_key: []const u8,
        sym_algo_id: u8,
    ) X25519NativeError!X25519EncryptedKey {
        // Generate ephemeral key pair
        const ephemeral = X25519.KeyPair.generate();

        // Compute shared secret
        const shared_secret = X25519.scalarmult(
            ephemeral.secret_key,
            recipient_public,
        ) catch return X25519NativeError.KeyAgreementFailed;

        // Determine KEK size from the symmetric algorithm
        const sym_algo: SymmetricAlgorithm = @enumFromInt(sym_algo_id);
        const kek_len = sym_algo.keySize() orelse return X25519NativeError.UnsupportedAlgorithm;

        // Derive the KEK using HKDF-SHA256
        var kek: [32]u8 = undefined;
        deriveKek(shared_secret, ephemeral.public_key, recipient_public, sym_algo_id, kek[0..kek_len]);

        // Pad session key for AES Key Wrap: must be multiple of 8, at least 16 bytes
        const padded = padSessionKey(session_key, allocator) catch
            return X25519NativeError.OutOfMemory;
        defer allocator.free(padded);

        // Wrap with AES Key Wrap
        const wrapped = aes_keywrap.wrap(
            kek[0..kek_len],
            padded,
            allocator,
        ) catch return X25519NativeError.OutOfMemory;

        return X25519EncryptedKey{
            .ephemeral_public = ephemeral.public_key,
            .wrapped_key = wrapped,
            .allocator = allocator,
        };
    }

    /// Decrypt a session key using X25519 (RFC 9580).
    ///
    /// `recipient_secret` - 32-byte X25519 secret key
    /// `ephemeral_public` - 32-byte ephemeral public key from sender
    /// `wrapped_data` - The wrapped session key data
    /// `sym_algo_id` - The symmetric algorithm identifier
    pub fn decryptSessionKey(
        allocator: Allocator,
        recipient_secret: [32]u8,
        recipient_public: [32]u8,
        ephemeral_public: [32]u8,
        wrapped_data: []const u8,
        sym_algo_id: u8,
    ) X25519NativeError![]u8 {
        // Compute shared secret
        const shared_secret = X25519.scalarmult(
            recipient_secret,
            ephemeral_public,
        ) catch return X25519NativeError.KeyAgreementFailed;

        // Determine KEK size
        const sym_algo: SymmetricAlgorithm = @enumFromInt(sym_algo_id);
        const kek_len = sym_algo.keySize() orelse return X25519NativeError.UnsupportedAlgorithm;

        // Derive the KEK
        var kek: [32]u8 = undefined;
        deriveKek(shared_secret, ephemeral_public, recipient_public, sym_algo_id, kek[0..kek_len]);

        // Unwrap
        const padded = aes_keywrap.unwrap(
            kek[0..kek_len],
            wrapped_data,
            allocator,
        ) catch return X25519NativeError.UnwrapFailed;
        defer allocator.free(padded);

        // Unpad: first byte is the session key length
        if (padded.len == 0) return X25519NativeError.UnwrapFailed;
        const sk_len = padded[0];
        if (sk_len == 0 or @as(usize, sk_len) + 1 > padded.len)
            return X25519NativeError.UnwrapFailed;

        const session_key = allocator.alloc(u8, sk_len) catch
            return X25519NativeError.OutOfMemory;
        @memcpy(session_key, padded[1..][0..sk_len]);
        return session_key;
    }

    /// Derive the public key from a secret key.
    pub fn publicKeyFromSecret(secret_key: [32]u8) [32]u8 {
        return X25519.recoverPublicKey(secret_key) catch {
            // This can only fail with IdentityElementError, which is
            // practically impossible with a random secret key
            return [_]u8{0} ** 32;
        };
    }
};

/// Pad a session key for AES Key Wrap.
/// Format: [length_byte] [session_key...] [PKCS5 padding to multiple of 8]
fn padSessionKey(session_key: []const u8, allocator: Allocator) ![]u8 {
    const total_unpadded = 1 + session_key.len;
    const padded_len = ((total_unpadded + 7) / 8) * 8;
    const final_len = @max(padded_len, 16);

    const buf = try allocator.alloc(u8, final_len);
    buf[0] = @intCast(session_key.len);
    @memcpy(buf[1..][0..session_key.len], session_key);

    const pad_byte: u8 = @intCast(final_len - total_unpadded);
    @memset(buf[total_unpadded..], pad_byte);

    return buf;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "X25519Native generate key pair" {
    const kp = X25519Native.generate();
    // Keys should not be all zeros
    try std.testing.expect(!std.mem.eql(u8, &kp.public, &([_]u8{0} ** 32)));
    try std.testing.expect(!std.mem.eql(u8, &kp.secret, &([_]u8{0} ** 32)));
}

test "X25519Native generated keys are unique" {
    const kp1 = X25519Native.generate();
    const kp2 = X25519Native.generate();
    try std.testing.expect(!std.mem.eql(u8, &kp1.public, &kp2.public));
    try std.testing.expect(!std.mem.eql(u8, &kp1.secret, &kp2.secret));
}

test "X25519Native encrypt/decrypt round-trip AES-128" {
    const allocator = std.testing.allocator;
    const recipient = X25519Native.generate();
    const session_key = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    };

    const result = try X25519Native.encryptSessionKey(
        allocator,
        recipient.public,
        &session_key,
        @intFromEnum(SymmetricAlgorithm.aes128),
    );
    defer result.deinit();

    const recovered = try X25519Native.decryptSessionKey(
        allocator,
        recipient.secret,
        recipient.public,
        result.ephemeral_public,
        result.wrapped_key,
        @intFromEnum(SymmetricAlgorithm.aes128),
    );
    defer allocator.free(recovered);

    try std.testing.expectEqualSlices(u8, &session_key, recovered);
}

test "X25519Native encrypt/decrypt round-trip AES-256" {
    const allocator = std.testing.allocator;
    const recipient = X25519Native.generate();
    const session_key = [_]u8{
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81,
        0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x82,
        0x13, 0x23, 0x33, 0x43, 0x53, 0x63, 0x73, 0x83,
    };

    const result = try X25519Native.encryptSessionKey(
        allocator,
        recipient.public,
        &session_key,
        @intFromEnum(SymmetricAlgorithm.aes256),
    );
    defer result.deinit();

    const recovered = try X25519Native.decryptSessionKey(
        allocator,
        recipient.secret,
        recipient.public,
        result.ephemeral_public,
        result.wrapped_key,
        @intFromEnum(SymmetricAlgorithm.aes256),
    );
    defer allocator.free(recovered);

    try std.testing.expectEqualSlices(u8, &session_key, recovered);
}

test "X25519Native decrypt with wrong key fails" {
    const allocator = std.testing.allocator;
    const recipient = X25519Native.generate();
    const wrong = X25519Native.generate();
    const session_key = [_]u8{0xFF} ** 16;

    const result = try X25519Native.encryptSessionKey(
        allocator,
        recipient.public,
        &session_key,
        @intFromEnum(SymmetricAlgorithm.aes128),
    );
    defer result.deinit();

    try std.testing.expectError(
        X25519NativeError.UnwrapFailed,
        X25519Native.decryptSessionKey(
            allocator,
            wrong.secret,
            wrong.public,
            result.ephemeral_public,
            result.wrapped_key,
            @intFromEnum(SymmetricAlgorithm.aes128),
        ),
    );
}

test "X25519Native HKDF info construction" {
    const eph = [_]u8{0xAA} ** 32;
    const rcpt = [_]u8{0xBB} ** 32;
    const algo_id: u8 = 9; // AES-256

    const info = X25519Native.buildInfo(eph, rcpt, algo_id);
    try std.testing.expectEqual(@as(usize, 65), info.len);
    try std.testing.expectEqualSlices(u8, &eph, info[0..32]);
    try std.testing.expectEqualSlices(u8, &rcpt, info[32..64]);
    try std.testing.expectEqual(@as(u8, 9), info[64]);
}

test "X25519Native publicKeyFromSecret" {
    const kp = X25519Native.generate();
    const derived_pub = X25519Native.publicKeyFromSecret(kp.secret);
    try std.testing.expectEqualSlices(u8, &kp.public, &derived_pub);
}

test "padSessionKey format" {
    const allocator = std.testing.allocator;
    const sk = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };
    const padded = try padSessionKey(&sk, allocator);
    defer allocator.free(padded);

    try std.testing.expect(padded.len >= 16);
    try std.testing.expect(padded.len % 8 == 0);
    try std.testing.expectEqual(@as(u8, 5), padded[0]);
    try std.testing.expectEqualSlices(u8, &sk, padded[1..6]);
}
