// SPDX-License-Identifier: MIT
//! RFC 9580 native X448 key agreement (algorithm ID 26).
//!
//! X448 (Curve448/Goldilocks) is specified in RFC 9580 for key agreement.
//! The Zig standard library does not currently include an X448 implementation,
//! so this module provides the packet format constants and stub operations
//! that return `error.UnsupportedAlgorithm`.
//!
//! When Zig's standard library adds X448 support, this module can be updated
//! to provide full functionality.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const X448Error = error{
    UnsupportedAlgorithm,
    InvalidPublicKey,
    KeyAgreementFailed,
    UnwrapFailed,
    OutOfMemory,
};

/// RFC 9580 native X448 key type (stub).
pub const X448Native = struct {
    /// Public key size in bytes (56 bytes for X448).
    pub const public_key_size = 56;
    /// Secret key size in bytes.
    pub const secret_key_size = 56;

    /// Generate an X448 key pair.
    ///
    /// Currently returns `error.UnsupportedAlgorithm` because Zig's standard
    /// library does not include X448/Curve448.
    pub fn generate() X448Error!struct { public: [56]u8, secret: [56]u8 } {
        return error.UnsupportedAlgorithm;
    }

    /// Encrypt a session key for an X448 recipient.
    pub fn encryptSessionKey(
        _: Allocator,
        _: [56]u8,
        _: []const u8,
        _: u8,
    ) X448Error!X448EncryptedKey {
        return error.UnsupportedAlgorithm;
    }

    /// Decrypt a session key.
    pub fn decryptSessionKey(
        _: Allocator,
        _: [56]u8,
        _: [56]u8,
        _: [56]u8,
        _: []const u8,
        _: u8,
    ) X448Error![]u8 {
        return error.UnsupportedAlgorithm;
    }

    /// Validate a public key.
    pub fn validatePublicKey(_: [56]u8) X448Error!void {
        return error.UnsupportedAlgorithm;
    }

    /// Derive public key from secret.
    pub fn publicKeyFromSecret(_: [56]u8) X448Error![56]u8 {
        return error.UnsupportedAlgorithm;
    }
};

/// Result of X448 encryption (stub type).
pub const X448EncryptedKey = struct {
    ephemeral_public: [56]u8,
    wrapped_key: []u8,
    allocator: Allocator,

    pub fn deinit(self: X448EncryptedKey) void {
        self.allocator.free(self.wrapped_key);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "X448Native constants" {
    try std.testing.expectEqual(@as(usize, 56), X448Native.public_key_size);
    try std.testing.expectEqual(@as(usize, 56), X448Native.secret_key_size);
}

test "X448Native generate returns UnsupportedAlgorithm" {
    try std.testing.expectError(error.UnsupportedAlgorithm, X448Native.generate());
}

test "X448Native encryptSessionKey returns UnsupportedAlgorithm" {
    const allocator = std.testing.allocator;
    const pub_key = [_]u8{0} ** 56;
    try std.testing.expectError(
        error.UnsupportedAlgorithm,
        X448Native.encryptSessionKey(allocator, pub_key, &[_]u8{0} ** 16, 9),
    );
}

test "X448Native decryptSessionKey returns UnsupportedAlgorithm" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0} ** 56;
    try std.testing.expectError(
        error.UnsupportedAlgorithm,
        X448Native.decryptSessionKey(allocator, key, key, key, &[_]u8{0} ** 16, 9),
    );
}

test "X448Native validatePublicKey returns UnsupportedAlgorithm" {
    const key = [_]u8{0} ** 56;
    try std.testing.expectError(error.UnsupportedAlgorithm, X448Native.validatePublicKey(key));
}
