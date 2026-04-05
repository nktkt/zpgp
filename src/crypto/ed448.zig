// SPDX-License-Identifier: MIT
//! RFC 9580 native Ed448 signing (algorithm ID 28).
//!
//! Ed448 is specified in RFC 9580 for digital signatures using Curve448.
//! The Zig standard library does not currently include an Ed448 implementation,
//! so this module provides the packet format constants and stub operations
//! that return `error.UnsupportedAlgorithm`.
//!
//! When Zig's standard library adds Ed448 support, this module can be updated
//! to provide full functionality.

const std = @import("std");

pub const Ed448Error = error{
    UnsupportedAlgorithm,
    InvalidSignature,
    InvalidKey,
    SignatureVerificationFailed,
};

/// RFC 9580 native Ed448 key type (stub).
pub const Ed448Native = struct {
    /// Public key size in bytes (57 bytes for Ed448).
    pub const public_key_size = 57;
    /// Secret key size in bytes.
    pub const secret_key_size = 57;
    /// Signature size in bytes (114 bytes for Ed448).
    pub const signature_size = 114;

    /// Generate an Ed448 key pair.
    ///
    /// Currently returns `error.UnsupportedAlgorithm` because Zig's standard
    /// library does not include Ed448.
    pub fn generate() Ed448Error!struct { public: [57]u8, secret: [57]u8 } {
        return error.UnsupportedAlgorithm;
    }

    /// Sign a message using Ed448.
    pub fn sign(
        _: [57]u8,
        _: [57]u8,
        _: []const u8,
    ) Ed448Error![114]u8 {
        return error.UnsupportedAlgorithm;
    }

    /// Verify an Ed448 signature.
    pub fn verify(
        _: [57]u8,
        _: []const u8,
        _: [114]u8,
    ) Ed448Error!void {
        return error.UnsupportedAlgorithm;
    }

    /// Validate a public key.
    pub fn validatePublicKey(_: [57]u8) Ed448Error!void {
        return error.UnsupportedAlgorithm;
    }

    /// Derive public key from secret.
    pub fn publicKeyFromSecret(_: [57]u8) Ed448Error![57]u8 {
        return error.UnsupportedAlgorithm;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Ed448Native constants" {
    try std.testing.expectEqual(@as(usize, 57), Ed448Native.public_key_size);
    try std.testing.expectEqual(@as(usize, 57), Ed448Native.secret_key_size);
    try std.testing.expectEqual(@as(usize, 114), Ed448Native.signature_size);
}

test "Ed448Native generate returns UnsupportedAlgorithm" {
    try std.testing.expectError(error.UnsupportedAlgorithm, Ed448Native.generate());
}

test "Ed448Native sign returns UnsupportedAlgorithm" {
    const key = [_]u8{0} ** 57;
    try std.testing.expectError(
        error.UnsupportedAlgorithm,
        Ed448Native.sign(key, key, "test"),
    );
}

test "Ed448Native verify returns UnsupportedAlgorithm" {
    const key = [_]u8{0} ** 57;
    const sig = [_]u8{0} ** 114;
    try std.testing.expectError(
        error.UnsupportedAlgorithm,
        Ed448Native.verify(key, "test", sig),
    );
}

test "Ed448Native validatePublicKey returns UnsupportedAlgorithm" {
    const key = [_]u8{0} ** 57;
    try std.testing.expectError(error.UnsupportedAlgorithm, Ed448Native.validatePublicKey(key));
}
