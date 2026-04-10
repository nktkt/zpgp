// SPDX-License-Identifier: MIT
//! RFC 9580 native Ed448 signing (algorithm ID 28).
//!
//! Ed448-Goldilocks is not yet implemented because the Zig standard library
//! does not include Curve448 point arithmetic. The X448 scalar multiplication
//! (key agreement) is implemented in x448.zig, but the full twisted Edwards
//! point operations needed for Ed448 signatures require additional work
//! (correct base point, SHAKE256 hashing, scalar reduction mod L, etc.).
//!
//! All public functions return `error.UnsupportedAlgorithm`.

const std = @import("std");

pub const Ed448Error = error{
    UnsupportedAlgorithm,
    InvalidSignature,
    InvalidKey,
    SignatureVerificationFailed,
    WeakPublicKey,
    NonCanonical,
};

/// Ed448 native key pair.
pub const Ed448Native = struct {
    pub const secret_key_len = 57;
    pub const public_key_len = 57;
    pub const signature_len = 114;

    /// Generate an Ed448 key pair.
    pub fn generate() Ed448Error!struct { secret_key: [57]u8, public_key: [57]u8 } {
        return Ed448Error.UnsupportedAlgorithm;
    }

    /// Derive the public key from a secret key seed.
    pub fn publicKeyFromSecret(_: [57]u8) Ed448Error![57]u8 {
        return Ed448Error.UnsupportedAlgorithm;
    }

    /// Sign a message.
    pub fn sign(_: [57]u8, _: []const u8) Ed448Error![114]u8 {
        return Ed448Error.UnsupportedAlgorithm;
    }

    /// Verify a signature.
    pub fn verify(_: [57]u8, _: []const u8, _: [114]u8) Ed448Error!void {
        return Ed448Error.UnsupportedAlgorithm;
    }

    /// Validate a public key.
    pub fn validatePublicKey(_: [57]u8) Ed448Error!void {
        return Ed448Error.UnsupportedAlgorithm;
    }
};

test "Ed448 returns UnsupportedAlgorithm" {
    try std.testing.expectError(Ed448Error.UnsupportedAlgorithm, Ed448Native.generate());
}
