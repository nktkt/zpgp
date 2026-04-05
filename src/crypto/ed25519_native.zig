// SPDX-License-Identifier: MIT
//! RFC 9580 native Ed25519 signing (algorithm ID 27).
//!
//! This implements the native Ed25519 key type introduced in RFC 9580.
//! Unlike legacy EdDSA (algorithm ID 22), native Ed25519 uses:
//!   - Algorithm ID 27 (not 22)
//!   - Raw 32-byte public key (no OID prefix)
//!   - Raw 32-byte secret key (seed only, not expanded 64-byte form)
//!   - Pure Ed25519 signatures (not pre-hashed)
//!
//! The key difference from legacy EdDSA: the secret key material stored
//! in the packet is the 32-byte seed, not the 64-byte expanded key.

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

pub const Ed25519NativeError = error{
    InvalidSignature,
    InvalidKey,
    SignatureVerificationFailed,
    KeyGenFailed,
};

/// RFC 9580 native Ed25519 key type.
pub const Ed25519Native = struct {
    /// Public key size in bytes.
    pub const public_key_size = 32;
    /// Secret key (seed) size in bytes.
    pub const secret_key_size = 32;
    /// Signature size in bytes.
    pub const signature_size = 64;

    /// Generate an Ed25519 key pair.
    ///
    /// Returns the 32-byte public key and 32-byte secret seed.
    /// The seed is the raw 32-byte secret, not the 64-byte expanded form
    /// used by legacy EdDSA.
    pub fn generate() struct { public: [32]u8, secret: [32]u8 } {
        const kp = Ed25519.KeyPair.generate();
        // The secret key in Zig's Ed25519 is 64 bytes (seed || public).
        // For RFC 9580 native Ed25519, we store only the 32-byte seed.
        const seed: [32]u8 = kp.secret_key.seed();
        return .{
            .public = kp.public_key.toBytes(),
            .secret = seed,
        };
    }

    /// Sign a message using Ed25519.
    ///
    /// `secret_key` is the 32-byte seed (not the 64-byte expanded key).
    /// `public_key` is the 32-byte public key.
    /// `message` is the data to sign.
    /// Returns the 64-byte Ed25519 signature.
    ///
    /// Uses deterministic signing (null noise) per RFC 8032.
    pub fn sign(secret_key: [32]u8, public_key: [32]u8, message: []const u8) Ed25519NativeError![64]u8 {
        // Reconstruct the full keypair from seed + public key
        const sk = Ed25519.SecretKey.fromBytes(secret_key ++ public_key) catch
            return Ed25519NativeError.InvalidKey;
        const pk = Ed25519.PublicKey.fromBytes(public_key) catch
            return Ed25519NativeError.InvalidKey;
        const kp = Ed25519.KeyPair{
            .secret_key = sk,
            .public_key = pk,
        };
        const sig = kp.sign(message, null) catch return Ed25519NativeError.InvalidKey;
        return sig.toBytes();
    }

    /// Verify an Ed25519 signature.
    ///
    /// `public_key` is the 32-byte Ed25519 public key.
    /// `message` is the data that was signed.
    /// `sig` is the 64-byte signature.
    pub fn verify(public_key: [32]u8, message: []const u8, sig: [64]u8) Ed25519NativeError!void {
        const signature = Ed25519.Signature.fromBytes(sig);
        const pk = Ed25519.PublicKey.fromBytes(public_key) catch
            return Ed25519NativeError.InvalidKey;
        signature.verify(message, pk) catch
            return Ed25519NativeError.SignatureVerificationFailed;
    }

    /// Derive the public key from the secret seed.
    pub fn publicKeyFromSeed(seed: [32]u8) Ed25519NativeError![32]u8 {
        const kp = Ed25519.KeyPair.generateDeterministic(seed) catch
            return Ed25519NativeError.InvalidKey;
        return kp.public_key.toBytes();
    }

    /// Validate that a public key is on the curve.
    pub fn validatePublicKey(public_key: [32]u8) Ed25519NativeError!void {
        _ = Ed25519.PublicKey.fromBytes(public_key) catch
            return Ed25519NativeError.InvalidKey;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Ed25519Native generate and sign/verify" {
    const kp = Ed25519Native.generate();
    const message = "Hello, RFC 9580 Ed25519!";

    const sig = try Ed25519Native.sign(kp.secret, kp.public, message);
    try Ed25519Native.verify(kp.public, message, sig);
}

test "Ed25519Native verify rejects wrong message" {
    const kp = Ed25519Native.generate();
    const sig = try Ed25519Native.sign(kp.secret, kp.public, "correct");

    const result = Ed25519Native.verify(kp.public, "wrong", sig);
    try std.testing.expectError(Ed25519NativeError.SignatureVerificationFailed, result);
}

test "Ed25519Native verify rejects wrong key" {
    const kp1 = Ed25519Native.generate();
    const kp2 = Ed25519Native.generate();
    const sig = try Ed25519Native.sign(kp1.secret, kp1.public, "test");

    const result = Ed25519Native.verify(kp2.public, "test", sig);
    try std.testing.expectError(Ed25519NativeError.SignatureVerificationFailed, result);
}

test "Ed25519Native verify rejects tampered signature" {
    const kp = Ed25519Native.generate();
    var sig = try Ed25519Native.sign(kp.secret, kp.public, "test");
    sig[0] ^= 0xFF;

    const result = Ed25519Native.verify(kp.public, "test", sig);
    try std.testing.expect(result == Ed25519NativeError.SignatureVerificationFailed or
        result == Ed25519NativeError.InvalidKey);
}

test "Ed25519Native generated keys are unique" {
    const kp1 = Ed25519Native.generate();
    const kp2 = Ed25519Native.generate();
    try std.testing.expect(!std.mem.eql(u8, &kp1.public, &kp2.public));
    try std.testing.expect(!std.mem.eql(u8, &kp1.secret, &kp2.secret));
}

test "Ed25519Native sign empty message" {
    const kp = Ed25519Native.generate();
    const sig = try Ed25519Native.sign(kp.secret, kp.public, "");
    try Ed25519Native.verify(kp.public, "", sig);
}

test "Ed25519Native sign large message" {
    const kp = Ed25519Native.generate();
    const msg = [_]u8{0x42} ** 8192;
    const sig = try Ed25519Native.sign(kp.secret, kp.public, &msg);
    try Ed25519Native.verify(kp.public, &msg, sig);
}

test "Ed25519Native secret is 32-byte seed not 64-byte expanded" {
    const kp = Ed25519Native.generate();
    // The secret must be exactly 32 bytes (seed), not 64 bytes
    try std.testing.expectEqual(@as(usize, 32), kp.secret.len);
    try std.testing.expectEqual(@as(usize, 32), kp.public.len);
}

test "Ed25519Native deterministic signatures" {
    const kp = Ed25519Native.generate();
    const msg = "deterministic test";
    const sig1 = try Ed25519Native.sign(kp.secret, kp.public, msg);
    const sig2 = try Ed25519Native.sign(kp.secret, kp.public, msg);
    // Ed25519 signatures are deterministic
    try std.testing.expectEqualSlices(u8, &sig1, &sig2);
}

test "Ed25519Native validate public key" {
    const kp = Ed25519Native.generate();
    try Ed25519Native.validatePublicKey(kp.public);
}
