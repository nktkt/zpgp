// SPDX-License-Identifier: MIT
//! Ed25519 sign/verify operations wrapped for OpenPGP.
//!
//! Provides thin wrappers around std.crypto.sign.Ed25519 with
//! OpenPGP-specific conventions:
//! - Key formats matching MPI storage
//! - Error types consistent with the crypto module
//! - Key generation using the system CSPRNG

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

pub const Ed25519Error = error{
    InvalidSignature,
    InvalidKey,
    WeakKey,
    SignatureVerificationFailed,
    KeyGenFailed,
    NonCanonical,
    IdentityElement,
};

/// Ed25519 key pair.
pub const Ed25519KeyPair = struct {
    public_key: [32]u8,
    secret_key: [64]u8,
};

/// Sign a message using Ed25519.
///
/// `secret_key` is the 64-byte expanded secret key (seed + public key)
/// as stored in OpenPGP secret key packets.
/// Returns the 64-byte signature.
pub fn ed25519Sign(secret_key: [64]u8, message: []const u8) Ed25519Error![64]u8 {
    const sk = Ed25519.SecretKey.fromBytes(secret_key) catch
        return Ed25519Error.InvalidKey;
    const pk = Ed25519.PublicKey.fromBytes(sk.publicKeyBytes()) catch
        return Ed25519Error.InvalidKey;
    const kp = Ed25519.KeyPair{
        .secret_key = sk,
        .public_key = pk,
    };
    var signer = kp.signer(null) catch return Ed25519Error.InvalidKey;
    signer.update(message);
    const sig = signer.finalize();
    return sig.toBytes();
}

/// Verify an Ed25519 signature.
///
/// `public_key` is the 32-byte Ed25519 public key.
/// `message` is the data that was signed.
/// `sig` is the 64-byte signature.
/// Returns error if verification fails.
pub fn ed25519Verify(public_key: [32]u8, message: []const u8, sig: [64]u8) Ed25519Error!void {
    const signature = Ed25519.Signature.fromBytes(sig);
    const pk = Ed25519.PublicKey.fromBytes(public_key) catch
        return Ed25519Error.InvalidKey;
    signature.verify(message, pk) catch
        return Ed25519Error.SignatureVerificationFailed;
}

/// Generate an Ed25519 key pair using the system CSPRNG.
pub fn ed25519Generate() Ed25519Error!Ed25519KeyPair {
    const kp = Ed25519.KeyPair.generate();
    return .{
        .public_key = kp.public_key.toBytes(),
        .secret_key = kp.secret_key.toBytes(),
    };
}

/// Extract the public key from a 64-byte secret key.
/// The public key is the last 32 bytes.
pub fn publicKeyFromSecret(secret_key: [64]u8) [32]u8 {
    return secret_key[32..64].*;
}

/// Check if a public key is valid (on the curve and not the identity element).
pub fn validatePublicKey(public_key: [32]u8) Ed25519Error!void {
    _ = Ed25519.PublicKey.fromBytes(public_key) catch
        return Ed25519Error.InvalidKey;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Ed25519 sign/verify round-trip" {
    const kp = try ed25519Generate();
    const message = "Hello, Ed25519!";

    const sig = try ed25519Sign(kp.secret_key, message);
    try ed25519Verify(kp.public_key, message, sig);
}

test "Ed25519 verify rejects wrong message" {
    const kp = try ed25519Generate();
    const message = "Hello, Ed25519!";
    const wrong_message = "Wrong message";

    const sig = try ed25519Sign(kp.secret_key, message);

    const result = ed25519Verify(kp.public_key, wrong_message, sig);
    try std.testing.expectError(Ed25519Error.SignatureVerificationFailed, result);
}

test "Ed25519 verify rejects wrong key" {
    const kp1 = try ed25519Generate();
    const kp2 = try ed25519Generate();
    const message = "Hello, Ed25519!";

    const sig = try ed25519Sign(kp1.secret_key, message);

    // Verify with wrong public key should fail
    const result = ed25519Verify(kp2.public_key, message, sig);
    try std.testing.expectError(Ed25519Error.SignatureVerificationFailed, result);
}

test "Ed25519 verify rejects tampered signature" {
    const kp = try ed25519Generate();
    const message = "Integrity test";

    var sig = try ed25519Sign(kp.secret_key, message);
    sig[0] ^= 0xFF; // tamper

    const result = ed25519Verify(kp.public_key, message, sig);
    // Could be SignatureVerificationFailed or NonCanonical depending on the tamper
    try std.testing.expect(result == Ed25519Error.SignatureVerificationFailed or
        result == Ed25519Error.InvalidKey);
}

test "Ed25519 generated keys are unique" {
    const kp1 = try ed25519Generate();
    const kp2 = try ed25519Generate();

    try std.testing.expect(!std.mem.eql(u8, &kp1.public_key, &kp2.public_key));
    try std.testing.expect(!std.mem.eql(u8, &kp1.secret_key, &kp2.secret_key));
}

test "Ed25519 publicKeyFromSecret extracts correct key" {
    const kp = try ed25519Generate();
    const extracted = publicKeyFromSecret(kp.secret_key);
    try std.testing.expectEqualSlices(u8, &kp.public_key, &extracted);
}

test "Ed25519 validatePublicKey accepts valid key" {
    const kp = try ed25519Generate();
    try validatePublicKey(kp.public_key);
}

test "Ed25519 sign empty message" {
    const kp = try ed25519Generate();
    const sig = try ed25519Sign(kp.secret_key, "");
    try ed25519Verify(kp.public_key, "", sig);
}

test "Ed25519 sign large message" {
    const kp = try ed25519Generate();
    const msg = [_]u8{0x42} ** 8192;
    const sig = try ed25519Sign(kp.secret_key, &msg);
    try ed25519Verify(kp.public_key, &msg, sig);
}

test "Ed25519 signatures are consistent with key" {
    const kp = try ed25519Generate();
    const message = "Consistency test";

    // Both signatures should verify correctly
    const sig1 = try ed25519Sign(kp.secret_key, message);
    const sig2 = try ed25519Sign(kp.secret_key, message);

    try ed25519Verify(kp.public_key, message, sig1);
    try ed25519Verify(kp.public_key, message, sig2);
}
