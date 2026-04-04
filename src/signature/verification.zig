// SPDX-License-Identifier: MIT
//! Signature verification per RFC 4880.
//!
//! Verifies document signatures, certification signatures, and subkey
//! binding signatures by computing the expected hash and checking it
//! against the signature MPIs using the signer's public key.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const SignaturePacket = @import("../packets/signature.zig").SignaturePacket;
const PublicKeyPacket = @import("../packets/public_key.zig").PublicKeyPacket;
const HashAlgorithm = @import("../types/enums.zig").HashAlgorithm;
const PublicKeyAlgorithm = @import("../types/enums.zig").PublicKeyAlgorithm;
const creation = @import("creation.zig");
const HashResult = creation.HashResult;
const sig_types = @import("types.zig");
const SignatureType = sig_types.SignatureType;

pub const VerificationError = error{
    UnsupportedVersion,
    UnsupportedAlgorithm,
    HashPrefixMismatch,
    InsufficientKeyMaterial,
    InvalidSignature,
    InvalidPacket,
    OutOfMemory,
};

/// Verify a document signature (sig_type 0x00 or 0x01).
///
/// Computes the hash of the document with the signature trailer, checks
/// the hash prefix, and verifies the signature using the public key.
pub fn verifyDocumentSignature(
    sig: *const SignaturePacket,
    document: []const u8,
    public_key: *const PublicKeyPacket,
    allocator: Allocator,
) VerificationError!bool {
    if (sig.version != 4) return error.UnsupportedVersion;

    // Compute the expected hash
    const hash_result = creation.computeDocumentHash(
        sig.hash_algo,
        document,
        sig.sig_type,
        @intFromEnum(sig.pub_algo),
        @intFromEnum(sig.hash_algo),
        sig.hashed_subpacket_data,
        allocator,
    ) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.UnsupportedAlgorithm,
    };

    // Verify hash prefix matches
    if (hash_result.prefix[0] != sig.hash_prefix[0] or
        hash_result.prefix[1] != sig.hash_prefix[1])
    {
        return false;
    }

    // Verify the cryptographic signature
    return verifySignatureMpis(sig, &hash_result, public_key);
}

/// Verify a certification signature (sig_type 0x10-0x13).
///
/// Computes the hash of the key material + user ID with the signature
/// trailer, checks the hash prefix, and verifies the signature.
pub fn verifyCertificationSignature(
    sig: *const SignaturePacket,
    key_packet_body: []const u8,
    user_id: []const u8,
    signer_key: *const PublicKeyPacket,
    allocator: Allocator,
) VerificationError!bool {
    if (sig.version != 4) return error.UnsupportedVersion;

    const hash_result = creation.computeCertificationHash(
        sig.hash_algo,
        key_packet_body,
        user_id,
        sig.sig_type,
        @intFromEnum(sig.pub_algo),
        @intFromEnum(sig.hash_algo),
        sig.hashed_subpacket_data,
        allocator,
    ) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.UnsupportedAlgorithm,
    };

    if (hash_result.prefix[0] != sig.hash_prefix[0] or
        hash_result.prefix[1] != sig.hash_prefix[1])
    {
        return false;
    }

    return verifySignatureMpis(sig, &hash_result, signer_key);
}

/// Verify a subkey binding signature (sig_type 0x18 or 0x19).
pub fn verifySubkeyBindingSignature(
    sig: *const SignaturePacket,
    primary_key_body: []const u8,
    subkey_body: []const u8,
    signer_key: *const PublicKeyPacket,
    allocator: Allocator,
) VerificationError!bool {
    if (sig.version != 4) return error.UnsupportedVersion;

    const hash_result = creation.computeSubkeyBindingHash(
        sig.hash_algo,
        primary_key_body,
        subkey_body,
        sig.sig_type,
        @intFromEnum(sig.pub_algo),
        @intFromEnum(sig.hash_algo),
        sig.hashed_subpacket_data,
        allocator,
    ) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.UnsupportedAlgorithm,
    };

    if (hash_result.prefix[0] != sig.hash_prefix[0] or
        hash_result.prefix[1] != sig.hash_prefix[1])
    {
        return false;
    }

    return verifySignatureMpis(sig, &hash_result, signer_key);
}

/// Verify the actual cryptographic signature against the computed hash.
///
/// For RSA: uses PKCS#1 v1.5 verification via the crypto/rsa module.
/// For DSA/ECDSA/EdDSA: currently returns error.UnsupportedAlgorithm.
fn verifySignatureMpis(
    sig: *const SignaturePacket,
    hash_result: *const HashResult,
    public_key: *const PublicKeyPacket,
) VerificationError!bool {
    return switch (sig.pub_algo) {
        .rsa_encrypt_sign, .rsa_sign_only => verifyRsa(sig, hash_result, public_key),
        else => error.UnsupportedAlgorithm,
    };
}

/// RSA PKCS#1 v1.5 signature verification.
fn verifyRsa(
    sig: *const SignaturePacket,
    hash_result: *const HashResult,
    public_key: *const PublicKeyPacket,
) VerificationError!bool {
    // RSA public key has 2 MPIs: n and e
    if (public_key.key_material.len < 2) return error.InsufficientKeyMaterial;

    // RSA signature has 1 MPI
    if (sig.signature_mpis.len < 1) return error.InvalidSignature;

    // Import RSA module for verification
    const rsa = @import("../crypto/rsa.zig");
    const rsa_pub = rsa.RsaPublicKey{
        .n_bytes = public_key.key_material[0].data,
        .e_bytes = public_key.key_material[1].data,
    };

    const digest = hash_result.digestSlice();
    rsa_pub.pkcs1v15Verify(
        sig.hash_algo,
        digest,
        sig.signature_mpis[0].data,
    ) catch {
        return false;
    };
    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Note: Full integration tests for verification require the crypto/rsa.zig
// and crypto/hash.zig modules to be available. The following tests verify
// the structural/logic aspects.

test "VerificationError is well-formed" {
    // Just verify the error set compiles and can be used.
    const err: VerificationError = error.HashPrefixMismatch;
    try std.testing.expect(err == error.HashPrefixMismatch);
}

test "SignatureType classification used in verification" {
    // Verify the signature type helpers work correctly for routing.
    const doc_sig: SignatureType = @enumFromInt(0x00);
    try std.testing.expect(doc_sig.isDocumentSignature());

    const cert_sig: SignatureType = @enumFromInt(0x13);
    try std.testing.expect(cert_sig.isCertification());

    const bind_sig: SignatureType = @enumFromInt(0x18);
    try std.testing.expect(bind_sig.isKeyBinding());
}
