// SPDX-License-Identifier: MIT
//! Streaming signature verification for OpenPGP.
//!
//! Provides an incremental interface for verifying document signatures over
//! large data. The caller parses the signature packet first (to obtain the
//! hash algorithm and signature value), then feeds the signed data in
//! arbitrary chunks, and finally calls `verify` to check the signature.
//!
//! Usage:
//!
//! ```
//! var verifier = try StreamVerifier.init(.{
//!     .hash_algo = sig.hash_algo,
//!     .pub_algo = sig.pub_algo,
//!     .sig_type = sig.sig_type,
//!     .hashed_subpackets = sig.hashed_subpacket_data,
//!     .hash_prefix = sig.hash_prefix,
//!     .signature_mpis = sig.signature_data,
//! });
//!
//! verifier.update(chunk1);
//! verifier.update(chunk2);
//!
//! const valid = try verifier.verify(public_key_data, allocator);
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const enums = @import("../types/enums.zig");
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const hash_mod = @import("../crypto/hash.zig");
const HashContext = hash_mod.HashContext;
const zeroize = @import("../security/zeroize.zig");

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

pub const StreamVerifyError = error{
    UnsupportedAlgorithm,
    InvalidState,
    InvalidSignatureType,
    HashPrefixMismatch,
    InvalidSignature,
    InvalidPublicKey,
    OutOfMemory,
    Overflow,
};

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// Configuration for a streaming verifier.
pub const StreamVerifyOptions = struct {
    /// The hash algorithm used in the signature.
    hash_algo: HashAlgorithm = .sha256,
    /// The public-key algorithm of the signer.
    pub_algo: PublicKeyAlgorithm = .rsa_encrypt_sign,
    /// Signature type: 0x00 (binary) or 0x01 (text).
    sig_type: u8 = 0x00,
    /// The hashed subpacket data from the signature packet.
    hashed_subpackets: []const u8 = &.{},
    /// The 2-byte hash prefix from the signature packet.
    hash_prefix: [2]u8 = [_]u8{ 0, 0 },
    /// The signature value (MPI data or native format).
    signature_data: []const u8 = &.{},
};

// ---------------------------------------------------------------------------
// Verification result
// ---------------------------------------------------------------------------

/// The result of signature verification.
pub const VerifyResult = struct {
    /// Whether the signature is valid.
    valid: bool,
    /// The computed hash digest.
    digest: [64]u8,
    /// Length of the digest in bytes.
    digest_len: usize,
    /// Whether the hash prefix matched.
    prefix_matched: bool,
    /// Whether the cryptographic verification succeeded.
    signature_matched: bool,
};

// ---------------------------------------------------------------------------
// StreamVerifier
// ---------------------------------------------------------------------------

/// Streaming document signature verifier.
///
/// Accumulates data via `update` and verifies the signature when `verify`
/// is called with the signer's public key material.
pub const StreamVerifier = struct {
    hash_ctx: HashContext,
    sig_type: u8,
    pub_algo: PublicKeyAlgorithm,
    hash_algo: HashAlgorithm,
    state: State,
    bytes_hashed: u64,

    // Signature parameters (from the signature packet)
    hashed_subpackets: []const u8,
    hash_prefix: [2]u8,
    signature_data: []const u8,

    const State = enum {
        hashing,
        verified,
        failed,
    };

    /// Create a new StreamVerifier.
    pub fn init(options: StreamVerifyOptions) StreamVerifyError!StreamVerifier {
        if (options.sig_type != 0x00 and options.sig_type != 0x01)
            return StreamVerifyError.InvalidSignatureType;

        const hash_ctx = HashContext.init(options.hash_algo) catch
            return StreamVerifyError.UnsupportedAlgorithm;

        return .{
            .hash_ctx = hash_ctx,
            .sig_type = options.sig_type,
            .pub_algo = options.pub_algo,
            .hash_algo = options.hash_algo,
            .state = .hashing,
            .bytes_hashed = 0,
            .hashed_subpackets = options.hashed_subpackets,
            .hash_prefix = options.hash_prefix,
            .signature_data = options.signature_data,
        };
    }

    /// Feed data into the verification hash.
    ///
    /// For text signatures (sig_type 0x01), the caller is responsible for
    /// canonicalizing line endings before calling this.
    pub fn update(self: *StreamVerifier, data: []const u8) void {
        if (self.state != .hashing) return;
        self.hash_ctx.update(data);
        self.bytes_hashed += data.len;
    }

    /// Finalize the hash and verify the signature.
    ///
    /// `public_key_data` is the raw public key material:
    /// - For RSA: the n and e MPIs as raw bytes.
    /// - For Ed25519: the 32-byte public key.
    ///
    /// Returns a VerifyResult indicating whether the signature is valid.
    pub fn verify(self: *StreamVerifier, public_key_data: []const u8, allocator: Allocator) StreamVerifyError!VerifyResult {
        if (self.state != .hashing) return StreamVerifyError.InvalidState;

        // 1. Build the V4 signature trailer and hash it
        const trailer = self.buildTrailer(allocator) catch
            return StreamVerifyError.OutOfMemory;
        defer allocator.free(trailer);

        self.hash_ctx.update(trailer);

        // 2. Finalize the hash
        const digest_size = hash_mod.digestSize(self.hash_algo) catch
            return StreamVerifyError.UnsupportedAlgorithm;
        var digest: [64]u8 = [_]u8{0} ** 64;
        self.hash_ctx.final(digest[0..digest_size]);

        // 3. Check hash prefix
        const prefix_matched = (digest[0] == self.hash_prefix[0] and
            digest[1] == self.hash_prefix[1]);

        if (!prefix_matched) {
            self.state = .failed;
            return .{
                .valid = false,
                .digest = digest,
                .digest_len = digest_size,
                .prefix_matched = false,
                .signature_matched = false,
            };
        }

        // 4. Verify the cryptographic signature
        const sig_valid = self.verifyCryptoSignature(
            digest[0..digest_size],
            public_key_data,
        );

        self.state = if (sig_valid) .verified else .failed;

        return .{
            .valid = sig_valid,
            .digest = digest,
            .digest_len = digest_size,
            .prefix_matched = true,
            .signature_matched = sig_valid,
        };
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Build the V4 signature trailer.
    fn buildTrailer(self: *const StreamVerifier, allocator: Allocator) ![]u8 {
        const hashed_len = 4 + 2 + self.hashed_subpackets.len;
        const total = hashed_len + 6;

        const buf = try allocator.alloc(u8, total);

        buf[0] = 0x04;
        buf[1] = self.sig_type;
        buf[2] = @intFromEnum(self.pub_algo);
        buf[3] = @intFromEnum(self.hash_algo);

        const sp_len: u16 = @intCast(self.hashed_subpackets.len);
        mem.writeInt(u16, buf[4..6], sp_len, .big);

        if (self.hashed_subpackets.len > 0) {
            @memcpy(buf[6 .. 6 + self.hashed_subpackets.len], self.hashed_subpackets);
        }

        const trailer_offset = 6 + self.hashed_subpackets.len;
        buf[trailer_offset] = 0x04;
        buf[trailer_offset + 1] = 0xFF;
        mem.writeInt(u32, buf[trailer_offset + 2 ..][0..4], @intCast(hashed_len), .big);

        return buf;
    }

    /// Verify the cryptographic signature against the digest.
    fn verifyCryptoSignature(self: *const StreamVerifier, digest: []const u8, public_key_data: []const u8) bool {
        switch (self.pub_algo) {
            .ed25519 => {
                return self.verifyEd25519(digest, public_key_data);
            },
            .rsa_encrypt_sign, .rsa_sign_only => {
                return self.verifyRsaPlaceholder(digest, public_key_data);
            },
            .eddsa => {
                // Legacy EdDSA (RFC 4880bis)
                return self.verifyEd25519(digest, public_key_data);
            },
            else => {
                // For algorithms without native Zig support, a complete
                // implementation would dispatch to the appropriate
                // algorithm. Return false since we cannot verify.
                return digest.len > 0 and public_key_data.len > 0 and false;
            },
        }
    }

    /// Verify an Ed25519 signature.
    fn verifyEd25519(self: *const StreamVerifier, digest: []const u8, public_key_data: []const u8) bool {
        if (public_key_data.len < 32) return false;
        if (self.signature_data.len < 64) return false;

        const pk_bytes: [32]u8 = public_key_data[0..32].*;
        const sig_bytes: [64]u8 = self.signature_data[0..64].*;

        const pk = std.crypto.sign.Ed25519.PublicKey.fromBytes(pk_bytes) catch return false;
        const sig = std.crypto.sign.Ed25519.Signature.fromBytes(sig_bytes);

        sig.verify(digest, pk) catch return false;
        return true;
    }

    /// Verify an RSA signature (placeholder using MPI structure).
    ///
    /// A complete RSA verification would parse the public key MPIs (n, e),
    /// perform modular exponentiation, and verify the PKCS#1 v1.5 padding.
    /// This placeholder checks structural validity only.
    fn verifyRsaPlaceholder(self: *const StreamVerifier, digest: []const u8, public_key_data: []const u8) bool {
        _ = self;
        // Basic structural check: both must be non-empty
        if (digest.len == 0 or public_key_data.len < 4) return false;

        // In a real implementation, we would:
        // 1. Parse n and e MPIs from public_key_data
        // 2. Parse the signature MPI from self.signature_data
        // 3. Compute s^e mod n
        // 4. Verify PKCS#1 v1.5 padding
        // 5. Compare the encoded hash
        //
        // For now, return false to indicate "not verified" rather than
        // giving a false positive.
        return false;
    }

    // -----------------------------------------------------------------------
    // Query methods
    // -----------------------------------------------------------------------

    /// Return the total number of bytes hashed.
    pub fn totalBytesHashed(self: *const StreamVerifier) u64 {
        return self.bytes_hashed;
    }

    /// Whether verification succeeded.
    pub fn isVerified(self: *const StreamVerifier) bool {
        return self.state == .verified;
    }

    /// Whether verification failed.
    pub fn hasFailed(self: *const StreamVerifier) bool {
        return self.state == .failed;
    }
};

// ---------------------------------------------------------------------------
// Convenience: verify a detached signature over a data stream
// ---------------------------------------------------------------------------

/// Configuration for detached signature verification.
pub const DetachedVerifyOptions = struct {
    hash_algo: HashAlgorithm,
    pub_algo: PublicKeyAlgorithm,
    sig_type: u8,
    hashed_subpackets: []const u8,
    hash_prefix: [2]u8,
    signature_data: []const u8,
    public_key_data: []const u8,
};

/// Verify a detached signature over a complete data buffer.
///
/// This is a convenience wrapper around StreamVerifier for cases where
/// the data is available all at once.
pub fn verifyDetached(
    data: []const u8,
    options: DetachedVerifyOptions,
    allocator: Allocator,
) StreamVerifyError!VerifyResult {
    var verifier = try StreamVerifier.init(.{
        .hash_algo = options.hash_algo,
        .pub_algo = options.pub_algo,
        .sig_type = options.sig_type,
        .hashed_subpackets = options.hashed_subpackets,
        .hash_prefix = options.hash_prefix,
        .signature_data = options.signature_data,
    });

    verifier.update(data);

    return verifier.verify(options.public_key_data, allocator);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "StreamVerifier init" {
    const verifier = try StreamVerifier.init(.{
        .hash_algo = .sha256,
        .pub_algo = .rsa_encrypt_sign,
        .sig_type = 0x00,
    });
    try std.testing.expectEqual(StreamVerifier.State.hashing, verifier.state);
    try std.testing.expectEqual(@as(u64, 0), verifier.bytes_hashed);
}

test "StreamVerifier invalid sig type" {
    const result = StreamVerifier.init(.{
        .hash_algo = .sha256,
        .pub_algo = .rsa_encrypt_sign,
        .sig_type = 0x13,
    });
    try std.testing.expectError(StreamVerifyError.InvalidSignatureType, result);
}

test "StreamVerifier update" {
    var verifier = try StreamVerifier.init(.{
        .hash_algo = .sha256,
        .pub_algo = .rsa_encrypt_sign,
        .sig_type = 0x00,
    });

    verifier.update("hello");
    try std.testing.expectEqual(@as(u64, 5), verifier.bytes_hashed);

    verifier.update(" world");
    try std.testing.expectEqual(@as(u64, 11), verifier.bytes_hashed);
}

test "StreamVerifier hash prefix mismatch" {
    const allocator = std.testing.allocator;

    var verifier = try StreamVerifier.init(.{
        .hash_algo = .sha256,
        .pub_algo = .rsa_encrypt_sign,
        .sig_type = 0x00,
        .hash_prefix = [2]u8{ 0xFF, 0xFF }, // wrong prefix
    });

    verifier.update("test data");

    const dummy_pk = [_]u8{0} ** 64;
    const result = try verifier.verify(&dummy_pk, allocator);

    try std.testing.expect(!result.valid);
    try std.testing.expect(!result.prefix_matched);
}

test "StreamVerifier verify only once" {
    const allocator = std.testing.allocator;

    var verifier = try StreamVerifier.init(.{
        .hash_algo = .sha256,
        .pub_algo = .rsa_encrypt_sign,
        .sig_type = 0x00,
        .hash_prefix = [2]u8{ 0xFF, 0xFF },
    });

    verifier.update("data");

    const dummy_pk = [_]u8{0} ** 64;
    _ = try verifier.verify(&dummy_pk, allocator);

    // Second verify should fail
    try std.testing.expectError(
        StreamVerifyError.InvalidState,
        verifier.verify(&dummy_pk, allocator),
    );
}

test "StreamVerifier Ed25519 roundtrip" {
    const allocator = std.testing.allocator;

    // Generate an Ed25519 key pair
    const kp = std.crypto.sign.Ed25519.KeyPair.generate();

    // Sign some data
    const data = "Hello, OpenPGP streaming verification!";

    // Compute the hash with trailer (matching what StreamSigner does)
    var hash_ctx = try HashContext.init(.sha256);
    hash_ctx.update(data);

    // Build a minimal trailer
    const creation_time: u32 = 1700000000;
    var hashed_sp: [6]u8 = undefined;
    hashed_sp[0] = 5;
    hashed_sp[1] = 2;
    mem.writeInt(u32, hashed_sp[2..6], creation_time, .big);

    const hashed_len: usize = 4 + 2 + 6; // version fields + sp_len + sp
    const trailer_len: usize = hashed_len + 6;
    var trailer: [trailer_len]u8 = undefined;
    trailer[0] = 0x04;
    trailer[1] = 0x00; // binary
    trailer[2] = @intFromEnum(PublicKeyAlgorithm.ed25519);
    trailer[3] = @intFromEnum(HashAlgorithm.sha256);
    mem.writeInt(u16, trailer[4..6], 6, .big);
    @memcpy(trailer[6..12], &hashed_sp);
    trailer[12] = 0x04;
    trailer[13] = 0xFF;
    mem.writeInt(u32, trailer[14..18], @intCast(hashed_len), .big);

    hash_ctx.update(&trailer);

    var digest: [32]u8 = undefined;
    hash_ctx.final(&digest);

    const sig = try kp.sign(&digest, null);
    const sig_bytes = sig.toBytes();

    // Now verify using StreamVerifier
    var verifier = try StreamVerifier.init(.{
        .hash_algo = .sha256,
        .pub_algo = .ed25519,
        .sig_type = 0x00,
        .hashed_subpackets = &hashed_sp,
        .hash_prefix = [2]u8{ digest[0], digest[1] },
        .signature_data = &sig_bytes,
    });

    verifier.update(data);

    const result = try verifier.verify(&kp.public_key.toBytes(), allocator);

    try std.testing.expect(result.valid);
    try std.testing.expect(result.prefix_matched);
    try std.testing.expect(result.signature_matched);
    try std.testing.expect(verifier.isVerified());
}

test "verifyDetached convenience" {
    const allocator = std.testing.allocator;

    // This test uses RSA placeholder which always returns false,
    // but it exercises the API path.
    const result = try verifyDetached(
        "test data",
        .{
            .hash_algo = .sha256,
            .pub_algo = .rsa_encrypt_sign,
            .sig_type = 0x00,
            .hashed_subpackets = &.{},
            .hash_prefix = [2]u8{ 0xFF, 0xFF },
            .signature_data = &.{},
            .public_key_data = &([_]u8{0} ** 64),
        },
        allocator,
    );

    // Hash prefix won't match, so it should be invalid
    try std.testing.expect(!result.valid);
}
