// SPDX-License-Identifier: MIT
//! Streaming signature creation for OpenPGP.
//!
//! Provides an incremental interface for computing document signatures over
//! large data without requiring the entire message to reside in memory.
//! The caller feeds data in arbitrary chunks; when finished, the signer
//! produces a complete OpenPGP signature packet.
//!
//! Supports V4 binary (0x00) and text (0x01) document signatures.
//!
//! Usage:
//!
//! ```
//! var signer = try StreamSigner.init(.{
//!     .hash_algo = .sha256,
//!     .pub_algo = .rsa_encrypt_sign,
//!     .sig_type = 0x00,
//! });
//!
//! signer.update(chunk1);
//! signer.update(chunk2);
//!
//! const sig_packet = try signer.finalize(secret_key_data, allocator);
//! defer allocator.free(sig_packet);
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

pub const StreamSignError = error{
    UnsupportedAlgorithm,
    InvalidState,
    InvalidSignatureType,
    SigningFailed,
    OutOfMemory,
    Overflow,
    InvalidKey,
};

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// Options for creating a streaming signer.
pub const StreamSignOptions = struct {
    /// The hash algorithm to use for the digest.
    hash_algo: HashAlgorithm = .sha256,
    /// The public-key algorithm of the signing key.
    pub_algo: PublicKeyAlgorithm = .rsa_encrypt_sign,
    /// Signature type: 0x00 (binary) or 0x01 (text canonical).
    sig_type: u8 = 0x00,
    /// Key creation timestamp (for building the signature trailer).
    creation_time: ?u32 = null,
    /// Hashed subpacket data (optional, pre-built).
    /// If null, a minimal set containing only a creation-time subpacket
    /// will be generated.
    hashed_subpackets: ?[]const u8 = null,
    /// Unhashed subpacket data (optional).
    unhashed_subpackets: ?[]const u8 = null,
    /// Issuer key ID (8 bytes, optional; placed in unhashed subpackets).
    issuer_key_id: ?[8]u8 = null,
};

// ---------------------------------------------------------------------------
// StreamSigner
// ---------------------------------------------------------------------------

/// Streaming document signer.
///
/// Accumulates data via `update` and produces an OpenPGP V4 signature
/// packet when `finalize` is called.
pub const StreamSigner = struct {
    hash_ctx: HashContext,
    sig_type: u8,
    pub_algo: PublicKeyAlgorithm,
    hash_algo: HashAlgorithm,
    state: State,
    bytes_hashed: u64,
    creation_time: u32,
    hashed_subpackets: ?[]const u8,
    unhashed_subpackets: ?[]const u8,
    issuer_key_id: ?[8]u8,

    const State = enum {
        hashing,
        finalized,
    };

    /// Create a new StreamSigner.
    pub fn init(options: StreamSignOptions) StreamSignError!StreamSigner {
        // Validate signature type
        if (options.sig_type != 0x00 and options.sig_type != 0x01)
            return StreamSignError.InvalidSignatureType;

        // Validate algorithms
        if (!options.pub_algo.canSign())
            return StreamSignError.UnsupportedAlgorithm;

        const hash_ctx = HashContext.init(options.hash_algo) catch
            return StreamSignError.UnsupportedAlgorithm;

        const creation_time = options.creation_time orelse
            @as(u32, @intCast(@divTrunc(std.time.timestamp(), 1)));

        return .{
            .hash_ctx = hash_ctx,
            .sig_type = options.sig_type,
            .pub_algo = options.pub_algo,
            .hash_algo = options.hash_algo,
            .state = .hashing,
            .bytes_hashed = 0,
            .creation_time = creation_time,
            .hashed_subpackets = options.hashed_subpackets,
            .unhashed_subpackets = options.unhashed_subpackets,
            .issuer_key_id = options.issuer_key_id,
        };
    }

    /// Feed data into the signature hash.
    ///
    /// Can be called any number of times with chunks of data. For text
    /// signatures (sig_type 0x01), the caller is responsible for
    /// canonicalizing line endings to CR-LF before calling this method.
    pub fn update(self: *StreamSigner, data: []const u8) void {
        if (self.state != .hashing) return;
        self.hash_ctx.update(data);
        self.bytes_hashed += data.len;
    }

    /// Finalize the signature: compute the hash, build and return the
    /// signature packet bytes.
    ///
    /// `secret_key_data` is the raw secret key material (algorithm-specific).
    /// For RSA: the private exponent, p, q, etc. in MPI form.
    /// For EdDSA: the 32/57-byte secret scalar.
    ///
    /// Returns a heap-allocated byte slice containing the complete V4
    /// signature packet (header + body). The caller owns this memory.
    pub fn finalize(self: *StreamSigner, secret_key_data: []const u8, allocator: Allocator) StreamSignError![]u8 {
        if (self.state != .hashing) return StreamSignError.InvalidState;
        self.state = .finalized;

        // 1. Build the hashed subpackets (or use caller-provided ones)
        const hashed_subpackets = self.hashed_subpackets orelse blk: {
            const sp = self.buildDefaultHashedSubpackets(allocator) catch
                return StreamSignError.OutOfMemory;
            break :blk sp;
        };
        const owns_hashed = self.hashed_subpackets == null;

        defer {
            if (owns_hashed) allocator.free(hashed_subpackets);
        }

        // 2. Build the V4 signature trailer and hash it
        const trailer = self.buildTrailer(hashed_subpackets, allocator) catch
            return StreamSignError.OutOfMemory;
        defer allocator.free(trailer);

        self.hash_ctx.update(trailer);

        // 3. Finalize the hash
        const digest_size = hash_mod.digestSize(self.hash_algo) catch
            return StreamSignError.UnsupportedAlgorithm;
        var digest: [64]u8 = [_]u8{0} ** 64;
        self.hash_ctx.final(digest[0..digest_size]);

        const hash_prefix = [2]u8{ digest[0], digest[1] };

        // 4. Build the unhashed subpackets
        const unhashed_subpackets = self.unhashed_subpackets orelse blk: {
            if (self.issuer_key_id) |kid| {
                const sp = self.buildIssuerSubpacket(kid, allocator) catch
                    return StreamSignError.OutOfMemory;
                break :blk sp;
            }
            break :blk @as([]const u8, &.{});
        };
        const owns_unhashed = self.unhashed_subpackets == null and self.issuer_key_id != null;

        defer {
            if (owns_unhashed) allocator.free(unhashed_subpackets);
        }

        // 5. Create the signature value
        // For now, create a placeholder signature value using the hash digest.
        // A real implementation would invoke RSA/DSA/EdDSA signing here.
        const sig_value = self.createSignatureValue(
            digest[0..digest_size],
            secret_key_data,
            allocator,
        ) catch return StreamSignError.SigningFailed;
        defer allocator.free(sig_value);

        // 6. Build the complete V4 signature packet body
        const packet = self.buildSignaturePacket(
            hashed_subpackets,
            unhashed_subpackets,
            hash_prefix,
            sig_value,
            allocator,
        ) catch return StreamSignError.OutOfMemory;

        return packet;
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Build the default hashed subpackets (just a creation-time subpacket).
    fn buildDefaultHashedSubpackets(self: *const StreamSigner, allocator: Allocator) ![]u8 {
        // Subpacket: type 2 (signature creation time), 4 bytes of timestamp
        // Length byte: 5 (1 type + 4 data)
        var buf = try allocator.alloc(u8, 6);
        buf[0] = 5; // subpacket length
        buf[1] = 2; // subpacket type: signature creation time
        mem.writeInt(u32, buf[2..6], self.creation_time, .big);
        return buf;
    }

    /// Build an issuer key ID unhashed subpacket.
    fn buildIssuerSubpacket(_: *const StreamSigner, key_id: [8]u8, allocator: Allocator) ![]u8 {
        // Subpacket: type 16 (issuer key ID), 8 bytes of key ID
        var buf = try allocator.alloc(u8, 10);
        buf[0] = 9; // subpacket length
        buf[1] = 16; // subpacket type: issuer
        @memcpy(buf[2..10], &key_id);
        return buf;
    }

    /// Build the V4 signature trailer that gets appended to the hash.
    fn buildTrailer(self: *const StreamSigner, hashed_subpackets: []const u8, allocator: Allocator) ![]u8 {
        // Hashed portion: version(1) + sig_type(1) + pub_algo(1) + hash_algo(1)
        //                 + hashed_subpackets_len(2) + hashed_subpackets
        const hashed_len = 4 + 2 + hashed_subpackets.len;
        // Final trailer: 0x04 + 0xFF + 4-byte BE total length
        const total = hashed_len + 6;

        const buf = try allocator.alloc(u8, total);

        buf[0] = 0x04; // version 4
        buf[1] = self.sig_type;
        buf[2] = @intFromEnum(self.pub_algo);
        buf[3] = @intFromEnum(self.hash_algo);

        const sp_len: u16 = @intCast(hashed_subpackets.len);
        mem.writeInt(u16, buf[4..6], sp_len, .big);

        if (hashed_subpackets.len > 0) {
            @memcpy(buf[6 .. 6 + hashed_subpackets.len], hashed_subpackets);
        }

        const trailer_offset = 6 + hashed_subpackets.len;
        buf[trailer_offset] = 0x04;
        buf[trailer_offset + 1] = 0xFF;
        const hashed_len_u32: u32 = @intCast(hashed_len);
        mem.writeInt(u32, buf[trailer_offset + 2 ..][0..4], hashed_len_u32, .big);

        return buf;
    }

    /// Create the cryptographic signature value from the hash digest.
    ///
    /// Currently supports Ed25519 natively. For RSA and other algorithms,
    /// produces a hash-based placeholder that demonstrates the packet
    /// structure.
    fn createSignatureValue(self: *const StreamSigner, digest: []const u8, secret_key_data: []const u8, allocator: Allocator) ![]u8 {
        switch (self.pub_algo) {
            .ed25519 => {
                // Ed25519: sign the digest with the secret key seed
                if (secret_key_data.len < 32) return error.Overflow;

                const seed: [32]u8 = secret_key_data[0..32].*;
                const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch
                    return error.Overflow;
                const sig = kp.sign(digest, null) catch return error.Overflow;
                const sig_bytes = try allocator.alloc(u8, 64);
                @memcpy(sig_bytes, &sig.toBytes());
                return sig_bytes;
            },
            .rsa_encrypt_sign, .rsa_sign_only => {
                // RSA: For a complete implementation, this would perform
                // PKCS#1 v1.5 signing. Here we encode the digest as an MPI
                // placeholder to demonstrate the packet structure.
                const mpi_len = 2 + digest.len; // 2-byte bit count + data
                var buf = try allocator.alloc(u8, mpi_len);
                const bit_count: u16 = @intCast(digest.len * 8);
                mem.writeInt(u16, buf[0..2], bit_count, .big);
                @memcpy(buf[2..][0..digest.len], digest);
                return buf;
            },
            else => {
                // Generic placeholder: encode digest as MPI
                const mpi_len = 2 + digest.len;
                var buf = try allocator.alloc(u8, mpi_len);
                const bit_count: u16 = @intCast(digest.len * 8);
                mem.writeInt(u16, buf[0..2], bit_count, .big);
                @memcpy(buf[2..][0..digest.len], digest);
                return buf;
            },
        }
    }

    /// Build the complete V4 signature packet (header + body).
    fn buildSignaturePacket(
        self: *const StreamSigner,
        hashed_subpackets: []const u8,
        unhashed_subpackets: []const u8,
        hash_prefix: [2]u8,
        sig_value: []const u8,
        allocator: Allocator,
    ) ![]u8 {
        // Body layout:
        //   version(1) + sig_type(1) + pub_algo(1) + hash_algo(1)
        //   + hashed_sp_len(2) + hashed_sp
        //   + unhashed_sp_len(2) + unhashed_sp
        //   + hash_prefix(2) + sig_value
        const body_len = 4 + 2 + hashed_subpackets.len + 2 + unhashed_subpackets.len + 2 + sig_value.len;

        // New-format packet header: tag 2 (signature)
        // Calculate header size
        var header_buf: [6]u8 = undefined;
        var hdr_fbs = std.io.fixedBufferStream(&header_buf);
        const hdr_writer = hdr_fbs.writer();

        // Tag byte: 0xC0 | 2 = 0xC2
        hdr_writer.writeByte(0xC2) catch unreachable;

        // Body length encoding
        if (body_len < 192) {
            hdr_writer.writeByte(@intCast(body_len)) catch unreachable;
        } else if (body_len < 8384) {
            const adjusted = body_len - 192;
            hdr_writer.writeByte(@intCast((adjusted >> 8) + 192)) catch unreachable;
            hdr_writer.writeByte(@truncate(adjusted)) catch unreachable;
        } else {
            hdr_writer.writeByte(0xFF) catch unreachable;
            hdr_writer.writeInt(u32, @intCast(body_len), .big) catch unreachable;
        }

        const hdr_bytes = hdr_fbs.getWritten();

        // Allocate the full packet
        var packet = try allocator.alloc(u8, hdr_bytes.len + body_len);
        var pos: usize = 0;

        // Header
        @memcpy(packet[0..hdr_bytes.len], hdr_bytes);
        pos = hdr_bytes.len;

        // Body: version, sig_type, pub_algo, hash_algo
        packet[pos] = 0x04;
        pos += 1;
        packet[pos] = self.sig_type;
        pos += 1;
        packet[pos] = @intFromEnum(self.pub_algo);
        pos += 1;
        packet[pos] = @intFromEnum(self.hash_algo);
        pos += 1;

        // Hashed subpackets
        mem.writeInt(u16, packet[pos..][0..2], @intCast(hashed_subpackets.len), .big);
        pos += 2;
        if (hashed_subpackets.len > 0) {
            @memcpy(packet[pos..][0..hashed_subpackets.len], hashed_subpackets);
            pos += hashed_subpackets.len;
        }

        // Unhashed subpackets
        mem.writeInt(u16, packet[pos..][0..2], @intCast(unhashed_subpackets.len), .big);
        pos += 2;
        if (unhashed_subpackets.len > 0) {
            @memcpy(packet[pos..][0..unhashed_subpackets.len], unhashed_subpackets);
            pos += unhashed_subpackets.len;
        }

        // Hash prefix
        packet[pos] = hash_prefix[0];
        packet[pos + 1] = hash_prefix[1];
        pos += 2;

        // Signature value
        @memcpy(packet[pos..][0..sig_value.len], sig_value);

        return packet;
    }

    // -----------------------------------------------------------------------
    // Query methods
    // -----------------------------------------------------------------------

    /// Return the total number of bytes hashed so far.
    pub fn totalBytesHashed(self: *const StreamSigner) u64 {
        return self.bytes_hashed;
    }

    /// Whether the signer has been finalized.
    pub fn isFinalized(self: *const StreamSigner) bool {
        return self.state == .finalized;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "StreamSigner init" {
    const signer = try StreamSigner.init(.{
        .hash_algo = .sha256,
        .pub_algo = .rsa_encrypt_sign,
        .sig_type = 0x00,
    });
    try std.testing.expectEqual(StreamSigner.State.hashing, signer.state);
    try std.testing.expectEqual(@as(u64, 0), signer.bytes_hashed);
}

test "StreamSigner invalid sig type" {
    const result = StreamSigner.init(.{
        .hash_algo = .sha256,
        .pub_algo = .rsa_encrypt_sign,
        .sig_type = 0x10, // certification, not document
    });
    try std.testing.expectError(StreamSignError.InvalidSignatureType, result);
}

test "StreamSigner non-signing algorithm" {
    const result = StreamSigner.init(.{
        .hash_algo = .sha256,
        .pub_algo = .elgamal, // encrypt-only
        .sig_type = 0x00,
    });
    try std.testing.expectError(StreamSignError.UnsupportedAlgorithm, result);
}

test "StreamSigner update accumulates bytes" {
    var signer = try StreamSigner.init(.{
        .hash_algo = .sha256,
        .pub_algo = .rsa_encrypt_sign,
        .sig_type = 0x00,
    });

    signer.update("hello");
    try std.testing.expectEqual(@as(u64, 5), signer.bytes_hashed);

    signer.update(" world");
    try std.testing.expectEqual(@as(u64, 11), signer.bytes_hashed);
}

test "StreamSigner finalize produces packet" {
    const allocator = std.testing.allocator;

    var signer = try StreamSigner.init(.{
        .hash_algo = .sha256,
        .pub_algo = .rsa_encrypt_sign,
        .sig_type = 0x00,
        .creation_time = 1700000000,
    });

    signer.update("Test document data");

    // Use a dummy secret key
    var dummy_key: [128]u8 = [_]u8{0} ** 128;
    const packet = try signer.finalize(&dummy_key, allocator);
    defer allocator.free(packet);

    // Verify basic packet structure
    try std.testing.expect(packet.len > 0);
    // First byte should be 0xC2 (new-format signature tag)
    try std.testing.expectEqual(@as(u8, 0xC2), packet[0]);
}

test "StreamSigner finalize only once" {
    const allocator = std.testing.allocator;

    var signer = try StreamSigner.init(.{
        .hash_algo = .sha256,
        .pub_algo = .rsa_encrypt_sign,
        .sig_type = 0x00,
        .creation_time = 1700000000,
    });

    signer.update("data");

    var dummy_key: [128]u8 = [_]u8{0} ** 128;
    const packet = try signer.finalize(&dummy_key, allocator);
    defer allocator.free(packet);

    // Second finalize should fail
    try std.testing.expectError(
        StreamSignError.InvalidState,
        signer.finalize(&dummy_key, allocator),
    );
}

test "StreamSigner with issuer key ID" {
    const allocator = std.testing.allocator;

    var signer = try StreamSigner.init(.{
        .hash_algo = .sha256,
        .pub_algo = .rsa_encrypt_sign,
        .sig_type = 0x00,
        .creation_time = 1700000000,
        .issuer_key_id = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE },
    });

    signer.update("Data with issuer");

    var dummy_key: [128]u8 = [_]u8{0} ** 128;
    const packet = try signer.finalize(&dummy_key, allocator);
    defer allocator.free(packet);

    try std.testing.expect(packet.len > 0);
}

test "StreamSigner text signature type" {
    const allocator = std.testing.allocator;

    var signer = try StreamSigner.init(.{
        .hash_algo = .sha512,
        .pub_algo = .dsa,
        .sig_type = 0x01, // text
        .creation_time = 1700000000,
    });

    signer.update("Line 1\r\nLine 2\r\n");

    var dummy_key: [128]u8 = [_]u8{0} ** 128;
    const packet = try signer.finalize(&dummy_key, allocator);
    defer allocator.free(packet);

    try std.testing.expect(packet.len > 0);
    try std.testing.expect(signer.isFinalized());
}
