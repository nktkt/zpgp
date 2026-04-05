// SPDX-License-Identifier: MIT
//! V6 Public-Key Encrypted Session Key Packet (Tag 1) per RFC 9580 Section 5.1.
//!
//! V6 PKESK differs from V3 PKESK:
//!   - Version byte is 6 (not 3)
//!   - Key version number (1 byte) instead of 8-byte key ID
//!   - Fingerprint length (1 byte)
//!   - Full fingerprint (N bytes: 32 for V6 keys, 20 for V4 keys)
//!   - Public-key algorithm (1 byte)
//!   - Encrypted session key material (algorithm-specific)
//!     - For X25519: 32 bytes ephemeral key + wrapped session key
//!     - For RSA: MPI-encoded ciphertext
//!
//! Wire format (V6 PKESK):
//!   1 octet  -- version (6)
//!   1 octet  -- key version (e.g. 6 for V6 keys, 4 for V4 keys)
//!   1 octet  -- fingerprint length
//!   N octets -- key fingerprint
//!   1 octet  -- public-key algorithm
//!   M octets -- algorithm-specific encrypted session key data

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Mpi = @import("../types/mpi.zig").Mpi;
const PublicKeyAlgorithm = @import("../types/enums.zig").PublicKeyAlgorithm;
const SymmetricAlgorithm = @import("../types/enums.zig").SymmetricAlgorithm;
const X25519Native = @import("x25519_native.zig").X25519Native;
const rsa_mod = @import("rsa.zig");
const RsaPublicKey = rsa_mod.RsaPublicKey;

/// Maximum fingerprint length supported (V6 uses 32 bytes).
const max_fingerprint_len = 32;

/// RFC 9580 Section 5.1 -- V6 Public-Key Encrypted Session Key Packet.
pub const V6PKESKPacket = struct {
    /// Packet version (always 6).
    version: u8,
    /// Version of the key that encrypted this session key.
    key_version: u8,
    /// Fingerprint of the recipient key.
    fingerprint: []const u8,
    /// Public-key algorithm used for encryption.
    algorithm: PublicKeyAlgorithm,
    /// Raw encrypted session key data (algorithm-specific).
    /// For X25519: 32-byte ephemeral key followed by wrapped session key.
    /// For RSA: raw MPI bytes (bit count + data).
    encrypted_data: []const u8,

    /// Parse a V6 PKESK Packet from the raw body bytes.
    pub fn parse(allocator: Allocator, body: []const u8) !V6PKESKPacket {
        // Minimum: version(1) + key_version(1) + fp_len(1) + algorithm(1) = 4
        if (body.len < 4) return error.InvalidPacket;

        const version = body[0];
        if (version != 6) return error.UnsupportedVersion;

        const key_version = body[1];
        const fp_len: usize = body[2];

        var offset: usize = 3;

        // Validate fingerprint length
        if (fp_len > max_fingerprint_len) return error.InvalidPacket;
        if (offset + fp_len > body.len) return error.InvalidPacket;

        const fingerprint = try allocator.dupe(u8, body[offset .. offset + fp_len]);
        errdefer allocator.free(fingerprint);
        offset += fp_len;

        // Algorithm byte
        if (offset >= body.len) return error.InvalidPacket;
        const algorithm: PublicKeyAlgorithm = @enumFromInt(body[offset]);
        offset += 1;

        // Remaining bytes are the encrypted session key data
        if (offset > body.len) return error.InvalidPacket;
        const encrypted_data = try allocator.dupe(u8, body[offset..]);
        errdefer allocator.free(encrypted_data);

        return .{
            .version = version,
            .key_version = key_version,
            .fingerprint = fingerprint,
            .algorithm = algorithm,
            .encrypted_data = encrypted_data,
        };
    }

    /// Serialize the V6 PKESK packet to its body bytes.
    pub fn serialize(self: @This(), allocator: Allocator) ![]u8 {
        // version(1) + key_version(1) + fp_len(1) + fingerprint + algo(1) + data
        const total_len = 1 + 1 + 1 + self.fingerprint.len + 1 + self.encrypted_data.len;
        const buf = try allocator.alloc(u8, total_len);
        errdefer allocator.free(buf);

        buf[0] = self.version;
        buf[1] = self.key_version;
        buf[2] = @intCast(self.fingerprint.len);

        var offset: usize = 3;
        @memcpy(buf[offset .. offset + self.fingerprint.len], self.fingerprint);
        offset += self.fingerprint.len;

        buf[offset] = @intFromEnum(self.algorithm);
        offset += 1;

        @memcpy(buf[offset..], self.encrypted_data);

        return buf;
    }

    /// Free all allocator-owned memory.
    pub fn deinit(self: @This(), allocator: Allocator) void {
        allocator.free(self.fingerprint);
        allocator.free(self.encrypted_data);
    }

    /// Get the ephemeral public key for X25519 (first 32 bytes of encrypted_data).
    pub fn x25519EphemeralKey(self: @This()) ?[32]u8 {
        if (self.algorithm != .x25519) return null;
        if (self.encrypted_data.len < 32) return null;
        return self.encrypted_data[0..32].*;
    }

    /// Get the wrapped session key for X25519 (bytes after the ephemeral key).
    pub fn x25519WrappedKey(self: @This()) ?[]const u8 {
        if (self.algorithm != .x25519) return null;
        if (self.encrypted_data.len <= 32) return null;
        return self.encrypted_data[32..];
    }

    /// Check if this packet uses a wildcard (anonymous) recipient.
    /// In V6, a zero-length fingerprint indicates an anonymous recipient.
    pub fn isAnonymousRecipient(self: @This()) bool {
        return self.fingerprint.len == 0;
    }

    /// Get the key ID from the fingerprint.
    /// For V6 keys (32-byte fingerprint): first 8 bytes.
    /// For V4 keys (20-byte fingerprint): last 8 bytes.
    pub fn keyIdFromFingerprint(self: @This()) ?[8]u8 {
        if (self.fingerprint.len == 32) {
            // V6: key ID is first 8 bytes
            return self.fingerprint[0..8].*;
        } else if (self.fingerprint.len == 20) {
            // V4: key ID is last 8 bytes
            return self.fingerprint[12..20].*;
        }
        return null;
    }
};

/// Create a V6 PKESK packet for an X25519 native recipient.
///
/// This generates an ephemeral X25519 key pair, performs DH key agreement,
/// derives a key-encryption key using HKDF-SHA256, wraps the session key
/// using AES Key Wrap, and constructs the V6 PKESK packet body.
///
/// Returns the serialized V6 PKESK packet body.
pub fn createV6PkeskX25519(
    allocator: Allocator,
    recipient_fingerprint: [32]u8,
    recipient_public: [32]u8,
    session_key: []const u8,
    sym_algo: SymmetricAlgorithm,
) ![]u8 {
    // Encrypt the session key using X25519 native
    const encrypted = X25519Native.encryptSessionKey(
        allocator,
        recipient_public,
        session_key,
        @intFromEnum(sym_algo),
    ) catch return error.EncryptionFailed;
    defer encrypted.deinit();

    // Build the encrypted data: ephemeral_public(32) + wrapped_key
    const enc_data_len = 32 + encrypted.wrapped_key.len;
    const enc_data = try allocator.alloc(u8, enc_data_len);
    defer allocator.free(enc_data);
    @memcpy(enc_data[0..32], &encrypted.ephemeral_public);
    @memcpy(enc_data[32..], encrypted.wrapped_key);

    // Build the V6 PKESK packet
    const pkt = V6PKESKPacket{
        .version = 6,
        .key_version = 6,
        .fingerprint = &recipient_fingerprint,
        .algorithm = .x25519,
        .encrypted_data = enc_data,
    };

    return pkt.serialize(allocator);
}

/// Create a V6 PKESK packet for an RSA recipient.
///
/// Encrypts the session key using PKCS#1 v1.5 with the recipient's RSA
/// public key and constructs the V6 PKESK packet body.
///
/// The session key material to encrypt includes:
///   sym_algo(1) + session_key + checksum(2)
///
/// Returns the serialized V6 PKESK packet body.
pub fn createV6PkeskRsa(
    allocator: Allocator,
    recipient_fingerprint: []const u8,
    recipient_n: []const u8,
    recipient_e: []const u8,
    session_key: []const u8,
    sym_algo: SymmetricAlgorithm,
) ![]u8 {
    // Build the session key material: algo(1) + key + checksum(2)
    const sk_material_len = 1 + session_key.len + 2;
    const sk_material = try allocator.alloc(u8, sk_material_len);
    defer allocator.free(sk_material);

    sk_material[0] = @intFromEnum(sym_algo);
    @memcpy(sk_material[1 .. 1 + session_key.len], session_key);

    // Compute checksum: sum of session key bytes mod 65536
    var checksum: u32 = 0;
    for (session_key) |b| {
        checksum += b;
    }
    mem.writeInt(u16, sk_material[1 + session_key.len ..][0..2], @intCast(checksum & 0xFFFF), .big);

    // RSA encrypt
    const rsa_pub = RsaPublicKey{
        .n_bytes = recipient_n,
        .e_bytes = recipient_e,
    };

    const mod_len = recipient_n.len;
    const ciphertext = try allocator.alloc(u8, mod_len);
    defer allocator.free(ciphertext);

    rsa_pub.pkcs1v15Encrypt(sk_material, ciphertext) catch return error.EncryptionFailed;

    // Encode as MPI: bit count + data
    const bit_count = countBits(ciphertext);
    const mpi_len = 2 + mod_len;
    const enc_data = try allocator.alloc(u8, mpi_len);
    defer allocator.free(enc_data);
    mem.writeInt(u16, enc_data[0..2], bit_count, .big);
    @memcpy(enc_data[2..], ciphertext);

    // Determine key version from fingerprint length
    const key_version: u8 = if (recipient_fingerprint.len == 32) 6 else if (recipient_fingerprint.len == 20) 4 else 0;

    const pkt = V6PKESKPacket{
        .version = 6,
        .key_version = key_version,
        .fingerprint = recipient_fingerprint,
        .algorithm = .rsa_encrypt_sign,
        .encrypted_data = enc_data,
    };

    return pkt.serialize(allocator);
}

/// Count the number of significant bits in a big-endian byte array.
fn countBits(data: []const u8) u16 {
    // Find the first non-zero byte
    for (data, 0..) |b, i| {
        if (b != 0) {
            // Count leading zeros in this byte
            const leading = @clz(b);
            const bits_in_byte: u16 = 8 - @as(u16, leading);
            const remaining_bytes: u16 = @intCast(data.len - i - 1);
            return bits_in_byte + remaining_bytes * 8;
        }
    }
    return 0;
}

/// Build a V6 PKESK packet body for an anonymous recipient.
///
/// This creates a packet with a zero-length fingerprint, indicating that
/// the recipient should try all available secret keys.
pub fn createV6PkeskAnonymous(
    allocator: Allocator,
    algorithm: PublicKeyAlgorithm,
    encrypted_data: []const u8,
) ![]u8 {
    const pkt = V6PKESKPacket{
        .version = 6,
        .key_version = 0,
        .fingerprint = &[_]u8{},
        .algorithm = algorithm,
        .encrypted_data = encrypted_data,
    };

    return pkt.serialize(allocator);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "V6PKESKPacket parse basic X25519" {
    const allocator = std.testing.allocator;

    // Build a V6 PKESK body for X25519
    var body: [200]u8 = undefined;
    body[0] = 6; // version
    body[1] = 6; // key version (V6 key)
    body[2] = 32; // fingerprint length

    // 32-byte fingerprint
    @memset(body[3..35], 0xAA);

    body[35] = @intFromEnum(PublicKeyAlgorithm.x25519); // algorithm

    // Encrypted data: 32-byte ephemeral key + 24-byte wrapped key
    @memset(body[36..68], 0xBB); // ephemeral key
    @memset(body[68..92], 0xCC); // wrapped key

    const pkt = try V6PKESKPacket.parse(allocator, body[0..92]);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 6), pkt.version);
    try std.testing.expectEqual(@as(u8, 6), pkt.key_version);
    try std.testing.expectEqual(@as(usize, 32), pkt.fingerprint.len);
    try std.testing.expectEqual(PublicKeyAlgorithm.x25519, pkt.algorithm);
    try std.testing.expectEqual(@as(usize, 56), pkt.encrypted_data.len);

    // Test ephemeral key extraction
    const eph = pkt.x25519EphemeralKey();
    try std.testing.expect(eph != null);
    try std.testing.expectEqual(@as(u8, 0xBB), eph.?[0]);

    // Test wrapped key extraction
    const wrapped = pkt.x25519WrappedKey();
    try std.testing.expect(wrapped != null);
    try std.testing.expectEqual(@as(u8, 0xCC), wrapped.?[0]);
}

test "V6PKESKPacket parse with V4 fingerprint" {
    const allocator = std.testing.allocator;

    var body: [100]u8 = undefined;
    body[0] = 6;
    body[1] = 4; // V4 key
    body[2] = 20; // 20-byte fingerprint

    @memset(body[3..23], 0xDD);

    body[23] = @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign);

    // RSA MPI: 16 bits = 2 bytes
    mem.writeInt(u16, body[24..26], 16, .big);
    body[26] = 0xCA;
    body[27] = 0xFE;

    const pkt = try V6PKESKPacket.parse(allocator, body[0..28]);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 4), pkt.key_version);
    try std.testing.expectEqual(@as(usize, 20), pkt.fingerprint.len);
    try std.testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, pkt.algorithm);

    // Test key ID extraction from V4 fingerprint
    const kid = pkt.keyIdFromFingerprint();
    try std.testing.expect(kid != null);
    try std.testing.expectEqual(@as(u8, 0xDD), kid.?[0]);
}

test "V6PKESKPacket parse wrong version" {
    const allocator = std.testing.allocator;

    var body: [40]u8 = undefined;
    body[0] = 3; // V3, not V6
    @memset(body[1..], 0);

    try std.testing.expectError(error.UnsupportedVersion, V6PKESKPacket.parse(allocator, &body));
}

test "V6PKESKPacket body too short" {
    const allocator = std.testing.allocator;

    const body = [_]u8{ 6, 6, 32 }; // 3 bytes, missing fingerprint
    try std.testing.expectError(error.InvalidPacket, V6PKESKPacket.parse(allocator, &body));
}

test "V6PKESKPacket serialize round-trip" {
    const allocator = std.testing.allocator;

    var body: [200]u8 = undefined;
    body[0] = 6;
    body[1] = 6;
    body[2] = 32;
    @memset(body[3..35], 0xAA);
    body[35] = @intFromEnum(PublicKeyAlgorithm.x25519);
    @memset(body[36..68], 0xBB);

    const pkt = try V6PKESKPacket.parse(allocator, body[0..68]);
    defer pkt.deinit(allocator);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);

    try std.testing.expectEqualSlices(u8, body[0..68], serialized);
}

test "V6PKESKPacket anonymous recipient" {
    const allocator = std.testing.allocator;

    // Build with zero-length fingerprint
    var body: [20]u8 = undefined;
    body[0] = 6;
    body[1] = 0; // no key version for anonymous
    body[2] = 0; // zero-length fingerprint
    body[3] = @intFromEnum(PublicKeyAlgorithm.x25519);
    @memset(body[4..20], 0xEE);

    const pkt = try V6PKESKPacket.parse(allocator, body[0..20]);
    defer pkt.deinit(allocator);

    try std.testing.expect(pkt.isAnonymousRecipient());
    try std.testing.expectEqual(@as(usize, 0), pkt.fingerprint.len);
    try std.testing.expect(pkt.keyIdFromFingerprint() == null);
}

test "V6PKESKPacket keyIdFromFingerprint V6" {
    const allocator = std.testing.allocator;

    var body: [100]u8 = undefined;
    body[0] = 6;
    body[1] = 6;
    body[2] = 32;
    // Set fingerprint bytes 0-7 to identifiable values
    for (0..32) |i| {
        body[3 + i] = @intCast(i);
    }
    body[35] = @intFromEnum(PublicKeyAlgorithm.x25519);
    @memset(body[36..68], 0x00);

    const pkt = try V6PKESKPacket.parse(allocator, body[0..68]);
    defer pkt.deinit(allocator);

    const kid = pkt.keyIdFromFingerprint();
    try std.testing.expect(kid != null);
    // V6: first 8 bytes of fingerprint
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 }, &kid.?);
}

test "V6PKESKPacket data is independent copy" {
    const allocator = std.testing.allocator;

    var body: [100]u8 = undefined;
    body[0] = 6;
    body[1] = 6;
    body[2] = 32;
    @memset(body[3..35], 0xAA);
    body[35] = @intFromEnum(PublicKeyAlgorithm.x25519);
    @memset(body[36..68], 0xBB);

    const pkt = try V6PKESKPacket.parse(allocator, body[0..68]);
    defer pkt.deinit(allocator);

    // Mutate original
    body[3] = 0xFF;
    body[36] = 0xFF;

    // Parsed data should be unchanged
    try std.testing.expectEqual(@as(u8, 0xAA), pkt.fingerprint[0]);
    try std.testing.expectEqual(@as(u8, 0xBB), pkt.encrypted_data[0]);
}

test "createV6PkeskAnonymous" {
    const allocator = std.testing.allocator;

    const enc_data = [_]u8{0x42} ** 56;
    const serialized = try createV6PkeskAnonymous(allocator, .x25519, &enc_data);
    defer allocator.free(serialized);

    // Parse it back
    const pkt = try V6PKESKPacket.parse(allocator, serialized);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 6), pkt.version);
    try std.testing.expect(pkt.isAnonymousRecipient());
    try std.testing.expectEqual(PublicKeyAlgorithm.x25519, pkt.algorithm);
    try std.testing.expectEqual(@as(usize, 56), pkt.encrypted_data.len);
}

test "countBits" {
    try std.testing.expectEqual(@as(u16, 0), countBits(&[_]u8{ 0, 0, 0 }));
    try std.testing.expectEqual(@as(u16, 8), countBits(&[_]u8{0xFF}));
    try std.testing.expectEqual(@as(u16, 16), countBits(&[_]u8{ 0xFF, 0x00 }));
    try std.testing.expectEqual(@as(u16, 1), countBits(&[_]u8{ 0x00, 0x01 }));
    try std.testing.expectEqual(@as(u16, 9), countBits(&[_]u8{ 0x01, 0xFF }));
    try std.testing.expectEqual(@as(u16, 7), countBits(&[_]u8{ 0x7F }));
}

test "V6PKESKPacket parse RSA MPI data" {
    const allocator = std.testing.allocator;

    // Build a V6 PKESK with RSA encrypted data (MPI format)
    var body: [200]u8 = undefined;
    body[0] = 6;
    body[1] = 6;
    body[2] = 32;
    @memset(body[3..35], 0x11);
    body[35] = @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign);
    // MPI: 2048 bits = 256 bytes, but we just put a small one for testing
    mem.writeInt(u16, body[36..38], 16, .big);
    body[38] = 0xDE;
    body[39] = 0xAD;

    const pkt = try V6PKESKPacket.parse(allocator, body[0..40]);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, pkt.algorithm);
    try std.testing.expectEqual(@as(usize, 4), pkt.encrypted_data.len);
}

test "V6PKESKPacket x25519 helpers return null for non-x25519" {
    const allocator = std.testing.allocator;

    var body: [200]u8 = undefined;
    body[0] = 6;
    body[1] = 6;
    body[2] = 32;
    @memset(body[3..35], 0x11);
    body[35] = @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign);
    mem.writeInt(u16, body[36..38], 8, .big);
    body[38] = 0xFF;

    const pkt = try V6PKESKPacket.parse(allocator, body[0..39]);
    defer pkt.deinit(allocator);

    try std.testing.expect(pkt.x25519EphemeralKey() == null);
    try std.testing.expect(pkt.x25519WrappedKey() == null);
}
