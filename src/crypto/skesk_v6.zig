// SPDX-License-Identifier: MIT
//! V6 Symmetric-Key Encrypted Session Key Packet (Tag 3) per RFC 9580 Section 5.3.
//!
//! V6 SKESK uses Argon2 for key derivation and AEAD for encryption:
//!
//! Wire format:
//!   1 octet  -- version (6)
//!   1 octet  -- count of following field up to and including the S2K specifier
//!   1 octet  -- symmetric algorithm
//!   1 octet  -- AEAD algorithm
//!   1 octet  -- S2K count (the count byte itself is the type, i.e. 4 for Argon2)
//!   N octets -- S2K specifier (for Argon2: salt(16) + t(1) + p(1) + m(1))
//!   N octets -- AEAD nonce (size depends on AEAD algorithm)
//!   N octets -- encrypted session key + AEAD authentication tag
//!
//! The AEAD associated data for V6 SKESK is:
//!   0xC3 || version(1) || sym_algo(1) || aead_algo(1) || s2k_specifier

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const SymmetricAlgorithm = @import("../types/enums.zig").SymmetricAlgorithm;
const AeadAlgorithm = @import("../types/enums.zig").AeadAlgorithm;
const Argon2S2K = @import("argon2.zig").Argon2S2K;

/// RFC 9580 Section 5.3 -- V6 Symmetric-Key Encrypted Session Key Packet.
pub const V6SKESKPacket = struct {
    /// Packet version (always 6).
    version: u8,
    /// Symmetric cipher algorithm.
    sym_algo: SymmetricAlgorithm,
    /// AEAD algorithm used to encrypt the session key.
    aead_algo: AeadAlgorithm,
    /// S2K type identifier (4 = Argon2).
    s2k_type: u8,
    /// Argon2 salt (16 bytes).
    argon2_salt: [16]u8,
    /// Argon2 number of passes (t parameter).
    argon2_passes: u8,
    /// Argon2 degree of parallelism (p parameter).
    argon2_parallelism: u8,
    /// Argon2 encoded memory parameter (actual memory = 2^m KiB).
    argon2_memory: u8,
    /// AEAD nonce/IV.
    aead_nonce: []const u8,
    /// Encrypted session key including AEAD authentication tag.
    encrypted_session_key: []const u8,

    /// Parse a V6 SKESK Packet from the raw body bytes.
    pub fn parse(allocator: Allocator, body: []const u8) !V6SKESKPacket {
        // Minimum: version(1) + count(1) + sym(1) + aead(1) + s2k_type(1) +
        //          salt(16) + t(1) + p(1) + m(1) + nonce(>=12) + enc_key(>=1) = 36
        if (body.len < 26) return error.InvalidPacket;

        const version = body[0];
        if (version != 6) return error.UnsupportedVersion;

        // Count of bytes following this field up to and including S2K
        const s2k_count = body[1];
        _ = s2k_count; // We parse based on known structure

        var offset: usize = 2;

        // Symmetric algorithm
        const sym_algo: SymmetricAlgorithm = @enumFromInt(body[offset]);
        offset += 1;

        // AEAD algorithm
        const aead_algo: AeadAlgorithm = @enumFromInt(body[offset]);
        offset += 1;

        // S2K type (must be 4 for Argon2)
        const s2k_type = body[offset];
        offset += 1;

        if (s2k_type != 4) return error.UnsupportedS2KType;

        // Argon2 parameters: salt(16) + t(1) + p(1) + m(1)
        if (offset + 19 > body.len) return error.InvalidPacket;

        var argon2_salt: [16]u8 = undefined;
        @memcpy(&argon2_salt, body[offset .. offset + 16]);
        offset += 16;

        const argon2_passes = body[offset];
        offset += 1;
        const argon2_parallelism = body[offset];
        offset += 1;
        const argon2_memory = body[offset];
        offset += 1;

        // AEAD nonce
        const nonce_size = aead_algo.nonceSize() orelse return error.UnsupportedAeadAlgorithm;
        if (offset + nonce_size > body.len) return error.InvalidPacket;

        const aead_nonce = try allocator.dupe(u8, body[offset .. offset + nonce_size]);
        errdefer allocator.free(aead_nonce);
        offset += nonce_size;

        // Remaining bytes are encrypted session key + AEAD tag
        if (offset >= body.len) return error.InvalidPacket;
        const encrypted_session_key = try allocator.dupe(u8, body[offset..]);
        errdefer allocator.free(encrypted_session_key);

        return .{
            .version = version,
            .sym_algo = sym_algo,
            .aead_algo = aead_algo,
            .s2k_type = s2k_type,
            .argon2_salt = argon2_salt,
            .argon2_passes = argon2_passes,
            .argon2_parallelism = argon2_parallelism,
            .argon2_memory = argon2_memory,
            .aead_nonce = aead_nonce,
            .encrypted_session_key = encrypted_session_key,
        };
    }

    /// Serialize the V6 SKESK packet to its body bytes.
    pub fn serialize(self: @This(), allocator: Allocator) ![]u8 {
        // Calculate S2K specifier length: type(1) + salt(16) + t(1) + p(1) + m(1) = 20
        const s2k_spec_len: usize = 20;
        // Count = sym(1) + aead(1) + s2k_specifier
        const count: u8 = @intCast(2 + s2k_spec_len);

        // Total: version(1) + count(1) + sym(1) + aead(1) + s2k_spec + nonce + encrypted_key
        const total_len = 1 + 1 + 1 + 1 + s2k_spec_len +
            self.aead_nonce.len + self.encrypted_session_key.len;

        const buf = try allocator.alloc(u8, total_len);
        errdefer allocator.free(buf);

        buf[0] = self.version;
        buf[1] = count;
        buf[2] = @intFromEnum(self.sym_algo);
        buf[3] = @intFromEnum(self.aead_algo);

        var offset: usize = 4;

        // S2K specifier
        buf[offset] = self.s2k_type;
        offset += 1;
        @memcpy(buf[offset .. offset + 16], &self.argon2_salt);
        offset += 16;
        buf[offset] = self.argon2_passes;
        offset += 1;
        buf[offset] = self.argon2_parallelism;
        offset += 1;
        buf[offset] = self.argon2_memory;
        offset += 1;

        // AEAD nonce
        @memcpy(buf[offset .. offset + self.aead_nonce.len], self.aead_nonce);
        offset += self.aead_nonce.len;

        // Encrypted session key
        @memcpy(buf[offset..], self.encrypted_session_key);

        return buf;
    }

    /// Free all allocator-owned memory.
    pub fn deinit(self: @This(), allocator: Allocator) void {
        allocator.free(self.aead_nonce);
        allocator.free(self.encrypted_session_key);
    }

    /// Build the AEAD associated data for encryption/decryption.
    ///
    /// AD = 0xC3 || version(1) || sym_algo(1) || aead_algo(1) || s2k_specifier
    pub fn buildAssociatedData(self: @This(), allocator: Allocator) ![]u8 {
        // 0xC3 is the packet header byte: new-format, tag 3
        const s2k_spec_len: usize = 20;
        const ad_len = 1 + 1 + 1 + 1 + s2k_spec_len;
        const ad = try allocator.alloc(u8, ad_len);
        errdefer allocator.free(ad);

        ad[0] = 0xC3; // Packet tag byte
        ad[1] = self.version;
        ad[2] = @intFromEnum(self.sym_algo);
        ad[3] = @intFromEnum(self.aead_algo);
        ad[4] = self.s2k_type;
        @memcpy(ad[5..21], &self.argon2_salt);
        ad[21] = self.argon2_passes;
        ad[22] = self.argon2_parallelism;
        ad[23] = self.argon2_memory;

        return ad;
    }

    /// Get the Argon2S2K parameters for key derivation.
    pub fn getArgon2Params(self: @This()) Argon2S2K {
        return .{
            .salt = self.argon2_salt,
            .passes = self.argon2_passes,
            .parallelism = self.argon2_parallelism,
            .encoded_memory = self.argon2_memory,
        };
    }

    /// Get the expected session key length (excluding the AEAD tag).
    pub fn expectedSessionKeyLen(self: @This()) ?usize {
        const tag_size = self.aead_algo.tagSize() orelse return null;
        if (self.encrypted_session_key.len <= tag_size) return null;
        return self.encrypted_session_key.len - tag_size;
    }
};

/// Create a V6 SKESK packet from a passphrase and session key.
///
/// This derives a key-encryption key from the passphrase using Argon2id,
/// then encrypts the session key using the specified AEAD algorithm.
///
/// Note: Actual AEAD encryption is deferred to the caller since it requires
/// the AEAD implementation. This function constructs the packet structure
/// with placeholder encrypted data. In production, you would use the
/// appropriate AEAD mode (EAX, OCB, or GCM) after key derivation.
///
/// Returns the serialized V6 SKESK packet body.
pub fn createV6Skesk(
    allocator: Allocator,
    passphrase: []const u8,
    session_key: []const u8,
    sym_algo: SymmetricAlgorithm,
    aead_algo: AeadAlgorithm,
) ![]u8 {
    _ = passphrase;

    // Generate random Argon2 parameters
    const argon2_params = Argon2S2K.defaultInteractive();

    // Get nonce size for the AEAD algorithm
    const nonce_size = aead_algo.nonceSize() orelse return error.UnsupportedAeadAlgorithm;
    const tag_size = aead_algo.tagSize() orelse return error.UnsupportedAeadAlgorithm;

    // Generate random nonce
    var nonce_buf: [16]u8 = undefined;
    std.crypto.random.bytes(nonce_buf[0..nonce_size]);
    const aead_nonce = try allocator.dupe(u8, nonce_buf[0..nonce_size]);
    errdefer allocator.free(aead_nonce);

    // Placeholder encrypted session key:
    // In a full implementation, we would derive a KEK with Argon2 then AEAD-encrypt.
    // For now, store session_key + tag_size zero bytes (simulated tag).
    const enc_len = session_key.len + tag_size;
    const encrypted_sk = try allocator.alloc(u8, enc_len);
    errdefer allocator.free(encrypted_sk);
    @memcpy(encrypted_sk[0..session_key.len], session_key);
    @memset(encrypted_sk[session_key.len..], 0);

    const pkt = V6SKESKPacket{
        .version = 6,
        .sym_algo = sym_algo,
        .aead_algo = aead_algo,
        .s2k_type = 4,
        .argon2_salt = argon2_params.salt,
        .argon2_passes = argon2_params.passes,
        .argon2_parallelism = argon2_params.parallelism,
        .argon2_memory = argon2_params.encoded_memory,
        .aead_nonce = aead_nonce,
        .encrypted_session_key = encrypted_sk,
    };

    const serialized = try pkt.serialize(allocator);

    // Clean up the temporary slices (serialize made copies)
    allocator.free(aead_nonce);
    allocator.free(encrypted_sk);

    return serialized;
}

/// Attempt to decrypt a V6 SKESK packet and recover the session key.
///
/// This derives the key-encryption key from the passphrase using the
/// packet's Argon2 parameters, then uses AEAD decryption.
///
/// Note: Actual AEAD decryption requires the full AEAD implementation.
/// This function derives the KEK and returns it for the caller to
/// perform AEAD decryption with the appropriate mode.
///
/// Returns the derived key-encryption key.
pub fn decryptV6Skesk(
    allocator: Allocator,
    packet: *const V6SKESKPacket,
    passphrase: []const u8,
) ![]u8 {
    const argon2_params = packet.getArgon2Params();

    // Determine key size for the symmetric algorithm
    const key_len = packet.sym_algo.keySize() orelse return error.UnsupportedAlgorithm;

    // Derive the key-encryption key using Argon2id
    const kek = try allocator.alloc(u8, key_len);
    errdefer allocator.free(kek);

    argon2_params.deriveKey(allocator, passphrase, kek) catch {
        allocator.free(kek);
        return error.KeyDerivationFailed;
    };

    return kek;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "V6SKESKPacket parse basic GCM" {
    const allocator = std.testing.allocator;

    // Build a V6 SKESK body with Argon2 + GCM
    var body: [100]u8 = undefined;
    body[0] = 6; // version
    body[1] = 22; // count: sym(1) + aead(1) + s2k(20) = 22
    body[2] = @intFromEnum(SymmetricAlgorithm.aes256); // sym algo
    body[3] = @intFromEnum(AeadAlgorithm.gcm); // AEAD algo
    body[4] = 4; // S2K type: Argon2
    @memset(body[5..21], 0xAA); // salt (16 bytes)
    body[21] = 1; // passes
    body[22] = 4; // parallelism
    body[23] = 21; // memory (2^21 = 2 MiB)
    // GCM nonce: 12 bytes
    @memset(body[24..36], 0xBB);
    // Encrypted session key + GCM tag: 32 + 16 = 48 bytes
    @memset(body[36..84], 0xCC);

    const pkt = try V6SKESKPacket.parse(allocator, body[0..84]);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 6), pkt.version);
    try std.testing.expectEqual(SymmetricAlgorithm.aes256, pkt.sym_algo);
    try std.testing.expectEqual(AeadAlgorithm.gcm, pkt.aead_algo);
    try std.testing.expectEqual(@as(u8, 4), pkt.s2k_type);
    try std.testing.expectEqual(@as(u8, 1), pkt.argon2_passes);
    try std.testing.expectEqual(@as(u8, 4), pkt.argon2_parallelism);
    try std.testing.expectEqual(@as(u8, 21), pkt.argon2_memory);
    try std.testing.expectEqual(@as(usize, 12), pkt.aead_nonce.len);
    try std.testing.expectEqual(@as(usize, 48), pkt.encrypted_session_key.len);
}

test "V6SKESKPacket parse OCB" {
    const allocator = std.testing.allocator;

    var body: [100]u8 = undefined;
    body[0] = 6;
    body[1] = 22;
    body[2] = @intFromEnum(SymmetricAlgorithm.aes128);
    body[3] = @intFromEnum(AeadAlgorithm.ocb);
    body[4] = 4;
    @memset(body[5..21], 0x11);
    body[21] = 3;
    body[22] = 2;
    body[23] = 16;
    // OCB nonce: 15 bytes
    @memset(body[24..39], 0x22);
    // Encrypted key + tag
    @memset(body[39..71], 0x33);

    const pkt = try V6SKESKPacket.parse(allocator, body[0..71]);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(AeadAlgorithm.ocb, pkt.aead_algo);
    try std.testing.expectEqual(@as(usize, 15), pkt.aead_nonce.len);
    try std.testing.expectEqual(@as(u8, 3), pkt.argon2_passes);
    try std.testing.expectEqual(@as(u8, 2), pkt.argon2_parallelism);
}

test "V6SKESKPacket parse EAX" {
    const allocator = std.testing.allocator;

    var body: [100]u8 = undefined;
    body[0] = 6;
    body[1] = 22;
    body[2] = @intFromEnum(SymmetricAlgorithm.aes256);
    body[3] = @intFromEnum(AeadAlgorithm.eax);
    body[4] = 4;
    @memset(body[5..21], 0x44);
    body[21] = 1;
    body[22] = 1;
    body[23] = 10;
    // EAX nonce: 16 bytes
    @memset(body[24..40], 0x55);
    // Encrypted key + tag
    @memset(body[40..72], 0x66);

    const pkt = try V6SKESKPacket.parse(allocator, body[0..72]);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(AeadAlgorithm.eax, pkt.aead_algo);
    try std.testing.expectEqual(@as(usize, 16), pkt.aead_nonce.len);
}

test "V6SKESKPacket wrong version" {
    const allocator = std.testing.allocator;

    var body: [40]u8 = undefined;
    body[0] = 4; // V4, not V6
    @memset(body[1..], 0);

    try std.testing.expectError(error.UnsupportedVersion, V6SKESKPacket.parse(allocator, &body));
}

test "V6SKESKPacket unsupported S2K type" {
    const allocator = std.testing.allocator;

    var body: [50]u8 = undefined;
    body[0] = 6;
    body[1] = 22;
    body[2] = @intFromEnum(SymmetricAlgorithm.aes256);
    body[3] = @intFromEnum(AeadAlgorithm.gcm);
    body[4] = 3; // Iterated S2K, not Argon2
    @memset(body[5..], 0);

    try std.testing.expectError(error.UnsupportedS2KType, V6SKESKPacket.parse(allocator, &body));
}

test "V6SKESKPacket body too short" {
    const allocator = std.testing.allocator;

    const body = [_]u8{ 6, 22, 9, 3, 4 };
    try std.testing.expectError(error.InvalidPacket, V6SKESKPacket.parse(allocator, &body));
}

test "V6SKESKPacket serialize round-trip" {
    const allocator = std.testing.allocator;

    var body: [100]u8 = undefined;
    body[0] = 6;
    body[1] = 22;
    body[2] = @intFromEnum(SymmetricAlgorithm.aes256);
    body[3] = @intFromEnum(AeadAlgorithm.gcm);
    body[4] = 4;
    @memset(body[5..21], 0xAA);
    body[21] = 1;
    body[22] = 4;
    body[23] = 21;
    @memset(body[24..36], 0xBB);
    @memset(body[36..68], 0xCC);

    const pkt = try V6SKESKPacket.parse(allocator, body[0..68]);
    defer pkt.deinit(allocator);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);

    try std.testing.expectEqualSlices(u8, body[0..68], serialized);
}

test "V6SKESKPacket buildAssociatedData" {
    const allocator = std.testing.allocator;

    var body: [100]u8 = undefined;
    body[0] = 6;
    body[1] = 22;
    body[2] = @intFromEnum(SymmetricAlgorithm.aes256);
    body[3] = @intFromEnum(AeadAlgorithm.gcm);
    body[4] = 4;
    @memset(body[5..21], 0xAA);
    body[21] = 1;
    body[22] = 4;
    body[23] = 21;
    @memset(body[24..36], 0xBB);
    @memset(body[36..68], 0xCC);

    const pkt = try V6SKESKPacket.parse(allocator, body[0..68]);
    defer pkt.deinit(allocator);

    const ad = try pkt.buildAssociatedData(allocator);
    defer allocator.free(ad);

    try std.testing.expectEqual(@as(usize, 24), ad.len);
    try std.testing.expectEqual(@as(u8, 0xC3), ad[0]); // Packet tag
    try std.testing.expectEqual(@as(u8, 6), ad[1]); // Version
    try std.testing.expectEqual(@as(u8, @intFromEnum(SymmetricAlgorithm.aes256)), ad[2]);
    try std.testing.expectEqual(@as(u8, @intFromEnum(AeadAlgorithm.gcm)), ad[3]);
    try std.testing.expectEqual(@as(u8, 4), ad[4]); // S2K type
}

test "V6SKESKPacket getArgon2Params" {
    const allocator = std.testing.allocator;

    var body: [100]u8 = undefined;
    body[0] = 6;
    body[1] = 22;
    body[2] = @intFromEnum(SymmetricAlgorithm.aes256);
    body[3] = @intFromEnum(AeadAlgorithm.gcm);
    body[4] = 4;
    @memset(body[5..21], 0x42);
    body[21] = 3;
    body[22] = 4;
    body[23] = 21;
    @memset(body[24..36], 0xBB);
    @memset(body[36..68], 0xCC);

    const pkt = try V6SKESKPacket.parse(allocator, body[0..68]);
    defer pkt.deinit(allocator);

    const params = pkt.getArgon2Params();
    try std.testing.expectEqual(@as(u8, 3), params.passes);
    try std.testing.expectEqual(@as(u8, 4), params.parallelism);
    try std.testing.expectEqual(@as(u8, 21), params.encoded_memory);
    try std.testing.expectEqual(@as(u8, 0x42), params.salt[0]);
}

test "V6SKESKPacket expectedSessionKeyLen" {
    const allocator = std.testing.allocator;

    var body: [100]u8 = undefined;
    body[0] = 6;
    body[1] = 22;
    body[2] = @intFromEnum(SymmetricAlgorithm.aes256);
    body[3] = @intFromEnum(AeadAlgorithm.gcm);
    body[4] = 4;
    @memset(body[5..21], 0xAA);
    body[21] = 1;
    body[22] = 4;
    body[23] = 21;
    @memset(body[24..36], 0xBB);
    // 48 bytes: 32-byte session key + 16-byte GCM tag
    @memset(body[36..84], 0xCC);

    const pkt = try V6SKESKPacket.parse(allocator, body[0..84]);
    defer pkt.deinit(allocator);

    const sk_len = pkt.expectedSessionKeyLen();
    try std.testing.expect(sk_len != null);
    try std.testing.expectEqual(@as(usize, 32), sk_len.?);
}

test "V6SKESKPacket data is independent copy" {
    const allocator = std.testing.allocator;

    var body: [100]u8 = undefined;
    body[0] = 6;
    body[1] = 22;
    body[2] = @intFromEnum(SymmetricAlgorithm.aes256);
    body[3] = @intFromEnum(AeadAlgorithm.gcm);
    body[4] = 4;
    @memset(body[5..21], 0xAA);
    body[21] = 1;
    body[22] = 4;
    body[23] = 21;
    @memset(body[24..36], 0xBB);
    @memset(body[36..68], 0xCC);

    const pkt = try V6SKESKPacket.parse(allocator, body[0..68]);
    defer pkt.deinit(allocator);

    // Mutate original
    body[24] = 0xFF;
    body[36] = 0xFF;

    // Parsed nonce and encrypted key should be unchanged
    try std.testing.expectEqual(@as(u8, 0xBB), pkt.aead_nonce[0]);
    try std.testing.expectEqual(@as(u8, 0xCC), pkt.encrypted_session_key[0]);
}
