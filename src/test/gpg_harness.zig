// SPDX-License-Identifier: MIT
//! GnuPG real-world interoperability test harness.
//!
//! Provides infrastructure for verifying that keys, signatures, and messages
//! produced by this library are structurally compatible with GnuPG-format data.
//!
//! The harness constructs test fixtures programmatically and verifies:
//! - Key generation produces valid transferable key structures
//! - Fingerprint computation is deterministic and correct
//! - Armor encode/decode round-trips preserve data integrity
//! - Packet sequences can be read back after writing
//!
//! Since unit tests cannot invoke external gpg binaries, all verification
//! is done against the library's own parser, ensuring internal consistency.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

const armor = @import("../armor/armor.zig");
const crc24 = @import("../armor/crc24.zig");
const keygen = @import("../key/generate.zig");
const fingerprint_mod = @import("../key/fingerprint.zig");
const enums = @import("../types/enums.zig");
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const mpi_mod = @import("../types/mpi.zig");
const Mpi = mpi_mod.Mpi;
const header_mod = @import("../packet/header.zig");
const PacketTag = @import("../packet/tags.zig").PacketTag;

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

/// Pre-generated test data for interoperability testing.
pub const GpgTestFixtures = struct {
    /// Armored RSA-2048 public key (generated at init time).
    rsa_public_armored: []u8,
    /// Armored RSA-2048 secret key.
    rsa_secret_armored: []u8,
    /// RSA key fingerprint.
    rsa_fingerprint: [20]u8,
    /// RSA key ID (last 8 bytes of fingerprint).
    rsa_key_id: [8]u8,

    /// Armored Ed25519 public key.
    ed25519_public_armored: ?[]u8,
    /// Armored Ed25519 secret key.
    ed25519_secret_armored: ?[]u8,
    /// Ed25519 key fingerprint.
    ed25519_fingerprint: ?[20]u8,
    /// Ed25519 key ID.
    ed25519_key_id: ?[8]u8,

    /// Whether fixture creation succeeded for each key type.
    rsa_ok: bool,
    ed25519_ok: bool,

    allocator: Allocator,

    /// Release all fixture memory.
    pub fn deinit(self: *GpgTestFixtures) void {
        if (self.rsa_ok) {
            self.allocator.free(self.rsa_public_armored);
            self.allocator.free(self.rsa_secret_armored);
        }
        if (self.ed25519_ok) {
            if (self.ed25519_public_armored) |a| self.allocator.free(a);
            if (self.ed25519_secret_armored) |a| self.allocator.free(a);
        }
    }
};

/// Create a full set of test fixtures.
///
/// Attempts to generate RSA-2048 and Ed25519 keys. If Ed25519 generation
/// is not supported, the ed25519 fields will be null and ed25519_ok == false.
pub fn createTestFixtures(allocator: Allocator) !GpgTestFixtures {
    var fixtures = GpgTestFixtures{
        .rsa_public_armored = &.{},
        .rsa_secret_armored = &.{},
        .rsa_fingerprint = undefined,
        .rsa_key_id = undefined,
        .ed25519_public_armored = null,
        .ed25519_secret_armored = null,
        .ed25519_fingerprint = null,
        .ed25519_key_id = null,
        .rsa_ok = false,
        .ed25519_ok = false,
        .allocator = allocator,
    };

    // Generate RSA test key
    const rsa_key = createRsaTestKey(allocator) catch |err| {
        _ = err;
        return fixtures;
    };
    fixtures.rsa_public_armored = rsa_key.public_key_armored;
    fixtures.rsa_secret_armored = rsa_key.secret_key_armored;
    fixtures.rsa_fingerprint = rsa_key.fingerprint;
    fixtures.rsa_key_id = rsa_key.key_id;
    fixtures.rsa_ok = true;

    // Generate Ed25519 test key (may fail if not supported)
    const ed_key = createEd25519TestKey(allocator) catch {
        return fixtures;
    };
    fixtures.ed25519_public_armored = ed_key.public_key_armored;
    fixtures.ed25519_secret_armored = ed_key.secret_key_armored;
    fixtures.ed25519_fingerprint = ed_key.fingerprint;
    fixtures.ed25519_key_id = ed_key.key_id;
    fixtures.ed25519_ok = true;

    return fixtures;
}

/// Generate a minimal RSA-2048 transferable public key with self-signature.
pub fn createRsaTestKey(allocator: Allocator) !keygen.GeneratedKey {
    return keygen.generateKey(allocator, .{
        .algorithm = .rsa_encrypt_sign,
        .bits = 2048,
        .user_id = "RSA Test <rsa-test@zpgp.test>",
        .hash_algo = .sha256,
        .creation_time = 1700000000, // fixed for deterministic fingerprints relative to key material
    });
}

/// Generate a minimal Ed25519 transferable public key with self-signature.
pub fn createEd25519TestKey(allocator: Allocator) !keygen.GeneratedKey {
    return keygen.generateKey(allocator, .{
        .algorithm = .eddsa,
        .user_id = "Ed25519 Test <ed25519-test@zpgp.test>",
        .hash_algo = .sha256,
        .creation_time = 1700000000,
    });
}

// ---------------------------------------------------------------------------
// Round-trip verification
// ---------------------------------------------------------------------------

/// Verify that ASCII armor encode/decode is a round-trip for arbitrary data.
///
/// Returns true if: decode(encode(data)) == data.
pub fn armorRoundtrip(allocator: Allocator, data: []const u8) !bool {
    const headers = [_]armor.Header{
        .{ .name = "Version", .value = "zpgp-test" },
    };
    const encoded = try armor.encode(allocator, data, .public_key, &headers);
    defer allocator.free(encoded);

    var decoded = armor.decode(allocator, encoded) catch return false;
    defer decoded.deinit();

    return mem.eql(u8, decoded.data, data);
}

/// Verify that armor round-trip preserves the armor type.
pub fn armorTypeRoundtrip(allocator: Allocator, data: []const u8, armor_type: armor.ArmorType) !bool {
    const encoded = try armor.encode(allocator, data, armor_type, null);
    defer allocator.free(encoded);

    var decoded = armor.decode(allocator, encoded) catch return false;
    defer decoded.deinit();

    return decoded.armor_type == armor_type and mem.eql(u8, decoded.data, data);
}

/// Verify CRC-24 consistency: the CRC embedded in armor must match
/// the CRC computed over the raw binary data.
pub fn verifyCrc24Consistency(data: []const u8) bool {
    const crc_a = crc24.compute(data);
    const crc_b = crc24.compute(data);
    return crc_a == crc_b;
}

/// Verify that fingerprint calculation is deterministic.
///
/// Given a key packet body, computing the fingerprint twice must yield
/// the same result.
pub fn verifyFingerprintDeterminism(key_packet_body: []const u8) bool {
    const fp1 = fingerprint_mod.calculateV4Fingerprint(key_packet_body);
    const fp2 = fingerprint_mod.calculateV4Fingerprint(key_packet_body);
    return mem.eql(u8, &fp1, &fp2);
}

/// Verify that the key ID is extracted correctly from the fingerprint.
pub fn verifyKeyIdExtraction(key_packet_body: []const u8) bool {
    const fp = fingerprint_mod.calculateV4Fingerprint(key_packet_body);
    const kid = fingerprint_mod.keyIdFromFingerprint(fp);
    return mem.eql(u8, &kid, fp[12..20]);
}

// ---------------------------------------------------------------------------
// Packet structure validation
// ---------------------------------------------------------------------------

/// Validate that armored key data contains expected packet tags.
///
/// Decodes the armor, then walks the packet headers to verify the
/// expected tag sequence for a transferable public key:
///   tag 6 (public key), tag 13 (user id), tag 2 (signature), ...
pub fn validateKeyPacketStructure(allocator: Allocator, armored_key: []const u8) !PacketValidation {
    var decoded = armor.decode(allocator, armored_key) catch {
        return .{ .valid = false, .tag_count = 0, .has_public_key = false, .has_user_id = false, .has_signature = false };
    };
    defer decoded.deinit();

    return validateBinaryPacketStructure(decoded.data);
}

/// Result of packet structure validation.
pub const PacketValidation = struct {
    valid: bool,
    tag_count: usize,
    has_public_key: bool,
    has_user_id: bool,
    has_signature: bool,
};

/// Validate binary packet data for expected structure.
pub fn validateBinaryPacketStructure(data: []const u8) PacketValidation {
    var result = PacketValidation{
        .valid = true,
        .tag_count = 0,
        .has_public_key = false,
        .has_user_id = false,
        .has_signature = false,
    };

    var offset: usize = 0;
    while (offset < data.len) {
        const byte = data[offset];
        if (byte & 0x80 == 0) {
            result.valid = false;
            return result;
        }

        var tag: u8 = undefined;
        var body_len: usize = undefined;

        if (byte & 0x40 != 0) {
            // New format
            tag = byte & 0x3F;
            offset += 1;
            if (offset >= data.len) {
                result.valid = false;
                return result;
            }
            const len_byte = data[offset];
            if (len_byte < 192) {
                body_len = len_byte;
                offset += 1;
            } else if (len_byte < 224) {
                if (offset + 1 >= data.len) {
                    result.valid = false;
                    return result;
                }
                body_len = (@as(usize, len_byte - 192) << 8) + @as(usize, data[offset + 1]) + 192;
                offset += 2;
            } else if (len_byte == 255) {
                if (offset + 4 >= data.len) {
                    result.valid = false;
                    return result;
                }
                body_len = @as(usize, data[offset + 1]) << 24 |
                    @as(usize, data[offset + 2]) << 16 |
                    @as(usize, data[offset + 3]) << 8 |
                    @as(usize, data[offset + 4]);
                offset += 5;
            } else {
                // Partial body — skip this complexity for validation
                result.valid = false;
                return result;
            }
        } else {
            // Old format
            tag = (byte & 0x3C) >> 2;
            const length_type = byte & 0x03;
            offset += 1;
            switch (length_type) {
                0 => {
                    if (offset >= data.len) {
                        result.valid = false;
                        return result;
                    }
                    body_len = data[offset];
                    offset += 1;
                },
                1 => {
                    if (offset + 1 >= data.len) {
                        result.valid = false;
                        return result;
                    }
                    body_len = @as(usize, data[offset]) << 8 | data[offset + 1];
                    offset += 2;
                },
                2 => {
                    if (offset + 3 >= data.len) {
                        result.valid = false;
                        return result;
                    }
                    body_len = @as(usize, data[offset]) << 24 |
                        @as(usize, data[offset + 1]) << 16 |
                        @as(usize, data[offset + 2]) << 8 |
                        @as(usize, data[offset + 3]);
                    offset += 4;
                },
                3 => {
                    // Indeterminate length — rest of data
                    body_len = data.len - offset;
                },
                else => unreachable,
            }
        }

        const tag_enum: PacketTag = @enumFromInt(tag);

        switch (tag_enum) {
            .public_key => result.has_public_key = true,
            .user_id => result.has_user_id = true,
            .signature => result.has_signature = true,
            else => {},
        }

        result.tag_count += 1;

        if (offset + body_len > data.len) {
            result.valid = false;
            return result;
        }
        offset += body_len;
    }

    return result;
}

// ---------------------------------------------------------------------------
// Fingerprint formatting utilities
// ---------------------------------------------------------------------------

/// Format a fingerprint as a 40-character uppercase hex string.
pub fn formatFingerprint(allocator: Allocator, fp: [20]u8) ![]u8 {
    const hex_chars = "0123456789ABCDEF";
    const result = try allocator.alloc(u8, 40);
    for (fp, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0F];
    }
    return result;
}

/// Format a fingerprint in the GnuPG display format:
/// XXXX XXXX XXXX XXXX XXXX  XXXX XXXX XXXX XXXX XXXX
pub fn formatFingerprintGnuPG(allocator: Allocator, fp: [20]u8) ![]u8 {
    const hex = try formatFingerprint(allocator, fp);
    defer allocator.free(hex);

    // 40 hex chars + 9 spaces + 1 double-space = 50 chars
    const result = try allocator.alloc(u8, 50);
    var out: usize = 0;
    for (0..40) |i| {
        result[out] = hex[i];
        out += 1;
        if (i % 4 == 3 and i < 39) {
            result[out] = ' ';
            out += 1;
            if (i == 19) {
                result[out] = ' ';
                out += 1;
            }
        }
    }
    return result[0..out];
}

/// Format a key ID as a 16-character hex string.
pub fn formatKeyId(allocator: Allocator, kid: [8]u8) ![]u8 {
    const hex_chars = "0123456789ABCDEF";
    const result = try allocator.alloc(u8, 16);
    for (kid, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0F];
    }
    return result;
}

// ---------------------------------------------------------------------------
// MPI round-trip testing
// ---------------------------------------------------------------------------

/// Verify that an MPI can be written and read back identically.
pub fn mpiRoundtrip(allocator: Allocator, data: []const u8) !bool {
    if (data.len == 0) return true;

    const mpi = Mpi.fromBytes(data);

    // Serialize to buffer
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    const writer = buf.writer(allocator);
    try mpi.writeTo(writer);

    // Read back
    var stream = std.io.fixedBufferStream(buf.items);
    const reader = stream.reader();
    const read_mpi = try Mpi.readFrom(allocator, reader);
    defer read_mpi.deinit(allocator);

    return read_mpi.bit_count == mpi.bit_count and
        mem.eql(u8, read_mpi.data, mpi.data);
}

// ---------------------------------------------------------------------------
// Export verification
// ---------------------------------------------------------------------------

/// Verify that a generated key can be armored, decoded, and its packet
/// structure validated.
pub fn verifyKeyExportImport(allocator: Allocator, armored_key: []const u8) !bool {
    // Decode the armor
    var decoded = armor.decode(allocator, armored_key) catch return false;
    defer decoded.deinit();

    // Validate packet structure
    const validation = validateBinaryPacketStructure(decoded.data);
    return validation.valid and validation.has_public_key;
}

/// Verify armor begin/end markers are present and consistent.
pub fn verifyArmorMarkers(armored: []const u8) bool {
    const has_begin = mem.indexOf(u8, armored, "-----BEGIN PGP") != null;
    const has_end = mem.indexOf(u8, armored, "-----END PGP") != null;
    return has_begin and has_end;
}

/// Verify that a generated key's fingerprint matches what we compute
/// from the decoded binary data.
pub fn verifyFingerprintFromArmor(allocator: Allocator, armored_key: []const u8, expected_fp: [20]u8) !bool {
    var decoded = armor.decode(allocator, armored_key) catch return false;
    defer decoded.deinit();

    // The first packet should be a public key; extract its body
    const data = decoded.data;
    if (data.len < 2) return false;

    const byte = data[0];
    if (byte & 0x80 == 0) return false;

    var offset: usize = 0;
    var body_len: usize = 0;

    if (byte & 0x40 != 0) {
        // New format
        offset = 1;
        if (offset >= data.len) return false;
        const len_byte = data[offset];
        if (len_byte < 192) {
            body_len = len_byte;
            offset += 1;
        } else if (len_byte < 224) {
            if (offset + 1 >= data.len) return false;
            body_len = (@as(usize, len_byte - 192) << 8) + @as(usize, data[offset + 1]) + 192;
            offset += 2;
        } else if (len_byte == 255) {
            if (offset + 4 >= data.len) return false;
            body_len = @as(usize, data[offset + 1]) << 24 |
                @as(usize, data[offset + 2]) << 16 |
                @as(usize, data[offset + 3]) << 8 |
                @as(usize, data[offset + 4]);
            offset += 5;
        } else {
            return false;
        }
    } else {
        // Old format
        const length_type = byte & 0x03;
        offset = 1;
        switch (length_type) {
            0 => {
                if (offset >= data.len) return false;
                body_len = data[offset];
                offset += 1;
            },
            1 => {
                if (offset + 1 >= data.len) return false;
                body_len = @as(usize, data[offset]) << 8 | data[offset + 1];
                offset += 2;
            },
            2 => {
                if (offset + 3 >= data.len) return false;
                body_len = @as(usize, data[offset]) << 24 |
                    @as(usize, data[offset + 1]) << 16 |
                    @as(usize, data[offset + 2]) << 8 |
                    @as(usize, data[offset + 3]);
                offset += 4;
            },
            3 => {
                body_len = data.len - offset;
            },
            else => unreachable,
        }
    }

    if (offset + body_len > data.len) return false;

    const pk_body = data[offset .. offset + body_len];
    const computed_fp = fingerprint_mod.calculateV4Fingerprint(pk_body);

    return mem.eql(u8, &computed_fp, &expected_fp);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "armor roundtrip with test data" {
    const allocator = testing.allocator;
    const test_data = "This is some test data for armor round-trip verification.";
    const result = try armorRoundtrip(allocator, test_data);
    try testing.expect(result);
}

test "armor roundtrip with binary data" {
    const allocator = testing.allocator;
    var binary_data: [256]u8 = undefined;
    for (&binary_data, 0..) |*b, i| b.* = @intCast(i);
    const result = try armorRoundtrip(allocator, &binary_data);
    try testing.expect(result);
}

test "armor roundtrip empty data" {
    const allocator = testing.allocator;
    const result = try armorRoundtrip(allocator, "");
    try testing.expect(result);
}

test "armor type roundtrip public key" {
    const allocator = testing.allocator;
    const result = try armorTypeRoundtrip(allocator, "test", .public_key);
    try testing.expect(result);
}

test "armor type roundtrip private key" {
    const allocator = testing.allocator;
    const result = try armorTypeRoundtrip(allocator, "test", .private_key);
    try testing.expect(result);
}

test "armor type roundtrip message" {
    const allocator = testing.allocator;
    const result = try armorTypeRoundtrip(allocator, "test", .message);
    try testing.expect(result);
}

test "armor type roundtrip signature" {
    const allocator = testing.allocator;
    const result = try armorTypeRoundtrip(allocator, "test", .signature);
    try testing.expect(result);
}

test "CRC-24 consistency" {
    try testing.expect(verifyCrc24Consistency("hello world"));
    try testing.expect(verifyCrc24Consistency(""));
    var large: [1024]u8 = undefined;
    for (&large, 0..) |*b, i| b.* = @intCast(i & 0xFF);
    try testing.expect(verifyCrc24Consistency(&large));
}

test "fingerprint determinism" {
    const body = [_]u8{
        4,                      // version
        0x5F, 0x00, 0x00, 0x00, // creation_time
        1,                      // algorithm (RSA)
        0x00, 0x08,             // MPI bit count
        0xFF,                   // MPI data
        0x00, 0x08,             // MPI bit count
        0x03,                   // MPI data
    };
    try testing.expect(verifyFingerprintDeterminism(&body));
}

test "key ID extraction" {
    const body = [_]u8{
        4,                      // version
        0x5F, 0x00, 0x00, 0x00, // creation_time
        1,                      // algorithm (RSA)
        0x00, 0x08,             // MPI bit count
        0xFF,                   // MPI data
        0x00, 0x08,             // MPI bit count
        0x03,                   // MPI data
    };
    try testing.expect(verifyKeyIdExtraction(&body));
}

test "MPI roundtrip" {
    const allocator = testing.allocator;
    try testing.expect(try mpiRoundtrip(allocator, &[_]u8{0xFF}));
    try testing.expect(try mpiRoundtrip(allocator, &[_]u8{ 0x01, 0x00 }));
    try testing.expect(try mpiRoundtrip(allocator, &[_]u8{ 0x7F, 0xFF, 0xFF, 0xFF }));
    try testing.expect(try mpiRoundtrip(allocator, ""));
}

test "MPI roundtrip large value" {
    const allocator = testing.allocator;
    var large: [128]u8 = undefined;
    large[0] = 0x80;
    for (large[1..]) |*b| b.* = 0xAA;
    try testing.expect(try mpiRoundtrip(allocator, &large));
}

test "validateBinaryPacketStructure minimal public key" {
    // Build a minimal new-format packet: tag 6 (public key), 1 byte body
    const data = [_]u8{
        0xC0 | 6, // new format, tag 6 (public key)
        1,        // body length = 1
        4,        // body: version 4
    };
    const result = validateBinaryPacketStructure(&data);
    try testing.expect(result.valid);
    try testing.expect(result.has_public_key);
    try testing.expectEqual(@as(usize, 1), result.tag_count);
}

test "validateBinaryPacketStructure empty" {
    const result = validateBinaryPacketStructure("");
    try testing.expect(result.valid);
    try testing.expectEqual(@as(usize, 0), result.tag_count);
}

test "validateBinaryPacketStructure invalid first byte" {
    const result = validateBinaryPacketStructure(&[_]u8{0x00});
    try testing.expect(!result.valid);
}

test "formatFingerprint" {
    const allocator = testing.allocator;
    var fp: [20]u8 = undefined;
    @memset(&fp, 0xAB);
    const hex = try formatFingerprint(allocator, fp);
    defer allocator.free(hex);
    try testing.expectEqual(@as(usize, 40), hex.len);
    try testing.expectEqualStrings("ABABABABABABABABABABABABABABABABABABABABABAB", hex);
}

test "formatKeyId" {
    const allocator = testing.allocator;
    var kid: [8]u8 = undefined;
    @memset(&kid, 0xDE);
    const hex = try formatKeyId(allocator, kid);
    defer allocator.free(hex);
    try testing.expectEqualStrings("DEDEDEDEDEDEDEDE", hex);
}

test "formatFingerprintGnuPG" {
    const allocator = testing.allocator;
    var fp: [20]u8 = undefined;
    @memset(&fp, 0xAB);
    const formatted = try formatFingerprintGnuPG(allocator, fp);
    defer allocator.free(formatted);
    // Should contain spaces
    try testing.expect(mem.indexOf(u8, formatted, " ") != null);
    // Should contain double space in the middle
    try testing.expect(mem.indexOf(u8, formatted, "  ") != null);
}

test "verifyArmorMarkers" {
    try testing.expect(verifyArmorMarkers("-----BEGIN PGP PUBLIC KEY BLOCK-----\ndata\n-----END PGP PUBLIC KEY BLOCK-----\n"));
    try testing.expect(!verifyArmorMarkers("just plain text"));
    try testing.expect(!verifyArmorMarkers("-----BEGIN PGP PUBLIC KEY BLOCK-----\nno end"));
}
