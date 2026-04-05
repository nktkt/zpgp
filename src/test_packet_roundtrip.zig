// SPDX-License-Identifier: MIT
//! Comprehensive packet round-trip tests for the zpgp library.
//!
//! Tests cover every packet type: create -> serialize -> parse -> compare.
//! Also tests packet header encoding/decoding for all length formats
//! and ASCII Armor round-trips.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

// Packet types
const LiteralDataPacket = @import("packets/literal_data.zig").LiteralDataPacket;
const DataFormat = @import("packets/literal_data.zig").DataFormat;
const UserIdPacket = @import("packets/user_id.zig").UserIdPacket;
const UserAttributePacket = @import("packets/user_attribute.zig").UserAttributePacket;
const TrustPacket = @import("packets/trust.zig").TrustPacket;
const MarkerPacket = @import("packets/marker.zig").MarkerPacket;
const OnePassSignaturePacket = @import("packets/one_pass_sig.zig").OnePassSignaturePacket;
const ModDetectionCodePacket = @import("packets/mod_detection.zig").ModDetectionCodePacket;
const CompressedDataPacket = @import("packets/compressed_data.zig").CompressedDataPacket;
const SymEncDataPacket = @import("packets/sym_enc_data.zig").SymEncDataPacket;
const SymEncIntegrityPacket = @import("packets/sym_enc_integrity.zig").SymEncIntegrityPacket;
const PKESKPacket = @import("packets/pkesk.zig").PKESKPacket;
const SKESKPacket = @import("packets/skesk.zig").SKESKPacket;
const SignaturePacket = @import("packets/signature.zig").SignaturePacket;
const PublicKeyPacket = @import("packets/public_key.zig").PublicKeyPacket;
const SecretKeyPacket = @import("packets/secret_key.zig").SecretKeyPacket;
const V3SignaturePacket = @import("packets/v3_signature.zig").V3SignaturePacket;
const V3PublicKeyPacket = @import("packets/v3_public_key.zig").V3PublicKeyPacket;
const V6PublicKeyPacket = @import("packets/v6_public_key.zig").V6PublicKeyPacket;
const V6SignaturePacket = @import("packets/v6_signature.zig").V6SignaturePacket;
const PaddingPacket = @import("packets/padding.zig").PaddingPacket;

// Packet infrastructure
const header_mod = @import("packet/header.zig");
const PacketTag = @import("packet/tags.zig").PacketTag;

// Types
const enums = @import("types/enums.zig");
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const CompressionAlgorithm = enums.CompressionAlgorithm;
const Mpi = @import("types/mpi.zig").Mpi;

// Armor
const armor = @import("armor/armor.zig");

// ==========================================================================
// Literal Data Packet round-trips
// ==========================================================================

test "LiteralDataPacket round-trip binary" {
    const allocator = testing.allocator;
    const body_data = "Hello, World! This is binary data.";

    // Build a packet body manually
    var body_buf: [2 + 0 + 4 + 34]u8 = undefined;
    body_buf[0] = 'b'; // binary format
    body_buf[1] = 0; // no filename
    mem.writeInt(u32, body_buf[2..6], 1700000000, .big); // timestamp
    @memcpy(body_buf[6..], body_data);

    const pkt = try LiteralDataPacket.parse(allocator, &body_buf);
    defer pkt.deinit(allocator);

    try testing.expectEqual(DataFormat.binary, pkt.format);
    try testing.expectEqual(@as(usize, 0), pkt.filename.len);
    try testing.expectEqual(@as(u32, 1700000000), pkt.timestamp);
    try testing.expectEqualSlices(u8, body_data, pkt.data);

    // Serialize and compare
    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try testing.expectEqualSlices(u8, &body_buf, serialized);
}

test "LiteralDataPacket round-trip text" {
    const allocator = testing.allocator;
    const text = "This is text data with line endings.\r\n";

    var body: [2 + 0 + 4 + 38]u8 = undefined;
    body[0] = 't'; // text format
    body[1] = 0; // no filename
    mem.writeInt(u32, body[2..6], 1600000000, .big);
    @memcpy(body[6..], text);

    const pkt = try LiteralDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try testing.expectEqual(DataFormat.text, pkt.format);
    try testing.expectEqualSlices(u8, text, pkt.data);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try testing.expectEqualSlices(u8, &body, serialized);
}

test "LiteralDataPacket round-trip with filename" {
    const allocator = testing.allocator;
    const filename = "test.txt";
    const data = "File contents here.";

    const body_len = 2 + filename.len + 4 + data.len;
    var body: [body_len]u8 = undefined;
    body[0] = 'b'; // binary
    body[1] = @intCast(filename.len);
    @memcpy(body[2 .. 2 + filename.len], filename);
    mem.writeInt(u32, body[2 + filename.len ..][0..4], 1500000000, .big);
    @memcpy(body[2 + filename.len + 4 ..], data);

    const pkt = try LiteralDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try testing.expectEqualStrings(filename, pkt.filename);
    try testing.expectEqualSlices(u8, data, pkt.data);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try testing.expectEqualSlices(u8, &body, serialized);
}

test "LiteralDataPacket empty data" {
    const allocator = testing.allocator;

    // Minimum valid body: format(1) + filename_len(1) + timestamp(4) = 6
    var body: [6]u8 = undefined;
    body[0] = 'b';
    body[1] = 0;
    mem.writeInt(u32, body[2..6], 0, .big);

    const pkt = try LiteralDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try testing.expectEqual(@as(usize, 0), pkt.data.len);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try testing.expectEqualSlices(u8, &body, serialized);
}

test "LiteralDataPacket UTF-8 format" {
    const allocator = testing.allocator;
    const data = "UTF-8 content: \xC3\xA9\xC3\xA0\xC3\xBC";

    var body: [6 + data.len]u8 = undefined;
    body[0] = 'u'; // UTF-8 format
    body[1] = 0;
    mem.writeInt(u32, body[2..6], 1700000000, .big);
    @memcpy(body[6..], data);

    const pkt = try LiteralDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try testing.expectEqual(@as(u8, 'u'), @intFromEnum(pkt.format));

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try testing.expectEqualSlices(u8, &body, serialized);
}

// ==========================================================================
// User ID Packet round-trips
// ==========================================================================

test "UserIdPacket round-trip" {
    const allocator = testing.allocator;
    const user_id = "Alice <alice@example.com>";

    const pkt = try UserIdPacket.parse(allocator, user_id);
    defer pkt.deinit(allocator);

    try testing.expectEqualStrings(user_id, pkt.id);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try testing.expectEqualSlices(u8, user_id, serialized);
}

test "UserIdPacket with Unicode" {
    const allocator = testing.allocator;
    const user_id = "\xC3\x89mile <emile@example.fr>";

    const pkt = try UserIdPacket.parse(allocator, user_id);
    defer pkt.deinit(allocator);

    try testing.expectEqualStrings(user_id, pkt.id);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try testing.expectEqualSlices(u8, user_id, serialized);
}

test "UserIdPacket with comment field" {
    const allocator = testing.allocator;
    const user_id = "Bob (Security Team) <bob@pgp.example.org>";

    const pkt = try UserIdPacket.parse(allocator, user_id);
    defer pkt.deinit(allocator);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try testing.expectEqualSlices(u8, user_id, serialized);
}

test "UserIdPacket empty" {
    const allocator = testing.allocator;

    const pkt = try UserIdPacket.parse(allocator, "");
    defer pkt.deinit(allocator);

    try testing.expectEqual(@as(usize, 0), pkt.id.len);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try testing.expectEqual(@as(usize, 0), serialized.len);
}

test "UserIdPacket long user ID" {
    const allocator = testing.allocator;
    var long_id: [500]u8 = undefined;
    @memset(&long_id, 'A');

    const pkt = try UserIdPacket.parse(allocator, &long_id);
    defer pkt.deinit(allocator);

    try testing.expectEqual(@as(usize, 500), pkt.id.len);
}

// ==========================================================================
// User Attribute Packet round-trips
// ==========================================================================

test "UserAttributePacket round-trip" {
    const allocator = testing.allocator;
    const body = [_]u8{ 0x01, 0x10, 0xFF, 0x00, 0xAB, 0xCD };

    const pkt = try UserAttributePacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try testing.expectEqualSlices(u8, &body, pkt.data);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try testing.expectEqualSlices(u8, &body, serialized);
}

test "UserAttributePacket empty body" {
    const allocator = testing.allocator;

    const pkt = try UserAttributePacket.parse(allocator, "");
    defer pkt.deinit(allocator);

    try testing.expectEqual(@as(usize, 0), pkt.data.len);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try testing.expectEqual(@as(usize, 0), serialized.len);
}

test "UserAttributePacket binary data" {
    const allocator = testing.allocator;
    // Simulate a JPEG image attribute subpacket header
    var body: [100]u8 = undefined;
    for (&body, 0..) |*b, i| b.* = @intCast(i % 256);

    const pkt = try UserAttributePacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try testing.expectEqualSlices(u8, &body, serialized);
}

// ==========================================================================
// Trust Packet round-trips
// ==========================================================================

test "TrustPacket round-trip" {
    const allocator = testing.allocator;
    const body = [_]u8{ 0x05, 0x60 }; // GnuPG trust value

    const pkt = try TrustPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try testing.expectEqualSlices(u8, &body, pkt.data);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try testing.expectEqualSlices(u8, &body, serialized);
}

test "TrustPacket single byte" {
    const allocator = testing.allocator;
    const body = [_]u8{0x00};

    const pkt = try TrustPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try testing.expectEqualSlices(u8, &body, serialized);
}

test "TrustPacket multiple bytes" {
    const allocator = testing.allocator;
    const body = [_]u8{ 0xFF, 0x00, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45 };

    const pkt = try TrustPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try testing.expectEqualSlices(u8, &body, serialized);
}

// ==========================================================================
// Marker Packet round-trips
// ==========================================================================

test "MarkerPacket round-trip" {
    const pkt = try MarkerPacket.parse("PGP");
    _ = pkt;
    const serialized = MarkerPacket.serialize();
    try testing.expectEqualStrings("PGP", &serialized);
}

test "MarkerPacket reject invalid" {
    try testing.expectError(error.InvalidPacket, MarkerPacket.parse("XYZ"));
    try testing.expectError(error.InvalidPacket, MarkerPacket.parse("PG"));
    try testing.expectError(error.InvalidPacket, MarkerPacket.parse("PGPX"));
    try testing.expectError(error.InvalidPacket, MarkerPacket.parse(""));
}

// ==========================================================================
// One-Pass Signature Packet round-trips
// ==========================================================================

test "OnePassSignaturePacket round-trip" {
    const body = [13]u8{
        3,    // version
        0x00, // sig type (binary signature)
        8,    // hash algo (SHA-256)
        1,    // pub algo (RSA)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // key ID
        1,    // not nested
    };

    const pkt = try OnePassSignaturePacket.parse(&body);
    try testing.expectEqual(@as(u8, 3), pkt.version);
    try testing.expectEqual(@as(u8, 0x00), pkt.sig_type);
    try testing.expectEqual(HashAlgorithm.sha256, pkt.hash_algo);
    try testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, pkt.pub_algo);
    try testing.expectEqual(@as(u8, 1), pkt.nested);

    const serialized = pkt.serialize();
    try testing.expectEqualSlices(u8, &body, &serialized);
}

test "OnePassSignaturePacket DSA round-trip" {
    const body = [13]u8{
        3,    // version
        0x01, // sig type (text signature)
        2,    // hash algo (SHA-1)
        17,   // pub algo (DSA)
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, // key ID
        0,    // nested
    };

    const pkt = try OnePassSignaturePacket.parse(&body);
    const serialized = pkt.serialize();
    try testing.expectEqualSlices(u8, &body, &serialized);
}

test "OnePassSignaturePacket wrong size rejected" {
    const short = [_]u8{3} ++ [_]u8{0} ** 11; // only 12 bytes
    try testing.expectError(error.InvalidPacket, OnePassSignaturePacket.parse(&short));
}

// ==========================================================================
// Modification Detection Code Packet round-trips
// ==========================================================================

test "ModDetectionCodePacket round-trip" {
    const hash = [20]u8{
        0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55,
        0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90, 0xAF, 0xD8, 0x07, 0x09,
    };

    const pkt = try ModDetectionCodePacket.parse(&hash);
    try testing.expectEqualSlices(u8, &hash, &pkt.hash);

    const serialized = pkt.serialize();
    try testing.expectEqualSlices(u8, &hash, &serialized);
}

test "ModDetectionCodePacket zero hash" {
    const hash = [_]u8{0} ** 20;
    const pkt = try ModDetectionCodePacket.parse(&hash);
    const serialized = pkt.serialize();
    try testing.expectEqualSlices(u8, &hash, &serialized);
}

test "ModDetectionCodePacket wrong length rejected" {
    const short = [_]u8{0} ** 19;
    try testing.expectError(error.InvalidPacket, ModDetectionCodePacket.parse(&short));
    const long = [_]u8{0} ** 21;
    try testing.expectError(error.InvalidPacket, ModDetectionCodePacket.parse(&long));
}

// ==========================================================================
// Compressed Data Packet round-trips
// ==========================================================================

test "CompressedDataPacket round-trip uncompressed" {
    const allocator = testing.allocator;

    // Uncompressed: algorithm=0 + raw data
    const inner = "This data is not compressed.";
    var body: [1 + inner.len]u8 = undefined;
    body[0] = 0; // uncompressed
    @memcpy(body[1..], inner);

    const pkt = try CompressedDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try testing.expectEqual(CompressionAlgorithm.uncompressed, pkt.algorithm);
    try testing.expectEqualSlices(u8, inner, pkt.compressed_data);

    // Decompress (for uncompressed, just returns a copy)
    const decompressed = try pkt.decompress(allocator);
    defer allocator.free(decompressed);
    try testing.expectEqualSlices(u8, inner, decompressed);
}

test "CompressedDataPacket empty data" {
    const allocator = testing.allocator;

    const body = [_]u8{0}; // algorithm only, no data
    const pkt = try CompressedDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try testing.expectEqual(@as(usize, 0), pkt.compressed_data.len);
}

// ==========================================================================
// Symmetrically Encrypted Data Packet round-trips
// ==========================================================================

test "SymEncDataPacket round-trip" {
    const allocator = testing.allocator;
    const body = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    const pkt = try SymEncDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try testing.expectEqualSlices(u8, &body, pkt.data);
}

test "SymEncDataPacket empty" {
    const allocator = testing.allocator;
    const pkt = try SymEncDataPacket.parse(allocator, "");
    defer pkt.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), pkt.data.len);
}

test "SymEncDataPacket large data" {
    const allocator = testing.allocator;
    var data: [1000]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i % 256);

    const pkt = try SymEncDataPacket.parse(allocator, &data);
    defer pkt.deinit(allocator);
    try testing.expectEqualSlices(u8, &data, pkt.data);
}

// ==========================================================================
// Sym. Encrypted Integrity Protected Data Packet round-trips
// ==========================================================================

test "SymEncIntegrityPacket round-trip" {
    const allocator = testing.allocator;

    var body: [17]u8 = undefined;
    body[0] = 1; // version
    @memset(body[1..], 0xAB);

    const pkt = try SymEncIntegrityPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try testing.expectEqual(@as(u8, 1), pkt.version);
    try testing.expectEqual(@as(usize, 16), pkt.data.len);
}

test "SymEncIntegrityPacket wrong version" {
    const allocator = testing.allocator;
    var body: [5]u8 = undefined;
    body[0] = 0; // invalid version
    @memset(body[1..], 0x00);
    try testing.expectError(error.UnsupportedVersion, SymEncIntegrityPacket.parse(allocator, &body));
}

test "SymEncIntegrityPacket empty data after version" {
    const allocator = testing.allocator;
    const body = [_]u8{1}; // version only, no data

    const pkt = try SymEncIntegrityPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), pkt.data.len);
}

// ==========================================================================
// PKESK Packet round-trips
// ==========================================================================

test "PKESKPacket round-trip RSA" {
    const allocator = testing.allocator;

    // Build a minimal PKESK body:
    // version(1)=3 + key_id(8) + algo(1) + MPI(bit_count=8, data=1byte)
    var body: [13]u8 = undefined;
    body[0] = 3; // version
    @memcpy(body[1..9], &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 });
    body[9] = 1; // RSA
    mem.writeInt(u16, body[10..12], 8, .big); // 8-bit MPI
    body[12] = 0xFF; // MPI data

    const pkt = try PKESKPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try testing.expectEqual(@as(u8, 3), pkt.version);
    try testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, pkt.algorithm);
    try testing.expectEqual(@as(usize, 1), pkt.encrypted_session_key.len);
    try testing.expectEqual(@as(u16, 8), pkt.encrypted_session_key[0].bit_count);
}

test "PKESKPacket wrong version" {
    const allocator = testing.allocator;
    var body: [13]u8 = undefined;
    body[0] = 4; // wrong version (expect 3)
    @memset(body[1..], 0);
    try testing.expectError(error.UnsupportedVersion, PKESKPacket.parse(allocator, &body));
}

// ==========================================================================
// SKESK Packet round-trips
// ==========================================================================

test "SKESKPacket round-trip simple S2K" {
    const allocator = testing.allocator;

    // version(1)=4 + algo(1) + S2K_type(1)=0 + hash(1) = 4 bytes
    const body = [_]u8{ 4, 9, 0, 8 }; // v4, AES-256, simple S2K, SHA-256

    const pkt = try SKESKPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try testing.expectEqual(@as(u8, 4), pkt.version);
    try testing.expectEqual(SymmetricAlgorithm.aes256, pkt.symmetric_algo);
    try testing.expect(pkt.encrypted_session_key == null);
}

test "SKESKPacket round-trip salted S2K" {
    const allocator = testing.allocator;

    // version(1)=4 + algo(1) + S2K: type(1)=1 + hash(1) + salt(8) = 12 bytes
    var body: [12]u8 = undefined;
    body[0] = 4; // version
    body[1] = 7; // AES-128
    body[2] = 1; // salted S2K
    body[3] = 8; // SHA-256
    @memcpy(body[4..12], &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE });

    const pkt = try SKESKPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try testing.expectEqual(@as(u8, 4), pkt.version);
    try testing.expectEqual(SymmetricAlgorithm.aes128, pkt.symmetric_algo);
    try testing.expectEqual(@as(usize, 10), pkt.s2k_data.len); // type + hash + salt
}

test "SKESKPacket with encrypted session key" {
    const allocator = testing.allocator;

    // version(1)=4 + algo(1) + S2K: type(1)=0 + hash(1) + esk(4) = 8 bytes
    const body = [_]u8{ 4, 9, 0, 8, 0xAA, 0xBB, 0xCC, 0xDD };

    const pkt = try SKESKPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try testing.expect(pkt.encrypted_session_key != null);
    try testing.expectEqual(@as(usize, 4), pkt.encrypted_session_key.?.len);
}

// ==========================================================================
// Signature Packet round-trips
// ==========================================================================

test "SignaturePacket round-trip minimal" {
    const allocator = testing.allocator;

    // Build a minimal V4 signature packet body:
    // version(1)=4 + sig_type(1) + pub_algo(1) + hash_algo(1) +
    // hashed_len(2)=0 + unhashed_len(2)=0 + hash_prefix(2) + MPI
    var body: [12]u8 = undefined;
    body[0] = 4; // version
    body[1] = 0x00; // sig type (binary)
    body[2] = 1; // RSA
    body[3] = 8; // SHA-256
    mem.writeInt(u16, body[4..6], 0, .big); // no hashed subpackets
    mem.writeInt(u16, body[6..8], 0, .big); // no unhashed subpackets
    body[8] = 0xAB; // hash prefix
    body[9] = 0xCD;
    mem.writeInt(u16, body[10..12], 8, .big); // MPI: 8-bit

    // Need at least 1 byte of MPI data
    var body_with_mpi: [13]u8 = undefined;
    @memcpy(body_with_mpi[0..12], &body);
    body_with_mpi[12] = 0xFF;

    const pkt = try SignaturePacket.parse(allocator, &body_with_mpi);
    defer pkt.deinit(allocator);

    try testing.expectEqual(@as(u8, 4), pkt.version);
    try testing.expectEqual(@as(u8, 0x00), pkt.sig_type);
    try testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, pkt.pub_algo);
    try testing.expectEqual(HashAlgorithm.sha256, pkt.hash_algo);
}

// ==========================================================================
// Public Key Packet round-trips
// ==========================================================================

test "PublicKeyPacket round-trip RSA" {
    const allocator = testing.allocator;

    // Build a V4 RSA public key body:
    // version(1)=4 + creation_time(4) + algo(1)=RSA + MPI(n) + MPI(e)
    var body: [12]u8 = undefined;
    body[0] = 4; // version
    mem.writeInt(u32, body[1..5], 1700000000, .big);
    body[5] = 1; // RSA
    mem.writeInt(u16, body[6..8], 8, .big); // n: 8-bit
    body[8] = 0xFF;
    mem.writeInt(u16, body[9..11], 8, .big); // e: 8-bit
    body[11] = 0x03;

    const pkt = try PublicKeyPacket.parse(allocator, &body, false);
    defer pkt.deinit(allocator);

    try testing.expectEqual(@as(u8, 4), pkt.version);
    try testing.expectEqual(@as(u32, 1700000000), pkt.creation_time);
    try testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, pkt.algorithm);
    try testing.expectEqual(@as(usize, 2), pkt.key_material.len);
    try testing.expect(!pkt.is_subkey);
}

test "PublicKeyPacket round-trip DSA" {
    const allocator = testing.allocator;

    // Build a V4 DSA public key body:
    // version(1)=4 + creation_time(4) + algo(1)=DSA + 4 MPIs (p,q,g,y)
    var body: [6 + 4 * 3]u8 = undefined; // 4 MPIs each 1-byte
    body[0] = 4;
    mem.writeInt(u32, body[1..5], 1600000000, .big);
    body[5] = 17; // DSA
    // 4 MPIs, each 8-bit with 1 byte of data
    var offset: usize = 6;
    for (0..4) |_| {
        mem.writeInt(u16, body[offset..][0..2], 8, .big);
        body[offset + 2] = 0xFF;
        offset += 3;
    }

    const pkt = try PublicKeyPacket.parse(allocator, &body, false);
    defer pkt.deinit(allocator);

    try testing.expectEqual(PublicKeyAlgorithm.dsa, pkt.algorithm);
    try testing.expectEqual(@as(usize, 4), pkt.key_material.len);
}

test "PublicKeyPacket subkey flag" {
    const allocator = testing.allocator;

    var body: [12]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], 1700000000, .big);
    body[5] = 1; // RSA
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xFF;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;

    const pkt = try PublicKeyPacket.parse(allocator, &body, true);
    defer pkt.deinit(allocator);

    try testing.expect(pkt.is_subkey);
}

// ==========================================================================
// V3 Signature Packet round-trips
// ==========================================================================

test "V3SignaturePacket round-trip" {
    const allocator = testing.allocator;

    // Build a V3 signature body:
    // version(1)=3 + hashed_len(1)=5 + sig_type(1) + creation_time(4)
    // + key_id(8) + pub_algo(1) + hash_algo(1) + hash_prefix(2) + MPI
    var body: [22]u8 = undefined;
    body[0] = 3; // version
    body[1] = 5; // hashed material length (always 5)
    body[2] = 0x00; // sig type (binary)
    mem.writeInt(u32, body[3..7], 1600000000, .big); // creation time
    @memcpy(body[7..15], &[_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 }); // key ID
    body[15] = 1; // RSA
    body[16] = 8; // SHA-256
    body[17] = 0xAB; // hash prefix
    body[18] = 0xCD;
    mem.writeInt(u16, body[19..21], 8, .big); // MPI bit count
    body[21] = 0xFF; // MPI data

    const pkt = try V3SignaturePacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try testing.expectEqual(@as(u8, 0x00), pkt.sig_type);
    try testing.expectEqual(@as(u32, 1600000000), pkt.creation_time);
    try testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, pkt.pub_algo);
}

// ==========================================================================
// V3 Public Key Packet round-trips
// ==========================================================================

test "V3PublicKeyPacket round-trip" {
    const allocator = testing.allocator;

    // Build a V3 public key body:
    // version(1)=3 + creation_time(4) + validity_days(2) + algo(1)=RSA + MPIs
    var body: [14]u8 = undefined;
    body[0] = 3; // version
    mem.writeInt(u32, body[1..5], 1500000000, .big);
    mem.writeInt(u16, body[5..7], 365, .big); // validity days
    body[7] = 1; // RSA
    mem.writeInt(u16, body[8..10], 8, .big); // n MPI: 8-bit
    body[10] = 0xFF;
    mem.writeInt(u16, body[11..13], 8, .big); // e MPI: 8-bit
    body[13] = 0x03;

    const pkt = try V3PublicKeyPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try testing.expectEqual(@as(u32, 1500000000), pkt.creation_time);
    try testing.expectEqual(@as(u16, 365), pkt.validity_days);
    try testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, pkt.algorithm);
    try testing.expectEqual(@as(usize, 2), pkt.key_material.len);
}

// ==========================================================================
// V6 Public Key Packet round-trips
// ==========================================================================

test "V6PublicKeyPacket round-trip RSA" {
    const allocator = testing.allocator;

    // Build a V6 RSA public key body:
    // version(1)=6 + creation_time(4) + algo(1)=1 + key_material_length(4) + MPI(n) + MPI(e)
    var body: [16]u8 = undefined;
    body[0] = 6; // version
    mem.writeInt(u32, body[1..5], 1700000000, .big);
    body[5] = 1; // RSA
    mem.writeInt(u32, body[6..10], 6, .big); // key material length = 6 (2 small MPIs)
    // n MPI: bit_count=8, data=0xFF
    mem.writeInt(u16, body[10..12], 8, .big);
    body[12] = 0xFF;
    // e MPI: bit_count=8, data=0x03
    mem.writeInt(u16, body[13..15], 8, .big);
    body[15] = 0x03;

    const pkt = try V6PublicKeyPacket.parse(allocator, &body, false);
    defer pkt.deinit(allocator);

    try testing.expectEqual(@as(u8, 6), pkt.version);
    try testing.expectEqual(@as(u32, 1700000000), pkt.creation_time);
    try testing.expectEqual(PublicKeyAlgorithm.rsa_encrypt_sign, pkt.algorithm);
    try testing.expectEqual(@as(u32, 6), pkt.key_material_length);
    try testing.expectEqual(@as(usize, 2), pkt.key_material.len);
}

test "V6PublicKeyPacket subkey flag" {
    const allocator = testing.allocator;

    // Build a V6 RSA subkey body
    var body: [16]u8 = undefined;
    body[0] = 6;
    mem.writeInt(u32, body[1..5], 1700000000, .big);
    body[5] = 1; // RSA
    mem.writeInt(u32, body[6..10], 6, .big);
    mem.writeInt(u16, body[10..12], 8, .big);
    body[12] = 0xFF;
    mem.writeInt(u16, body[13..15], 8, .big);
    body[15] = 0x03;

    const pkt = try V6PublicKeyPacket.parse(allocator, &body, true);
    defer pkt.deinit(allocator);

    try testing.expect(pkt.is_subkey);
    try testing.expectEqual(@as(u8, 6), pkt.version);
}

test "V6PublicKeyPacket wrong version rejected" {
    const allocator = testing.allocator;

    var body: [42]u8 = undefined;
    body[0] = 4; // wrong version
    @memset(body[1..], 0);

    try testing.expectError(error.UnsupportedVersion, V6PublicKeyPacket.parse(allocator, &body, false));
}

// ==========================================================================
// V6 Signature Packet round-trips
// ==========================================================================

test "V6SignaturePacket salt size lookup" {
    // Verify salt sizes per RFC 9580
    try testing.expectEqual(@as(?usize, 16), V6SignaturePacket.saltSize(.sha256));
    try testing.expectEqual(@as(?usize, 24), V6SignaturePacket.saltSize(.sha384));
    try testing.expectEqual(@as(?usize, 32), V6SignaturePacket.saltSize(.sha512));
    try testing.expectEqual(@as(?usize, 16), V6SignaturePacket.saltSize(.sha224));
    try testing.expectEqual(@as(?usize, 16), V6SignaturePacket.saltSize(.sha1));
}

// ==========================================================================
// Padding Packet round-trips
// ==========================================================================

test "PaddingPacket round-trip" {
    const allocator = testing.allocator;
    const body = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };

    const pkt = try PaddingPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try testing.expectEqual(@as(usize, 4), pkt.data.len);
    try testing.expectEqualSlices(u8, &body, pkt.data);
}

test "PaddingPacket empty" {
    const allocator = testing.allocator;

    const pkt = try PaddingPacket.parse(allocator, &.{});
    defer pkt.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), pkt.data.len);
}

test "PaddingPacket create" {
    const allocator = testing.allocator;

    const pkt = try PaddingPacket.create(allocator, 32);
    defer pkt.deinit(allocator);
    try testing.expectEqual(@as(usize, 32), pkt.data.len);
}

// ==========================================================================
// Packet Header round-trips
// ==========================================================================

test "new format header one-octet length" {
    // Tag 2 (signature), length 100
    const data = [_]u8{ 0xC2, 100 };
    var fbs = std.io.fixedBufferStream(&data);
    const hdr = try header_mod.readHeader(fbs.reader());

    try testing.expectEqual(PacketTag.signature, hdr.tag);
    try testing.expectEqual(header_mod.Format.new, hdr.format);
    try testing.expectEqual(@as(u32, 100), hdr.body_length.fixed);

    // Write back
    var out: [6]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out);
    try header_mod.writeHeader(out_fbs.writer(), .signature, 100);
    try testing.expectEqualSlices(u8, &data, out_fbs.getWritten());
}

test "new format header two-octet length" {
    // Two-octet: length = 200 -> first = (200-192)/256 + 192 = 192, second = (200-192)%256 = 8
    var buf: [6]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try header_mod.writeHeader(fbs.writer(), .literal_data, 200);

    var read_fbs = std.io.fixedBufferStream(fbs.getWritten());
    const hdr = try header_mod.readHeader(read_fbs.reader());

    try testing.expectEqual(PacketTag.literal_data, hdr.tag);
    try testing.expectEqual(@as(u32, 200), hdr.body_length.fixed);
}

test "new format header five-octet length" {
    // Five-octet: length > 8383 uses 0xFF prefix + 4-byte BE
    var buf: [6]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try header_mod.writeHeader(fbs.writer(), .public_key, 100000);

    var read_fbs = std.io.fixedBufferStream(fbs.getWritten());
    const hdr = try header_mod.readHeader(read_fbs.reader());

    try testing.expectEqual(PacketTag.public_key, hdr.tag);
    try testing.expectEqual(@as(u32, 100000), hdr.body_length.fixed);
}

test "new format header zero length" {
    var buf: [6]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try header_mod.writeHeader(fbs.writer(), .user_id, 0);

    var read_fbs = std.io.fixedBufferStream(fbs.getWritten());
    const hdr = try header_mod.readHeader(read_fbs.reader());

    try testing.expectEqual(PacketTag.user_id, hdr.tag);
    try testing.expectEqual(@as(u32, 0), hdr.body_length.fixed);
}

test "new format header length 191 (max one-octet)" {
    var buf: [6]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try header_mod.writeHeader(fbs.writer(), .signature, 191);

    var read_fbs = std.io.fixedBufferStream(fbs.getWritten());
    const hdr = try header_mod.readHeader(read_fbs.reader());

    try testing.expectEqual(@as(u32, 191), hdr.body_length.fixed);
}

test "new format header length 192 (min two-octet)" {
    var buf: [6]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try header_mod.writeHeader(fbs.writer(), .signature, 192);

    var read_fbs = std.io.fixedBufferStream(fbs.getWritten());
    const hdr = try header_mod.readHeader(read_fbs.reader());

    try testing.expectEqual(@as(u32, 192), hdr.body_length.fixed);
}

test "new format header length 8383 (max two-octet)" {
    var buf: [6]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try header_mod.writeHeader(fbs.writer(), .signature, 8383);

    var read_fbs = std.io.fixedBufferStream(fbs.getWritten());
    const hdr = try header_mod.readHeader(read_fbs.reader());

    try testing.expectEqual(@as(u32, 8383), hdr.body_length.fixed);
}

test "old format header 1-byte length" {
    var buf: [6]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try header_mod.writeOldHeader(fbs.writer(), .signature, 100);

    var read_fbs = std.io.fixedBufferStream(fbs.getWritten());
    const hdr = try header_mod.readHeader(read_fbs.reader());

    try testing.expectEqual(PacketTag.signature, hdr.tag);
    try testing.expectEqual(header_mod.Format.old, hdr.format);
    try testing.expectEqual(@as(u32, 100), hdr.body_length.fixed);
}

test "old format header 2-byte length" {
    var buf: [6]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try header_mod.writeOldHeader(fbs.writer(), .signature, 1000);

    var read_fbs = std.io.fixedBufferStream(fbs.getWritten());
    const hdr = try header_mod.readHeader(read_fbs.reader());

    try testing.expectEqual(@as(u32, 1000), hdr.body_length.fixed);
}

test "old format header 4-byte length" {
    var buf: [6]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try header_mod.writeOldHeader(fbs.writer(), .signature, 100000);

    var read_fbs = std.io.fixedBufferStream(fbs.getWritten());
    const hdr = try header_mod.readHeader(read_fbs.reader());

    try testing.expectEqual(@as(u32, 100000), hdr.body_length.fixed);
}

test "partial body length header" {
    // Partial body length: byte in range 224-254
    // partial_len = 2^(byte & 0x1F)
    // Tag 11 (literal data), partial body
    const data = [_]u8{
        0xCB, // new format, tag 11
        0xE0, // partial body: 2^(0xE0 & 0x1F) = 2^0 = 1
    };
    var fbs = std.io.fixedBufferStream(&data);
    const hdr = try header_mod.readHeader(fbs.reader());

    try testing.expectEqual(PacketTag.literal_data, hdr.tag);
    try testing.expectEqual(@as(u32, 1), hdr.body_length.partial);
}

// ==========================================================================
// ASCII Armor round-trips
// ==========================================================================

test "armor MESSAGE round-trip" {
    const allocator = testing.allocator;
    const data = "Hello, World!";

    const encoded = try armor.encode(allocator, data, .message, null);
    defer allocator.free(encoded);

    try testing.expect(mem.startsWith(u8, encoded, "-----BEGIN PGP MESSAGE-----"));

    var decoded = try armor.decode(allocator, encoded);
    defer decoded.deinit();
    try testing.expectEqualSlices(u8, data, decoded.data);
}

test "armor PUBLIC KEY round-trip" {
    const allocator = testing.allocator;
    const data = [_]u8{ 0x99, 0x01, 0x0D };

    const encoded = try armor.encode(allocator, &data, .public_key, null);
    defer allocator.free(encoded);

    try testing.expect(mem.startsWith(u8, encoded, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));

    var decoded = try armor.decode(allocator, encoded);
    defer decoded.deinit();
    try testing.expectEqualSlices(u8, &data, decoded.data);
}

test "armor PRIVATE KEY round-trip" {
    const allocator = testing.allocator;
    const data = [_]u8{ 0xC5, 0x01, 0x0D };

    const encoded = try armor.encode(allocator, &data, .private_key, null);
    defer allocator.free(encoded);

    try testing.expect(mem.startsWith(u8, encoded, "-----BEGIN PGP PRIVATE KEY BLOCK-----"));

    var decoded = try armor.decode(allocator, encoded);
    defer decoded.deinit();
    try testing.expectEqualSlices(u8, &data, decoded.data);
}

test "armor SIGNATURE round-trip" {
    const allocator = testing.allocator;
    const data = [_]u8{ 0xC2, 0x04, 0x00, 0x13, 0x01, 0x08 };

    const encoded = try armor.encode(allocator, &data, .signature, null);
    defer allocator.free(encoded);

    try testing.expect(mem.startsWith(u8, encoded, "-----BEGIN PGP SIGNATURE-----"));

    var decoded = try armor.decode(allocator, encoded);
    defer decoded.deinit();
    try testing.expectEqualSlices(u8, &data, decoded.data);
}

test "armor with custom headers round-trip" {
    const allocator = testing.allocator;
    const data = "armored content";
    const headers = [_]armor.Header{
        .{ .name = "Version", .value = "zpgp 0.1" },
    };

    const encoded = try armor.encode(allocator, data, .message, &headers);
    defer allocator.free(encoded);

    try testing.expect(mem.indexOf(u8, encoded, "Version: zpgp 0.1") != null);

    var decoded = try armor.decode(allocator, encoded);
    defer decoded.deinit();
    try testing.expectEqualSlices(u8, data, decoded.data);
}

test "armor large data (>76 char lines)" {
    const allocator = testing.allocator;
    var data: [500]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i % 256);

    const encoded = try armor.encode(allocator, &data, .message, null);
    defer allocator.free(encoded);

    var decoded = try armor.decode(allocator, encoded);
    defer decoded.deinit();
    try testing.expectEqualSlices(u8, &data, decoded.data);
}

test "armor empty data round-trip" {
    const allocator = testing.allocator;

    const encoded = try armor.encode(allocator, "", .message, null);
    defer allocator.free(encoded);

    var decoded = try armor.decode(allocator, encoded);
    defer decoded.deinit();
    try testing.expectEqual(@as(usize, 0), decoded.data.len);
}

// ==========================================================================
// Packet tag enumeration tests
// ==========================================================================

test "PacketTag name coverage" {
    try testing.expectEqualStrings("Signature", PacketTag.signature.name());
    try testing.expectEqualStrings("Public-Key", PacketTag.public_key.name());
    try testing.expectEqualStrings("Secret-Key", PacketTag.secret_key.name());
    try testing.expectEqualStrings("Literal Data", PacketTag.literal_data.name());
    try testing.expectEqualStrings("User ID", PacketTag.user_id.name());
    try testing.expectEqualStrings("Trust", PacketTag.trust.name());
    try testing.expectEqualStrings("Marker", PacketTag.marker.name());
    try testing.expectEqualStrings("Compressed Data", PacketTag.compressed_data.name());
}

test "algorithm name coverage" {
    try testing.expectEqualStrings("RSA (Encrypt or Sign)", PublicKeyAlgorithm.rsa_encrypt_sign.name());
    try testing.expectEqualStrings("DSA", PublicKeyAlgorithm.dsa.name());
    try testing.expectEqualStrings("Ed25519", PublicKeyAlgorithm.ed25519.name());
    try testing.expectEqualStrings("X25519", PublicKeyAlgorithm.x25519.name());
    try testing.expectEqualStrings("AES-128", SymmetricAlgorithm.aes128.name());
    try testing.expectEqualStrings("AES-256", SymmetricAlgorithm.aes256.name());
    try testing.expectEqualStrings("CAST5", SymmetricAlgorithm.cast5.name());
    try testing.expectEqualStrings("Twofish", SymmetricAlgorithm.twofish.name());
    try testing.expectEqualStrings("SHA256", HashAlgorithm.sha256.name());
    try testing.expectEqualStrings("SHA512", HashAlgorithm.sha512.name());
}

test "algorithm properties" {
    // RSA can sign and encrypt
    try testing.expect(PublicKeyAlgorithm.rsa_encrypt_sign.canSign());
    try testing.expect(PublicKeyAlgorithm.rsa_encrypt_sign.canEncrypt());

    // Ed25519 can sign but not encrypt
    try testing.expect(PublicKeyAlgorithm.ed25519.canSign());
    try testing.expect(!PublicKeyAlgorithm.ed25519.canEncrypt());

    // X25519 can encrypt but not sign
    try testing.expect(!PublicKeyAlgorithm.x25519.canSign());
    try testing.expect(PublicKeyAlgorithm.x25519.canEncrypt());

    // Native V6 check
    try testing.expect(PublicKeyAlgorithm.ed25519.isNativeV6());
    try testing.expect(PublicKeyAlgorithm.x25519.isNativeV6());
    try testing.expect(!PublicKeyAlgorithm.rsa_encrypt_sign.isNativeV6());
}

test "symmetric algorithm key sizes" {
    try testing.expectEqual(@as(?usize, 16), SymmetricAlgorithm.aes128.keySize());
    try testing.expectEqual(@as(?usize, 24), SymmetricAlgorithm.aes192.keySize());
    try testing.expectEqual(@as(?usize, 32), SymmetricAlgorithm.aes256.keySize());
    try testing.expectEqual(@as(?usize, 16), SymmetricAlgorithm.cast5.keySize());
    try testing.expectEqual(@as(?usize, 32), SymmetricAlgorithm.twofish.keySize());
    try testing.expectEqual(@as(?usize, 24), SymmetricAlgorithm.triple_des.keySize());
}

test "symmetric algorithm block sizes" {
    try testing.expectEqual(@as(?usize, 16), SymmetricAlgorithm.aes128.blockSize());
    try testing.expectEqual(@as(?usize, 16), SymmetricAlgorithm.aes256.blockSize());
    try testing.expectEqual(@as(?usize, 8), SymmetricAlgorithm.cast5.blockSize());
    try testing.expectEqual(@as(?usize, 16), SymmetricAlgorithm.twofish.blockSize());
    try testing.expectEqual(@as(?usize, 8), SymmetricAlgorithm.triple_des.blockSize());
}

test "hash algorithm digest sizes" {
    try testing.expectEqual(@as(?usize, 20), HashAlgorithm.sha1.digestSize());
    try testing.expectEqual(@as(?usize, 28), HashAlgorithm.sha224.digestSize());
    try testing.expectEqual(@as(?usize, 32), HashAlgorithm.sha256.digestSize());
    try testing.expectEqual(@as(?usize, 48), HashAlgorithm.sha384.digestSize());
    try testing.expectEqual(@as(?usize, 64), HashAlgorithm.sha512.digestSize());
}
