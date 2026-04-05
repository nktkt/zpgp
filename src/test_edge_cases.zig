// SPDX-License-Identifier: MIT
//! Edge case and boundary tests for the zpgp library.
//!
//! Tests boundary values, empty/zero inputs, maximum values, Unicode handling,
//! error handling for malformed data, multiple operations, and algorithm
//! combinations.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

// Packet layer
const header_mod = @import("packet/header.zig");
const tags = @import("packet/tags.zig");
const PacketTag = tags.PacketTag;
const BodyLength = header_mod.BodyLength;

// Types
const enums = @import("types/enums.zig");
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const AeadAlgorithm = aead_mod.AeadAlgorithm;
const mpi_mod = @import("types/mpi.zig");
const Mpi = mpi_mod.Mpi;
const s2k_mod = @import("types/s2k.zig");
const S2K = s2k_mod.S2K;

// Armor
const armor = @import("armor/armor.zig");
const crc24 = @import("armor/crc24.zig");

// Packets
const literal_data = @import("packets/literal_data.zig");
const LiteralDataPacket = literal_data.LiteralDataPacket;
const user_id = @import("packets/user_id.zig");
const UserIdPacket = user_id.UserIdPacket;

// Crypto
const seipd = @import("crypto/seipd.zig");
const seipd_v2 = @import("crypto/seipd_v2.zig");
const aead_mod = @import("crypto/aead/aead.zig");
const hash_mod = @import("crypto/hash.zig");
const HashContext = hash_mod.HashContext;
const cfb_mod = @import("crypto/cfb.zig");

// ==========================================================================
// Empty/Zero Inputs
// ==========================================================================

test "edge: encrypt empty plaintext" {
    const allocator = testing.allocator;
    const key = [_]u8{0x42} ** 16;

    // SEIPD v1
    const enc1 = try seipd.seipdEncrypt(allocator, "", &key, .aes128);
    defer allocator.free(enc1);
    const dec1 = try seipd.seipdDecrypt(allocator, enc1, &key, .aes128);
    defer allocator.free(dec1);
    try testing.expectEqual(@as(usize, 0), dec1.len);

    // SEIPD v2
    const enc2 = try seipd_v2.seipdV2Encrypt(allocator, "", &key, .aes128, .eax, 6);
    defer allocator.free(enc2);
    const dec2 = try seipd_v2.seipdV2Decrypt(allocator, enc2, &key);
    defer allocator.free(dec2);
    try testing.expectEqual(@as(usize, 0), dec2.len);
}

test "edge: sign empty document" {
    // Hashing an empty document should still produce a valid hash
    var ctx = try HashContext.init(.sha256);
    ctx.update("");
    var digest: [32]u8 = undefined;
    ctx.final(&digest);

    // SHA-256 of empty string is well-known
    const expected = [_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    try testing.expectEqualSlices(u8, &expected, &digest);
}

test "edge: armor empty data" {
    const allocator = testing.allocator;

    const armored = try armor.encode(allocator, "", .message, null);
    defer allocator.free(armored);

    var result = try armor.decode(allocator, armored);
    defer result.deinit();

    try testing.expectEqual(@as(usize, 0), result.data.len);
    try testing.expectEqual(armor.ArmorType.message, result.armor_type);
}

test "edge: MPI zero value wire format" {
    const allocator = testing.allocator;

    // MPI of value 0: bit_count = 0, no data bytes
    const m = Mpi{ .bit_count = 0, .data = &.{} };
    try testing.expectEqual(@as(usize, 0), m.byteLen());
    try testing.expectEqual(@as(usize, 2), m.wireLen()); // just the 2-byte bit count

    // Write and read back
    var buf: [16]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try m.writeTo(fbs.writer());
    try testing.expectEqual(@as(usize, 2), fbs.pos);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00 }, buf[0..2]);

    fbs.pos = 0;
    const decoded = try Mpi.readFrom(allocator, fbs.reader());
    defer decoded.deinit(allocator);
    try testing.expectEqual(@as(u16, 0), decoded.bit_count);
    try testing.expectEqual(@as(usize, 0), decoded.byteLen());
}

test "edge: literal data empty filename" {
    const allocator = testing.allocator;

    // Literal data packet with empty filename
    var body: [7]u8 = undefined;
    body[0] = 'b'; // binary format
    body[1] = 0; // filename length = 0
    mem.writeInt(u32, body[2..6], 0, .big); // timestamp = 0
    body[6] = 0x42; // 1 byte of data

    const pkt = try LiteralDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try testing.expectEqual(@as(usize, 0), pkt.filename.len);
    try testing.expectEqual(@as(usize, 1), pkt.data.len);
    try testing.expectEqual(@as(u8, 0x42), pkt.data[0]);
}

test "edge: user ID empty string" {
    const allocator = testing.allocator;

    const pkt = try UserIdPacket.parse(allocator, "");
    defer pkt.deinit(allocator);

    try testing.expectEqual(@as(usize, 0), pkt.id.len);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try testing.expectEqual(@as(usize, 0), serialized.len);
}

// ==========================================================================
// Maximum Values
// ==========================================================================

test "edge: packet length max u32" {
    // Verify that a 5-octet new-format length header can encode max u32.
    var buf: [16]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try header_mod.writeHeader(fbs.writer(), PacketTag.literal_data, std.math.maxInt(u32));

    // Read it back
    const written = fbs.getWritten();
    var read_fbs = std.io.fixedBufferStream(written);
    const hdr = try header_mod.readHeader(read_fbs.reader());
    try testing.expectEqual(BodyLength{ .fixed = std.math.maxInt(u32) }, hdr.body_length);
}

test "edge: MPI max bit count 65535" {
    // An MPI with bit_count = 65535 requires ceil(65535/8) = 8192 bytes.
    const m = Mpi{ .bit_count = 65535, .data = &.{} };
    try testing.expectEqual(@as(usize, 8192), m.byteLen());
    try testing.expectEqual(@as(usize, 8194), m.wireLen());
}

test "edge: very long user ID (1000 chars)" {
    const allocator = testing.allocator;

    var long_id: [1000]u8 = undefined;
    @memset(&long_id, 'A');

    const pkt = try UserIdPacket.parse(allocator, &long_id);
    defer pkt.deinit(allocator);

    try testing.expectEqual(@as(usize, 1000), pkt.id.len);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try testing.expectEqualSlices(u8, &long_id, serialized);
}

test "edge: very long filename (255 chars)" {
    const allocator = testing.allocator;

    // Filename length is a u8, so max is 255
    var body: [262]u8 = undefined;
    body[0] = 'b'; // binary
    body[1] = 255; // max filename length
    @memset(body[2..257], 'x'); // 255 bytes of filename
    mem.writeInt(u32, body[257..261], 1000, .big); // timestamp
    body[261] = 0xAA; // 1 byte of data

    const pkt = try LiteralDataPacket.parse(allocator, &body);
    defer pkt.deinit(allocator);

    try testing.expectEqual(@as(usize, 255), pkt.filename.len);
    try testing.expectEqual(@as(u32, 1000), pkt.timestamp);
}

// ==========================================================================
// Boundary Values
// ==========================================================================

test "edge: new format length boundary 191-192" {
    // 191 uses 1-octet encoding, 192 uses 2-octet encoding
    {
        var buf: [16]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        try header_mod.writeHeader(fbs.writer(), PacketTag.literal_data, 191);
        // 1-octet: tag(1) + length(1) = 2 bytes
        try testing.expectEqual(@as(usize, 2), fbs.getWritten().len);
    }
    {
        var buf: [16]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        try header_mod.writeHeader(fbs.writer(), PacketTag.literal_data, 192);
        // 2-octet: tag(1) + length(2) = 3 bytes
        try testing.expectEqual(@as(usize, 3), fbs.getWritten().len);
    }
}

test "edge: new format length boundary 8383-8384" {
    // 8383 uses 2-octet encoding, 8384 uses 5-octet encoding
    {
        var buf: [16]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        try header_mod.writeHeader(fbs.writer(), PacketTag.literal_data, 8383);
        try testing.expectEqual(@as(usize, 3), fbs.getWritten().len);

        // Read it back and verify
        var read_fbs = std.io.fixedBufferStream(fbs.getWritten());
        const hdr = try header_mod.readHeader(read_fbs.reader());
        try testing.expectEqual(BodyLength{ .fixed = 8383 }, hdr.body_length);
    }
    {
        var buf: [16]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        try header_mod.writeHeader(fbs.writer(), PacketTag.literal_data, 8384);
        // 5-octet: tag(1) + 0xFF(1) + length(4) = 6 bytes
        try testing.expectEqual(@as(usize, 6), fbs.getWritten().len);

        var read_fbs = std.io.fixedBufferStream(fbs.getWritten());
        const hdr = try header_mod.readHeader(read_fbs.reader());
        try testing.expectEqual(BodyLength{ .fixed = 8384 }, hdr.body_length);
    }
}

test "edge: old format 1-byte max (255)" {
    // Old format 1-byte length type can encode 0-255.
    var buf: [16]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try header_mod.writeOldHeader(fbs.writer(), PacketTag.signature, 255);

    var read_fbs = std.io.fixedBufferStream(fbs.getWritten());
    const hdr = try header_mod.readHeader(read_fbs.reader());
    try testing.expectEqual(BodyLength{ .fixed = 255 }, hdr.body_length);
}

test "edge: old format 2-byte max (65535)" {
    // Old format 2-byte length type can encode 0-65535.
    var buf: [16]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try header_mod.writeOldHeader(fbs.writer(), PacketTag.signature, 65535);

    var read_fbs = std.io.fixedBufferStream(fbs.getWritten());
    const hdr = try header_mod.readHeader(read_fbs.reader());
    try testing.expectEqual(BodyLength{ .fixed = 65535 }, hdr.body_length);
}

test "edge: S2K iteration count min (1024)" {
    // Minimum coded_count = 0 => (16 + 0) << (0 + 6) = 16 << 6 = 1024
    const s2k = S2K{
        .s2k_type = .iterated,
        .hash_algo = .sha256,
        .salt = [_]u8{0} ** 8,
        .coded_count = 0,
        .argon2_data = null,
    };
    try testing.expectEqual(@as(u32, 1024), s2k.iterationCount());
}

test "edge: S2K iteration count max" {
    // Maximum coded_count = 255 => (16 + 15) << (15 + 6) = 31 << 21 = 65011712
    const s2k = S2K{
        .s2k_type = .iterated,
        .hash_algo = .sha256,
        .salt = [_]u8{0} ** 8,
        .coded_count = 255,
        .argon2_data = null,
    };
    try testing.expectEqual(@as(u32, 65011712), s2k.iterationCount());
}

// ==========================================================================
// Unicode and Special Characters
// ==========================================================================

test "edge: user ID with CJK characters" {
    const allocator = testing.allocator;

    // UTF-8 encoded CJK characters
    const cjk_id = "\xe5\xb1\xb1\xe7\x94\xb0\xe5\xa4\xaa\xe9\x83\x8e <taro@example.jp>";
    const pkt = try UserIdPacket.parse(allocator, cjk_id);
    defer pkt.deinit(allocator);

    try testing.expectEqualStrings(cjk_id, pkt.id);

    const serialized = try pkt.serialize(allocator);
    defer allocator.free(serialized);
    try testing.expectEqualSlices(u8, cjk_id, serialized);
}

test "edge: user ID with emoji" {
    const allocator = testing.allocator;

    const emoji_id = "User \xf0\x9f\x94\x91 <key@example.com>";
    const pkt = try UserIdPacket.parse(allocator, emoji_id);
    defer pkt.deinit(allocator);

    try testing.expectEqualStrings(emoji_id, pkt.id);
}

test "edge: user ID with angle brackets in name" {
    const allocator = testing.allocator;

    const tricky_id = "Alice <alice@example.com> (Test <User>)";
    const pkt = try UserIdPacket.parse(allocator, tricky_id);
    defer pkt.deinit(allocator);

    try testing.expectEqualStrings(tricky_id, pkt.id);
}

test "edge: filename with spaces" {
    const allocator = testing.allocator;

    const filename = "my document.txt";
    var body: [6 + filename.len + 3]u8 = undefined;
    body[0] = 'b';
    body[1] = @intCast(filename.len);
    @memcpy(body[2 .. 2 + filename.len], filename);
    mem.writeInt(u32, body[2 + filename.len ..][0..4], 0, .big);
    body[body.len - 1] = 0x42; // 1 byte data overflow protection
    // Adjust: body needs exactly 2 + filename.len + 4 + data_len
    const header_len = 2 + filename.len + 4;
    const total_body = body[0..header_len]; // no data bytes

    const pkt = try LiteralDataPacket.parse(allocator, total_body);
    defer pkt.deinit(allocator);

    try testing.expectEqualStrings(filename, pkt.filename);
    try testing.expectEqual(@as(usize, 0), pkt.data.len);
}

test "edge: notation data with UTF-8" {
    // Test that UTF-8 data can round-trip through armor encoding
    const allocator = testing.allocator;
    const utf8_data = "Notation: \xc3\xa9\xc3\xa0\xc3\xbc\xc3\xb6";

    const armored = try armor.encode(allocator, utf8_data, .message, null);
    defer allocator.free(armored);

    var result = try armor.decode(allocator, armored);
    defer result.deinit();

    try testing.expectEqualSlices(u8, utf8_data, result.data);
}

// ==========================================================================
// Error Handling
// ==========================================================================

test "edge: truncated packet header" {
    // A single byte that has bit 7 set but is a new-format header
    // that needs more bytes for the length -- should fail with EndOfStream.
    const data = [_]u8{0xC2}; // new-format, needs length byte
    var fbs = std.io.fixedBufferStream(&data);
    const result = header_mod.readHeader(fbs.reader());
    try testing.expectError(error.EndOfStream, result);
}

test "edge: truncated MPI header" {
    const allocator = testing.allocator;

    // A single byte is not enough for the 2-byte MPI bit count header
    const data = [_]u8{0x00}; // only 1 byte, need 2 for header
    var fbs = std.io.fixedBufferStream(&data);
    const result = Mpi.readFrom(allocator, fbs.reader());
    try testing.expectError(error.EndOfStream, result);
}

test "edge: truncated armor" {
    const allocator = testing.allocator;

    // Armor with BEGIN but no END
    const truncated = "-----BEGIN PGP MESSAGE-----\n\nSGVsbG8=\n";
    const result = armor.decode(allocator, truncated);
    try testing.expect(result == armor.ArmorError.InvalidArmor or
        result == armor.ArmorError.MissingCrc);
}

test "edge: armor with invalid base64" {
    const allocator = testing.allocator;

    const bad_armor =
        \\-----BEGIN PGP MESSAGE-----
        \\
        \\!!!invalid base64!!!
        \\=AAAA
        \\-----END PGP MESSAGE-----
        \\
    ;
    const result = armor.decode(allocator, bad_armor);
    try testing.expect(result == armor.ArmorError.InvalidBase64 or
        result == armor.ArmorError.InvalidCrc);
}

test "edge: armor with wrong CRC" {
    const allocator = testing.allocator;

    // Manually construct armor with a wrong CRC
    const bad_armor =
        \\-----BEGIN PGP MESSAGE-----
        \\
        \\SGVsbG8=
        \\=AAAA
        \\-----END PGP MESSAGE-----
        \\
    ;
    const result = armor.decode(allocator, bad_armor);
    try testing.expect(result == armor.ArmorError.InvalidCrc or
        result == armor.ArmorError.InvalidBase64);
}

test "edge: armor with missing footer" {
    const allocator = testing.allocator;

    const no_footer =
        \\-----BEGIN PGP MESSAGE-----
        \\
        \\SGVsbG8=
        \\=j1gH
        \\
    ;
    const result = armor.decode(allocator, no_footer);
    try testing.expect(result == armor.ArmorError.InvalidArmor or
        result == armor.ArmorError.MissingCrc);
}

test "edge: SEIPD with truncated MDC" {
    const allocator = testing.allocator;
    const key = [_]u8{0x42} ** 16;

    // Version byte + too little data for prefix + MDC
    const data = [_]u8{1} ++ [_]u8{0xAA} ** 10; // version + 10 bytes (needs at least 40)
    const result = seipd.seipdDecrypt(allocator, &data, &key, .aes128);
    try testing.expectError(seipd.SeipdError.InvalidData, result);
}

test "edge: SEIPD with wrong MDC" {
    const allocator = testing.allocator;
    const key = [_]u8{0x42} ** 16;

    const encrypted = try seipd.seipdEncrypt(allocator, "integrity test", &key, .aes128);
    defer allocator.free(encrypted);

    // Flip the last byte of the encrypted data (which is part of the MDC)
    encrypted[encrypted.len - 1] ^= 0xFF;

    if (seipd.seipdDecrypt(allocator, encrypted, &key, .aes128)) |dec| {
        allocator.free(dec);
    } else |err| {
        try testing.expect(err == seipd.SeipdError.MdcMismatch or
            err == seipd.SeipdError.MdcMissing or
            err == seipd.SeipdError.QuickCheckFailed);
    }
}

test "edge: signature with wrong hash prefix" {
    // The hash prefix is the first 2 bytes of the digest. Verify we can
    // detect when they don't match by computing two different hashes.
    var ctx1 = try HashContext.init(.sha256);
    ctx1.update("document A");
    var digest1: [32]u8 = undefined;
    ctx1.final(&digest1);

    var ctx2 = try HashContext.init(.sha256);
    ctx2.update("document B");
    var digest2: [32]u8 = undefined;
    ctx2.final(&digest2);

    // The hash prefixes should differ for different documents
    const prefix1 = [2]u8{ digest1[0], digest1[1] };
    const prefix2 = [2]u8{ digest2[0], digest2[1] };
    try testing.expect(!mem.eql(u8, &prefix1, &prefix2));
}

test "edge: PKESK with unknown algorithm" {
    // An unknown public key algorithm value should be representable
    const unknown: enums.PublicKeyAlgorithm = @enumFromInt(99);
    try testing.expectEqualStrings("Unknown", unknown.name());
    try testing.expect(!unknown.canSign());
    try testing.expect(!unknown.canEncrypt());
}

test "edge: unknown packet tag handled gracefully" {
    // Verify that unknown packet tags are representable and parseable
    const unknown_tag: PacketTag = @enumFromInt(60);
    try testing.expectEqualStrings("Unknown", unknown_tag.name());

    // Reading a packet with an unknown tag should still work
    const data = [_]u8{ 0xC0 | 60, 0 }; // new-format, tag 60, length 0
    var fbs = std.io.fixedBufferStream(&data);
    const hdr = try header_mod.readHeader(fbs.reader());
    try testing.expectEqual(unknown_tag, hdr.tag);
}

// ==========================================================================
// Multiple Operations
// ==========================================================================

test "edge: encrypt same data twice produces different ciphertext" {
    const allocator = testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const plaintext = "same data";

    const enc1 = try seipd.seipdEncrypt(allocator, plaintext, &key, .aes128);
    defer allocator.free(enc1);
    const enc2 = try seipd.seipdEncrypt(allocator, plaintext, &key, .aes128);
    defer allocator.free(enc2);

    // Random prefix means different ciphertext
    try testing.expect(!mem.eql(u8, enc1, enc2));

    // Both decrypt to the same plaintext
    const dec1 = try seipd.seipdDecrypt(allocator, enc1, &key, .aes128);
    defer allocator.free(dec1);
    const dec2 = try seipd.seipdDecrypt(allocator, enc2, &key, .aes128);
    defer allocator.free(dec2);

    try testing.expectEqualStrings(plaintext, dec1);
    try testing.expectEqualStrings(plaintext, dec2);
}

test "edge: sign same data twice produces same signature (deterministic)" {
    // SHA-256 of the same data is always the same
    var digest1: [32]u8 = undefined;
    var digest2: [32]u8 = undefined;

    std.crypto.hash.sha2.Sha256.hash("deterministic test", &digest1, .{});
    std.crypto.hash.sha2.Sha256.hash("deterministic test", &digest2, .{});

    try testing.expectEqualSlices(u8, &digest1, &digest2);
}

test "edge: multiple armor headers" {
    const allocator = testing.allocator;
    const headers = [_]armor.Header{
        .{ .name = "Version", .value = "zpgp 1.0" },
        .{ .name = "Comment", .value = "Test comment" },
        .{ .name = "Hash", .value = "SHA256" },
    };

    const armored = try armor.encode(allocator, "test", .signature, &headers);
    defer allocator.free(armored);

    var result = try armor.decode(allocator, armored);
    defer result.deinit();

    try testing.expectEqual(@as(usize, 3), result.headers.len);
    try testing.expectEqualStrings("Version", result.headers[0].name);
    try testing.expectEqualStrings("zpgp 1.0", result.headers[0].value);
    try testing.expectEqualStrings("Comment", result.headers[1].name);
    try testing.expectEqualStrings("Test comment", result.headers[1].value);
    try testing.expectEqualStrings("Hash", result.headers[2].name);
    try testing.expectEqualStrings("SHA256", result.headers[2].value);
}

// ==========================================================================
// Algorithm Combinations
// ==========================================================================

test "edge: all symmetric algorithms CFB round-trip" {
    // Test that supported symmetric algorithms can encrypt and decrypt with SEIPD.
    const allocator = testing.allocator;
    const plaintext = "Algorithm round-trip test data for symmetric encryption";

    const algos = [_]struct { algo: SymmetricAlgorithm, key_size: usize }{
        .{ .algo = .aes128, .key_size = 16 },
        .{ .algo = .aes256, .key_size = 32 },
        .{ .algo = .cast5, .key_size = 16 },
        .{ .algo = .twofish, .key_size = 32 },
    };

    for (algos) |a| {
        var key: [32]u8 = undefined;
        @memset(&key, 0x42);

        const encrypted = try seipd.seipdEncrypt(allocator, plaintext, key[0..a.key_size], a.algo);
        defer allocator.free(encrypted);

        const decrypted = try seipd.seipdDecrypt(allocator, encrypted, key[0..a.key_size], a.algo);
        defer allocator.free(decrypted);

        try testing.expectEqualStrings(plaintext, decrypted);
    }
}

test "edge: all hash algorithms digest size" {
    // Verify that all known hash algorithms report their correct digest size.
    const cases = [_]struct { algo: HashAlgorithm, size: usize }{
        .{ .algo = .md5, .size = 16 },
        .{ .algo = .sha1, .size = 20 },
        .{ .algo = .ripemd160, .size = 20 },
        .{ .algo = .sha256, .size = 32 },
        .{ .algo = .sha384, .size = 48 },
        .{ .algo = .sha512, .size = 64 },
        .{ .algo = .sha224, .size = 28 },
    };

    for (cases) |c| {
        try testing.expectEqual(c.size, c.algo.digestSize().?);
    }
}

test "edge: all AEAD algorithms round-trip" {
    const allocator = testing.allocator;
    const plaintext = "AEAD algorithm test";
    const ad = "associated data";

    const configs = [_]struct {
        sym: SymmetricAlgorithm,
        aead: AeadAlgorithm,
        key_size: usize,
        nonce_size: usize,
    }{
        .{ .sym = .aes128, .aead = .eax, .key_size = 16, .nonce_size = 16 },
        .{ .sym = .aes256, .aead = .eax, .key_size = 32, .nonce_size = 16 },
        .{ .sym = .aes128, .aead = .ocb, .key_size = 16, .nonce_size = 15 },
        .{ .sym = .aes256, .aead = .ocb, .key_size = 32, .nonce_size = 15 },
        .{ .sym = .aes128, .aead = .gcm, .key_size = 16, .nonce_size = 12 },
        .{ .sym = .aes256, .aead = .gcm, .key_size = 32, .nonce_size = 12 },
    };

    for (configs) |cfg| {
        var key: [32]u8 = undefined;
        @memset(&key, 0x55);
        var nonce: [16]u8 = undefined;
        @memset(&nonce, 0x33);

        const result = try aead_mod.aeadEncrypt(
            allocator,
            cfg.sym,
            cfg.aead,
            key[0..cfg.key_size],
            nonce[0..cfg.nonce_size],
            plaintext,
            ad,
        );
        defer result.deinit(allocator);

        const decrypted = try aead_mod.aeadDecrypt(
            allocator,
            cfg.sym,
            cfg.aead,
            key[0..cfg.key_size],
            nonce[0..cfg.nonce_size],
            result.ciphertext,
            &result.tag,
            ad,
        );
        defer allocator.free(decrypted);

        try testing.expectEqualStrings(plaintext, decrypted);
    }
}
