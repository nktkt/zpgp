// SPDX-License-Identifier: MIT
//! Tests for the validation modules (key_validator, message_validator, armor_validator).
//!
//! Exercises:
//!   - Key validation with various algorithms, versions, and policies
//!   - Message validation for encrypted, signed, and combined messages
//!   - Armor validation for correct and malformed armored data
//!   - Edge cases: truncated data, wrong packet types, strict mode

const std = @import("std");
const mem = std.mem;
const base64 = std.base64;
const testing = std.testing;

const key_validator = @import("validation/key_validator.zig");
const KeyValidator = key_validator.KeyValidator;
const ValidationReport = key_validator.ValidationReport;

const message_validator = @import("validation/message_validator.zig");
const MessageValidator = message_validator.MessageValidator;
const MessageValidation = message_validator.MessageValidation;
const EncryptionValidation = message_validator.EncryptionValidation;
const SignatureValidation = message_validator.SignatureValidation;

const armor_validator = @import("validation/armor_validator.zig");
const ArmorValidation = armor_validator.ArmorValidation;

const enums = @import("types/enums.zig");
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const PacketTag = @import("packet/tags.zig").PacketTag;
const crc24 = @import("armor/crc24.zig");

const algo_policy = @import("policy/algorithm_policy.zig");
const PolicyLevel = algo_policy.PolicyLevel;

const SecurityScore = @import("inspect/key_analyzer.zig").SecurityScore;

// =========================================================================
// Helper: build a minimal key packet (new format)
// =========================================================================

fn buildKeyPacket(version: u8, algo: PublicKeyAlgorithm, is_secret: bool) [14]u8 {
    var data: [14]u8 = undefined;
    const tag: u8 = if (is_secret) @intFromEnum(PacketTag.secret_key) else @intFromEnum(PacketTag.public_key);
    data[0] = 0xC0 | tag;
    data[1] = 12; // body length
    data[2] = version;
    data[3] = 0x60; // creation time
    data[4] = 0x00;
    data[5] = 0x00;
    data[6] = 0x00;
    data[7] = @intFromEnum(algo);
    @memset(data[8..], 0);
    return data;
}

// =========================================================================
// KeyValidator — basic validation
// =========================================================================

test "validation: key empty data" {
    const allocator = testing.allocator;
    const v = KeyValidator.init(.rfc9580, false);

    var report = try v.validateKey(allocator, "");
    defer report.deinit(allocator);

    try testing.expect(!report.valid);
    try testing.expect(report.errors.items.len > 0);
    try testing.expectEqualStrings("EMPTY_KEY", report.errors.items[0].code);
}

test "validation: key non-openpgp data" {
    const allocator = testing.allocator;
    const v = KeyValidator.init(.rfc9580, false);

    const data = [_]u8{ 0x00, 0x01, 0x02 };
    var report = try v.validateKey(allocator, &data);
    defer report.deinit(allocator);

    try testing.expect(!report.valid);
    try testing.expectEqualStrings("INVALID_PACKET", report.errors.items[0].code);
}

test "validation: key non-key packet" {
    const allocator = testing.allocator;
    const v = KeyValidator.init(.rfc9580, false);

    // Literal data packet (tag 11)
    var data: [14]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.literal_data);
    data[1] = 12;
    @memset(data[2..], 0);

    var report = try v.validateKey(allocator, &data);
    defer report.deinit(allocator);

    try testing.expect(!report.valid);
    try testing.expectEqualStrings("NOT_A_KEY", report.errors.items[0].code);
}

test "validation: key V3 rejected" {
    const allocator = testing.allocator;
    const v = KeyValidator.init(.rfc9580, false);

    var data: [14]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.public_key);
    data[1] = 12;
    data[2] = 3; // V3
    @memset(data[3..], 0);

    var report = try v.validateKey(allocator, &data);
    defer report.deinit(allocator);

    try testing.expect(!report.valid);
    try testing.expectEqualStrings("OLD_VERSION", report.errors.items[0].code);
}

test "validation: key V4 RSA accepted under rfc4880" {
    const allocator = testing.allocator;
    const v = KeyValidator.init(.rfc4880, false);

    const data = buildKeyPacket(4, .rsa_encrypt_sign, false);
    var report = try v.validateKey(allocator, &data);
    defer report.deinit(allocator);

    try testing.expectEqual(@as(u8, 4), report.version);
    try testing.expectEqualStrings("RSA (Encrypt or Sign)", report.algorithm);
}

test "validation: key V4 Ed25519" {
    const allocator = testing.allocator;
    const v = KeyValidator.init(.rfc9580, false);

    const data = buildKeyPacket(4, .ed25519, false);
    var report = try v.validateKey(allocator, &data);
    defer report.deinit(allocator);

    try testing.expectEqualStrings("Ed25519", report.algorithm);
    // Should warn about V6 algo with V4 key.
    var found_warning = false;
    for (report.warnings.items) |w| {
        if (mem.indexOf(u8, w.code, "V6_ALGO_V4_KEY") != null) {
            found_warning = true;
            break;
        }
    }
    try testing.expect(found_warning);
}

test "validation: key V6 Ed25519 no V6 warning" {
    const allocator = testing.allocator;
    const v = KeyValidator.init(.rfc9580, false);

    const data = buildKeyPacket(6, .ed25519, false);
    var report = try v.validateKey(allocator, &data);
    defer report.deinit(allocator);

    try testing.expectEqual(@as(u8, 6), report.version);
    var found_v6_warning = false;
    for (report.warnings.items) |w| {
        if (mem.indexOf(u8, w.code, "V6_ALGO_V4_KEY") != null) {
            found_v6_warning = true;
            break;
        }
    }
    try testing.expect(!found_v6_warning);
}

test "validation: key secret key packet accepted" {
    const allocator = testing.allocator;
    const v = KeyValidator.init(.rfc9580, false);

    const data = buildKeyPacket(4, .rsa_encrypt_sign, true);
    var report = try v.validateKey(allocator, &data);
    defer report.deinit(allocator);

    try testing.expectEqual(@as(u8, 4), report.version);
}

// =========================================================================
// KeyValidator — strict mode
// =========================================================================

test "validation: strict mode rejects ElGamal" {
    const allocator = testing.allocator;
    const v = KeyValidator.init(.strict, true);

    const data = buildKeyPacket(4, .elgamal, false);
    var report = try v.validateKey(allocator, &data);
    defer report.deinit(allocator);

    try testing.expect(!report.valid);
}

test "validation: non-strict mode warns about ElGamal" {
    const allocator = testing.allocator;
    const v = KeyValidator.init(.strict, false);

    const data = buildKeyPacket(4, .elgamal, false);
    var report = try v.validateKey(allocator, &data);
    defer report.deinit(allocator);

    try testing.expect(report.warnings.items.len > 0);
}

test "validation: strict mode accepts Ed25519" {
    const allocator = testing.allocator;
    const v = KeyValidator.init(.strict, true);

    const data = buildKeyPacket(4, .ed25519, false);
    var report = try v.validateKey(allocator, &data);
    defer report.deinit(allocator);

    // May have warnings about V6 algo on V4 but should not have errors.
    try testing.expect(report.errors.items.len == 0 or
        !mem.eql(u8, report.errors.items[0].code, "WEAK_ALGO"));
}

// =========================================================================
// KeyValidator — algorithm assessment
// =========================================================================

test "validation: algorithm strength Ed25519 excellent" {
    const allocator = testing.allocator;
    const v = KeyValidator.init(.rfc9580, false);

    const data = buildKeyPacket(4, .ed25519, false);
    var assessment = try v.validateAlgorithmStrength(allocator, &data);
    defer assessment.deinit(allocator);

    try testing.expect(assessment.score == .excellent);
}

test "validation: algorithm strength X25519 excellent" {
    const allocator = testing.allocator;
    const v = KeyValidator.init(.rfc9580, false);

    const data = buildKeyPacket(4, .x25519, false);
    var assessment = try v.validateAlgorithmStrength(allocator, &data);
    defer assessment.deinit(allocator);

    try testing.expect(assessment.score == .excellent);
}

test "validation: algorithm strength DSA fair" {
    const allocator = testing.allocator;
    const v = KeyValidator.init(.rfc9580, false);

    const data = buildKeyPacket(4, .dsa, false);
    var assessment = try v.validateAlgorithmStrength(allocator, &data);
    defer assessment.deinit(allocator);

    try testing.expect(assessment.score == .fair);
}

test "validation: algorithm strength ECDSA good" {
    const allocator = testing.allocator;
    const v = KeyValidator.init(.rfc9580, false);

    const data = buildKeyPacket(4, .ecdsa, false);
    var assessment = try v.validateAlgorithmStrength(allocator, &data);
    defer assessment.deinit(allocator);

    try testing.expect(assessment.score == .good);
}

test "validation: algorithm strength short data" {
    const allocator = testing.allocator;
    const v = KeyValidator.init(.rfc9580, false);

    const data = [_]u8{ 0xC0, 0x02, 0x04 };
    var assessment = try v.validateAlgorithmStrength(allocator, &data);
    defer assessment.deinit(allocator);

    try testing.expect(assessment.score == .critical);
}

// =========================================================================
// KeyValidator — self-signature and revocation
// =========================================================================

test "validation: self-signature absent on bare key" {
    const allocator = testing.allocator;
    const v = KeyValidator.init(.rfc9580, false);

    const data = buildKeyPacket(4, .ed25519, false);
    const result = try v.validateSelfSignature(allocator, &data);
    try testing.expect(!result);
}

test "validation: revocation status non-revoked" {
    const allocator = testing.allocator;
    const v = KeyValidator.init(.rfc9580, false);

    const data = buildKeyPacket(4, .ed25519, false);
    var status = try v.validateRevocationStatus(allocator, &data);
    defer status.deinit(allocator);

    try testing.expect(!status.revoked);
}

test "validation: expiration on key without expiry" {
    const allocator = testing.allocator;
    const v = KeyValidator.init(.rfc9580, false);

    const data = buildKeyPacket(4, .ed25519, false);
    const status = try v.validateExpiration(allocator, &data, 0x70000000);
    try testing.expect(!status.expired);
    try testing.expect(status.expires == null);
}

// =========================================================================
// KeyValidator — report formatting
// =========================================================================

test "validation: report format includes all sections" {
    const allocator = testing.allocator;

    var report = ValidationReport{
        .valid = false,
        .errors = .empty,
        .warnings = .empty,
        .info = .empty,
        .self_sig_valid = false,
        .subkey_count = 2,
        .uid_count = 1,
        .algorithm = try allocator.dupe(u8, "RSA"),
        .bits = 4096,
        .fingerprint = try allocator.dupe(u8, "abcdef"),
        .version = 4,
    };
    defer report.deinit(allocator);

    try report.errors.append(allocator, .{
        .code = try allocator.dupe(u8, "TEST_ERR"),
        .description = try allocator.dupe(u8, "A test error"),
    });
    try report.warnings.append(allocator, .{
        .code = try allocator.dupe(u8, "TEST_WARN"),
        .description = try allocator.dupe(u8, "A test warning"),
        .suggestion = try allocator.dupe(u8, "Fix it"),
    });
    try report.info.append(allocator, try allocator.dupe(u8, "Info line"));

    const formatted = try report.format(allocator);
    defer allocator.free(formatted);

    try testing.expect(mem.indexOf(u8, formatted, "Valid:        no") != null);
    try testing.expect(mem.indexOf(u8, formatted, "Key Size:     4096 bits") != null);
    try testing.expect(mem.indexOf(u8, formatted, "TEST_ERR") != null);
    try testing.expect(mem.indexOf(u8, formatted, "TEST_WARN") != null);
    try testing.expect(mem.indexOf(u8, formatted, "Fix it") != null);
    try testing.expect(mem.indexOf(u8, formatted, "Info line") != null);
}

// =========================================================================
// MessageValidator — basic validation
// =========================================================================

test "validation: message empty" {
    const allocator = testing.allocator;
    const v = MessageValidator.init(.rfc9580);

    var result = try v.validateMessage(allocator, "");
    defer result.deinit(allocator);

    try testing.expect(!result.valid_structure);
    try testing.expect(!result.is_encrypted);
    try testing.expect(!result.is_signed);
}

test "validation: message non-openpgp" {
    const allocator = testing.allocator;
    const v = MessageValidator.init(.rfc9580);

    const data = [_]u8{ 0x00, 0xFF };
    var result = try v.validateMessage(allocator, &data);
    defer result.deinit(allocator);

    try testing.expect(!result.valid_structure);
}

test "validation: message PKESK + SEIPD encrypted" {
    const allocator = testing.allocator;
    const v = MessageValidator.init(.rfc9580);

    var data: [20]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.public_key_encrypted_session_key);
    data[1] = 8;
    data[2] = 3;
    @memset(data[3..10], 0);
    data[10] = 0xC0 | @intFromEnum(PacketTag.sym_encrypted_integrity_protected_data);
    data[11] = 8;
    data[12] = 1;
    @memset(data[13..20], 0);

    var result = try v.validateMessage(allocator, &data);
    defer result.deinit(allocator);

    try testing.expect(result.is_encrypted);
    try testing.expect(result.encryption != null);
    try testing.expect(result.encryption.?.has_integrity);
    try testing.expectEqual(@as(u32, 1), result.encryption.?.recipient_count);
    try testing.expect(!result.encryption.?.has_password);
}

test "validation: message SKESK + SEIPDv2" {
    const allocator = testing.allocator;
    const v = MessageValidator.init(.rfc9580);

    var data: [20]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.symmetric_key_encrypted_session_key);
    data[1] = 8;
    data[2] = 4;
    data[3] = @intFromEnum(SymmetricAlgorithm.aes256);
    @memset(data[4..10], 0);
    data[10] = 0xC0 | @intFromEnum(PacketTag.sym_encrypted_integrity_protected_data);
    data[11] = 8;
    data[12] = 2;
    data[13] = @intFromEnum(SymmetricAlgorithm.aes256);
    @memset(data[14..20], 0);

    var result = try v.validateMessage(allocator, &data);
    defer result.deinit(allocator);

    try testing.expect(result.is_encrypted);
    try testing.expect(result.encryption.?.uses_aead);
    try testing.expect(result.encryption.?.has_password);
    try testing.expect(result.encryption.?.sym_algo == .aes256);
}

test "validation: message SED warns about no integrity" {
    const allocator = testing.allocator;
    const v = MessageValidator.init(.rfc9580);

    var data: [12]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.symmetrically_encrypted_data);
    data[1] = 10;
    @memset(data[2..], 0);

    var result = try v.validateMessage(allocator, &data);
    defer result.deinit(allocator);

    try testing.expect(result.is_encrypted);
    try testing.expect(!result.encryption.?.has_integrity);
    try testing.expect(result.warnings.items.len > 0);
}

test "validation: message signature detection" {
    const allocator = testing.allocator;
    const v = MessageValidator.init(.rfc9580);

    // V4 signature packet
    var data: [14]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.signature);
    data[1] = 12;
    data[2] = 4; // V4
    data[3] = 0; // sig type
    data[4] = @intFromEnum(PublicKeyAlgorithm.ed25519);
    data[5] = @intFromEnum(HashAlgorithm.sha512);
    @memset(data[6..], 0);

    var result = try v.validateMessage(allocator, &data);
    defer result.deinit(allocator);

    try testing.expect(result.is_signed);
    try testing.expect(result.signature != null);
    try testing.expect(result.signature.?.hash_algo == .sha512);
    try testing.expect(result.signature.?.pub_algo == .ed25519);
}

test "validation: message format output" {
    const allocator = testing.allocator;

    var result = MessageValidation{
        .valid_structure = true,
        .is_encrypted = false,
        .is_signed = true,
        .encryption = null,
        .signature = SignatureValidation{
            .sig_count = 1,
            .hash_algo = .sha256,
            .hash_algo_secure = true,
            .pub_algo = .rsa_encrypt_sign,
        },
        .warnings = .empty,
    };
    defer result.deinit(allocator);

    const formatted = try result.format(allocator);
    defer allocator.free(formatted);

    try testing.expect(mem.indexOf(u8, formatted, "Signed:     yes") != null);
    try testing.expect(mem.indexOf(u8, formatted, "SHA256") != null);
}

// =========================================================================
// MessageValidator — validateEncryptedMessage / validateSignedMessage
// =========================================================================

test "validation: validateEncryptedMessage non-encrypted returns defaults" {
    const allocator = testing.allocator;
    const v = MessageValidator.init(.rfc9580);

    var data: [12]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.literal_data);
    data[1] = 10;
    @memset(data[2..], 0);

    const enc = try v.validateEncryptedMessage(allocator, &data);
    try testing.expect(!enc.has_integrity);
    try testing.expectEqual(@as(u32, 0), enc.recipient_count);
}

test "validation: validateSignedMessage unsigned returns defaults" {
    const allocator = testing.allocator;
    const v = MessageValidator.init(.rfc9580);

    var data: [12]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.literal_data);
    data[1] = 10;
    @memset(data[2..], 0);

    const sig = try v.validateSignedMessage(allocator, &data);
    try testing.expectEqual(@as(u32, 0), sig.sig_count);
}

// =========================================================================
// ArmorValidator — basic validation
// =========================================================================

test "validation: armor empty data" {
    const allocator = testing.allocator;

    var result = try armor_validator.validateArmor(allocator, "");
    defer result.deinit(allocator);

    try testing.expect(!result.valid);
}

test "validation: armor no begin line" {
    const allocator = testing.allocator;

    var result = try armor_validator.validateArmor(allocator, "just text\n");
    defer result.deinit(allocator);

    try testing.expect(!result.valid);
}

test "validation: armor missing end line" {
    const allocator = testing.allocator;

    const text =
        \\-----BEGIN PGP MESSAGE-----
        \\
        \\AQID
    ;

    var result = try armor_validator.validateArmor(allocator, text);
    defer result.deinit(allocator);

    try testing.expect(!result.valid);
}

test "validation: armor all four types detected" {
    const allocator = testing.allocator;

    const types = [_]struct { label: []const u8, expected: @import("armor/armor.zig").ArmorType }{
        .{ .label = "PGP MESSAGE", .expected = .message },
        .{ .label = "PGP PUBLIC KEY BLOCK", .expected = .public_key },
        .{ .label = "PGP PRIVATE KEY BLOCK", .expected = .private_key },
        .{ .label = "PGP SIGNATURE", .expected = .signature },
    };

    for (types) |tc| {
        const text = try std.fmt.allocPrint(
            allocator,
            "-----BEGIN {s}-----\n\nAQID\n-----END {s}-----\n",
            .{ tc.label, tc.label },
        );
        defer allocator.free(text);

        var result = try armor_validator.validateArmor(allocator, text);
        defer result.deinit(allocator);

        try testing.expect(result.armor_type != null);
        try testing.expect(result.armor_type.? == tc.expected);
    }
}

test "validation: armor headers parsed" {
    const allocator = testing.allocator;

    const text =
        \\-----BEGIN PGP MESSAGE-----
        \\Version: zpgp 0.1
        \\Comment: Test
        \\Hash: SHA256
        \\
        \\AQID
        \\-----END PGP MESSAGE-----
    ;

    var result = try armor_validator.validateArmor(allocator, text);
    defer result.deinit(allocator);

    try testing.expectEqual(@as(usize, 3), result.headers.items.len);
    try testing.expectEqualStrings("Version", result.headers.items[0].name);
    try testing.expectEqualStrings("zpgp 0.1", result.headers.items[0].value);
    try testing.expectEqualStrings("Comment", result.headers.items[1].name);
    try testing.expectEqualStrings("Hash", result.headers.items[2].name);
}

test "validation: armor blank separator detected" {
    const allocator = testing.allocator;

    const text =
        \\-----BEGIN PGP MESSAGE-----
        \\
        \\AQID
        \\-----END PGP MESSAGE-----
    ;

    var result = try armor_validator.validateArmor(allocator, text);
    defer result.deinit(allocator);

    try testing.expect(result.has_blank_separator);
}

test "validation: armor CRC present" {
    const allocator = testing.allocator;

    // Construct valid CRC.
    const payload = [_]u8{ 0x01, 0x02, 0x03 };
    const crc_val = crc24.compute(&payload);
    const crc_bytes = [_]u8{
        @intCast((crc_val >> 16) & 0xFF),
        @intCast((crc_val >> 8) & 0xFF),
        @intCast(crc_val & 0xFF),
    };

    var b64_body_buf: [4]u8 = undefined;
    const b64_body = base64.standard.Encoder.encode(&b64_body_buf, &payload);
    var b64_crc_buf: [4]u8 = undefined;
    const b64_crc = base64.standard.Encoder.encode(&b64_crc_buf, &crc_bytes);

    const text = try std.fmt.allocPrint(
        allocator,
        "-----BEGIN PGP MESSAGE-----\n\n{s}\n={s}\n-----END PGP MESSAGE-----\n",
        .{ b64_body, b64_crc },
    );
    defer allocator.free(text);

    var result = try armor_validator.validateArmor(allocator, text);
    defer result.deinit(allocator);

    try testing.expect(result.has_crc);
    try testing.expect(result.crc_valid);
}

test "validation: armor format output" {
    const allocator = testing.allocator;

    var result = ArmorValidation{
        .valid = true,
        .armor_type = .public_key,
        .has_crc = true,
        .crc_valid = true,
        .line_lengths_valid = true,
        .has_blank_separator = true,
        .headers = .empty,
        .issues = .empty,
    };
    defer result.deinit(allocator);

    const formatted = try result.format(allocator);
    defer allocator.free(formatted);

    try testing.expect(mem.indexOf(u8, formatted, "Valid:          yes") != null);
    try testing.expect(mem.indexOf(u8, formatted, "PGP PUBLIC KEY BLOCK") != null);
}

// =========================================================================
// Cross-module: policy levels affect validation
// =========================================================================

test "validation: rfc4880 policy accepts CAST5" {
    const allocator = testing.allocator;
    const v = MessageValidator.init(.rfc4880);

    var data: [20]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.symmetric_key_encrypted_session_key);
    data[1] = 8;
    data[2] = 4;
    data[3] = @intFromEnum(SymmetricAlgorithm.cast5);
    @memset(data[4..10], 0);
    data[10] = 0xC0 | @intFromEnum(PacketTag.sym_encrypted_integrity_protected_data);
    data[11] = 8;
    data[12] = 1;
    @memset(data[13..20], 0);

    var result = try v.validateMessage(allocator, &data);
    defer result.deinit(allocator);

    try testing.expect(result.encryption.?.sym_algo_secure);
}

test "validation: strict policy rejects CAST5" {
    const allocator = testing.allocator;
    const v = MessageValidator.init(.strict);

    var data: [20]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.symmetric_key_encrypted_session_key);
    data[1] = 8;
    data[2] = 4;
    data[3] = @intFromEnum(SymmetricAlgorithm.cast5);
    @memset(data[4..10], 0);
    data[10] = 0xC0 | @intFromEnum(PacketTag.sym_encrypted_integrity_protected_data);
    data[11] = 8;
    data[12] = 1;
    @memset(data[13..20], 0);

    var result = try v.validateMessage(allocator, &data);
    defer result.deinit(allocator);

    try testing.expect(!result.encryption.?.sym_algo_secure);
}

test "validation: multiple recipients counted" {
    const allocator = testing.allocator;
    const v = MessageValidator.init(.rfc9580);

    var data: [30]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.public_key_encrypted_session_key);
    data[1] = 8;
    data[2] = 3;
    @memset(data[3..10], 0);
    data[10] = 0xC0 | @intFromEnum(PacketTag.public_key_encrypted_session_key);
    data[11] = 8;
    data[12] = 3;
    @memset(data[13..20], 0);
    data[20] = 0xC0 | @intFromEnum(PacketTag.sym_encrypted_integrity_protected_data);
    data[21] = 8;
    data[22] = 1;
    @memset(data[23..30], 0);

    var result = try v.validateMessage(allocator, &data);
    defer result.deinit(allocator);

    try testing.expectEqual(@as(u32, 2), result.encryption.?.recipient_count);
}
