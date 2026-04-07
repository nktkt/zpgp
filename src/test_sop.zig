// SPDX-License-Identifier: MIT
//! Tests for the SOP (Stateless OpenPGP) interface.
//!
//! These tests exercise the SopInterface methods with various inputs,
//! edge cases, and error conditions per the SOP specification
//! (draft-dkg-openpgp-stateless-cli).

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

const sop_mod = @import("sop/sop.zig");
const SopInterface = sop_mod.SopInterface;
const SopError = sop_mod.SopError;
const SignMode = sop_mod.SignMode;
const EncryptOptions = sop_mod.EncryptOptions;
const DecryptOptions = sop_mod.DecryptOptions;
const VerifyResult = sop_mod.VerifyResult;
const DecryptResult = sop_mod.DecryptResult;
const InlineVerifyResult = sop_mod.InlineVerifyResult;
const SopCommand = sop_mod.SopCommand;
const ExitCode = sop_mod.ExitCode;
const VersionInfo = sop_mod.VersionInfo;

// =========================================================================
// Version subcommand tests
// =========================================================================

test "sop: version returns non-empty string" {
    const allocator = testing.allocator;
    var sop = SopInterface.init(allocator);
    defer sop.deinit();

    const ver = try sop.version();
    defer allocator.free(ver);

    try testing.expect(ver.len > 0);
    try testing.expect(mem.startsWith(u8, ver, "zpgp"));
}

test "sop: version info has name and backend" {
    const allocator = testing.allocator;
    var sop = SopInterface.init(allocator);
    defer sop.deinit();

    const info = try sop.versionInfo();
    try testing.expect(info.name.len > 0);
    try testing.expect(info.backend.len > 0);
}

// =========================================================================
// generate-key subcommand tests
// =========================================================================

test "sop: generate-key rejects empty user ID" {
    const allocator = testing.allocator;
    var sop = SopInterface.init(allocator);
    defer sop.deinit();

    try testing.expectError(SopError.MissingArg, sop.generateKey("", true));
}

// =========================================================================
// extract-cert subcommand tests
// =========================================================================

test "sop: extract-cert rejects empty input" {
    const allocator = testing.allocator;
    var sop = SopInterface.init(allocator);
    defer sop.deinit();

    try testing.expectError(SopError.BadData, sop.extractCert("", true));
}

test "sop: extract-cert rejects garbage input" {
    const allocator = testing.allocator;
    var sop = SopInterface.init(allocator);
    defer sop.deinit();

    try testing.expectError(SopError.BadData, sop.extractCert("this is not a key", true));
}

// =========================================================================
// sign subcommand tests
// =========================================================================

test "sop: sign rejects empty key" {
    const allocator = testing.allocator;
    var sop = SopInterface.init(allocator);
    defer sop.deinit();

    try testing.expectError(SopError.NoKey, sop.sign("", "data", true, .binary));
}

test "sop: sign rejects empty data" {
    const allocator = testing.allocator;
    var sop = SopInterface.init(allocator);
    defer sop.deinit();

    try testing.expectError(SopError.BadData, sop.sign("key-data", "", true, .text));
}

test "sop: sign with invalid key data" {
    const allocator = testing.allocator;
    var sop = SopInterface.init(allocator);
    defer sop.deinit();

    try testing.expectError(SopError.BadData, sop.sign("not-a-valid-key", "hello", true, .binary));
}

// =========================================================================
// verify subcommand tests
// =========================================================================

test "sop: verify rejects empty signature" {
    const allocator = testing.allocator;
    var sop = SopInterface.init(allocator);
    defer sop.deinit();

    try testing.expectError(SopError.BadData, sop.verify("", "data", &.{"cert"}));
}

test "sop: verify rejects empty certs list" {
    const allocator = testing.allocator;
    var sop = SopInterface.init(allocator);
    defer sop.deinit();

    const empty: []const []const u8 = &.{};
    try testing.expectError(SopError.MissingArg, sop.verify("sig", "data", empty));
}

// =========================================================================
// encrypt subcommand tests
// =========================================================================

test "sop: encrypt requires recipients or passwords" {
    const allocator = testing.allocator;
    var sop = SopInterface.init(allocator);
    defer sop.deinit();

    try testing.expectError(SopError.MissingArg, sop.encrypt("hello", .{}));
}

test "sop: encrypt options validation" {
    // Empty options -> error
    try testing.expectError(SopError.MissingArg, (EncryptOptions{}).validate());

    // With recipients -> ok
    try (EncryptOptions{ .recipients = &.{"cert"} }).validate();

    // With passwords -> ok
    try (EncryptOptions{ .passwords = &.{"pass"} }).validate();

    // With both -> ok
    try (EncryptOptions{ .recipients = &.{"cert"}, .passwords = &.{"pass"} }).validate();
}

// =========================================================================
// decrypt subcommand tests
// =========================================================================

test "sop: decrypt requires keys or passwords" {
    const allocator = testing.allocator;
    var sop = SopInterface.init(allocator);
    defer sop.deinit();

    try testing.expectError(SopError.MissingArg, sop.decrypt("ct", .{}));
}

test "sop: decrypt rejects empty ciphertext" {
    const allocator = testing.allocator;
    var sop = SopInterface.init(allocator);
    defer sop.deinit();

    try testing.expectError(SopError.BadData, sop.decrypt("", .{ .secret_keys = &.{"key"} }));
}

test "sop: decrypt options validation" {
    try testing.expectError(SopError.MissingArg, (DecryptOptions{}).validate());
    try (DecryptOptions{ .secret_keys = &.{"k"} }).validate();
    try (DecryptOptions{ .passwords = &.{"p"} }).validate();
}

// =========================================================================
// armor/dearmor subcommand tests
// =========================================================================

test "sop: armor rejects empty input" {
    const allocator = testing.allocator;
    var sop = SopInterface.init(allocator);
    defer sop.deinit();

    try testing.expectError(SopError.BadData, sop.armor_(""));
}

test "sop: dearmor rejects empty input" {
    const allocator = testing.allocator;
    var sop = SopInterface.init(allocator);
    defer sop.deinit();

    try testing.expectError(SopError.BadData, sop.dearmor_(""));
}

test "sop: dearmor rejects non-armored input" {
    const allocator = testing.allocator;
    var sop = SopInterface.init(allocator);
    defer sop.deinit();

    try testing.expectError(SopError.BadData, sop.dearmor_("not armored data at all"));
}

// =========================================================================
// inline-sign subcommand tests
// =========================================================================

test "sop: inline-sign rejects empty key" {
    const allocator = testing.allocator;
    var sop = SopInterface.init(allocator);
    defer sop.deinit();

    try testing.expectError(SopError.NoKey, sop.inlineSign("", "data", .text));
}

test "sop: inline-sign rejects empty data" {
    const allocator = testing.allocator;
    var sop = SopInterface.init(allocator);
    defer sop.deinit();

    try testing.expectError(SopError.BadData, sop.inlineSign("key", "", .binary));
}

// =========================================================================
// inline-verify subcommand tests
// =========================================================================

test "sop: inline-verify rejects empty data" {
    const allocator = testing.allocator;
    var sop = SopInterface.init(allocator);
    defer sop.deinit();

    try testing.expectError(SopError.BadData, sop.inlineVerify("", &.{"cert"}));
}

test "sop: inline-verify rejects empty certs" {
    const allocator = testing.allocator;
    var sop = SopInterface.init(allocator);
    defer sop.deinit();

    const empty: []const []const u8 = &.{};
    try testing.expectError(SopError.MissingArg, sop.inlineVerify("signed", empty));
}

// =========================================================================
// list-profiles tests
// =========================================================================

test "sop: list-profiles returns at least one profile" {
    const allocator = testing.allocator;
    var sop = SopInterface.init(allocator);
    defer sop.deinit();

    const profiles = try sop.listProfiles("encrypt");
    defer allocator.free(profiles);
    try testing.expect(profiles.len >= 1);
    try testing.expectEqualStrings("default", profiles[0]);
}

// =========================================================================
// SignMode tests
// =========================================================================

test "sop: SignMode sigType" {
    try testing.expectEqual(@as(u8, 0x00), SignMode.binary.sigType());
    try testing.expectEqual(@as(u8, 0x01), SignMode.text.sigType());
}

// =========================================================================
// SopCommand tests
// =========================================================================

test "sop: SopCommand.parseSubcommand known commands" {
    const cases = .{
        .{ "version", SopCommand.Subcommand.version },
        .{ "generate-key", SopCommand.Subcommand.generate_key },
        .{ "extract-cert", SopCommand.Subcommand.extract_cert },
        .{ "sign", SopCommand.Subcommand.sign_cmd },
        .{ "verify", SopCommand.Subcommand.verify_cmd },
        .{ "encrypt", SopCommand.Subcommand.encrypt_cmd },
        .{ "decrypt", SopCommand.Subcommand.decrypt_cmd },
        .{ "armor", SopCommand.Subcommand.armor_cmd },
        .{ "dearmor", SopCommand.Subcommand.dearmor_cmd },
        .{ "inline-sign", SopCommand.Subcommand.inline_sign },
        .{ "inline-verify", SopCommand.Subcommand.inline_verify },
        .{ "list-profiles", SopCommand.Subcommand.list_profiles },
    };

    inline for (cases) |case| {
        try testing.expectEqual(case[1], SopCommand.parseSubcommand(case[0]));
    }
}

test "sop: SopCommand.parseSubcommand unknown" {
    try testing.expectEqual(SopCommand.Subcommand.unknown, SopCommand.parseSubcommand("bogus"));
    try testing.expectEqual(SopCommand.Subcommand.unknown, SopCommand.parseSubcommand(""));
    try testing.expectEqual(SopCommand.Subcommand.unknown, SopCommand.parseSubcommand("VERSION")); // case-sensitive
}

// =========================================================================
// ExitCode tests
// =========================================================================

test "sop: ExitCode fromError" {
    try testing.expectEqual(ExitCode.missing_input, ExitCode.fromError(SopError.NoKey));
    try testing.expectEqual(ExitCode.missing_input, ExitCode.fromError(SopError.KeyNotFound));
    try testing.expectEqual(ExitCode.missing_input, ExitCode.fromError(SopError.MissingArg));
    try testing.expectEqual(ExitCode.bad_data, ExitCode.fromError(SopError.BadData));
    try testing.expectEqual(ExitCode.bad_data, ExitCode.fromError(SopError.AmbiguousInput));
    try testing.expectEqual(ExitCode.not_implemented, ExitCode.fromError(SopError.NotImplemented));
    try testing.expectEqual(ExitCode.unsupported_option, ExitCode.fromError(SopError.UnsupportedOption));
    try testing.expectEqual(ExitCode.password_not_human_readable, ExitCode.fromError(SopError.PasswordNotHumanReadable));
    try testing.expectEqual(ExitCode.key_cannot_sign, ExitCode.fromError(SopError.KeyCannotSign));
    try testing.expectEqual(ExitCode.key_cannot_encrypt, ExitCode.fromError(SopError.KeyCannotEncrypt));
}

// =========================================================================
// Data structure tests
// =========================================================================

test "sop: VerifyResult deinit null fp" {
    const allocator = testing.allocator;
    const vr = VerifyResult{
        .valid = false,
        .signing_time = null,
        .signing_key_fp = null,
    };
    vr.deinit(allocator);
}

test "sop: VerifyResult deinit with allocated fp" {
    const allocator = testing.allocator;
    const fp = try allocator.dupe(u8, "AABBCCDD11223344");
    const vr = VerifyResult{
        .valid = true,
        .signing_time = 1000000,
        .signing_key_fp = fp,
    };
    vr.deinit(allocator);
}

test "sop: DecryptResult deinit" {
    const allocator = testing.allocator;
    const pt = try allocator.dupe(u8, "plaintext");
    const sk = try allocator.dupe(u8, "session-key");
    const verifs = try allocator.alloc(VerifyResult, 0);

    var dr = DecryptResult{
        .plaintext = pt,
        .session_key = sk,
        .verifications = verifs,
    };
    dr.deinit(allocator);
}

test "sop: DecryptResult deinit null session key" {
    const allocator = testing.allocator;
    const pt = try allocator.dupe(u8, "plaintext");
    const verifs = try allocator.alloc(VerifyResult, 0);

    var dr = DecryptResult{
        .plaintext = pt,
        .session_key = null,
        .verifications = verifs,
    };
    dr.deinit(allocator);
}

test "sop: InlineVerifyResult deinit" {
    const allocator = testing.allocator;
    const pt = try allocator.dupe(u8, "verified text");
    const verifs = try allocator.alloc(VerifyResult, 0);

    var ivr = InlineVerifyResult{
        .plaintext = pt,
        .verifications = verifs,
    };
    ivr.deinit(allocator);
}

// =========================================================================
// Utility function tests
// =========================================================================

test "sop: validateOpenPgpData" {
    try testing.expect(sop_mod.validateOpenPgpData(&[_]u8{ 0xC6, 0x01, 0x04 }));
    try testing.expect(sop_mod.validateOpenPgpData(&[_]u8{0x84})); // Old-format
    try testing.expect(!sop_mod.validateOpenPgpData(&[_]u8{}));
    try testing.expect(!sop_mod.validateOpenPgpData(&[_]u8{0x00})); // No high bit
    try testing.expect(!sop_mod.validateOpenPgpData(&[_]u8{0x30})); // Not a packet
}

test "sop: isArmored" {
    try testing.expect(sop_mod.isArmored("-----BEGIN PGP MESSAGE-----\ndata\n-----END PGP MESSAGE-----"));
    try testing.expect(sop_mod.isArmored("-----BEGIN PGP PUBLIC KEY BLOCK-----\ndata"));
    try testing.expect(!sop_mod.isArmored("binary data"));
    try testing.expect(!sop_mod.isArmored(""));
    try testing.expect(!sop_mod.isArmored("short"));
}

// =========================================================================
// Edge case tests
// =========================================================================

test "sop: multiple init/deinit cycles" {
    const allocator = testing.allocator;

    for (0..10) |_| {
        var sop = SopInterface.init(allocator);
        _ = try sop.version();
        const ver = try sop.version();
        allocator.free(ver);
        sop.deinit();
    }
}

test "sop: EncryptOptions defaults" {
    const opts = EncryptOptions{};
    try testing.expectEqual(@as(usize, 0), opts.recipients.len);
    try testing.expectEqual(@as(usize, 0), opts.sign_keys.len);
    try testing.expectEqual(@as(usize, 0), opts.passwords.len);
    try testing.expect(opts.armor_output);
    try testing.expect(opts.profile == null);
}

test "sop: DecryptOptions defaults" {
    const opts = DecryptOptions{};
    try testing.expectEqual(@as(usize, 0), opts.secret_keys.len);
    try testing.expectEqual(@as(usize, 0), opts.passwords.len);
    try testing.expectEqual(@as(usize, 0), opts.verify_with.len);
    try testing.expect(!opts.session_key_out);
}
