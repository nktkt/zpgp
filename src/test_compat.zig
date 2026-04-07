// SPDX-License-Identifier: MIT
//! Compatibility tests for the GnuPG and Sequoia-PGP compatibility layers.
//!
//! Tests cover:
//!   - GnuPG home directory path construction
//!   - Trust database parsing and record extraction
//!   - Status-fd protocol message parsing and generation
//!   - GnuPG version detection and feature gating
//!   - Sequoia-PGP compatibility checking
//!   - RFC 9580 compliance checking
//!   - Migration guidance generation

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

const gnupg = @import("compat/gnupg.zig");
const GnupgHome = gnupg.GnupgHome;
const StatusMessage = gnupg.StatusMessage;
const Keyword = gnupg.Keyword;
const TrustDbReader = gnupg.TrustDbReader;
const TrustDatabase = gnupg.TrustDatabase;
const RecordType = gnupg.RecordType;
const GnupgVersion = gnupg.GnupgVersion;

const sequoia = @import("compat/sequoia.zig");
const CompatReport = sequoia.CompatReport;
const Rfc9580Report = sequoia.Rfc9580Report;
const IssueSeverity = sequoia.IssueSeverity;

const enums = @import("types/enums.zig");
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const PacketTag = @import("packet/tags.zig").PacketTag;

// =========================================================================
// GnuPG home directory tests
// =========================================================================

test "compat: GnupgHome constructs all file paths correctly" {
    const allocator = testing.allocator;

    const home = GnupgHome{ .path = "/tmp/test-gnupg" };

    const pubring = try home.pubringPath(allocator);
    defer allocator.free(pubring);
    try testing.expectEqualStrings("/tmp/test-gnupg/pubring.kbx", pubring);

    const secring = try home.secringPath(allocator);
    defer allocator.free(secring);
    try testing.expectEqualStrings("/tmp/test-gnupg/secring.gpg", secring);

    const trustdb = try home.trustdbPath(allocator);
    defer allocator.free(trustdb);
    try testing.expectEqualStrings("/tmp/test-gnupg/trustdb.gpg", trustdb);

    const config = try home.configPath(allocator);
    defer allocator.free(config);
    try testing.expectEqualStrings("/tmp/test-gnupg/gpg.conf", config);

    const agent = try home.agentConfigPath(allocator);
    defer allocator.free(agent);
    try testing.expectEqualStrings("/tmp/test-gnupg/gpg-agent.conf", agent);

    const dirmngr = try home.dirmngrConfigPath(allocator);
    defer allocator.free(dirmngr);
    try testing.expectEqualStrings("/tmp/test-gnupg/dirmngr.conf", dirmngr);

    const privkeys = try home.privateKeysDir(allocator);
    defer allocator.free(privkeys);
    try testing.expectEqualStrings("/tmp/test-gnupg/private-keys-v1.d", privkeys);

    const random = try home.randomSeedPath(allocator);
    defer allocator.free(random);
    try testing.expectEqualStrings("/tmp/test-gnupg/random_seed", random);
}

test "compat: GnupgHome with spaces in path" {
    const allocator = testing.allocator;

    const home = GnupgHome{ .path = "/Users/test user/.gnupg" };

    const config = try home.configPath(allocator);
    defer allocator.free(config);
    try testing.expectEqualStrings("/Users/test user/.gnupg/gpg.conf", config);
}

// =========================================================================
// Trust database tests
// =========================================================================

test "compat: TrustDbReader rejects data shorter than one record" {
    const allocator = testing.allocator;

    const short_data = [_]u8{ 1, 3, 0, 0, 0, 0 };
    const result = TrustDbReader.parseFromBytes(allocator, &short_data);
    try testing.expectError(error.InvalidTrustDb, result);
}

test "compat: TrustDbReader parses version record fields" {
    const allocator = testing.allocator;

    var data: [40]u8 = undefined;
    @memset(&data, 0);
    data[0] = @intFromEnum(RecordType.version);
    data[1] = 3; // version
    data[2] = 0x65;
    data[3] = 0x43;
    data[4] = 0x21;
    data[5] = 0x00; // created
    data[6] = 0x65;
    data[7] = 0x50;
    data[8] = 0x00;
    data[9] = 0x00; // next_check
    data[10] = 3; // marginals
    data[11] = 1; // completes
    data[12] = 4; // max_cert_depth
    data[13] = 1; // trust_model (PGP)
    data[14] = 0x08;
    data[15] = 0x00; // min_key_size = 2048

    var db = try TrustDbReader.parseFromBytes(allocator, &data);
    defer db.deinit(allocator);

    try testing.expectEqual(@as(u8, 3), db.version);
    try testing.expectEqual(@as(u32, 0x65432100), db.created);
    try testing.expectEqual(@as(u32, 0x65500000), db.next_check);
    try testing.expectEqual(@as(u8, 3), db.marginals);
    try testing.expectEqual(@as(u8, 1), db.completes);
    try testing.expectEqual(@as(u8, 4), db.max_cert_depth);
    try testing.expectEqual(@as(u8, 1), db.trust_model);
    try testing.expectEqual(@as(u16, 0x0800), db.min_key_size);
}

test "compat: TrustDbReader multiple record types" {
    const allocator = testing.allocator;

    // 4 records: version, free, trust, valid
    var data: [160]u8 = undefined;
    @memset(&data, 0);
    data[0] = @intFromEnum(RecordType.version);
    data[1] = 3;
    data[40] = @intFromEnum(RecordType.free);
    data[80] = @intFromEnum(RecordType.trust);
    data[120] = @intFromEnum(RecordType.valid);

    var db = try TrustDbReader.parseFromBytes(allocator, &data);
    defer db.deinit(allocator);

    try testing.expectEqual(@as(usize, 4), db.records.items.len);
    try testing.expect(db.records.items[0].record_type == .version);
    try testing.expect(db.records.items[1].record_type == .free);
    try testing.expect(db.records.items[2].record_type == .trust);
    try testing.expect(db.records.items[3].record_type == .valid);

    try testing.expectEqual(@as(usize, 1), db.countRecordsByType(.trust));
    try testing.expectEqual(@as(usize, 1), db.countRecordsByType(.valid));
    try testing.expectEqual(@as(usize, 1), db.countRecordsByType(.free));
    try testing.expectEqual(@as(usize, 0), db.countRecordsByType(.hash_table));
}

test "compat: TrustDbReader record numbers are sequential" {
    const allocator = testing.allocator;

    var data: [120]u8 = undefined;
    @memset(&data, 0);
    data[0] = @intFromEnum(RecordType.version);
    data[40] = @intFromEnum(RecordType.trust);
    data[80] = @intFromEnum(RecordType.trust);

    var db = try TrustDbReader.parseFromBytes(allocator, &data);
    defer db.deinit(allocator);

    try testing.expectEqual(@as(u32, 0), db.records.items[0].record_number);
    try testing.expectEqual(@as(u32, 1), db.records.items[1].record_number);
    try testing.expectEqual(@as(u32, 2), db.records.items[2].record_number);
}

// =========================================================================
// Status message tests
// =========================================================================

test "compat: StatusMessage parse all standard keywords" {
    const allocator = testing.allocator;

    const test_cases = [_]struct { line: []const u8, expected: Keyword }{
        .{ .line = "[GNUPG:] GOODSIG ABCD", .expected = .GOODSIG },
        .{ .line = "[GNUPG:] BADSIG ABCD", .expected = .BADSIG },
        .{ .line = "[GNUPG:] ERRSIG ABCD", .expected = .ERRSIG },
        .{ .line = "[GNUPG:] TRUST_ULTIMATE 0 pgp", .expected = .TRUST_ULTIMATE },
        .{ .line = "[GNUPG:] TRUST_FULLY 0 pgp", .expected = .TRUST_FULLY },
        .{ .line = "[GNUPG:] TRUST_MARGINAL 0 pgp", .expected = .TRUST_MARGINAL },
        .{ .line = "[GNUPG:] TRUST_NEVER 0 pgp", .expected = .TRUST_NEVER },
        .{ .line = "[GNUPG:] TRUST_UNDEFINED", .expected = .TRUST_UNDEFINED },
        .{ .line = "[GNUPG:] DECRYPTION_OKAY", .expected = .DECRYPTION_OKAY },
        .{ .line = "[GNUPG:] DECRYPTION_FAILED", .expected = .DECRYPTION_FAILED },
        .{ .line = "[GNUPG:] KEY_CREATED B FP algo", .expected = .KEY_CREATED },
        .{ .line = "[GNUPG:] IMPORT_OK 1 FP", .expected = .IMPORT_OK },
        .{ .line = "[GNUPG:] NO_PUBKEY KEYID", .expected = .NO_PUBKEY },
        .{ .line = "[GNUPG:] NO_SECKEY KEYID", .expected = .NO_SECKEY },
        .{ .line = "[GNUPG:] SIG_CREATED D 1 8 KEYID 12345 --", .expected = .SIG_CREATED },
        .{ .line = "[GNUPG:] BEGIN_SIGNING H8", .expected = .BEGIN_SIGNING },
        .{ .line = "[GNUPG:] BEGIN_ENCRYPTION", .expected = .BEGIN_ENCRYPTION },
        .{ .line = "[GNUPG:] END_ENCRYPTION", .expected = .END_ENCRYPTION },
        .{ .line = "[GNUPG:] ENC_TO KID 9 0", .expected = .ENC_TO },
        .{ .line = "[GNUPG:] NEWSIG", .expected = .NEWSIG },
    };

    for (test_cases) |tc| {
        const msg = try StatusMessage.parse(allocator, tc.line);
        defer msg.deinit(allocator);
        try testing.expect(msg.keyword == tc.expected);
    }
}

test "compat: StatusMessage format preserves content" {
    const allocator = testing.allocator;

    const line = "[GNUPG:] VALIDSIG ABCDEF1234567890 2024 0 00 8 1";
    const msg = try StatusMessage.parse(allocator, line);
    defer msg.deinit(allocator);

    const formatted = try msg.format(allocator);
    defer allocator.free(formatted);

    try testing.expectEqualStrings(line, formatted);
}

test "compat: StatusMessage keyword-only message" {
    const allocator = testing.allocator;

    const msg = try StatusMessage.parse(allocator, "[GNUPG:] NEWSIG");
    defer msg.deinit(allocator);

    try testing.expect(msg.keyword == .NEWSIG);
    try testing.expectEqualStrings("", msg.args);

    const formatted = try msg.format(allocator);
    defer allocator.free(formatted);
    try testing.expectEqualStrings("[GNUPG:] NEWSIG", formatted);
}

test "compat: parseStatusOutput multi-line" {
    const allocator = testing.allocator;

    const input =
        \\[GNUPG:] BEGIN_DECRYPTION
        \\[GNUPG:] ENC_TO ABCD1234 9 0
        \\[GNUPG:] DECRYPTION_OKAY
        \\[GNUPG:] END_DECRYPTION
        \\
    ;

    var messages = try gnupg.parseStatusOutput(allocator, input);
    defer {
        for (messages.items) |msg| msg.deinit(allocator);
        messages.deinit(allocator);
    }

    try testing.expectEqual(@as(usize, 4), messages.items.len);
    try testing.expect(messages.items[0].keyword == .BEGIN_DECRYPTION);
    try testing.expect(messages.items[1].keyword == .ENC_TO);
    try testing.expect(messages.items[2].keyword == .DECRYPTION_OKAY);
    try testing.expect(messages.items[3].keyword == .END_DECRYPTION);
}

test "compat: formatStatusOutput produces valid lines" {
    const allocator = testing.allocator;

    const a1 = try allocator.dupe(u8, "ABCD1234 Test User");
    defer allocator.free(a1);
    const a2 = try allocator.dupe(u8, "0 pgp");
    defer allocator.free(a2);

    const messages = [_]StatusMessage{
        .{ .keyword = .GOODSIG, .args = a1 },
        .{ .keyword = .TRUST_FULLY, .args = a2 },
    };

    const output = try gnupg.formatStatusOutput(allocator, &messages);
    defer allocator.free(output);

    try testing.expect(mem.indexOf(u8, output, "[GNUPG:] GOODSIG ABCD1234 Test User\n") != null);
    try testing.expect(mem.indexOf(u8, output, "[GNUPG:] TRUST_FULLY 0 pgp\n") != null);
}

// =========================================================================
// Status generation tests
// =========================================================================

test "compat: generateStatus for verify with VALIDSIG" {
    const allocator = testing.allocator;

    const fp = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14 };

    var messages = try gnupg.generateStatus(allocator, .verify, .{
        .verify = .{
            .valid = true,
            .key_id = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
            .user_id = "Alice <alice@example.com>",
            .trust = 3,
            .fingerprint = fp,
            .sig_creation_time = 1700000000,
            .sig_expiration_time = 0,
            .hash_algo = .sha256,
            .pub_algo = .ed25519,
        },
    });
    defer {
        for (messages.items) |msg| msg.deinit(allocator);
        messages.deinit(allocator);
    }

    // Should have NEWSIG, GOODSIG, VALIDSIG, TRUST_FULLY
    try testing.expect(messages.items.len >= 4);
    try testing.expect(messages.items[0].keyword == .NEWSIG);
    try testing.expect(messages.items[1].keyword == .GOODSIG);
    try testing.expect(messages.items[2].keyword == .VALIDSIG);
    try testing.expect(messages.items[3].keyword == .TRUST_FULLY);
}

test "compat: generateStatus for sign" {
    const allocator = testing.allocator;

    var messages = try gnupg.generateStatus(allocator, .sign, .{
        .sign = .{
            .key_id = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 },
            .hash_algo = .sha512,
            .pub_algo = .ed25519,
            .sig_class = 0,
            .timestamp = 1700000000,
            .fingerprint = null,
        },
    });
    defer {
        for (messages.items) |msg| msg.deinit(allocator);
        messages.deinit(allocator);
    }

    try testing.expect(messages.items.len >= 2);
    try testing.expect(messages.items[0].keyword == .BEGIN_SIGNING);
    try testing.expect(messages.items[1].keyword == .SIG_CREATED);
}

test "compat: generateStatus for import" {
    const allocator = testing.allocator;

    var messages = try gnupg.generateStatus(allocator, .import_key, .{
        .import_key = .{
            .imported = 1,
            .unchanged = 0,
            .no_user_id = 0,
            .new_user_ids = 0,
            .new_subkeys = 0,
            .new_signatures = 1,
            .new_revocations = 0,
            .secret_read = 0,
            .secret_imported = 0,
            .secret_unchanged = 0,
            .not_imported = 0,
            .fingerprint = .{ 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
        },
    });
    defer {
        for (messages.items) |msg| msg.deinit(allocator);
        messages.deinit(allocator);
    }

    try testing.expect(messages.items.len >= 2);
    try testing.expect(messages.items[0].keyword == .IMPORT_OK);
    try testing.expect(messages.items[1].keyword == .IMPORT_RES);
}

test "compat: generateStatus for encrypt" {
    const allocator = testing.allocator;

    const recipients = [_][8]u8{
        .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
        .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 },
    };

    var messages = try gnupg.generateStatus(allocator, .encrypt, .{
        .encrypt = .{
            .recipients = &recipients,
            .sym_algo = .aes256,
            .uses_aead = true,
        },
    });
    defer {
        for (messages.items) |msg| msg.deinit(allocator);
        messages.deinit(allocator);
    }

    // 2 ENC_TO + BEGIN_ENCRYPTION + END_ENCRYPTION = 4
    try testing.expect(messages.items.len >= 4);
    try testing.expect(messages.items[0].keyword == .ENC_TO);
    try testing.expect(messages.items[1].keyword == .ENC_TO);
    try testing.expect(messages.items[2].keyword == .BEGIN_ENCRYPTION);
    try testing.expect(messages.items[3].keyword == .END_ENCRYPTION);
}

test "compat: generateStatus for generate_key" {
    const allocator = testing.allocator;

    var messages = try gnupg.generateStatus(allocator, .generate_key, .{
        .generate_key = .{
            .fingerprint = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14 },
            .algorithm = "ed25519",
            .key_type = "B",
        },
    });
    defer {
        for (messages.items) |msg| msg.deinit(allocator);
        messages.deinit(allocator);
    }

    try testing.expect(messages.items.len >= 1);
    try testing.expect(messages.items[0].keyword == .KEY_CREATED);
}

// =========================================================================
// GnuPG version tests
// =========================================================================

test "compat: parseGnupgVersion 2.2.40" {
    const allocator = testing.allocator;

    const v = try gnupg.parseGnupgVersion(allocator, "2.2.40");
    defer allocator.free(v.version_string);

    try testing.expectEqual(@as(u16, 2), v.major);
    try testing.expectEqual(@as(u16, 2), v.minor);
    try testing.expectEqual(@as(u16, 40), v.patch);
    try testing.expect(v.supportsKeybox());
    try testing.expect(!v.supportsAead());
    try testing.expect(!v.supportsV6Keys());
}

test "compat: parseGnupgVersion 1.4.23" {
    const allocator = testing.allocator;

    const v = try gnupg.parseGnupgVersion(allocator, "1.4.23");
    defer allocator.free(v.version_string);

    try testing.expectEqual(@as(u16, 1), v.major);
    try testing.expect(!v.supportsKeybox());
    try testing.expect(!v.supportsAead());
    try testing.expect(!v.supportsV6Keys());
}

test "compat: GnupgVersion isAtLeast boundary conditions" {
    const v = GnupgVersion{
        .major = 2,
        .minor = 4,
        .patch = 0,
        .version_string = "2.4.0",
    };

    try testing.expect(v.isAtLeast(2, 4, 0));
    try testing.expect(v.isAtLeast(2, 3, 99));
    try testing.expect(v.isAtLeast(1, 99, 99));
    try testing.expect(!v.isAtLeast(2, 4, 1));
    try testing.expect(!v.isAtLeast(2, 5, 0));
    try testing.expect(!v.isAtLeast(3, 0, 0));
}

// =========================================================================
// Sequoia compatibility tests
// =========================================================================

test "compat: Sequoia empty data is incompatible" {
    const allocator = testing.allocator;

    var report = try sequoia.checkSequoiaCompatibility(allocator, "");
    defer report.deinit(allocator);

    try testing.expect(!report.compatible);
}

test "compat: Sequoia non-packet data is incompatible" {
    const allocator = testing.allocator;

    const data = [_]u8{ 0x00, 0x01, 0x02 };
    var report = try sequoia.checkSequoiaCompatibility(allocator, &data);
    defer report.deinit(allocator);

    try testing.expect(!report.compatible);
}

test "compat: Sequoia new-format V4 Ed25519 key is compatible" {
    const allocator = testing.allocator;

    var data: [14]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.public_key);
    data[1] = 12;
    data[2] = 4;
    data[3] = 0x60;
    data[4] = 0x00;
    data[5] = 0x00;
    data[6] = 0x00;
    data[7] = @intFromEnum(PublicKeyAlgorithm.ed25519);
    @memset(data[8..], 0);

    var report = try sequoia.checkSequoiaCompatibility(allocator, &data);
    defer report.deinit(allocator);

    // Should be compatible (possibly with info-level notes).
    try testing.expect(report.compatible);
}

test "compat: Sequoia V6 key is fully compatible" {
    const allocator = testing.allocator;

    var data: [14]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.public_key);
    data[1] = 12;
    data[2] = 6; // V6
    data[3] = 0x60;
    data[4] = 0x00;
    data[5] = 0x00;
    data[6] = 0x00;
    data[7] = @intFromEnum(PublicKeyAlgorithm.ed25519);
    @memset(data[8..], 0);

    var report = try sequoia.checkSequoiaCompatibility(allocator, &data);
    defer report.deinit(allocator);

    try testing.expect(report.compatible);
    try testing.expect(report.countBySeverity(.info) > 0);
}

test "compat: Sequoia old-format packet warns" {
    const allocator = testing.allocator;

    var data: [14]u8 = undefined;
    data[0] = 0x80 | (6 << 2) | 0; // Old format, tag 6, 1-byte length
    data[1] = 12;
    data[2] = 4;
    data[3] = 0x60;
    data[4] = 0x00;
    data[5] = 0x00;
    data[6] = 0x00;
    data[7] = @intFromEnum(PublicKeyAlgorithm.ed25519);
    @memset(data[8..], 0);

    var report = try sequoia.checkSequoiaCompatibility(allocator, &data);
    defer report.deinit(allocator);

    try testing.expect(report.countBySeverity(.warning) > 0);
}

test "compat: Sequoia DSA key warns" {
    const allocator = testing.allocator;

    var data: [14]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.public_key);
    data[1] = 12;
    data[2] = 4;
    data[3] = 0x60;
    data[4] = 0x00;
    data[5] = 0x00;
    data[6] = 0x00;
    data[7] = @intFromEnum(PublicKeyAlgorithm.dsa);
    @memset(data[8..], 0);

    var report = try sequoia.checkSequoiaCompatibility(allocator, &data);
    defer report.deinit(allocator);

    try testing.expect(report.countBySeverity(.warning) > 0);
}

// =========================================================================
// RFC 9580 compliance tests
// =========================================================================

test "compat: RFC 9580 compliance empty data" {
    const allocator = testing.allocator;

    var report = try sequoia.checkRfc9580Compliance(allocator, "");
    defer report.deinit(allocator);

    try testing.expect(!report.compliant);
}

test "compat: RFC 9580 compliance old-format fails" {
    const allocator = testing.allocator;

    var data: [14]u8 = undefined;
    data[0] = 0x80 | (6 << 2) | 0;
    data[1] = 12;
    data[2] = 4;
    @memset(data[3..], 0);

    var report = try sequoia.checkRfc9580Compliance(allocator, &data);
    defer report.deinit(allocator);

    try testing.expect(!report.compliant);
}

test "compat: RFC 9580 compliance V4 key notes" {
    const allocator = testing.allocator;

    var data: [14]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.public_key);
    data[1] = 12;
    data[2] = 4; // V4
    data[3] = 0x60;
    data[4] = 0x00;
    data[5] = 0x00;
    data[6] = 0x00;
    data[7] = @intFromEnum(PublicKeyAlgorithm.ed25519);
    @memset(data[8..], 0);

    var report = try sequoia.checkRfc9580Compliance(allocator, &data);
    defer report.deinit(allocator);

    try testing.expectEqual(@as(u8, 4), report.version);
    try testing.expect(!report.has_v6_keys);
}

test "compat: RFC 9580 compliance V6 key" {
    const allocator = testing.allocator;

    var data: [14]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.public_key);
    data[1] = 12;
    data[2] = 6; // V6
    data[3] = 0x60;
    data[4] = 0x00;
    data[5] = 0x00;
    data[6] = 0x00;
    data[7] = @intFromEnum(PublicKeyAlgorithm.ed25519);
    @memset(data[8..], 0);

    var report = try sequoia.checkRfc9580Compliance(allocator, &data);
    defer report.deinit(allocator);

    try testing.expect(report.has_v6_keys);
    try testing.expectEqual(@as(u8, 6), report.version);
}

test "compat: RFC 9580 report format" {
    const allocator = testing.allocator;

    var report = Rfc9580Report{
        .compliant = false,
        .version = 4,
        .uses_aead = false,
        .has_v6_keys = false,
        .deprecated_algorithms = .empty,
        .issues = .empty,
    };
    defer report.deinit(allocator);

    try report.deprecated_algorithms.append(allocator, try allocator.dupe(u8, "DSA"));

    const formatted = try report.format(allocator);
    defer allocator.free(formatted);

    try testing.expect(mem.indexOf(u8, formatted, "Compliant:  no") != null);
    try testing.expect(mem.indexOf(u8, formatted, "DSA") != null);
}

// =========================================================================
// Migration guide tests
// =========================================================================

test "compat: migration guide for compatible key is empty" {
    const allocator = testing.allocator;

    var report = CompatReport{
        .compatible = true,
        .issues = .empty,
    };
    defer report.deinit(allocator);

    var guide = try sequoia.generateMigrationGuide(allocator, &report);
    defer guide.deinit(allocator);

    try testing.expectEqual(@as(usize, 0), guide.steps.items.len);
}

test "compat: migration guide categorizes steps" {
    const allocator = testing.allocator;

    var report = CompatReport{
        .compatible = false,
        .issues = .empty,
    };
    defer report.deinit(allocator);

    try report.issues.append(allocator, .{
        .severity = .error_level,
        .description = try allocator.dupe(u8, "Critical issue"),
    });
    try report.issues.append(allocator, .{
        .severity = .warning,
        .description = try allocator.dupe(u8, "Warning issue"),
    });
    try report.issues.append(allocator, .{
        .severity = .info,
        .description = try allocator.dupe(u8, "Info issue"),
    });

    var guide = try sequoia.generateMigrationGuide(allocator, &report);
    defer guide.deinit(allocator);

    try testing.expectEqual(@as(usize, 3), guide.steps.items.len);
    try testing.expect(mem.indexOf(u8, guide.steps.items[0], "[REQUIRED]") != null);
    try testing.expect(mem.indexOf(u8, guide.steps.items[1], "[RECOMMENDED]") != null);
    try testing.expect(mem.indexOf(u8, guide.steps.items[2], "[OPTIONAL]") != null);
}
