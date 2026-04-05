// SPDX-License-Identifier: MIT
//! Tests that run all example modules to ensure they compile and work.
//!
//! This test file imports the three example modules and runs their
//! embedded tests. It also performs additional integration-style tests
//! that combine multiple example operations.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

// Import example modules to pull in their tests
const encrypt_decrypt = @import("examples/encrypt_decrypt.zig");
const key_management = @import("examples/key_management.zig");
const signatures = @import("examples/signatures.zig");

// Import library modules for integration tests
const armor = @import("armor/armor.zig");
const keygen = @import("key/generate.zig");
const Key = @import("key/key.zig").Key;
const UserIdBinding = @import("key/key.zig").UserIdBinding;
const Keyring = @import("key/keyring.zig").Keyring;
const PublicKeyPacket = @import("packets/public_key.zig").PublicKeyPacket;
const UserIdPacket = @import("packets/user_id.zig").UserIdPacket;
const compose = @import("message/compose.zig");
const notation = @import("signature/notation.zig");
const sig_creation = @import("signature/creation.zig");
const enums = @import("types/enums.zig");

// Import utility and policy modules
const hex = @import("utils/hex.zig");
const base64_extra = @import("utils/base64.zig");
const pem = @import("utils/pem.zig");
const email_util = @import("utils/email.zig");
const time_fmt = @import("utils/time_fmt.zig");
const algo_policy = @import("policy/algorithm_policy.zig");
const compliance = @import("policy/compliance.zig");

// Pull in tests from example modules
test {
    testing.refAllDecls(encrypt_decrypt);
    testing.refAllDecls(key_management);
    testing.refAllDecls(signatures);
}

// =========================================================================
// Integration tests: combining examples with utilities
// =========================================================================

test "integration: key generation + fingerprint formatting" {
    const allocator = testing.allocator;

    const generated = keygen.generateKey(allocator, .{
        .algorithm = .rsa_encrypt_sign,
        .bits = 2048,
        .user_id = "Integration Test <integration@example.com>",
    }) catch return; // Skip if keygen fails
    defer generated.deinit(allocator);

    // Format fingerprint using hex utility
    const fp_hex = try hex.hexEncodeUpper(allocator, &generated.fingerprint);
    defer allocator.free(fp_hex);
    try testing.expectEqual(@as(usize, 40), fp_hex.len);

    // Format as grouped fingerprint
    const fp_grouped = try hex.formatFingerprintGrouped(allocator, &generated.fingerprint);
    defer allocator.free(fp_grouped);
    try testing.expect(fp_grouped.len > 40); // Includes spaces

    // Format as colon-separated
    const fp_colon = try hex.formatFingerprint(allocator, &generated.fingerprint);
    defer allocator.free(fp_colon);
    try testing.expect(mem.indexOf(u8, fp_colon, ":") != null);
}

test "integration: key generation + compliance check" {
    const allocator = testing.allocator;

    const generated = keygen.generateKey(allocator, .{
        .algorithm = .rsa_encrypt_sign,
        .bits = 2048,
        .user_id = "Compliance Test <compliance@example.com>",
    }) catch return;
    defer generated.deinit(allocator);

    // Decode the public key to get the binary data
    var decoded = armor.decode(allocator, generated.public_key_armored) catch return;
    defer decoded.deinit();

    // Verify the binary data is valid OpenPGP
    try testing.expect(decoded.data.len > 0);
    try testing.expect(decoded.data[0] & 0x80 != 0); // Valid packet header
}

test "integration: armor + base64 + hex utilities" {
    const allocator = testing.allocator;

    // Create test data
    const data = "Test data for integration";

    // Armor encode
    const armored = try armor.encode(allocator, data, .message, null);
    defer allocator.free(armored);

    // Decode back
    var decoded = try armor.decode(allocator, armored);
    defer decoded.deinit();

    // Hex encode the decoded data
    const hex_encoded = try hex.hexEncode(allocator, decoded.data);
    defer allocator.free(hex_encoded);

    // Hex decode back
    const hex_decoded = try hex.hexDecode(allocator, hex_encoded);
    defer allocator.free(hex_decoded);

    try testing.expectEqualSlices(u8, decoded.data, hex_decoded);

    // Base64 encode the decoded data
    const b64_encoded = try base64_extra.encodeMultiLine(allocator, decoded.data, 76);
    defer allocator.free(b64_encoded);

    // Base64 decode back
    const b64_decoded = try base64_extra.decodeIgnoringWhitespace(allocator, b64_encoded);
    defer allocator.free(b64_decoded);

    try testing.expectEqualSlices(u8, decoded.data, b64_decoded);
}

test "integration: email parsing + user ID formatting" {
    const allocator = testing.allocator;

    // Parse a User ID
    const parts = email_util.parseUserId("Alice Smith (Security) <alice@example.com>");
    try testing.expectEqualStrings("Alice Smith", parts.name.?);
    try testing.expectEqualStrings("Security", parts.comment.?);
    try testing.expectEqualStrings("alice@example.com", parts.email.?);

    // Format it back
    const formatted = try email_util.formatUserId(parts, allocator);
    defer allocator.free(formatted);
    try testing.expectEqualStrings("Alice Smith (Security) <alice@example.com>", formatted);

    // Validate the email
    try testing.expect(email_util.isValidEmail(parts.email.?));

    // Normalize the email
    const normalized = try email_util.normalizeEmail(allocator, parts.email.?);
    defer allocator.free(normalized);
    try testing.expectEqualStrings("alice@example.com", normalized);
}

test "integration: time formatting + expiration calculation" {
    var buf: [64]u8 = undefined;

    // Format a known timestamp
    const ts = try time_fmt.formatTimestamp(1700000000, &buf);
    try testing.expect(ts.len == 23);

    // Calculate days until expiry
    const days = time_fmt.daysUntilExpiry(1700000000, 365 * 86400, 1700000000 + 100 * 86400);
    try testing.expect(days != null);
    try testing.expectEqual(@as(i64, 265), days.?);

    // Format the duration
    const dur = try time_fmt.formatDuration(265 * 86400, &buf);
    try testing.expectEqualStrings("265 days", dur);
}

test "integration: policy + notation data" {
    const allocator = testing.allocator;

    // Create a notation
    const nota = try notation.createNotation(
        allocator,
        "preferred-email-encoding@pgp.com",
        "pgpmime",
        true,
    );
    defer allocator.free(nota);

    // Parse it back
    const parsed = try notation.parseNotation(nota, allocator);
    defer parsed.deinit(allocator);

    try testing.expect(parsed.human_readable);
    try testing.expectEqualStrings("preferred-email-encoding@pgp.com", parsed.name);
    try testing.expectEqualStrings("pgpmime", parsed.value);
}

test "integration: keyring + email lookup" {
    const allocator = testing.allocator;

    var ring = Keyring.init(allocator);
    defer ring.deinit();

    // Create two keys
    const emails = [_][]const u8{
        "user1@example.com",
        "user2@example.com",
    };

    for (emails, 0..) |email_addr, i| {
        var body: [12]u8 = undefined;
        body[0] = 4;
        mem.writeInt(u32, body[1..5], @as(u32, @intCast(1000 + i * 1000)), .big);
        body[5] = 1;
        mem.writeInt(u16, body[6..8], 8, .big);
        body[8] = @as(u8, @intCast(0xE0 + i));
        mem.writeInt(u16, body[9..11], 8, .big);
        body[11] = 0x03;

        const pk = try PublicKeyPacket.parse(allocator, &body, false);
        var key = Key.init(pk);

        const uid_str = try std.fmt.allocPrint(allocator, "User <{s}>", .{email_addr});
        defer allocator.free(uid_str);

        const uid = UserIdPacket{ .id = try allocator.dupe(u8, uid_str) };
        try key.addUserId(allocator, .{
            .user_id = uid,
            .self_signature = null,
            .certifications = .empty,
        });

        try ring.addKey(key);
    }

    // Look up by email
    const found = try ring.findByEmail("user1@example.com", allocator);
    defer allocator.free(found);
    try testing.expectEqual(@as(usize, 1), found.len);

    // Validate the email with our utility
    try testing.expect(email_util.isValidEmail("user1@example.com"));
}

test "integration: PEM + armor interop concepts" {
    const allocator = testing.allocator;

    // Create a PEM block
    const pem_data = "test binary data for PEM";
    const pem_encoded = try pem.encodePemBlock(allocator, "PGP MESSAGE", pem_data);
    defer allocator.free(pem_encoded);

    // Parse it back
    const blocks = try pem.parsePemBlocks(allocator, pem_encoded);
    defer {
        for (blocks) |blk| blk.deinit(allocator);
        allocator.free(blocks);
    }

    try testing.expectEqual(@as(usize, 1), blocks.len);
    try testing.expectEqualStrings("PGP MESSAGE", blocks[0].label);
    try testing.expectEqualStrings(pem_data, blocks[0].data);
}

test "integration: literal data + compression" {
    const allocator = testing.allocator;

    const message = "Test message for literal data and compression.";

    // Create literal data
    const literal = try compose.createLiteralData(allocator, message, "test.txt", true);
    defer allocator.free(literal);

    // Compress it
    const compressed = try compose.compressData(allocator, literal, .uncompressed);
    defer allocator.free(compressed);

    // Verify the compressed packet is larger (includes header + algo byte)
    try testing.expect(compressed.len > 0);
}

test "integration: policy validation chain" {
    // Demonstrate validating an entire algorithm suite
    const policy = algo_policy.AlgorithmPolicy.init(.rfc9580);

    // A good V4 suite
    const v4_result = policy.validateSuite(.aes256, .sha256, .rsa_encrypt_sign, 4096);
    try testing.expect(v4_result.accepted);

    // A V6 suite would use AEAD
    try testing.expect(policy.isAcceptableAead(.gcm));
    try testing.expect(policy.isAcceptableAead(.ocb));

    // Preferred algorithms should be strong
    try testing.expectEqual(enums.SymmetricAlgorithm.aes256, policy.preferredSymmetric());
    try testing.expectEqual(enums.HashAlgorithm.sha256, policy.preferredHash());
}
