// SPDX-License-Identifier: MIT
//! Tests for format conversion modules.
//!
//! Exercises:
//!   - SSH key format encoding/decoding
//!   - PGP/MIME message creation and parsing
//!   - Enhanced cleartext signature handling
//!   - Keyring format detection and conversion
//!   - GPG agent Assuan protocol encoding

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

const ssh = @import("formats/ssh.zig");
const pgp_mime = @import("formats/pgp_mime.zig");
const ascii_clearsign = @import("formats/ascii_clearsign.zig");
const keyring_format = @import("formats/keyring_format.zig");
const gpg_agent = @import("formats/gpg_agent.zig");

const HashAlgorithm = @import("types/enums.zig").HashAlgorithm;

// =========================================================================
// SSH format tests
// =========================================================================

test "formats: SSH wire string encode/decode round-trip" {
    const allocator = testing.allocator;
    const test_data = "ssh-ed25519";

    const encoded = try ssh.encodeSshString(allocator, test_data);
    defer allocator.free(encoded);

    const decoded = try ssh.decodeSshString(encoded);
    try testing.expectEqualStrings(test_data, decoded.value);
    try testing.expectEqual(@as(usize, 0), decoded.rest.len);
}

test "formats: SSH wire string empty" {
    const allocator = testing.allocator;
    const encoded = try ssh.encodeSshString(allocator, "");
    defer allocator.free(encoded);

    try testing.expectEqual(@as(usize, 4), encoded.len);

    const decoded = try ssh.decodeSshString(encoded);
    try testing.expectEqual(@as(usize, 0), decoded.value.len);
}

test "formats: SSH mpint no padding" {
    const allocator = testing.allocator;
    // 0x42 has MSB clear, no padding
    const encoded = try ssh.encodeSshMpint(allocator, &[_]u8{0x42});
    defer allocator.free(encoded);

    try testing.expectEqual(@as(usize, 5), encoded.len);
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, encoded[0..4], .big));
    try testing.expectEqual(@as(u8, 0x42), encoded[4]);
}

test "formats: SSH mpint with padding" {
    const allocator = testing.allocator;
    // 0xAB has MSB set, needs zero padding
    const encoded = try ssh.encodeSshMpint(allocator, &[_]u8{0xAB});
    defer allocator.free(encoded);

    try testing.expectEqual(@as(usize, 6), encoded.len);
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, encoded[0..4], .big));
    try testing.expectEqual(@as(u8, 0x00), encoded[4]);
    try testing.expectEqual(@as(u8, 0xAB), encoded[5]);
}

test "formats: SSH Ed25519 authorized keys" {
    const allocator = testing.allocator;
    var pubkey: [32]u8 = undefined;
    @memset(&pubkey, 0x42);

    const line = try ssh.toSshEd25519AuthorizedKeys(allocator, &pubkey, "user@host");
    defer allocator.free(line);

    try testing.expect(mem.startsWith(u8, line, "ssh-ed25519 "));
    try testing.expect(mem.endsWith(u8, line, " user@host"));
}

test "formats: SSH Ed25519 authorized keys no comment" {
    const allocator = testing.allocator;
    var pubkey: [32]u8 = undefined;
    @memset(&pubkey, 0x42);

    const line = try ssh.toSshEd25519AuthorizedKeys(allocator, &pubkey, null);
    defer allocator.free(line);

    try testing.expect(mem.startsWith(u8, line, "ssh-ed25519 "));
    try testing.expect(!mem.endsWith(u8, line, " "));
}

test "formats: SSH Ed25519 invalid key length" {
    const allocator = testing.allocator;
    try testing.expectError(
        ssh.SshError.InvalidKeyData,
        ssh.toSshEd25519AuthorizedKeys(allocator, &[_]u8{ 0x01, 0x02, 0x03 }, null),
    );
}

test "formats: SSH RSA authorized keys" {
    const allocator = testing.allocator;
    const n = [_]u8{0xBB} ** 16;
    const e = [_]u8{ 0x01, 0x00, 0x01 };

    const line = try ssh.toSshRsaAuthorizedKeys(allocator, &n, &e, "rsa@test");
    defer allocator.free(line);

    try testing.expect(mem.startsWith(u8, line, "ssh-rsa "));
    try testing.expect(mem.endsWith(u8, line, " rsa@test"));
}

test "formats: SSH key type name round-trip" {
    const types = [_]ssh.SshKeyType{
        .ssh_rsa,
        .ssh_ed25519,
        .ecdsa_sha2_nistp256,
        .ecdsa_sha2_nistp384,
        .ecdsa_sha2_nistp521,
    };

    for (types) |kt| {
        const name = kt.name();
        const parsed = ssh.SshKeyType.fromName(name);
        try testing.expectEqual(kt, parsed.?);
    }
}

test "formats: SSH fingerprint computation" {
    const allocator = testing.allocator;
    var pubkey: [32]u8 = undefined;
    @memset(&pubkey, 0x42);

    // Build wire blob manually for fingerprinting
    const type_str = "ssh-ed25519";
    const type_encoded = try ssh.encodeSshString(allocator, type_str);
    defer allocator.free(type_encoded);
    const key_encoded = try ssh.encodeSshString(allocator, &pubkey);
    defer allocator.free(key_encoded);

    const blob = try allocator.alloc(u8, type_encoded.len + key_encoded.len);
    defer allocator.free(blob);
    @memcpy(blob[0..type_encoded.len], type_encoded);
    @memcpy(blob[type_encoded.len..], key_encoded);

    const fp = try ssh.computeSshFingerprint(allocator, blob);
    defer allocator.free(fp);

    try testing.expect(mem.startsWith(u8, fp, "SHA256:"));
    try testing.expect(fp.len > 7);
}

test "formats: SSH export authentication key" {
    const allocator = testing.allocator;
    var key_material: [32]u8 = undefined;
    @memset(&key_material, 0x77);

    const line = try ssh.exportAuthenticationKeyAsSsh(allocator, &key_material, "auth@key");
    defer allocator.free(line);

    try testing.expect(mem.startsWith(u8, line, "ssh-ed25519 "));
}

test "formats: SSH export authentication key too short" {
    const allocator = testing.allocator;
    try testing.expectError(
        ssh.SshError.KeyTooShort,
        ssh.exportAuthenticationKeyAsSsh(allocator, &[_]u8{0x01}, null),
    );
}

// =========================================================================
// PGP/MIME tests
// =========================================================================

test "formats: PGP/MIME content type strings" {
    try testing.expectEqualStrings("multipart/encrypted", pgp_mime.PgpMimeType.encrypted.contentType());
    try testing.expectEqualStrings("multipart/signed", pgp_mime.PgpMimeType.signed.contentType());
    try testing.expectEqualStrings("application/pgp-keys", pgp_mime.PgpMimeType.keys.contentType());
}

test "formats: PGP/MIME protocol strings" {
    try testing.expectEqualStrings("application/pgp-encrypted", pgp_mime.PgpMimeType.encrypted.protocol().?);
    try testing.expectEqualStrings("application/pgp-signature", pgp_mime.PgpMimeType.signed.protocol().?);
    try testing.expect(pgp_mime.PgpMimeType.keys.protocol() == null);
}

test "formats: PGP/MIME micalg names" {
    try testing.expectEqualStrings("sha256", pgp_mime.micalgName(.sha256));
    try testing.expectEqualStrings("sha512", pgp_mime.micalgName(.sha512));
    try testing.expectEqualStrings("sha1", pgp_mime.micalgName(.sha1));
}

test "formats: PGP/MIME micalg parse" {
    try testing.expectEqual(HashAlgorithm.sha256, pgp_mime.parseMicalg("pgp-sha256").?);
    try testing.expectEqual(HashAlgorithm.sha256, pgp_mime.parseMicalg("sha256").?);
    try testing.expect(pgp_mime.parseMicalg("bogus") == null);
}

test "formats: PGP/MIME encrypted message creation" {
    const allocator = testing.allocator;
    const body = "PGP ENCRYPTED BODY";
    const boundary = "test-boundary";

    const result = try pgp_mime.createPgpMimeEncrypted(allocator, body, boundary);
    defer allocator.free(result);

    try testing.expect(mem.indexOf(u8, result, "multipart/encrypted") != null);
    try testing.expect(mem.indexOf(u8, result, "Version: 1") != null);
    try testing.expect(mem.indexOf(u8, result, body) != null);
    try testing.expect(mem.indexOf(u8, result, "--test-boundary--") != null);
}

test "formats: PGP/MIME signed message creation" {
    const allocator = testing.allocator;
    const text = "Signed text content";
    const sig = "PGP SIGNATURE";
    const boundary = "sig-bound";

    const result = try pgp_mime.createPgpMimeSigned(allocator, text, sig, .sha256, boundary);
    defer allocator.free(result);

    try testing.expect(mem.indexOf(u8, result, "multipart/signed") != null);
    try testing.expect(mem.indexOf(u8, result, "micalg=pgp-sha256") != null);
    try testing.expect(mem.indexOf(u8, result, text) != null);
    try testing.expect(mem.indexOf(u8, result, sig) != null);
}

test "formats: PGP/MIME keys message creation" {
    const allocator = testing.allocator;
    const key_data = "PGP PUBLIC KEY DATA";

    const result = try pgp_mime.createPgpMimeKeys(allocator, key_data);
    defer allocator.free(result);

    try testing.expect(mem.indexOf(u8, result, "application/pgp-keys") != null);
    try testing.expect(mem.indexOf(u8, result, key_data) != null);
}

test "formats: PGP/MIME boundary generation" {
    const allocator = testing.allocator;
    const b1 = try pgp_mime.generateBoundary(allocator);
    defer allocator.free(b1);
    const b2 = try pgp_mime.generateBoundary(allocator);
    defer allocator.free(b2);

    try testing.expect(mem.startsWith(u8, b1, "----zpgp-"));
    try testing.expect(!mem.eql(u8, b1, b2));
}

test "formats: PGP/MIME content type header" {
    const allocator = testing.allocator;

    const ct_enc = try pgp_mime.pgpMimeContentType(.encrypted, "b123", allocator);
    defer allocator.free(ct_enc);
    try testing.expect(mem.indexOf(u8, ct_enc, "multipart/encrypted") != null);
    try testing.expect(mem.indexOf(u8, ct_enc, "b123") != null);

    const ct_sig = try pgp_mime.pgpMimeContentType(.signed, "sig-b", allocator);
    defer allocator.free(ct_sig);
    try testing.expect(mem.indexOf(u8, ct_sig, "multipart/signed") != null);
}

test "formats: PGP/MIME encrypted round-trip" {
    const allocator = testing.allocator;
    const body = "encrypted content here";
    const boundary = "rt-boundary";

    const msg = try pgp_mime.createPgpMimeEncrypted(allocator, body, boundary);
    defer allocator.free(msg);

    var parsed = try pgp_mime.parsePgpMime(allocator, msg);
    defer parsed.deinit(allocator);

    try testing.expectEqual(pgp_mime.PgpMimeType.encrypted, parsed.msg_type);
    try testing.expectEqualStrings(boundary, parsed.boundary);
}

test "formats: PGP/MIME empty inputs" {
    const allocator = testing.allocator;
    try testing.expectError(pgp_mime.PgpMimeError.MissingBoundary, pgp_mime.createPgpMimeEncrypted(allocator, "data", ""));
    try testing.expectError(pgp_mime.PgpMimeError.MissingPgpData, pgp_mime.createPgpMimeEncrypted(allocator, "", "bound"));
    try testing.expectError(pgp_mime.PgpMimeError.MissingPgpData, pgp_mime.createPgpMimeSigned(allocator, "text", "", .sha256, "bound"));
    try testing.expectError(pgp_mime.PgpMimeError.MissingPgpData, pgp_mime.createPgpMimeKeys(allocator, ""));
}

// =========================================================================
// Enhanced cleartext signature tests
// =========================================================================

test "formats: multi-hash cleartext signature creation" {
    const allocator = testing.allocator;
    const text = "Test message for multi-hash";
    const fake_sig = "fake sig data";

    const result = try ascii_clearsign.createMultiHashCleartextSig(
        allocator,
        text,
        fake_sig,
        &[_]HashAlgorithm{ .sha256, .sha512 },
    );
    defer allocator.free(result);

    try testing.expect(mem.indexOf(u8, result, "Hash: SHA256") != null);
    try testing.expect(mem.indexOf(u8, result, "Hash: SHA512") != null);
    try testing.expect(mem.indexOf(u8, result, "-----BEGIN PGP SIGNED MESSAGE-----") != null);
}

test "formats: combined-hash cleartext signature" {
    const allocator = testing.allocator;
    const text = "Combined hash test";
    const fake_sig = "sig bytes";

    const result = try ascii_clearsign.createCombinedHashCleartextSig(
        allocator,
        text,
        fake_sig,
        &[_]HashAlgorithm{ .sha256, .sha384 },
    );
    defer allocator.free(result);

    try testing.expect(mem.indexOf(u8, result, "Hash: SHA256, SHA384") != null);
}

test "formats: canonicalize for signing" {
    const allocator = testing.allocator;

    const input = "Hello   \nWorld\t\t\nFoo";
    const expected = "Hello\r\nWorld\r\nFoo";
    const result = try ascii_clearsign.canonicalizeForSigning(allocator, input);
    defer allocator.free(result);
    try testing.expectEqualStrings(expected, result);
}

test "formats: canonicalize for signing empty" {
    const allocator = testing.allocator;
    const result = try ascii_clearsign.canonicalizeForSigning(allocator, "");
    defer allocator.free(result);
    try testing.expectEqualStrings("", result);
}

test "formats: validate cleartext format valid" {
    const allocator = testing.allocator;
    const msg =
        "-----BEGIN PGP SIGNED MESSAGE-----\n" ++
        "Hash: SHA256\n" ++
        "\n" ++
        "Hello\n" ++
        "-----BEGIN PGP SIGNATURE-----\n" ++
        "\n" ++
        "data\n" ++
        "-----END PGP SIGNATURE-----\n";

    var result = try ascii_clearsign.validateCleartextFormat(allocator, msg);
    defer result.deinit(allocator);

    try testing.expect(result.valid);
    try testing.expectEqual(@as(usize, 1), result.hash_headers.len);
}

test "formats: validate cleartext format invalid" {
    const allocator = testing.allocator;
    var result = try ascii_clearsign.validateCleartextFormat(allocator, "not a valid message");
    defer result.deinit(allocator);
    try testing.expect(!result.valid);
}

// =========================================================================
// Keyring format tests
// =========================================================================

test "formats: keyring format detection armored" {
    try testing.expectEqual(
        keyring_format.KeyringFormat.armored,
        keyring_format.detectFormat("-----BEGIN PGP PUBLIC KEY BLOCK-----\ndata"),
    );
}

test "formats: keyring format detection binary" {
    try testing.expectEqual(
        keyring_format.KeyringFormat.binary,
        keyring_format.detectFormat(&[_]u8{ 0xC6, 0x01, 0x04 }),
    );
}

test "formats: keyring format detection SSH" {
    try testing.expectEqual(
        keyring_format.KeyringFormat.ssh_authorized_keys,
        keyring_format.detectFormat("ssh-ed25519 AAAA... user@host"),
    );
    try testing.expectEqual(
        keyring_format.KeyringFormat.ssh_authorized_keys,
        keyring_format.detectFormat("ssh-rsa AAAA... user@host"),
    );
}

test "formats: keyring format detection empty" {
    try testing.expectEqual(
        keyring_format.KeyringFormat.binary,
        keyring_format.detectFormat(""),
    );
}

test "formats: keyring format labels" {
    try testing.expectEqualStrings("OpenPGP (binary)", keyring_format.KeyringFormat.binary.label());
    try testing.expectEqualStrings("OpenPGP (armored)", keyring_format.KeyringFormat.armored.label());
    try testing.expectEqualStrings("SSH authorized_keys", keyring_format.KeyringFormat.ssh_authorized_keys.label());
}

test "formats: keyring format conversion binary to armored" {
    const allocator = testing.allocator;
    const binary = [_]u8{ 0xC6, 0x04, 0x04, 0x00, 0x00, 0x01 };

    const armored = try keyring_format.convertFormat(allocator, &binary, .binary, .armored);
    defer allocator.free(armored);

    try testing.expect(mem.startsWith(u8, armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));
}

test "formats: keyring format conversion round-trip" {
    const allocator = testing.allocator;
    const binary = [_]u8{ 0xC6, 0x04, 0x04, 0x00, 0x00, 0x01 };

    const armored = try keyring_format.convertFormat(allocator, &binary, .binary, .armored);
    defer allocator.free(armored);

    const round_trip = try keyring_format.convertFormat(allocator, armored, .armored, .binary);
    defer allocator.free(round_trip);

    try testing.expectEqualSlices(u8, &binary, round_trip);
}

test "formats: keyring format conversion same format" {
    const allocator = testing.allocator;
    const data = "test data";
    const result = try keyring_format.convertFormat(allocator, data, .binary, .binary);
    defer allocator.free(result);
    try testing.expectEqualStrings(data, result);
}

test "formats: keyring format conversion unsupported" {
    const allocator = testing.allocator;
    try testing.expectError(
        keyring_format.KeyringFormatError.ConversionNotSupported,
        keyring_format.convertFormat(allocator, "data", .keybox, .binary),
    );
}

test "formats: import from binary format" {
    const allocator = testing.allocator;
    const data = [_]u8{ 0xC6, 0x04, 0x04, 0x00, 0x00, 0x01 };

    var result = try keyring_format.importFromAnyFormat(allocator, &data);
    defer result.deinit(allocator);

    try testing.expectEqual(keyring_format.KeyringFormat.binary, result.format_detected);
    try testing.expectEqual(@as(usize, 1), result.count());
}

test "formats: import from SSH format" {
    const allocator = testing.allocator;
    const data = "ssh-ed25519 AAAA... user@host\nssh-rsa BBBB... user2@host\n";

    var result = try keyring_format.importFromAnyFormat(allocator, data);
    defer result.deinit(allocator);

    try testing.expectEqual(keyring_format.KeyringFormat.ssh_authorized_keys, result.format_detected);
    try testing.expectEqual(@as(usize, 2), result.count());
}

test "formats: import from empty fails" {
    const allocator = testing.allocator;
    try testing.expectError(
        keyring_format.KeyringFormatError.InvalidData,
        keyring_format.importFromAnyFormat(allocator, ""),
    );
}

test "formats: export in format binary" {
    const allocator = testing.allocator;
    const data = [_]u8{ 0xC6, 0x04, 0x04, 0x00, 0x00, 0x01 };
    const result = try keyring_format.exportInFormat(allocator, &data, .binary, false);
    defer allocator.free(result);
    try testing.expectEqualSlices(u8, &data, result);
}

test "formats: export in format armored" {
    const allocator = testing.allocator;
    const data = [_]u8{ 0xC6, 0x04, 0x04, 0x00, 0x00, 0x01 };
    const result = try keyring_format.exportInFormat(allocator, &data, .armored, false);
    defer allocator.free(result);
    try testing.expect(mem.indexOf(u8, result, "PUBLIC KEY") != null);
}

// =========================================================================
// GPG agent protocol tests
// =========================================================================

test "formats: Assuan command serialize" {
    const allocator = testing.allocator;

    const cmd_with_args = gpg_agent.AssuanCommand{ .command = "GETINFO", .args = "version" };
    const s1 = try cmd_with_args.serialize(allocator);
    defer allocator.free(s1);
    try testing.expectEqualStrings("GETINFO version\n", s1);

    const cmd_no_args = gpg_agent.AssuanCommand{ .command = "RESET", .args = null };
    const s2 = try cmd_no_args.serialize(allocator);
    defer allocator.free(s2);
    try testing.expectEqualStrings("RESET\n", s2);
}

test "formats: Assuan response parse OK" {
    const allocator = testing.allocator;
    var resp = try gpg_agent.AssuanResponse.parse(allocator, "OK");
    defer resp.deinit(allocator);
    try testing.expectEqual(gpg_agent.ResponseStatus.ok, resp.status);
}

test "formats: Assuan response parse ERR" {
    const allocator = testing.allocator;
    var resp = try gpg_agent.AssuanResponse.parse(allocator, "ERR 100 Not found");
    defer resp.deinit(allocator);
    try testing.expectEqual(gpg_agent.ResponseStatus.err, resp.status);
    try testing.expectEqual(@as(u32, 100), resp.error_code);
}

test "formats: Assuan response parse data" {
    const allocator = testing.allocator;
    var resp = try gpg_agent.AssuanResponse.parse(allocator, "D hello");
    defer resp.deinit(allocator);
    try testing.expectEqual(gpg_agent.ResponseStatus.data_line, resp.status);
    try testing.expectEqualStrings("hello", resp.data.?);
}

test "formats: Assuan percent-encoding round-trip" {
    const allocator = testing.allocator;
    const original = "Hello\nWorld\r100%";
    const encoded = try gpg_agent.assuanEncode(allocator, original);
    defer allocator.free(encoded);
    const decoded = try gpg_agent.assuanDecode(allocator, encoded);
    defer allocator.free(decoded);
    try testing.expectEqualStrings(original, decoded);
}

test "formats: Assuan encode special chars" {
    const allocator = testing.allocator;
    const result = try gpg_agent.assuanEncode(allocator, "a\nb%c");
    defer allocator.free(result);
    try testing.expectEqualStrings("a%0Ab%25c", result);
}

test "formats: gpg-agent command builders" {
    try testing.expectEqualStrings("HAVEKEY", gpg_agent.haveSecretKey("grip").command);
    try testing.expectEqualStrings("GETINFO", gpg_agent.getInfo("version").command);
    try testing.expectEqualStrings("CLEAR_PASSPHRASE", gpg_agent.clearPassphrase("id").command);
    try testing.expectEqualStrings("SIGKEY", gpg_agent.signKey("grip").command);
    try testing.expectEqualStrings("SETKEY", gpg_agent.setKey("grip").command);
    try testing.expectEqualStrings("PKSIGN", gpg_agent.pkSign().command);
    try testing.expectEqualStrings("PKDECRYPT", gpg_agent.pkDecrypt().command);
    try testing.expectEqualStrings("RESET", gpg_agent.reset().command);
    try testing.expectEqualStrings("BYE", gpg_agent.bye().command);
    try testing.expectEqualStrings("KEYINFO", gpg_agent.keyInfo("grip").command);
}

test "formats: key grip calculation RSA deterministic" {
    const n = [_]u8{0x42} ** 16;
    const g1 = gpg_agent.calculateRsaKeyGrip(&n);
    const g2 = gpg_agent.calculateRsaKeyGrip(&n);
    try testing.expectEqualSlices(u8, &g1, &g2);
}

test "formats: key grip calculation Ed25519" {
    var pubkey: [32]u8 = undefined;
    @memset(&pubkey, 0x55);
    const g1 = gpg_agent.calculateEd25519KeyGrip(&pubkey);
    const g2 = gpg_agent.calculateEd25519KeyGrip(&pubkey);
    try testing.expectEqualSlices(u8, &g1, &g2);
}

test "formats: key grip format/parse round-trip" {
    const allocator = testing.allocator;
    var original: [20]u8 = undefined;
    @memset(&original, 0xDE);
    const hex = try gpg_agent.formatKeyGrip(allocator, original);
    defer allocator.free(hex);
    try testing.expectEqual(@as(usize, 40), hex.len);

    const parsed = (try gpg_agent.parseKeyGrip(hex)).?;
    try testing.expectEqualSlices(u8, &original, &parsed);
}

test "formats: key grip parse invalid length" {
    try testing.expect((try gpg_agent.parseKeyGrip("AABB")) == null);
}

test "formats: key grip parse invalid chars" {
    try testing.expect((try gpg_agent.parseKeyGrip("GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG")) == null);
}
