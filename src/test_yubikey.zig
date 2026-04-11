// SPDX-License-Identifier: MIT
//! Integration tests for YubiKey OpenPGP smart card support.
//!
//! These tests use the mock YubiKey implementation to verify:
//!   - ATR detection and pattern matching
//!   - APDU command construction for key operations
//!   - PIN management flow
//!   - Signing and decryption operations
//!   - Key generation and touch policy handling
//!   - Multi-device management

const std = @import("std");
const testing = std.testing;

const yubikey = @import("card/yubikey.zig");
const YubiKey = yubikey.YubiKey;
const YubiKeyManager = yubikey.YubiKeyManager;
const YubiKeySeries = yubikey.YubiKeySeries;
const FirmwareVersion = yubikey.FirmwareVersion;
const TouchPolicy = yubikey.TouchPolicy;
const AtrPatterns = yubikey.AtrPatterns;
const YubiKeyCapabilities = yubikey.YubiKeyCapabilities;
const YubiKeyError = yubikey.YubiKeyError;

const pcsc_bridge = @import("card/pcsc_bridge.zig");
const MockPcscReader = pcsc_bridge.MockPcscReader;
const openpgp_card = @import("card/openpgp_card.zig");
const KeyRef = openpgp_card.KeyRef;

// =========================================================================
// ATR Detection Tests
// =========================================================================

test "ATR pattern: YubiKey 5 NFC detected" {
    try testing.expect(AtrPatterns.matchesYubiKey(AtrPatterns.yk5_nfc));
    try testing.expectEqual(YubiKeySeries.yk5, AtrPatterns.seriesFromAtr(AtrPatterns.yk5_nfc));
}

test "ATR pattern: YubiKey 5 USB prefix detected" {
    const usb_atr = AtrPatterns.yk5_usb_prefix ++ &[_]u8{ 0x4B, 0x65, 0x79, 0x40 };
    try testing.expect(AtrPatterns.matchesYubiKey(usb_atr));
}

test "ATR pattern: YubiKey 4 prefix detected" {
    const yk4_atr = AtrPatterns.yk4_prefix ++ &[_]u8{ 0x15, 0x00, 0x00, 0x00 };
    try testing.expect(AtrPatterns.matchesYubiKey(yk4_atr));
    try testing.expectEqual(YubiKeySeries.yk4, AtrPatterns.seriesFromAtr(yk4_atr));
}

test "ATR pattern: YubiKey NEO prefix detected" {
    const neo_atr = AtrPatterns.neo_prefix ++ &[_]u8{ 0x15, 0x00, 0x00 };
    try testing.expect(AtrPatterns.matchesYubiKey(neo_atr));
    try testing.expectEqual(YubiKeySeries.neo, AtrPatterns.seriesFromAtr(neo_atr));
}

test "ATR pattern: non-YubiKey not detected" {
    // Generic smart card ATR
    const generic_atr: []const u8 = &.{ 0x3B, 0x8C, 0x80, 0x01, 0x00, 0x00 };
    try testing.expect(!AtrPatterns.matchesYubiKey(generic_atr));
    try testing.expectEqual(YubiKeySeries.unknown, AtrPatterns.seriesFromAtr(generic_atr));
}

test "ATR pattern: empty or short ATR rejected" {
    try testing.expect(!AtrPatterns.matchesYubiKey(&.{}));
    try testing.expect(!AtrPatterns.matchesYubiKey(&.{0x3B}));
    try testing.expect(!AtrPatterns.matchesYubiKey(&.{ 0x3B, 0x00, 0x00 }));
}

test "ATR pattern: Yubi string in historical bytes" {
    // ATR with "Yubi" embedded in historical bytes
    const atr: []const u8 = &.{
        0x3B, 0xF8, 0x13, 0x00, 0x00, 0x81, 0x31,
        0x59, 0x75, 0x62, 0x69, // "Yubi"
        0x00, 0x00,
    };
    try testing.expect(AtrPatterns.matchesYubiKey(atr));
}

// =========================================================================
// Firmware Version Tests
// =========================================================================

test "FirmwareVersion series mapping" {
    const v2 = FirmwareVersion{ .major = 2, .minor = 0, .patch = 0 };
    try testing.expectEqual(YubiKeySeries.unknown, v2.series());

    const v3 = FirmwareVersion{ .major = 3, .minor = 5, .patch = 0 };
    try testing.expectEqual(YubiKeySeries.neo, v3.series());

    const v4 = FirmwareVersion{ .major = 4, .minor = 3, .patch = 7 };
    try testing.expectEqual(YubiKeySeries.yk4, v4.series());

    const v5 = FirmwareVersion{ .major = 5, .minor = 4, .patch = 3 };
    try testing.expectEqual(YubiKeySeries.yk5, v5.series());

    const v6 = FirmwareVersion{ .major = 6, .minor = 0, .patch = 0 };
    try testing.expectEqual(YubiKeySeries.yk5, v6.series());
}

test "FirmwareVersion feature detection" {
    // YubiKey 5.4.x supports everything
    const v54 = FirmwareVersion{ .major = 5, .minor = 4, .patch = 0 };
    try testing.expect(v54.supports(.touch_policy));
    try testing.expect(v54.supports(.cached_touch));
    try testing.expect(v54.supports(.attestation));
    try testing.expect(v54.supports(.ecc_p256));
    try testing.expect(v54.supports(.ecc_p384));
    try testing.expect(v54.supports(.ed25519));
    try testing.expect(v54.supports(.x25519));
    try testing.expect(v54.supports(.rsa4096));
    try testing.expect(v54.supports(.kdf));
    try testing.expect(v54.supports(.aes));

    // YubiKey 4.3 - no Ed25519, no attestation, no KDF
    const v43 = FirmwareVersion{ .major = 4, .minor = 3, .patch = 0 };
    try testing.expect(v43.supports(.touch_policy));
    try testing.expect(v43.supports(.cached_touch));
    try testing.expect(!v43.supports(.attestation));
    try testing.expect(v43.supports(.ecc_p256));
    try testing.expect(!v43.supports(.ed25519));
    try testing.expect(!v43.supports(.kdf));
    try testing.expect(!v43.supports(.aes));

    // YubiKey 5.0 - no cached touch, no attestation, no Ed25519
    const v50 = FirmwareVersion{ .major = 5, .minor = 0, .patch = 0 };
    try testing.expect(v50.supports(.touch_policy));
    try testing.expect(!v50.supports(.cached_touch));
    try testing.expect(!v50.supports(.attestation));
    try testing.expect(v50.supports(.aes));

    // YubiKey NEO (3.x) - minimal features
    const v35 = FirmwareVersion{ .major = 3, .minor = 5, .patch = 0 };
    try testing.expect(!v35.supports(.touch_policy));
    try testing.expect(!v35.supports(.ecc_p256));
    try testing.expect(!v35.supports(.rsa4096));
}

test "FirmwareVersion format string" {
    var buf: [12]u8 = undefined;

    const v1 = FirmwareVersion{ .major = 5, .minor = 4, .patch = 3 };
    try testing.expectEqualStrings("5.4.3", v1.format(&buf));

    const v2 = FirmwareVersion{ .major = 4, .minor = 0, .patch = 0 };
    try testing.expectEqualStrings("4.0.0", v2.format(&buf));

    const v3 = FirmwareVersion{ .major = 10, .minor = 20, .patch = 30 };
    try testing.expectEqualStrings("10.20.30", v3.format(&buf));
}

// =========================================================================
// APDU Command Construction Tests
// =========================================================================

test "SELECT OpenPGP application APDU" {
    const cmd = openpgp_card.selectOpenPgpApp();
    try testing.expectEqual(@as(u8, 0x00), cmd.cla);
    try testing.expectEqual(@as(u8, 0xA4), cmd.ins); // SELECT
    try testing.expectEqual(@as(u8, 0x04), cmd.p1); // By DF name
    try testing.expectEqual(@as(u8, 0x00), cmd.p2);
    try testing.expect(cmd.data != null);
    try testing.expectEqual(@as(usize, 6), cmd.data.?.len);
    // AID: D2 76 00 01 24 01
    try testing.expectEqual(@as(u8, 0xD2), cmd.data.?[0]);
    try testing.expectEqual(@as(u8, 0x01), cmd.data.?[5]);
}

test "VERIFY PIN APDU" {
    const pin = "123456";
    const cmd = openpgp_card.verify(.user, pin);
    try testing.expectEqual(@as(u8, 0x20), cmd.ins); // VERIFY
    try testing.expectEqual(@as(u8, 0x81), cmd.p2); // PW1 for signing
    try testing.expectEqualStrings("123456", cmd.data.?);
}

test "COMPUTE DIGITAL SIGNATURE APDU" {
    const hash: [32]u8 = .{0xAA} ** 32;
    const cmd = openpgp_card.computeDigitalSignature(&hash);
    try testing.expectEqual(@as(u8, 0x2A), cmd.ins); // PSO
    try testing.expectEqual(@as(u8, 0x9E), cmd.p1); // CDS
    try testing.expectEqual(@as(u8, 0x9A), cmd.p2);
    try testing.expectEqual(@as(usize, 32), cmd.data.?.len);
}

test "DECIPHER APDU" {
    const ciphertext: [64]u8 = .{0xBB} ** 64;
    const cmd = openpgp_card.decipher(&ciphertext);
    try testing.expectEqual(@as(u8, 0x2A), cmd.ins); // PSO
    try testing.expectEqual(@as(u8, 0x80), cmd.p1); // Decipher
    try testing.expectEqual(@as(u8, 0x86), cmd.p2);
}

test "GENERATE KEY APDU" {
    const cmd = openpgp_card.generateAsymmetricKey(.signature);
    try testing.expectEqual(@as(u8, 0x47), cmd.ins);
    try testing.expectEqual(@as(u8, 0x80), cmd.p1); // Generate
    // Data should contain the CRT tag
    try testing.expectEqual(@as(u8, 0xB6), cmd.data.?[0]); // Signature CRT
}

test "READ PUBLIC KEY APDU" {
    const cmd = openpgp_card.readPublicKeyFromCard(.decryption);
    try testing.expectEqual(@as(u8, 0x47), cmd.ins);
    try testing.expectEqual(@as(u8, 0x81), cmd.p1); // Read existing
    try testing.expectEqual(@as(u8, 0xB8), cmd.data.?[0]); // Decryption CRT
}

test "GET DATA APDU" {
    const cmd = openpgp_card.getData(0x006E); // Application Related Data
    try testing.expectEqual(@as(u8, 0xCA), cmd.ins); // GET DATA
    try testing.expectEqual(@as(u8, 0x00), cmd.p1);
    try testing.expectEqual(@as(u8, 0x6E), cmd.p2);
}

test "PUT DATA APDU" {
    const data = "test data";
    const cmd = openpgp_card.putData(0x005B, data); // Cardholder name
    try testing.expectEqual(@as(u8, 0xDA), cmd.ins); // PUT DATA
    try testing.expectEqual(@as(u8, 0x00), cmd.p1);
    try testing.expectEqual(@as(u8, 0x5B), cmd.p2);
}

test "RESET RETRY COUNTER APDU" {
    const new_pin = "654321";
    const cmd = openpgp_card.resetRetryCounter(new_pin);
    try testing.expectEqual(@as(u8, 0x2C), cmd.ins);
    try testing.expectEqual(@as(u8, 0x02), cmd.p1); // Reset by admin
    try testing.expectEqual(@as(u8, 0x81), cmd.p2); // PW1
}

// =========================================================================
// Mock YubiKey Operation Tests
// =========================================================================

test "Mock YubiKey: connect and detect" {
    const allocator = testing.allocator;
    var mock = try yubikey.createMockYubiKey(allocator);
    defer mock.deinit(allocator);

    var reader = mock.reader();
    var yk = YubiKey.init(allocator, reader);

    try yk.connect();
    defer yk.disconnect();

    // Should detect YubiKey 5
    try testing.expectEqual(YubiKeySeries.yk5, yk.getSeries());
    try testing.expect(yk.app_selected);
}

test "Mock YubiKey: PIN verification" {
    const allocator = testing.allocator;
    var mock = try yubikey.createMockYubiKey(allocator);
    defer mock.deinit(allocator);

    var reader = mock.reader();
    var yk = YubiKey.init(allocator, reader);

    try yk.connect();
    defer yk.disconnect();

    // Verify user PIN
    try yk.verifyUserPin("123456");
    try testing.expect(yk.user_pin_verified);

    // Verify admin PIN
    try yk.verifyAdminPin("12345678");
    try testing.expect(yk.admin_pin_verified);
}

test "Mock YubiKey: sign operation" {
    const allocator = testing.allocator;
    var mock = try yubikey.createMockYubiKey(allocator);
    defer mock.deinit(allocator);

    var reader = mock.reader();
    var yk = YubiKey.init(allocator, reader);

    try yk.connect();
    defer yk.disconnect();

    // Sign without PIN should fail
    try testing.expectError(YubiKeyError.PinRequired, yk.sign(&.{0xAA} ** 32));

    // Verify PIN first, then set a signature key fingerprint
    try yk.verifyUserPin("123456");

    // Manually set card info with a signature key
    if (yk.card_info) |*info| {
        info.sig_key_fingerprint = .{0x01} ** 20;
    }

    const signature = try yk.sign(&.{0xAA} ** 32);
    defer allocator.free(signature);

    try testing.expect(signature.len > 0);
    try testing.expectEqual(@as(u8, 0xAB), signature[0]); // First byte of mock signature
}

test "Mock YubiKey: decrypt operation" {
    const allocator = testing.allocator;
    var mock = try yubikey.createMockYubiKey(allocator);
    defer mock.deinit(allocator);

    var reader = mock.reader();
    var yk = YubiKey.init(allocator, reader);

    try yk.connect();
    defer yk.disconnect();

    // Decrypt without PIN should fail
    try testing.expectError(YubiKeyError.PinRequired, yk.decrypt(&.{0xBB} ** 32));

    // Verify decryption PIN and set enc key fingerprint
    try yk.verifyDecryptionPin("123456");

    if (yk.card_info) |*info| {
        info.enc_key_fingerprint = .{0x02} ** 20;
    }

    const plaintext = try yk.decrypt(&.{0xBB} ** 32);
    defer allocator.free(plaintext);

    try testing.expect(plaintext.len > 0);
}

test "Mock YubiKey: feature support queries" {
    const allocator = testing.allocator;
    var mock = try yubikey.createMockYubiKey(allocator);
    defer mock.deinit(allocator);

    var reader = mock.reader();
    var yk = YubiKey.init(allocator, reader);

    try yk.connect();
    defer yk.disconnect();

    // YubiKey 5.4 should support all features
    try testing.expect(yk.supportsFeature(.touch_policy));
    try testing.expect(yk.supportsFeature(.ed25519));
    try testing.expect(yk.supportsFeature(.attestation));
    try testing.expect(yk.supportsFeature(.rsa4096));
}

// =========================================================================
// YubiKey Capabilities Tests
// =========================================================================

test "YubiKeyCapabilities from firmware version" {
    const yk5_caps = YubiKeyCapabilities.fromFirmware(.{ .major = 5, .minor = 4, .patch = 0 });
    try testing.expect(yk5_caps.supported_algorithms.rsa2048);
    try testing.expect(yk5_caps.supported_algorithms.rsa4096);
    try testing.expect(yk5_caps.supported_algorithms.ed25519);
    try testing.expect(yk5_caps.supported_algorithms.x25519);
    try testing.expect(yk5_caps.touch_policy_available);
    try testing.expect(yk5_caps.attestation_available);
    try testing.expectEqual(@as(u16, 4096), yk5_caps.max_rsa_bits);

    const yk4_caps = YubiKeyCapabilities.fromFirmware(.{ .major = 4, .minor = 2, .patch = 0 });
    try testing.expect(yk4_caps.supported_algorithms.rsa4096);
    try testing.expect(yk4_caps.supported_algorithms.ecc_p256);
    try testing.expect(!yk4_caps.supported_algorithms.ed25519); // YK4 doesn't support Ed25519
    try testing.expect(yk4_caps.touch_policy_available);
    try testing.expect(!yk4_caps.attestation_available); // Requires 5.2+

    const neo_caps = YubiKeyCapabilities.fromFirmware(.{ .major = 3, .minor = 4, .patch = 0 });
    try testing.expect(neo_caps.supported_algorithms.rsa2048);
    try testing.expect(!neo_caps.supported_algorithms.rsa4096);
    try testing.expect(!neo_caps.supported_algorithms.ecc_p256);
    try testing.expectEqual(@as(u16, 2048), neo_caps.max_rsa_bits);
}

// =========================================================================
// TouchPolicy Tests
// =========================================================================

test "TouchPolicy properties" {
    try testing.expect(!TouchPolicy.off.requiresTouch());
    try testing.expect(TouchPolicy.on.requiresTouch());
    try testing.expect(TouchPolicy.cached.requiresTouch());
    try testing.expect(TouchPolicy.fixed.requiresTouch());
    try testing.expect(TouchPolicy.cached_fixed.requiresTouch());

    try testing.expectEqualStrings("Off", TouchPolicy.off.name());
    try testing.expectEqualStrings("On (always)", TouchPolicy.on.name());
    try testing.expectEqualStrings("Cached (15s)", TouchPolicy.cached.name());
}

// =========================================================================
// YubiKeySeries Tests
// =========================================================================

test "YubiKeySeries properties" {
    try testing.expect(YubiKeySeries.yk5.supportsTouchPolicy());
    try testing.expect(YubiKeySeries.yk4.supportsTouchPolicy());
    try testing.expect(!YubiKeySeries.neo.supportsTouchPolicy());
    try testing.expect(!YubiKeySeries.unknown.supportsTouchPolicy());

    try testing.expect(YubiKeySeries.yk5.supportsEcc());
    try testing.expect(YubiKeySeries.yk4.supportsEcc());
    try testing.expect(!YubiKeySeries.neo.supportsEcc());

    try testing.expectEqual(@as(u16, 4096), YubiKeySeries.yk5.maxRsaKeySize());
    try testing.expectEqual(@as(u16, 2048), YubiKeySeries.neo.maxRsaKeySize());

    try testing.expectEqualStrings("YubiKey 5", YubiKeySeries.yk5.name());
    try testing.expectEqualStrings("YubiKey NEO", YubiKeySeries.neo.name());
}

// =========================================================================
// YubiKeyManager Tests
// =========================================================================

test "YubiKeyManager init and scan with no readers" {
    const allocator = testing.allocator;
    var mgr = YubiKeyManager.init(allocator);
    defer mgr.deinit();

    try mgr.establish();
    const count = try mgr.scan();
    try testing.expectEqual(@as(usize, 0), count);
    try testing.expectEqual(@as(usize, 0), mgr.yubikeyCount());
}
