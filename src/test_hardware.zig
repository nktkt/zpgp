// SPDX-License-Identifier: MIT
//! Tests for hardware token support modules:
//!   - BZip2 decompression (src/crypto/bzip2.zig)
//!   - PKCS#11 hardware token interface (src/crypto/pkcs11.zig)
//!   - PCSC bridge (src/card/pcsc_bridge.zig)
//!
//! These tests exercise the public APIs with mock implementations
//! and synthetic test data. No actual hardware is required.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

const bzip2 = @import("crypto/bzip2.zig");
const pkcs11 = @import("crypto/pkcs11.zig");
const pcsc_bridge = @import("card/pcsc_bridge.zig");
const openpgp_card = @import("card/openpgp_card.zig");

// ===========================================================================
// BZip2 Decompression Tests
// ===========================================================================

test "bzip2: BitReader multi-byte read" {
    // 0xAB = 1010_1011, 0xCD = 1100_1101
    const data = [_]u8{ 0xAB, 0xCD };
    var reader = bzip2.BitReader.init(&data);

    // Read 12 bits: 1010_1011_1100 = 0xABC
    const val = try reader.readU32(12);
    try testing.expectEqual(@as(u32, 0xABC), val);
}

test "bzip2: BitReader single bit exhaustion" {
    const data = [_]u8{0b10000000};
    var reader = bzip2.BitReader.init(&data);

    try testing.expectEqual(@as(u1, 1), try reader.readBit());
    for (0..7) |_| {
        _ = try reader.readBit();
    }
    try testing.expectError(bzip2.BZip2Error.UnexpectedEndOfStream, reader.readBit());
}

test "bzip2: CRC32 consistency" {
    // Verify CRC is consistent across calls
    const test_data = "The quick brown fox jumps over the lazy dog";
    const crc1 = bzip2.bzip2CrcBlock(test_data);
    const crc2 = bzip2.bzip2CrcBlock(test_data);
    try testing.expectEqual(crc1, crc2);

    // Different data produces different CRC
    const crc3 = bzip2.bzip2CrcBlock("The quick brown fox jumps over the lazy cat");
    try testing.expect(crc1 != crc3);
}

test "bzip2: CRC32 known values" {
    // Empty data CRC should be 0 (0xFFFFFFFF ^ 0xFFFFFFFF)
    try testing.expectEqual(@as(u32, 0), bzip2.bzip2CrcBlock(""));

    // Single byte
    const single_crc = bzip2.bzip2CrcBlock("a");
    try testing.expect(single_crc != 0);
}

test "bzip2: inverseBWT roundtrip various strings" {
    const allocator = testing.allocator;

    const test_cases = [_][]const u8{
        "hello",
        "abcdef",
        "aabbcc",
        "zzzzz",
        "ab",
        "a",
        "abracadabra",
        "mississippi",
        "the quick brown fox",
    };

    for (test_cases) |input| {
        const bwt = try bzip2.forwardBWT(allocator, input);
        defer allocator.free(bwt.data);

        const recovered = try bzip2.inverseBWT(allocator, bwt.data, bwt.origin);
        defer allocator.free(recovered);

        try testing.expectEqualStrings(input, recovered);
    }
}

test "bzip2: RLE1 roundtrip various patterns" {
    const allocator = testing.allocator;

    const test_cases = [_][]const u8{
        "abc",
        "aaaa", // Exactly 4 (triggers RLE)
        "aaaaa", // 5 identical
        "aaaaabbb",
        "xxxxxxxxxxxx", // Long run
        "",
        "abababab",
        "aaabbbccc",
    };

    for (test_cases) |input| {
        const encoded = try bzip2.encodeRLE1(allocator, input);
        defer allocator.free(encoded);

        const decoded = try bzip2.decodeRLE1(allocator, encoded);
        defer allocator.free(decoded);

        try testing.expectEqualStrings(input, decoded);
    }
}

test "bzip2: RLE1 encoding produces shorter output for runs" {
    const allocator = testing.allocator;

    // 10 identical bytes: should be encoded as 4 bytes + count(6) = 5 bytes
    const input = "aaaaaaaaaa"; // 10 'a's
    const encoded = try bzip2.encodeRLE1(allocator, input);
    defer allocator.free(encoded);

    try testing.expect(encoded.len < input.len);
}

test "bzip2: decompress invalid magic" {
    const allocator = testing.allocator;

    try testing.expectError(bzip2.BZip2Error.InvalidMagic, bzip2.decompress(allocator, "GZIPdata"));
    try testing.expectError(bzip2.BZip2Error.InvalidMagic, bzip2.decompress(allocator, "BZ"));
    try testing.expectError(bzip2.BZip2Error.InvalidMagic, bzip2.decompress(allocator, ""));
}

test "bzip2: decompress invalid block size" {
    const allocator = testing.allocator;

    try testing.expectError(bzip2.BZip2Error.InvalidBlockSize, bzip2.decompress(allocator, "BZh0data"));
    try testing.expectError(bzip2.BZip2Error.InvalidBlockSize, bzip2.decompress(allocator, "BZhAdata"));
}

test "bzip2: BZip2Decompressor init state" {
    var decompressor = bzip2.BZip2Decompressor.init("BZh9somedata");
    defer decompressor.deinit(testing.allocator);

    try testing.expect(!decompressor.isFinished());
    try testing.expectEqual(@as(usize, 0), decompressor.output_pos);
}

test "bzip2: HuffmanTree two symbols" {
    // Two symbols with code length 1: 0 -> sym0, 1 -> sym1
    const lengths = [_]u5{ 1, 1 };
    const tree = try bzip2.HuffmanTree.build(&lengths, 2);

    try testing.expectEqual(@as(u5, 1), tree.min_len);
    try testing.expectEqual(@as(u5, 1), tree.max_len);
}

test "bzip2: HuffmanTree decode three symbols" {
    const lengths = [_]u5{ 1, 2, 2 };
    const tree = try bzip2.HuffmanTree.build(&lengths, 3);

    // Symbol 0 has code 0 (1 bit)
    var d0 = [_]u8{0b00000000};
    var r0 = bzip2.BitReader.init(&d0);
    try testing.expectEqual(@as(u16, 0), try tree.decode(&r0));

    // Symbol 1 has code 10 (2 bits)
    var d1 = [_]u8{0b10000000};
    var r1 = bzip2.BitReader.init(&d1);
    try testing.expectEqual(@as(u16, 1), try tree.decode(&r1));

    // Symbol 2 has code 11 (2 bits)
    var d2 = [_]u8{0b11000000};
    var r2 = bzip2.BitReader.init(&d2);
    try testing.expectEqual(@as(u16, 2), try tree.decode(&r2));
}

test "bzip2: HuffmanTree invalid lengths" {
    // Zero-length code is invalid
    const lengths = [_]u5{ 0, 1 };
    try testing.expectError(bzip2.BZip2Error.InvalidHuffmanTable, bzip2.HuffmanTree.build(&lengths, 2));
}

test "bzip2: BitWriter and flush" {
    var writer = bzip2.BitWriter.init(testing.allocator);
    defer writer.deinit();

    // Write 3 bits: 101
    try writer.writeBits(3, 0b101);
    try writer.flush();

    const data = writer.bytes();
    try testing.expectEqual(@as(usize, 1), data.len);
    // 101 padded to 10100000 = 0xA0
    try testing.expectEqual(@as(u8, 0xA0), data[0]);
}

test "bzip2: forward BWT preserves length" {
    const allocator = testing.allocator;

    const input = "hello world";
    const bwt = try bzip2.forwardBWT(allocator, input);
    defer allocator.free(bwt.data);

    try testing.expectEqual(input.len, bwt.data.len);
    try testing.expect(bwt.origin < input.len);
}

test "bzip2: MTF encode basic" {
    const allocator = testing.allocator;

    var in_use: [256]bool = .{false} ** 256;
    in_use['a'] = true;
    in_use['b'] = true;
    in_use['c'] = true;

    const result = try bzip2.mtfEncode(allocator, "abc", &in_use);
    defer allocator.free(result.symbols);

    try testing.expectEqual(@as(u16, 3), result.n_in_use);
    try testing.expectEqual(@as(usize, 3), result.symbols.len);
}

// ===========================================================================
// PKCS#11 Hardware Token Interface Tests
// ===========================================================================

test "pkcs11: mechanism type properties" {
    // RSA mechanisms
    try testing.expect(pkcs11.MechanismType.rsa_pkcs.isRsa());
    try testing.expect(pkcs11.MechanismType.sha256_rsa_pkcs.isRsa());
    try testing.expect(pkcs11.MechanismType.sha512_rsa_pkcs_pss.isRsa());

    // Non-RSA
    try testing.expect(!pkcs11.MechanismType.ecdsa.isRsa());
    try testing.expect(!pkcs11.MechanismType.eddsa.isRsa());
    try testing.expect(!pkcs11.MechanismType.dsa.isRsa());

    // Hash-included mechanisms
    try testing.expect(pkcs11.MechanismType.sha256_rsa_pkcs.includesHash());
    try testing.expect(pkcs11.MechanismType.ecdsa_sha256.includesHash());
    try testing.expect(!pkcs11.MechanismType.rsa_pkcs.includesHash());
    try testing.expect(!pkcs11.MechanismType.ecdsa.includesHash());

    // Signing capability
    try testing.expect(pkcs11.MechanismType.rsa_pkcs.canSign());
    try testing.expect(pkcs11.MechanismType.ecdsa.canSign());
    try testing.expect(pkcs11.MechanismType.eddsa.canSign());
}

test "pkcs11: mechanism names" {
    try testing.expectEqualStrings("CKM_RSA_PKCS", pkcs11.MechanismType.rsa_pkcs.name());
    try testing.expectEqualStrings("CKM_SHA256_RSA_PKCS", pkcs11.MechanismType.sha256_rsa_pkcs.name());
    try testing.expectEqualStrings("CKM_ECDSA", pkcs11.MechanismType.ecdsa.name());
    try testing.expectEqualStrings("CKM_EDDSA", pkcs11.MechanismType.eddsa.name());
    try testing.expectEqualStrings("CKM_DSA_SHA256", pkcs11.MechanismType.dsa_sha256.name());
}

test "pkcs11: error mapping from CK_RV" {
    // Test known CK_RV codes
    try testing.expectError(pkcs11.Pkcs11Error.SlotIdInvalid, returnPkcsError(0x00000003));
    try testing.expectError(pkcs11.Pkcs11Error.PinIncorrect, returnPkcsError(0x000000A0));
    try testing.expectError(pkcs11.Pkcs11Error.PinLocked, returnPkcsError(0x000000A4));
    try testing.expectError(pkcs11.Pkcs11Error.TokenNotPresent, returnPkcsError(0x000000E0));
    try testing.expectError(pkcs11.Pkcs11Error.UserAlreadyLoggedIn, returnPkcsError(0x00000100));
    try testing.expectError(pkcs11.Pkcs11Error.UserNotLoggedIn, returnPkcsError(0x00000101));
    try testing.expectError(pkcs11.Pkcs11Error.DeviceError, returnPkcsError(0x00000030));
    try testing.expectError(pkcs11.Pkcs11Error.DeviceRemoved, returnPkcsError(0x00000032));
    try testing.expectError(pkcs11.Pkcs11Error.MechanismInvalid, returnPkcsError(0x00000070));

    // Unknown code maps to GeneralError
    try testing.expectError(pkcs11.Pkcs11Error.GeneralError, returnPkcsError(0xDEADBEEF));
}

fn returnPkcsError(rv: u32) pkcs11.Pkcs11Error!void {
    return pkcs11.mapCkRv(rv);
}

test "pkcs11: token info string trimming" {
    var info: pkcs11.TokenInfo = undefined;
    info.label = .{' '} ** 32;
    @memcpy(info.label[0..13], "My HSM Token ");
    info.manufacturer_id = .{' '} ** 32;
    @memcpy(info.manufacturer_id[0..9], "Thales   ");
    info.model = .{' '} ** 16;
    @memcpy(info.model[0..9], "Luna 7   ");
    info.serial_number = .{' '} ** 16;
    @memcpy(info.serial_number[0..10], "ABC1234567");

    try testing.expectEqualStrings("My HSM Token", info.labelStr());
    try testing.expectEqualStrings("Thales", info.manufacturerStr());
    try testing.expectEqualStrings("Luna 7", info.modelStr());
    try testing.expectEqualStrings("ABC1234567", info.serialStr());
}

test "pkcs11: session sign workflow" {
    var session = pkcs11.Pkcs11Session.init(1, 0, .{
        .rw_session = true,
        .serial_session = true,
    });

    // Can't sign without login
    try testing.expectError(pkcs11.Pkcs11Error.UserNotLoggedIn, session.signInit(.rsa_pkcs, 42));

    // Login
    session.setLoggedIn(.user);
    try testing.expect(session.logged_in);

    // Initialize signing
    try session.signInit(.sha256_rsa_pkcs, 42);
    try testing.expect(session.sign_active);
    try testing.expectEqual(pkcs11.MechanismType.sha256_rsa_pkcs, session.sign_mechanism.?);
    try testing.expectEqual(@as(u64, 42), session.sign_key.?);

    // Can't init again while active
    try testing.expectError(pkcs11.Pkcs11Error.OperationActive, session.signInit(.rsa_pkcs, 42));

    // Finalize
    try session.signFinalize();
    try testing.expect(!session.sign_active);
    try testing.expect(session.sign_mechanism == null);

    // Can't finalize without init
    try testing.expectError(pkcs11.Pkcs11Error.OperationNotInitialized, session.signFinalize());
}

test "pkcs11: session cancel" {
    var session = pkcs11.Pkcs11Session.init(2, 1, .{
        .rw_session = false,
        .serial_session = true,
    });

    session.setLoggedIn(.user);
    try session.signInit(.ecdsa, 99);
    try testing.expect(session.sign_active);

    session.signCancel();
    try testing.expect(!session.sign_active);

    // Can init again after cancel
    try session.signInit(.ecdsa, 100);
    try testing.expect(session.sign_active);
    try session.signFinalize();
}

test "pkcs11: mock token full workflow" {
    const allocator = testing.allocator;

    var mock = pkcs11.MockToken.init();
    var provider = mock.provider();

    // Provider should be ready
    try testing.expect(provider.isReady());

    // Get token info
    const info = try provider.getTokenInfo();
    try testing.expectEqualStrings("Mock Token", info.labelStr());

    // Login with wrong PIN
    try testing.expectError(pkcs11.Pkcs11Error.PinIncorrect, provider.login(.user, "wrong_pin"));

    // Login with correct PIN
    try provider.login(.user, "1234");

    // Sign with RSA mechanism
    const rsa_sig = try provider.sign(allocator, &.{ 0x01, 0x02 }, .rsa_pkcs, "test document");
    defer allocator.free(rsa_sig);
    try testing.expectEqual(@as(usize, 256), rsa_sig.len);

    // Sign with ECDSA mechanism
    const ec_sig = try provider.sign(allocator, &.{0x03}, .ecdsa, "test document");
    defer allocator.free(ec_sig);
    try testing.expectEqual(@as(usize, 64), ec_sig.len);

    // Verify sign count
    try testing.expectEqual(@as(u32, 2), mock.sign_count);

    // Logout
    try provider.logout();

    // Double logout
    try testing.expectError(pkcs11.Pkcs11Error.UserNotLoggedIn, provider.logout());
}

test "pkcs11: mock token disconnected state" {
    var mock = pkcs11.MockToken.init();
    mock.connected = false;
    const provider = mock.provider();

    try testing.expect(!provider.isReady());
    try testing.expectError(pkcs11.Pkcs11Error.DeviceRemoved, provider.login(.user, "1234"));
    try testing.expectError(pkcs11.Pkcs11Error.DeviceRemoved, provider.getTokenInfo());
}

test "pkcs11: mock token list keys" {
    const allocator = testing.allocator;

    const test_keys = [_]pkcs11.KeyObject{
        pkcs11.makeTestKey(1, .private_key, .rsa, &.{ 0xAA, 0xBB }, "RSA-2048 Sign"),
        pkcs11.makeTestKey(2, .public_key, .rsa, &.{ 0xAA, 0xBB }, "RSA-2048 Verify"),
        pkcs11.makeTestKey(3, .private_key, .ec, &.{ 0xCC, 0xDD }, "ECDSA-P256 Sign"),
    };

    var mock = pkcs11.MockToken.init();
    mock.keys = &test_keys;
    const provider = mock.provider();

    const keys = try provider.listKeys(allocator);
    defer allocator.free(keys);

    try testing.expectEqual(@as(usize, 3), keys.len);

    // Check key properties
    try testing.expectEqualStrings("RSA-2048 Sign", keys[0].labelStr());
    try testing.expect(keys[0].can_sign);
    try testing.expectEqual(pkcs11.KeyType.rsa, keys[0].key_type);
    try testing.expectEqual(@as(u32, 2048), keys[0].key_size_bits);

    try testing.expectEqualStrings("RSA-2048 Verify", keys[1].labelStr());
    try testing.expect(!keys[1].can_sign);
    try testing.expect(keys[1].can_verify);

    try testing.expectEqualStrings("ECDSA-P256 Sign", keys[2].labelStr());
    try testing.expectEqual(pkcs11.KeyType.ec, keys[2].key_type);
    try testing.expectEqual(@as(u32, 256), keys[2].key_size_bits);
}

test "pkcs11: key object ID matching" {
    const key1 = pkcs11.makeTestKey(1, .private_key, .rsa, &.{ 0x01, 0x02, 0x03 }, "Key1");
    const key2 = pkcs11.makeTestKey(2, .private_key, .rsa, &.{ 0x01, 0x02, 0x03 }, "Key2");
    const key3 = pkcs11.makeTestKey(3, .private_key, .rsa, &.{ 0x04, 0x05 }, "Key3");

    // Keys with same ID should match
    try testing.expectEqualSlices(u8, key1.keyId(), key2.keyId());

    // Keys with different IDs should not match
    try testing.expect(!mem.eql(u8, key1.keyId(), key3.keyId()));
}

test "pkcs11: slot with token info" {
    var desc: [64]u8 = .{' '} ** 64;
    @memcpy(desc[0..12], "YubiKey 5 NF");
    var mfr: [32]u8 = .{' '} ** 32;
    @memcpy(mfr[0..6], "Yubico");

    var token_label: [32]u8 = .{' '} ** 32;
    @memcpy(token_label[0..13], "OpenPGP card ");
    var token_mfr: [32]u8 = .{' '} ** 32;
    @memcpy(token_mfr[0..10], "Yubico Inc");
    var token_model: [16]u8 = .{' '} ** 16;
    @memcpy(token_model[0..8], "YubiKey ");
    var token_serial: [16]u8 = .{' '} ** 16;
    @memcpy(token_serial[0..8], "12345678");

    const slot = pkcs11.Pkcs11Slot.init(0, .{
        .description = desc,
        .manufacturer_id = mfr,
        .token_present = true,
        .removable_device = true,
        .hardware_slot = true,
        .flags = 0x07,
        .hw_version = .{ .major = 5, .minor = 0 },
        .fw_version = .{ .major = 5, .minor = 4 },
    }, .{
        .label = token_label,
        .manufacturer_id = token_mfr,
        .model = token_model,
        .serial_number = token_serial,
        .initialized = true,
        .user_pin_initialized = true,
        .login_required = true,
        .protected_auth_path = false,
        .flags = 0x01,
        .max_session_count = 1,
        .session_count = 0,
        .max_pin_len = 127,
        .min_pin_len = 6,
        .total_public_memory = 0,
        .free_public_memory = 0,
        .total_private_memory = 0,
        .free_private_memory = 0,
        .hw_version = .{ .major = 5, .minor = 0 },
        .fw_version = .{ .major = 5, .minor = 4 },
    });

    try testing.expect(slot.hasToken());
    try testing.expectEqualStrings("OpenPGP card", slot.tokenLabel().?);
    try testing.expectEqualStrings("12345678", slot.tokenSerial().?);
    try testing.expectEqualStrings("YubiKey 5 NF", slot.description());
}

test "pkcs11: mechanism info struct" {
    const info: pkcs11.MechanismInfo = .{
        .mechanism = .sha256_rsa_pkcs,
        .min_key_size = 2048,
        .max_key_size = 4096,
        .can_sign = true,
        .can_verify = true,
        .can_encrypt = false,
        .can_decrypt = false,
        .hardware = true,
    };

    try testing.expect(info.can_sign);
    try testing.expect(info.can_verify);
    try testing.expect(!info.can_encrypt);
    try testing.expect(info.hardware);
    try testing.expectEqual(@as(u32, 2048), info.min_key_size);
}

// ===========================================================================
// PCSC Bridge Tests
// ===========================================================================

test "pcsc: protocol names" {
    try testing.expectEqualStrings("T=0", pcsc_bridge.Protocol.t0.name());
    try testing.expectEqualStrings("T=1", pcsc_bridge.Protocol.t1.name());
    try testing.expectEqualStrings("Raw", pcsc_bridge.Protocol.raw.name());
}

test "pcsc: card state properties" {
    try testing.expect(!pcsc_bridge.CardState.absent.isPresent());
    try testing.expect(pcsc_bridge.CardState.present.isPresent());
    try testing.expect(pcsc_bridge.CardState.powered.isPresent());
    try testing.expect(pcsc_bridge.CardState.specific.isPresent());

    try testing.expect(!pcsc_bridge.CardState.absent.isReady());
    try testing.expect(!pcsc_bridge.CardState.present.isReady());
    try testing.expect(!pcsc_bridge.CardState.swallowed.isReady());
    try testing.expect(pcsc_bridge.CardState.powered.isReady());
    try testing.expect(pcsc_bridge.CardState.negotiable.isReady());
    try testing.expect(pcsc_bridge.CardState.specific.isReady());
}

test "pcsc: ATR parse minimal T=0" {
    const atr_data = [_]u8{ 0x3B, 0x00 };
    const atr = try pcsc_bridge.Atr.parse(&atr_data);

    try testing.expect(atr.direct_convention);
    try testing.expectEqual(@as(u4, 0), atr.historical_len);
    try testing.expect(atr.supports_t0);
    try testing.expect(!atr.supports_t1);
    try testing.expectEqual(pcsc_bridge.Protocol.t0, atr.preferredProtocol());
    try testing.expectEqual(@as(u8, 2), atr.len);
}

test "pcsc: ATR parse with historical bytes" {
    const atr_data = [_]u8{ 0x3B, 0x04, 'T', 'E', 'S', 'T' };
    const atr = try pcsc_bridge.Atr.parse(&atr_data);

    try testing.expectEqual(@as(u4, 4), atr.historical_len);
    try testing.expectEqualSlices(u8, "TEST", atr.historicalBytes());
}

test "pcsc: ATR parse with TA1" {
    // T0=0x10: TA1 present, 0 historical bytes
    // TA1=0x18: Fi=1, Di=8
    const atr_data = [_]u8{ 0x3B, 0x10, 0x18 };
    const atr = try pcsc_bridge.Atr.parse(&atr_data);

    try testing.expect(atr.fi_di != null);
    try testing.expectEqual(@as(u4, 1), atr.fi_di.?.fi);
    try testing.expectEqual(@as(u4, 8), atr.fi_di.?.di);
}

test "pcsc: ATR parse inverse convention" {
    const atr_data = [_]u8{ 0x3F, 0x00 };
    const atr = try pcsc_bridge.Atr.parse(&atr_data);
    try testing.expect(!atr.direct_convention);
}

test "pcsc: ATR parse errors" {
    // Too short
    try testing.expectError(pcsc_bridge.PcscError.InvalidAtr, pcsc_bridge.Atr.parse(&.{0x3B}));

    // Invalid TS byte
    try testing.expectError(pcsc_bridge.PcscError.InvalidAtr, pcsc_bridge.Atr.parse(&.{ 0x00, 0x00 }));
    try testing.expectError(pcsc_bridge.PcscError.InvalidAtr, pcsc_bridge.Atr.parse(&.{ 0xFF, 0x00 }));

    // Empty
    try testing.expectError(pcsc_bridge.PcscError.InvalidAtr, pcsc_bridge.Atr.parse(&.{}));
}

test "pcsc: ATR with T=1 protocol" {
    // T0=0x80 (TD1 present), TD1=0x01 (T=1), TCK=0x81
    const atr_data = [_]u8{ 0x3B, 0x80, 0x01, 0x81 };
    const atr = try pcsc_bridge.Atr.parse(&atr_data);

    try testing.expect(atr.supports_t1);
    try testing.expect(atr.protocols.t1);
    try testing.expectEqual(pcsc_bridge.Protocol.t1, atr.preferredProtocol());
}

test "pcsc: ATR OpenPGP card detection" {
    // ATR with 0x80 category indicator
    const openpgp_atr = [_]u8{ 0x3B, 0x01, 0x80 };
    const atr1 = try pcsc_bridge.Atr.parse(&openpgp_atr);
    try testing.expect(atr1.isOpenPgpCard());

    // Non-OpenPGP ATR
    const other_atr = [_]u8{ 0x3B, 0x02, 0x41, 0x42 };
    const atr2 = try pcsc_bridge.Atr.parse(&other_atr);
    try testing.expect(!atr2.isOpenPgpCard());
}

test "pcsc: LRC computation" {
    // XOR of all bytes
    const data = [_]u8{ 0x00, 0x40, 0x03, 0xAA, 0xBB, 0xCC };
    const lrc = pcsc_bridge.computeLrc(&data);
    var expected: u8 = 0;
    for (data) |b| expected ^= b;
    try testing.expectEqual(expected, lrc);

    // Empty data
    try testing.expectEqual(@as(u8, 0), pcsc_bridge.computeLrc(&.{}));
}

test "pcsc: CRC16 computation" {
    const data1 = [_]u8{ 0x01, 0x02, 0x03 };
    const crc1 = pcsc_bridge.computeCrc16(&data1);

    // Deterministic
    try testing.expectEqual(crc1, pcsc_bridge.computeCrc16(&data1));

    // Different data gives different CRC
    const data2 = [_]u8{ 0x01, 0x02, 0x04 };
    try testing.expect(crc1 != pcsc_bridge.computeCrc16(&data2));
}

test "pcsc: T0 framing Case 1" {
    const allocator = testing.allocator;

    const cmd = openpgp_card.ApduCommand{
        .cla = 0x00,
        .ins = 0xE6,
        .p1 = 0x00,
        .p2 = 0x00,
        .data = null,
        .le = null,
    };

    const framed = try pcsc_bridge.T0Framing.frameCommand(allocator, cmd);
    defer allocator.free(framed);

    try testing.expectEqual(@as(usize, 4), framed.len);
    try testing.expectEqual(@as(u8, 0x00), framed[0]);
    try testing.expectEqual(@as(u8, 0xE6), framed[1]);
}

test "pcsc: T0 framing Case 2" {
    const allocator = testing.allocator;

    const cmd = openpgp_card.ApduCommand{
        .cla = 0x00,
        .ins = 0xCA,
        .p1 = 0x00,
        .p2 = 0x6E,
        .data = null,
        .le = 256,
    };

    const framed = try pcsc_bridge.T0Framing.frameCommand(allocator, cmd);
    defer allocator.free(framed);

    try testing.expectEqual(@as(usize, 5), framed.len);
    try testing.expectEqual(@as(u8, 0x00), framed[4]); // Le=256 encoded as 0x00
}

test "pcsc: T0 framing Case 3" {
    const allocator = testing.allocator;

    const pin = [_]u8{ '1', '2', '3', '4', '5', '6' };
    const cmd = openpgp_card.ApduCommand{
        .cla = 0x00,
        .ins = 0x20,
        .p1 = 0x00,
        .p2 = 0x81,
        .data = &pin,
        .le = null,
    };

    const framed = try pcsc_bridge.T0Framing.frameCommand(allocator, cmd);
    defer allocator.free(framed);

    try testing.expectEqual(@as(usize, 11), framed.len);
    try testing.expectEqual(@as(u8, 6), framed[4]); // Lc
    try testing.expectEqual(@as(u8, '1'), framed[5]);
    try testing.expectEqual(@as(u8, '6'), framed[10]);
}

test "pcsc: T0 APDU case detection" {
    try testing.expectEqual(@as(u8, 1), pcsc_bridge.T0Framing.apduCase(.{
        .cla = 0, .ins = 0, .p1 = 0, .p2 = 0, .data = null, .le = null,
    }));
    try testing.expectEqual(@as(u8, 2), pcsc_bridge.T0Framing.apduCase(.{
        .cla = 0, .ins = 0, .p1 = 0, .p2 = 0, .data = null, .le = 256,
    }));
    try testing.expectEqual(@as(u8, 3), pcsc_bridge.T0Framing.apduCase(.{
        .cla = 0, .ins = 0, .p1 = 0, .p2 = 0, .data = "data", .le = null,
    }));
    try testing.expectEqual(@as(u8, 4), pcsc_bridge.T0Framing.apduCase(.{
        .cla = 0, .ins = 0, .p1 = 0, .p2 = 0, .data = "data", .le = 256,
    }));
}

test "pcsc: T1 framing I-block build and parse" {
    const allocator = testing.allocator;

    var framing = pcsc_bridge.T1Framing.init();
    const block = try framing.buildIBlock(allocator, "Hello", false);
    defer allocator.free(block);

    // NAD + PCB + LEN + "Hello" + LRC = 3 + 5 + 1 = 9
    try testing.expectEqual(@as(usize, 9), block.len);
    try testing.expectEqual(@as(u8, 0x00), block[0]); // NAD
    try testing.expectEqual(@as(u8, 5), block[2]); // LEN

    // Parse it back
    const framing2 = pcsc_bridge.T1Framing.init();
    const parsed = try framing2.parseBlock(block);
    try testing.expectEqual(pcsc_bridge.T1BlockType.i_block, parsed.block_type);
    try testing.expectEqualStrings("Hello", parsed.inf);
    try testing.expect(!parsed.more_data);
}

test "pcsc: T1 framing chaining" {
    const allocator = testing.allocator;

    var framing = pcsc_bridge.T1Framing.init();

    // First block with more-data flag
    const block1 = try framing.buildIBlock(allocator, "part1", true);
    defer allocator.free(block1);
    try testing.expect((block1[1] & 0x20) != 0); // more-data bit

    // Second block without more-data
    const block2 = try framing.buildIBlock(allocator, "part2", false);
    defer allocator.free(block2);
    try testing.expect((block2[1] & 0x20) == 0);
}

test "pcsc: T1 sequence number alternation" {
    const allocator = testing.allocator;
    var framing = pcsc_bridge.T1Framing.init();

    try testing.expectEqual(@as(u1, 0), framing.send_seq);

    const b1 = try framing.buildIBlock(allocator, "a", false);
    defer allocator.free(b1);
    try testing.expectEqual(@as(u1, 1), framing.send_seq);

    const b2 = try framing.buildIBlock(allocator, "b", false);
    defer allocator.free(b2);
    try testing.expectEqual(@as(u1, 0), framing.send_seq);
}

test "pcsc: T1 R-block" {
    const allocator = testing.allocator;
    const framing = pcsc_bridge.T1Framing.init();

    const block = try framing.buildRBlock(allocator, 0, 0);
    defer allocator.free(block);

    try testing.expect((block[1] & 0x80) != 0); // R-block bit
    try testing.expectEqual(@as(u8, 0), block[2]); // No INF
}

test "pcsc: T1 S-block WTX" {
    const allocator = testing.allocator;
    const framing = pcsc_bridge.T1Framing.init();

    const block = try framing.buildSBlock(allocator, true, .wtx, &.{0x05});
    defer allocator.free(block);

    try testing.expect((block[1] & 0xC0) == 0xC0); // S-block marker
    try testing.expectEqual(@as(u8, 1), block[2]); // LEN=1
    try testing.expectEqual(@as(u8, 0x05), block[3]); // WTX multiplier
}

test "pcsc: context lifecycle" {
    const allocator = testing.allocator;

    var ctx = pcsc_bridge.PcscContext.init();
    defer ctx.release(allocator);

    try testing.expect(!ctx.isEstablished());
    try ctx.establish();
    try testing.expect(ctx.isEstablished());
    try testing.expectEqual(@as(usize, 0), ctx.readerCount());
}

test "pcsc: context reader management" {
    const allocator = testing.allocator;

    var ctx = pcsc_bridge.PcscContext.init();
    defer ctx.release(allocator);

    try ctx.establish();

    const name1 = try allocator.dupe(u8, "Gemalto USB Reader");
    try ctx.addReader(allocator, .{
        .name = name1,
        .card_present = true,
        .state = .specific,
        .atr = null,
    });

    const name2 = try allocator.dupe(u8, "ACR122U");
    try ctx.addReader(allocator, .{
        .name = name2,
        .card_present = false,
        .state = .absent,
        .atr = null,
    });

    try testing.expectEqual(@as(usize, 2), ctx.readerCount());

    // Find by name
    const found = ctx.findReader("Gemalto USB Reader");
    try testing.expect(found != null);
    try testing.expect(found.?.card_present);

    const not_found = ctx.findReader("Nonexistent");
    try testing.expect(not_found == null);

    // Find with cards
    const with_cards = try ctx.findReadersWithCards(allocator);
    defer allocator.free(with_cards);
    try testing.expectEqual(@as(usize, 1), with_cards.len);
    try testing.expectEqualStrings("Gemalto USB Reader", with_cards[0].name);
}

test "pcsc: mock reader connect and transmit" {
    const allocator = testing.allocator;

    var mock = pcsc_bridge.MockPcscReader.init("Test Reader 0", &.{ 0x3B, 0x00 });
    defer mock.deinit(allocator);

    var rdr = mock.reader();

    // Check initial state
    try testing.expectEqualStrings("Test Reader 0", rdr.getName());
    try testing.expect(rdr.isCardPresent());
    try testing.expectEqual(pcsc_bridge.CardState.present, rdr.getState());

    // Connect
    try rdr.connect(allocator, .shared, .t1);
    try testing.expectEqual(pcsc_bridge.CardState.specific, rdr.getState());

    // Transmit default response
    const resp = try rdr.transmit(allocator, &.{ 0x00, 0xCA, 0x00, 0x6E, 0x00 });
    defer allocator.free(resp);
    try testing.expectEqualSlices(u8, &.{ 0x90, 0x00 }, resp);

    // ATR
    const atr = try rdr.getAtr(allocator);
    defer allocator.free(atr);
    try testing.expectEqualSlices(u8, &.{ 0x3B, 0x00 }, atr);

    // Disconnect
    try rdr.disconnect(.leave);
    try testing.expectEqual(pcsc_bridge.CardState.present, rdr.getState());
}

test "pcsc: mock reader custom response" {
    const allocator = testing.allocator;

    var mock = pcsc_bridge.MockPcscReader.init("Card Reader", &.{ 0x3B, 0x00 });
    defer mock.deinit(allocator);

    // Configure response for SELECT OpenPGP
    try mock.addResponse(allocator, &.{ 0x00, 0xA4, 0x04, 0x00 }, &.{ 0x90, 0x00 });
    // Configure response for GET DATA
    try mock.addResponse(allocator, &.{ 0x00, 0xCA }, &.{ 0x01, 0x02, 0x03, 0x90, 0x00 });

    var rdr = mock.reader();
    try rdr.connect(allocator, .shared, .t1);

    // SELECT
    const sel_resp = try rdr.transmit(allocator, &.{ 0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01 });
    defer allocator.free(sel_resp);
    try testing.expectEqualSlices(u8, &.{ 0x90, 0x00 }, sel_resp);

    // GET DATA
    const data_resp = try rdr.transmit(allocator, &.{ 0x00, 0xCA, 0x00, 0x6E, 0x00 });
    defer allocator.free(data_resp);
    try testing.expectEqual(@as(usize, 5), data_resp.len);
    try testing.expectEqual(@as(u8, 0x90), data_resp[3]);

    try rdr.disconnect(.leave);
}

test "pcsc: mock reader no card" {
    const allocator = testing.allocator;

    var mock = pcsc_bridge.MockPcscReader.init("Empty", &.{});
    defer mock.deinit(allocator);
    mock.card_present = false;

    var rdr = mock.reader();
    try testing.expect(!rdr.isCardPresent());
    try testing.expectError(pcsc_bridge.PcscError.ConnectionFailed, rdr.connect(allocator, .shared, .t1));
    try testing.expectError(pcsc_bridge.PcscError.CardRemoved, rdr.getAtr(allocator));
}

test "pcsc: mock reader transmit without connect" {
    const allocator = testing.allocator;

    var mock = pcsc_bridge.MockPcscReader.init("Test", &.{ 0x3B, 0x00 });
    defer mock.deinit(allocator);
    const rdr = mock.reader();

    try testing.expectError(pcsc_bridge.PcscError.TransmitFailed, rdr.transmit(allocator, &.{ 0x00, 0xCA }));
}
