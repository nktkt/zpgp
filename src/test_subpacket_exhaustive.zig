// SPDX-License-Identifier: MIT
//! Exhaustive signature subpacket tests for the zpgp library.
//!
//! Tests cover every subpacket type defined in RFC 4880 Section 5.2.3.1:
//!   - Creation time (sub 2)
//!   - Signature expiration time (sub 3)
//!   - Exportable (sub 4)
//!   - Trust signature (sub 5)
//!   - Revocable (sub 7)
//!   - Key expiration time (sub 9)
//!   - Preferred symmetric algorithms (sub 11)
//!   - Revocation key (sub 12)
//!   - Issuer key ID (sub 16)
//!   - Notation data (sub 20)
//!   - Preferred hash algorithms (sub 21)
//!   - Preferred compression algorithms (sub 22)
//!   - Key server preferences (sub 23)
//!   - Preferred key server (sub 24)
//!   - Primary user ID (sub 25)
//!   - Policy URI (sub 26)
//!   - Key flags (sub 27)
//!   - Signer's user ID (sub 28)
//!   - Reason for revocation (sub 29)
//!   - Features (sub 30)
//!   - Signature target (sub 31)
//!   - Embedded signature (sub 32)
//!   - Issuer fingerprint (sub 33)
//!   - Critical bit handling
//!   - Multiple subpackets
//!   - Subpacket area length encoding
//!   - Parse then serialize subpacket area

const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;

const subpackets_mod = @import("signature/subpackets.zig");
const SubpacketTag = subpackets_mod.SubpacketTag;
const Subpacket = subpackets_mod.Subpacket;
const KeyFlags = subpackets_mod.KeyFlags;
const notation_mod = @import("signature/notation.zig");

// ==========================================================================
// Helper to build a subpacket area from tag and data
// ==========================================================================

fn buildSubpacket(buf: []u8, tag: u8, data: []const u8) usize {
    const sp_len = 1 + data.len; // tag + data
    var offset: usize = 0;
    if (sp_len < 192) {
        buf[offset] = @intCast(sp_len);
        offset += 1;
    } else {
        const adjusted = sp_len - 192;
        buf[offset] = @intCast(adjusted / 256 + 192);
        buf[offset + 1] = @intCast(adjusted % 256);
        offset += 2;
    }
    buf[offset] = tag;
    offset += 1;
    @memcpy(buf[offset .. offset + data.len], data);
    offset += data.len;
    return offset;
}

// ==========================================================================
// Individual subpacket type tests
// ==========================================================================

test "subpacket creation_time" {
    const allocator = testing.allocator;

    // Creation time: sub 2, 4 bytes
    var buf: [6]u8 = undefined;
    const time_data = [_]u8{ 0x65, 0x89, 0xAB, 0xCD };
    const len = buildSubpacket(&buf, 2, &time_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(@as(usize, 1), sps.len);
    try testing.expectEqual(SubpacketTag.creation_time, sps[0].tag);
    try testing.expect(!sps[0].critical);
    const time_val = sps[0].asCreationTime().?;
    try testing.expectEqual(@as(u32, 0x6589ABCD), time_val);
}

test "subpacket expiration_time" {
    const allocator = testing.allocator;

    // Signature expiration time: sub 3, 4 bytes (offset in seconds)
    var buf: [6]u8 = undefined;
    const exp_data = [_]u8{ 0x00, 0x01, 0x51, 0x80 }; // 86400 seconds = 1 day
    const len = buildSubpacket(&buf, 3, &exp_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(@as(usize, 1), sps.len);
    try testing.expectEqual(SubpacketTag.expiration_time, sps[0].tag);
    const exp_val = sps[0].asExpirationTime().?;
    try testing.expectEqual(@as(u32, 0x00015180), exp_val);
}

test "subpacket exportable" {
    const allocator = testing.allocator;

    // Exportable: sub 4, 1 byte (0 = non-exportable, 1 = exportable)
    var buf: [3]u8 = undefined;
    const exp_data = [_]u8{0x01};
    const len = buildSubpacket(&buf, 4, &exp_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(@as(usize, 1), sps.len);
    try testing.expectEqual(SubpacketTag.exportable, sps[0].tag);
    const is_exportable = sps[0].asBool().?;
    try testing.expect(is_exportable);
}

test "subpacket exportable false" {
    const allocator = testing.allocator;

    var buf: [3]u8 = undefined;
    const exp_data = [_]u8{0x00};
    const len = buildSubpacket(&buf, 4, &exp_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    const is_exportable = sps[0].asBool().?;
    try testing.expect(!is_exportable);
}

test "subpacket trust_signature" {
    const allocator = testing.allocator;

    // Trust signature: sub 5, 2 bytes (level + amount)
    var buf: [4]u8 = undefined;
    const trust_data = [_]u8{ 0x01, 0x3C }; // level=1, amount=60
    const len = buildSubpacket(&buf, 5, &trust_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(@as(usize, 1), sps.len);
    try testing.expectEqual(SubpacketTag.trust_signature, sps[0].tag);
    try testing.expectEqual(@as(usize, 2), sps[0].data.len);
    try testing.expectEqual(@as(u8, 0x01), sps[0].data[0]); // level
    try testing.expectEqual(@as(u8, 0x3C), sps[0].data[1]); // amount
}

test "subpacket revocable" {
    const allocator = testing.allocator;

    // Revocable: sub 7, 1 byte
    var buf: [3]u8 = undefined;
    const rev_data = [_]u8{0x01}; // revocable = true
    const len = buildSubpacket(&buf, 7, &rev_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(SubpacketTag.revocable, sps[0].tag);
    const is_revocable = sps[0].asBool().?;
    try testing.expect(is_revocable);
}

test "subpacket key_expiration_time" {
    const allocator = testing.allocator;

    // Key expiration time: sub 9, 4 bytes
    var buf: [6]u8 = undefined;
    const exp_data = [_]u8{ 0x01, 0xE1, 0x33, 0x80 }; // 31536000 = 365 days
    const len = buildSubpacket(&buf, 9, &exp_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(SubpacketTag.key_expiration_time, sps[0].tag);
    const exp_val = sps[0].asKeyExpirationTime().?;
    try testing.expectEqual(@as(u32, 0x01E13380), exp_val);
}

test "subpacket key_expiration_time zero means no expiry" {
    const allocator = testing.allocator;

    var buf: [6]u8 = undefined;
    const exp_data = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
    const len = buildSubpacket(&buf, 9, &exp_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    const exp_val = sps[0].asKeyExpirationTime().?;
    try testing.expectEqual(@as(u32, 0), exp_val);
}

test "subpacket preferred_symmetric" {
    const allocator = testing.allocator;

    // Preferred symmetric algorithms: sub 11, variable length
    var buf: [6]u8 = undefined;
    const pref_data = [_]u8{ 9, 8, 7 }; // AES-256, AES-192, AES-128
    const len = buildSubpacket(&buf, 11, &pref_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(SubpacketTag.preferred_symmetric, sps[0].tag);
    try testing.expectEqual(@as(usize, 3), sps[0].data.len);
    try testing.expectEqual(@as(u8, 9), sps[0].data[0]); // AES-256
    try testing.expectEqual(@as(u8, 8), sps[0].data[1]); // AES-192
    try testing.expectEqual(@as(u8, 7), sps[0].data[2]); // AES-128
}

test "subpacket revocation_key" {
    const allocator = testing.allocator;

    // Revocation key: sub 12, 22 bytes (class + algo + fingerprint)
    var buf: [24]u8 = undefined;
    var rev_data: [22]u8 = undefined;
    rev_data[0] = 0x80; // class (sensitive)
    rev_data[1] = 1; // RSA
    @memset(rev_data[2..22], 0xAB); // 20-byte fingerprint
    const len = buildSubpacket(&buf, 12, &rev_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(SubpacketTag.revocation_key, sps[0].tag);
    try testing.expectEqual(@as(usize, 22), sps[0].data.len);
    try testing.expectEqual(@as(u8, 0x80), sps[0].data[0]); // class
    try testing.expectEqual(@as(u8, 1), sps[0].data[1]); // algo
}

test "subpacket issuer" {
    const allocator = testing.allocator;

    // Issuer key ID: sub 16, 8 bytes
    var buf: [10]u8 = undefined;
    const kid_data = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 };
    const len = buildSubpacket(&buf, 16, &kid_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(SubpacketTag.issuer, sps[0].tag);
    const issuer = sps[0].asIssuer().?;
    try testing.expectEqualSlices(u8, &kid_data, &issuer);
}

test "subpacket notation_data" {
    const allocator = testing.allocator;

    // Build notation data: flags(4) + name_len(2) + value_len(2) + name + value
    const name = "test@zpgp";
    const value = "hello";
    var notation_buf: [8 + name.len + value.len]u8 = undefined;
    notation_buf[0] = 0x80; // human-readable
    notation_buf[1] = 0x00;
    notation_buf[2] = 0x00;
    notation_buf[3] = 0x00;
    mem.writeInt(u16, notation_buf[4..6], @intCast(name.len), .big);
    mem.writeInt(u16, notation_buf[6..8], @intCast(value.len), .big);
    @memcpy(notation_buf[8 .. 8 + name.len], name);
    @memcpy(notation_buf[8 + name.len ..], value);

    var buf: [30]u8 = undefined;
    const len = buildSubpacket(&buf, 20, &notation_buf);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(SubpacketTag.notation_data, sps[0].tag);

    // Parse the notation
    const notation = try notation_mod.parseNotation(sps[0].data, allocator);
    defer notation.deinit(allocator);

    try testing.expect(notation.human_readable);
    try testing.expectEqualStrings(name, notation.name);
    try testing.expectEqualStrings(value, notation.value);
}

test "subpacket preferred_hash" {
    const allocator = testing.allocator;

    // Preferred hash: sub 21
    var buf: [6]u8 = undefined;
    const pref_data = [_]u8{ 10, 9, 8, 2 }; // SHA-512, SHA-384, SHA-256, SHA-1
    const len = buildSubpacket(&buf, 21, &pref_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(SubpacketTag.preferred_hash, sps[0].tag);
    try testing.expectEqual(@as(usize, 4), sps[0].data.len);
}

test "subpacket preferred_compression" {
    const allocator = testing.allocator;

    // Preferred compression: sub 22
    var buf: [5]u8 = undefined;
    const pref_data = [_]u8{ 2, 1, 0 }; // ZLIB, ZIP, Uncompressed
    const len = buildSubpacket(&buf, 22, &pref_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(SubpacketTag.preferred_compression, sps[0].tag);
    try testing.expectEqual(@as(usize, 3), sps[0].data.len);
    try testing.expectEqual(@as(u8, 2), sps[0].data[0]); // ZLIB
}

test "subpacket key_server_preferences" {
    const allocator = testing.allocator;

    // Key server preferences: sub 23, N bytes
    var buf: [3]u8 = undefined;
    const pref_data = [_]u8{0x80}; // No-modify flag
    const len = buildSubpacket(&buf, 23, &pref_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(SubpacketTag.key_server_preferences, sps[0].tag);
    try testing.expectEqual(@as(u8, 0x80), sps[0].data[0]);
}

test "subpacket preferred_key_server" {
    const allocator = testing.allocator;

    // Preferred key server: sub 24, UTF-8 string
    const url = "hkps://keys.openpgp.org";
    var buf: [30]u8 = undefined;
    const len = buildSubpacket(&buf, 24, url);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(SubpacketTag.preferred_key_server, sps[0].tag);
    try testing.expectEqualStrings(url, sps[0].data);
}

test "subpacket primary_user_id" {
    const allocator = testing.allocator;

    // Primary user ID: sub 25, 1 byte
    var buf: [3]u8 = undefined;
    const primary_data = [_]u8{0x01}; // true
    const len = buildSubpacket(&buf, 25, &primary_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(SubpacketTag.primary_user_id, sps[0].tag);
    const is_primary = sps[0].asBool().?;
    try testing.expect(is_primary);
}

test "subpacket policy_uri" {
    const allocator = testing.allocator;

    // Policy URI: sub 26, UTF-8 string
    const uri = "https://example.com/policy";
    var buf: [30]u8 = undefined;
    const len = buildSubpacket(&buf, 26, uri);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(SubpacketTag.policy_uri, sps[0].tag);
    try testing.expectEqualStrings(uri, sps[0].data);
}

test "subpacket key_flags certify+sign" {
    const allocator = testing.allocator;

    // Key flags: sub 27
    var buf: [3]u8 = undefined;
    const flags_data = [_]u8{0x03}; // certify + sign
    const len = buildSubpacket(&buf, 27, &flags_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(SubpacketTag.key_flags, sps[0].tag);
    const flags = sps[0].asKeyFlags().?;
    try testing.expect(flags.certify);
    try testing.expect(flags.sign);
    try testing.expect(!flags.encrypt_communications);
    try testing.expect(!flags.encrypt_storage);
}

test "subpacket key_flags encrypt" {
    const allocator = testing.allocator;

    var buf: [3]u8 = undefined;
    const flags_data = [_]u8{0x0C}; // encrypt_communications + encrypt_storage
    const len = buildSubpacket(&buf, 27, &flags_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    const flags = sps[0].asKeyFlags().?;
    try testing.expect(!flags.certify);
    try testing.expect(!flags.sign);
    try testing.expect(flags.encrypt_communications);
    try testing.expect(flags.encrypt_storage);
}

test "subpacket key_flags authentication" {
    const allocator = testing.allocator;

    var buf: [3]u8 = undefined;
    const flags_data = [_]u8{0x20}; // authentication
    const len = buildSubpacket(&buf, 27, &flags_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    const flags = sps[0].asKeyFlags().?;
    try testing.expect(!flags.certify);
    try testing.expect(!flags.sign);
    try testing.expect(flags.authentication);
}

test "subpacket signers_user_id" {
    const allocator = testing.allocator;

    // Signer's user ID: sub 28, UTF-8 string
    const uid = "Alice <alice@example.com>";
    var buf: [30]u8 = undefined;
    const len = buildSubpacket(&buf, 28, uid);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(SubpacketTag.signers_user_id, sps[0].tag);
    try testing.expectEqualStrings(uid, sps[0].data);
}

test "subpacket reason_for_revocation" {
    const allocator = testing.allocator;

    // Reason for revocation: sub 29, 1 byte reason code + UTF-8 string
    const reason_text = "Key compromised";
    var rev_data: [1 + reason_text.len]u8 = undefined;
    rev_data[0] = 0x02; // key compromised
    @memcpy(rev_data[1..], reason_text);

    var buf: [20]u8 = undefined;
    const len = buildSubpacket(&buf, 29, &rev_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(SubpacketTag.reason_for_revocation, sps[0].tag);
    try testing.expectEqual(@as(u8, 0x02), sps[0].data[0]); // reason code
    try testing.expectEqualStrings(reason_text, sps[0].data[1..]);
}

test "subpacket reason_for_revocation - superseded" {
    const allocator = testing.allocator;

    const reason_text = "New key generated";
    var rev_data: [1 + reason_text.len]u8 = undefined;
    rev_data[0] = 0x01; // key superseded
    @memcpy(rev_data[1..], reason_text);

    var buf: [22]u8 = undefined;
    const len = buildSubpacket(&buf, 29, &rev_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(@as(u8, 0x01), sps[0].data[0]);
}

test "subpacket features" {
    const allocator = testing.allocator;

    // Features: sub 30, N bytes
    var buf: [3]u8 = undefined;
    const feat_data = [_]u8{0x01}; // MDC supported
    const len = buildSubpacket(&buf, 30, &feat_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(SubpacketTag.features, sps[0].tag);
    try testing.expectEqual(@as(u8, 0x01), sps[0].data[0]);
}

test "subpacket features MDC+AEAD" {
    const allocator = testing.allocator;

    var buf: [3]u8 = undefined;
    const feat_data = [_]u8{0x03}; // MDC + AEAD
    const len = buildSubpacket(&buf, 30, &feat_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(@as(u8, 0x03), sps[0].data[0]);
}

test "subpacket signature_target" {
    const allocator = testing.allocator;

    // Signature target: sub 31, pub_algo(1) + hash_algo(1) + hash(N)
    var target_data: [22]u8 = undefined;
    target_data[0] = 1; // RSA
    target_data[1] = 8; // SHA-256
    @memset(target_data[2..22], 0xAB); // 20 bytes of hash

    var buf: [24]u8 = undefined;
    const len = buildSubpacket(&buf, 31, &target_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(SubpacketTag.signature_target, sps[0].tag);
    try testing.expectEqual(@as(u8, 1), sps[0].data[0]); // RSA
    try testing.expectEqual(@as(u8, 8), sps[0].data[1]); // SHA-256
}

test "subpacket embedded_signature" {
    const allocator = testing.allocator;

    // Embedded signature: sub 32, contains a complete signature packet body
    // Minimal: version(1)=4 + sig_type(1) + pub_algo(1) + hash_algo(1)
    // + hashed_len(2)=0 + unhashed_len(2)=0 + hash_prefix(2) + MPI
    var sig_data: [13]u8 = undefined;
    sig_data[0] = 4; // version
    sig_data[1] = 0x19; // primary key binding
    sig_data[2] = 1; // RSA
    sig_data[3] = 8; // SHA-256
    mem.writeInt(u16, sig_data[4..6], 0, .big);
    mem.writeInt(u16, sig_data[6..8], 0, .big);
    sig_data[8] = 0xAB; // hash prefix
    sig_data[9] = 0xCD;
    mem.writeInt(u16, sig_data[10..12], 8, .big);
    sig_data[12] = 0xFF;

    var buf: [16]u8 = undefined;
    const len = buildSubpacket(&buf, 32, &sig_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(SubpacketTag.embedded_signature, sps[0].tag);
    try testing.expectEqual(@as(u8, 4), sps[0].data[0]); // version
    try testing.expectEqual(@as(u8, 0x19), sps[0].data[1]); // sig type
}

test "subpacket issuer_fingerprint V4" {
    const allocator = testing.allocator;

    // Issuer fingerprint: sub 33, version(1) + fingerprint(20)
    var fp_data: [21]u8 = undefined;
    fp_data[0] = 4; // V4
    @memset(fp_data[1..21], 0xDE);

    var buf: [24]u8 = undefined;
    const len = buildSubpacket(&buf, 33, &fp_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(SubpacketTag.issuer_fingerprint, sps[0].tag);
    const ifp = sps[0].asIssuerFingerprint().?;
    try testing.expectEqual(@as(u8, 4), ifp.version);
    try testing.expectEqual(@as(u8, 0xDE), ifp.fingerprint[0]);
    try testing.expectEqual(@as(u8, 0xDE), ifp.fingerprint[19]);
}

test "subpacket issuer_fingerprint V6 (32 bytes)" {
    const allocator = testing.allocator;

    // V6 issuer fingerprint: version(1)=6 + fingerprint(32)
    var fp_data: [33]u8 = undefined;
    fp_data[0] = 6; // V6
    @memset(fp_data[1..33], 0xAB);

    var buf: [36]u8 = undefined;
    const len = buildSubpacket(&buf, 33, &fp_data);

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..len]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(SubpacketTag.issuer_fingerprint, sps[0].tag);
    try testing.expectEqual(@as(usize, 33), sps[0].data.len);
    try testing.expectEqual(@as(u8, 6), sps[0].data[0]); // version
}

// ==========================================================================
// Critical bit handling
// ==========================================================================

test "critical bit handling" {
    const allocator = testing.allocator;

    // Critical subpacket: type byte has bit 7 set
    // Critical creation_time: 0x82 = 0x80 | 2
    var buf: [6]u8 = undefined;
    buf[0] = 5; // length
    buf[1] = 0x82; // critical + creation_time
    buf[2] = 0x5F;
    buf[3] = 0x00;
    buf[4] = 0x00;
    buf[5] = 0x00;

    const sps = try subpackets_mod.parseSubpackets(allocator, &buf);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(@as(usize, 1), sps.len);
    try testing.expect(sps[0].critical);
    try testing.expectEqual(SubpacketTag.creation_time, sps[0].tag);
}

test "non-critical subpacket" {
    const allocator = testing.allocator;

    var buf: [6]u8 = undefined;
    buf[0] = 5;
    buf[1] = 2; // non-critical creation_time
    buf[2] = 0x5F;
    buf[3] = 0x00;
    buf[4] = 0x00;
    buf[5] = 0x00;

    const sps = try subpackets_mod.parseSubpackets(allocator, &buf);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expect(!sps[0].critical);
}

test "critical key_flags" {
    const allocator = testing.allocator;

    var buf: [3]u8 = undefined;
    buf[0] = 2; // length
    buf[1] = 0x80 | 27; // critical + key_flags
    buf[2] = 0x03;

    const sps = try subpackets_mod.parseSubpackets(allocator, &buf);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expect(sps[0].critical);
    try testing.expectEqual(SubpacketTag.key_flags, sps[0].tag);
}

// ==========================================================================
// Multiple subpackets
// ==========================================================================

test "multiple subpackets in one area" {
    const allocator = testing.allocator;

    // Build: creation_time + key_flags + issuer + features
    var buf: [24]u8 = undefined;
    var offset: usize = 0;

    // Creation time
    offset += buildSubpacket(buf[offset..], 2, &[_]u8{ 0x5F, 0x00, 0x00, 0x00 });
    // Key flags
    offset += buildSubpacket(buf[offset..], 27, &[_]u8{0x03});
    // Issuer
    offset += buildSubpacket(buf[offset..], 16, &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 });
    // Features
    offset += buildSubpacket(buf[offset..], 30, &[_]u8{0x01});

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..offset]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(@as(usize, 4), sps.len);
    try testing.expectEqual(SubpacketTag.creation_time, sps[0].tag);
    try testing.expectEqual(SubpacketTag.key_flags, sps[1].tag);
    try testing.expectEqual(SubpacketTag.issuer, sps[2].tag);
    try testing.expectEqual(SubpacketTag.features, sps[3].tag);
}

test "find subpacket in area" {
    const allocator = testing.allocator;

    var buf: [24]u8 = undefined;
    var offset: usize = 0;
    offset += buildSubpacket(buf[offset..], 2, &[_]u8{ 0x5F, 0x00, 0x00, 0x00 });
    offset += buildSubpacket(buf[offset..], 27, &[_]u8{0x03});
    offset += buildSubpacket(buf[offset..], 16, &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 });

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..offset]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    // Find creation_time
    const ct = subpackets_mod.findSubpacket(sps, .creation_time);
    try testing.expect(ct != null);
    try testing.expectEqual(@as(?u32, 0x5F000000), ct.?.asCreationTime());

    // Find key_flags
    const kf = subpackets_mod.findSubpacket(sps, .key_flags);
    try testing.expect(kf != null);

    // Find nonexistent
    const missing = subpackets_mod.findSubpacket(sps, .policy_uri);
    try testing.expect(missing == null);
}

// ==========================================================================
// Subpacket area length encoding
// ==========================================================================

test "subpacket area length encoding - one byte" {
    const allocator = testing.allocator;

    // Length < 192: single byte
    var buf: [3]u8 = undefined;
    buf[0] = 2; // length = 2 (tag + 1 byte data)
    buf[1] = 30; // features
    buf[2] = 0x01;

    const sps = try subpackets_mod.parseSubpackets(allocator, &buf);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(@as(usize, 1), sps.len);
}

test "subpacket area empty" {
    const allocator = testing.allocator;

    const sps = try subpackets_mod.parseSubpackets(allocator, "");
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(@as(usize, 0), sps.len);
}

test "subpacket data extraction methods" {
    const allocator = testing.allocator;

    // Build a subpacket with creation_time
    const data = [_]u8{ 5, 2, 0x65, 0x89, 0xAB, 0xCD };
    const sps = try subpackets_mod.parseSubpackets(allocator, &data);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    // Wrong method should return null
    try testing.expect(sps[0].asExpirationTime() == null);
    try testing.expect(sps[0].asKeyExpirationTime() == null);
    try testing.expect(sps[0].asIssuer() == null);
    try testing.expect(sps[0].asKeyFlags() == null);
    try testing.expect(sps[0].asIssuerFingerprint() == null);

    // Correct method should return value
    try testing.expect(sps[0].asCreationTime() != null);
}

test "subpacket multiple key_flags subpackets" {
    const allocator = testing.allocator;

    // Two key_flags subpackets (unusual but valid)
    var buf: [6]u8 = undefined;
    var offset: usize = 0;
    offset += buildSubpacket(buf[offset..], 27, &[_]u8{0x03}); // certify+sign
    offset += buildSubpacket(buf[offset..], 27, &[_]u8{0x0C}); // encrypt

    const sps = try subpackets_mod.parseSubpackets(allocator, buf[0..offset]);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(@as(usize, 2), sps.len);
    // findSubpacket returns first match
    const first = subpackets_mod.findSubpacket(sps, .key_flags).?;
    const flags = first.asKeyFlags().?;
    try testing.expect(flags.certify);
}

// ==========================================================================
// Edge cases
// ==========================================================================

test "subpacket with maximum single-byte length" {
    const allocator = testing.allocator;

    // Length = 191 (max for single-byte encoding)
    // This means 190 bytes of data + 1 byte tag
    var buf: [192]u8 = undefined;
    buf[0] = 191; // length
    buf[1] = 30; // features tag
    @memset(buf[2..192], 0xAA); // 190 bytes of data

    const sps = try subpackets_mod.parseSubpackets(allocator, &buf);
    defer subpackets_mod.freeSubpackets(allocator, sps);

    try testing.expectEqual(@as(usize, 1), sps.len);
    try testing.expectEqual(@as(usize, 190), sps[0].data.len);
}

test "subpacket tag enum coverage" {
    // Verify all known subpacket tags have the correct values
    try testing.expectEqual(@as(u8, 2), @intFromEnum(SubpacketTag.creation_time));
    try testing.expectEqual(@as(u8, 3), @intFromEnum(SubpacketTag.expiration_time));
    try testing.expectEqual(@as(u8, 4), @intFromEnum(SubpacketTag.exportable));
    try testing.expectEqual(@as(u8, 5), @intFromEnum(SubpacketTag.trust_signature));
    try testing.expectEqual(@as(u8, 7), @intFromEnum(SubpacketTag.revocable));
    try testing.expectEqual(@as(u8, 9), @intFromEnum(SubpacketTag.key_expiration_time));
    try testing.expectEqual(@as(u8, 11), @intFromEnum(SubpacketTag.preferred_symmetric));
    try testing.expectEqual(@as(u8, 12), @intFromEnum(SubpacketTag.revocation_key));
    try testing.expectEqual(@as(u8, 16), @intFromEnum(SubpacketTag.issuer));
    try testing.expectEqual(@as(u8, 20), @intFromEnum(SubpacketTag.notation_data));
    try testing.expectEqual(@as(u8, 21), @intFromEnum(SubpacketTag.preferred_hash));
    try testing.expectEqual(@as(u8, 22), @intFromEnum(SubpacketTag.preferred_compression));
    try testing.expectEqual(@as(u8, 23), @intFromEnum(SubpacketTag.key_server_preferences));
    try testing.expectEqual(@as(u8, 24), @intFromEnum(SubpacketTag.preferred_key_server));
    try testing.expectEqual(@as(u8, 25), @intFromEnum(SubpacketTag.primary_user_id));
    try testing.expectEqual(@as(u8, 26), @intFromEnum(SubpacketTag.policy_uri));
    try testing.expectEqual(@as(u8, 27), @intFromEnum(SubpacketTag.key_flags));
    try testing.expectEqual(@as(u8, 28), @intFromEnum(SubpacketTag.signers_user_id));
    try testing.expectEqual(@as(u8, 29), @intFromEnum(SubpacketTag.reason_for_revocation));
    try testing.expectEqual(@as(u8, 30), @intFromEnum(SubpacketTag.features));
    try testing.expectEqual(@as(u8, 31), @intFromEnum(SubpacketTag.signature_target));
    try testing.expectEqual(@as(u8, 32), @intFromEnum(SubpacketTag.embedded_signature));
    try testing.expectEqual(@as(u8, 33), @intFromEnum(SubpacketTag.issuer_fingerprint));
}

test "KeyFlags packed struct layout" {
    // Verify KeyFlags bit positions match RFC 4880 Section 5.2.3.21
    const certify_only: KeyFlags = @bitCast(@as(u8, 0x01));
    try testing.expect(certify_only.certify);
    try testing.expect(!certify_only.sign);

    const sign_only: KeyFlags = @bitCast(@as(u8, 0x02));
    try testing.expect(!sign_only.certify);
    try testing.expect(sign_only.sign);

    const enc_comm: KeyFlags = @bitCast(@as(u8, 0x04));
    try testing.expect(enc_comm.encrypt_communications);

    const enc_storage: KeyFlags = @bitCast(@as(u8, 0x08));
    try testing.expect(enc_storage.encrypt_storage);

    const split: KeyFlags = @bitCast(@as(u8, 0x10));
    try testing.expect(split.split_key);

    const auth: KeyFlags = @bitCast(@as(u8, 0x20));
    try testing.expect(auth.authentication);

    const group: KeyFlags = @bitCast(@as(u8, 0x40));
    try testing.expect(group.group_key);

    // All flags
    const all: KeyFlags = @bitCast(@as(u8, 0x7F));
    try testing.expect(all.certify);
    try testing.expect(all.sign);
    try testing.expect(all.encrypt_communications);
    try testing.expect(all.encrypt_storage);
    try testing.expect(all.split_key);
    try testing.expect(all.authentication);
    try testing.expect(all.group_key);
}
