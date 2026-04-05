// SPDX-License-Identifier: MIT
//! Integration tests for the inspect module.
//!
//! Tests the packet_dump, key_analyzer, and message_analyzer modules
//! working together on realistic OpenPGP data structures.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

const packet_dump = @import("inspect/packet_dump.zig");
const key_analyzer = @import("inspect/key_analyzer.zig");
const message_analyzer = @import("inspect/message_analyzer.zig");
const header_mod = @import("packet/header.zig");
const PacketTag = @import("packet/tags.zig").PacketTag;

// ---------------------------------------------------------------------------
// Helper: build a minimal V4 RSA public key packet sequence
// ---------------------------------------------------------------------------

fn buildMinimalRsaKey(allocator: std.mem.Allocator, rsa_bits: u16, creation_time: u32) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    // Public key packet (tag 6, new format)
    try w.writeByte(0xC0 | 6);
    try w.writeByte(12); // body length
    try w.writeByte(4); // version
    try w.writeInt(u32, creation_time, .big);
    try w.writeByte(1); // RSA
    try w.writeInt(u16, rsa_bits, .big); // n bit count
    try w.writeAll(&[_]u8{ 0xFF, 0x00 }); // minimal n data
    try w.writeInt(u16, 17, .big); // e bit count = 17 (65537)
    // no e data needed for our minimal parse

    // User ID packet
    const uid = "Test User <test@example.com>";
    try w.writeByte(0xC0 | 13);
    try w.writeByte(@intCast(uid.len));
    try w.writeAll(uid);

    // Self-signature (v4, positive certification, RSA, SHA-256)
    // With creation_time and key_expiration_time subpackets
    const hashed_sp = buildSelfSigSubpackets(creation_time, 365 * 24 * 60 * 60);
    try w.writeByte(0xC0 | 2); // signature
    const sig_body_len: u8 = @intCast(4 + 2 + hashed_sp.len + 2 + 0 + 2); // v4 header + hashed + unhashed + prefix
    try w.writeByte(sig_body_len);
    try w.writeByte(4); // version
    try w.writeByte(0x13); // positive certification
    try w.writeByte(1); // RSA
    try w.writeByte(8); // SHA-256
    try w.writeInt(u16, @intCast(hashed_sp.len), .big);
    try w.writeAll(&hashed_sp);
    try w.writeInt(u16, 0, .big); // unhashed len
    try w.writeAll(&[_]u8{ 0xAB, 0xCD }); // hash prefix

    return buf.toOwnedSlice(allocator);
}

fn buildSelfSigSubpackets(creation_time: u32, expiry_offset: u32) [12]u8 {
    var sp: [12]u8 = undefined;
    // Subpacket 1: creation time (tag=2, 4 bytes)
    sp[0] = 5; // length (includes tag byte)
    sp[1] = 2; // creation_time
    mem.writeInt(u32, sp[2..6], creation_time, .big);
    // Subpacket 2: key expiration (tag=9, 4 bytes)
    sp[6] = 5;
    sp[7] = 9; // key_expiration_time
    mem.writeInt(u32, sp[8..12], expiry_offset, .big);
    return sp;
}

fn buildMinimalEdDsaKey(allocator: std.mem.Allocator, creation_time: u32) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    // Public key packet (tag 6) - EdDSA
    try w.writeByte(0xC0 | 6);
    try w.writeByte(8);
    try w.writeByte(4); // version
    try w.writeInt(u32, creation_time, .big);
    try w.writeByte(22); // EdDSA
    try w.writeByte(0x00); // padding
    try w.writeByte(0x00);

    // User ID
    const uid = "Ed User <ed@example.com>";
    try w.writeByte(0xC0 | 13);
    try w.writeByte(@intCast(uid.len));
    try w.writeAll(uid);

    // Self-signature with SHA-256
    try w.writeByte(0xC0 | 2);
    try w.writeByte(10);
    try w.writeAll(&[_]u8{ 4, 0x13, 22, 8, 0, 0, 0, 0, 0xAB, 0xCD });

    return buf.toOwnedSlice(allocator);
}

fn buildMinimalSignedMessage(allocator: std.mem.Allocator) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    // One-Pass Signature
    try w.writeByte(0xC0 | 4);
    try w.writeByte(13);
    try w.writeByte(3); // version
    try w.writeByte(0x00); // sig type: binary
    try w.writeByte(8); // SHA-256
    try w.writeByte(1); // RSA
    try w.writeAll(&[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 });
    try w.writeByte(1); // nested

    // Literal data
    try w.writeByte(0xCB); // tag 11
    try w.writeByte(12);
    try w.writeByte('t'); // text
    try w.writeByte(4); // name len
    try w.writeAll("test");
    try w.writeInt(u32, 1700000000, .big);
    try w.writeAll("Hi");

    // Signature
    try w.writeByte(0xC0 | 2);
    try w.writeByte(10);
    try w.writeAll(&[_]u8{ 4, 0x00, 1, 8, 0, 0, 0, 0, 0xEF, 0x01 });

    return buf.toOwnedSlice(allocator);
}

fn buildMinimalEncryptedMessage(allocator: std.mem.Allocator) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    // SKESK v4 (AES-256)
    try w.writeByte(0xC0 | 3);
    try w.writeByte(4);
    try w.writeByte(4); // version
    try w.writeByte(9); // AES-256
    try w.writeByte(0); // S2K
    try w.writeByte(0);

    // SEIPD v1
    try w.writeByte(0xC0 | 18);
    try w.writeByte(5);
    try w.writeByte(1); // version
    try w.writeAll(&[_]u8{ 0x00, 0x00, 0x00, 0x00 });

    return buf.toOwnedSlice(allocator);
}

fn buildAeadEncryptedMessage(allocator: std.mem.Allocator) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    // PKESK v3
    try w.writeByte(0xC0 | 1);
    try w.writeByte(11);
    try w.writeByte(3);
    try w.writeAll(&[_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 });
    try w.writeByte(25); // X25519
    try w.writeByte(0);

    // SEIPD v2 (AES-256 + GCM)
    try w.writeByte(0xC0 | 18);
    try w.writeByte(5);
    try w.writeByte(2); // version 2
    try w.writeByte(9); // AES-256
    try w.writeByte(3); // GCM
    try w.writeByte(0);
    try w.writeByte(0);

    return buf.toOwnedSlice(allocator);
}

fn buildKeyWithSubkeys(allocator: std.mem.Allocator) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    // Primary key (EdDSA signing)
    try w.writeByte(0xC0 | 6);
    try w.writeByte(8);
    try w.writeByte(4);
    try w.writeInt(u32, 1700000000, .big);
    try w.writeByte(22); // EdDSA
    try w.writeByte(0);
    try w.writeByte(0);

    // User ID
    try w.writeByte(0xC0 | 13);
    try w.writeByte(4);
    try w.writeAll("Test");

    // Self-sig
    try w.writeByte(0xC0 | 2);
    try w.writeByte(10);
    try w.writeAll(&[_]u8{ 4, 0x13, 22, 8, 0, 0, 0, 0, 0xAB, 0xCD });

    // Signing subkey (EdDSA)
    try w.writeByte(0xC0 | 14);
    try w.writeByte(8);
    try w.writeByte(4);
    try w.writeInt(u32, 1700000001, .big);
    try w.writeByte(22); // EdDSA
    try w.writeByte(0);
    try w.writeByte(0);

    // Binding sig
    try w.writeByte(0xC0 | 2);
    try w.writeByte(10);
    try w.writeAll(&[_]u8{ 4, 0x18, 22, 8, 0, 0, 0, 0, 0xEF, 0x01 });

    // Encryption subkey (ECDH)
    try w.writeByte(0xC0 | 14);
    try w.writeByte(8);
    try w.writeByte(4);
    try w.writeInt(u32, 1700000002, .big);
    try w.writeByte(18); // ECDH
    try w.writeByte(0);
    try w.writeByte(0);

    // Binding sig
    try w.writeByte(0xC0 | 2);
    try w.writeByte(10);
    try w.writeAll(&[_]u8{ 4, 0x18, 18, 8, 0, 0, 0, 0, 0x12, 0x34 });

    return buf.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Packet Dump Tests
// ---------------------------------------------------------------------------

test "inspectPackets on RSA key" {
    const allocator = testing.allocator;
    const key_data = try buildMinimalRsaKey(allocator, 2048, 1700000000);
    defer allocator.free(key_data);

    const packets = try packet_dump.inspectPackets(allocator, key_data);
    defer {
        for (packets) |p| p.deinit(allocator);
        allocator.free(packets);
    }

    try testing.expectEqual(@as(usize, 3), packets.len);
    try testing.expectEqual(PacketTag.public_key, packets[0].tag);
    try testing.expectEqual(PacketTag.user_id, packets[1].tag);
    try testing.expectEqual(PacketTag.signature, packets[2].tag);
}

test "inspectPackets on EdDSA key" {
    const allocator = testing.allocator;
    const key_data = try buildMinimalEdDsaKey(allocator, 1700000000);
    defer allocator.free(key_data);

    const packets = try packet_dump.inspectPackets(allocator, key_data);
    defer {
        for (packets) |p| p.deinit(allocator);
        allocator.free(packets);
    }

    try testing.expectEqual(@as(usize, 3), packets.len);
}

test "formatPacketDump output contains packet info" {
    const allocator = testing.allocator;
    const key_data = try buildMinimalRsaKey(allocator, 4096, 1700000000);
    defer allocator.free(key_data);

    const packets = try packet_dump.inspectPackets(allocator, key_data);
    defer {
        for (packets) |p| p.deinit(allocator);
        allocator.free(packets);
    }

    const dump = try packet_dump.formatPacketDump(allocator, packets);
    defer allocator.free(dump);

    try testing.expect(dump.len > 0);
    try testing.expect(mem.indexOf(u8, dump, "Public-Key") != null);
    try testing.expect(mem.indexOf(u8, dump, "User ID") != null);
    try testing.expect(mem.indexOf(u8, dump, "Signature") != null);
}

test "inspectKey returns correct key properties" {
    const allocator = testing.allocator;
    const key_data = try buildMinimalRsaKey(allocator, 4096, 1700000000);
    defer allocator.free(key_data);

    var ki = try packet_dump.inspectKey(allocator, key_data);
    defer ki.deinit(allocator);

    try testing.expectEqual(@as(u8, 4), ki.version);
    try testing.expectEqual(@as(u32, 4096), ki.bits.?);
    try testing.expectEqual(@as(u32, 1700000000), ki.creation_time);
    try testing.expect(!ki.is_secret);
    try testing.expect(!ki.is_revoked);
    try testing.expectEqual(@as(usize, 1), ki.user_ids.len);
    try testing.expect(mem.indexOf(u8, ki.user_ids[0], "test@example.com") != null);
}

test "inspectKey format produces readable output" {
    const allocator = testing.allocator;
    const key_data = try buildMinimalRsaKey(allocator, 2048, 1700000000);
    defer allocator.free(key_data);

    var ki = try packet_dump.inspectKey(allocator, key_data);
    defer ki.deinit(allocator);

    const formatted = try ki.format(allocator);
    defer allocator.free(formatted);

    try testing.expect(formatted.len > 0);
    try testing.expect(mem.indexOf(u8, formatted, "Version:") != null);
    try testing.expect(mem.indexOf(u8, formatted, "Algorithm:") != null);
}

test "inspectMessage on signed message" {
    const allocator = testing.allocator;
    const msg_data = try buildMinimalSignedMessage(allocator);
    defer allocator.free(msg_data);

    var mi = try packet_dump.inspectMessage(allocator, msg_data);
    defer mi.deinit(allocator);

    try testing.expect(mi.is_signed);
    try testing.expect(!mi.is_encrypted);
    try testing.expect(!mi.is_armored);
}

test "inspectMessage on encrypted message" {
    const allocator = testing.allocator;
    const msg_data = try buildMinimalEncryptedMessage(allocator);
    defer allocator.free(msg_data);

    var mi = try packet_dump.inspectMessage(allocator, msg_data);
    defer mi.deinit(allocator);

    try testing.expect(mi.is_encrypted);
    try testing.expect(!mi.is_signed);
    try testing.expectEqual(@as(?u8, 1), mi.seipd_version);
}

test "inspectMessage on AEAD encrypted message" {
    const allocator = testing.allocator;
    const msg_data = try buildAeadEncryptedMessage(allocator);
    defer allocator.free(msg_data);

    var mi = try packet_dump.inspectMessage(allocator, msg_data);
    defer mi.deinit(allocator);

    try testing.expect(mi.is_encrypted);
    try testing.expectEqual(@as(?u8, 2), mi.seipd_version);
    try testing.expect(mi.aead_algo != null);
    try testing.expect(mi.sym_algo != null);
    try testing.expectEqual(@as(usize, 1), mi.recipient_key_ids.len);
}

// ---------------------------------------------------------------------------
// Key Analyzer Tests
// ---------------------------------------------------------------------------

test "analyzeKey RSA 2048 scores fair" {
    const allocator = testing.allocator;
    const key_data = try buildMinimalRsaKey(allocator, 2048, 1700000000);
    defer allocator.free(key_data);

    var analysis = try key_analyzer.analyzeKey(allocator, key_data);
    defer analysis.deinit(allocator);

    // RSA 2048 should score at most fair
    try testing.expect(@intFromEnum(analysis.overall_score) >= @intFromEnum(key_analyzer.SecurityScore.fair));
    try testing.expect(analysis.issues.items.len > 0);
}

test "analyzeKey EdDSA scores well" {
    const allocator = testing.allocator;
    const key_data = try buildMinimalEdDsaKey(allocator, 1700000000);
    defer allocator.free(key_data);

    var analysis = try key_analyzer.analyzeKey(allocator, key_data);
    defer analysis.deinit(allocator);

    // EdDSA should score excellent or good
    try testing.expect(analysis.overall_score == .excellent or analysis.overall_score == .good);
}

test "analyzeKey with subkeys" {
    const allocator = testing.allocator;
    const key_data = try buildKeyWithSubkeys(allocator);
    defer allocator.free(key_data);

    var analysis = try key_analyzer.analyzeKey(allocator, key_data);
    defer analysis.deinit(allocator);

    // Should have detected subkey algorithms
    try testing.expect(analysis.issues.items.len > 0);
}

test "analyzeKey format output" {
    const allocator = testing.allocator;
    const key_data = try buildMinimalRsaKey(allocator, 4096, 1700000000);
    defer allocator.free(key_data);

    var analysis = try key_analyzer.analyzeKey(allocator, key_data);
    defer analysis.deinit(allocator);

    const report = try analysis.format(allocator);
    defer allocator.free(report);

    try testing.expect(report.len > 0);
    try testing.expect(mem.indexOf(u8, report, "Key Security Analysis") != null);
}

// ---------------------------------------------------------------------------
// Message Analyzer Tests
// ---------------------------------------------------------------------------

test "analyzeMessage signed message" {
    const allocator = testing.allocator;
    const msg_data = try buildMinimalSignedMessage(allocator);
    defer allocator.free(msg_data);

    var ma = try message_analyzer.analyzeMessage(allocator, msg_data);
    defer ma.deinit(allocator);

    try testing.expect(ma.signature_strength != null);
    try testing.expect(ma.encryption_strength == null);
    try testing.expect(ma.hash_algo_assessment != null);
}

test "analyzeMessage encrypted with SKESK" {
    const allocator = testing.allocator;
    const msg_data = try buildMinimalEncryptedMessage(allocator);
    defer allocator.free(msg_data);

    var ma = try message_analyzer.analyzeMessage(allocator, msg_data);
    defer ma.deinit(allocator);

    try testing.expect(ma.encryption_strength != null);
    try testing.expect(ma.uses_mdc);
    try testing.expect(!ma.uses_aead);
    try testing.expect(ma.warnings.items.len > 0);
}

test "analyzeMessage AEAD encrypted" {
    const allocator = testing.allocator;
    const msg_data = try buildAeadEncryptedMessage(allocator);
    defer allocator.free(msg_data);

    var ma = try message_analyzer.analyzeMessage(allocator, msg_data);
    defer ma.deinit(allocator);

    try testing.expect(ma.uses_aead);
    try testing.expect(ma.encryption_strength != null);
    try testing.expect(ma.sym_algo_assessment != null);
}

test "analyzeMessage format output" {
    const allocator = testing.allocator;
    const msg_data = try buildMinimalEncryptedMessage(allocator);
    defer allocator.free(msg_data);

    var ma = try message_analyzer.analyzeMessage(allocator, msg_data);
    defer ma.deinit(allocator);

    const report = try ma.format(allocator);
    defer allocator.free(report);

    try testing.expect(report.len > 0);
    try testing.expect(mem.indexOf(u8, report, "Message Security Analysis") != null);
}

// ---------------------------------------------------------------------------
// Cross-module integration tests
// ---------------------------------------------------------------------------

test "inspect then analyze key" {
    const allocator = testing.allocator;
    const key_data = try buildMinimalRsaKey(allocator, 2048, 1700000000);
    defer allocator.free(key_data);

    // First inspect
    var ki = try packet_dump.inspectKey(allocator, key_data);
    defer ki.deinit(allocator);

    try testing.expectEqual(@as(u8, 4), ki.version);

    // Then analyze
    var analysis = try key_analyzer.analyzeKey(allocator, key_data);
    defer analysis.deinit(allocator);

    try testing.expect(analysis.issues.items.len > 0);
}

test "inspect then analyze message" {
    const allocator = testing.allocator;
    const msg_data = try buildMinimalEncryptedMessage(allocator);
    defer allocator.free(msg_data);

    // Inspect
    var mi = try packet_dump.inspectMessage(allocator, msg_data);
    defer mi.deinit(allocator);

    try testing.expect(mi.is_encrypted);

    // Analyze
    var ma = try message_analyzer.analyzeMessage(allocator, msg_data);
    defer ma.deinit(allocator);

    try testing.expect(ma.encryption_strength != null);
}
