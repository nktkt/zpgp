// SPDX-License-Identifier: MIT
//! Integration tests for the protocol module.
//!
//! Tests openpgp_message grammar validation, transferable key validation,
//! and keyserver protocol helpers with realistic packet sequences.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

const openpgp_message = @import("protocol/openpgp_message.zig");
const transferable_key = @import("protocol/transferable_key.zig");
const keyserver_protocol = @import("protocol/keyserver_protocol.zig");
const PacketTag = @import("packet/tags.zig").PacketTag;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn buildLiteralDataMessage(allocator: std.mem.Allocator) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    try w.writeByte(0xCB); // tag 11
    try w.writeByte(11);
    try w.writeByte('b'); // binary
    try w.writeByte(0); // name len
    try w.writeInt(u32, 1700000000, .big);
    try w.writeAll("Hello");

    return buf.toOwnedSlice(allocator);
}

fn buildOnePassSignedMessage(allocator: std.mem.Allocator) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    // One-Pass Signature
    try w.writeByte(0xC0 | 4);
    try w.writeByte(13);
    try w.writeByte(3);
    try w.writeByte(0x00);
    try w.writeByte(8); // SHA256
    try w.writeByte(1); // RSA
    try w.writeAll(&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 });
    try w.writeByte(1);

    // Literal data
    try w.writeByte(0xCB);
    try w.writeByte(7);
    try w.writeByte('t');
    try w.writeByte(0);
    try w.writeInt(u32, 0, .big);
    try w.writeByte('X');

    // Trailing signature
    try w.writeByte(0xC0 | 2);
    try w.writeByte(10);
    try w.writeAll(&[_]u8{ 4, 0, 1, 8, 0, 0, 0, 0, 0xAB, 0xCD });

    return buf.toOwnedSlice(allocator);
}

fn buildEncryptedMessage(allocator: std.mem.Allocator) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    // PKESK v3
    try w.writeByte(0xC0 | 1);
    try w.writeByte(11);
    try w.writeByte(3);
    try w.writeAll(&[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 });
    try w.writeByte(1); // RSA
    try w.writeByte(0);

    // SEIPD v1
    try w.writeByte(0xC0 | 18);
    try w.writeByte(3);
    try w.writeByte(1);
    try w.writeByte(0);
    try w.writeByte(0);

    return buf.toOwnedSlice(allocator);
}

fn buildDoubleEncryptedMessage(allocator: std.mem.Allocator) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    // Two PKESK packets (multiple recipients)
    try w.writeByte(0xC0 | 1);
    try w.writeByte(11);
    try w.writeByte(3);
    try w.writeAll(&[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 });
    try w.writeByte(1);
    try w.writeByte(0);

    try w.writeByte(0xC0 | 1);
    try w.writeByte(11);
    try w.writeByte(3);
    try w.writeAll(&[_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 });
    try w.writeByte(1);
    try w.writeByte(0);

    // SEIPD v1
    try w.writeByte(0xC0 | 18);
    try w.writeByte(3);
    try w.writeByte(1);
    try w.writeByte(0);
    try w.writeByte(0);

    return buf.toOwnedSlice(allocator);
}

fn buildCompressedMessage(allocator: std.mem.Allocator) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    // Compressed data (ZLIB)
    try w.writeByte(0xC0 | 8);
    try w.writeByte(3);
    try w.writeByte(2); // ZLIB
    try w.writeByte(0);
    try w.writeByte(0);

    return buf.toOwnedSlice(allocator);
}

fn buildValidKeyPackets(allocator: std.mem.Allocator) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    // Public key
    try w.writeByte(0xC0 | 6);
    try w.writeByte(6);
    try w.writeByte(4);
    try w.writeInt(u32, 1700000000, .big);
    try w.writeByte(1);

    // User ID
    try w.writeByte(0xC0 | 13);
    try w.writeByte(5);
    try w.writeAll("Alice");

    // Self-sig
    try w.writeByte(0xC0 | 2);
    try w.writeByte(10);
    try w.writeAll(&[_]u8{ 4, 0x13, 1, 8, 0, 0, 0, 0, 0xAB, 0xCD });

    return buf.toOwnedSlice(allocator);
}

fn buildKeyWithMultipleUids(allocator: std.mem.Allocator) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    // Public key
    try w.writeByte(0xC0 | 6);
    try w.writeByte(6);
    try w.writeByte(4);
    try w.writeInt(u32, 1700000000, .big);
    try w.writeByte(1);

    // UID 1
    try w.writeByte(0xC0 | 13);
    try w.writeByte(5);
    try w.writeAll("Alice");

    // Self-sig for UID 1
    try w.writeByte(0xC0 | 2);
    try w.writeByte(10);
    try w.writeAll(&[_]u8{ 4, 0x13, 1, 8, 0, 0, 0, 0, 0xAB, 0xCD });

    // UID 2
    try w.writeByte(0xC0 | 13);
    try w.writeByte(3);
    try w.writeAll("Bob");

    // Self-sig for UID 2
    try w.writeByte(0xC0 | 2);
    try w.writeByte(10);
    try w.writeAll(&[_]u8{ 4, 0x13, 1, 8, 0, 0, 0, 0, 0xEF, 0x01 });

    return buf.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Message Grammar Tests
// ---------------------------------------------------------------------------

test "validateMessageGrammar literal data is valid" {
    const allocator = testing.allocator;
    const data = try buildLiteralDataMessage(allocator);
    defer allocator.free(data);

    var result = try openpgp_message.validateMessageGrammar(allocator, data);
    defer result.deinit(allocator);

    try testing.expect(result.valid);
}

test "validateMessageGrammar one-pass signed is valid" {
    const allocator = testing.allocator;
    const data = try buildOnePassSignedMessage(allocator);
    defer allocator.free(data);

    var result = try openpgp_message.validateMessageGrammar(allocator, data);
    defer result.deinit(allocator);

    try testing.expect(result.valid);
}

test "validateMessageGrammar encrypted is valid" {
    const allocator = testing.allocator;
    const data = try buildEncryptedMessage(allocator);
    defer allocator.free(data);

    var result = try openpgp_message.validateMessageGrammar(allocator, data);
    defer result.deinit(allocator);

    try testing.expect(result.valid);
}

test "validateMessageGrammar double PKESK encrypted is valid" {
    const allocator = testing.allocator;
    const data = try buildDoubleEncryptedMessage(allocator);
    defer allocator.free(data);

    var result = try openpgp_message.validateMessageGrammar(allocator, data);
    defer result.deinit(allocator);

    try testing.expect(result.valid);
}

test "validateMessageGrammar compressed is valid" {
    const allocator = testing.allocator;
    const data = try buildCompressedMessage(allocator);
    defer allocator.free(data);

    var result = try openpgp_message.validateMessageGrammar(allocator, data);
    defer result.deinit(allocator);

    try testing.expect(result.valid);
}

test "validateMessageGrammar rejects key packets as message" {
    const allocator = testing.allocator;
    const data = try buildValidKeyPackets(allocator);
    defer allocator.free(data);

    var result = try openpgp_message.validateMessageGrammar(allocator, data);
    defer result.deinit(allocator);

    try testing.expect(!result.valid);
}

test "analyzeMessageStructure on encrypted" {
    const allocator = testing.allocator;
    const data = try buildEncryptedMessage(allocator);
    defer allocator.free(data);

    var structure = try openpgp_message.analyzeMessageStructure(allocator, data);
    defer structure.deinit(allocator);

    try testing.expectEqual(openpgp_message.MessageType.encrypted, structure.msg_type);
    try testing.expect(structure.layers.items.len >= 2);
}

test "analyzeMessageStructure on signed" {
    const allocator = testing.allocator;
    const data = try buildOnePassSignedMessage(allocator);
    defer allocator.free(data);

    var structure = try openpgp_message.analyzeMessageStructure(allocator, data);
    defer structure.deinit(allocator);

    try testing.expectEqual(openpgp_message.MessageType.signed, structure.msg_type);
}

test "analyzeMessageStructure format" {
    const allocator = testing.allocator;
    const data = try buildEncryptedMessage(allocator);
    defer allocator.free(data);

    var structure = try openpgp_message.analyzeMessageStructure(allocator, data);
    defer structure.deinit(allocator);

    const output = try structure.format(allocator);
    defer allocator.free(output);

    try testing.expect(output.len > 0);
    try testing.expect(mem.indexOf(u8, output, "Encrypted") != null);
}

// ---------------------------------------------------------------------------
// Transferable Key Validation Tests
// ---------------------------------------------------------------------------

test "validate valid public key" {
    const allocator = testing.allocator;
    const data = try buildValidKeyPackets(allocator);
    defer allocator.free(data);

    var result = try transferable_key.TransferableKeyValidator.validate(allocator, data);
    defer result.deinit(allocator);

    try testing.expect(result.valid);
    try testing.expect(result.has_primary_key);
    try testing.expect(result.has_user_id);
    try testing.expect(result.has_self_signature);
}

test "validate key with multiple UIDs" {
    const allocator = testing.allocator;
    const data = try buildKeyWithMultipleUids(allocator);
    defer allocator.free(data);

    var result = try transferable_key.TransferableKeyValidator.validate(allocator, data);
    defer result.deinit(allocator);

    try testing.expect(result.valid);
    try testing.expectEqual(@as(u32, 2), result.user_id_count);
    try testing.expectEqual(@as(u32, 2), result.signature_count);
}

test "validate rejects no primary key" {
    const allocator = testing.allocator;

    var buf: [16]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();

    // Only a user ID (no key)
    w.writeByte(0xC0 | 13) catch unreachable;
    w.writeByte(5) catch unreachable;
    w.writeAll("Alice") catch unreachable;

    const written = wfbs.getWritten();
    var result = try transferable_key.TransferableKeyValidator.validate(allocator, written);
    defer result.deinit(allocator);

    try testing.expect(!result.valid);
    try testing.expect(!result.has_primary_key);
}

test "validate detects missing user ID" {
    const allocator = testing.allocator;

    var buf: [16]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();

    // Only a public key
    w.writeByte(0xC0 | 6) catch unreachable;
    w.writeByte(6) catch unreachable;
    w.writeByte(4) catch unreachable;
    w.writeInt(u32, 0, .big) catch unreachable;
    w.writeByte(1) catch unreachable;

    const written = wfbs.getWritten();
    var result = try transferable_key.TransferableKeyValidator.validate(allocator, written);
    defer result.deinit(allocator);

    try testing.expect(!result.valid);
    try testing.expect(!result.has_user_id);
}

test "validatePublicKey function" {
    const allocator = testing.allocator;
    const data = try buildValidKeyPackets(allocator);
    defer allocator.free(data);

    var result = try transferable_key.TransferableKeyValidator.validatePublicKey(allocator, data);
    defer result.deinit(allocator);

    try testing.expect(result.valid);
}

test "format validation result" {
    const allocator = testing.allocator;
    const data = try buildValidKeyPackets(allocator);
    defer allocator.free(data);

    var result = try transferable_key.TransferableKeyValidator.validate(allocator, data);
    defer result.deinit(allocator);

    const output = try result.format(allocator);
    defer allocator.free(output);

    try testing.expect(output.len > 0);
    try testing.expect(mem.indexOf(u8, output, "VALID") != null);
}

// ---------------------------------------------------------------------------
// Keyserver Protocol Tests
// ---------------------------------------------------------------------------

test "detectProtocol various schemes" {
    try testing.expectEqual(keyserver_protocol.KeyserverProtocol.hkp,
        keyserver_protocol.detectProtocol("hkp://pool.sks-keyservers.net").?);
    try testing.expectEqual(keyserver_protocol.KeyserverProtocol.hkps,
        keyserver_protocol.detectProtocol("hkps://keys.openpgp.org").?);
    try testing.expectEqual(keyserver_protocol.KeyserverProtocol.hkps,
        keyserver_protocol.detectProtocol("https://keys.openpgp.org").?);
}

test "normalizeKeyId various formats" {
    const allocator = testing.allocator;

    // V4 fingerprint
    {
        const result = try keyserver_protocol.normalizeKeyId(allocator, "AAAA BBBB CCCC DDDD 1111 2222 3333 4444 AAAA BBBB");
        defer result.deinit(allocator);
        try testing.expectEqual(keyserver_protocol.KeyIdType.fingerprint_v4, result.id_type);
    }

    // Email
    {
        const result = try keyserver_protocol.normalizeKeyId(allocator, "user@example.com");
        defer result.deinit(allocator);
        try testing.expectEqual(keyserver_protocol.KeyIdType.email, result.id_type);
    }

    // Key ID
    {
        const result = try keyserver_protocol.normalizeKeyId(allocator, "0xAABBCCDD11223344");
        defer result.deinit(allocator);
        try testing.expectEqual(keyserver_protocol.KeyIdType.key_id, result.id_type);
    }
}

test "buildHkpLookupUrl with different inputs" {
    const allocator = testing.allocator;

    // HKPS server
    {
        const url = try keyserver_protocol.buildHkpLookupUrl(allocator, "hkps://keys.openpgp.org", "0xAABBCCDD");
        defer allocator.free(url);
        try testing.expect(mem.startsWith(u8, url, "https://"));
        try testing.expect(mem.indexOf(u8, url, "pks/lookup") != null);
    }

    // HKP server (should include port)
    {
        const url = try keyserver_protocol.buildHkpLookupUrl(allocator, "hkp://pool.sks-keyservers.net", "0xAABBCCDD");
        defer allocator.free(url);
        try testing.expect(mem.indexOf(u8, url, "11371") != null);
    }

    // Plain hostname
    {
        const url = try keyserver_protocol.buildHkpLookupUrl(allocator, "keys.example.com", "0xAABBCCDD");
        defer allocator.free(url);
        try testing.expect(mem.startsWith(u8, url, "https://"));
    }
}

test "buildWkdDirectUrl produces valid URL" {
    const allocator = testing.allocator;
    const url = try keyserver_protocol.buildWkdDirectUrl(allocator, "test@example.com");
    defer allocator.free(url);

    try testing.expect(mem.startsWith(u8, url, "https://example.com/.well-known/openpgpkey/hu/"));
}

test "buildWkdAdvancedUrl produces valid URL" {
    const allocator = testing.allocator;
    const url = try keyserver_protocol.buildWkdAdvancedUrl(allocator, "test@example.com");
    defer allocator.free(url);

    try testing.expect(mem.startsWith(u8, url, "https://openpgpkey.example.com/"));
    try testing.expect(mem.indexOf(u8, url, "example.com/hu/") != null);
}

// ---------------------------------------------------------------------------
// Cross-module tests
// ---------------------------------------------------------------------------

test "validate key then validate as message (should fail)" {
    const allocator = testing.allocator;
    const key_data = try buildValidKeyPackets(allocator);
    defer allocator.free(key_data);

    // Key validation should pass
    var key_result = try transferable_key.TransferableKeyValidator.validate(allocator, key_data);
    defer key_result.deinit(allocator);
    try testing.expect(key_result.valid);

    // Message grammar validation should fail (keys are not messages)
    var msg_result = try openpgp_message.validateMessageGrammar(allocator, key_data);
    defer msg_result.deinit(allocator);
    try testing.expect(!msg_result.valid);
}

test "validate message then validate as key (should fail)" {
    const allocator = testing.allocator;
    const msg_data = try buildEncryptedMessage(allocator);
    defer allocator.free(msg_data);

    // Message validation should pass
    var msg_result = try openpgp_message.validateMessageGrammar(allocator, msg_data);
    defer msg_result.deinit(allocator);
    try testing.expect(msg_result.valid);

    // Key validation should fail (messages are not keys)
    var key_result = try transferable_key.TransferableKeyValidator.validate(allocator, msg_data);
    defer key_result.deinit(allocator);
    try testing.expect(!key_result.valid);
}
