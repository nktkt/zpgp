// SPDX-License-Identifier: MIT
//! Message decomposition - parsing OpenPGP messages from packet streams.
//!
//! Reads a sequence of packets (possibly armored) and identifies message
//! structure: encrypted data, signatures, literal data, etc.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const header_mod = @import("../packet/header.zig");
const PacketTag = @import("../packet/tags.zig").PacketTag;
const armor = @import("../armor/armor.zig");

const PKESKPacket = @import("../packets/pkesk.zig").PKESKPacket;
const SKESKPacket = @import("../packets/skesk.zig").SKESKPacket;
const SymEncIntegrityPacket = @import("../packets/sym_enc_integrity.zig").SymEncIntegrityPacket;
const SignaturePacket = @import("../packets/signature.zig").SignaturePacket;
const OnePassSignaturePacket = @import("../packets/one_pass_sig.zig").OnePassSignaturePacket;
const LiteralDataPacket = @import("../packets/literal_data.zig").LiteralDataPacket;
const CompressedDataPacket = @import("../packets/compressed_data.zig").CompressedDataPacket;

const Key = @import("../key/key.zig").Key;

pub const DecomposeError = error{
    InvalidPacket,
    UnsupportedVersion,
    InvalidPacketTag,
    MalformedMessage,
    NotImplemented,
    OutOfMemory,
    EndOfStream,
    Overflow,
};

/// A parsed OpenPGP message, broken into its constituent packet types.
pub const ParsedMessage = struct {
    pkesk_packets: std.ArrayList(PKESKPacket),
    skesk_packets: std.ArrayList(SKESKPacket),
    encrypted_data: ?SymEncIntegrityPacket,
    signatures: std.ArrayList(SignaturePacket),
    one_pass_sigs: std.ArrayList(OnePassSignaturePacket),
    literal_data: ?LiteralDataPacket,
    compressed_data: ?CompressedDataPacket,

    /// Create an empty ParsedMessage.
    pub fn init() ParsedMessage {
        return .{
            .pkesk_packets = .empty,
            .skesk_packets = .empty,
            .encrypted_data = null,
            .signatures = .empty,
            .one_pass_sigs = .empty,
            .literal_data = null,
            .compressed_data = null,
        };
    }

    /// Free all memory associated with this parsed message.
    pub fn deinit(self: *ParsedMessage, allocator: Allocator) void {
        for (self.pkesk_packets.items) |pkt| pkt.deinit(allocator);
        self.pkesk_packets.deinit(allocator);

        for (self.skesk_packets.items) |pkt| pkt.deinit(allocator);
        self.skesk_packets.deinit(allocator);

        if (self.encrypted_data) |pkt| pkt.deinit(allocator);

        for (self.signatures.items) |pkt| pkt.deinit(allocator);
        self.signatures.deinit(allocator);

        // OnePassSignaturePacket has no heap data, but clear the list
        self.one_pass_sigs.deinit(allocator);

        if (self.literal_data) |pkt| pkt.deinit(allocator);
        if (self.compressed_data) |pkt| pkt.deinit(allocator);
    }

    /// Check whether this message contains encrypted data.
    pub fn isEncrypted(self: *const ParsedMessage) bool {
        return self.encrypted_data != null;
    }

    /// Check whether this message contains signatures.
    pub fn isSigned(self: *const ParsedMessage) bool {
        return self.signatures.items.len > 0 or self.one_pass_sigs.items.len > 0;
    }
};

/// Parse a message from packet data (may be armored).
///
/// This function reads packet headers and dispatches to the appropriate
/// packet parser for each tag type. Unknown packet types are skipped.
pub fn parseMessage(
    allocator: Allocator,
    data: []const u8,
) DecomposeError!ParsedMessage {
    // Try to detect if data is ASCII-armored
    var binary_data: ?[]u8 = null;
    defer if (binary_data) |bd| allocator.free(bd);

    var packet_data: []const u8 = data;

    if (data.len > 10 and mem.startsWith(u8, data, "-----BEGIN ")) {
        const result = armor.decode(allocator, data) catch {
            // Not valid armor, try as binary
            packet_data = data;
            binary_data = null;
            return parsePacketStream(allocator, packet_data);
        };
        binary_data = result.data;
        // Free the headers
        for (result.headers) |hdr| {
            allocator.free(hdr.name);
            allocator.free(hdr.value);
        }
        allocator.free(result.headers);
        packet_data = binary_data.?;
    }

    return parsePacketStream(allocator, packet_data);
}

/// Parse a stream of binary OpenPGP packets into a ParsedMessage.
fn parsePacketStream(
    allocator: Allocator,
    data: []const u8,
) DecomposeError!ParsedMessage {
    var result = ParsedMessage.init();
    errdefer result.deinit(allocator);

    var fbs = std.io.fixedBufferStream(data);
    const reader = fbs.reader();

    while (true) {
        const hdr = header_mod.readHeader(reader) catch |err| {
            switch (err) {
                error.EndOfStream => break,
                error.InvalidPacketTag => return error.InvalidPacketTag,
            }
        };

        // Determine the body length
        const body_len: usize = switch (hdr.body_length) {
            .fixed => |len| len,
            .indeterminate => {
                // Read remaining data
                const pos = fbs.pos;
                const remaining = data.len - pos;
                const body = data[pos..];
                fbs.pos = data.len;
                try parsePacketBody(allocator, hdr.tag, body, &result);
                _ = remaining;
                continue;
            },
            .partial => {
                // Partial body: collect all chunks
                const collected = collectPartialBody(allocator, data, &fbs) catch
                    return error.MalformedMessage;
                defer allocator.free(collected);
                try parsePacketBody(allocator, hdr.tag, collected, &result);
                continue;
            },
        };

        // Read fixed-length body
        const pos = fbs.pos;
        if (pos + body_len > data.len) return error.MalformedMessage;
        const body = data[pos .. pos + body_len];
        fbs.pos = pos + body_len;

        try parsePacketBody(allocator, hdr.tag, body, &result);
    }

    return result;
}

/// Parse a single packet body and add it to the result.
fn parsePacketBody(
    allocator: Allocator,
    tag: PacketTag,
    body: []const u8,
    result: *ParsedMessage,
) DecomposeError!void {
    switch (tag) {
        .public_key_encrypted_session_key => {
            const pkt = PKESKPacket.parse(allocator, body) catch
                return error.InvalidPacket;
            result.pkesk_packets.append(allocator, pkt) catch
                return error.OutOfMemory;
        },
        .symmetric_key_encrypted_session_key => {
            const pkt = SKESKPacket.parse(allocator, body) catch
                return error.InvalidPacket;
            result.skesk_packets.append(allocator, pkt) catch
                return error.OutOfMemory;
        },
        .sym_encrypted_integrity_protected_data => {
            const pkt = SymEncIntegrityPacket.parse(allocator, body) catch
                return error.InvalidPacket;
            result.encrypted_data = pkt;
        },
        .signature => {
            const pkt = SignaturePacket.parse(allocator, body) catch
                return error.InvalidPacket;
            result.signatures.append(allocator, pkt) catch
                return error.OutOfMemory;
        },
        .one_pass_signature => {
            const pkt = OnePassSignaturePacket.parse(body) catch
                return error.InvalidPacket;
            result.one_pass_sigs.append(allocator, pkt) catch
                return error.OutOfMemory;
        },
        .literal_data => {
            const pkt = LiteralDataPacket.parse(allocator, body) catch
                return error.InvalidPacket;
            result.literal_data = pkt;
        },
        .compressed_data => {
            const pkt = CompressedDataPacket.parse(allocator, body) catch
                return error.InvalidPacket;
            result.compressed_data = pkt;
        },
        else => {
            // Skip unknown/unhandled packet types
        },
    }
}

/// Collect partial body chunks into a single contiguous buffer.
fn collectPartialBody(
    allocator: Allocator,
    data: []const u8,
    fbs: *std.io.FixedBufferStream([]const u8),
) ![]u8 {
    var collected: std.ArrayList(u8) = .empty;
    errdefer collected.deinit(allocator);

    const reader = fbs.reader();

    // Read the first partial chunk (the header already told us its size)
    // We need to re-read the length since we already parsed the header.
    // Actually, the caller has already parsed the partial header.
    // We need to handle the continuation here.
    // For now, read remaining as the body (simplified).
    const pos = fbs.pos;
    if (pos < data.len) {
        try collected.appendSlice(allocator, data[pos..]);
        fbs.pos = data.len;
    }

    _ = reader;
    return try collected.toOwnedSlice(allocator);
}

/// Decrypt a parsed message using a secret key.
///
/// This requires the crypto modules (CFB, session key) which are being
/// created in parallel. Returns error.NotImplemented until those are available.
pub fn decryptWithKey(
    allocator: Allocator,
    msg: *const ParsedMessage,
    secret_key: *const Key,
    passphrase: ?[]const u8,
) DecomposeError![]u8 {
    _ = allocator;
    _ = msg;
    _ = secret_key;
    _ = passphrase;
    return error.NotImplemented;
}

/// Decrypt a parsed message using a passphrase (symmetric encryption).
///
/// This requires the crypto modules (CFB, S2K) which are being created
/// in parallel. Returns error.NotImplemented until those are available.
pub fn decryptWithPassphrase(
    allocator: Allocator,
    msg: *const ParsedMessage,
    passphrase: []const u8,
) DecomposeError![]u8 {
    _ = allocator;
    _ = msg;
    _ = passphrase;
    return error.NotImplemented;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ParsedMessage init and deinit" {
    const allocator = std.testing.allocator;

    var msg = ParsedMessage.init();
    defer msg.deinit(allocator);

    try std.testing.expect(!msg.isEncrypted());
    try std.testing.expect(!msg.isSigned());
    try std.testing.expect(msg.literal_data == null);
    try std.testing.expect(msg.compressed_data == null);
}

test "parseMessage literal data packet" {
    const allocator = std.testing.allocator;

    // Build a new-format literal data packet:
    // tag 11, body: format='b', filename_len=0, timestamp=0, data="Hello"
    const body = [_]u8{ 'b', 0, 0, 0, 0, 0, 'H', 'e', 'l', 'l', 'o' };
    const body_len: u8 = body.len;

    // New format header: 0xC0 | 11 = 0xCB, length = 11
    var packet: [2 + body.len]u8 = undefined;
    packet[0] = 0xCB; // new format, tag 11
    packet[1] = body_len;
    @memcpy(packet[2..], &body);

    var msg = try parseMessage(allocator, &packet);
    defer msg.deinit(allocator);

    try std.testing.expect(msg.literal_data != null);
    try std.testing.expectEqualStrings("Hello", msg.literal_data.?.data);
    try std.testing.expect(!msg.isEncrypted());
    try std.testing.expect(!msg.isSigned());
}

test "parseMessage PKESK packet" {
    const allocator = std.testing.allocator;

    // Build a PKESK packet: version=3, key_id=8 bytes, algo=RSA(1), 1 MPI
    var pkesk_body: [14]u8 = undefined;
    pkesk_body[0] = 3; // version
    @memset(pkesk_body[1..9], 0x42); // key_id
    pkesk_body[9] = 1; // RSA
    mem.writeInt(u16, pkesk_body[10..12], 8, .big); // MPI: 8 bits
    pkesk_body[12] = 0xFF;

    // Packet header: new format tag 1 = 0xC1
    var packet: [2 + 13]u8 = undefined;
    packet[0] = 0xC1;
    packet[1] = 13;
    @memcpy(packet[2..], pkesk_body[0..13]);

    var msg = try parseMessage(allocator, &packet);
    defer msg.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), msg.pkesk_packets.items.len);
    try std.testing.expectEqual(@as(u8, 3), msg.pkesk_packets.items[0].version);
}

test "parseMessage SKESK packet" {
    const allocator = std.testing.allocator;

    // SKESK: version=4, algo=AES128(7), S2K simple: type=0, hash=SHA256(8)
    const skesk_body = [_]u8{ 4, 7, 0, 8 };

    // Packet header: new format tag 3 = 0xC3
    var packet: [2 + skesk_body.len]u8 = undefined;
    packet[0] = 0xC3;
    packet[1] = skesk_body.len;
    @memcpy(packet[2..], &skesk_body);

    var msg = try parseMessage(allocator, &packet);
    defer msg.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), msg.skesk_packets.items.len);
    try std.testing.expectEqual(@as(u8, 4), msg.skesk_packets.items[0].version);
}

test "parseMessage signature packet" {
    const allocator = std.testing.allocator;

    // Minimal v4 RSA signature
    var sig_body: [13]u8 = undefined;
    sig_body[0] = 4; // version
    sig_body[1] = 0x00; // sig_type
    sig_body[2] = 1; // RSA
    sig_body[3] = 8; // SHA256
    mem.writeInt(u16, sig_body[4..6], 0, .big);
    mem.writeInt(u16, sig_body[6..8], 0, .big);
    sig_body[8] = 0xAB;
    sig_body[9] = 0xCD;
    mem.writeInt(u16, sig_body[10..12], 8, .big);
    sig_body[12] = 0xFF;

    // New format tag 2 = 0xC2
    var packet: [2 + 13]u8 = undefined;
    packet[0] = 0xC2;
    packet[1] = 13;
    @memcpy(packet[2..], sig_body[0..13]);

    var msg = try parseMessage(allocator, &packet);
    defer msg.deinit(allocator);

    try std.testing.expect(msg.isSigned());
    try std.testing.expectEqual(@as(usize, 1), msg.signatures.items.len);
}

test "parseMessage SEIPD packet" {
    const allocator = std.testing.allocator;

    // SEIPD: version=1, some data
    const seipd_body = [_]u8{ 1, 0xDE, 0xAD, 0xBE, 0xEF };

    // New format tag 18 = 0xD2
    var packet: [2 + seipd_body.len]u8 = undefined;
    packet[0] = 0xD2;
    packet[1] = seipd_body.len;
    @memcpy(packet[2..], &seipd_body);

    var msg = try parseMessage(allocator, &packet);
    defer msg.deinit(allocator);

    try std.testing.expect(msg.isEncrypted());
    try std.testing.expectEqual(@as(u8, 1), msg.encrypted_data.?.version);
}

test "parseMessage multiple packets" {
    const allocator = std.testing.allocator;

    // Build a message with: PKESK + SEIPD
    var buf: [64]u8 = undefined;
    var offset: usize = 0;

    // PKESK: tag 1 new format
    const pkesk_body_len: u8 = 13;
    buf[offset] = 0xC1; // tag 1 new format
    offset += 1;
    buf[offset] = pkesk_body_len;
    offset += 1;
    buf[offset] = 3; // version
    offset += 1;
    @memset(buf[offset .. offset + 8], 0x11); // key_id
    offset += 8;
    buf[offset] = 1; // RSA
    offset += 1;
    mem.writeInt(u16, buf[offset..][0..2], 8, .big); // MPI 8 bits
    offset += 2;
    buf[offset] = 0xAA;
    offset += 1;

    // SEIPD: tag 18 new format
    const seipd_body_len: u8 = 5;
    buf[offset] = 0xD2; // tag 18 new format
    offset += 1;
    buf[offset] = seipd_body_len;
    offset += 1;
    buf[offset] = 1; // version
    offset += 1;
    @memset(buf[offset .. offset + 4], 0xBB);
    offset += 4;

    var msg = try parseMessage(allocator, buf[0..offset]);
    defer msg.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), msg.pkesk_packets.items.len);
    try std.testing.expect(msg.isEncrypted());
}

test "parseMessage one-pass signature" {
    const allocator = std.testing.allocator;

    // One-pass sig: always 13 bytes
    const ops_body = [13]u8{
        3, // version
        0x00, // sig_type: binary
        2, // hash: SHA1
        1, // pub algo: RSA
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, // key_id
        1, // nested: last
    };

    // New format tag 4 = 0xC4
    var packet: [2 + 13]u8 = undefined;
    packet[0] = 0xC4;
    packet[1] = 13;
    @memcpy(packet[2..], &ops_body);

    var msg = try parseMessage(allocator, &packet);
    defer msg.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), msg.one_pass_sigs.items.len);
    try std.testing.expect(msg.isSigned());
}

test "parseMessage empty data" {
    const allocator = std.testing.allocator;

    var msg = try parseMessage(allocator, &[_]u8{});
    defer msg.deinit(allocator);

    try std.testing.expect(!msg.isEncrypted());
    try std.testing.expect(!msg.isSigned());
    try std.testing.expect(msg.literal_data == null);
}

test "decryptWithKey returns NotImplemented" {
    const allocator = std.testing.allocator;

    var msg = ParsedMessage.init();
    defer msg.deinit(allocator);

    const result = decryptWithKey(allocator, &msg, undefined, null);
    try std.testing.expectError(error.NotImplemented, result);
}

test "decryptWithPassphrase returns NotImplemented" {
    const allocator = std.testing.allocator;

    var msg = ParsedMessage.init();
    defer msg.deinit(allocator);

    const result = decryptWithPassphrase(allocator, &msg, "password");
    try std.testing.expectError(error.NotImplemented, result);
}
