// SPDX-License-Identifier: MIT
//! High-level OpenPGP message types and operations.
//!
//! A Message represents a parsed or constructed OpenPGP message that may
//! be encrypted, signed, compressed, or a literal data message.

const std = @import("std");
const Allocator = std.mem.Allocator;

const LiteralDataPacket = @import("../packets/literal_data.zig").LiteralDataPacket;
const SignaturePacket = @import("../packets/signature.zig").SignaturePacket;
const CompressedDataPacket = @import("../packets/compressed_data.zig").CompressedDataPacket;

/// The type of OpenPGP message.
pub const MessageType = enum {
    /// Encrypted message (PKESK/SKESK + SEIPD).
    encrypted,
    /// Signed message (One-Pass Sig + Literal Data + Signature).
    signed,
    /// Compressed message (wrapping inner packets).
    compressed,
    /// Plain literal data message.
    literal,
};

/// A high-level OpenPGP message.
pub const Message = struct {
    allocator: Allocator,
    msg_type: MessageType,
    /// The literal data payload, if present.
    literal_data: ?LiteralDataPacket,
    /// Signatures attached to this message.
    signatures: std.ArrayList(SignaturePacket),

    /// Create an empty message of the given type.
    pub fn init(allocator: Allocator, msg_type: MessageType) Message {
        return .{
            .allocator = allocator,
            .msg_type = msg_type,
            .literal_data = null,
            .signatures = .empty,
        };
    }

    /// Free all memory associated with this message.
    pub fn deinit(self: *Message) void {
        if (self.literal_data) |ld| ld.deinit(self.allocator);
        for (self.signatures.items) |sig| sig.deinit(self.allocator);
        self.signatures.deinit(self.allocator);
    }

    /// Add a signature to this message.
    pub fn addSignature(self: *Message, sig: SignaturePacket) !void {
        try self.signatures.append(self.allocator, sig);
    }

    /// Return the number of signatures.
    pub fn signatureCount(self: *const Message) usize {
        return self.signatures.items.len;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Message init and deinit" {
    const allocator = std.testing.allocator;

    var msg = Message.init(allocator, .literal);
    defer msg.deinit();

    try std.testing.expectEqual(MessageType.literal, msg.msg_type);
    try std.testing.expect(msg.literal_data == null);
    try std.testing.expectEqual(@as(usize, 0), msg.signatureCount());
}

test "Message with literal data" {
    const allocator = std.testing.allocator;

    // Build a minimal literal data packet
    const body = [_]u8{ 'b', 0, 0, 0, 0, 0, 'H', 'i' };
    const ld = try LiteralDataPacket.parse(allocator, &body);

    var msg = Message.init(allocator, .literal);
    defer msg.deinit();

    msg.literal_data = ld;
    try std.testing.expectEqualStrings("Hi", msg.literal_data.?.data);
}

test "Message with signatures" {
    const allocator = std.testing.allocator;

    var msg = Message.init(allocator, .signed);
    defer msg.deinit();

    // Build a minimal v4 RSA signature
    var sig_body: [15]u8 = undefined;
    sig_body[0] = 4; // version
    sig_body[1] = 0x00; // sig_type
    sig_body[2] = 1; // RSA
    sig_body[3] = 8; // SHA256
    std.mem.writeInt(u16, sig_body[4..6], 0, .big); // hashed sp len
    std.mem.writeInt(u16, sig_body[6..8], 0, .big); // unhashed sp len
    sig_body[8] = 0xAB; // hash prefix
    sig_body[9] = 0xCD;
    std.mem.writeInt(u16, sig_body[10..12], 8, .big); // MPI 8 bits
    sig_body[12] = 0xFF;

    const sig = try SignaturePacket.parse(allocator, sig_body[0..13]);
    try msg.addSignature(sig);

    try std.testing.expectEqual(@as(usize, 1), msg.signatureCount());
}

test "MessageType enum values" {
    try std.testing.expect(@intFromEnum(MessageType.encrypted) != @intFromEnum(MessageType.signed));
    try std.testing.expect(@intFromEnum(MessageType.compressed) != @intFromEnum(MessageType.literal));
}
