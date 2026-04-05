// SPDX-License-Identifier: MIT
//! OpenPGP message grammar validation per RFC 4880 Section 11.3.
//!
//! This module validates that a sequence of OpenPGP packets forms a
//! valid message according to the grammar:
//!
//!   OpenPGP Message := Encrypted Message | Signed Message |
//!                      Compressed Message | Literal Data
//!   Encrypted Message := (PKESK | SKESK)+ (SED | SEIPD)
//!   Signed Message := One-Pass-Sig+ Literal-Data Signature+ |
//!                     Signature+ Literal-Data
//!   Compressed Message := Compressed-Data
//!
//! The module also provides structural analysis to describe the
//! layers of encryption, signing, and compression in a message.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const header_mod = @import("../packet/header.zig");
const PacketTag = @import("../packet/tags.zig").PacketTag;
const armor = @import("../armor/armor.zig");
const enums = @import("../types/enums.zig");
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const AeadAlgorithm = enums.AeadAlgorithm;
const CompressionAlgorithm = enums.CompressionAlgorithm;

/// Describes the overall type of a message.
pub const MessageType = enum {
    literal,
    signed,
    encrypted,
    compressed,
    signed_encrypted,
    compressed_signed,
    unknown,

    pub fn name(self: MessageType) []const u8 {
        return switch (self) {
            .literal => "Literal Data",
            .signed => "Signed Message",
            .encrypted => "Encrypted Message",
            .compressed => "Compressed Message",
            .signed_encrypted => "Signed and Encrypted Message",
            .compressed_signed => "Compressed Signed Message",
            .unknown => "Unknown",
        };
    }
};

/// A layer in the message structure.
pub const Layer = struct {
    layer_type: LayerType,
    algorithm: ?[]const u8,
    details: ?[]const u8,

    pub fn deinit(self: Layer, allocator: Allocator) void {
        if (self.algorithm) |a| allocator.free(a);
        if (self.details) |d| allocator.free(d);
    }
};

/// Type of a message layer.
pub const LayerType = enum {
    public_key_encryption,
    symmetric_encryption,
    aead_encryption,
    signature,
    compression,
    literal_data,

    pub fn name(self: LayerType) []const u8 {
        return switch (self) {
            .public_key_encryption => "Public-Key Encryption",
            .symmetric_encryption => "Symmetric Encryption",
            .aead_encryption => "AEAD Encryption",
            .signature => "Signature",
            .compression => "Compression",
            .literal_data => "Literal Data",
        };
    }
};

/// Structural analysis of an OpenPGP message.
pub const MessageStructure = struct {
    msg_type: MessageType,
    layers: std.ArrayList(Layer),

    pub fn deinit(self: *MessageStructure, allocator: Allocator) void {
        for (self.layers.items) |layer| layer.deinit(allocator);
        self.layers.deinit(allocator);
    }

    /// Format the structure as a human-readable string.
    pub fn format(self: *const MessageStructure, allocator: Allocator) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);
        const w = buf.writer(allocator);

        try w.print("Message Structure: {s}\n", .{self.msg_type.name()});
        try w.print("Layers ({d}):\n", .{self.layers.items.len});

        for (self.layers.items, 0..) |layer, i| {
            try w.print("  {d}. {s}", .{ i + 1, layer.layer_type.name() });
            if (layer.algorithm) |algo| {
                try w.print(" ({s})", .{algo});
            }
            if (layer.details) |details| {
                try w.print(" - {s}", .{details});
            }
            try w.print("\n", .{});
        }

        return buf.toOwnedSlice(allocator);
    }
};

/// Result of grammar validation.
pub const GrammarResult = struct {
    valid: bool,
    errors: std.ArrayList([]const u8),

    pub fn deinit(self: *GrammarResult, allocator: Allocator) void {
        for (self.errors.items) |e| allocator.free(e);
        self.errors.deinit(allocator);
    }
};

// ---------------------------------------------------------------------------
// Structure analysis
// ---------------------------------------------------------------------------

/// Parse and analyze the structure of an OpenPGP message.
pub fn analyzeMessageStructure(allocator: Allocator, data: []const u8) !MessageStructure {
    const stripped = stripArmor(allocator, data);
    const binary = stripped.binary;
    defer freeArmorResult(allocator, stripped.decoded, stripped.headers);

    var structure = MessageStructure{
        .msg_type = .unknown,
        .layers = .empty,
    };
    errdefer structure.deinit(allocator);

    var has_pkesk = false;
    var has_skesk = false;
    var has_seipd = false;
    var has_sed = false;
    var has_one_pass = false;
    var has_signature = false;
    var has_literal = false;
    var has_compressed = false;

    var fbs = std.io.fixedBufferStream(binary);
    const rdr = fbs.reader();

    while (true) {
        const hdr = header_mod.readHeader(rdr) catch break;
        const body_len: u32 = switch (hdr.body_length) {
            .fixed => |len| len,
            .partial => |len| len,
            .indeterminate => 0,
        };

        const can_read = body_len > 0 and fbs.pos + body_len <= binary.len;
        const body: ?[]const u8 = if (can_read) binary[fbs.pos .. fbs.pos + body_len] else null;

        switch (hdr.tag) {
            .public_key_encrypted_session_key => {
                has_pkesk = true;
                var algo_str: ?[]u8 = null;
                var details_str: ?[]u8 = null;
                if (body) |b| {
                    if (b.len >= 10 and b[0] == 3) {
                        const pk_algo: PublicKeyAlgorithm = @enumFromInt(b[9]);
                        algo_str = try allocator.dupe(u8, pk_algo.name());

                        var kid_buf: std.ArrayList(u8) = .empty;
                        const kid_w = kid_buf.writer(allocator);
                        try kid_w.print("Key ID: ", .{});
                        for (b[1..9]) |byte| {
                            try kid_w.print("{X:0>2}", .{byte});
                        }
                        details_str = try kid_buf.toOwnedSlice(allocator);
                    }
                }
                try structure.layers.append(allocator, .{
                    .layer_type = .public_key_encryption,
                    .algorithm = algo_str,
                    .details = details_str,
                });
            },
            .symmetric_key_encrypted_session_key => {
                has_skesk = true;
                var algo_str: ?[]u8 = null;
                if (body) |b| {
                    if (b.len >= 2 and b[0] == 4) {
                        const sa: SymmetricAlgorithm = @enumFromInt(b[1]);
                        algo_str = try allocator.dupe(u8, sa.name());
                    }
                }
                try structure.layers.append(allocator, .{
                    .layer_type = .symmetric_encryption,
                    .algorithm = algo_str,
                    .details = try allocator.dupe(u8, "Password-based encryption"),
                });
            },
            .sym_encrypted_integrity_protected_data => {
                has_seipd = true;
                if (body) |b| {
                    if (b.len >= 1 and b[0] == 2 and b.len >= 3) {
                        const sa: SymmetricAlgorithm = @enumFromInt(b[1]);
                        const aa: AeadAlgorithm = @enumFromInt(b[2]);
                        try structure.layers.append(allocator, .{
                            .layer_type = .aead_encryption,
                            .algorithm = try std.fmt.allocPrint(allocator, "{s}+{s}", .{ sa.name(), aa.name() }),
                            .details = try allocator.dupe(u8, "SEIPD v2 with AEAD"),
                        });
                    } else {
                        try structure.layers.append(allocator, .{
                            .layer_type = .symmetric_encryption,
                            .algorithm = null,
                            .details = try allocator.dupe(u8, "SEIPD v1 with MDC"),
                        });
                    }
                } else {
                    try structure.layers.append(allocator, .{
                        .layer_type = .symmetric_encryption,
                        .algorithm = null,
                        .details = null,
                    });
                }
            },
            .symmetrically_encrypted_data => {
                has_sed = true;
                try structure.layers.append(allocator, .{
                    .layer_type = .symmetric_encryption,
                    .algorithm = null,
                    .details = try allocator.dupe(u8, "Legacy SED (no integrity protection)"),
                });
            },
            .one_pass_signature => {
                has_one_pass = true;
                var algo_str: ?[]u8 = null;
                if (body) |b| {
                    if (b.len >= 4) {
                        const ha: HashAlgorithm = @enumFromInt(b[2]);
                        const pa: PublicKeyAlgorithm = @enumFromInt(b[3]);
                        algo_str = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ pa.name(), ha.name() });
                    }
                }
                try structure.layers.append(allocator, .{
                    .layer_type = .signature,
                    .algorithm = algo_str,
                    .details = try allocator.dupe(u8, "One-Pass Signature"),
                });
            },
            .signature => {
                has_signature = true;
                var algo_str: ?[]u8 = null;
                if (body) |b| {
                    if (b.len >= 4 and b[0] == 4) {
                        const pa: PublicKeyAlgorithm = @enumFromInt(b[2]);
                        const ha: HashAlgorithm = @enumFromInt(b[3]);
                        algo_str = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ pa.name(), ha.name() });
                    }
                }
                // Only add signature layer if not from one-pass (to avoid duplicating)
                if (!has_one_pass or !has_literal) {
                    try structure.layers.append(allocator, .{
                        .layer_type = .signature,
                        .algorithm = algo_str,
                        .details = try allocator.dupe(u8, "Signature"),
                    });
                } else {
                    if (algo_str) |a| allocator.free(a);
                }
            },
            .compressed_data => {
                has_compressed = true;
                var algo_str: ?[]u8 = null;
                if (body) |b| {
                    if (b.len >= 1) {
                        const ca: CompressionAlgorithm = @enumFromInt(b[0]);
                        algo_str = try allocator.dupe(u8, ca.name());
                    }
                }
                try structure.layers.append(allocator, .{
                    .layer_type = .compression,
                    .algorithm = algo_str,
                    .details = null,
                });
            },
            .literal_data => {
                has_literal = true;
                var details_str: ?[]u8 = null;
                if (body) |b| {
                    if (b.len >= 2) {
                        const fmt_byte = b[0];
                        const fmt_name: []const u8 = switch (fmt_byte) {
                            'b' => "binary",
                            't' => "text",
                            'u' => "UTF-8",
                            else => "unknown",
                        };
                        details_str = try std.fmt.allocPrint(allocator, "Format: {s}", .{fmt_name});
                    }
                }
                try structure.layers.append(allocator, .{
                    .layer_type = .literal_data,
                    .algorithm = null,
                    .details = details_str,
                });
            },
            else => {},
        }

        if (can_read) {
            fbs.pos += body_len;
        } else {
            break;
        }
    }

    // Determine message type
    structure.msg_type = classifyMessage(
        has_pkesk,
        has_skesk,
        has_seipd,
        has_sed,
        has_one_pass,
        has_signature,
        has_literal,
        has_compressed,
    );

    return structure;
}

fn classifyMessage(
    has_pkesk: bool,
    has_skesk: bool,
    has_seipd: bool,
    has_sed: bool,
    has_one_pass: bool,
    has_signature: bool,
    has_literal: bool,
    has_compressed: bool,
) MessageType {
    const has_encryption = has_pkesk or has_skesk or has_seipd or has_sed;
    const has_signing = has_one_pass or has_signature;

    if (has_encryption and has_signing) return .signed_encrypted;
    if (has_encryption) return .encrypted;
    if (has_compressed and has_signing) return .compressed_signed;
    if (has_signing) return .signed;
    if (has_compressed) return .compressed;
    if (has_literal) return .literal;
    return .unknown;
}

// ---------------------------------------------------------------------------
// Grammar validation
// ---------------------------------------------------------------------------

/// Validate that a packet sequence forms a valid OpenPGP message per
/// RFC 4880 Section 11.3.
pub fn validateMessageGrammar(allocator: Allocator, data: []const u8) !GrammarResult {
    const stripped = stripArmor(allocator, data);
    const binary = stripped.binary;
    defer freeArmorResult(allocator, stripped.decoded, stripped.headers);

    var result = GrammarResult{
        .valid = true,
        .errors = .empty,
    };
    errdefer result.deinit(allocator);

    // Collect packet tags in order
    var tags: std.ArrayList(PacketTag) = .empty;
    defer tags.deinit(allocator);

    var fbs = std.io.fixedBufferStream(binary);
    const rdr = fbs.reader();

    while (true) {
        const hdr = header_mod.readHeader(rdr) catch break;
        const body_len: u32 = switch (hdr.body_length) {
            .fixed => |len| len,
            .partial => |len| len,
            .indeterminate => 0,
        };

        try tags.append(allocator, hdr.tag);

        if (body_len > 0 and fbs.pos + body_len <= binary.len) {
            fbs.pos += body_len;
        } else {
            break;
        }
    }

    if (tags.items.len == 0) {
        result.valid = false;
        try result.errors.append(allocator, try allocator.dupe(u8, "No packets found"));
        return result;
    }

    // Validate the packet sequence
    try validatePacketSequence(allocator, tags.items, &result);

    return result;
}

fn validatePacketSequence(allocator: Allocator, tags: []const PacketTag, result: *GrammarResult) !void {
    if (tags.len == 0) return;

    const first = tags[0];

    switch (first) {
        // Encrypted message: (PKESK | SKESK)+ (SED | SEIPD)
        .public_key_encrypted_session_key, .symmetric_key_encrypted_session_key => {
            try validateEncryptedMessage(allocator, tags, result);
        },

        // Signed message with one-pass: OPS+ Literal Sig+
        .one_pass_signature => {
            try validateOnePassSigned(allocator, tags, result);
        },

        // Signed message with prepended signature: Sig+ Literal
        .signature => {
            try validatePrependedSigned(allocator, tags, result);
        },

        // Compressed message
        .compressed_data => {
            if (tags.len != 1) {
                // Compressed data should be a single packet (contents are inside)
                // Additional packets after are allowed in some implementations
            }
        },

        // Literal data only
        .literal_data => {
            if (tags.len > 1) {
                // Check for trailing packets
                for (tags[1..]) |tag| {
                    if (tag != .padding and tag != .trust) {
                        result.valid = false;
                        try result.errors.append(allocator,
                            try std.fmt.allocPrint(allocator,
                                "Unexpected packet after literal data: {s}", .{tag.name()}));
                    }
                }
            }
        },

        // Marker packet (allowed at the start, skip it)
        .marker => {
            if (tags.len > 1) {
                try validatePacketSequence(allocator, tags[1..], result);
            }
        },

        else => {
            result.valid = false;
            try result.errors.append(allocator,
                try std.fmt.allocPrint(allocator,
                    "Message cannot start with {s} packet", .{first.name()}));
        },
    }
}

fn validateEncryptedMessage(allocator: Allocator, tags: []const PacketTag, result: *GrammarResult) !void {
    var idx: usize = 0;

    // Consume session key packets
    while (idx < tags.len) {
        if (tags[idx] == .public_key_encrypted_session_key or
            tags[idx] == .symmetric_key_encrypted_session_key)
        {
            idx += 1;
        } else {
            break;
        }
    }

    if (idx == 0) {
        result.valid = false;
        try result.errors.append(allocator,
            try allocator.dupe(u8, "Encrypted message must start with PKESK or SKESK"));
        return;
    }

    // Must be followed by SED or SEIPD
    if (idx >= tags.len) {
        result.valid = false;
        try result.errors.append(allocator,
            try allocator.dupe(u8, "Encrypted message missing encrypted data packet (SED or SEIPD)"));
        return;
    }

    if (tags[idx] != .sym_encrypted_integrity_protected_data and
        tags[idx] != .symmetrically_encrypted_data and
        tags[idx] != .aead_encrypted_data)
    {
        result.valid = false;
        try result.errors.append(allocator,
            try std.fmt.allocPrint(allocator,
                "Expected SED/SEIPD after session key packets, got {s}", .{tags[idx].name()}));
        return;
    }

    // Legacy SED warning
    if (tags[idx] == .symmetrically_encrypted_data) {
        try result.errors.append(allocator,
            try allocator.dupe(u8, "Warning: Legacy SED without integrity protection"));
    }

    idx += 1;

    // Remaining packets should only be padding/trust or nothing
    while (idx < tags.len) {
        if (tags[idx] != .padding and tags[idx] != .trust) {
            result.valid = false;
            try result.errors.append(allocator,
                try std.fmt.allocPrint(allocator,
                    "Unexpected packet after encrypted data: {s}", .{tags[idx].name()}));
        }
        idx += 1;
    }
}

fn validateOnePassSigned(allocator: Allocator, tags: []const PacketTag, result: *GrammarResult) !void {
    var idx: usize = 0;
    var one_pass_count: usize = 0;

    // Consume one-pass signature packets
    while (idx < tags.len and tags[idx] == .one_pass_signature) {
        one_pass_count += 1;
        idx += 1;
    }

    // Must be followed by literal data (or compressed data)
    if (idx >= tags.len) {
        result.valid = false;
        try result.errors.append(allocator,
            try allocator.dupe(u8, "One-pass signed message missing data packet"));
        return;
    }

    if (tags[idx] != .literal_data and tags[idx] != .compressed_data) {
        result.valid = false;
        try result.errors.append(allocator,
            try std.fmt.allocPrint(allocator,
                "Expected literal or compressed data after one-pass signature, got {s}", .{tags[idx].name()}));
        return;
    }
    idx += 1;

    // Must be followed by matching number of signature packets
    var sig_count: usize = 0;
    while (idx < tags.len and tags[idx] == .signature) {
        sig_count += 1;
        idx += 1;
    }

    if (sig_count == 0) {
        result.valid = false;
        try result.errors.append(allocator,
            try allocator.dupe(u8, "One-pass signed message missing trailing signature packet(s)"));
    } else if (sig_count != one_pass_count) {
        // This is a warning, not necessarily invalid
        try result.errors.append(allocator,
            try std.fmt.allocPrint(allocator,
                "Warning: {d} one-pass signature(s) but {d} trailing signature(s)", .{ one_pass_count, sig_count }));
    }

    // Check for trailing junk
    while (idx < tags.len) {
        if (tags[idx] != .padding and tags[idx] != .trust) {
            result.valid = false;
            try result.errors.append(allocator,
                try std.fmt.allocPrint(allocator,
                    "Unexpected packet after signed message: {s}", .{tags[idx].name()}));
        }
        idx += 1;
    }
}

fn validatePrependedSigned(allocator: Allocator, tags: []const PacketTag, result: *GrammarResult) !void {
    var idx: usize = 0;

    // Consume signature packets
    while (idx < tags.len and tags[idx] == .signature) {
        idx += 1;
    }

    // Must be followed by literal data or compressed data
    if (idx >= tags.len) {
        // A standalone signature (no data) is valid in some contexts
        return;
    }

    if (tags[idx] != .literal_data and tags[idx] != .compressed_data) {
        result.valid = false;
        try result.errors.append(allocator,
            try std.fmt.allocPrint(allocator,
                "Expected literal or compressed data after signature, got {s}", .{tags[idx].name()}));
        return;
    }
    idx += 1;

    // Check for trailing packets
    while (idx < tags.len) {
        if (tags[idx] != .padding and tags[idx] != .trust and tags[idx] != .signature) {
            result.valid = false;
            try result.errors.append(allocator,
                try std.fmt.allocPrint(allocator,
                    "Unexpected packet after prepended-signed message: {s}", .{tags[idx].name()}));
        }
        idx += 1;
    }
}

// ---------------------------------------------------------------------------
// Armor helpers
// ---------------------------------------------------------------------------

fn stripArmor(allocator: Allocator, data: []const u8) struct { binary: []const u8, decoded: ?[]u8, headers: ?[]armor.Header } {
    if (data.len > 10 and mem.startsWith(u8, data, "-----BEGIN ")) {
        const result = armor.decode(allocator, data) catch {
            return .{ .binary = data, .decoded = null, .headers = null };
        };
        return .{ .binary = result.data, .decoded = result.data, .headers = result.headers };
    }
    return .{ .binary = data, .decoded = null, .headers = null };
}

fn freeArmorResult(allocator: Allocator, decoded: ?[]u8, headers: ?[]armor.Header) void {
    if (decoded) |d| allocator.free(d);
    if (headers) |hdrs| {
        for (hdrs) |hdr| {
            allocator.free(hdr.name);
            allocator.free(hdr.value);
        }
        allocator.free(hdrs);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "MessageType names" {
    try std.testing.expectEqualStrings("Encrypted Message", MessageType.encrypted.name());
    try std.testing.expectEqualStrings("Signed Message", MessageType.signed.name());
    try std.testing.expectEqualStrings("Literal Data", MessageType.literal.name());
}

test "LayerType names" {
    try std.testing.expectEqualStrings("Public-Key Encryption", LayerType.public_key_encryption.name());
    try std.testing.expectEqualStrings("AEAD Encryption", LayerType.aead_encryption.name());
}

test "classifyMessage encrypted" {
    try std.testing.expectEqual(MessageType.encrypted,
        classifyMessage(true, false, true, false, false, false, false, false));
}

test "classifyMessage signed" {
    try std.testing.expectEqual(MessageType.signed,
        classifyMessage(false, false, false, false, true, false, true, false));
}

test "classifyMessage literal" {
    try std.testing.expectEqual(MessageType.literal,
        classifyMessage(false, false, false, false, false, false, true, false));
}

test "classifyMessage compressed" {
    try std.testing.expectEqual(MessageType.compressed,
        classifyMessage(false, false, false, false, false, false, false, true));
}

test "classifyMessage signed_encrypted" {
    try std.testing.expectEqual(MessageType.signed_encrypted,
        classifyMessage(true, false, true, false, true, false, true, false));
}

test "validateMessageGrammar on empty data" {
    const allocator = std.testing.allocator;
    var result = try validateMessageGrammar(allocator, "");
    defer result.deinit(allocator);

    try std.testing.expect(!result.valid);
    try std.testing.expect(result.errors.items.len > 0);
}

test "validateMessageGrammar on literal data" {
    const allocator = std.testing.allocator;

    var buf: [32]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();

    // Literal data packet
    w.writeByte(0xCB) catch unreachable; // tag 11
    w.writeByte(7) catch unreachable;
    w.writeByte('t') catch unreachable;
    w.writeByte(0) catch unreachable;
    w.writeInt(u32, 0, .big) catch unreachable;
    w.writeByte('X') catch unreachable;

    const written = wfbs.getWritten();
    var result = try validateMessageGrammar(allocator, written);
    defer result.deinit(allocator);

    try std.testing.expect(result.valid);
}

test "validateMessageGrammar on encrypted message" {
    const allocator = std.testing.allocator;

    var buf: [32]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();

    // SKESK v4
    w.writeByte(0xC0 | 3) catch unreachable;
    w.writeByte(4) catch unreachable;
    w.writeByte(4) catch unreachable;
    w.writeByte(9) catch unreachable;
    w.writeByte(0) catch unreachable;
    w.writeByte(0) catch unreachable;

    // SEIPD v1
    w.writeByte(0xC0 | 18) catch unreachable;
    w.writeByte(3) catch unreachable;
    w.writeByte(1) catch unreachable;
    w.writeByte(0) catch unreachable;
    w.writeByte(0) catch unreachable;

    const written = wfbs.getWritten();
    var result = try validateMessageGrammar(allocator, written);
    defer result.deinit(allocator);

    try std.testing.expect(result.valid);
}

test "validateMessageGrammar on one-pass signed message" {
    const allocator = std.testing.allocator;

    var buf: [64]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();

    // One-Pass Signature
    w.writeByte(0xC0 | 4) catch unreachable;
    w.writeByte(13) catch unreachable;
    w.writeByte(3) catch unreachable;
    w.writeByte(0) catch unreachable;
    w.writeByte(8) catch unreachable;
    w.writeByte(1) catch unreachable;
    w.writeAll(&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }) catch unreachable;
    w.writeByte(1) catch unreachable;

    // Literal data
    w.writeByte(0xCB) catch unreachable;
    w.writeByte(7) catch unreachable;
    w.writeByte('t') catch unreachable;
    w.writeByte(0) catch unreachable;
    w.writeInt(u32, 0, .big) catch unreachable;
    w.writeByte('X') catch unreachable;

    // Signature (minimal v4)
    w.writeByte(0xC0 | 2) catch unreachable;
    w.writeByte(10) catch unreachable;
    w.writeAll(&[_]u8{ 4, 0, 1, 8, 0, 0, 0, 0, 0xAB, 0xCD }) catch unreachable;

    const written = wfbs.getWritten();
    var result = try validateMessageGrammar(allocator, written);
    defer result.deinit(allocator);

    try std.testing.expect(result.valid);
}

test "validateMessageGrammar rejects bad start" {
    const allocator = std.testing.allocator;

    var buf: [16]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();

    // Public key packet (not a valid message start)
    w.writeByte(0xC0 | 6) catch unreachable;
    w.writeByte(6) catch unreachable;
    w.writeByte(4) catch unreachable;
    w.writeInt(u32, 0, .big) catch unreachable;
    w.writeByte(1) catch unreachable;

    const written = wfbs.getWritten();
    var result = try validateMessageGrammar(allocator, written);
    defer result.deinit(allocator);

    try std.testing.expect(!result.valid);
}

test "analyzeMessageStructure on encrypted message" {
    const allocator = std.testing.allocator;

    var buf: [32]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();

    // PKESK v3
    w.writeByte(0xC0 | 1) catch unreachable;
    w.writeByte(11) catch unreachable;
    w.writeByte(3) catch unreachable;
    w.writeAll(&[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 }) catch unreachable;
    w.writeByte(1) catch unreachable; // RSA
    w.writeByte(0) catch unreachable;

    // SEIPD v1
    w.writeByte(0xC0 | 18) catch unreachable;
    w.writeByte(3) catch unreachable;
    w.writeByte(1) catch unreachable;
    w.writeByte(0) catch unreachable;
    w.writeByte(0) catch unreachable;

    const written = wfbs.getWritten();
    var structure = try analyzeMessageStructure(allocator, written);
    defer structure.deinit(allocator);

    try std.testing.expectEqual(MessageType.encrypted, structure.msg_type);
    try std.testing.expect(structure.layers.items.len >= 2);
}

test "MessageStructure format produces output" {
    const allocator = std.testing.allocator;
    var structure = MessageStructure{
        .msg_type = .encrypted,
        .layers = .empty,
    };
    defer structure.deinit(allocator);

    try structure.layers.append(allocator, .{
        .layer_type = .public_key_encryption,
        .algorithm = try allocator.dupe(u8, "RSA"),
        .details = try allocator.dupe(u8, "Key ID: AABBCCDD"),
    });

    const output = try structure.format(allocator);
    defer allocator.free(output);

    try std.testing.expect(output.len > 0);
    try std.testing.expect(mem.indexOf(u8, output, "Encrypted") != null);
}

test "GrammarResult deinit on empty" {
    const allocator = std.testing.allocator;
    var result = GrammarResult{
        .valid = true,
        .errors = .empty,
    };
    result.deinit(allocator);
}
