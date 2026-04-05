// SPDX-License-Identifier: MIT
//! Transferable key validation per RFC 4880 Section 11.1 and 11.2.
//!
//! Validates that a packet sequence forms a valid transferable public
//! or secret key. The expected structure is:
//!
//!   Transferable Public Key:
//!     Public-Key Packet
//!     [Revocation Signature]
//!     User ID Packet
//!       [Signature Packet (self-signature)]
//!       [Signature Packet (certifications)]
//!     [User ID Packet ...]
//!     [Public-Subkey Packet
//!       Signature Packet (binding)]
//!     [Public-Subkey Packet ...]
//!
//!   Transferable Secret Key:
//!     Secret-Key Packet
//!     [User ID Packet + Signatures ...]
//!     [Secret-Subkey Packet + Binding Signatures ...]

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const header_mod = @import("../packet/header.zig");
const PacketTag = @import("../packet/tags.zig").PacketTag;
const armor = @import("../armor/armor.zig");

/// Result of key structure validation.
pub const KeyValidation = struct {
    valid: bool,
    has_primary_key: bool,
    has_user_id: bool,
    has_self_signature: bool,
    user_id_count: u32,
    subkey_count: u32,
    signature_count: u32,
    errors: std.ArrayList([]const u8),
    warnings: std.ArrayList([]const u8),

    pub fn deinit(self: *KeyValidation, allocator: Allocator) void {
        for (self.errors.items) |e| allocator.free(e);
        self.errors.deinit(allocator);
        for (self.warnings.items) |w| allocator.free(w);
        self.warnings.deinit(allocator);
    }

    /// Format the validation result as a human-readable string.
    pub fn format(self: *const KeyValidation, allocator: Allocator) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);
        const w = buf.writer(allocator);

        try w.print("Key Validation Result: {s}\n", .{if (self.valid) "VALID" else "INVALID"});
        try w.print("  Primary key:      {s}\n", .{if (self.has_primary_key) "yes" else "no"});
        try w.print("  User ID:          {s} ({d} total)\n", .{ if (self.has_user_id) "yes" else "no", self.user_id_count });
        try w.print("  Self-signature:   {s}\n", .{if (self.has_self_signature) "yes" else "no"});
        try w.print("  Subkeys:          {d}\n", .{self.subkey_count});
        try w.print("  Signatures:       {d}\n", .{self.signature_count});

        if (self.errors.items.len > 0) {
            try w.print("\n  Errors:\n", .{});
            for (self.errors.items, 0..) |err_msg, i| {
                try w.print("    {d}. {s}\n", .{ i + 1, err_msg });
            }
        }

        if (self.warnings.items.len > 0) {
            try w.print("\n  Warnings:\n", .{});
            for (self.warnings.items, 0..) |warn, i| {
                try w.print("    {d}. {s}\n", .{ i + 1, warn });
            }
        }

        return buf.toOwnedSlice(allocator);
    }
};

/// Transferable key validator.
pub const TransferableKeyValidator = struct {
    /// Validate a transferable key (public or secret, auto-detected).
    pub fn validate(allocator: Allocator, data: []const u8) !KeyValidation {
        const stripped = stripArmor(allocator, data);
        const binary = stripped.binary;
        defer freeArmorResult(allocator, stripped.decoded, stripped.headers);

        return try validateBinary(allocator, binary, false);
    }

    /// Validate specifically as a transferable public key.
    pub fn validatePublicKey(allocator: Allocator, data: []const u8) !KeyValidation {
        const stripped = stripArmor(allocator, data);
        const binary = stripped.binary;
        defer freeArmorResult(allocator, stripped.decoded, stripped.headers);

        return try validateBinary(allocator, binary, false);
    }

    /// Validate specifically as a transferable secret key.
    pub fn validateSecretKey(allocator: Allocator, data: []const u8) !KeyValidation {
        const stripped = stripArmor(allocator, data);
        const binary = stripped.binary;
        defer freeArmorResult(allocator, stripped.decoded, stripped.headers);

        return try validateBinary(allocator, binary, true);
    }
};

fn validateBinary(allocator: Allocator, binary: []const u8, expect_secret: bool) !KeyValidation {
    var validation = KeyValidation{
        .valid = true,
        .has_primary_key = false,
        .has_user_id = false,
        .has_self_signature = false,
        .user_id_count = 0,
        .subkey_count = 0,
        .signature_count = 0,
        .errors = .empty,
        .warnings = .empty,
    };
    errdefer validation.deinit(allocator);

    // Collect packet tags and their bodies
    var tags: std.ArrayList(PacketTag) = .empty;
    defer tags.deinit(allocator);

    var fbs = std.io.fixedBufferStream(binary);
    const rdr = fbs.reader();

    // State tracking
    var seen_primary = false;
    var seen_uid = false;
    var last_was_uid = false;
    var last_was_subkey = false;
    var seen_sig_after_uid = false;
    var seen_sig_after_subkey = false;
    var key_version: u8 = 0;

    while (true) {
        const hdr = header_mod.readHeader(rdr) catch break;
        const body_len: u32 = switch (hdr.body_length) {
            .fixed => |len| len,
            .partial => |len| len,
            .indeterminate => 0,
        };

        const can_read = body_len > 0 and fbs.pos + body_len <= binary.len;
        const body: ?[]const u8 = if (can_read) binary[fbs.pos .. fbs.pos + body_len] else null;

        try tags.append(allocator, hdr.tag);

        switch (hdr.tag) {
            .public_key => {
                if (expect_secret) {
                    validation.valid = false;
                    try validation.errors.append(allocator,
                        try allocator.dupe(u8, "Expected secret key packet, found public key"));
                }
                if (seen_primary) {
                    validation.valid = false;
                    try validation.errors.append(allocator,
                        try allocator.dupe(u8, "Multiple primary key packets found"));
                }
                seen_primary = true;
                validation.has_primary_key = true;
                if (body) |b| {
                    if (b.len >= 1) key_version = b[0];
                }
                last_was_uid = false;
                last_was_subkey = false;
            },
            .secret_key => {
                if (!expect_secret and seen_primary) {
                    validation.valid = false;
                    try validation.errors.append(allocator,
                        try allocator.dupe(u8, "Multiple primary key packets found"));
                }
                seen_primary = true;
                validation.has_primary_key = true;
                if (body) |b| {
                    if (b.len >= 1) key_version = b[0];
                }
                last_was_uid = false;
                last_was_subkey = false;
            },
            .user_id => {
                if (!seen_primary) {
                    validation.valid = false;
                    try validation.errors.append(allocator,
                        try allocator.dupe(u8, "User ID packet before primary key"));
                }
                seen_uid = true;
                validation.has_user_id = true;
                validation.user_id_count += 1;
                last_was_uid = true;
                last_was_subkey = false;
                seen_sig_after_uid = false;
            },
            .user_attribute => {
                if (!seen_primary) {
                    validation.valid = false;
                    try validation.errors.append(allocator,
                        try allocator.dupe(u8, "User attribute packet before primary key"));
                }
                last_was_uid = true; // Treat user attribute like user ID for signature binding
                last_was_subkey = false;
                seen_sig_after_uid = false;
            },
            .signature => {
                validation.signature_count += 1;
                if (last_was_uid and !seen_sig_after_uid) {
                    seen_sig_after_uid = true;
                    // Check if this is a self-signature
                    if (body) |b| {
                        if (b.len >= 2 and b[0] == 4) {
                            const sig_type = b[1];
                            if (sig_type >= 0x10 and sig_type <= 0x13) {
                                validation.has_self_signature = true;
                            }
                        }
                    }
                }
                if (last_was_subkey and !seen_sig_after_subkey) {
                    seen_sig_after_subkey = true;
                }
            },
            .public_subkey, .secret_subkey => {
                if (!seen_primary) {
                    validation.valid = false;
                    try validation.errors.append(allocator,
                        try allocator.dupe(u8, "Subkey packet before primary key"));
                }
                validation.subkey_count += 1;
                last_was_uid = false;
                last_was_subkey = true;
                seen_sig_after_subkey = false;
            },
            .trust => {
                // Trust packets are implementation-specific and can appear anywhere
            },
            else => {
                // Unexpected packet types
                try validation.warnings.append(allocator,
                    try std.fmt.allocPrint(allocator,
                        "Unexpected packet in key: {s}", .{hdr.tag.name()}));
            },
        }

        if (can_read) {
            fbs.pos += body_len;
        } else {
            break;
        }
    }

    // Post-validation checks
    if (!validation.has_primary_key) {
        validation.valid = false;
        try validation.errors.append(allocator,
            try allocator.dupe(u8, "No primary key packet found"));
    }

    if (!validation.has_user_id) {
        validation.valid = false;
        try validation.errors.append(allocator,
            try allocator.dupe(u8, "No user ID packet found (required by RFC 4880)"));
    }

    if (!validation.has_self_signature and validation.has_user_id) {
        try validation.warnings.append(allocator,
            try allocator.dupe(u8, "No self-signature found on user ID (key may not be verifiable)"));
    }

    // Check version
    if (key_version == 3) {
        try validation.warnings.append(allocator,
            try allocator.dupe(u8, "V3 key format is deprecated; use V4 or V6"));
    }

    // Check subkey binding
    if (validation.subkey_count > 0 and !seen_sig_after_subkey) {
        try validation.warnings.append(allocator,
            try allocator.dupe(u8, "Subkey found without binding signature"));
    }

    return validation;
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

test "KeyValidation deinit on empty" {
    const allocator = std.testing.allocator;
    var kv = KeyValidation{
        .valid = true,
        .has_primary_key = false,
        .has_user_id = false,
        .has_self_signature = false,
        .user_id_count = 0,
        .subkey_count = 0,
        .signature_count = 0,
        .errors = .empty,
        .warnings = .empty,
    };
    kv.deinit(allocator);
}

test "validate empty data" {
    const allocator = std.testing.allocator;
    var result = try TransferableKeyValidator.validate(allocator, "");
    defer result.deinit(allocator);

    try std.testing.expect(!result.valid);
    try std.testing.expect(!result.has_primary_key);
}

test "validate minimal valid key structure" {
    const allocator = std.testing.allocator;

    var buf: [64]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();

    // Public key packet (tag 6)
    w.writeByte(0xC0 | 6) catch unreachable;
    w.writeByte(6) catch unreachable;
    w.writeByte(4) catch unreachable; // v4
    w.writeInt(u32, 1700000000, .big) catch unreachable;
    w.writeByte(1) catch unreachable; // RSA

    // User ID packet (tag 13)
    w.writeByte(0xC0 | 13) catch unreachable;
    w.writeByte(5) catch unreachable;
    w.writeAll("Alice") catch unreachable;

    // Signature packet (tag 2) - self-signature
    w.writeByte(0xC0 | 2) catch unreachable;
    w.writeByte(10) catch unreachable;
    w.writeAll(&[_]u8{ 4, 0x13, 1, 8, 0, 0, 0, 0, 0xAB, 0xCD }) catch unreachable;

    const written = wfbs.getWritten();
    var result = try TransferableKeyValidator.validate(allocator, written);
    defer result.deinit(allocator);

    try std.testing.expect(result.valid);
    try std.testing.expect(result.has_primary_key);
    try std.testing.expect(result.has_user_id);
    try std.testing.expect(result.has_self_signature);
    try std.testing.expectEqual(@as(u32, 1), result.user_id_count);
    try std.testing.expectEqual(@as(u32, 1), result.signature_count);
}

test "validate key with subkey" {
    const allocator = std.testing.allocator;

    var buf: [96]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();

    // Public key
    w.writeByte(0xC0 | 6) catch unreachable;
    w.writeByte(6) catch unreachable;
    w.writeByte(4) catch unreachable;
    w.writeInt(u32, 1700000000, .big) catch unreachable;
    w.writeByte(1) catch unreachable;

    // User ID
    w.writeByte(0xC0 | 13) catch unreachable;
    w.writeByte(3) catch unreachable;
    w.writeAll("Bob") catch unreachable;

    // Self-signature
    w.writeByte(0xC0 | 2) catch unreachable;
    w.writeByte(10) catch unreachable;
    w.writeAll(&[_]u8{ 4, 0x13, 1, 8, 0, 0, 0, 0, 0xAB, 0xCD }) catch unreachable;

    // Public subkey
    w.writeByte(0xC0 | 14) catch unreachable;
    w.writeByte(6) catch unreachable;
    w.writeByte(4) catch unreachable;
    w.writeInt(u32, 1700000001, .big) catch unreachable;
    w.writeByte(1) catch unreachable;

    // Subkey binding signature
    w.writeByte(0xC0 | 2) catch unreachable;
    w.writeByte(10) catch unreachable;
    w.writeAll(&[_]u8{ 4, 0x18, 1, 8, 0, 0, 0, 0, 0xEF, 0x01 }) catch unreachable;

    const written = wfbs.getWritten();
    var result = try TransferableKeyValidator.validate(allocator, written);
    defer result.deinit(allocator);

    try std.testing.expect(result.valid);
    try std.testing.expectEqual(@as(u32, 1), result.subkey_count);
    try std.testing.expectEqual(@as(u32, 2), result.signature_count);
}

test "validate rejects key without user ID" {
    const allocator = std.testing.allocator;

    var buf: [16]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();

    // Public key only - no user ID
    w.writeByte(0xC0 | 6) catch unreachable;
    w.writeByte(6) catch unreachable;
    w.writeByte(4) catch unreachable;
    w.writeInt(u32, 1700000000, .big) catch unreachable;
    w.writeByte(1) catch unreachable;

    const written = wfbs.getWritten();
    var result = try TransferableKeyValidator.validate(allocator, written);
    defer result.deinit(allocator);

    try std.testing.expect(!result.valid);
    try std.testing.expect(!result.has_user_id);
}

test "validate secret key" {
    const allocator = std.testing.allocator;

    var buf: [64]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();

    // Secret key packet (tag 5)
    w.writeByte(0xC0 | 5) catch unreachable;
    w.writeByte(6) catch unreachable;
    w.writeByte(4) catch unreachable;
    w.writeInt(u32, 1700000000, .big) catch unreachable;
    w.writeByte(1) catch unreachable;

    // User ID
    w.writeByte(0xC0 | 13) catch unreachable;
    w.writeByte(5) catch unreachable;
    w.writeAll("Alice") catch unreachable;

    // Self-signature
    w.writeByte(0xC0 | 2) catch unreachable;
    w.writeByte(10) catch unreachable;
    w.writeAll(&[_]u8{ 4, 0x13, 1, 8, 0, 0, 0, 0, 0xAB, 0xCD }) catch unreachable;

    const written = wfbs.getWritten();
    var result = try TransferableKeyValidator.validateSecretKey(allocator, written);
    defer result.deinit(allocator);

    try std.testing.expect(result.valid);
    try std.testing.expect(result.has_primary_key);
}

test "validate rejects UID before primary" {
    const allocator = std.testing.allocator;

    var buf: [32]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();

    // User ID first (wrong order)
    w.writeByte(0xC0 | 13) catch unreachable;
    w.writeByte(5) catch unreachable;
    w.writeAll("Alice") catch unreachable;

    // Then public key
    w.writeByte(0xC0 | 6) catch unreachable;
    w.writeByte(6) catch unreachable;
    w.writeByte(4) catch unreachable;
    w.writeInt(u32, 0, .big) catch unreachable;
    w.writeByte(1) catch unreachable;

    const written = wfbs.getWritten();
    var result = try TransferableKeyValidator.validate(allocator, written);
    defer result.deinit(allocator);

    try std.testing.expect(!result.valid);
}

test "format produces readable output" {
    const allocator = std.testing.allocator;
    var kv = KeyValidation{
        .valid = true,
        .has_primary_key = true,
        .has_user_id = true,
        .has_self_signature = true,
        .user_id_count = 1,
        .subkey_count = 2,
        .signature_count = 3,
        .errors = .empty,
        .warnings = .empty,
    };
    defer kv.deinit(allocator);

    const output = try kv.format(allocator);
    defer allocator.free(output);

    try std.testing.expect(output.len > 0);
    try std.testing.expect(mem.indexOf(u8, output, "VALID") != null);
}
