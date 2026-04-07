// SPDX-License-Identifier: MIT
//! Message validation module.
//!
//! Validates the structure, encryption, and signature properties of
//! OpenPGP messages without performing full cryptographic operations.
//! This is useful for pre-flight checks, policy enforcement, and
//! diagnostic reporting.
//!
//! The validator checks:
//!   - Packet structure integrity (valid headers, consistent lengths)
//!   - Encryption method and algorithm strength
//!   - Signature presence and algorithm acceptability
//!   - AEAD usage and integrity protection
//!   - Recipient count and key references

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const enums = @import("../types/enums.zig");
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const AeadAlgorithm = enums.AeadAlgorithm;

const PacketTag = @import("../packet/tags.zig").PacketTag;
const algo_policy = @import("../policy/algorithm_policy.zig");
const AlgorithmPolicy = algo_policy.AlgorithmPolicy;
const PolicyLevel = algo_policy.PolicyLevel;

// =========================================================================
// Validation result types
// =========================================================================

/// Validation of encryption properties.
pub const EncryptionValidation = struct {
    /// Symmetric algorithm used (if detectable from SKESK/SEIPD headers).
    sym_algo: ?SymmetricAlgorithm,
    /// Whether the symmetric algorithm is considered secure.
    sym_algo_secure: bool,
    /// Whether integrity protection is present (MDC or AEAD).
    has_integrity: bool,
    /// Whether AEAD encryption is used (SEIPDv2).
    uses_aead: bool,
    /// Number of PKESK recipients.
    recipient_count: u32,
    /// Whether a password (SKESK) recipient is present.
    has_password: bool,
};

/// Validation of signature properties.
pub const SignatureValidation = struct {
    /// Number of signature packets found.
    sig_count: u32,
    /// Hash algorithm used (from the first signature found).
    hash_algo: ?HashAlgorithm,
    /// Whether the hash algorithm is considered secure.
    hash_algo_secure: bool,
    /// Public key algorithm used (from the first signature found).
    pub_algo: ?PublicKeyAlgorithm,
};

/// Complete message validation result.
pub const MessageValidation = struct {
    /// Whether the message has a valid OpenPGP structure.
    valid_structure: bool,
    /// Whether the message is encrypted.
    is_encrypted: bool,
    /// Whether the message is signed.
    is_signed: bool,
    /// Encryption validation details (if encrypted).
    encryption: ?EncryptionValidation,
    /// Signature validation details (if signed).
    signature: ?SignatureValidation,
    /// Warning messages.
    warnings: std.ArrayList([]const u8),

    /// Free all memory.
    pub fn deinit(self: *MessageValidation, allocator: Allocator) void {
        for (self.warnings.items) |w| allocator.free(w);
        self.warnings.deinit(allocator);
    }

    /// Format the validation result as a human-readable string.
    pub fn format(self: *const MessageValidation, allocator: Allocator) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);
        const w = buf.writer(allocator);

        try w.writeAll("Message Validation Report\n");
        try w.writeAll("========================================\n");
        try w.print("Structure:  {s}\n", .{if (self.valid_structure) "valid" else "INVALID"});
        try w.print("Encrypted:  {s}\n", .{if (self.is_encrypted) "yes" else "no"});
        try w.print("Signed:     {s}\n", .{if (self.is_signed) "yes" else "no"});

        if (self.encryption) |enc| {
            try w.writeAll("\nEncryption Details:\n");
            if (enc.sym_algo) |algo| {
                try w.print("  Algorithm:    {s} ({s})\n", .{
                    algo.name(),
                    if (enc.sym_algo_secure) "secure" else "WEAK",
                });
            }
            try w.print("  Integrity:    {s}\n", .{if (enc.has_integrity) "yes" else "NO"});
            try w.print("  AEAD:         {s}\n", .{if (enc.uses_aead) "yes" else "no"});
            try w.print("  Recipients:   {d}\n", .{enc.recipient_count});
            try w.print("  Has Password: {s}\n", .{if (enc.has_password) "yes" else "no"});
        }

        if (self.signature) |sig| {
            try w.writeAll("\nSignature Details:\n");
            try w.print("  Signatures:   {d}\n", .{sig.sig_count});
            if (sig.hash_algo) |algo| {
                try w.print("  Hash:         {s} ({s})\n", .{
                    algo.name(),
                    if (sig.hash_algo_secure) "secure" else "WEAK",
                });
            }
            if (sig.pub_algo) |algo| {
                try w.print("  Pub Key Algo: {s}\n", .{algo.name()});
            }
        }

        if (self.warnings.items.len > 0) {
            try w.print("\nWarnings ({d}):\n", .{self.warnings.items.len});
            for (self.warnings.items, 0..) |warning, i| {
                try w.print("  {d}. {s}\n", .{ i + 1, warning });
            }
        }

        return buf.toOwnedSlice(allocator);
    }
};

// =========================================================================
// Message validator
// =========================================================================

/// Validates OpenPGP messages for structural integrity and policy compliance.
pub const MessageValidator = struct {
    policy: AlgorithmPolicy,

    /// Create a new message validator with the given policy.
    pub fn init(policy_level: PolicyLevel) MessageValidator {
        return .{ .policy = AlgorithmPolicy.init(policy_level) };
    }

    /// Validate an OpenPGP message (encrypted, signed, or both).
    pub fn validateMessage(
        self: MessageValidator,
        allocator: Allocator,
        data: []const u8,
    ) !MessageValidation {
        var result = MessageValidation{
            .valid_structure = true,
            .is_encrypted = false,
            .is_signed = false,
            .encryption = null,
            .signature = null,
            .warnings = .empty,
        };
        errdefer result.deinit(allocator);

        if (data.len == 0) {
            result.valid_structure = false;
            try result.warnings.append(allocator, try allocator.dupe(u8, "Message data is empty"));
            return result;
        }

        // Verify the first byte is a valid OpenPGP packet.
        if (data[0] & 0x80 == 0) {
            result.valid_structure = false;
            try result.warnings.append(allocator, try allocator.dupe(u8, "Data does not start with a valid OpenPGP packet"));
            return result;
        }

        // Scan all packets in the message.
        var enc_info = EncryptionInfo{};
        var sig_info = SignatureInfo{};

        var offset: usize = 0;
        while (offset < data.len) {
            if (data[offset] & 0x80 == 0) {
                result.valid_structure = false;
                try result.warnings.append(
                    allocator,
                    try std.fmt.allocPrint(allocator, "Invalid packet header at offset {d}", .{offset}),
                );
                break;
            }

            const is_new = (data[offset] & 0x40) != 0;
            const tag_val: u8 = if (is_new) (data[offset] & 0x3F) else ((data[offset] & 0x3C) >> 2);

            self.processPacket(data, offset, is_new, tag_val, &enc_info, &sig_info);

            const pkt_len = getPacketLength(data[offset..], is_new);
            if (pkt_len == 0) {
                result.valid_structure = false;
                try result.warnings.append(
                    allocator,
                    try std.fmt.allocPrint(allocator, "Cannot determine packet length at offset {d}", .{offset}),
                );
                break;
            }
            offset += pkt_len;
        }

        // Build encryption validation.
        if (enc_info.has_encryption) {
            result.is_encrypted = true;
            const sym = enc_info.sym_algo;
            result.encryption = EncryptionValidation{
                .sym_algo = sym,
                .sym_algo_secure = if (sym) |a| self.policy.isAcceptableSymmetric(a) else true,
                .has_integrity = enc_info.has_integrity,
                .uses_aead = enc_info.uses_aead,
                .recipient_count = enc_info.pkesk_count,
                .has_password = enc_info.skesk_count > 0,
            };

            if (!enc_info.has_integrity) {
                try result.warnings.append(
                    allocator,
                    try allocator.dupe(u8, "Message lacks integrity protection (no MDC or AEAD)"),
                );
            }
        }

        // Build signature validation.
        if (sig_info.sig_count > 0) {
            result.is_signed = true;
            const hash = sig_info.hash_algo;
            result.signature = SignatureValidation{
                .sig_count = sig_info.sig_count,
                .hash_algo = hash,
                .hash_algo_secure = if (hash) |h| self.policy.isAcceptableHash(h) else true,
                .pub_algo = sig_info.pub_algo,
            };
        }

        return result;
    }

    /// Validate only the encryption aspects of a message.
    pub fn validateEncryptedMessage(
        self: MessageValidator,
        allocator: Allocator,
        data: []const u8,
    ) !EncryptionValidation {
        const full = try self.validateMessage(allocator, data);
        defer {
            var mutable = full;
            mutable.deinit(allocator);
        }
        return full.encryption orelse EncryptionValidation{
            .sym_algo = null,
            .sym_algo_secure = false,
            .has_integrity = false,
            .uses_aead = false,
            .recipient_count = 0,
            .has_password = false,
        };
    }

    /// Validate only the signature aspects of a message.
    pub fn validateSignedMessage(
        self: MessageValidator,
        allocator: Allocator,
        data: []const u8,
    ) !SignatureValidation {
        const full = try self.validateMessage(allocator, data);
        defer {
            var mutable = full;
            mutable.deinit(allocator);
        }
        return full.signature orelse SignatureValidation{
            .sig_count = 0,
            .hash_algo = null,
            .hash_algo_secure = false,
            .pub_algo = null,
        };
    }

    // -----------------------------------------------------------------
    // Internal processing
    // -----------------------------------------------------------------

    const EncryptionInfo = struct {
        has_encryption: bool = false,
        has_integrity: bool = false,
        uses_aead: bool = false,
        pkesk_count: u32 = 0,
        skesk_count: u32 = 0,
        sym_algo: ?SymmetricAlgorithm = null,
    };

    const SignatureInfo = struct {
        sig_count: u32 = 0,
        hash_algo: ?HashAlgorithm = null,
        pub_algo: ?PublicKeyAlgorithm = null,
    };

    fn processPacket(
        self: MessageValidator,
        data: []const u8,
        offset: usize,
        is_new: bool,
        tag_val: u8,
        enc_info: *EncryptionInfo,
        sig_info: *SignatureInfo,
    ) void {
        _ = self;
        switch (tag_val) {
            @intFromEnum(PacketTag.public_key_encrypted_session_key) => {
                enc_info.pkesk_count += 1;
                enc_info.has_encryption = true;

                // Try to extract the public key algorithm from the PKESK.
                const body_off = getBodyOffset(data[offset..], is_new);
                if (body_off) |bo| {
                    const abs = offset + bo;
                    // PKESK v3: version(1) + key_id(8) + algo(1)
                    if (abs + 10 <= data.len and data[abs] == 3) {
                        // Version 3 PKESK
                        _ = data[abs + 9]; // algorithm byte
                    }
                }
            },
            @intFromEnum(PacketTag.symmetric_key_encrypted_session_key) => {
                enc_info.skesk_count += 1;
                enc_info.has_encryption = true;

                // Try to extract the symmetric algorithm.
                const body_off = getBodyOffset(data[offset..], is_new);
                if (body_off) |bo| {
                    const abs = offset + bo;
                    // SKESK v4: version(1) + sym_algo(1) + s2k(...)
                    if (abs + 2 <= data.len and data[abs] == 4) {
                        enc_info.sym_algo = @enumFromInt(data[abs + 1]);
                    } else if (abs + 2 <= data.len and data[abs] == 6) {
                        // SKESK v6 has different layout
                        if (abs + 5 <= data.len) {
                            enc_info.sym_algo = @enumFromInt(data[abs + 3]);
                        }
                    }
                }
            },
            @intFromEnum(PacketTag.sym_encrypted_integrity_protected_data) => {
                enc_info.has_encryption = true;
                enc_info.has_integrity = true;

                // Check SEIPD version.
                const body_off = getBodyOffset(data[offset..], is_new);
                if (body_off) |bo| {
                    const abs = offset + bo;
                    if (abs < data.len) {
                        if (data[abs] == 2) {
                            enc_info.uses_aead = true;
                            // SEIPDv2: version(1) + sym_algo(1) + aead_algo(1)
                            if (abs + 2 <= data.len) {
                                enc_info.sym_algo = @enumFromInt(data[abs + 1]);
                            }
                        }
                    }
                }
            },
            @intFromEnum(PacketTag.symmetrically_encrypted_data) => {
                enc_info.has_encryption = true;
                // SED packets have NO integrity protection.
                enc_info.has_integrity = false;
            },
            @intFromEnum(PacketTag.signature) => {
                sig_info.sig_count += 1;

                const body_off = getBodyOffset(data[offset..], is_new);
                if (body_off) |bo| {
                    const abs = offset + bo;
                    if (abs + 5 <= data.len) {
                        const sig_ver = data[abs];
                        if (sig_ver == 4) {
                            // V4: version(1) + sig_type(1) + pub_algo(1) + hash_algo(1)
                            if (sig_info.hash_algo == null) {
                                sig_info.pub_algo = @enumFromInt(data[abs + 2]);
                                sig_info.hash_algo = @enumFromInt(data[abs + 3]);
                            }
                        } else if (sig_ver == 6) {
                            // V6: version(1) + sig_type(1) + pub_algo(1) + hash_algo(1)
                            if (sig_info.hash_algo == null) {
                                sig_info.pub_algo = @enumFromInt(data[abs + 2]);
                                sig_info.hash_algo = @enumFromInt(data[abs + 3]);
                            }
                        }
                    }
                }
            },
            @intFromEnum(PacketTag.one_pass_signature) => {
                sig_info.sig_count += 1;

                const body_off = getBodyOffset(data[offset..], is_new);
                if (body_off) |bo| {
                    const abs = offset + bo;
                    // OPS: version(1) + sig_type(1) + hash_algo(1) + pub_algo(1)
                    if (abs + 4 <= data.len) {
                        const ops_ver = data[abs];
                        if (ops_ver == 3 or ops_ver == 6) {
                            if (sig_info.hash_algo == null) {
                                sig_info.hash_algo = @enumFromInt(data[abs + 2]);
                                sig_info.pub_algo = @enumFromInt(data[abs + 3]);
                            }
                        }
                    }
                }
            },
            else => {},
        }
    }
};

// =========================================================================
// Packet parsing helpers
// =========================================================================

fn getBodyOffset(data: []const u8, is_new_format: bool) ?usize {
    if (data.len < 2) return null;

    if (is_new_format) {
        const len_byte = data[1];
        if (len_byte < 192) return 2;
        if (len_byte < 224) return 3;
        if (len_byte == 255) return 6;
        return null;
    } else {
        const len_type = data[0] & 0x03;
        return switch (len_type) {
            0 => 2,
            1 => 3,
            2 => 5,
            3 => null,
            else => null,
        };
    }
}

fn getPacketLength(data: []const u8, is_new_format: bool) usize {
    if (data.len < 2) return 0;

    if (is_new_format) {
        const len_byte = data[1];
        if (len_byte < 192) {
            return 2 + @as(usize, len_byte);
        }
        if (len_byte < 224 and data.len >= 3) {
            return 3 + (@as(usize, len_byte - 192) << 8) + @as(usize, data[2]) + 192;
        }
        if (len_byte == 255 and data.len >= 6) {
            return 6 + @as(usize, mem.readInt(u32, data[2..6], .big));
        }
        return 0;
    } else {
        const len_type = data[0] & 0x03;
        switch (len_type) {
            0 => return 2 + @as(usize, data[1]),
            1 => {
                if (data.len < 3) return 0;
                return 3 + @as(usize, mem.readInt(u16, data[1..3], .big));
            },
            2 => {
                if (data.len < 5) return 0;
                return 5 + @as(usize, mem.readInt(u32, data[1..5], .big));
            },
            else => return 0,
        }
    }
}

// =========================================================================
// Tests
// =========================================================================

test "message_validator: empty message" {
    const allocator = std.testing.allocator;
    const validator = MessageValidator.init(.rfc9580);

    var result = try validator.validateMessage(allocator, "");
    defer result.deinit(allocator);

    try std.testing.expect(!result.valid_structure);
    try std.testing.expect(!result.is_encrypted);
    try std.testing.expect(!result.is_signed);
}

test "message_validator: invalid packet header" {
    const allocator = std.testing.allocator;
    const validator = MessageValidator.init(.rfc9580);

    const data = [_]u8{ 0x00, 0x01 };
    var result = try validator.validateMessage(allocator, &data);
    defer result.deinit(allocator);

    try std.testing.expect(!result.valid_structure);
}

test "message_validator: SEIPD v1 message" {
    const allocator = std.testing.allocator;
    const validator = MessageValidator.init(.rfc9580);

    // Construct: PKESK (tag 1) + SEIPD (tag 18)
    var data: [20]u8 = undefined;

    // PKESK v3: new format, tag=1
    data[0] = 0xC0 | @intFromEnum(PacketTag.public_key_encrypted_session_key);
    data[1] = 8; // body length
    data[2] = 3; // version 3
    @memset(data[3..10], 0); // key_id + algo + padding

    // SEIPD v1: new format, tag=18
    data[10] = 0xC0 | @intFromEnum(PacketTag.sym_encrypted_integrity_protected_data);
    data[11] = 8; // body length
    data[12] = 1; // version 1
    @memset(data[13..20], 0); // padding

    var result = try validator.validateMessage(allocator, &data);
    defer result.deinit(allocator);

    try std.testing.expect(result.is_encrypted);
    try std.testing.expect(result.encryption != null);
    try std.testing.expect(result.encryption.?.has_integrity);
    try std.testing.expect(!result.encryption.?.uses_aead);
    try std.testing.expectEqual(@as(u32, 1), result.encryption.?.recipient_count);
}

test "message_validator: SEIPD v2 (AEAD) message" {
    const allocator = std.testing.allocator;
    const validator = MessageValidator.init(.rfc9580);

    // Construct: SKESK (tag 3) + SEIPDv2 (tag 18)
    var data: [20]u8 = undefined;

    // SKESK v4: new format, tag=3
    data[0] = 0xC0 | @intFromEnum(PacketTag.symmetric_key_encrypted_session_key);
    data[1] = 8;
    data[2] = 4; // version 4
    data[3] = @intFromEnum(SymmetricAlgorithm.aes256); // sym algo
    @memset(data[4..10], 0);

    // SEIPDv2: new format, tag=18
    data[10] = 0xC0 | @intFromEnum(PacketTag.sym_encrypted_integrity_protected_data);
    data[11] = 8;
    data[12] = 2; // version 2 (AEAD)
    data[13] = @intFromEnum(SymmetricAlgorithm.aes256); // sym algo
    @memset(data[14..20], 0);

    var result = try validator.validateMessage(allocator, &data);
    defer result.deinit(allocator);

    try std.testing.expect(result.is_encrypted);
    try std.testing.expect(result.encryption != null);
    try std.testing.expect(result.encryption.?.has_integrity);
    try std.testing.expect(result.encryption.?.uses_aead);
    try std.testing.expect(result.encryption.?.has_password);
    try std.testing.expect(result.encryption.?.sym_algo == .aes256);
}

test "message_validator: SED message (no integrity)" {
    const allocator = std.testing.allocator;
    const validator = MessageValidator.init(.rfc9580);

    // SED packet: tag=9
    var data: [12]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.symmetrically_encrypted_data);
    data[1] = 10;
    @memset(data[2..], 0);

    var result = try validator.validateMessage(allocator, &data);
    defer result.deinit(allocator);

    try std.testing.expect(result.is_encrypted);
    try std.testing.expect(result.encryption != null);
    try std.testing.expect(!result.encryption.?.has_integrity);
    try std.testing.expect(result.warnings.items.len > 0);
}

test "message_validator: signed message" {
    const allocator = std.testing.allocator;
    const validator = MessageValidator.init(.rfc9580);

    // One-pass signature + literal data + signature
    var data: [30]u8 = undefined;

    // OPS: new format, tag=4
    data[0] = 0xC0 | @intFromEnum(PacketTag.one_pass_signature);
    data[1] = 8;
    data[2] = 3; // version 3
    data[3] = 0; // sig type (binary)
    data[4] = @intFromEnum(HashAlgorithm.sha256); // hash algo
    data[5] = @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign); // pub algo
    @memset(data[6..10], 0);

    // Literal data: tag=11
    data[10] = 0xC0 | @intFromEnum(PacketTag.literal_data);
    data[11] = 8;
    @memset(data[12..20], 0);

    // Signature: tag=2
    data[20] = 0xC0 | @intFromEnum(PacketTag.signature);
    data[21] = 8;
    data[22] = 4; // version 4
    data[23] = 0; // sig type
    data[24] = @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign);
    data[25] = @intFromEnum(HashAlgorithm.sha256);
    @memset(data[26..30], 0);

    var result = try validator.validateMessage(allocator, &data);
    defer result.deinit(allocator);

    try std.testing.expect(result.is_signed);
    try std.testing.expect(result.signature != null);
    // OPS + sig = 2
    try std.testing.expectEqual(@as(u32, 2), result.signature.?.sig_count);
    try std.testing.expect(result.signature.?.hash_algo == .sha256);
}

test "message_validator: validateEncryptedMessage returns defaults for non-encrypted" {
    const allocator = std.testing.allocator;
    const validator = MessageValidator.init(.rfc9580);

    // Literal data only (not encrypted)
    var data: [12]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.literal_data);
    data[1] = 10;
    @memset(data[2..], 0);

    const enc = try validator.validateEncryptedMessage(allocator, &data);
    try std.testing.expect(!enc.has_integrity);
    try std.testing.expect(!enc.uses_aead);
    try std.testing.expectEqual(@as(u32, 0), enc.recipient_count);
}

test "message_validator: validateSignedMessage returns defaults for unsigned" {
    const allocator = std.testing.allocator;
    const validator = MessageValidator.init(.rfc9580);

    // Literal data only (not signed)
    var data: [12]u8 = undefined;
    data[0] = 0xC0 | @intFromEnum(PacketTag.literal_data);
    data[1] = 10;
    @memset(data[2..], 0);

    const sig = try validator.validateSignedMessage(allocator, &data);
    try std.testing.expectEqual(@as(u32, 0), sig.sig_count);
    try std.testing.expect(sig.hash_algo == null);
}

test "message_validator: MessageValidation format" {
    const allocator = std.testing.allocator;

    var result = MessageValidation{
        .valid_structure = true,
        .is_encrypted = true,
        .is_signed = false,
        .encryption = EncryptionValidation{
            .sym_algo = .aes256,
            .sym_algo_secure = true,
            .has_integrity = true,
            .uses_aead = true,
            .recipient_count = 2,
            .has_password = false,
        },
        .signature = null,
        .warnings = .empty,
    };
    defer result.deinit(allocator);

    const formatted = try result.format(allocator);
    defer allocator.free(formatted);

    try std.testing.expect(mem.indexOf(u8, formatted, "Encrypted:  yes") != null);
    try std.testing.expect(mem.indexOf(u8, formatted, "AES-256") != null);
    try std.testing.expect(mem.indexOf(u8, formatted, "AEAD:         yes") != null);
    try std.testing.expect(mem.indexOf(u8, formatted, "Recipients:   2") != null);
}

test "message_validator: multiple PKESK recipients" {
    const allocator = std.testing.allocator;
    const validator = MessageValidator.init(.rfc9580);

    // Two PKESK packets + SEIPD
    var data: [30]u8 = undefined;

    // PKESK 1
    data[0] = 0xC0 | @intFromEnum(PacketTag.public_key_encrypted_session_key);
    data[1] = 8;
    data[2] = 3;
    @memset(data[3..10], 0);

    // PKESK 2
    data[10] = 0xC0 | @intFromEnum(PacketTag.public_key_encrypted_session_key);
    data[11] = 8;
    data[12] = 3;
    @memset(data[13..20], 0);

    // SEIPD
    data[20] = 0xC0 | @intFromEnum(PacketTag.sym_encrypted_integrity_protected_data);
    data[21] = 8;
    data[22] = 1;
    @memset(data[23..30], 0);

    var result = try validator.validateMessage(allocator, &data);
    defer result.deinit(allocator);

    try std.testing.expect(result.encryption != null);
    try std.testing.expectEqual(@as(u32, 2), result.encryption.?.recipient_count);
}
