// SPDX-License-Identifier: MIT
//! Message security analysis module.
//!
//! Analyzes OpenPGP messages for security properties including
//! encryption strength, signature strength, AEAD vs MDC usage,
//! compression, and potential vulnerabilities.

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

/// Security level assessment.
pub const SecurityLevel = enum {
    excellent,
    good,
    adequate,
    weak,
    broken,

    pub fn name(self: SecurityLevel) []const u8 {
        return switch (self) {
            .excellent => "Excellent",
            .good => "Good",
            .adequate => "Adequate",
            .weak => "Weak",
            .broken => "Broken",
        };
    }
};

/// Result of a message security analysis.
pub const MessageAnalysis = struct {
    encryption_strength: ?SecurityLevel,
    signature_strength: ?SecurityLevel,
    sym_algo_assessment: ?[]const u8,
    hash_algo_assessment: ?[]const u8,
    uses_aead: bool,
    uses_mdc: bool,
    compression: ?[]const u8,
    warnings: std.ArrayList([]const u8),

    pub fn deinit(self: *MessageAnalysis, allocator: Allocator) void {
        if (self.sym_algo_assessment) |sa| allocator.free(sa);
        if (self.hash_algo_assessment) |ha| allocator.free(ha);
        if (self.compression) |c| allocator.free(c);
        for (self.warnings.items) |w| allocator.free(w);
        self.warnings.deinit(allocator);
    }

    /// Format the analysis as a human-readable string.
    pub fn format(self: *const MessageAnalysis, allocator: Allocator) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);
        const w = buf.writer(allocator);

        try w.print("Message Security Analysis\n", .{});
        try w.writeAll("========================================\n");

        if (self.encryption_strength) |es| {
            try w.print("Encryption:  {s}\n", .{es.name()});
        } else {
            try w.print("Encryption:  None\n", .{});
        }

        if (self.signature_strength) |ss| {
            try w.print("Signature:   {s}\n", .{ss.name()});
        } else {
            try w.print("Signature:   None\n", .{});
        }

        if (self.sym_algo_assessment) |sa| {
            try w.print("Cipher:      {s}\n", .{sa});
        }
        if (self.hash_algo_assessment) |ha| {
            try w.print("Hash:        {s}\n", .{ha});
        }

        try w.print("AEAD:        {s}\n", .{if (self.uses_aead) "yes" else "no"});
        try w.print("MDC:         {s}\n", .{if (self.uses_mdc) "yes" else "no"});

        if (self.compression) |c| {
            try w.print("Compression: {s}\n", .{c});
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

/// Analyze an OpenPGP message for security properties.
pub fn analyzeMessage(allocator: Allocator, data: []const u8) !MessageAnalysis {
    var analysis = MessageAnalysis{
        .encryption_strength = null,
        .signature_strength = null,
        .sym_algo_assessment = null,
        .hash_algo_assessment = null,
        .uses_aead = false,
        .uses_mdc = false,
        .compression = null,
        .warnings = .empty,
    };
    errdefer analysis.deinit(allocator);

    // Strip armor if present
    const stripped = stripArmor(allocator, data);
    const binary = stripped.binary;
    defer freeArmorResult(allocator, stripped.decoded, stripped.headers);

    // Collect info from packets
    var has_encryption = false;
    var has_signature = false;
    var has_sed = false;
    var seipd_version: ?u8 = null;
    var sym_algo: ?SymmetricAlgorithm = null;
    var aead_algo: ?AeadAlgorithm = null;
    var hash_algo: ?HashAlgorithm = null;
    var pub_algo: ?PublicKeyAlgorithm = null;
    var compression_algo: ?CompressionAlgorithm = null;
    var has_pkesk = false;
    var has_skesk = false;

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
                has_encryption = true;
                has_pkesk = true;
                if (body) |b| {
                    if (b.len >= 10 and b[0] == 3) {
                        const pk_algo: PublicKeyAlgorithm = @enumFromInt(b[9]);
                        pub_algo = pk_algo;
                    }
                }
            },
            .symmetric_key_encrypted_session_key => {
                has_encryption = true;
                has_skesk = true;
                if (body) |b| {
                    if (b.len >= 2) {
                        if (b[0] == 4) {
                            sym_algo = @enumFromInt(b[1]);
                        } else if (b[0] == 6 and b.len >= 4) {
                            sym_algo = @enumFromInt(b[2]);
                            aead_algo = @enumFromInt(b[3]);
                        }
                    }
                }
            },
            .sym_encrypted_integrity_protected_data => {
                has_encryption = true;
                if (body) |b| {
                    if (b.len >= 1) {
                        seipd_version = b[0];
                        if (b[0] == 1) {
                            analysis.uses_mdc = true;
                        } else if (b[0] == 2 and b.len >= 3) {
                            analysis.uses_aead = true;
                            sym_algo = @enumFromInt(b[1]);
                            aead_algo = @enumFromInt(b[2]);
                        }
                    }
                }
            },
            .symmetrically_encrypted_data => {
                has_encryption = true;
                has_sed = true;
            },
            .signature => {
                has_signature = true;
                if (body) |b| {
                    if (b.len >= 4 and b[0] == 4) {
                        pub_algo = @enumFromInt(b[2]);
                        hash_algo = @enumFromInt(b[3]);
                    }
                }
            },
            .one_pass_signature => {
                has_signature = true;
                if (body) |b| {
                    if (b.len >= 4) {
                        hash_algo = @enumFromInt(b[2]);
                        pub_algo = @enumFromInt(b[3]);
                    }
                }
            },
            .compressed_data => {
                if (body) |b| {
                    if (b.len >= 1) {
                        compression_algo = @enumFromInt(b[0]);
                    }
                }
            },
            else => {},
        }

        if (can_read) {
            fbs.pos += body_len;
        } else {
            break;
        }
    }

    // Assess encryption strength
    if (has_encryption) {
        analysis.encryption_strength = assessEncryptionStrength(sym_algo, aead_algo, seipd_version, has_sed);
    }

    // Assess signature strength
    if (has_signature) {
        analysis.signature_strength = assessSignatureStrength(pub_algo, hash_algo);
    }

    // Symmetric algorithm assessment
    if (sym_algo) |sa| {
        analysis.sym_algo_assessment = try allocator.dupe(u8, assessSymAlgo(sa));
    }

    // Hash algorithm assessment
    if (hash_algo) |ha| {
        analysis.hash_algo_assessment = try allocator.dupe(u8, assessHashAlgo(ha));
    }

    // Compression
    if (compression_algo) |ca| {
        analysis.compression = try allocator.dupe(u8, ca.name());
    }

    // Generate warnings
    if (has_sed) {
        try analysis.warnings.append(allocator,
            try allocator.dupe(u8, "Message uses legacy Symmetrically Encrypted Data (no integrity protection)"));
    }

    if (has_encryption and !analysis.uses_mdc and !analysis.uses_aead) {
        try analysis.warnings.append(allocator,
            try allocator.dupe(u8, "Encrypted message has no integrity protection (no MDC or AEAD)"));
    }

    if (has_encryption and analysis.uses_mdc and !analysis.uses_aead) {
        try analysis.warnings.append(allocator,
            try allocator.dupe(u8, "Message uses MDC integrity protection; AEAD (SEIPD v2) provides stronger guarantees"));
    }

    if (has_skesk and !has_pkesk) {
        try analysis.warnings.append(allocator,
            try allocator.dupe(u8, "Message uses only password-based encryption (no public-key recipients)"));
    }

    if (hash_algo) |ha| {
        if (ha == .sha1 or ha == .md5) {
            try analysis.warnings.append(allocator,
                try allocator.dupe(u8, "Signature uses a deprecated hash algorithm"));
        }
    }

    if (sym_algo) |sa| {
        if (sa == .triple_des or sa == .cast5 or sa == .idea or sa == .blowfish) {
            try analysis.warnings.append(allocator,
                try allocator.dupe(u8, "Message uses a legacy symmetric cipher with 64-bit block size"));
        }
    }

    return analysis;
}

// ---------------------------------------------------------------------------
// Assessment helpers
// ---------------------------------------------------------------------------

fn assessEncryptionStrength(
    sym_algo: ?SymmetricAlgorithm,
    aead_algo: ?AeadAlgorithm,
    seipd_version: ?u8,
    has_sed: bool,
) SecurityLevel {
    if (has_sed) return .weak; // No integrity protection

    if (aead_algo != null and seipd_version != null and seipd_version.? == 2) {
        // AEAD mode
        if (sym_algo) |sa| {
            return switch (sa) {
                .aes256 => .excellent,
                .aes192, .aes128 => .good,
                .twofish => .good,
                else => .adequate,
            };
        }
        return .good;
    }

    // SEIPD v1 (MDC)
    if (seipd_version != null and seipd_version.? == 1) {
        if (sym_algo) |sa| {
            return switch (sa) {
                .aes256 => .good,
                .aes192, .aes128 => .good,
                .twofish => .good,
                .cast5 => .adequate,
                .triple_des => .weak,
                .idea => .weak,
                .blowfish => .weak,
                else => .adequate,
            };
        }
        return .adequate;
    }

    return .weak;
}

fn assessSignatureStrength(
    pub_algo: ?PublicKeyAlgorithm,
    hash_algo: ?HashAlgorithm,
) SecurityLevel {
    var hash_level: SecurityLevel = .good;
    var algo_level: SecurityLevel = .good;

    if (hash_algo) |ha| {
        hash_level = switch (ha) {
            .md5 => .broken,
            .sha1 => .weak,
            .ripemd160 => .adequate,
            .sha224 => .adequate,
            .sha256 => .good,
            .sha384, .sha512 => .excellent,
            _ => .adequate,
        };
    }

    if (pub_algo) |pa| {
        algo_level = switch (pa) {
            .rsa_encrypt_sign, .rsa_sign_only => .good,
            .dsa => .adequate,
            .ecdsa => .good,
            .eddsa, .ed25519, .ed448 => .excellent,
            else => .adequate,
        };
    }

    // The overall strength is the worse of the two components
    return worseLevel(hash_level, algo_level);
}

fn assessSymAlgo(algo: SymmetricAlgorithm) []const u8 {
    return switch (algo) {
        .aes256 => "AES-256: Excellent - gold standard for symmetric encryption",
        .aes192 => "AES-192: Good - strong encryption",
        .aes128 => "AES-128: Good - widely used and secure",
        .twofish => "Twofish: Good - 256-bit key, 128-bit block",
        .cast5 => "CAST5: Adequate - 64-bit block size limits security for large messages",
        .triple_des => "3DES: Weak - slow, 64-bit block, deprecated",
        .idea => "IDEA: Weak - 64-bit block, legacy algorithm",
        .blowfish => "Blowfish: Weak - 64-bit block",
        .plaintext => "Plaintext: NONE - no encryption at all!",
        .camellia128 => "Camellia-128: Good - 128-bit block, 128-bit key",
        .camellia192 => "Camellia-192: Good - 128-bit block, 192-bit key",
        .camellia256 => "Camellia-256: Excellent - 128-bit block, 256-bit key",
        _ => "Unknown algorithm",
    };
}

fn assessHashAlgo(algo: HashAlgorithm) []const u8 {
    return switch (algo) {
        .sha512 => "SHA-512: Excellent - strongest standard hash",
        .sha384 => "SHA-384: Excellent - very strong",
        .sha256 => "SHA-256: Good - standard secure hash",
        .sha224 => "SHA-224: Adequate - consider SHA-256+",
        .sha1 => "SHA-1: Weak - vulnerable to collision attacks, deprecated",
        .ripemd160 => "RIPEMD-160: Adequate - outdated but not broken",
        .md5 => "MD5: Broken - completely insecure for signatures",
        _ => "Unknown hash algorithm",
    };
}

fn worseLevel(a: SecurityLevel, b: SecurityLevel) SecurityLevel {
    if (@intFromEnum(b) > @intFromEnum(a)) return b;
    return a;
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

test "SecurityLevel ordering" {
    try std.testing.expect(@intFromEnum(SecurityLevel.broken) > @intFromEnum(SecurityLevel.excellent));
    try std.testing.expect(@intFromEnum(SecurityLevel.weak) > @intFromEnum(SecurityLevel.good));
}

test "worseLevel picks the worse" {
    try std.testing.expectEqual(SecurityLevel.weak, worseLevel(.good, .weak));
    try std.testing.expectEqual(SecurityLevel.broken, worseLevel(.broken, .good));
    try std.testing.expectEqual(SecurityLevel.excellent, worseLevel(.excellent, .excellent));
}

test "assessSymAlgo known algorithms" {
    try std.testing.expect(mem.indexOf(u8, assessSymAlgo(.aes256), "Excellent") != null);
    try std.testing.expect(mem.indexOf(u8, assessSymAlgo(.triple_des), "Weak") != null);
    try std.testing.expect(mem.indexOf(u8, assessSymAlgo(.cast5), "Adequate") != null);
}

test "assessHashAlgo known algorithms" {
    try std.testing.expect(mem.indexOf(u8, assessHashAlgo(.sha512), "Excellent") != null);
    try std.testing.expect(mem.indexOf(u8, assessHashAlgo(.sha1), "Weak") != null);
    try std.testing.expect(mem.indexOf(u8, assessHashAlgo(.md5), "Broken") != null);
}

test "assessEncryptionStrength AEAD" {
    const level = assessEncryptionStrength(.aes256, .gcm, 2, false);
    try std.testing.expectEqual(SecurityLevel.excellent, level);
}

test "assessEncryptionStrength SED is weak" {
    const level = assessEncryptionStrength(.aes256, null, null, true);
    try std.testing.expectEqual(SecurityLevel.weak, level);
}

test "assessEncryptionStrength SEIPD v1 with AES" {
    const level = assessEncryptionStrength(.aes256, null, 1, false);
    try std.testing.expectEqual(SecurityLevel.good, level);
}

test "assessSignatureStrength Ed25519 + SHA-512" {
    const level = assessSignatureStrength(.ed25519, .sha512);
    try std.testing.expectEqual(SecurityLevel.excellent, level);
}

test "assessSignatureStrength RSA + SHA-1" {
    const level = assessSignatureStrength(.rsa_sign_only, .sha1);
    try std.testing.expectEqual(SecurityLevel.weak, level);
}

test "MessageAnalysis deinit on empty" {
    const allocator = std.testing.allocator;
    var ma = MessageAnalysis{
        .encryption_strength = null,
        .signature_strength = null,
        .sym_algo_assessment = null,
        .hash_algo_assessment = null,
        .uses_aead = false,
        .uses_mdc = false,
        .compression = null,
        .warnings = .empty,
    };
    ma.deinit(allocator);
}

test "analyzeMessage on PKESK + SEIPD v1" {
    const allocator = std.testing.allocator;

    var buf: [64]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();

    // PKESK v3
    w.writeByte(0xC0 | 1) catch unreachable;
    w.writeByte(12) catch unreachable;
    w.writeByte(3) catch unreachable;
    w.writeAll(&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }) catch unreachable;
    w.writeByte(1) catch unreachable; // RSA
    w.writeByte(0) catch unreachable;
    w.writeByte(0) catch unreachable;

    // SEIPD v1
    w.writeByte(0xC0 | 18) catch unreachable;
    w.writeByte(3) catch unreachable;
    w.writeByte(1) catch unreachable;
    w.writeByte(0) catch unreachable;
    w.writeByte(0) catch unreachable;

    const written = wfbs.getWritten();
    var ma = try analyzeMessage(allocator, written);
    defer ma.deinit(allocator);

    try std.testing.expect(ma.encryption_strength != null);
    try std.testing.expect(ma.uses_mdc);
    try std.testing.expect(!ma.uses_aead);
}

test "analyzeMessage on one-pass signature" {
    const allocator = std.testing.allocator;

    var buf: [64]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();

    // One-Pass Signature v3: tag 4
    w.writeByte(0xC0 | 4) catch unreachable;
    w.writeByte(13) catch unreachable;
    w.writeByte(3) catch unreachable; // version
    w.writeByte(0x00) catch unreachable; // sig type
    w.writeByte(8) catch unreachable; // SHA256
    w.writeByte(1) catch unreachable; // RSA
    w.writeAll(&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }) catch unreachable; // key id
    w.writeByte(1) catch unreachable; // nested flag

    const written = wfbs.getWritten();
    var ma = try analyzeMessage(allocator, written);
    defer ma.deinit(allocator);

    try std.testing.expect(ma.signature_strength != null);
    try std.testing.expect(ma.encryption_strength == null);
}

test "format produces readable output" {
    const allocator = std.testing.allocator;
    var ma = MessageAnalysis{
        .encryption_strength = .good,
        .signature_strength = .excellent,
        .sym_algo_assessment = try allocator.dupe(u8, "AES-256: Excellent"),
        .hash_algo_assessment = try allocator.dupe(u8, "SHA-512: Excellent"),
        .uses_aead = true,
        .uses_mdc = false,
        .compression = try allocator.dupe(u8, "ZLIB"),
        .warnings = .empty,
    };
    defer ma.deinit(allocator);

    const output = try ma.format(allocator);
    defer allocator.free(output);

    try std.testing.expect(output.len > 0);
    try std.testing.expect(mem.indexOf(u8, output, "AES-256") != null);
}
