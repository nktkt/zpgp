// SPDX-License-Identifier: MIT
//! Key certification operations for OpenPGP.
//!
//! Provides functions for creating and verifying key certifications,
//! which are the foundation of the Web of Trust. A certification is
//! a signature by one key on another key's user ID, asserting that
//! the key belongs to the person described by the user ID.
//!
//! Certification signature types (RFC 4880 Section 5.2.1):
//!   - 0x10: Generic certification (no claim about verification)
//!   - 0x11: Persona certification (no verification performed)
//!   - 0x12: Casual certification (some verification)
//!   - 0x13: Positive certification (thorough verification)
//!
//! Trust signatures (RFC 4880 Section 5.2.3.13):
//!   Trust signatures allow delegating trust to other keys. A trust
//!   signature includes a trust depth and trust amount, enabling
//!   hierarchical trust models (e.g., CA-like trust).

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const Key = @import("key.zig").Key;
const UserIdPacket = @import("../packets/user_id.zig").UserIdPacket;
const SignaturePacket = @import("../packets/signature.zig").SignaturePacket;
const PublicKeyPacket = @import("../packets/public_key.zig").PublicKeyPacket;
const fingerprint_mod = @import("fingerprint.zig");

// ---------------------------------------------------------------------------
// Certification types
// ---------------------------------------------------------------------------

/// Level of identity verification for certifications.
pub const CertificationLevel = enum(u8) {
    /// Generic certification (0x10): No particular claim about verification.
    generic = 0x10,
    /// Persona certification (0x11): No verification was performed.
    persona = 0x11,
    /// Casual certification (0x12): Some casual verification was done.
    casual = 0x12,
    /// Positive certification (0x13): Thorough identity verification.
    positive = 0x13,

    pub fn name(self: CertificationLevel) []const u8 {
        return switch (self) {
            .generic => "Generic certification",
            .persona => "Persona certification",
            .casual => "Casual certification",
            .positive => "Positive certification",
        };
    }

    /// Whether this certification implies any identity verification.
    pub fn impliesVerification(self: CertificationLevel) bool {
        return switch (self) {
            .casual, .positive => true,
            .generic, .persona => false,
        };
    }
};

// ---------------------------------------------------------------------------
// Trust signature parameters
// ---------------------------------------------------------------------------

/// Parameters for trust signatures.
pub const TrustSignatureParams = struct {
    /// Trust depth (1 = direct trust, 2+ = meta-trust / CA-like).
    depth: u8,
    /// Trust amount (60 = partial, 120 = complete, 255 = ultimate).
    amount: u8,
    /// Optional regular expression constraint on user IDs.
    /// Only user IDs matching this regex are trusted.
    regex: ?[]const u8,

    /// Create default trust signature params (depth 1, full trust).
    pub fn default() TrustSignatureParams {
        return .{
            .depth = 1,
            .amount = 120,
            .regex = null,
        };
    }

    /// Create params for a CA-like trust (depth 2, full trust).
    pub fn ca() TrustSignatureParams {
        return .{
            .depth = 2,
            .amount = 120,
            .regex = null,
        };
    }

    /// Create params for partial/marginal trust.
    pub fn partial() TrustSignatureParams {
        return .{
            .depth = 1,
            .amount = 60,
            .regex = null,
        };
    }
};

// ---------------------------------------------------------------------------
// Certification data builder
// ---------------------------------------------------------------------------

/// Build the certification signature data (hashed portion).
///
/// For a certification signature over a user ID, the hash input is:
///   1. Key material of the certified key
///   2. User ID data (with prefix)
///   3. V4 signature trailer
///
/// This function builds the "hash data" that should be signed.
pub fn buildCertificationHashData(
    allocator: Allocator,
    certified_key_body: []const u8,
    user_id_data: []const u8,
    sig_type: u8,
    hash_algo: u8,
    pub_algo: u8,
    hashed_subpackets: []const u8,
) ![]u8 {
    // Calculate sizes
    // Key material: 0x99 + 2-byte length + key body
    const key_prefix_len: usize = 3 + certified_key_body.len;
    // User ID: 0xB4 + 4-byte length + user ID data
    const uid_prefix_len: usize = 5 + user_id_data.len;
    // V4 signature trailer
    const hashed_data_len = 4 + 2 + hashed_subpackets.len;
    const trailer_len: usize = hashed_data_len + 6;

    const total = key_prefix_len + uid_prefix_len + trailer_len;
    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);

    var offset: usize = 0;

    // Key material
    buf[offset] = 0x99;
    offset += 1;
    const key_len: u16 = @intCast(certified_key_body.len);
    mem.writeInt(u16, buf[offset..][0..2], key_len, .big);
    offset += 2;
    @memcpy(buf[offset .. offset + certified_key_body.len], certified_key_body);
    offset += certified_key_body.len;

    // User ID (0xB4 prefix for V4 certification)
    buf[offset] = 0xB4;
    offset += 1;
    const uid_len: u32 = @intCast(user_id_data.len);
    mem.writeInt(u32, buf[offset..][0..4], uid_len, .big);
    offset += 4;
    @memcpy(buf[offset .. offset + user_id_data.len], user_id_data);
    offset += user_id_data.len;

    // V4 signature trailer
    buf[offset] = 0x04; // version
    offset += 1;
    buf[offset] = sig_type;
    offset += 1;
    buf[offset] = pub_algo;
    offset += 1;
    buf[offset] = hash_algo;
    offset += 1;

    // Hashed subpackets length
    const sp_len: u16 = @intCast(hashed_subpackets.len);
    mem.writeInt(u16, buf[offset..][0..2], sp_len, .big);
    offset += 2;

    // Hashed subpackets
    if (hashed_subpackets.len > 0) {
        @memcpy(buf[offset .. offset + hashed_subpackets.len], hashed_subpackets);
        offset += hashed_subpackets.len;
    }

    // Final trailer: 0x04 + 0xFF + 4-byte BE length
    buf[offset] = 0x04;
    offset += 1;
    buf[offset] = 0xFF;
    offset += 1;
    const hd_len_u32: u32 = @intCast(hashed_data_len);
    mem.writeInt(u32, buf[offset..][0..4], hd_len_u32, .big);

    return buf;
}

/// Build hashed subpackets for a certification signature.
///
/// Includes:
///   - Creation time (subpacket 2)
///   - Issuer fingerprint (subpacket 33)
///   - Optionally: trust signature (subpacket 5)
///   - Optionally: regular expression (subpacket 6)
///   - Optionally: exportable (subpacket 4)
pub fn buildCertificationSubpackets(
    allocator: Allocator,
    creation_time: u32,
    issuer_fingerprint: [20]u8,
    trust_params: ?TrustSignatureParams,
    exportable: bool,
) ![]u8 {
    var subpackets = std.ArrayList(u8).init(allocator);
    errdefer subpackets.deinit();

    // Subpacket 2: Creation time (length=5: 1 type + 4 data)
    try subpackets.append(5); // subpacket length
    try subpackets.append(2); // subpacket type: creation time
    var time_buf: [4]u8 = undefined;
    mem.writeInt(u32, &time_buf, creation_time, .big);
    try subpackets.appendSlice(&time_buf);

    // Subpacket 33: Issuer fingerprint (length=22: 1 type + 1 version + 20 fp)
    try subpackets.append(22); // subpacket length
    try subpackets.append(33); // subpacket type: issuer fingerprint
    try subpackets.append(4); // version 4
    try subpackets.appendSlice(&issuer_fingerprint);

    // Subpacket 4: Exportable certification (optional)
    if (!exportable) {
        try subpackets.append(2); // length
        try subpackets.append(4); // type: exportable
        try subpackets.append(0); // not exportable
    }

    // Subpacket 5: Trust signature (optional)
    if (trust_params) |tp| {
        try subpackets.append(3); // length
        try subpackets.append(5); // type: trust signature
        try subpackets.append(tp.depth);
        try subpackets.append(tp.amount);

        // Subpacket 6: Regular expression (optional)
        if (tp.regex) |regex| {
            const regex_len: u8 = @intCast(regex.len + 2); // type + data + null
            try subpackets.append(regex_len);
            try subpackets.append(6); // type: regular expression
            try subpackets.appendSlice(regex);
            try subpackets.append(0); // null terminator
        }
    }

    return subpackets.toOwnedSlice();
}

/// Build unhashed subpackets for a certification signature.
///
/// Includes:
///   - Issuer key ID (subpacket 16)
pub fn buildUnhashedSubpackets(
    allocator: Allocator,
    issuer_key_id: [8]u8,
) ![]u8 {
    var subpackets = std.ArrayList(u8).init(allocator);
    errdefer subpackets.deinit();

    // Subpacket 16: Issuer (length=9: 1 type + 8 data)
    try subpackets.append(9); // subpacket length
    try subpackets.append(16); // subpacket type: issuer
    try subpackets.appendSlice(&issuer_key_id);

    return subpackets.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Certification result
// ---------------------------------------------------------------------------

/// Result of verifying a certification chain.
pub const CertificationResult = struct {
    /// Whether the certification chain is valid.
    valid: bool,
    /// The certification chain from the root certifier to the target.
    chain: []ChainLink,
    /// The effective trust depth after traversing the chain.
    trust_depth: u32,

    /// A single link in a certification chain.
    pub const ChainLink = struct {
        /// Fingerprint of the certifying key.
        certifier_fp: [20]u8,
        /// Fingerprint of the certified key.
        certified_fp: [20]u8,
        /// The certification level (0x10-0x13).
        cert_level: CertificationLevel,
        /// Trust signature depth (0 if not a trust sig).
        trust_depth: u8,
        /// Trust signature amount (0 if not a trust sig).
        trust_amount: u8,
        /// Whether the certification is exportable.
        exportable: bool,
    };

    /// Free allocated memory.
    pub fn deinit(self: CertificationResult, allocator: Allocator) void {
        allocator.free(self.chain);
    }
};

/// Verify a certification chain from a root certifier to a target key.
///
/// Walks through the chain of certifications and checks:
///   1. Each certification signature type is valid (0x10-0x13)
///   2. Trust depth is sufficient for the chain length
///   3. All links are connected (each step certifies the next)
///
/// This does NOT verify cryptographic signatures (that requires the
/// full signature verification machinery). It only checks the
/// structural validity of the chain.
pub fn verifyCertificationChain(
    allocator: Allocator,
    chain_links: []const CertificationResult.ChainLink,
) !CertificationResult {
    if (chain_links.len == 0) {
        const empty_chain = try allocator.alloc(CertificationResult.ChainLink, 0);
        return .{
            .valid = false,
            .chain = empty_chain,
            .trust_depth = 0,
        };
    }

    var valid = true;
    var effective_depth: u32 = 0;

    // Verify chain connectivity and trust depth
    for (chain_links, 0..) |link, i| {
        // Check certification level
        const sig_type = @intFromEnum(link.cert_level);
        if (sig_type < 0x10 or sig_type > 0x13) {
            valid = false;
            break;
        }

        // Check chain connectivity
        if (i + 1 < chain_links.len) {
            const next_link = chain_links[i + 1];
            if (!mem.eql(u8, &link.certified_fp, &next_link.certifier_fp)) {
                valid = false;
                break;
            }

            // For trust signatures, check depth
            if (link.trust_depth > 0) {
                if (link.trust_depth <= i) {
                    valid = false; // Trust depth exceeded
                    break;
                }
            }
        }

        if (link.trust_depth > 0) {
            effective_depth = @max(effective_depth, @as(u32, link.trust_depth));
        }
    }

    const chain = try allocator.dupe(CertificationResult.ChainLink, chain_links);

    return .{
        .valid = valid,
        .chain = chain,
        .trust_depth = effective_depth,
    };
}

/// Create a local (non-exportable) certification.
///
/// Builds the certification hash data for a local signature.
/// Local certifications are only valid in the keyring where they were created.
pub fn buildLocalCertification(
    allocator: Allocator,
    certified_key_body: []const u8,
    user_id_data: []const u8,
    cert_level: CertificationLevel,
    hash_algo: u8,
    pub_algo: u8,
    creation_time: u32,
    issuer_fingerprint: [20]u8,
) ![]u8 {
    const subpackets = try buildCertificationSubpackets(
        allocator,
        creation_time,
        issuer_fingerprint,
        null,
        false, // not exportable
    );
    defer allocator.free(subpackets);

    return buildCertificationHashData(
        allocator,
        certified_key_body,
        user_id_data,
        @intFromEnum(cert_level),
        hash_algo,
        pub_algo,
        subpackets,
    );
}

/// Create a trust signature certification.
///
/// Builds the certification hash data for a trust signature.
/// Trust signatures delegate trust to the certified key, allowing
/// it to make trusted certifications up to the specified depth.
pub fn buildTrustCertification(
    allocator: Allocator,
    certified_key_body: []const u8,
    user_id_data: []const u8,
    cert_level: CertificationLevel,
    hash_algo: u8,
    pub_algo: u8,
    creation_time: u32,
    issuer_fingerprint: [20]u8,
    trust_params: TrustSignatureParams,
) ![]u8 {
    const subpackets = try buildCertificationSubpackets(
        allocator,
        creation_time,
        issuer_fingerprint,
        trust_params,
        true, // exportable
    );
    defer allocator.free(subpackets);

    return buildCertificationHashData(
        allocator,
        certified_key_body,
        user_id_data,
        @intFromEnum(cert_level),
        hash_algo,
        pub_algo,
        subpackets,
    );
}

/// Extract certification information from a signature packet's subpacket data.
pub const CertificationInfo = struct {
    /// Creation timestamp.
    creation_time: ?u32,
    /// Trust signature depth (0 if not a trust sig).
    trust_depth: u8,
    /// Trust signature amount (0 if not a trust sig).
    trust_amount: u8,
    /// Whether the certification is exportable (default: true).
    exportable: bool,
    /// Issuer fingerprint.
    issuer_fingerprint: ?[20]u8,
    /// Issuer key ID.
    issuer_key_id: ?[8]u8,
    /// Regular expression constraint.
    regex: ?[]const u8,
};

/// Parse certification-specific information from hashed subpacket data.
pub fn parseCertificationInfo(hashed_subpackets: []const u8) CertificationInfo {
    var info = CertificationInfo{
        .creation_time = null,
        .trust_depth = 0,
        .trust_amount = 0,
        .exportable = true, // Default per RFC 4880
        .issuer_fingerprint = null,
        .issuer_key_id = null,
        .regex = null,
    };

    var offset: usize = 0;
    while (offset < hashed_subpackets.len) {
        if (offset >= hashed_subpackets.len) break;
        const first = hashed_subpackets[offset];
        offset += 1;

        var body_len: usize = undefined;
        if (first < 192) {
            body_len = @as(usize, first);
        } else if (first <= 254) {
            if (offset >= hashed_subpackets.len) break;
            body_len = (@as(usize, first) - 192) * 256 + @as(usize, hashed_subpackets[offset]) + 192;
            offset += 1;
        } else {
            if (offset + 4 > hashed_subpackets.len) break;
            body_len = mem.readInt(u32, hashed_subpackets[offset..][0..4], .big);
            offset += 4;
        }

        if (body_len == 0 or offset + body_len > hashed_subpackets.len) break;

        const tag = hashed_subpackets[offset] & 0x7F;

        switch (tag) {
            2 => {
                // Creation time
                if (body_len >= 5) {
                    info.creation_time = mem.readInt(u32, hashed_subpackets[offset + 1 ..][0..4], .big);
                }
            },
            4 => {
                // Exportable
                if (body_len >= 2) {
                    info.exportable = hashed_subpackets[offset + 1] != 0;
                }
            },
            5 => {
                // Trust signature
                if (body_len >= 3) {
                    info.trust_depth = hashed_subpackets[offset + 1];
                    info.trust_amount = hashed_subpackets[offset + 2];
                }
            },
            6 => {
                // Regular expression
                if (body_len > 1) {
                    info.regex = hashed_subpackets[offset + 1 .. offset + body_len];
                }
            },
            33 => {
                // Issuer fingerprint
                if (body_len >= 22) {
                    info.issuer_fingerprint = hashed_subpackets[offset + 2 .. offset + 22][0..20].*;
                }
            },
            16 => {
                // Issuer key ID
                if (body_len >= 9) {
                    info.issuer_key_id = hashed_subpackets[offset + 1 .. offset + 9][0..8].*;
                }
            },
            else => {},
        }

        offset += body_len;
    }

    return info;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "CertificationLevel names" {
    try std.testing.expectEqualStrings("Generic certification", CertificationLevel.generic.name());
    try std.testing.expectEqualStrings("Persona certification", CertificationLevel.persona.name());
    try std.testing.expectEqualStrings("Casual certification", CertificationLevel.casual.name());
    try std.testing.expectEqualStrings("Positive certification", CertificationLevel.positive.name());
}

test "CertificationLevel impliesVerification" {
    try std.testing.expect(!CertificationLevel.generic.impliesVerification());
    try std.testing.expect(!CertificationLevel.persona.impliesVerification());
    try std.testing.expect(CertificationLevel.casual.impliesVerification());
    try std.testing.expect(CertificationLevel.positive.impliesVerification());
}

test "CertificationLevel enum values" {
    try std.testing.expectEqual(@as(u8, 0x10), @intFromEnum(CertificationLevel.generic));
    try std.testing.expectEqual(@as(u8, 0x11), @intFromEnum(CertificationLevel.persona));
    try std.testing.expectEqual(@as(u8, 0x12), @intFromEnum(CertificationLevel.casual));
    try std.testing.expectEqual(@as(u8, 0x13), @intFromEnum(CertificationLevel.positive));
}

test "TrustSignatureParams default" {
    const params = TrustSignatureParams.default();
    try std.testing.expectEqual(@as(u8, 1), params.depth);
    try std.testing.expectEqual(@as(u8, 120), params.amount);
    try std.testing.expect(params.regex == null);
}

test "TrustSignatureParams ca" {
    const params = TrustSignatureParams.ca();
    try std.testing.expectEqual(@as(u8, 2), params.depth);
    try std.testing.expectEqual(@as(u8, 120), params.amount);
}

test "TrustSignatureParams partial" {
    const params = TrustSignatureParams.partial();
    try std.testing.expectEqual(@as(u8, 1), params.depth);
    try std.testing.expectEqual(@as(u8, 60), params.amount);
}

test "buildCertificationSubpackets basic" {
    const allocator = std.testing.allocator;

    const fp = [_]u8{0xAA} ** 20;
    const subpackets = try buildCertificationSubpackets(
        allocator,
        1700000000,
        fp,
        null,
        true,
    );
    defer allocator.free(subpackets);

    // Should contain at least creation time (5 bytes) + issuer fingerprint (22 bytes)
    try std.testing.expect(subpackets.len >= 27);

    // Check creation time subpacket: len=5, type=2
    try std.testing.expectEqual(@as(u8, 5), subpackets[0]);
    try std.testing.expectEqual(@as(u8, 2), subpackets[1]);
}

test "buildCertificationSubpackets with trust" {
    const allocator = std.testing.allocator;

    const fp = [_]u8{0xBB} ** 20;
    const trust = TrustSignatureParams.default();
    const subpackets = try buildCertificationSubpackets(
        allocator,
        1700000000,
        fp,
        trust,
        true,
    );
    defer allocator.free(subpackets);

    // Should be longer than basic (includes trust subpacket)
    try std.testing.expect(subpackets.len >= 30);
}

test "buildCertificationSubpackets non-exportable" {
    const allocator = std.testing.allocator;

    const fp = [_]u8{0xCC} ** 20;
    const subpackets = try buildCertificationSubpackets(
        allocator,
        1700000000,
        fp,
        null,
        false,
    );
    defer allocator.free(subpackets);

    // Should contain exportable subpacket (2 extra bytes)
    try std.testing.expect(subpackets.len >= 29);
}

test "buildUnhashedSubpackets" {
    const allocator = std.testing.allocator;

    const kid = [_]u8{0xDD} ** 8;
    const subpackets = try buildUnhashedSubpackets(allocator, kid);
    defer allocator.free(subpackets);

    try std.testing.expectEqual(@as(usize, 10), subpackets.len); // len(1) + type(1) + kid(8)
    try std.testing.expectEqual(@as(u8, 9), subpackets[0]); // length
    try std.testing.expectEqual(@as(u8, 16), subpackets[1]); // type: issuer
    try std.testing.expectEqualSlices(u8, &kid, subpackets[2..10]);
}

test "buildCertificationHashData" {
    const allocator = std.testing.allocator;

    const key_body = [_]u8{ 0x04, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x08, 0xFF, 0x00, 0x08, 0x03 };
    const uid_data = "Test User <test@example.com>";
    const hashed_sp = [_]u8{ 5, 2, 0x65, 0x8F, 0xEC, 0x00 }; // creation time

    const hash_data = try buildCertificationHashData(
        allocator,
        &key_body,
        uid_data,
        0x13, // positive certification
        8, // SHA256
        1, // RSA
        &hashed_sp,
    );
    defer allocator.free(hash_data);

    // Should start with key prefix 0x99
    try std.testing.expectEqual(@as(u8, 0x99), hash_data[0]);

    // Key length should be 12
    const klen = mem.readInt(u16, hash_data[1..3], .big);
    try std.testing.expectEqual(@as(u16, 12), klen);

    // After key: UID prefix 0xB4
    const uid_offset = 3 + key_body.len;
    try std.testing.expectEqual(@as(u8, 0xB4), hash_data[uid_offset]);
}

test "verifyCertificationChain empty" {
    const allocator = std.testing.allocator;

    const result = try verifyCertificationChain(allocator, &.{});
    defer result.deinit(allocator);

    try std.testing.expect(!result.valid);
    try std.testing.expectEqual(@as(usize, 0), result.chain.len);
}

test "verifyCertificationChain single link" {
    const allocator = std.testing.allocator;

    const links = [_]CertificationResult.ChainLink{
        .{
            .certifier_fp = [_]u8{0x01} ** 20,
            .certified_fp = [_]u8{0x02} ** 20,
            .cert_level = .positive,
            .trust_depth = 0,
            .trust_amount = 0,
            .exportable = true,
        },
    };

    const result = try verifyCertificationChain(allocator, &links);
    defer result.deinit(allocator);

    try std.testing.expect(result.valid);
    try std.testing.expectEqual(@as(usize, 1), result.chain.len);
}

test "verifyCertificationChain connected chain" {
    const allocator = std.testing.allocator;

    const links = [_]CertificationResult.ChainLink{
        .{
            .certifier_fp = [_]u8{0x01} ** 20,
            .certified_fp = [_]u8{0x02} ** 20,
            .cert_level = .positive,
            .trust_depth = 2,
            .trust_amount = 120,
            .exportable = true,
        },
        .{
            .certifier_fp = [_]u8{0x02} ** 20,
            .certified_fp = [_]u8{0x03} ** 20,
            .cert_level = .casual,
            .trust_depth = 1,
            .trust_amount = 120,
            .exportable = true,
        },
    };

    const result = try verifyCertificationChain(allocator, &links);
    defer result.deinit(allocator);

    try std.testing.expect(result.valid);
    try std.testing.expectEqual(@as(usize, 2), result.chain.len);
    try std.testing.expectEqual(@as(u32, 2), result.trust_depth);
}

test "verifyCertificationChain disconnected" {
    const allocator = std.testing.allocator;

    const links = [_]CertificationResult.ChainLink{
        .{
            .certifier_fp = [_]u8{0x01} ** 20,
            .certified_fp = [_]u8{0x02} ** 20,
            .cert_level = .positive,
            .trust_depth = 0,
            .trust_amount = 0,
            .exportable = true,
        },
        .{
            // Disconnected: certifier should be 0x02 but is 0x03
            .certifier_fp = [_]u8{0x03} ** 20,
            .certified_fp = [_]u8{0x04} ** 20,
            .cert_level = .positive,
            .trust_depth = 0,
            .trust_amount = 0,
            .exportable = true,
        },
    };

    const result = try verifyCertificationChain(allocator, &links);
    defer result.deinit(allocator);

    try std.testing.expect(!result.valid);
}

test "parseCertificationInfo basic" {
    // Build subpackets: creation time (type 2) + issuer fingerprint (type 33)
    var subpackets: [29]u8 = undefined;
    // Creation time: len=5, type=2, time=0x658FEC00
    subpackets[0] = 5;
    subpackets[1] = 2;
    mem.writeInt(u32, subpackets[2..6], 0x658FEC00, .big);
    // Issuer fingerprint: len=22, type=33, version=4, fp=20 bytes
    subpackets[6] = 22;
    subpackets[7] = 33;
    subpackets[8] = 4;
    @memset(subpackets[9..29], 0xAA);

    const info = parseCertificationInfo(&subpackets);

    try std.testing.expectEqual(@as(u32, 0x658FEC00), info.creation_time.?);
    try std.testing.expect(info.issuer_fingerprint != null);
    try std.testing.expectEqual(@as(u8, 0xAA), info.issuer_fingerprint.?[0]);
    try std.testing.expect(info.exportable); // default
    try std.testing.expectEqual(@as(u8, 0), info.trust_depth);
}

test "parseCertificationInfo with trust sig" {
    // Creation time + trust signature
    var subpackets: [9]u8 = undefined;
    // Creation time: len=5, type=2
    subpackets[0] = 5;
    subpackets[1] = 2;
    mem.writeInt(u32, subpackets[2..6], 1000, .big);
    // Trust signature: len=3, type=5, depth=2, amount=120
    subpackets[6] = 3;
    subpackets[7] = 5;
    subpackets[8] = 2;

    // Need one more byte for amount
    var sp2: [10]u8 = undefined;
    @memcpy(sp2[0..9], &subpackets);
    sp2[9] = 120; // trust amount

    // Actually the trust sig body is: type(1) + depth(1) + amount(1) = body_len=3
    // So subpackets should be: len=3, type=5, depth=2, amount is next byte inside body
    // Wait: body_len includes the type byte. len=3 means type(1) + data(2).
    // So data[offset+1] = depth, data[offset+2] = amount
    // But we only have 3 bytes total body (offset -> offset+3).
    // Let me fix:
    var sp_fixed: [9]u8 = undefined;
    sp_fixed[0] = 5; // creation time len
    sp_fixed[1] = 2; // type
    mem.writeInt(u32, sp_fixed[2..6], 1000, .big);
    sp_fixed[6] = 3; // trust sig len
    sp_fixed[7] = 5; // type: trust sig
    sp_fixed[8] = 2; // depth -- but we need amount too, body_len=3 means 1 type + 2 data bytes

    // body_len=3 at offset 6: data[7]=type(5), data[8]=depth(2), but body goes to offset 6+3=9
    // So we need data[9] = amount, but total array is only 9 bytes (0..8).
    // Fix: make array size 10
    var sp_real: [10]u8 = undefined;
    sp_real[0] = 5;
    sp_real[1] = 2;
    mem.writeInt(u32, sp_real[2..6], 1000, .big);
    sp_real[6] = 3;
    sp_real[7] = 5; // trust sig
    sp_real[8] = 2; // depth
    sp_real[9] = 120; // amount

    const info = parseCertificationInfo(&sp_real);
    try std.testing.expectEqual(@as(u32, 1000), info.creation_time.?);
    try std.testing.expectEqual(@as(u8, 2), info.trust_depth);
    try std.testing.expectEqual(@as(u8, 120), info.trust_amount);
}

test "parseCertificationInfo empty" {
    const info = parseCertificationInfo(&[_]u8{});
    try std.testing.expect(info.creation_time == null);
    try std.testing.expect(info.issuer_fingerprint == null);
    try std.testing.expect(info.exportable);
}

test "parseCertificationInfo non-exportable" {
    // Exportable subpacket: len=2, type=4, value=0
    const subpackets = [_]u8{ 2, 4, 0 };
    const info = parseCertificationInfo(&subpackets);
    try std.testing.expect(!info.exportable);
}

test "buildLocalCertification" {
    const allocator = std.testing.allocator;

    const key_body = [_]u8{ 0x04, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x08, 0xFF, 0x00, 0x08, 0x03 };
    const uid_data = "test@example.com";
    const fp = [_]u8{0xAA} ** 20;

    const hash_data = try buildLocalCertification(
        allocator,
        &key_body,
        uid_data,
        .positive,
        8, // SHA256
        1, // RSA
        1700000000,
        fp,
    );
    defer allocator.free(hash_data);

    try std.testing.expect(hash_data.len > 0);
    try std.testing.expectEqual(@as(u8, 0x99), hash_data[0]); // Key prefix
}

test "buildTrustCertification" {
    const allocator = std.testing.allocator;

    const key_body = [_]u8{ 0x04, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x08, 0xFF, 0x00, 0x08, 0x03 };
    const uid_data = "test@example.com";
    const fp = [_]u8{0xBB} ** 20;

    const hash_data = try buildTrustCertification(
        allocator,
        &key_body,
        uid_data,
        .positive,
        8,
        1,
        1700000000,
        fp,
        TrustSignatureParams.ca(),
    );
    defer allocator.free(hash_data);

    try std.testing.expect(hash_data.len > 0);
}

test "CertificationResult deinit" {
    const allocator = std.testing.allocator;

    const chain = try allocator.alloc(CertificationResult.ChainLink, 1);
    chain[0] = .{
        .certifier_fp = [_]u8{0x01} ** 20,
        .certified_fp = [_]u8{0x02} ** 20,
        .cert_level = .positive,
        .trust_depth = 0,
        .trust_amount = 0,
        .exportable = true,
    };

    const result = CertificationResult{
        .valid = true,
        .chain = chain,
        .trust_depth = 0,
    };
    result.deinit(allocator);
}
