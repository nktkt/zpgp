// SPDX-License-Identifier: MIT
//! Packet inspection/dump tool - parse and describe OpenPGP data.
//!
//! Provides functions to inspect binary OpenPGP data and produce
//! human-readable descriptions of packet structure, key properties,
//! signature details, and encrypted message metadata.

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

/// Information about a single parsed OpenPGP packet.
pub const PacketInfo = struct {
    tag: PacketTag,
    tag_name: []const u8,
    format: []const u8,
    body_length: u32,
    offset: u64,
    details: []const u8,

    pub fn deinit(self: PacketInfo, allocator: Allocator) void {
        allocator.free(self.tag_name);
        allocator.free(self.format);
        allocator.free(self.details);
    }
};

/// Detailed inspection of an OpenPGP key.
pub const KeyInspection = struct {
    version: u8,
    algorithm: []const u8,
    bits: ?u32,
    fingerprint: []const u8,
    key_id: []const u8,
    creation_time: u32,
    expiration_time: ?u32,
    user_ids: [][]const u8,
    subkeys: []SubkeyInfo,
    is_secret: bool,
    is_expired: bool,
    is_revoked: bool,

    pub const SubkeyInfo = struct {
        fingerprint: []const u8,
        algorithm: []const u8,
        bits: ?u32,
        flags: []const u8,
        creation_time: u32,

        pub fn deinit(self: SubkeyInfo, allocator: Allocator) void {
            allocator.free(self.fingerprint);
            allocator.free(self.algorithm);
            allocator.free(self.flags);
        }
    };

    pub fn deinit(self: *KeyInspection, allocator: Allocator) void {
        allocator.free(self.algorithm);
        allocator.free(self.fingerprint);
        allocator.free(self.key_id);
        for (self.user_ids) |uid| allocator.free(uid);
        allocator.free(self.user_ids);
        for (self.subkeys) |sk| sk.deinit(allocator);
        allocator.free(self.subkeys);
    }

    /// Format key inspection as a human-readable string.
    pub fn format(self: *const KeyInspection, allocator: Allocator) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);
        const w = buf.writer(allocator);

        try w.print("Key Inspection:\n", .{});
        try w.print("  Version:       {d}\n", .{self.version});
        try w.print("  Algorithm:     {s}\n", .{self.algorithm});
        if (self.bits) |b| {
            try w.print("  Key Size:      {d} bits\n", .{b});
        }
        try w.print("  Fingerprint:   {s}\n", .{self.fingerprint});
        try w.print("  Key ID:        {s}\n", .{self.key_id});
        try w.print("  Created:       {d}\n", .{self.creation_time});
        if (self.expiration_time) |exp| {
            try w.print("  Expires:       {d}\n", .{exp});
        } else {
            try w.print("  Expires:       never\n", .{});
        }
        try w.print("  Secret Key:    {s}\n", .{if (self.is_secret) "yes" else "no"});
        try w.print("  Expired:       {s}\n", .{if (self.is_expired) "yes" else "no"});
        try w.print("  Revoked:       {s}\n", .{if (self.is_revoked) "yes" else "no"});

        try w.print("  User IDs ({d}):\n", .{self.user_ids.len});
        for (self.user_ids, 0..) |uid, i| {
            try w.print("    [{d}] {s}\n", .{ i, uid });
        }

        try w.print("  Subkeys ({d}):\n", .{self.subkeys.len});
        for (self.subkeys, 0..) |sk, i| {
            try w.print("    [{d}] {s} ({s})", .{ i, sk.algorithm, sk.fingerprint });
            if (sk.bits) |b| {
                try w.print(" {d} bits", .{b});
            }
            try w.print(" flags={s} created={d}\n", .{ sk.flags, sk.creation_time });
        }

        return buf.toOwnedSlice(allocator);
    }
};

/// Detailed inspection of an OpenPGP signature.
pub const SignatureInspection = struct {
    version: u8,
    sig_type: []const u8,
    pub_algo: []const u8,
    hash_algo: []const u8,
    creation_time: ?u32,
    issuer_key_id: ?[]const u8,
    issuer_fingerprint: ?[]const u8,

    pub fn deinit(self: *SignatureInspection, allocator: Allocator) void {
        allocator.free(self.sig_type);
        allocator.free(self.pub_algo);
        allocator.free(self.hash_algo);
        if (self.issuer_key_id) |kid| allocator.free(kid);
        if (self.issuer_fingerprint) |fp| allocator.free(fp);
    }
};

/// Detailed inspection of an encrypted OpenPGP message.
pub const MessageInspection = struct {
    is_encrypted: bool,
    is_signed: bool,
    is_armored: bool,
    encryption_type: ?[]const u8,
    sym_algo: ?[]const u8,
    aead_algo: ?[]const u8,
    recipient_key_ids: [][]const u8,
    seipd_version: ?u8,

    pub fn deinit(self: *MessageInspection, allocator: Allocator) void {
        if (self.encryption_type) |et| allocator.free(et);
        if (self.sym_algo) |sa| allocator.free(sa);
        if (self.aead_algo) |aa| allocator.free(aa);
        for (self.recipient_key_ids) |kid| allocator.free(kid);
        allocator.free(self.recipient_key_ids);
    }
};

// ---------------------------------------------------------------------------
// Packet inspection
// ---------------------------------------------------------------------------

/// Strip ASCII armor if present and return binary data.
/// Returns the binary data and whether it was decoded (caller must free decoded data).
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

/// Inspect binary OpenPGP data and return info about each packet.
pub fn inspectPackets(allocator: Allocator, data: []const u8) ![]PacketInfo {
    const stripped = stripArmor(allocator, data);
    const binary = stripped.binary;
    defer freeArmorResult(allocator, stripped.decoded, stripped.headers);

    var packets: std.ArrayList(PacketInfo) = .empty;
    errdefer {
        for (packets.items) |p| p.deinit(allocator);
        packets.deinit(allocator);
    }

    var offset: u64 = 0;
    var fbs = std.io.fixedBufferStream(binary);
    const rdr = fbs.reader();

    while (true) {
        const start_pos: u64 = @intCast(fbs.pos);

        const hdr = header_mod.readHeader(rdr) catch |err| {
            switch (err) {
                error.EndOfStream => break,
                else => break,
            }
        };

        const body_len: u32 = switch (hdr.body_length) {
            .fixed => |len| len,
            .partial => |len| len,
            .indeterminate => 0,
        };

        // Build details string based on packet type
        const details = buildPacketDetails(allocator, hdr.tag, binary, fbs.pos, body_len) catch
            try allocator.dupe(u8, "(unable to parse details)");

        const format_str = try allocator.dupe(u8, switch (hdr.format) {
            .old => "old",
            .new => "new",
        });

        const tag_name_str = try allocator.dupe(u8, hdr.tag.name());

        try packets.append(allocator, .{
            .tag = hdr.tag,
            .tag_name = tag_name_str,
            .format = format_str,
            .body_length = body_len,
            .offset = start_pos,
            .details = details,
        });

        // Skip the packet body
        const skip_len: u64 = @intCast(body_len);
        const new_pos = fbs.pos + @as(usize, @intCast(skip_len));
        if (new_pos > binary.len) break;
        fbs.pos = new_pos;
        offset = @intCast(fbs.pos);
    }

    return packets.toOwnedSlice(allocator);
}

/// Build a human-readable description for a packet body.
fn buildPacketDetails(
    allocator: Allocator,
    tag: PacketTag,
    data: []const u8,
    body_offset: usize,
    body_len: u32,
) ![]u8 {
    if (body_len == 0 or body_offset + body_len > data.len) {
        return try allocator.dupe(u8, "");
    }
    const body = data[body_offset .. body_offset + body_len];

    return switch (tag) {
        .public_key, .public_subkey, .secret_key, .secret_subkey => try describeKeyPacket(allocator, body, tag),
        .signature => try describeSignaturePacket(allocator, body),
        .user_id => try describeUserIdPacket(allocator, body),
        .literal_data => try describeLiteralDataPacket(allocator, body),
        .compressed_data => try describeCompressedPacket(allocator, body),
        .public_key_encrypted_session_key => try describePkeskPacket(allocator, body),
        .symmetric_key_encrypted_session_key => try describeSkeskPacket(allocator, body),
        .sym_encrypted_integrity_protected_data => try describeSeipdPacket(allocator, body),
        .one_pass_signature => try describeOnePassSigPacket(allocator, body),
        else => try allocator.dupe(u8, ""),
    };
}

fn describeKeyPacket(allocator: Allocator, body: []const u8, tag: PacketTag) ![]u8 {
    if (body.len < 6) return try allocator.dupe(u8, "truncated key packet");
    const version = body[0];
    const creation_time = mem.readInt(u32, body[1..5], .big);
    const algo: PublicKeyAlgorithm = @enumFromInt(body[5]);
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);
    const tag_label: []const u8 = switch (tag) {
        .public_key => "pub",
        .public_subkey => "sub",
        .secret_key => "sec",
        .secret_subkey => "ssb",
        else => "key",
    };
    try w.print("v{d} {s} {s} created={d}", .{ version, tag_label, algo.name(), creation_time });

    // Try to get RSA bit count
    if ((algo == .rsa_encrypt_sign or algo == .rsa_encrypt_only or algo == .rsa_sign_only) and body.len > 8) {
        const bit_count = mem.readInt(u16, body[6..8], .big);
        try w.print(" {d}-bit", .{bit_count});
    }

    return buf.toOwnedSlice(allocator);
}

fn describeSignaturePacket(allocator: Allocator, body: []const u8) ![]u8 {
    if (body.len < 5) return try allocator.dupe(u8, "truncated signature");
    const version = body[0];
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    if (version == 4) {
        if (body.len < 10) return try allocator.dupe(u8, "truncated v4 signature");
        const sig_type = body[1];
        const pub_algo: PublicKeyAlgorithm = @enumFromInt(body[2]);
        const hash_algo: HashAlgorithm = @enumFromInt(body[3]);
        try w.print("v4 type=0x{X:0>2} ({s}) {s}/{s}", .{
            sig_type,
            sigTypeName(sig_type),
            pub_algo.name(),
            hash_algo.name(),
        });

        // Try to extract creation time from hashed subpackets
        const hashed_len: usize = mem.readInt(u16, body[4..6], .big);
        if (6 + hashed_len <= body.len) {
            const ct = extractCreationTime(body[6 .. 6 + hashed_len]);
            if (ct) |t| {
                try w.print(" created={d}", .{t});
            }
        }
    } else if (version == 3) {
        try w.print("v3 signature", .{});
    } else {
        try w.print("v{d} signature", .{version});
    }

    return buf.toOwnedSlice(allocator);
}

fn describeUserIdPacket(allocator: Allocator, body: []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);
    // Limit to 80 chars for readability
    const limit = @min(body.len, 80);
    try w.print("\"{s}\"", .{body[0..limit]});
    if (body.len > 80) {
        try w.print("...", .{});
    }
    return buf.toOwnedSlice(allocator);
}

fn describeLiteralDataPacket(allocator: Allocator, body: []const u8) ![]u8 {
    if (body.len < 2) return try allocator.dupe(u8, "truncated literal data");
    const format_byte = body[0];
    const name_len = body[1];
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);
    const fmt_name: []const u8 = switch (format_byte) {
        'b' => "binary",
        't' => "text",
        'u' => "UTF-8",
        else => "unknown",
    };
    try w.print("format={s}", .{fmt_name});
    if (name_len > 0 and 2 + name_len <= body.len) {
        try w.print(" name=\"{s}\"", .{body[2 .. 2 + name_len]});
    }
    return buf.toOwnedSlice(allocator);
}

fn describeCompressedPacket(allocator: Allocator, body: []const u8) ![]u8 {
    if (body.len < 1) return try allocator.dupe(u8, "truncated compressed data");
    const algo: CompressionAlgorithm = @enumFromInt(body[0]);
    return try std.fmt.allocPrint(allocator, "algorithm={s}", .{algo.name()});
}

fn describePkeskPacket(allocator: Allocator, body: []const u8) ![]u8 {
    if (body.len < 10) return try allocator.dupe(u8, "truncated PKESK");
    const version = body[0];
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);
    try w.print("v{d}", .{version});
    if (version == 3 and body.len >= 10) {
        // v3 PKESK: version(1) + key_id(8) + algo(1) + encrypted_session_key
        try w.print(" key_id=", .{});
        for (body[1..9]) |b| {
            try w.print("{X:0>2}", .{b});
        }
        const algo: PublicKeyAlgorithm = @enumFromInt(body[9]);
        try w.print(" algo={s}", .{algo.name()});
    }
    return buf.toOwnedSlice(allocator);
}

fn describeSkeskPacket(allocator: Allocator, body: []const u8) ![]u8 {
    if (body.len < 2) return try allocator.dupe(u8, "truncated SKESK");
    const version = body[0];
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);
    try w.print("v{d}", .{version});
    if (version == 4 and body.len >= 2) {
        const algo: SymmetricAlgorithm = @enumFromInt(body[1]);
        try w.print(" cipher={s}", .{algo.name()});
    } else if (version == 6 and body.len >= 5) {
        // V6: version(1) + count(1) + cipher(1) + aead(1) + s2k
        const cipher: SymmetricAlgorithm = @enumFromInt(body[2]);
        const aead_algo: AeadAlgorithm = @enumFromInt(body[3]);
        try w.print(" cipher={s} aead={s}", .{ cipher.name(), aead_algo.name() });
    }
    return buf.toOwnedSlice(allocator);
}

fn describeSeipdPacket(allocator: Allocator, body: []const u8) ![]u8 {
    if (body.len < 1) return try allocator.dupe(u8, "truncated SEIPD");
    const version = body[0];
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);
    try w.print("v{d}", .{version});
    if (version == 2 and body.len >= 4) {
        const cipher: SymmetricAlgorithm = @enumFromInt(body[1]);
        const aead_algo: AeadAlgorithm = @enumFromInt(body[2]);
        try w.print(" cipher={s} aead={s}", .{ cipher.name(), aead_algo.name() });
    }
    return buf.toOwnedSlice(allocator);
}

fn describeOnePassSigPacket(allocator: Allocator, body: []const u8) ![]u8 {
    if (body.len < 4) return try allocator.dupe(u8, "truncated one-pass signature");
    const version = body[0];
    const sig_type = body[1];
    const hash_algo: HashAlgorithm = @enumFromInt(body[2]);
    const pub_algo: PublicKeyAlgorithm = @enumFromInt(body[3]);
    return try std.fmt.allocPrint(allocator, "v{d} type=0x{X:0>2} {s}/{s}", .{
        version,
        sig_type,
        pub_algo.name(),
        hash_algo.name(),
    });
}

/// Return a human-readable name for a signature type.
fn sigTypeName(sig_type: u8) []const u8 {
    return switch (sig_type) {
        0x00 => "Binary Document",
        0x01 => "Canonical Text",
        0x02 => "Standalone",
        0x10 => "Generic Certification",
        0x11 => "Persona Certification",
        0x12 => "Casual Certification",
        0x13 => "Positive Certification",
        0x18 => "Subkey Binding",
        0x19 => "Primary Key Binding",
        0x1F => "Direct Key",
        0x20 => "Key Revocation",
        0x28 => "Subkey Revocation",
        0x30 => "Certification Revocation",
        0x40 => "Timestamp",
        0x50 => "Third-Party Confirmation",
        else => "Unknown",
    };
}

/// Extract creation time from hashed subpacket data.
fn extractCreationTime(subpacket_data: []const u8) ?u32 {
    var pos: usize = 0;
    while (pos < subpacket_data.len) {
        // Read subpacket length
        if (pos >= subpacket_data.len) break;
        const first = subpacket_data[pos];
        pos += 1;
        var sp_len: usize = 0;
        if (first < 192) {
            sp_len = first;
        } else if (first < 255) {
            if (pos >= subpacket_data.len) break;
            const second = subpacket_data[pos];
            pos += 1;
            sp_len = (@as(usize, first) - 192) * 256 + @as(usize, second) + 192;
        } else {
            if (pos + 4 > subpacket_data.len) break;
            sp_len = mem.readInt(u32, subpacket_data[pos..][0..4], .big);
            pos += 4;
        }
        if (sp_len == 0) break;
        if (pos + sp_len - 1 > subpacket_data.len) break;

        const tag_byte = subpacket_data[pos];
        const tag_val = tag_byte & 0x7F; // strip critical bit
        if (tag_val == 2 and sp_len >= 5) { // creation_time
            if (pos + 5 <= subpacket_data.len) {
                return mem.readInt(u32, subpacket_data[pos + 1 ..][0..4], .big);
            }
        }
        pos += sp_len - 1; // -1 because sp_len includes the tag byte
    }
    return null;
}

/// Extract issuer key ID from subpacket data (both hashed and unhashed).
fn extractIssuerKeyId(allocator: Allocator, subpacket_data: []const u8) ?[]u8 {
    var pos: usize = 0;
    while (pos < subpacket_data.len) {
        if (pos >= subpacket_data.len) break;
        const first = subpacket_data[pos];
        pos += 1;
        var sp_len: usize = 0;
        if (first < 192) {
            sp_len = first;
        } else if (first < 255) {
            if (pos >= subpacket_data.len) break;
            const second = subpacket_data[pos];
            pos += 1;
            sp_len = (@as(usize, first) - 192) * 256 + @as(usize, second) + 192;
        } else {
            if (pos + 4 > subpacket_data.len) break;
            sp_len = mem.readInt(u32, subpacket_data[pos..][0..4], .big);
            pos += 4;
        }
        if (sp_len == 0) break;
        if (pos + sp_len - 1 > subpacket_data.len) break;

        const tag_byte = subpacket_data[pos];
        const tag_val = tag_byte & 0x7F;
        if (tag_val == 16 and sp_len >= 9) { // issuer key ID
            if (pos + 9 <= subpacket_data.len) {
                var hex_buf: std.ArrayList(u8) = .empty;
                const w = hex_buf.writer(allocator);
                for (subpacket_data[pos + 1 .. pos + 9]) |b| {
                    w.print("{X:0>2}", .{b}) catch return null;
                }
                return hex_buf.toOwnedSlice(allocator) catch return null;
            }
        }
        pos += sp_len - 1;
    }
    return null;
}

/// Extract issuer fingerprint from subpacket data.
fn extractIssuerFingerprint(allocator: Allocator, subpacket_data: []const u8) ?[]u8 {
    var pos: usize = 0;
    while (pos < subpacket_data.len) {
        if (pos >= subpacket_data.len) break;
        const first = subpacket_data[pos];
        pos += 1;
        var sp_len: usize = 0;
        if (first < 192) {
            sp_len = first;
        } else if (first < 255) {
            if (pos >= subpacket_data.len) break;
            const second = subpacket_data[pos];
            pos += 1;
            sp_len = (@as(usize, first) - 192) * 256 + @as(usize, second) + 192;
        } else {
            if (pos + 4 > subpacket_data.len) break;
            sp_len = mem.readInt(u32, subpacket_data[pos..][0..4], .big);
            pos += 4;
        }
        if (sp_len == 0) break;
        if (pos + sp_len - 1 > subpacket_data.len) break;

        const tag_byte = subpacket_data[pos];
        const tag_val = tag_byte & 0x7F;
        if (tag_val == 33 and sp_len >= 22) { // issuer fingerprint (v4: 1 version + 20 fp)
            if (pos + 22 <= subpacket_data.len) {
                // skip version byte at pos+1, fingerprint at pos+2..pos+22
                var hex_buf: std.ArrayList(u8) = .empty;
                const w = hex_buf.writer(allocator);
                for (subpacket_data[pos + 2 .. pos + 22]) |b| {
                    w.print("{X:0>2}", .{b}) catch return null;
                }
                return hex_buf.toOwnedSlice(allocator) catch return null;
            }
        }
        pos += sp_len - 1;
    }
    return null;
}

/// Extract key expiration time from subpacket data.
fn extractKeyExpirationTime(subpacket_data: []const u8) ?u32 {
    var pos: usize = 0;
    while (pos < subpacket_data.len) {
        if (pos >= subpacket_data.len) break;
        const first = subpacket_data[pos];
        pos += 1;
        var sp_len: usize = 0;
        if (first < 192) {
            sp_len = first;
        } else if (first < 255) {
            if (pos >= subpacket_data.len) break;
            const second = subpacket_data[pos];
            pos += 1;
            sp_len = (@as(usize, first) - 192) * 256 + @as(usize, second) + 192;
        } else {
            if (pos + 4 > subpacket_data.len) break;
            sp_len = mem.readInt(u32, subpacket_data[pos..][0..4], .big);
            pos += 4;
        }
        if (sp_len == 0) break;
        if (pos + sp_len - 1 > subpacket_data.len) break;

        const tag_byte = subpacket_data[pos];
        const tag_val = tag_byte & 0x7F;
        if (tag_val == 9 and sp_len >= 5) { // key_expiration_time
            if (pos + 5 <= subpacket_data.len) {
                return mem.readInt(u32, subpacket_data[pos + 1 ..][0..4], .big);
            }
        }
        pos += sp_len - 1;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Format packet dump
// ---------------------------------------------------------------------------

/// Format packet info as human-readable text.
pub fn formatPacketDump(allocator: Allocator, packets: []const PacketInfo) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    try w.print("OpenPGP Packet Dump ({d} packets):\n", .{packets.len});
    try w.writeAll("============================================================\n");

    for (packets, 0..) |pkt, i| {
        try w.print("\nPacket #{d}:\n", .{i + 1});
        try w.print("  Tag:    {d} ({s})\n", .{ @intFromEnum(pkt.tag), pkt.tag_name });
        try w.print("  Format: {s}\n", .{pkt.format});
        try w.print("  Length: {d} bytes\n", .{pkt.body_length});
        try w.print("  Offset: {d}\n", .{pkt.offset});
        if (pkt.details.len > 0) {
            try w.print("  Detail: {s}\n", .{pkt.details});
        }
    }

    return buf.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Key inspection
// ---------------------------------------------------------------------------

/// Inspect a key and produce detailed information.
pub fn inspectKey(allocator: Allocator, key_data: []const u8) !KeyInspection {
    const stripped = stripArmor(allocator, key_data);
    const binary = stripped.binary;
    defer freeArmorResult(allocator, stripped.decoded, stripped.headers);

    var version: u8 = 0;
    var algorithm: PublicKeyAlgorithm = .rsa_encrypt_sign;
    var creation_time: u32 = 0;
    var is_secret = false;
    var rsa_bits: ?u32 = null;
    var primary_body: ?[]const u8 = null;

    var user_ids: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (user_ids.items) |uid| allocator.free(uid);
        user_ids.deinit(allocator);
    }

    var subkeys: std.ArrayList(KeyInspection.SubkeyInfo) = .empty;
    errdefer {
        for (subkeys.items) |sk| sk.deinit(allocator);
        subkeys.deinit(allocator);
    }

    var is_revoked = false;
    var expiration_offset: ?u32 = null;

    // Parse packets
    var fbs = std.io.fixedBufferStream(binary);
    const rdr = fbs.reader();

    while (true) {
        const hdr = header_mod.readHeader(rdr) catch break;
        const body_len: u32 = switch (hdr.body_length) {
            .fixed => |len| len,
            .partial => |len| len,
            .indeterminate => 0,
        };

        if (body_len == 0 or fbs.pos + body_len > binary.len) break;
        const body = binary[fbs.pos .. fbs.pos + body_len];
        fbs.pos += body_len;

        switch (hdr.tag) {
            .public_key, .secret_key => {
                if (body.len >= 6) {
                    version = body[0];
                    creation_time = mem.readInt(u32, body[1..5], .big);
                    algorithm = @enumFromInt(body[5]);
                    is_secret = hdr.tag == .secret_key;
                    primary_body = body;

                    if ((algorithm == .rsa_encrypt_sign or algorithm == .rsa_encrypt_only or algorithm == .rsa_sign_only) and body.len > 8) {
                        rsa_bits = mem.readInt(u16, body[6..8], .big);
                    }
                }
            },
            .public_subkey, .secret_subkey => {
                if (body.len >= 6) {
                    const sk_version = body[0];
                    _ = sk_version;
                    const sk_creation = mem.readInt(u32, body[1..5], .big);
                    const sk_algo: PublicKeyAlgorithm = @enumFromInt(body[5]);
                    var sk_bits: ?u32 = null;
                    if ((sk_algo == .rsa_encrypt_sign or sk_algo == .rsa_encrypt_only or sk_algo == .rsa_sign_only) and body.len > 8) {
                        sk_bits = mem.readInt(u16, body[6..8], .big);
                    }
                    try subkeys.append(allocator, .{
                        .fingerprint = try allocator.dupe(u8, "(computed at import)"),
                        .algorithm = try allocator.dupe(u8, sk_algo.name()),
                        .bits = sk_bits,
                        .flags = try allocator.dupe(u8, ""),
                        .creation_time = sk_creation,
                    });
                }
            },
            .user_id => {
                try user_ids.append(allocator, try allocator.dupe(u8, body));
            },
            .signature => {
                if (body.len >= 6 and body[0] == 4) {
                    const sig_type = body[1];
                    // Check for revocation
                    if (sig_type == 0x20) { // Key revocation
                        is_revoked = true;
                    }
                    // Check for key expiration in self-signatures
                    if (sig_type >= 0x10 and sig_type <= 0x13) {
                        const hashed_len: usize = mem.readInt(u16, body[4..6], .big);
                        if (6 + hashed_len <= body.len) {
                            const exp = extractKeyExpirationTime(body[6 .. 6 + hashed_len]);
                            if (exp) |e| {
                                expiration_offset = e;
                            }
                        }
                    }
                }
            },
            else => {},
        }
    }

    // Calculate fingerprint and key ID
    var fingerprint_hex: []u8 = undefined;
    var key_id_hex: []u8 = undefined;

    if (primary_body) |_| {
        // Use the fingerprint module to compute
        const fingerprint_mod = @import("../key/fingerprint.zig");
        const fp = fingerprint_mod.calculateV4Fingerprint(primary_body.?);
        const kid = fingerprint_mod.calculateV4KeyId(primary_body.?);

        var fp_buf: std.ArrayList(u8) = .empty;
        errdefer fp_buf.deinit(allocator);
        const fp_w = fp_buf.writer(allocator);
        for (fp) |b| {
            try fp_w.print("{X:0>2}", .{b});
        }
        fingerprint_hex = try fp_buf.toOwnedSlice(allocator);

        var kid_buf: std.ArrayList(u8) = .empty;
        errdefer kid_buf.deinit(allocator);
        const kid_w = kid_buf.writer(allocator);
        for (kid) |b| {
            try kid_w.print("{X:0>2}", .{b});
        }
        key_id_hex = try kid_buf.toOwnedSlice(allocator);
    } else {
        fingerprint_hex = try allocator.dupe(u8, "(unknown)");
        key_id_hex = try allocator.dupe(u8, "(unknown)");
    }

    // Determine expiration
    var expiration_time: ?u32 = null;
    var is_expired = false;
    if (expiration_offset) |offset| {
        if (offset > 0) {
            expiration_time = creation_time + offset;
            // A rough check: if expiration_time < ~2026, it might be expired
            // Use 1775000000 as approximate April 2026 in unix time
            if (creation_time + offset < 1775000000) {
                is_expired = true;
            }
        }
    }

    return .{
        .version = version,
        .algorithm = try allocator.dupe(u8, algorithm.name()),
        .bits = rsa_bits,
        .fingerprint = fingerprint_hex,
        .key_id = key_id_hex,
        .creation_time = creation_time,
        .expiration_time = expiration_time,
        .user_ids = try user_ids.toOwnedSlice(allocator),
        .subkeys = try subkeys.toOwnedSlice(allocator),
        .is_secret = is_secret,
        .is_expired = is_expired,
        .is_revoked = is_revoked,
    };
}

// ---------------------------------------------------------------------------
// Signature inspection
// ---------------------------------------------------------------------------

/// Inspect a signature and produce detailed information.
pub fn inspectSignature(allocator: Allocator, sig_data: []const u8) !SignatureInspection {
    const stripped = stripArmor(allocator, sig_data);
    const binary = stripped.binary;
    defer freeArmorResult(allocator, stripped.decoded, stripped.headers);

    // Find the signature packet
    var fbs = std.io.fixedBufferStream(binary);
    const rdr = fbs.reader();

    while (true) {
        const hdr = header_mod.readHeader(rdr) catch return error.InvalidPacket;
        const body_len: u32 = switch (hdr.body_length) {
            .fixed => |len| len,
            .partial => |len| len,
            .indeterminate => 0,
        };

        if (body_len == 0 or fbs.pos + body_len > binary.len) return error.InvalidPacket;
        const body = binary[fbs.pos .. fbs.pos + body_len];
        fbs.pos += body_len;

        if (hdr.tag == .signature) {
            if (body.len < 4) return error.InvalidPacket;
            const version = body[0];

            if (version == 4 and body.len >= 10) {
                const sig_type = body[1];
                const pub_algo: PublicKeyAlgorithm = @enumFromInt(body[2]);
                const hash_algo: HashAlgorithm = @enumFromInt(body[3]);

                // Parse hashed subpackets for creation time
                const hashed_len: usize = mem.readInt(u16, body[4..6], .big);
                var creation: ?u32 = null;
                var issuer_kid: ?[]u8 = null;
                var issuer_fp: ?[]u8 = null;

                if (6 + hashed_len <= body.len) {
                    creation = extractCreationTime(body[6 .. 6 + hashed_len]);
                    issuer_kid = extractIssuerKeyId(allocator, body[6 .. 6 + hashed_len]);
                    issuer_fp = extractIssuerFingerprint(allocator, body[6 .. 6 + hashed_len]);
                }

                // Also check unhashed subpackets
                const unhashed_start = 6 + hashed_len;
                if (unhashed_start + 2 <= body.len) {
                    const unhashed_len: usize = mem.readInt(u16, body[unhashed_start..][0..2], .big);
                    const unhashed_data_start = unhashed_start + 2;
                    if (unhashed_data_start + unhashed_len <= body.len) {
                        if (issuer_kid == null) {
                            issuer_kid = extractIssuerKeyId(allocator, body[unhashed_data_start .. unhashed_data_start + unhashed_len]);
                        }
                        if (issuer_fp == null) {
                            issuer_fp = extractIssuerFingerprint(allocator, body[unhashed_data_start .. unhashed_data_start + unhashed_len]);
                        }
                    }
                }

                return .{
                    .version = version,
                    .sig_type = try allocator.dupe(u8, sigTypeName(sig_type)),
                    .pub_algo = try allocator.dupe(u8, pub_algo.name()),
                    .hash_algo = try allocator.dupe(u8, hash_algo.name()),
                    .creation_time = creation,
                    .issuer_key_id = issuer_kid,
                    .issuer_fingerprint = issuer_fp,
                };
            }

            // V3 or other
            return .{
                .version = version,
                .sig_type = try allocator.dupe(u8, "Unknown"),
                .pub_algo = try allocator.dupe(u8, "Unknown"),
                .hash_algo = try allocator.dupe(u8, "Unknown"),
                .creation_time = null,
                .issuer_key_id = null,
                .issuer_fingerprint = null,
            };
        }
    }

    return error.InvalidPacket;
}

// ---------------------------------------------------------------------------
// Message inspection
// ---------------------------------------------------------------------------

/// Inspect an encrypted message and produce detailed information.
pub fn inspectMessage(allocator: Allocator, data: []const u8) !MessageInspection {
    const is_armored = data.len > 10 and mem.startsWith(u8, data, "-----BEGIN ");
    const stripped = stripArmor(allocator, data);
    const binary = stripped.binary;
    defer freeArmorResult(allocator, stripped.decoded, stripped.headers);

    var is_encrypted = false;
    var is_signed = false;
    var has_pkesk = false;
    var has_skesk = false;
    var sym_algo: ?SymmetricAlgorithm = null;
    var aead_algo_val: ?AeadAlgorithm = null;
    var seipd_version: ?u8 = null;

    var recipient_ids: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (recipient_ids.items) |rid| allocator.free(rid);
        recipient_ids.deinit(allocator);
    }

    var fbs = std.io.fixedBufferStream(binary);
    const rdr = fbs.reader();

    while (true) {
        const hdr = header_mod.readHeader(rdr) catch break;
        const body_len: u32 = switch (hdr.body_length) {
            .fixed => |len| len,
            .partial => |len| len,
            .indeterminate => 0,
        };

        // For indeterminate or partial, we can't easily skip; just note the tag
        const can_skip = body_len > 0 and fbs.pos + body_len <= binary.len;
        const body: ?[]const u8 = if (can_skip) binary[fbs.pos .. fbs.pos + body_len] else null;

        switch (hdr.tag) {
            .public_key_encrypted_session_key => {
                is_encrypted = true;
                has_pkesk = true;
                if (body) |b| {
                    if (b.len >= 10 and b[0] == 3) {
                        var kid_buf: std.ArrayList(u8) = .empty;
                        const kid_w = kid_buf.writer(allocator);
                        for (b[1..9]) |byte| {
                            kid_w.print("{X:0>2}", .{byte}) catch break;
                        }
                        const kid_str = kid_buf.toOwnedSlice(allocator) catch break;
                        recipient_ids.append(allocator, kid_str) catch {
                            allocator.free(kid_str);
                        };
                    }
                }
            },
            .symmetric_key_encrypted_session_key => {
                is_encrypted = true;
                has_skesk = true;
                if (body) |b| {
                    if (b.len >= 2) {
                        if (b[0] == 4) {
                            sym_algo = @enumFromInt(b[1]);
                        } else if (b[0] == 6 and b.len >= 4) {
                            sym_algo = @enumFromInt(b[2]);
                            aead_algo_val = @enumFromInt(b[3]);
                        }
                    }
                }
            },
            .sym_encrypted_integrity_protected_data => {
                is_encrypted = true;
                if (body) |b| {
                    if (b.len >= 1) {
                        seipd_version = b[0];
                        if (b[0] == 2 and b.len >= 3) {
                            sym_algo = @enumFromInt(b[1]);
                            aead_algo_val = @enumFromInt(b[2]);
                        }
                    }
                }
            },
            .symmetrically_encrypted_data => {
                is_encrypted = true;
            },
            .signature, .one_pass_signature => {
                is_signed = true;
            },
            else => {},
        }

        if (can_skip) {
            fbs.pos += body_len;
        } else {
            break;
        }
    }

    // Determine encryption type
    var encryption_type: ?[]u8 = null;
    if (is_encrypted) {
        if (aead_algo_val != null) {
            encryption_type = try allocator.dupe(u8, "AEAD");
        } else if (has_pkesk) {
            encryption_type = try allocator.dupe(u8, "public-key");
        } else if (has_skesk) {
            encryption_type = try allocator.dupe(u8, "symmetric");
        } else {
            encryption_type = try allocator.dupe(u8, "unknown");
        }
    }

    return .{
        .is_encrypted = is_encrypted,
        .is_signed = is_signed,
        .is_armored = is_armored,
        .encryption_type = encryption_type,
        .sym_algo = if (sym_algo) |sa| try allocator.dupe(u8, sa.name()) else null,
        .aead_algo = if (aead_algo_val) |aa| try allocator.dupe(u8, aa.name()) else null,
        .recipient_key_ids = try recipient_ids.toOwnedSlice(allocator),
        .seipd_version = seipd_version,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "inspectPackets parses a simple literal data packet" {
    const allocator = std.testing.allocator;

    // Build a literal data packet: new format, tag=11, body = "b\x00\x00\x00\x00\x00Hello"
    var buf: [32]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();
    w.writeByte(0xCB) catch unreachable; // tag 11 new format
    w.writeByte(11) catch unreachable; // body length
    w.writeByte('b') catch unreachable; // format: binary
    w.writeByte(0) catch unreachable; // name length
    w.writeInt(u32, 0, .big) catch unreachable; // date
    w.writeAll("Hello") catch unreachable; // literal data

    const written = wfbs.getWritten();
    const packets = try inspectPackets(allocator, written);
    defer {
        for (packets) |p| p.deinit(allocator);
        allocator.free(packets);
    }

    try std.testing.expectEqual(@as(usize, 1), packets.len);
    try std.testing.expectEqual(PacketTag.literal_data, packets[0].tag);
    try std.testing.expectEqualStrings("Literal Data", packets[0].tag_name);
    try std.testing.expectEqualStrings("new", packets[0].format);
    try std.testing.expectEqual(@as(u32, 11), packets[0].body_length);
}

test "inspectPackets parses multiple packets" {
    const allocator = std.testing.allocator;

    // Build two packets: user_id + signature stub
    var buf: [64]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();

    // Packet 1: User ID "Alice"
    w.writeByte(0xC0 | 13) catch unreachable; // tag 13
    w.writeByte(5) catch unreachable;
    w.writeAll("Alice") catch unreachable;

    // Packet 2: Signature (minimal v4)
    w.writeByte(0xC0 | 2) catch unreachable; // tag 2
    w.writeByte(10) catch unreachable;
    // v4, type=0x13, RSA, SHA256, hashed_len=0, unhashed_len=0, hash_prefix
    w.writeAll(&[_]u8{ 4, 0x13, 1, 8, 0, 0, 0, 0, 0xAB, 0xCD }) catch unreachable;

    const written = wfbs.getWritten();
    const packets = try inspectPackets(allocator, written);
    defer {
        for (packets) |p| p.deinit(allocator);
        allocator.free(packets);
    }

    try std.testing.expectEqual(@as(usize, 2), packets.len);
    try std.testing.expectEqual(PacketTag.user_id, packets[0].tag);
    try std.testing.expectEqual(PacketTag.signature, packets[1].tag);
}

test "formatPacketDump produces output" {
    const allocator = std.testing.allocator;

    const info = [_]PacketInfo{
        .{
            .tag = .user_id,
            .tag_name = "User ID",
            .format = "new",
            .body_length = 5,
            .offset = 0,
            .details = "\"Alice\"",
        },
    };

    const dump = try formatPacketDump(allocator, &info);
    defer allocator.free(dump);

    try std.testing.expect(dump.len > 0);
    try std.testing.expect(mem.indexOf(u8, dump, "User ID") != null);
}

test "sigTypeName returns known names" {
    try std.testing.expectEqualStrings("Binary Document", sigTypeName(0x00));
    try std.testing.expectEqualStrings("Positive Certification", sigTypeName(0x13));
    try std.testing.expectEqualStrings("Subkey Binding", sigTypeName(0x18));
    try std.testing.expectEqualStrings("Key Revocation", sigTypeName(0x20));
    try std.testing.expectEqualStrings("Unknown", sigTypeName(0xFF));
}

test "extractCreationTime finds creation time" {
    // Subpacket: length=5, tag=2 (creation_time), 4 bytes timestamp
    var sp: [6]u8 = undefined;
    sp[0] = 5; // length (includes tag byte)
    sp[1] = 2; // tag: creation_time
    mem.writeInt(u32, sp[2..6], 1700000000, .big);

    const ct = extractCreationTime(&sp);
    try std.testing.expectEqual(@as(?u32, 1700000000), ct);
}

test "extractCreationTime returns null on empty data" {
    const ct = extractCreationTime("");
    try std.testing.expect(ct == null);
}

test "PacketInfo deinit frees memory" {
    const allocator = std.testing.allocator;
    const info = PacketInfo{
        .tag = .user_id,
        .tag_name = try allocator.dupe(u8, "User ID"),
        .format = try allocator.dupe(u8, "new"),
        .body_length = 0,
        .offset = 0,
        .details = try allocator.dupe(u8, "test"),
    };
    info.deinit(allocator);
}

test "MessageInspection deinit frees memory" {
    const allocator = std.testing.allocator;
    var mi = MessageInspection{
        .is_encrypted = true,
        .is_signed = false,
        .is_armored = false,
        .encryption_type = try allocator.dupe(u8, "public-key"),
        .sym_algo = try allocator.dupe(u8, "AES-256"),
        .aead_algo = null,
        .recipient_key_ids = try allocator.alloc([]const u8, 0),
        .seipd_version = 1,
    };
    mi.deinit(allocator);
}

test "inspectMessage on PKESK + SEIPD data" {
    const allocator = std.testing.allocator;

    // Build a minimal PKESK v3 + SEIPD v1 message
    var buf: [64]u8 = undefined;
    var wfbs = std.io.fixedBufferStream(&buf);
    const w = wfbs.writer();

    // PKESK v3: tag 1, length 12
    w.writeByte(0xC0 | 1) catch unreachable;
    w.writeByte(12) catch unreachable;
    w.writeByte(3) catch unreachable; // version
    w.writeAll(&[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 }) catch unreachable; // key_id
    w.writeByte(1) catch unreachable; // RSA
    w.writeByte(0) catch unreachable; // padding
    w.writeByte(0) catch unreachable; // padding

    // SEIPD v1: tag 18, length 3
    w.writeByte(0xC0 | 18) catch unreachable;
    w.writeByte(3) catch unreachable;
    w.writeByte(1) catch unreachable; // version
    w.writeByte(0x00) catch unreachable;
    w.writeByte(0x00) catch unreachable;

    const written = wfbs.getWritten();
    var msg = try inspectMessage(allocator, written);
    defer msg.deinit(allocator);

    try std.testing.expect(msg.is_encrypted);
    try std.testing.expect(!msg.is_signed);
    try std.testing.expect(!msg.is_armored);
    try std.testing.expectEqual(@as(?u8, 1), msg.seipd_version);
    try std.testing.expectEqual(@as(usize, 1), msg.recipient_key_ids.len);
    try std.testing.expectEqualStrings("AABBCCDDEEFF1122", msg.recipient_key_ids[0]);
}
