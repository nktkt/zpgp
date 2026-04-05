// SPDX-License-Identifier: MIT
//! V6 message decomposition - parsing and decrypting RFC 9580 messages.
//!
//! Handles messages that may contain:
//!   - SEIPDv2 packets (AEAD-encrypted, tag 18 version 2)
//!   - V6 PKESK packets (version 6)
//!   - V6 SKESK packets (version 6 with Argon2 S2K)
//!   - V6 signature packets
//!   - Mixed V4/V6 content
//!
//! The key difference from V4 decomposition:
//!   - SEIPDv2 uses AEAD (EAX/OCB/GCM) instead of CFB+MDC
//!   - SKESK v6 embeds Argon2 S2K parameters and AEAD-wrapped session keys
//!   - PKESK v6 includes key version and fingerprint
//!   - V6 signatures include a salt field

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const header_mod = @import("../packet/header.zig");
const PacketTag = @import("../packet/tags.zig").PacketTag;
const armor = @import("../armor/armor.zig");
const enums = @import("../types/enums.zig");
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const AeadAlgorithm = enums.AeadAlgorithm;
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;

const seipd_v2 = @import("../crypto/seipd_v2.zig");
const seipd = @import("../crypto/seipd.zig");
const aead_mod = @import("../crypto/aead/aead.zig");
const x25519_native = @import("../crypto/x25519_native.zig").X25519Native;
const rsa = @import("../crypto/rsa.zig");
const Argon2S2K = @import("../crypto/argon2.zig").Argon2S2K;
const S2K = @import("../types/s2k.zig").S2K;
const Mpi = @import("../types/mpi.zig").Mpi;

pub const V6DecomposeError = error{
    InvalidPacket,
    UnsupportedVersion,
    InvalidPacketTag,
    MalformedMessage,
    NotImplemented,
    OutOfMemory,
    EndOfStream,
    Overflow,
    DecryptionFailed,
    IntegrityCheckFailed,
    NoMatchingKey,
    UnsupportedAlgorithm,
    AeadAuthenticationFailed,
    InvalidS2K,
};

/// Information about a PKESK (Public-Key Encrypted Session Key) packet.
pub const PKESKInfo = struct {
    version: u8, // 3 (V4) or 6 (V6)
    key_version: u8, // for V6 only
    key_id: [8]u8,
    algorithm: PublicKeyAlgorithm,
    encrypted_data: []u8,

    pub fn deinit(self: PKESKInfo, allocator: Allocator) void {
        allocator.free(self.encrypted_data);
    }
};

/// Information about a SKESK (Symmetric-Key Encrypted Session Key) packet.
pub const SKESKInfo = struct {
    version: u8, // 4 or 6
    sym_algo: SymmetricAlgorithm,
    aead_algo: ?AeadAlgorithm, // V6 only
    s2k_data: []u8,
    encrypted_session_key: ?[]u8, // V4: CFB-encrypted; V6: AEAD-encrypted + tag
    iv_or_nonce: ?[]u8, // V6 only

    pub fn deinit(self: SKESKInfo, allocator: Allocator) void {
        allocator.free(self.s2k_data);
        if (self.encrypted_session_key) |esk| allocator.free(esk);
        if (self.iv_or_nonce) |iv| allocator.free(iv);
    }
};

/// Information about a V6 signature.
pub const SignatureInfo = struct {
    version: u8,
    sig_type: u8,
    pub_algo: PublicKeyAlgorithm,
    hash_algo: HashAlgorithm,
    hash_prefix: [2]u8,
    salt: []u8,
    signature_data: []u8,

    pub fn deinit(self: SignatureInfo, allocator: Allocator) void {
        allocator.free(self.salt);
        allocator.free(self.signature_data);
    }
};

/// Literal data information.
pub const LiteralDataInfo = struct {
    format: u8,
    filename: []u8,
    timestamp: u32,
    data: []u8,

    pub fn deinit(self: LiteralDataInfo, allocator: Allocator) void {
        allocator.free(self.filename);
        allocator.free(self.data);
    }
};

/// SEIPDv2 specific information.
pub const SeipdV2Info = struct {
    sym_algo: SymmetricAlgorithm,
    aead_algo: AeadAlgorithm,
    chunk_size_octet: u8,
    salt: [32]u8,
    encrypted_data: []u8,

    pub fn deinit(self: SeipdV2Info, allocator: Allocator) void {
        allocator.free(self.encrypted_data);
    }
};

/// A parsed V6 OpenPGP message.
pub const ParsedV6Message = struct {
    version: u8, // 1 (legacy SEIPDv1) or 2 (v6/AEAD SEIPDv2)
    pkesk_packets: std.ArrayList(PKESKInfo),
    skesk_packets: std.ArrayList(SKESKInfo),
    encrypted_data_v1: ?[]u8, // SEIPD v1 data
    encrypted_data_v2: ?SeipdV2Info, // SEIPD v2 data
    signatures: std.ArrayList(SignatureInfo),
    literal_data: ?LiteralDataInfo,

    /// Create an empty ParsedV6Message.
    pub fn init() ParsedV6Message {
        return .{
            .version = 0,
            .pkesk_packets = .empty,
            .skesk_packets = .empty,
            .encrypted_data_v1 = null,
            .encrypted_data_v2 = null,
            .signatures = .empty,
            .literal_data = null,
        };
    }

    /// Free all memory associated with this parsed message.
    pub fn deinit(self: *ParsedV6Message, allocator: Allocator) void {
        for (self.pkesk_packets.items) |pkt| pkt.deinit(allocator);
        self.pkesk_packets.deinit(allocator);

        for (self.skesk_packets.items) |pkt| pkt.deinit(allocator);
        self.skesk_packets.deinit(allocator);

        if (self.encrypted_data_v1) |d| allocator.free(d);
        if (self.encrypted_data_v2) |*d| d.deinit(allocator);

        for (self.signatures.items) |sig| sig.deinit(allocator);
        self.signatures.deinit(allocator);

        if (self.literal_data) |*ld| ld.deinit(allocator);
    }

    /// Check whether this message contains encrypted data.
    pub fn isEncrypted(self: *const ParsedV6Message) bool {
        return self.encrypted_data_v1 != null or self.encrypted_data_v2 != null;
    }

    /// Check whether this message contains signatures.
    pub fn isSigned(self: *const ParsedV6Message) bool {
        return self.signatures.items.len > 0;
    }

    /// Check whether this message uses V6/AEAD encryption.
    pub fn isAeadEncrypted(self: *const ParsedV6Message) bool {
        return self.encrypted_data_v2 != null;
    }
};

/// Parse a V6 message from packet data (may be armored).
pub fn parseV6Message(
    allocator: Allocator,
    data: []const u8,
) V6DecomposeError!ParsedV6Message {
    // Try to detect if data is ASCII-armored
    var binary_data: ?[]u8 = null;
    defer if (binary_data) |bd| allocator.free(bd);

    var packet_data: []const u8 = data;

    if (data.len > 10 and mem.startsWith(u8, data, "-----BEGIN ")) {
        const result = armor.decode(allocator, data) catch {
            return parseV6PacketStream(allocator, data);
        };
        binary_data = result.data;
        for (result.headers) |hdr| {
            allocator.free(hdr.name);
            allocator.free(hdr.value);
        }
        allocator.free(result.headers);
        packet_data = binary_data.?;
    }

    return parseV6PacketStream(allocator, packet_data);
}

/// Parse a stream of binary OpenPGP packets.
fn parseV6PacketStream(
    allocator: Allocator,
    data: []const u8,
) V6DecomposeError!ParsedV6Message {
    var result = ParsedV6Message.init();
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

        const body_len: usize = switch (hdr.body_length) {
            .fixed => |len| len,
            .indeterminate => {
                const pos = fbs.pos;
                const body = data[pos..];
                fbs.pos = data.len;
                try parseV6PacketBody(allocator, hdr.tag, body, &result);
                continue;
            },
            .partial => {
                // Collect partial body chunks
                const collected = collectPartialBody(allocator, data, &fbs) catch
                    return error.MalformedMessage;
                defer allocator.free(collected);
                try parseV6PacketBody(allocator, hdr.tag, collected, &result);
                continue;
            },
        };

        const pos = fbs.pos;
        if (pos + body_len > data.len) return error.MalformedMessage;
        const body = data[pos .. pos + body_len];
        fbs.pos = pos + body_len;

        try parseV6PacketBody(allocator, hdr.tag, body, &result);
    }

    return result;
}

/// Parse a single packet body.
fn parseV6PacketBody(
    allocator: Allocator,
    tag: PacketTag,
    body: []const u8,
    result: *ParsedV6Message,
) V6DecomposeError!void {
    switch (tag) {
        .public_key_encrypted_session_key => {
            const pkesk = try parsePkeskBody(allocator, body);
            result.pkesk_packets.append(allocator, pkesk) catch
                return error.OutOfMemory;
        },
        .symmetric_key_encrypted_session_key => {
            const skesk = try parseSkeskBody(allocator, body);
            result.skesk_packets.append(allocator, skesk) catch
                return error.OutOfMemory;
        },
        .sym_encrypted_integrity_protected_data => {
            if (body.len < 1) return error.InvalidPacket;
            const version = body[0];
            if (version == 2) {
                // SEIPDv2
                result.version = 2;
                const info = try parseSeipdV2Body(allocator, body);
                result.encrypted_data_v2 = info;
            } else {
                // SEIPDv1
                result.version = 1;
                result.encrypted_data_v1 = allocator.dupe(u8, body) catch
                    return error.OutOfMemory;
            }
        },
        .signature => {
            const sig = try parseSignatureBody(allocator, body);
            result.signatures.append(allocator, sig) catch
                return error.OutOfMemory;
        },
        .literal_data => {
            const ld = try parseLiteralDataBody(allocator, body);
            result.literal_data = ld;
        },
        else => {
            // Skip unknown/unhandled packet types
        },
    }
}

/// Parse a PKESK packet body (supports V3 and V6).
fn parsePkeskBody(allocator: Allocator, body: []const u8) V6DecomposeError!PKESKInfo {
    if (body.len < 2) return error.InvalidPacket;

    const version = body[0];

    if (version == 6) {
        // V6 PKESK
        if (body.len < 3) return error.InvalidPacket;
        const key_version = body[1];

        var offset: usize = 2;
        var key_id: [8]u8 = [_]u8{0} ** 8;

        if (key_version == 6) {
            // 32-byte fingerprint; extract first 8 as key ID
            if (offset + 32 > body.len) return error.InvalidPacket;
            @memcpy(&key_id, body[offset..][0..8]);
            offset += 32;
        } else {
            // 8-byte key ID
            if (offset + 8 > body.len) return error.InvalidPacket;
            @memcpy(&key_id, body[offset..][0..8]);
            offset += 8;
        }

        if (offset >= body.len) return error.InvalidPacket;
        const algorithm: PublicKeyAlgorithm = @enumFromInt(body[offset]);
        offset += 1;

        const enc_data = allocator.dupe(u8, body[offset..]) catch
            return error.OutOfMemory;

        return .{
            .version = 6,
            .key_version = key_version,
            .key_id = key_id,
            .algorithm = algorithm,
            .encrypted_data = enc_data,
        };
    } else if (version == 3) {
        // V3 PKESK (legacy)
        if (body.len < 10) return error.InvalidPacket;

        var key_id: [8]u8 = undefined;
        @memcpy(&key_id, body[1..9]);
        const algorithm: PublicKeyAlgorithm = @enumFromInt(body[9]);

        const enc_data = allocator.dupe(u8, body[10..]) catch
            return error.OutOfMemory;

        return .{
            .version = 3,
            .key_version = 4,
            .key_id = key_id,
            .algorithm = algorithm,
            .encrypted_data = enc_data,
        };
    } else {
        return error.UnsupportedVersion;
    }
}

/// Parse a SKESK packet body (supports V4 and V6).
fn parseSkeskBody(allocator: Allocator, body: []const u8) V6DecomposeError!SKESKInfo {
    if (body.len < 2) return error.InvalidPacket;

    const version = body[0];

    if (version == 6) {
        // V6 SKESK
        if (body.len < 5) return error.InvalidPacket;

        const count = body[1]; // length of following fields before IV
        const sym_algo: SymmetricAlgorithm = @enumFromInt(body[2]);
        const aead_algo: AeadAlgorithm = @enumFromInt(body[3]);

        // S2K specifier starts at offset 4
        var offset: usize = 4;
        const s2k_end = 2 + @as(usize, count); // version(1) + count(1) + count bytes
        if (s2k_end > body.len) return error.InvalidPacket;

        const s2k_data = allocator.dupe(u8, body[offset..s2k_end]) catch
            return error.OutOfMemory;
        errdefer allocator.free(s2k_data);
        offset = s2k_end;

        // IV/nonce
        const nonce_size = aead_algo.nonceSize() orelse return error.UnsupportedAlgorithm;
        if (offset + nonce_size > body.len) return error.InvalidPacket;
        const nonce = allocator.dupe(u8, body[offset..][0..nonce_size]) catch
            return error.OutOfMemory;
        errdefer allocator.free(nonce);
        offset += nonce_size;

        // Encrypted session key + AEAD tag
        const esk = if (offset < body.len)
            allocator.dupe(u8, body[offset..]) catch return error.OutOfMemory
        else
            null;

        return .{
            .version = 6,
            .sym_algo = sym_algo,
            .aead_algo = aead_algo,
            .s2k_data = s2k_data,
            .encrypted_session_key = esk,
            .iv_or_nonce = nonce,
        };
    } else if (version == 4) {
        // V4 SKESK
        const sym_algo: SymmetricAlgorithm = @enumFromInt(body[1]);

        const s2k_data = allocator.dupe(u8, body[2..]) catch
            return error.OutOfMemory;

        return .{
            .version = 4,
            .sym_algo = sym_algo,
            .aead_algo = null,
            .s2k_data = s2k_data,
            .encrypted_session_key = null,
            .iv_or_nonce = null,
        };
    } else {
        return error.UnsupportedVersion;
    }
}

/// Parse a SEIPDv2 body.
fn parseSeipdV2Body(allocator: Allocator, body: []const u8) V6DecomposeError!SeipdV2Info {
    if (body.len < 36) return error.InvalidPacket;

    const sym_algo: SymmetricAlgorithm = @enumFromInt(body[1]);
    const aead_algo: AeadAlgorithm = @enumFromInt(body[2]);
    const chunk_size_octet = body[3];
    var salt: [32]u8 = undefined;
    @memcpy(&salt, body[4..36]);

    const encrypted_data = allocator.dupe(u8, body[36..]) catch
        return error.OutOfMemory;

    return .{
        .sym_algo = sym_algo,
        .aead_algo = aead_algo,
        .chunk_size_octet = chunk_size_octet,
        .salt = salt,
        .encrypted_data = encrypted_data,
    };
}

/// Parse a signature packet body.
fn parseSignatureBody(allocator: Allocator, body: []const u8) V6DecomposeError!SignatureInfo {
    if (body.len < 4) return error.InvalidPacket;

    const version = body[0];

    if (version == 6) {
        // V6 signature
        if (body.len < 12) return error.InvalidPacket;

        const sig_type = body[1];
        const pub_algo: PublicKeyAlgorithm = @enumFromInt(body[2]);
        const hash_algo: HashAlgorithm = @enumFromInt(body[3]);

        // Hashed subpackets (4-byte length in V6)
        const hashed_len = mem.readInt(u32, body[4..8], .big);
        var offset: usize = 8 + hashed_len;

        // Unhashed subpackets (4-byte length in V6)
        if (offset + 4 > body.len) return error.InvalidPacket;
        const unhashed_len = mem.readInt(u32, body[offset..][0..4], .big);
        offset += 4 + unhashed_len;

        // Hash prefix
        if (offset + 2 > body.len) return error.InvalidPacket;
        var hash_prefix: [2]u8 = undefined;
        hash_prefix[0] = body[offset];
        hash_prefix[1] = body[offset + 1];
        offset += 2;

        // Salt
        if (offset >= body.len) return error.InvalidPacket;
        const salt_len = body[offset];
        offset += 1;
        if (offset + salt_len > body.len) return error.InvalidPacket;
        const salt = allocator.dupe(u8, body[offset..][0..salt_len]) catch
            return error.OutOfMemory;
        errdefer allocator.free(salt);
        offset += salt_len;

        // Signature data
        const sig_data = allocator.dupe(u8, body[offset..]) catch
            return error.OutOfMemory;

        return .{
            .version = 6,
            .sig_type = sig_type,
            .pub_algo = pub_algo,
            .hash_algo = hash_algo,
            .hash_prefix = hash_prefix,
            .salt = salt,
            .signature_data = sig_data,
        };
    } else if (version == 4) {
        // V4 signature (simplified parsing)
        const sig_type = body[1];
        const pub_algo: PublicKeyAlgorithm = @enumFromInt(body[2]);
        const hash_algo: HashAlgorithm = @enumFromInt(body[3]);

        // Skip subpackets
        if (body.len < 8) return error.InvalidPacket;
        const hashed_len = mem.readInt(u16, body[4..6], .big);
        var offset: usize = 6 + hashed_len;
        if (offset + 2 > body.len) return error.InvalidPacket;
        const unhashed_len = mem.readInt(u16, body[offset..][0..2], .big);
        offset += 2 + unhashed_len;

        if (offset + 2 > body.len) return error.InvalidPacket;
        var hash_prefix: [2]u8 = undefined;
        hash_prefix[0] = body[offset];
        hash_prefix[1] = body[offset + 1];
        offset += 2;

        const sig_data = allocator.dupe(u8, body[offset..]) catch
            return error.OutOfMemory;

        return .{
            .version = 4,
            .sig_type = sig_type,
            .pub_algo = pub_algo,
            .hash_algo = hash_algo,
            .hash_prefix = hash_prefix,
            .salt = allocator.alloc(u8, 0) catch return error.OutOfMemory,
            .signature_data = sig_data,
        };
    } else {
        return error.UnsupportedVersion;
    }
}

/// Parse a literal data packet body.
fn parseLiteralDataBody(allocator: Allocator, body: []const u8) V6DecomposeError!LiteralDataInfo {
    if (body.len < 6) return error.InvalidPacket;

    const format = body[0];
    const filename_len = body[1];
    if (2 + @as(usize, filename_len) + 4 > body.len) return error.InvalidPacket;

    const filename = allocator.dupe(u8, body[2..][0..filename_len]) catch
        return error.OutOfMemory;
    errdefer allocator.free(filename);

    const ts_offset = 2 + @as(usize, filename_len);
    const timestamp = mem.readInt(u32, body[ts_offset..][0..4], .big);

    const data_offset = ts_offset + 4;
    const data = allocator.dupe(u8, body[data_offset..]) catch
        return error.OutOfMemory;

    return .{
        .format = format,
        .filename = filename,
        .timestamp = timestamp,
        .data = data,
    };
}

/// Collect partial body chunks.
fn collectPartialBody(
    allocator: Allocator,
    data: []const u8,
    fbs: *std.io.FixedBufferStream([]const u8),
) ![]u8 {
    var collected: std.ArrayList(u8) = .empty;
    errdefer collected.deinit(allocator);

    const pos = fbs.pos;
    if (pos < data.len) {
        try collected.appendSlice(allocator, data[pos..]);
        fbs.pos = data.len;
    }

    return try collected.toOwnedSlice(allocator);
}

/// Decrypt a V6 message using the provided session key.
///
/// Works for both SEIPDv1 and SEIPDv2 messages.
pub fn decryptV6WithSessionKey(
    allocator: Allocator,
    msg: *const ParsedV6Message,
    session_key: []const u8,
    sym_algo: SymmetricAlgorithm,
) V6DecomposeError![]u8 {
    if (msg.encrypted_data_v2) |v2| {
        // SEIPDv2 decryption
        // Reconstruct the full SEIPD v2 packet body
        const total_len = 36 + v2.encrypted_data.len;
        const seipd_body = allocator.alloc(u8, total_len) catch
            return error.OutOfMemory;
        defer allocator.free(seipd_body);

        seipd_body[0] = 2; // version
        seipd_body[1] = @intFromEnum(v2.sym_algo);
        seipd_body[2] = @intFromEnum(v2.aead_algo);
        seipd_body[3] = v2.chunk_size_octet;
        @memcpy(seipd_body[4..36], &v2.salt);
        @memcpy(seipd_body[36..], v2.encrypted_data);

        const inner_packets = seipd_v2.seipdV2Decrypt(
            allocator,
            seipd_body,
            session_key,
        ) catch return error.AeadAuthenticationFailed;
        defer allocator.free(inner_packets);

        return extractLiteralDataFromPackets(allocator, inner_packets);
    } else if (msg.encrypted_data_v1) |v1| {
        // SEIPDv1 decryption
        const inner_packets = seipd.seipdDecrypt(
            allocator,
            v1,
            session_key,
            sym_algo,
        ) catch return error.IntegrityCheckFailed;
        defer allocator.free(inner_packets);

        return extractLiteralDataFromPackets(allocator, inner_packets);
    } else {
        return error.MalformedMessage;
    }
}

/// Decrypt a V6 message with a secret key (X25519 or RSA).
pub fn decryptV6WithKey(
    allocator: Allocator,
    msg: *const ParsedV6Message,
    key_data: []const u8,
) V6DecomposeError![]u8 {
    if (!msg.isEncrypted()) return error.MalformedMessage;

    // Try to find a matching PKESK and decrypt the session key
    for (msg.pkesk_packets.items) |pkesk| {
        switch (pkesk.algorithm) {
            .x25519 => {
                if (key_data.len < 64) continue; // need secret(32) + public(32)
                var secret: [32]u8 = undefined;
                @memcpy(&secret, key_data[0..32]);
                var public: [32]u8 = undefined;
                @memcpy(&public, key_data[32..64]);

                // The encrypted data should contain: ephemeral_public(32) + wrapped_key_len(1) + wrapped_key
                if (pkesk.encrypted_data.len < 33) continue;
                var eph_pub: [32]u8 = undefined;
                @memcpy(&eph_pub, pkesk.encrypted_data[0..32]);
                const wk_len = pkesk.encrypted_data[32];
                if (33 + @as(usize, wk_len) > pkesk.encrypted_data.len) continue;
                const wrapped_key = pkesk.encrypted_data[33..][0..wk_len];

                // Try to determine the symmetric algorithm from the message
                const sym_algo: SymmetricAlgorithm = if (msg.encrypted_data_v2) |v2|
                    v2.sym_algo
                else
                    .aes128;

                const session_key = x25519_native.decryptSessionKey(
                    allocator,
                    secret,
                    public,
                    eph_pub,
                    wrapped_key,
                    @intFromEnum(sym_algo),
                ) catch continue;
                defer allocator.free(session_key);

                return decryptV6WithSessionKey(allocator, msg, session_key, sym_algo);
            },
            .rsa_encrypt_sign, .rsa_encrypt_only => {
                // RSA decryption would go here
                continue;
            },
            else => continue,
        }
    }

    return error.NoMatchingKey;
}

/// Decrypt a V6 message with a passphrase.
pub fn decryptV6WithPassphrase(
    allocator: Allocator,
    msg: *const ParsedV6Message,
    passphrase: []const u8,
) V6DecomposeError![]u8 {
    if (!msg.isEncrypted()) return error.MalformedMessage;

    for (msg.skesk_packets.items) |skesk| {
        if (skesk.version == 6) {
            // V6 SKESK: Argon2 S2K + AEAD
            const aead_algo = skesk.aead_algo orelse continue;
            const key_size = skesk.sym_algo.keySize() orelse continue;

            // Parse the S2K specifier
            if (skesk.s2k_data.len < 1) continue;
            const s2k_type = skesk.s2k_data[0];

            if (s2k_type == 4) {
                // Argon2
                var s2k_fbs = std.io.fixedBufferStream(skesk.s2k_data[1..]);
                const argon2 = Argon2S2K.readFrom(s2k_fbs.reader()) catch continue;

                // Derive the key
                var derived_key: [32]u8 = undefined;
                argon2.deriveKey(allocator, passphrase, derived_key[0..key_size]) catch continue;

                // Decrypt the session key using AEAD
                const nonce = skesk.iv_or_nonce orelse continue;
                const esk = skesk.encrypted_session_key orelse continue;

                if (esk.len < 16) continue; // at least a tag
                const ct_len = esk.len - 16;
                const ct = esk[0..ct_len];
                const tag = esk[ct_len..][0..16];

                // Build AD
                var ad: [24]u8 = undefined;
                ad[0] = 6; // version
                const inner_count: u8 = @intCast(1 + 1 + skesk.s2k_data.len);
                ad[1] = inner_count;
                ad[2] = @intFromEnum(skesk.sym_algo);
                ad[3] = @intFromEnum(aead_algo);
                const ad_len = @min(4 + skesk.s2k_data.len, ad.len);
                if (4 + skesk.s2k_data.len <= ad.len) {
                    @memcpy(ad[4..][0..skesk.s2k_data.len], skesk.s2k_data);
                }

                const aead_inner_algo: aead_mod.AeadAlgorithm = @enumFromInt(@intFromEnum(aead_algo));
                const session_key = aead_mod.aeadDecrypt(
                    allocator,
                    skesk.sym_algo,
                    aead_inner_algo,
                    derived_key[0..key_size],
                    nonce,
                    ct,
                    tag,
                    ad[0..ad_len],
                ) catch continue;
                defer allocator.free(session_key);

                return decryptV6WithSessionKey(allocator, msg, session_key, skesk.sym_algo);
            }
        } else if (skesk.version == 4) {
            // V4 SKESK: classic S2K
            const key_size = skesk.sym_algo.keySize() orelse continue;

            var s2k_fbs = std.io.fixedBufferStream(skesk.s2k_data);
            const s2k = S2K.readFrom(s2k_fbs.reader()) catch continue;

            var derived_key: [32]u8 = undefined;
            s2k.deriveKey(passphrase, derived_key[0..key_size]) catch continue;

            // If no encrypted session key, use derived key directly
            if (skesk.encrypted_session_key == null) {
                return decryptV6WithSessionKey(allocator, msg, derived_key[0..key_size], skesk.sym_algo);
            }
        }
    }

    return error.DecryptionFailed;
}

/// Extract literal data from decrypted inner packets.
fn extractLiteralDataFromPackets(allocator: Allocator, packet_data: []const u8) V6DecomposeError![]u8 {
    var fbs = std.io.fixedBufferStream(packet_data);
    const reader = fbs.reader();

    while (true) {
        const hdr = header_mod.readHeader(reader) catch |err| {
            switch (err) {
                error.EndOfStream => return error.MalformedMessage,
                error.InvalidPacketTag => return error.InvalidPacketTag,
            }
        };

        const body_len: usize = switch (hdr.body_length) {
            .fixed => |len| len,
            .indeterminate => {
                const pos = fbs.pos;
                const body = packet_data[pos..];
                fbs.pos = packet_data.len;

                if (hdr.tag == .literal_data) {
                    const ld = try parseLiteralDataBody(allocator, body);
                    defer {
                        allocator.free(ld.filename);
                    }
                    return ld.data;
                }
                continue;
            },
            .partial => {
                return error.MalformedMessage;
            },
        };

        const pos = fbs.pos;
        if (pos + body_len > packet_data.len) return error.MalformedMessage;
        const body = packet_data[pos .. pos + body_len];
        fbs.pos = pos + body_len;

        switch (hdr.tag) {
            .literal_data => {
                const ld = try parseLiteralDataBody(allocator, body);
                defer {
                    allocator.free(ld.filename);
                }
                return ld.data;
            },
            .compressed_data => {
                // TODO: decompress and recurse
                continue;
            },
            else => continue,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ParsedV6Message init and deinit" {
    const allocator = std.testing.allocator;
    var msg = ParsedV6Message.init();
    defer msg.deinit(allocator);

    try std.testing.expect(!msg.isEncrypted());
    try std.testing.expect(!msg.isSigned());
    try std.testing.expect(!msg.isAeadEncrypted());
    try std.testing.expect(msg.literal_data == null);
}

test "parseLiteralDataBody basic" {
    const allocator = std.testing.allocator;
    // format='b', filename_len=4, "test", timestamp=0, data="Hello"
    const body = [_]u8{ 'b', 4, 't', 'e', 's', 't', 0, 0, 0, 0, 'H', 'e', 'l', 'l', 'o' };
    const ld = try parseLiteralDataBody(allocator, &body);
    defer ld.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 'b'), ld.format);
    try std.testing.expectEqualStrings("test", ld.filename);
    try std.testing.expectEqual(@as(u32, 0), ld.timestamp);
    try std.testing.expectEqualStrings("Hello", ld.data);
}

test "parseLiteralDataBody empty filename" {
    const allocator = std.testing.allocator;
    const body = [_]u8{ 'b', 0, 0, 0, 0, 0, 'A', 'B', 'C' };
    const ld = try parseLiteralDataBody(allocator, &body);
    defer ld.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), ld.filename.len);
    try std.testing.expectEqualStrings("ABC", ld.data);
}

test "parseV6Message literal data packet" {
    const allocator = std.testing.allocator;
    const body = [_]u8{ 'b', 0, 0, 0, 0, 0, 'H', 'i' };
    const body_len: u8 = body.len;

    var packet: [2 + body.len]u8 = undefined;
    packet[0] = 0xCB; // new format, tag 11
    packet[1] = body_len;
    @memcpy(packet[2..], &body);

    var msg = try parseV6Message(allocator, &packet);
    defer msg.deinit(allocator);

    try std.testing.expect(msg.literal_data != null);
    try std.testing.expectEqualStrings("Hi", msg.literal_data.?.data);
}

test "parseV6Message SEIPD v1 packet" {
    const allocator = std.testing.allocator;
    const seipd_body = [_]u8{ 1, 0xDE, 0xAD, 0xBE, 0xEF };

    var packet: [2 + seipd_body.len]u8 = undefined;
    packet[0] = 0xD2; // tag 18
    packet[1] = seipd_body.len;
    @memcpy(packet[2..], &seipd_body);

    var msg = try parseV6Message(allocator, &packet);
    defer msg.deinit(allocator);

    try std.testing.expect(msg.isEncrypted());
    try std.testing.expectEqual(@as(u8, 1), msg.version);
    try std.testing.expect(!msg.isAeadEncrypted());
}

test "parseV6Message SEIPD v2 packet" {
    const allocator = std.testing.allocator;
    // SEIPDv2: version(2) + sym(7=AES128) + aead(1=EAX) + chunk_size(6) + salt(32) + data(16+16)
    var seipd_body: [68]u8 = undefined;
    seipd_body[0] = 2; // version
    seipd_body[1] = 7; // AES-128
    seipd_body[2] = 1; // EAX
    seipd_body[3] = 6; // chunk_size_octet
    @memset(seipd_body[4..36], 0xAA); // salt
    @memset(seipd_body[36..68], 0xBB); // encrypted data

    var packet: [2 + 68]u8 = undefined;
    packet[0] = 0xD2; // tag 18
    packet[1] = 68;
    @memcpy(packet[2..], &seipd_body);

    var msg = try parseV6Message(allocator, &packet);
    defer msg.deinit(allocator);

    try std.testing.expect(msg.isEncrypted());
    try std.testing.expectEqual(@as(u8, 2), msg.version);
    try std.testing.expect(msg.isAeadEncrypted());

    const v2 = msg.encrypted_data_v2.?;
    try std.testing.expectEqual(SymmetricAlgorithm.aes128, v2.sym_algo);
    try std.testing.expectEqual(@as(u8, 6), v2.chunk_size_octet);
}

test "parseV6Message PKESK v3 packet" {
    const allocator = std.testing.allocator;
    var pkesk_body: [13]u8 = undefined;
    pkesk_body[0] = 3; // version
    @memset(pkesk_body[1..9], 0x42); // key_id
    pkesk_body[9] = 1; // RSA
    mem.writeInt(u16, pkesk_body[10..12], 8, .big); // MPI bits
    pkesk_body[12] = 0xFF;

    var packet: [2 + 13]u8 = undefined;
    packet[0] = 0xC1; // tag 1
    packet[1] = 13;
    @memcpy(packet[2..], pkesk_body[0..13]);

    var msg = try parseV6Message(allocator, &packet);
    defer msg.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), msg.pkesk_packets.items.len);
    try std.testing.expectEqual(@as(u8, 3), msg.pkesk_packets.items[0].version);
}

test "parseV6Message SKESK v4 packet" {
    const allocator = std.testing.allocator;
    const skesk_body = [_]u8{ 4, 7, 0, 8 }; // version 4, AES128, simple S2K, SHA256

    var packet: [2 + skesk_body.len]u8 = undefined;
    packet[0] = 0xC3; // tag 3
    packet[1] = skesk_body.len;
    @memcpy(packet[2..], &skesk_body);

    var msg = try parseV6Message(allocator, &packet);
    defer msg.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), msg.skesk_packets.items.len);
    try std.testing.expectEqual(@as(u8, 4), msg.skesk_packets.items[0].version);
}

test "parseV6Message signature v4 packet" {
    const allocator = std.testing.allocator;
    var sig_body: [13]u8 = undefined;
    sig_body[0] = 4; // version
    sig_body[1] = 0x00; // sig_type
    sig_body[2] = 1; // RSA
    sig_body[3] = 8; // SHA256
    mem.writeInt(u16, sig_body[4..6], 0, .big); // hashed subpackets
    mem.writeInt(u16, sig_body[6..8], 0, .big); // unhashed subpackets
    sig_body[8] = 0xAB; // hash prefix
    sig_body[9] = 0xCD;
    mem.writeInt(u16, sig_body[10..12], 8, .big); // MPI
    sig_body[12] = 0xFF;

    var packet: [2 + 13]u8 = undefined;
    packet[0] = 0xC2; // tag 2
    packet[1] = 13;
    @memcpy(packet[2..], sig_body[0..13]);

    var msg = try parseV6Message(allocator, &packet);
    defer msg.deinit(allocator);

    try std.testing.expect(msg.isSigned());
    try std.testing.expectEqual(@as(usize, 1), msg.signatures.items.len);
    try std.testing.expectEqual(@as(u8, 4), msg.signatures.items[0].version);
}

test "parseV6Message empty data" {
    const allocator = std.testing.allocator;
    var msg = try parseV6Message(allocator, &[_]u8{});
    defer msg.deinit(allocator);

    try std.testing.expect(!msg.isEncrypted());
    try std.testing.expect(!msg.isSigned());
}

test "parseV6Message multiple packets" {
    const allocator = std.testing.allocator;

    var buf: [128]u8 = undefined;
    var offset: usize = 0;

    // PKESK packet
    buf[offset] = 0xC1; // tag 1
    offset += 1;
    buf[offset] = 13; // body len
    offset += 1;
    buf[offset] = 3; // version
    offset += 1;
    @memset(buf[offset .. offset + 8], 0x11);
    offset += 8;
    buf[offset] = 1; // RSA
    offset += 1;
    mem.writeInt(u16, buf[offset..][0..2], 8, .big);
    offset += 2;
    buf[offset] = 0xAA;
    offset += 1;

    // SEIPD v1 packet
    buf[offset] = 0xD2; // tag 18
    offset += 1;
    buf[offset] = 5; // body len
    offset += 1;
    buf[offset] = 1; // version 1
    offset += 1;
    @memset(buf[offset .. offset + 4], 0xBB);
    offset += 4;

    var msg = try parseV6Message(allocator, buf[0..offset]);
    defer msg.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), msg.pkesk_packets.items.len);
    try std.testing.expect(msg.isEncrypted());
}

test "decryptV6WithSessionKey requires encrypted message" {
    const allocator = std.testing.allocator;
    var msg = ParsedV6Message.init();
    defer msg.deinit(allocator);

    const result = decryptV6WithSessionKey(allocator, &msg, &[_]u8{0} ** 16, .aes128);
    try std.testing.expectError(error.MalformedMessage, result);
}

test "decryptV6WithKey requires encrypted message" {
    const allocator = std.testing.allocator;
    var msg = ParsedV6Message.init();
    defer msg.deinit(allocator);

    const result = decryptV6WithKey(allocator, &msg, &[_]u8{0} ** 64);
    try std.testing.expectError(error.MalformedMessage, result);
}

test "decryptV6WithPassphrase requires encrypted message" {
    const allocator = std.testing.allocator;
    var msg = ParsedV6Message.init();
    defer msg.deinit(allocator);

    const result = decryptV6WithPassphrase(allocator, &msg, "password");
    try std.testing.expectError(error.MalformedMessage, result);
}

test "SeipdV2Info stores correct algorithm info" {
    const allocator = std.testing.allocator;
    const data = try allocator.alloc(u8, 32);
    defer allocator.free(data);
    @memset(data, 0xCC);

    var info = SeipdV2Info{
        .sym_algo = .aes256,
        .aead_algo = .gcm,
        .chunk_size_octet = 10,
        .salt = [_]u8{0xDD} ** 32,
        .encrypted_data = data,
    };
    _ = &info;

    try std.testing.expectEqual(SymmetricAlgorithm.aes256, info.sym_algo);
    try std.testing.expectEqual(@as(u8, 10), info.chunk_size_octet);
}

test "PKESKInfo version tracking" {
    const allocator = std.testing.allocator;
    const data = try allocator.alloc(u8, 4);
    defer allocator.free(data);
    @memset(data, 0xEE);

    const info = PKESKInfo{
        .version = 6,
        .key_version = 6,
        .key_id = [_]u8{0xFF} ** 8,
        .algorithm = .x25519,
        .encrypted_data = data,
    };

    try std.testing.expectEqual(@as(u8, 6), info.version);
    try std.testing.expectEqual(@as(u8, 6), info.key_version);
}

test "SKESKInfo version 6 fields" {
    const allocator = std.testing.allocator;
    const s2k_data = try allocator.alloc(u8, 4);
    defer allocator.free(s2k_data);

    const info = SKESKInfo{
        .version = 6,
        .sym_algo = .aes256,
        .aead_algo = .ocb,
        .s2k_data = s2k_data,
        .encrypted_session_key = null,
        .iv_or_nonce = null,
    };

    try std.testing.expectEqual(@as(u8, 6), info.version);
    try std.testing.expect(info.aead_algo != null);
}
