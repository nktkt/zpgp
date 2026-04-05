// SPDX-License-Identifier: MIT
//! V6 key import and export per RFC 9580 Section 10.1 (Transferable Public Keys).
//!
//! V6 transferable public key format:
//!   V6 Public-Key Packet (tag 6)
//!   [Direct Key Signature Packets (tag 2)]
//!   User ID Packet (tag 13)
//!     [V6 Signature Packet (tag 2) - self-signature]
//!     [V6 Signature Packets (tag 2) - certifications]
//!   [V6 Public-Subkey Packet (tag 14)
//!     [V6 Signature Packet (tag 2) - binding signature]]
//!
//! This module also provides auto-detection of V4 vs V6 keys.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const header_mod = @import("../packet/header.zig");
const PacketTag = @import("../packet/tags.zig").PacketTag;
const V6PublicKeyPacket = @import("../packets/v6_public_key.zig").V6PublicKeyPacket;
const V6SignaturePacket = @import("../packets/v6_signature.zig").V6SignaturePacket;
const V6Key = @import("v6_key.zig").V6Key;
const V6UserIdBinding = @import("v6_key.zig").V6UserIdBinding;
const V6SubkeyBinding = @import("v6_key.zig").V6SubkeyBinding;
const Key = @import("key.zig").Key;
const v4_import_export = @import("import_export.zig");
const armor = @import("../armor/armor.zig");

pub const V6ImportExportError = error{
    InvalidPacket,
    UnsupportedVersion,
    InvalidPacketTag,
    MalformedKey,
    NotAPublicKey,
    NotAV6Key,
    OutOfMemory,
    Overflow,
    NoSpaceLeft,
};

/// Union type that can hold either a V4 or V6 key.
pub const KeyVersion = union(enum) {
    v4: Key,
    v6: V6Key,

    /// Free all memory associated with this key, regardless of version.
    pub fn deinit(self: *KeyVersion, allocator: Allocator) void {
        switch (self.*) {
            .v4 => |*k| k.deinit(allocator),
            .v6 => |*k| k.deinit(),
        }
    }

    /// Get the key version number.
    pub fn version(self: *const KeyVersion) u8 {
        return switch (self.*) {
            .v4 => 4,
            .v6 => 6,
        };
    }

    /// Get the primary user ID, regardless of key version.
    pub fn primaryUserId(self: *const KeyVersion) ?[]const u8 {
        return switch (self.*) {
            .v4 => |*k| k.primaryUserId(),
            .v6 => |*k| k.primaryUserId(),
        };
    }
};

/// Export a V6 public key as an OpenPGP binary packet sequence.
///
/// Format:
///   V6 Public-Key Packet (tag 6)
///   [Direct Key Signature Packets (tag 2)]
///   For each user ID:
///     User ID Packet (tag 13)
///     [V6 Signature Packet (tag 2) - self-signature]
///     [V6 Signature Packets (tag 2) - certifications]
///   For each subkey:
///     V6 Public-Subkey Packet (tag 14)
///     [V6 Signature Packet (tag 2) - binding signature]
pub fn exportV6PublicKey(allocator: Allocator, key: *const V6Key) V6ImportExportError![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // 1. Write primary V6 public key packet (tag 6)
    const pk_body = key.primary_key.serialize(allocator) catch
        return error.OutOfMemory;
    defer allocator.free(pk_body);
    try writePacket(allocator, &output, .public_key, pk_body);

    // 2. Write direct key signatures
    for (key.direct_signatures.items) |sig| {
        const sig_body = serializeV6Signature(allocator, &sig) catch
            return error.OutOfMemory;
        defer allocator.free(sig_body);
        try writePacket(allocator, &output, .signature, sig_body);
    }

    // 3. Write user IDs and their signatures
    for (key.user_ids.items) |uid_binding| {
        // User ID packet (tag 13)
        const uid_body_len: u32 = @intCast(uid_binding.user_id.len);
        try writePacketRaw(allocator, &output, .user_id, uid_binding.user_id);

        _ = uid_body_len;

        // Self-signature
        if (uid_binding.self_signature) |sig| {
            const sig_body = serializeV6Signature(allocator, &sig) catch
                return error.OutOfMemory;
            defer allocator.free(sig_body);
            try writePacket(allocator, &output, .signature, sig_body);
        }

        // Third-party certifications
        for (uid_binding.certifications.items) |sig| {
            const sig_body = serializeV6Signature(allocator, &sig) catch
                return error.OutOfMemory;
            defer allocator.free(sig_body);
            try writePacket(allocator, &output, .signature, sig_body);
        }
    }

    // 4. Write subkeys and their binding signatures
    for (key.subkeys.items) |sub| {
        // Public-Subkey packet (tag 14)
        const sub_body = sub.key.serialize(allocator) catch
            return error.OutOfMemory;
        defer allocator.free(sub_body);
        try writePacket(allocator, &output, .public_subkey, sub_body);

        // Binding signature
        if (sub.binding_signature) |sig| {
            const sig_body = serializeV6Signature(allocator, &sig) catch
                return error.OutOfMemory;
            defer allocator.free(sig_body);
            try writePacket(allocator, &output, .signature, sig_body);
        }
    }

    return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Export a V6 public key as ASCII-armored text.
pub fn exportV6PublicKeyArmored(allocator: Allocator, key: *const V6Key) V6ImportExportError![]u8 {
    const binary = try exportV6PublicKey(allocator, key);
    defer allocator.free(binary);

    const headers = [_]armor.Header{
        .{ .name = "Version", .value = "zpgp 0.1 (RFC 9580)" },
    };

    return armor.encode(allocator, binary, .public_key, &headers) catch
        return error.OutOfMemory;
}

/// Import a V6 public key from binary packet data.
///
/// Reads the transferable V6 public key structure:
///   V6 Public-Key Packet -> Direct Sigs -> User ID + Sigs -> Subkeys + Sigs
pub fn importV6PublicKey(allocator: Allocator, data: []const u8) V6ImportExportError!V6Key {
    var fbs = std.io.fixedBufferStream(data);
    const reader = fbs.reader();

    // Read the first packet: must be a public key (tag 6)
    const first_hdr = header_mod.readHeader(reader) catch |err| {
        return switch (err) {
            error.EndOfStream => error.MalformedKey,
            error.InvalidPacketTag => error.InvalidPacketTag,
        };
    };

    if (first_hdr.tag != .public_key) return error.NotAPublicKey;

    const pk_body_len: usize = switch (first_hdr.body_length) {
        .fixed => |len| len,
        else => return error.MalformedKey,
    };

    if (fbs.pos + pk_body_len > data.len) return error.MalformedKey;
    const pk_body = data[fbs.pos .. fbs.pos + pk_body_len];
    fbs.pos += pk_body_len;

    // Check version byte
    if (pk_body.len < 1 or pk_body[0] != 6) return error.NotAV6Key;

    const primary_key = V6PublicKeyPacket.parse(allocator, pk_body, false) catch
        return error.InvalidPacket;
    errdefer primary_key.deinit(allocator);

    var key = V6Key.init(allocator, primary_key);
    errdefer key.deinit();

    // Parse remaining packets
    var current_uid_str: ?[]const u8 = null;
    var current_uid_sig: ?V6SignaturePacket = null;
    var pending_uid = false;

    while (true) {
        const hdr = header_mod.readHeader(reader) catch |err| {
            switch (err) {
                error.EndOfStream => break,
                error.InvalidPacketTag => return error.InvalidPacketTag,
            }
        };

        const body_len: usize = switch (hdr.body_length) {
            .fixed => |len| len,
            else => return error.MalformedKey,
        };

        if (fbs.pos + body_len > data.len) return error.MalformedKey;
        const body = data[fbs.pos .. fbs.pos + body_len];
        fbs.pos += body_len;

        switch (hdr.tag) {
            .user_id => {
                // Save any pending UID binding
                if (pending_uid) {
                    if (current_uid_str) |uid_str| {
                        key.addUserId(uid_str, current_uid_sig) catch return error.OutOfMemory;
                        allocator.free(uid_str);
                        current_uid_str = null;
                        current_uid_sig = null;
                    }
                }

                current_uid_str = allocator.dupe(u8, body) catch return error.OutOfMemory;
                current_uid_sig = null;
                pending_uid = true;
            },
            .signature => {
                // Try to parse as V6 signature
                const sig = V6SignaturePacket.parse(allocator, body) catch {
                    // If it's not a V6 signature, skip it
                    continue;
                };

                if (pending_uid) {
                    // Attach to current user ID
                    if (current_uid_sig == null and
                        sig.sig_type >= 0x10 and sig.sig_type <= 0x13)
                    {
                        current_uid_sig = sig;
                    } else {
                        // Additional certification - we need to flush current UID first
                        // For simplicity, discard extra sigs here
                        sig.deinit(allocator);
                    }
                } else if (key.user_ids.items.len == 0 and key.subkeys.items.len == 0) {
                    // Direct key signature (before any UIDs or subkeys)
                    if (sig.sig_type == 0x1F) {
                        key.addDirectSignature(sig) catch return error.OutOfMemory;
                    } else {
                        sig.deinit(allocator);
                    }
                } else {
                    // Signature after a subkey = binding signature
                    if (key.subkeys.items.len > 0) {
                        const last = &key.subkeys.items[key.subkeys.items.len - 1];
                        if (last.binding_signature == null) {
                            last.binding_signature = sig;
                        } else {
                            sig.deinit(allocator);
                        }
                    } else {
                        sig.deinit(allocator);
                    }
                }
            },
            .public_subkey => {
                // Save any pending UID binding
                if (pending_uid) {
                    if (current_uid_str) |uid_str| {
                        key.addUserId(uid_str, current_uid_sig) catch return error.OutOfMemory;
                        allocator.free(uid_str);
                        current_uid_str = null;
                        current_uid_sig = null;
                    }
                    pending_uid = false;
                }

                const sub_pk = V6PublicKeyPacket.parse(allocator, body, true) catch {
                    continue;
                };
                key.addSubkey(sub_pk, null) catch return error.OutOfMemory;
            },
            else => {
                // Skip unknown packet types
            },
        }
    }

    // Save the last pending UID binding
    if (pending_uid) {
        if (current_uid_str) |uid_str| {
            key.addUserId(uid_str, current_uid_sig) catch return error.OutOfMemory;
            allocator.free(uid_str);
        }
    }

    return key;
}

/// Auto-detect and import a public key (V4 or V6) from binary packet data.
///
/// Peeks at the first packet's body to determine the key version, then
/// dispatches to the appropriate import function.
pub fn importPublicKeyAuto(allocator: Allocator, data: []const u8) V6ImportExportError!KeyVersion {
    // Check for ASCII armor first
    if (data.len > 10 and mem.startsWith(u8, data, "-----BEGIN ")) {
        const result = armor.decode(allocator, data) catch {
            return importPublicKeyAutoBinary(allocator, data);
        };
        defer {
            allocator.free(result.data);
            for (result.headers) |hdr| {
                allocator.free(hdr.name);
                allocator.free(hdr.value);
            }
            allocator.free(result.headers);
        }
        return importPublicKeyAutoBinary(allocator, result.data);
    }

    return importPublicKeyAutoBinary(allocator, data);
}

/// Auto-detect V4 vs V6 from binary packet data.
fn importPublicKeyAutoBinary(allocator: Allocator, data: []const u8) V6ImportExportError!KeyVersion {
    // Parse the first packet header to find the key body
    var fbs = std.io.fixedBufferStream(data);
    const reader = fbs.reader();

    const hdr = header_mod.readHeader(reader) catch |err| {
        return switch (err) {
            error.EndOfStream => error.MalformedKey,
            error.InvalidPacketTag => error.InvalidPacketTag,
        };
    };

    if (hdr.tag != .public_key) return error.NotAPublicKey;

    const body_len: usize = switch (hdr.body_length) {
        .fixed => |len| len,
        else => return error.MalformedKey,
    };

    if (fbs.pos + body_len > data.len) return error.MalformedKey;
    const body = data[fbs.pos .. fbs.pos + body_len];

    if (body.len < 1) return error.MalformedKey;

    // Check version byte
    const key_version = body[0];

    if (key_version == 6) {
        const v6_key = try importV6PublicKey(allocator, data);
        return .{ .v6 = v6_key };
    } else if (key_version == 4) {
        const v4_key = v4_import_export.importPublicKey(allocator, data) catch |err| {
            return switch (err) {
                error.InvalidPacket => error.InvalidPacket,
                error.UnsupportedVersion => error.UnsupportedVersion,
                error.InvalidPacketTag => error.InvalidPacketTag,
                error.MalformedKey => error.MalformedKey,
                error.NotAPublicKey => error.NotAPublicKey,
                error.OutOfMemory => error.OutOfMemory,
                error.Overflow => error.Overflow,
                error.NoSpaceLeft => error.NoSpaceLeft,
            };
        };
        return .{ .v4 = v4_key };
    } else {
        return error.UnsupportedVersion;
    }
}

/// Write a single packet (header + body) to the output buffer.
fn writePacket(
    allocator: Allocator,
    output: *std.ArrayList(u8),
    tag: PacketTag,
    body: []const u8,
) V6ImportExportError!void {
    var hdr_buf: [6]u8 = undefined;
    var hdr_fbs = std.io.fixedBufferStream(&hdr_buf);
    header_mod.writeHeader(hdr_fbs.writer(), tag, @intCast(body.len)) catch
        return error.Overflow;
    output.appendSlice(allocator, hdr_fbs.getWritten()) catch return error.OutOfMemory;
    output.appendSlice(allocator, body) catch return error.OutOfMemory;
}

/// Write a packet with raw body data (no serialization needed).
fn writePacketRaw(
    allocator: Allocator,
    output: *std.ArrayList(u8),
    tag: PacketTag,
    body: []const u8,
) V6ImportExportError!void {
    try writePacket(allocator, output, tag, body);
}

/// Serialize a V6SignaturePacket to its body bytes.
fn serializeV6Signature(allocator: Allocator, sig: *const V6SignaturePacket) ![]u8 {
    // Reconstruct the signature body from fields
    // version(1) + sig_type(1) + pub_algo(1) + hash_algo(1)
    // + hashed_sp_len(4) + hashed_sp
    // + unhashed_sp_len(4) + unhashed_sp
    // + hash_prefix(2)
    // + salt
    // + signature MPIs
    var body_len: usize = 4 + // version + sig_type + pub_algo + hash_algo
        4 + sig.hashed_subpacket_data.len + // hashed subpackets (4-byte length in V6)
        4 + sig.unhashed_subpacket_data.len + // unhashed subpackets (4-byte length in V6)
        2 + // hash_prefix
        sig.salt.len; // salt

    for (sig.signature_mpis) |m| {
        body_len += m.wireLen();
    }

    const buf = try allocator.alloc(u8, body_len);
    errdefer allocator.free(buf);

    buf[0] = sig.version;
    buf[1] = sig.sig_type;
    buf[2] = @intFromEnum(sig.pub_algo);
    buf[3] = @intFromEnum(sig.hash_algo);

    var offset: usize = 4;

    // Hashed subpackets (4-byte length in V6)
    mem.writeInt(u32, buf[offset..][0..4], @intCast(sig.hashed_subpacket_data.len), .big);
    offset += 4;
    if (sig.hashed_subpacket_data.len > 0) {
        @memcpy(buf[offset .. offset + sig.hashed_subpacket_data.len], sig.hashed_subpacket_data);
        offset += sig.hashed_subpacket_data.len;
    }

    // Unhashed subpackets (4-byte length in V6)
    mem.writeInt(u32, buf[offset..][0..4], @intCast(sig.unhashed_subpacket_data.len), .big);
    offset += 4;
    if (sig.unhashed_subpacket_data.len > 0) {
        @memcpy(buf[offset .. offset + sig.unhashed_subpacket_data.len], sig.unhashed_subpacket_data);
        offset += sig.unhashed_subpacket_data.len;
    }

    // Hash prefix
    buf[offset] = sig.hash_prefix[0];
    buf[offset + 1] = sig.hash_prefix[1];
    offset += 2;

    // Salt
    @memcpy(buf[offset .. offset + sig.salt.len], sig.salt);
    offset += sig.salt.len;

    // Signature MPIs
    for (sig.signature_mpis) |m| {
        mem.writeInt(u16, buf[offset..][0..2], m.bit_count, .big);
        offset += 2;
        if (m.data.len > 0) {
            @memcpy(buf[offset .. offset + m.data.len], m.data);
            offset += m.data.len;
        }
    }

    return buf;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn buildTestV6KeyBody() [16]u8 {
    var body: [16]u8 = undefined;
    body[0] = 6; // version
    mem.writeInt(u32, body[1..5], 1000, .big);
    body[5] = @intFromEnum(@import("../types/enums.zig").PublicKeyAlgorithm.rsa_encrypt_sign);
    mem.writeInt(u32, body[6..10], 6, .big);
    mem.writeInt(u16, body[10..12], 8, .big);
    body[12] = 0xFF;
    mem.writeInt(u16, body[13..15], 8, .big);
    body[15] = 0x03;
    return body;
}

test "exportV6PublicKey minimal key" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestV6KeyBody();
    const pk = try V6PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = V6Key.init(allocator, pk);
    defer key.deinit();

    try key.addUserId("Test <test@example.com>", null);

    const exported = try exportV6PublicKey(allocator, &key);
    defer allocator.free(exported);

    // Should contain at least a public key packet and a user ID packet
    try std.testing.expect(exported.len > 0);

    // Verify we can parse the first packet header
    var fbs = std.io.fixedBufferStream(exported);
    const hdr = try header_mod.readHeader(fbs.reader());
    try std.testing.expectEqual(PacketTag.public_key, hdr.tag);
}

test "importV6PublicKey round-trip" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestV6KeyBody();
    const pk = try V6PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = V6Key.init(allocator, pk);
    defer key.deinit();

    try key.addUserId("Alice <alice@example.com>", null);

    const exported = try exportV6PublicKey(allocator, &key);
    defer allocator.free(exported);

    var imported = try importV6PublicKey(allocator, exported);
    defer imported.deinit();

    try std.testing.expectEqual(@as(u8, 6), imported.primary_key.version);
    try std.testing.expectEqual(@as(usize, 1), imported.user_ids.items.len);
    try std.testing.expectEqualStrings("Alice <alice@example.com>", imported.user_ids.items[0].user_id);
}

test "importV6PublicKey with subkey" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestV6KeyBody();
    const pk = try V6PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = V6Key.init(allocator, pk);
    defer key.deinit();

    try key.addUserId("Bob <bob@example.com>", null);

    // Add subkey
    var sub_body: [16]u8 = undefined;
    sub_body[0] = 6;
    mem.writeInt(u32, sub_body[1..5], 2000, .big);
    sub_body[5] = @intFromEnum(@import("../types/enums.zig").PublicKeyAlgorithm.rsa_encrypt_sign);
    mem.writeInt(u32, sub_body[6..10], 6, .big);
    mem.writeInt(u16, sub_body[10..12], 8, .big);
    sub_body[12] = 0xAA;
    mem.writeInt(u16, sub_body[13..15], 8, .big);
    sub_body[15] = 0x03;

    const subkey = try V6PublicKeyPacket.parse(allocator, &sub_body, true);
    try key.addSubkey(subkey, null);

    const exported = try exportV6PublicKey(allocator, &key);
    defer allocator.free(exported);

    var imported = try importV6PublicKey(allocator, exported);
    defer imported.deinit();

    try std.testing.expectEqual(@as(usize, 1), imported.user_ids.items.len);
    try std.testing.expectEqual(@as(usize, 1), imported.subkeys.items.len);
    try std.testing.expect(imported.subkeys.items[0].key.is_subkey);
}

test "exportV6PublicKeyArmored" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestV6KeyBody();
    const pk = try V6PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = V6Key.init(allocator, pk);
    defer key.deinit();

    try key.addUserId("Test <test@example.com>", null);

    const armored = try exportV6PublicKeyArmored(allocator, &key);
    defer allocator.free(armored);

    try std.testing.expect(mem.startsWith(u8, armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    try std.testing.expect(mem.indexOf(u8, armored, "-----END PGP PUBLIC KEY BLOCK-----") != null);
}

test "importV6PublicKey empty data fails" {
    const allocator = std.testing.allocator;
    const result = importV6PublicKey(allocator, &[_]u8{});
    try std.testing.expectError(error.MalformedKey, result);
}

test "importV6PublicKey wrong packet type fails" {
    const allocator = std.testing.allocator;

    // Build a literal data packet instead of public key
    const body = [_]u8{ 'b', 0, 0, 0, 0, 0 };
    var packet_buf: [2 + body.len]u8 = undefined;
    packet_buf[0] = 0xCB; // tag 11 (literal data)
    packet_buf[1] = body.len;
    @memcpy(packet_buf[2..], &body);

    const result = importV6PublicKey(allocator, &packet_buf);
    try std.testing.expectError(error.NotAPublicKey, result);
}

test "importV6PublicKey rejects V4 key" {
    const allocator = std.testing.allocator;

    // Build a V4 public key packet
    var body: [12]u8 = undefined;
    body[0] = 4; // V4 version
    mem.writeInt(u32, body[1..5], 1000, .big);
    body[5] = 1;
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xFF;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;

    var packet_buf: [2 + body.len]u8 = undefined;
    packet_buf[0] = 0xC6; // tag 6 (public key)
    packet_buf[1] = body.len;
    @memcpy(packet_buf[2..], &body);

    const result = importV6PublicKey(allocator, &packet_buf);
    try std.testing.expectError(error.NotAV6Key, result);
}

test "importV6PublicKey multiple user IDs" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestV6KeyBody();
    const pk = try V6PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = V6Key.init(allocator, pk);
    defer key.deinit();

    try key.addUserId("Eve <eve@home.com>", null);
    try key.addUserId("Eve <eve@work.com>", null);

    const exported = try exportV6PublicKey(allocator, &key);
    defer allocator.free(exported);

    var imported = try importV6PublicKey(allocator, exported);
    defer imported.deinit();

    try std.testing.expectEqual(@as(usize, 2), imported.user_ids.items.len);
    try std.testing.expectEqualStrings("Eve <eve@home.com>", imported.user_ids.items[0].user_id);
    try std.testing.expectEqualStrings("Eve <eve@work.com>", imported.user_ids.items[1].user_id);
}

test "KeyVersion union basics" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestV6KeyBody();
    const pk = try V6PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = V6Key.init(allocator, pk);
    defer key.deinit();

    try key.addUserId("Test <test@test.com>", null);

    const kv = KeyVersion{ .v6 = key };
    _ = &kv; // test that the union construction works

    try std.testing.expectEqual(@as(u8, 6), kv.version());
}

test "importPublicKeyAuto detects V6" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestV6KeyBody();
    const pk = try V6PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = V6Key.init(allocator, pk);
    defer key.deinit();

    try key.addUserId("Auto <auto@test.com>", null);

    const exported = try exportV6PublicKey(allocator, &key);
    defer allocator.free(exported);

    var imported = try importPublicKeyAuto(allocator, exported);
    defer imported.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 6), imported.version());
    switch (imported) {
        .v6 => |*v6| {
            try std.testing.expectEqualStrings("Auto <auto@test.com>", v6.primaryUserId().?);
        },
        .v4 => unreachable,
    }
}

test "importPublicKeyAuto detects V4" {
    const allocator = std.testing.allocator;

    // Build a V4 key using the existing V4 infrastructure
    const PublicKeyPacket = @import("../packets/public_key.zig").PublicKeyPacket;
    const UserIdPacket = @import("../packets/user_id.zig").UserIdPacket;

    var body: [12]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], 1000, .big);
    body[5] = 1;
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xFF;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;

    const pk4 = try PublicKeyPacket.parse(allocator, &body, false);
    var key4 = Key.init(pk4);
    defer key4.deinit(allocator);

    const uid4 = try UserIdPacket.parse(allocator, "V4User <v4@test.com>");
    try key4.addUserId(allocator, .{
        .user_id = uid4,
        .self_signature = null,
        .certifications = .empty,
    });

    const exported4 = try v4_import_export.exportPublicKey(allocator, &key4);
    defer allocator.free(exported4);

    var imported = try importPublicKeyAuto(allocator, exported4);
    defer imported.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 4), imported.version());
    switch (imported) {
        .v4 => |*v4| {
            try std.testing.expectEqualStrings("V4User <v4@test.com>", v4.primaryUserId().?);
        },
        .v6 => unreachable,
    }
}
