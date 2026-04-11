// SPDX-License-Identifier: MIT
//! Key import and export per RFC 4880 Section 11.1 (Transferable Public Keys).
//!
//! Transferable public key format:
//!   Public-Key Packet
//!     User ID Packet
//!       [Signature Packet (self-signature)]
//!     [Public-Subkey Packet
//!       [Signature Packet (binding)]]

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const header_mod = @import("../packet/header.zig");
const PacketTag = @import("../packet/tags.zig").PacketTag;
const PublicKeyPacket = @import("../packets/public_key.zig").PublicKeyPacket;
const SecretKeyPacket = @import("../packets/secret_key.zig").SecretKeyPacket;
const UserIdPacket = @import("../packets/user_id.zig").UserIdPacket;
const SignaturePacket = @import("../packets/signature.zig").SignaturePacket;
const Key = @import("key.zig").Key;
const UserIdBinding = @import("key.zig").UserIdBinding;
const SubkeyBinding = @import("key.zig").SubkeyBinding;
const armor = @import("../armor/armor.zig");
const SymmetricAlgorithm = @import("../types/enums.zig").SymmetricAlgorithm;
const secret_key_decrypt = @import("../crypto/secret_key_decrypt.zig");

/// A key pair consisting of a public key (with user IDs, subkeys, etc.)
/// and the decrypted secret key material.
pub const KeyPair = struct {
    /// The assembled public key structure.
    key: Key,
    /// Decrypted primary secret key MPI data (owned by allocator).
    secret_data: ?[]u8,

    pub fn deinit(self: *KeyPair, allocator: Allocator) void {
        if (self.secret_data) |sd| allocator.free(sd);
        self.key.deinit(allocator);
    }
};

pub const ImportExportError = error{
    InvalidPacket,
    UnsupportedVersion,
    InvalidPacketTag,
    MalformedKey,
    NotAPublicKey,
    OutOfMemory,
    Overflow,
    NoSpaceLeft,
};

/// Export a public key as an OpenPGP binary packet sequence.
///
/// Format:
///   Public-Key Packet (tag 6)
///   For each user ID:
///     User ID Packet (tag 13)
///     [Signature Packet (tag 2) - self-signature]
///     [Signature Packets (tag 2) - certifications]
///   For each subkey:
///     Public-Subkey Packet (tag 14)
///     [Signature Packet (tag 2) - binding signature]
pub fn exportPublicKey(allocator: Allocator, key: *const Key) ImportExportError![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // 1. Write primary public key packet (tag 6)
    const pk_body = key.primary_key.serialize(allocator) catch
        return error.OutOfMemory;
    defer allocator.free(pk_body);
    try writePacket(allocator, &output, .public_key, pk_body);

    // 2. Write user IDs and their signatures
    for (key.user_ids.items) |uid_binding| {
        // User ID packet (tag 13)
        const uid_body = uid_binding.user_id.serialize(allocator) catch
            return error.OutOfMemory;
        defer allocator.free(uid_body);
        try writePacket(allocator, &output, .user_id, uid_body);

        // Self-signature
        if (uid_binding.self_signature) |sig| {
            const sig_body = serializeSignature(allocator, &sig) catch
                return error.OutOfMemory;
            defer allocator.free(sig_body);
            try writePacket(allocator, &output, .signature, sig_body);
        }

        // Third-party certifications
        for (uid_binding.certifications.items) |sig| {
            const sig_body = serializeSignature(allocator, &sig) catch
                return error.OutOfMemory;
            defer allocator.free(sig_body);
            try writePacket(allocator, &output, .signature, sig_body);
        }
    }

    // 3. Write subkeys and their binding signatures
    for (key.subkeys.items) |sub| {
        // Public-Subkey packet (tag 14)
        const sub_body = sub.key.serialize(allocator) catch
            return error.OutOfMemory;
        defer allocator.free(sub_body);
        try writePacket(allocator, &output, .public_subkey, sub_body);

        // Binding signature
        if (sub.binding_signature) |sig| {
            const sig_body = serializeSignature(allocator, &sig) catch
                return error.OutOfMemory;
            defer allocator.free(sig_body);
            try writePacket(allocator, &output, .signature, sig_body);
        }
    }

    return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Export a public key as ASCII-armored text.
pub fn exportPublicKeyArmored(allocator: Allocator, key: *const Key) ImportExportError![]u8 {
    const binary = try exportPublicKey(allocator, key);
    defer allocator.free(binary);

    const headers = [_]armor.Header{
        .{ .name = "Version", .value = "zpgp 0.1" },
    };

    return armor.encode(allocator, binary, .public_key, &headers) catch
        return error.OutOfMemory;
}

/// Import a public key from binary packet data.
///
/// Reads the transferable public key structure:
///   Public-Key Packet -> User ID + Sigs -> Subkeys + Sigs
pub fn importPublicKey(allocator: Allocator, data: []const u8) ImportExportError!Key {
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

    const primary_key = PublicKeyPacket.parse(allocator, pk_body, false) catch
        return error.InvalidPacket;
    errdefer primary_key.deinit(allocator);

    var key = Key.init(primary_key);
    errdefer key.deinit(allocator);

    // Parse remaining packets
    var current_uid: ?UserIdBinding = null;
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
                    if (current_uid) |uid| {
                        key.addUserId(allocator, uid) catch return error.OutOfMemory;
                    }
                }

                const uid_pkt = UserIdPacket.parse(allocator, body) catch
                    return error.InvalidPacket;
                current_uid = .{
                    .user_id = uid_pkt,
                    .self_signature = null,
                    .certifications = .empty,
                };
                pending_uid = true;
            },
            .signature => {
                const sig = SignaturePacket.parse(allocator, body) catch
                    return error.InvalidPacket;

                if (pending_uid) {
                    if (current_uid) |*uid| {
                        // Check if this is a self-signature (certification types 0x10-0x13)
                        if (sig.sig_type >= 0x10 and sig.sig_type <= 0x13) {
                            if (uid.self_signature == null) {
                                uid.self_signature = sig;
                            } else {
                                uid.certifications.append(allocator, sig) catch
                                    return error.OutOfMemory;
                            }
                        } else {
                            uid.certifications.append(allocator, sig) catch
                                return error.OutOfMemory;
                        }
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
                    if (current_uid) |uid| {
                        key.addUserId(allocator, uid) catch return error.OutOfMemory;
                    }
                    current_uid = null;
                    pending_uid = false;
                }

                const sub_pk = PublicKeyPacket.parse(allocator, body, true) catch
                    return error.InvalidPacket;
                key.addSubkey(allocator, .{
                    .key = sub_pk,
                    .secret_key = null,
                    .binding_signature = null,
                }) catch return error.OutOfMemory;
            },
            else => {
                // Skip unknown packet types (trust, user attribute, etc.)
            },
        }
    }

    // Save the last pending UID binding
    if (pending_uid) {
        if (current_uid) |uid| {
            key.addUserId(allocator, uid) catch return error.OutOfMemory;
        }
    }

    return key;
}

/// Import a public key from data that may be either armored or binary.
pub fn importPublicKeyAuto(allocator: Allocator, data: []const u8) ImportExportError!Key {
    // Try ASCII armor first
    if (data.len > 10 and mem.startsWith(u8, data, "-----BEGIN ")) {
        const result = armor.decode(allocator, data) catch {
            // Fall through to binary import
            return importPublicKey(allocator, data);
        };
        defer {
            allocator.free(result.data);
            for (result.headers) |hdr| {
                allocator.free(hdr.name);
                allocator.free(hdr.value);
            }
            allocator.free(result.headers);
        }
        return importPublicKey(allocator, result.data);
    }

    return importPublicKey(allocator, data);
}

/// Import a secret key with passphrase-based decryption.
///
/// Reads an OpenPGP transferable secret key (which may be armored or binary),
/// locates the secret key packet, and decrypts the secret key material
/// using the provided passphrase.
///
/// The returned `KeyPair` contains both the assembled public key structure
/// and the decrypted secret key MPI data.
pub fn importSecretKeyWithPassphrase(
    allocator: Allocator,
    data: []const u8,
    passphrase: []const u8,
) ImportSecretKeyError!KeyPair {
    // Dearmor if necessary
    var binary_data: []const u8 = data;
    var decode_result: ?armor.DecodeResult = null;
    defer {
        if (decode_result) |*dr| dr.deinit();
    }

    if (data.len > 10 and mem.startsWith(u8, data, "-----BEGIN ")) {
        decode_result = armor.decode(allocator, data) catch {
            return error.MalformedKey;
        };
        binary_data = decode_result.?.data;
    }

    var fbs = std.io.fixedBufferStream(binary_data);
    const reader = fbs.reader();

    // Read the first packet: must be a secret key (tag 5)
    const first_hdr = header_mod.readHeader(reader) catch |err| {
        return switch (err) {
            error.EndOfStream => error.MalformedKey,
            error.InvalidPacketTag => error.InvalidPacketTag,
        };
    };

    if (first_hdr.tag != .secret_key) return error.NotASecretKey;

    const sk_body_len: usize = switch (first_hdr.body_length) {
        .fixed => |len| len,
        else => return error.MalformedKey,
    };

    if (fbs.pos + sk_body_len > binary_data.len) return error.MalformedKey;
    const sk_body = binary_data[fbs.pos .. fbs.pos + sk_body_len];
    fbs.pos += sk_body_len;

    // Parse the secret key packet
    const sk_packet = SecretKeyPacket.parse(allocator, sk_body, false) catch
        return error.InvalidPacket;
    // Note: we must be careful about ownership. Key.init copies the
    // PublicKeyPacket struct (which shares slice pointers with
    // sk_packet.public_key). To avoid a double-free when Key.deinit
    // frees both primary_key and secret_key.public_key, we do NOT
    // store the SecretKeyPacket in key.secret_key. Instead, we keep
    // the sk_packet alive for reading S2K/IV/encrypted data, then
    // free only the secret-key-specific fields afterwards.
    var key = Key.init(sk_packet.public_key);
    errdefer key.deinit(allocator);

    // We'll free the secret-key-only fields manually after decryption.
    // The public_key portion is now owned by `key.primary_key`.
    defer {
        if (sk_packet.s2k_data) |s| allocator.free(s);
        if (sk_packet.iv) |v| allocator.free(v);
        if (sk_packet.secret_data.len > 0) allocator.free(sk_packet.secret_data);
        if (sk_packet.checksum_data.len > 0) allocator.free(sk_packet.checksum_data);
    }

    // Parse remaining packets (user IDs, signatures, subkeys)
    var current_uid: ?UserIdBinding = null;
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

        if (fbs.pos + body_len > binary_data.len) return error.MalformedKey;
        const body = binary_data[fbs.pos .. fbs.pos + body_len];
        fbs.pos += body_len;

        switch (hdr.tag) {
            .user_id => {
                if (pending_uid) {
                    if (current_uid) |uid| {
                        key.addUserId(allocator, uid) catch return error.OutOfMemory;
                    }
                }
                const uid_pkt = UserIdPacket.parse(allocator, body) catch
                    return error.InvalidPacket;
                current_uid = .{
                    .user_id = uid_pkt,
                    .self_signature = null,
                    .certifications = .empty,
                };
                pending_uid = true;
            },
            .signature => {
                const sig = SignaturePacket.parse(allocator, body) catch
                    return error.InvalidPacket;

                if (pending_uid) {
                    if (current_uid) |*uid| {
                        if (sig.sig_type >= 0x10 and sig.sig_type <= 0x13) {
                            if (uid.self_signature == null) {
                                uid.self_signature = sig;
                            } else {
                                uid.certifications.append(allocator, sig) catch
                                    return error.OutOfMemory;
                            }
                        } else {
                            uid.certifications.append(allocator, sig) catch
                                return error.OutOfMemory;
                        }
                    }
                } else {
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
            .secret_subkey => {
                if (pending_uid) {
                    if (current_uid) |uid| {
                        key.addUserId(allocator, uid) catch return error.OutOfMemory;
                    }
                    current_uid = null;
                    pending_uid = false;
                }

                // Parse as secret subkey, extract public portion.
                // We don't store the SecretKeyPacket in SubkeyBinding
                // to avoid double-free (public_key is shared).
                const sub_sk = SecretKeyPacket.parse(allocator, body, true) catch
                    return error.InvalidPacket;
                // Free only the secret-key specific fields
                if (sub_sk.s2k_data) |s| allocator.free(s);
                if (sub_sk.iv) |v| allocator.free(v);
                if (sub_sk.secret_data.len > 0) allocator.free(sub_sk.secret_data);
                if (sub_sk.checksum_data.len > 0) allocator.free(sub_sk.checksum_data);

                key.addSubkey(allocator, .{
                    .key = sub_sk.public_key,
                    .secret_key = null,
                    .binding_signature = null,
                }) catch return error.OutOfMemory;
            },
            .public_subkey => {
                if (pending_uid) {
                    if (current_uid) |uid| {
                        key.addUserId(allocator, uid) catch return error.OutOfMemory;
                    }
                    current_uid = null;
                    pending_uid = false;
                }

                const sub_pk = PublicKeyPacket.parse(allocator, body, true) catch
                    return error.InvalidPacket;
                key.addSubkey(allocator, .{
                    .key = sub_pk,
                    .secret_key = null,
                    .binding_signature = null,
                }) catch return error.OutOfMemory;
            },
            else => {},
        }
    }

    if (pending_uid) {
        if (current_uid) |uid| {
            key.addUserId(allocator, uid) catch return error.OutOfMemory;
        }
    }

    // Decrypt the secret key material if it is protected
    var decrypted_data: ?[]u8 = null;
    errdefer if (decrypted_data) |dd| allocator.free(dd);

    if (sk_packet.s2k_usage != 0) {
        const sym_algo = sk_packet.symmetric_algo orelse return error.DecryptionFailed;
        const iv_data = sk_packet.iv orelse return error.DecryptionFailed;
        const s2k_bytes = sk_packet.s2k_data orelse return error.DecryptionFailed;

        // For s2k_usage 254: secret_data is the encrypted portion, checksum_data is separate
        // But our SecretKeyPacket parser already splits them. We need to reassemble.
        var encrypted_total: []u8 = undefined;
        var need_free_encrypted = false;

        if (sk_packet.checksum_data.len > 0) {
            // Reassemble: encrypted = secret_data + checksum_data
            const total_len = sk_packet.secret_data.len + sk_packet.checksum_data.len;
            encrypted_total = allocator.alloc(u8, total_len) catch return error.OutOfMemory;
            need_free_encrypted = true;
            @memcpy(encrypted_total[0..sk_packet.secret_data.len], sk_packet.secret_data);
            @memcpy(encrypted_total[sk_packet.secret_data.len..], sk_packet.checksum_data);
        } else {
            encrypted_total = allocator.dupe(u8, sk_packet.secret_data) catch return error.OutOfMemory;
            need_free_encrypted = true;
        }
        defer if (need_free_encrypted) allocator.free(encrypted_total);

        decrypted_data = secret_key_decrypt.decryptSecretKey(
            allocator,
            encrypted_total,
            passphrase,
            sym_algo,
            iv_data,
            s2k_bytes,
            sk_packet.s2k_usage,
        ) catch return error.DecryptionFailed;
    } else {
        // Unencrypted: secret_data is already plaintext
        decrypted_data = allocator.dupe(u8, sk_packet.secret_data) catch return error.OutOfMemory;
    }

    return .{
        .key = key,
        .secret_data = decrypted_data,
    };
}

pub const ImportSecretKeyError = error{
    InvalidPacket,
    UnsupportedVersion,
    InvalidPacketTag,
    MalformedKey,
    NotASecretKey,
    OutOfMemory,
    Overflow,
    NoSpaceLeft,
    DecryptionFailed,
};

/// Write a single packet (header + body) to the output buffer.
fn writePacket(
    allocator: Allocator,
    output: *std.ArrayList(u8),
    tag: PacketTag,
    body: []const u8,
) ImportExportError!void {
    var hdr_buf: [6]u8 = undefined;
    var hdr_fbs = std.io.fixedBufferStream(&hdr_buf);
    header_mod.writeHeader(hdr_fbs.writer(), tag, @intCast(body.len)) catch
        return error.Overflow;
    output.appendSlice(allocator, hdr_fbs.getWritten()) catch return error.OutOfMemory;
    output.appendSlice(allocator, body) catch return error.OutOfMemory;
}

/// Serialize a SignaturePacket to its body bytes.
fn serializeSignature(allocator: Allocator, sig: *const SignaturePacket) ![]u8 {
    // Reconstruct the signature body from fields
    var body_len: usize = 4 + // version + sig_type + pub_algo + hash_algo
        2 + sig.hashed_subpacket_data.len + // hashed subpackets
        2 + sig.unhashed_subpacket_data.len + // unhashed subpackets
        2; // hash_prefix

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

    // Hashed subpackets
    mem.writeInt(u16, buf[offset..][0..2], @intCast(sig.hashed_subpacket_data.len), .big);
    offset += 2;
    if (sig.hashed_subpacket_data.len > 0) {
        @memcpy(buf[offset .. offset + sig.hashed_subpacket_data.len], sig.hashed_subpacket_data);
        offset += sig.hashed_subpacket_data.len;
    }

    // Unhashed subpackets
    mem.writeInt(u16, buf[offset..][0..2], @intCast(sig.unhashed_subpacket_data.len), .big);
    offset += 2;
    if (sig.unhashed_subpacket_data.len > 0) {
        @memcpy(buf[offset .. offset + sig.unhashed_subpacket_data.len], sig.unhashed_subpacket_data);
        offset += sig.unhashed_subpacket_data.len;
    }

    // Hash prefix
    buf[offset] = sig.hash_prefix[0];
    buf[offset + 1] = sig.hash_prefix[1];
    offset += 2;

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

fn buildTestKeyBody() [12]u8 {
    var body: [12]u8 = undefined;
    body[0] = 4; // version
    mem.writeInt(u32, body[1..5], 1000, .big);
    body[5] = 1; // RSA
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xFF;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;
    return body;
}

test "exportPublicKey minimal key" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestKeyBody();
    const pk = try PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = Key.init(pk);
    defer key.deinit(allocator);

    // Add a user ID
    const uid = try UserIdPacket.parse(allocator, "Test <test@example.com>");
    try key.addUserId(allocator, .{
        .user_id = uid,
        .self_signature = null,
        .certifications = .empty,
    });

    const exported = try exportPublicKey(allocator, &key);
    defer allocator.free(exported);

    // Should contain at least a public key packet and a user ID packet
    try std.testing.expect(exported.len > 0);

    // Verify we can parse the first packet header
    var fbs = std.io.fixedBufferStream(exported);
    const hdr = try header_mod.readHeader(fbs.reader());
    try std.testing.expectEqual(PacketTag.public_key, hdr.tag);
}

test "importPublicKey round-trip" {
    const allocator = std.testing.allocator;

    // Create a key
    var pk_body = buildTestKeyBody();
    const pk = try PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = Key.init(pk);
    defer key.deinit(allocator);

    const uid = try UserIdPacket.parse(allocator, "Alice <alice@example.com>");
    try key.addUserId(allocator, .{
        .user_id = uid,
        .self_signature = null,
        .certifications = .empty,
    });

    // Export
    const exported = try exportPublicKey(allocator, &key);
    defer allocator.free(exported);

    // Import
    var imported = try importPublicKey(allocator, exported);
    defer imported.deinit(allocator);

    // Verify
    try std.testing.expectEqual(@as(u8, 4), imported.primary_key.version);
    try std.testing.expectEqual(@as(usize, 1), imported.user_ids.items.len);
    try std.testing.expectEqualStrings("Alice <alice@example.com>", imported.user_ids.items[0].user_id.id);
}

test "importPublicKey with subkey" {
    const allocator = std.testing.allocator;

    // Create key with subkey
    var pk_body = buildTestKeyBody();
    const pk = try PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = Key.init(pk);
    defer key.deinit(allocator);

    const uid = try UserIdPacket.parse(allocator, "Bob <bob@example.com>");
    try key.addUserId(allocator, .{
        .user_id = uid,
        .self_signature = null,
        .certifications = .empty,
    });

    // Add subkey
    var sub_body: [12]u8 = undefined;
    sub_body[0] = 4;
    mem.writeInt(u32, sub_body[1..5], 2000, .big);
    sub_body[5] = 1; // RSA
    mem.writeInt(u16, sub_body[6..8], 8, .big);
    sub_body[8] = 0xAA;
    mem.writeInt(u16, sub_body[9..11], 8, .big);
    sub_body[11] = 0x03;

    const subkey = try PublicKeyPacket.parse(allocator, &sub_body, true);
    try key.addSubkey(allocator, .{
        .key = subkey,
        .secret_key = null,
        .binding_signature = null,
    });

    // Export
    const exported = try exportPublicKey(allocator, &key);
    defer allocator.free(exported);

    // Import
    var imported = try importPublicKey(allocator, exported);
    defer imported.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), imported.user_ids.items.len);
    try std.testing.expectEqual(@as(usize, 1), imported.subkeys.items.len);
    try std.testing.expect(imported.subkeys.items[0].key.is_subkey);
}

test "exportPublicKeyArmored" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestKeyBody();
    const pk = try PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = Key.init(pk);
    defer key.deinit(allocator);

    const uid = try UserIdPacket.parse(allocator, "Test <test@example.com>");
    try key.addUserId(allocator, .{
        .user_id = uid,
        .self_signature = null,
        .certifications = .empty,
    });

    const armored = try exportPublicKeyArmored(allocator, &key);
    defer allocator.free(armored);

    // Check that it's properly armored
    try std.testing.expect(mem.startsWith(u8, armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    try std.testing.expect(mem.indexOf(u8, armored, "-----END PGP PUBLIC KEY BLOCK-----") != null);
}

test "importPublicKeyAuto armored round-trip" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestKeyBody();
    const pk = try PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = Key.init(pk);
    defer key.deinit(allocator);

    const uid = try UserIdPacket.parse(allocator, "Carol <carol@example.com>");
    try key.addUserId(allocator, .{
        .user_id = uid,
        .self_signature = null,
        .certifications = .empty,
    });

    // Export as armored
    const armored = try exportPublicKeyArmored(allocator, &key);
    defer allocator.free(armored);

    // Import from armored
    var imported = try importPublicKeyAuto(allocator, armored);
    defer imported.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 4), imported.primary_key.version);
    try std.testing.expectEqual(@as(usize, 1), imported.user_ids.items.len);
    try std.testing.expectEqualStrings("Carol <carol@example.com>", imported.user_ids.items[0].user_id.id);
}

test "importPublicKeyAuto binary input" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestKeyBody();
    const pk = try PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = Key.init(pk);
    defer key.deinit(allocator);

    const uid = try UserIdPacket.parse(allocator, "Dave <dave@example.com>");
    try key.addUserId(allocator, .{
        .user_id = uid,
        .self_signature = null,
        .certifications = .empty,
    });

    const binary = try exportPublicKey(allocator, &key);
    defer allocator.free(binary);

    var imported = try importPublicKeyAuto(allocator, binary);
    defer imported.deinit(allocator);

    try std.testing.expectEqualStrings("Dave <dave@example.com>", imported.user_ids.items[0].user_id.id);
}

test "importPublicKey empty data fails" {
    const allocator = std.testing.allocator;
    const result = importPublicKey(allocator, &[_]u8{});
    try std.testing.expectError(error.MalformedKey, result);
}

test "importPublicKey wrong packet type fails" {
    const allocator = std.testing.allocator;

    // Build a literal data packet instead of public key
    const body = [_]u8{ 'b', 0, 0, 0, 0, 0 };
    var packet: [2 + body.len]u8 = undefined;
    packet[0] = 0xCB; // tag 11 (literal data)
    packet[1] = body.len;
    @memcpy(packet[2..], &body);

    const result = importPublicKey(allocator, &packet);
    try std.testing.expectError(error.NotAPublicKey, result);
}

test "importPublicKey multiple user IDs" {
    const allocator = std.testing.allocator;

    var pk_body = buildTestKeyBody();
    const pk = try PublicKeyPacket.parse(allocator, &pk_body, false);

    var key = Key.init(pk);
    defer key.deinit(allocator);

    const uid1 = try UserIdPacket.parse(allocator, "Eve <eve@home.com>");
    try key.addUserId(allocator, .{
        .user_id = uid1,
        .self_signature = null,
        .certifications = .empty,
    });

    const uid2 = try UserIdPacket.parse(allocator, "Eve <eve@work.com>");
    try key.addUserId(allocator, .{
        .user_id = uid2,
        .self_signature = null,
        .certifications = .empty,
    });

    const exported = try exportPublicKey(allocator, &key);
    defer allocator.free(exported);

    var imported = try importPublicKey(allocator, exported);
    defer imported.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), imported.user_ids.items.len);
    try std.testing.expectEqualStrings("Eve <eve@home.com>", imported.user_ids.items[0].user_id.id);
    try std.testing.expectEqualStrings("Eve <eve@work.com>", imported.user_ids.items[1].user_id.id);
}

test "serializeSignature round-trip" {
    const allocator = std.testing.allocator;

    // Build a minimal v4 RSA signature
    var sig_body: [13]u8 = undefined;
    sig_body[0] = 4;
    sig_body[1] = 0x00;
    sig_body[2] = 1; // RSA
    sig_body[3] = 8; // SHA256
    mem.writeInt(u16, sig_body[4..6], 0, .big);
    mem.writeInt(u16, sig_body[6..8], 0, .big);
    sig_body[8] = 0xAB;
    sig_body[9] = 0xCD;
    mem.writeInt(u16, sig_body[10..12], 8, .big);
    sig_body[12] = 0xFF;

    const sig = try SignaturePacket.parse(allocator, sig_body[0..13]);
    defer sig.deinit(allocator);

    // Serialize
    const serialized = try serializeSignature(allocator, &sig);
    defer allocator.free(serialized);

    // Parse again
    const sig2 = try SignaturePacket.parse(allocator, serialized);
    defer sig2.deinit(allocator);

    try std.testing.expectEqual(sig.version, sig2.version);
    try std.testing.expectEqual(sig.sig_type, sig2.sig_type);
    try std.testing.expectEqual(sig.pub_algo, sig2.pub_algo);
    try std.testing.expectEqual(sig.hash_algo, sig2.hash_algo);
    try std.testing.expectEqual(sig.hash_prefix, sig2.hash_prefix);
}
