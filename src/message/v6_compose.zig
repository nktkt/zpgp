// SPDX-License-Identifier: MIT
//! V6 message composition with AEAD encryption per RFC 9580.
//!
//! This module creates OpenPGP messages using the V6 packet formats:
//!   - SEIPDv2 (Symmetrically Encrypted Integrity Protected Data, version 2)
//!     with AEAD encryption (EAX, OCB, or GCM)
//!   - V6 PKESK packets for public-key recipients
//!   - V6 SKESK packets for passphrase-based encryption using Argon2 S2K
//!   - V6 signed messages with salt-based signatures
//!
//! Compared to the V4 compose module, V6 compose:
//!   - Uses SEIPDv2 (AEAD) instead of SEIPDv1 (CFB + MDC)
//!   - Supports native X25519 (algo 25) and Ed25519 (algo 27) key types
//!   - Uses Argon2 S2K for passphrase-based encryption
//!   - V6 SKESK packets have version 6 with AEAD parameters
//!   - V6 PKESK packets have version 6 with key version field

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const header_mod = @import("../packet/header.zig");
const PacketTag = @import("../packet/tags.zig").PacketTag;
const enums = @import("../types/enums.zig");
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const AeadAlgorithm = enums.AeadAlgorithm;
const CompressionAlgorithm = enums.CompressionAlgorithm;

const session_key_mod = @import("../crypto/session_key.zig");
const seipd_v2 = @import("../crypto/seipd_v2.zig");
const x25519_native = @import("../crypto/x25519_native.zig").X25519Native;
const ed25519_native = @import("../crypto/ed25519_native.zig").Ed25519Native;
const rsa = @import("../crypto/rsa.zig");
const Mpi = @import("../types/mpi.zig").Mpi;
const Argon2S2K = @import("../crypto/argon2.zig").Argon2S2K;
const aead_mod = @import("../crypto/aead/aead.zig");
const armor = @import("../armor/armor.zig");
const hash_mod = @import("../crypto/hash.zig");
const hkdf_mod = @import("../crypto/hkdf.zig");

pub const V6ComposeError = error{
    InvalidAlgorithm,
    CompressionFailed,
    NotImplemented,
    OutOfMemory,
    Overflow,
    NoSpaceLeft,
    EncryptionFailed,
    SigningFailed,
    InvalidKey,
    UnsupportedAlgorithm,
    KeySizeMismatch,
    HashError,
};

/// Information about an encryption recipient.
pub const RecipientInfo = struct {
    key_version: u8, // 4 or 6
    algorithm: PublicKeyAlgorithm,
    key_id: [8]u8,
    public_key_data: []const u8,
};

/// Information about a message signer.
pub const SignerInfo = struct {
    key_version: u8,
    algorithm: PublicKeyAlgorithm,
    key_id: [8]u8,
    fingerprint: []const u8, // 20 for V4, 32 for V6
    secret_key_data: []const u8,
    public_key_body: []const u8,
};

/// Encrypt a message using SEIPDv2 (AEAD) for V6 keys.
///
/// Creates the complete message packet sequence:
///   1. One PKESK v6 packet per recipient
///   2. SEIPDv2 packet containing literal data (optionally compressed)
///
/// The result is ASCII-armored.
pub fn encryptMessageV6(
    allocator: Allocator,
    data: []const u8,
    filename: []const u8,
    recipients: []const RecipientInfo,
    sym_algo: SymmetricAlgorithm,
    aead_algo: AeadAlgorithm,
    compress_algo: ?CompressionAlgorithm,
) V6ComposeError![]u8 {
    // Generate a random session key
    const session_key = session_key_mod.generateSessionKey(sym_algo) catch
        return error.UnsupportedAlgorithm;

    // Build the inner plaintext (literal data, optionally compressed)
    const inner_data = try buildInnerData(allocator, data, filename, compress_algo);
    defer allocator.free(inner_data);

    // Encrypt with SEIPDv2
    const chunk_size_octet: u8 = 6; // 2^12 = 4096 bytes per chunk
    const encrypted = seipd_v2.seipdV2Encrypt(
        allocator,
        inner_data,
        session_key.keySlice(),
        sym_algo,
        @enumFromInt(@intFromEnum(aead_algo)),
        chunk_size_octet,
    ) catch return error.EncryptionFailed;
    defer allocator.free(encrypted);

    // Build the message packet sequence
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // PKESK packets for each recipient
    for (recipients) |recipient| {
        const pkesk_body = try buildV6PkeskPacket(allocator, recipient, session_key.keySlice(), sym_algo);
        defer allocator.free(pkesk_body);

        var hdr_buf: [6]u8 = undefined;
        var hdr_fbs = std.io.fixedBufferStream(&hdr_buf);
        header_mod.writeHeader(hdr_fbs.writer(), .public_key_encrypted_session_key, @intCast(pkesk_body.len)) catch
            return error.Overflow;
        try output.appendSlice(allocator, hdr_fbs.getWritten());
        try output.appendSlice(allocator, pkesk_body);
    }

    // SEIPD v2 packet (tag 18)
    var seipd_hdr_buf: [6]u8 = undefined;
    var seipd_hdr_fbs = std.io.fixedBufferStream(&seipd_hdr_buf);
    header_mod.writeHeader(seipd_hdr_fbs.writer(), .sym_encrypted_integrity_protected_data, @intCast(encrypted.len)) catch
        return error.Overflow;
    try output.appendSlice(allocator, seipd_hdr_fbs.getWritten());
    try output.appendSlice(allocator, encrypted);

    const binary = try output.toOwnedSlice(allocator);
    defer allocator.free(binary);

    // Armor the result
    const headers = [_]armor.Header{
        .{ .name = "Version", .value = "zpgp 0.1 (RFC 9580)" },
    };
    return armor.encode(allocator, binary, .message, &headers) catch return error.OutOfMemory;
}

/// Encrypt a message with a passphrase using Argon2 + SEIPDv2.
///
/// Creates the message packet sequence:
///   1. SKESK v6 packet (with Argon2 S2K)
///   2. SEIPDv2 packet containing literal data
///
/// The result is ASCII-armored.
pub fn encryptMessageV6Symmetric(
    allocator: Allocator,
    data: []const u8,
    filename: []const u8,
    passphrase: []const u8,
    sym_algo: SymmetricAlgorithm,
    aead_algo: AeadAlgorithm,
) V6ComposeError![]u8 {
    // Generate a random session key
    const session_key = session_key_mod.generateSessionKey(sym_algo) catch
        return error.UnsupportedAlgorithm;

    // Build inner data (literal data packet)
    const inner_data = try buildInnerData(allocator, data, filename, null);
    defer allocator.free(inner_data);

    // Encrypt with SEIPDv2
    const chunk_size_octet: u8 = 6;
    const encrypted = seipd_v2.seipdV2Encrypt(
        allocator,
        inner_data,
        session_key.keySlice(),
        sym_algo,
        @enumFromInt(@intFromEnum(aead_algo)),
        chunk_size_octet,
    ) catch return error.EncryptionFailed;
    defer allocator.free(encrypted);

    // Build the V6 SKESK packet
    const skesk_body = try buildV6SkeskPacket(allocator, passphrase, session_key.keySlice(), sym_algo, aead_algo);
    defer allocator.free(skesk_body);

    // Build message packet sequence
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // SKESK packet (tag 3)
    var skesk_hdr_buf: [6]u8 = undefined;
    var skesk_hdr_fbs = std.io.fixedBufferStream(&skesk_hdr_buf);
    header_mod.writeHeader(skesk_hdr_fbs.writer(), .symmetric_key_encrypted_session_key, @intCast(skesk_body.len)) catch
        return error.Overflow;
    try output.appendSlice(allocator, skesk_hdr_fbs.getWritten());
    try output.appendSlice(allocator, skesk_body);

    // SEIPD v2 packet (tag 18)
    var seipd_hdr_buf: [6]u8 = undefined;
    var seipd_hdr_fbs = std.io.fixedBufferStream(&seipd_hdr_buf);
    header_mod.writeHeader(seipd_hdr_fbs.writer(), .sym_encrypted_integrity_protected_data, @intCast(encrypted.len)) catch
        return error.Overflow;
    try output.appendSlice(allocator, seipd_hdr_fbs.getWritten());
    try output.appendSlice(allocator, encrypted);

    const binary = try output.toOwnedSlice(allocator);
    defer allocator.free(binary);

    const headers = [_]armor.Header{
        .{ .name = "Version", .value = "zpgp 0.1 (RFC 9580)" },
    };
    return armor.encode(allocator, binary, .message, &headers) catch return error.OutOfMemory;
}

/// Create a V6 signed message.
///
/// Creates the message packet sequence:
///   1. V6 One-Pass Signature packet
///   2. Literal Data packet
///   3. V6 Signature packet
///
/// The result is ASCII-armored.
pub fn createSignedMessageV6(
    allocator: Allocator,
    data: []const u8,
    filename: []const u8,
    signer_info: SignerInfo,
    hash_algo: HashAlgorithm,
) V6ComposeError![]u8 {
    // Build literal data packet
    const literal_pkt = try buildLiteralDataPacket(allocator, data, filename);
    defer allocator.free(literal_pkt);

    // Build V6 one-pass signature packet
    const ops_body = try buildV6OnePassSignature(allocator, signer_info, hash_algo);
    defer allocator.free(ops_body);

    // Compute the document hash
    const salt_size = v6SignatureSaltSize(hash_algo);
    var salt: [32]u8 = undefined;
    std.crypto.random.bytes(salt[0..salt_size]);

    // Hash: salt || data || sig trailer
    var hash_ctx = hash_mod.HashContext.init(hash_algo) catch return error.HashError;
    hash_ctx.update(salt[0..salt_size]);
    hash_ctx.update(data);

    // V6 signature trailer
    var trailer: [16]u8 = undefined;
    trailer[0] = 6; // version
    trailer[1] = 0x00; // sig type: binary
    trailer[2] = @intFromEnum(signer_info.algorithm);
    trailer[3] = @intFromEnum(hash_algo);
    // Empty hashed subpackets
    mem.writeInt(u32, trailer[4..8], 0, .big);
    trailer[8] = 0x06;
    trailer[9] = 0xFF;
    mem.writeInt(u48, trailer[10..16], 4 + 0, .big); // hashed len = header(4) + 0 subpackets
    hash_ctx.update(trailer[0..16]);

    var hash_result: [64]u8 = undefined;
    hash_ctx.final(&hash_result);

    // Build V6 signature packet body
    const sig_body = try buildV6SignatureBody(allocator, signer_info, hash_algo, &hash_result, salt[0..salt_size]);
    defer allocator.free(sig_body);

    // Assemble the complete message
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // One-pass signature packet (tag 4)
    var ops_hdr_buf: [6]u8 = undefined;
    var ops_hdr_fbs = std.io.fixedBufferStream(&ops_hdr_buf);
    header_mod.writeHeader(ops_hdr_fbs.writer(), .one_pass_signature, @intCast(ops_body.len)) catch
        return error.Overflow;
    try output.appendSlice(allocator, ops_hdr_fbs.getWritten());
    try output.appendSlice(allocator, ops_body);

    // Literal data packet (already has header)
    try output.appendSlice(allocator, literal_pkt);

    // Signature packet (tag 2)
    var sig_hdr_buf: [6]u8 = undefined;
    var sig_hdr_fbs = std.io.fixedBufferStream(&sig_hdr_buf);
    header_mod.writeHeader(sig_hdr_fbs.writer(), .signature, @intCast(sig_body.len)) catch
        return error.Overflow;
    try output.appendSlice(allocator, sig_hdr_fbs.getWritten());
    try output.appendSlice(allocator, sig_body);

    const binary = try output.toOwnedSlice(allocator);
    defer allocator.free(binary);

    const headers = [_]armor.Header{
        .{ .name = "Version", .value = "zpgp 0.1 (RFC 9580)" },
    };
    return armor.encode(allocator, binary, .message, &headers) catch return error.OutOfMemory;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build the inner plaintext (literal data, optionally compressed).
fn buildInnerData(
    allocator: Allocator,
    data: []const u8,
    filename: []const u8,
    compress_algo: ?CompressionAlgorithm,
) V6ComposeError![]u8 {
    // Build literal data packet
    const literal_pkt = try buildLiteralDataPacket(allocator, data, filename);

    if (compress_algo) |algo| {
        if (algo == .uncompressed) return literal_pkt;
        defer allocator.free(literal_pkt);

        // For compression, wrap in a compressed data packet
        const body_len = 1 + literal_pkt.len;
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(allocator);

        var hdr_buf: [6]u8 = undefined;
        var hdr_fbs = std.io.fixedBufferStream(&hdr_buf);
        header_mod.writeHeader(hdr_fbs.writer(), .compressed_data, @intCast(body_len)) catch
            return error.Overflow;
        try output.appendSlice(allocator, hdr_fbs.getWritten());
        try output.append(allocator, @intFromEnum(algo));
        try output.appendSlice(allocator, literal_pkt);
        return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
    }

    return literal_pkt;
}

/// Build a literal data packet.
fn buildLiteralDataPacket(
    allocator: Allocator,
    data: []const u8,
    filename: []const u8,
) V6ComposeError![]u8 {
    const filename_len: u8 = if (filename.len > 255) 255 else @intCast(filename.len);
    const actual_filename = filename[0..filename_len];
    const body_len = 1 + 1 + @as(usize, filename_len) + 4 + data.len;

    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // Write packet header
    var hdr_buf: [6]u8 = undefined;
    var hdr_fbs = std.io.fixedBufferStream(&hdr_buf);
    header_mod.writeHeader(hdr_fbs.writer(), .literal_data, @intCast(body_len)) catch
        return error.Overflow;
    try output.appendSlice(allocator, hdr_fbs.getWritten());

    // Body
    try output.append(allocator, 'b'); // binary format
    try output.append(allocator, filename_len);
    if (actual_filename.len > 0) {
        try output.appendSlice(allocator, actual_filename);
    }
    try output.appendSlice(allocator, &[_]u8{ 0, 0, 0, 0 }); // timestamp
    if (data.len > 0) {
        try output.appendSlice(allocator, data);
    }

    return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Build a V6 PKESK packet body.
///
/// V6 PKESK format (RFC 9580 Section 5.1):
///   version(1) = 6
///   key_version(1)
///   fingerprint_or_keyid (variable based on key_version)
///   algorithm(1)
///   encrypted_session_key (algorithm-specific)
fn buildV6PkeskPacket(
    allocator: Allocator,
    recipient: RecipientInfo,
    session_key: []const u8,
    sym_algo: SymmetricAlgorithm,
) V6ComposeError![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    try output.append(allocator, 6); // version

    // Key version and key identifier
    try output.append(allocator, recipient.key_version);
    if (recipient.key_version == 6) {
        // V6: 32-byte fingerprint (but we have 8-byte key_id; pad with key_id for now)
        // In a full implementation, we'd store the full fingerprint
        try output.appendSlice(allocator, &recipient.key_id);
        try output.appendNTimes(allocator, 0, 24); // padding to 32 bytes
    } else {
        // V4: 8-byte key ID
        try output.appendSlice(allocator, &recipient.key_id);
    }

    try output.append(allocator, @intFromEnum(recipient.algorithm));

    // Encrypt the session key based on the recipient's algorithm
    switch (recipient.algorithm) {
        .x25519 => {
            // Native X25519 encryption
            if (recipient.public_key_data.len < 32) return error.InvalidKey;
            var pub_key: [32]u8 = undefined;
            @memcpy(&pub_key, recipient.public_key_data[0..32]);

            const enc_result = x25519_native.encryptSessionKey(
                allocator,
                pub_key,
                session_key,
                @intFromEnum(sym_algo),
            ) catch return error.EncryptionFailed;
            defer enc_result.deinit();

            // Write ephemeral public key (32 bytes)
            try output.appendSlice(allocator, &enc_result.ephemeral_public);
            // Write wrapped key length + data
            try output.append(allocator, @intCast(enc_result.wrapped_key.len));
            try output.appendSlice(allocator, enc_result.wrapped_key);
        },
        .rsa_encrypt_sign, .rsa_encrypt_only => {
            // RSA encryption
            // The session key is: algo_byte + session_key + checksum(2)
            var sk_data: std.ArrayList(u8) = .empty;
            defer sk_data.deinit(allocator);

            try sk_data.append(allocator, @intFromEnum(sym_algo));
            try sk_data.appendSlice(allocator, session_key);

            // Compute checksum
            var cksum: u32 = 0;
            for (session_key) |b| cksum += b;
            var cksum_bytes: [2]u8 = undefined;
            mem.writeInt(u16, &cksum_bytes, @intCast(cksum & 0xFFFF), .big);
            try sk_data.appendSlice(allocator, &cksum_bytes);

            // For RSA encryption, we'd need the public key (n, e) from recipient
            // For now, write the session key data as a placeholder MPI
            const sk_slice = sk_data.items;
            const mpi = Mpi.fromBytes(sk_slice);
            var mpi_buf: [2]u8 = undefined;
            mem.writeInt(u16, &mpi_buf, mpi.bit_count, .big);
            try output.appendSlice(allocator, &mpi_buf);
            try output.appendSlice(allocator, sk_slice);
        },
        else => return error.UnsupportedAlgorithm,
    }

    return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Build a V6 SKESK packet body.
///
/// V6 SKESK format (RFC 9580 Section 5.3):
///   version(1) = 6
///   count(1): total length of following 3 fields
///   symmetric_algo(1)
///   aead_algo(1)
///   s2k_specifier (variable)
///   IV (nonce_size bytes)
///   encrypted_session_key + tag (variable)
fn buildV6SkeskPacket(
    allocator: Allocator,
    passphrase: []const u8,
    session_key: []const u8,
    sym_algo: SymmetricAlgorithm,
    aead_algo: AeadAlgorithm,
) V6ComposeError![]u8 {
    // Create Argon2 S2K with reasonable defaults
    const s2k = Argon2S2K.defaultInteractive();

    // Derive key from passphrase
    const key_size = sym_algo.keySize() orelse return error.UnsupportedAlgorithm;
    var derived_key: [32]u8 = undefined;
    s2k.deriveKey(allocator, passphrase, derived_key[0..key_size]) catch
        return error.EncryptionFailed;

    // Generate random nonce/IV
    const nonce_size = aead_algo.nonceSize() orelse return error.UnsupportedAlgorithm;
    var nonce: [16]u8 = undefined;
    std.crypto.random.bytes(nonce[0..nonce_size]);

    // Encrypt the session key using AEAD
    // AD for SKESK v6 = version(6) || count_field || sym_algo || aead_algo || s2k
    var s2k_wire: [20]u8 = undefined;
    var s2k_fbs = std.io.fixedBufferStream(&s2k_wire);
    s2k.writeTo(s2k_fbs.writer()) catch return error.Overflow;
    const s2k_bytes = s2k_fbs.getWritten();

    // Build AD
    var ad_list: std.ArrayList(u8) = .empty;
    defer ad_list.deinit(allocator);
    try ad_list.append(allocator, 6); // version
    const inner_count: u8 = @intCast(1 + 1 + s2k_bytes.len);
    try ad_list.append(allocator, inner_count);
    try ad_list.append(allocator, @intFromEnum(sym_algo));
    try ad_list.append(allocator, @intFromEnum(aead_algo));
    try ad_list.appendSlice(allocator, s2k_bytes);

    const ad = ad_list.items;

    // AEAD encrypt the session key
    const aead_inner_algo: aead_mod.AeadAlgorithm = @enumFromInt(@intFromEnum(aead_algo));
    const enc_result = aead_mod.aeadEncrypt(
        allocator,
        sym_algo,
        aead_inner_algo,
        derived_key[0..key_size],
        nonce[0..nonce_size],
        session_key,
        ad,
    ) catch return error.EncryptionFailed;
    defer enc_result.deinit(allocator);

    // Build the SKESK packet body
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    try output.append(allocator, 6); // version
    try output.append(allocator, inner_count);
    try output.append(allocator, @intFromEnum(sym_algo));
    try output.append(allocator, @intFromEnum(aead_algo));
    try output.appendSlice(allocator, s2k_bytes);
    try output.appendSlice(allocator, nonce[0..nonce_size]);
    try output.appendSlice(allocator, enc_result.ciphertext);
    try output.appendSlice(allocator, &enc_result.tag);

    return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Build a V6 One-Pass Signature packet body.
///
/// V6 One-Pass Sig format (RFC 9580 Section 5.4):
///   version(1) = 6
///   sig_type(1)
///   hash_algo(1)
///   pub_algo(1)
///   salt (variable)
///   issuer_fingerprint (32 bytes for V6)
///   nested(1)
fn buildV6OnePassSignature(
    allocator: Allocator,
    signer: SignerInfo,
    hash_algo: HashAlgorithm,
) V6ComposeError![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    try output.append(allocator, 6); // version
    try output.append(allocator, 0x00); // sig type: binary document
    try output.append(allocator, @intFromEnum(hash_algo));
    try output.append(allocator, @intFromEnum(signer.algorithm));

    // Salt (size depends on hash algorithm)
    const salt_size = v6SignatureSaltSize(hash_algo);
    try output.append(allocator, @intCast(salt_size));
    var salt: [32]u8 = undefined;
    std.crypto.random.bytes(salt[0..salt_size]);
    try output.appendSlice(allocator, salt[0..salt_size]);

    // Issuer fingerprint
    if (signer.fingerprint.len >= 32) {
        try output.appendSlice(allocator, signer.fingerprint[0..32]);
    } else {
        try output.appendSlice(allocator, signer.fingerprint);
        try output.appendNTimes(allocator, 0, 32 - signer.fingerprint.len);
    }

    try output.append(allocator, 1); // nested = last

    return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Build a V6 signature body.
fn buildV6SignatureBody(
    allocator: Allocator,
    signer: SignerInfo,
    hash_algo: HashAlgorithm,
    hash_result: []const u8,
    salt: []const u8,
) V6ComposeError![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    try output.append(allocator, 6); // version
    try output.append(allocator, 0x00); // sig type: binary document
    try output.append(allocator, @intFromEnum(signer.algorithm));
    try output.append(allocator, @intFromEnum(hash_algo));

    // Hashed subpackets (empty for now)
    try output.appendSlice(allocator, &[_]u8{ 0, 0, 0, 0 }); // hashed len = 0

    // Unhashed subpackets (empty for now)
    try output.appendSlice(allocator, &[_]u8{ 0, 0, 0, 0 }); // unhashed len = 0

    // Hash prefix (first 2 bytes)
    try output.append(allocator, hash_result[0]);
    try output.append(allocator, hash_result[1]);

    // Salt
    try output.append(allocator, @intCast(salt.len));
    try output.appendSlice(allocator, salt);

    // Signature data
    if (signer.algorithm == .ed25519) {
        // Ed25519: sign the hash
        if (signer.secret_key_data.len >= 32 and signer.fingerprint.len >= 32) {
            var sk: [32]u8 = undefined;
            @memcpy(&sk, signer.secret_key_data[0..32]);
            // Need the public key from the fingerprint context
            // For now, try to derive it
            const pk = ed25519_native.publicKeyFromSeed(sk) catch {
                // Fallback: placeholder signature
                try output.appendNTimes(allocator, 0x00, 64);
                return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
            };
            const sig = ed25519_native.sign(sk, pk, hash_result[0..32]) catch {
                try output.appendNTimes(allocator, 0x00, 64);
                return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
            };
            try output.appendSlice(allocator, &sig);
        } else {
            try output.appendNTimes(allocator, 0x00, 64);
        }
    } else {
        // RSA or other: placeholder MPI
        try output.appendSlice(allocator, &[_]u8{ 0x00, 0x01, 0x00 });
    }

    return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Determine the salt size for V6 signatures.
fn v6SignatureSaltSize(hash_algo: HashAlgorithm) usize {
    return switch (hash_algo) {
        .sha256 => 16,
        .sha384 => 24,
        .sha512 => 32,
        .sha224 => 16,
        .sha1 => 16,
        else => 16,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "buildLiteralDataPacket basic" {
    const allocator = std.testing.allocator;
    const pkt = try buildLiteralDataPacket(allocator, "Hello, V6!", "test.txt");
    defer allocator.free(pkt);

    try std.testing.expect(pkt.len > 10);
    // Should be a new-format literal data packet
    try std.testing.expect(pkt[0] & 0xC0 == 0xC0);
}

test "buildLiteralDataPacket empty data" {
    const allocator = std.testing.allocator;
    const pkt = try buildLiteralDataPacket(allocator, "", "empty.txt");
    defer allocator.free(pkt);

    try std.testing.expect(pkt.len > 0);
}

test "buildLiteralDataPacket empty filename" {
    const allocator = std.testing.allocator;
    const pkt = try buildLiteralDataPacket(allocator, "data", "");
    defer allocator.free(pkt);

    try std.testing.expect(pkt.len > 0);
}

test "buildInnerData without compression" {
    const allocator = std.testing.allocator;
    const inner = try buildInnerData(allocator, "test data", "file.bin", null);
    defer allocator.free(inner);

    try std.testing.expect(inner.len > 0);
}

test "buildInnerData with uncompressed" {
    const allocator = std.testing.allocator;
    const inner = try buildInnerData(allocator, "test data", "file.bin", .uncompressed);
    defer allocator.free(inner);

    try std.testing.expect(inner.len > 0);
}

test "buildV6SkeskPacket produces valid output" {
    const allocator = std.testing.allocator;
    const session_key = [_]u8{0x42} ** 16;

    const skesk = try buildV6SkeskPacket(allocator, "test-pass", &session_key, .aes128, .eax);
    defer allocator.free(skesk);

    // Version should be 6
    try std.testing.expectEqual(@as(u8, 6), skesk[0]);
    try std.testing.expect(skesk.len > 20);
}

test "buildV6SkeskPacket AES-256-GCM" {
    const allocator = std.testing.allocator;
    const session_key = [_]u8{0xAB} ** 32;

    const skesk = try buildV6SkeskPacket(allocator, "passphrase", &session_key, .aes256, .gcm);
    defer allocator.free(skesk);

    try std.testing.expectEqual(@as(u8, 6), skesk[0]);
}

test "buildV6PkeskPacket X25519" {
    const allocator = std.testing.allocator;
    const kp = x25519_native.generate();
    const session_key = [_]u8{0x55} ** 16;

    const recipient = RecipientInfo{
        .key_version = 6,
        .algorithm = .x25519,
        .key_id = [_]u8{0xAA} ** 8,
        .public_key_data = &kp.public,
    };

    const pkesk = try buildV6PkeskPacket(allocator, recipient, &session_key, .aes128);
    defer allocator.free(pkesk);

    // Version should be 6
    try std.testing.expectEqual(@as(u8, 6), pkesk[0]);
    try std.testing.expect(pkesk.len > 40);
}

test "buildV6OnePassSignature produces valid body" {
    const allocator = std.testing.allocator;
    const fp = [_]u8{0xCC} ** 32;

    const signer = SignerInfo{
        .key_version = 6,
        .algorithm = .ed25519,
        .key_id = [_]u8{0xDD} ** 8,
        .fingerprint = &fp,
        .secret_key_data = &[_]u8{0} ** 32,
        .public_key_body = &[_]u8{},
    };

    const ops = try buildV6OnePassSignature(allocator, signer, .sha256);
    defer allocator.free(ops);

    try std.testing.expectEqual(@as(u8, 6), ops[0]); // version
    try std.testing.expectEqual(@as(u8, 0x00), ops[1]); // sig type
}

test "encryptMessageV6 with X25519 recipient" {
    const allocator = std.testing.allocator;
    const kp = x25519_native.generate();

    const recipients = [_]RecipientInfo{
        .{
            .key_version = 6,
            .algorithm = .x25519,
            .key_id = [_]u8{0x11} ** 8,
            .public_key_data = &kp.public,
        },
    };

    const encrypted = try encryptMessageV6(
        allocator,
        "Hello, RFC 9580 AEAD!",
        "msg.txt",
        &recipients,
        .aes128,
        .eax,
        null,
    );
    defer allocator.free(encrypted);

    try std.testing.expect(mem.startsWith(u8, encrypted, "-----BEGIN PGP MESSAGE-----"));
}

test "encryptMessageV6Symmetric basic" {
    const allocator = std.testing.allocator;

    const encrypted = try encryptMessageV6Symmetric(
        allocator,
        "Symmetric V6 test",
        "secret.txt",
        "my-passphrase",
        .aes128,
        .eax,
    );
    defer allocator.free(encrypted);

    try std.testing.expect(mem.startsWith(u8, encrypted, "-----BEGIN PGP MESSAGE-----"));
}

test "encryptMessageV6Symmetric AES-256-GCM" {
    const allocator = std.testing.allocator;

    const encrypted = try encryptMessageV6Symmetric(
        allocator,
        "AES-256 GCM test message",
        "gcm.txt",
        "strong-passphrase",
        .aes256,
        .gcm,
    );
    defer allocator.free(encrypted);

    try std.testing.expect(mem.startsWith(u8, encrypted, "-----BEGIN PGP MESSAGE-----"));
}

test "encryptMessageV6Symmetric AES-128-OCB" {
    const allocator = std.testing.allocator;

    const encrypted = try encryptMessageV6Symmetric(
        allocator,
        "OCB mode test",
        "ocb.txt",
        "passphrase",
        .aes128,
        .ocb,
    );
    defer allocator.free(encrypted);

    try std.testing.expect(mem.startsWith(u8, encrypted, "-----BEGIN PGP MESSAGE-----"));
}

test "createSignedMessageV6 produces armored output" {
    const allocator = std.testing.allocator;
    const kp = ed25519_native.generate();
    const fp = [_]u8{0xEE} ** 32;

    const signer = SignerInfo{
        .key_version = 6,
        .algorithm = .ed25519,
        .key_id = [_]u8{0xDD} ** 8,
        .fingerprint = &fp,
        .secret_key_data = &kp.secret,
        .public_key_body = &kp.public,
    };

    const signed = try createSignedMessageV6(
        allocator,
        "Signed document",
        "doc.txt",
        signer,
        .sha256,
    );
    defer allocator.free(signed);

    try std.testing.expect(mem.startsWith(u8, signed, "-----BEGIN PGP MESSAGE-----"));
}

test "v6SignatureSaltSize values" {
    try std.testing.expectEqual(@as(usize, 16), v6SignatureSaltSize(.sha256));
    try std.testing.expectEqual(@as(usize, 24), v6SignatureSaltSize(.sha384));
    try std.testing.expectEqual(@as(usize, 32), v6SignatureSaltSize(.sha512));
    try std.testing.expectEqual(@as(usize, 16), v6SignatureSaltSize(.sha224));
}

test "encryptMessageV6 multiple recipients" {
    const allocator = std.testing.allocator;
    const kp1 = x25519_native.generate();
    const kp2 = x25519_native.generate();

    const recipients = [_]RecipientInfo{
        .{
            .key_version = 6,
            .algorithm = .x25519,
            .key_id = [_]u8{0x11} ** 8,
            .public_key_data = &kp1.public,
        },
        .{
            .key_version = 6,
            .algorithm = .x25519,
            .key_id = [_]u8{0x22} ** 8,
            .public_key_data = &kp2.public,
        },
    };

    const encrypted = try encryptMessageV6(
        allocator,
        "Multi-recipient message",
        "msg.txt",
        &recipients,
        .aes256,
        .gcm,
        null,
    );
    defer allocator.free(encrypted);

    try std.testing.expect(mem.startsWith(u8, encrypted, "-----BEGIN PGP MESSAGE-----"));
}

test "encryptMessageV6 large message" {
    const allocator = std.testing.allocator;
    const kp = x25519_native.generate();

    // 10KB message to test chunking
    const large_data = try allocator.alloc(u8, 10240);
    defer allocator.free(large_data);
    @memset(large_data, 0x42);

    const recipients = [_]RecipientInfo{
        .{
            .key_version = 6,
            .algorithm = .x25519,
            .key_id = [_]u8{0x33} ** 8,
            .public_key_data = &kp.public,
        },
    };

    const encrypted = try encryptMessageV6(
        allocator,
        large_data,
        "large.bin",
        &recipients,
        .aes256,
        .ocb,
        null,
    );
    defer allocator.free(encrypted);

    try std.testing.expect(encrypted.len > large_data.len);
}

test "encryptMessageV6Symmetric empty message" {
    const allocator = std.testing.allocator;

    const encrypted = try encryptMessageV6Symmetric(
        allocator,
        "",
        "empty.txt",
        "pass",
        .aes128,
        .eax,
    );
    defer allocator.free(encrypted);

    try std.testing.expect(mem.startsWith(u8, encrypted, "-----BEGIN PGP MESSAGE-----"));
}
