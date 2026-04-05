// SPDX-License-Identifier: MIT
//! SEIPDv2 (Symmetrically Encrypted Integrity Protected Data, version 2)
//! per RFC 9580 Section 5.13.2.
//!
//! SEIPDv2 uses AEAD encryption with chunking for large messages.
//!
//! Packet format:
//!   - version (1 byte, value 2)
//!   - symmetric algorithm (1 byte)
//!   - AEAD algorithm (1 byte)
//!   - chunk size octet (1 byte): chunk_size = 2^(c+6) bytes
//!   - salt (32 bytes)
//!   - encrypted data (chunked AEAD)
//!
//! Key derivation: HKDF-SHA256
//!   salt_input = packet salt (32 bytes)
//!   IKM = session_key
//!   info = "OpenPGP" || version || sym_algo || aead_algo || chunk_size_octet
//!
//! Each chunk is AEAD-encrypted with:
//!   nonce = IV[0..nonce_size-8] || (IV_suffix XOR chunk_index_BE8)
//!   ad = version || sym_algo || aead_algo || chunk_size_octet || chunk_index (8 bytes BE)
//!
//! The IV is derived alongside the message key from HKDF.
//! A final authentication tag (encrypting empty plaintext) covers the total
//! message length.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const crypto = std.crypto;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;

const SymmetricAlgorithm = @import("../types/enums.zig").SymmetricAlgorithm;
const aead_mod = @import("aead/aead.zig");
const AeadAlgorithm = aead_mod.AeadAlgorithm;

pub const SeipdV2Error = error{
    UnsupportedAlgorithm,
    UnsupportedAeadAlgorithm,
    InvalidVersion,
    InvalidData,
    AuthenticationFailed,
    OutOfMemory,
    KeySizeMismatch,
    ChunkAuthenticationFailed,
    FinalTagMismatch,
};

/// Salt size for SEIPDv2 (RFC 9580).
const SALT_SIZE = 32;

/// Encrypt plaintext using SEIPDv2 (Tag 18, version 2).
///
/// Returns the complete SEIPD v2 packet body including the header fields,
/// salt, and encrypted chunked data.
pub fn seipdV2Encrypt(
    allocator: Allocator,
    plaintext: []const u8,
    session_key: []const u8,
    sym_algo: SymmetricAlgorithm,
    aead_algo: AeadAlgorithm,
    chunk_size_octet: u8,
) SeipdV2Error![]u8 {
    const key_size = sym_algo.keySize() orelse return SeipdV2Error.UnsupportedAlgorithm;
    const nonce_size = aead_algo.nonceSize() orelse return SeipdV2Error.UnsupportedAeadAlgorithm;
    const tag_size: usize = 16;

    if (session_key.len != key_size) return SeipdV2Error.KeySizeMismatch;

    // Chunk size = 2^(c+6) bytes
    const chunk_size: usize = @as(usize, 1) << @as(std.math.Log2Int(usize), @intCast(@as(u16, chunk_size_octet) + 6));

    // Generate random salt
    var salt: [SALT_SIZE]u8 = undefined;
    crypto.random.bytes(&salt);

    // Derive message key and IV using HKDF-SHA256
    // info = "OpenPGP" || version(2) || sym_algo || aead_algo || chunk_size_octet
    var info: [12]u8 = undefined;
    @memcpy(info[0..7], "OpenPGP");
    info[7] = 2; // version
    info[8] = @intFromEnum(sym_algo);
    info[9] = @intFromEnum(aead_algo);
    info[10] = chunk_size_octet;
    info[11] = 0; // padding to have a clean info string (not strictly needed)
    const info_len: usize = 11; // actual info length

    // HKDF: Extract PRK from salt + session_key, then expand to key_size + nonce_size
    const derived_len = key_size + nonce_size;
    var derived: [64]u8 = undefined; // max: 32 key + 16 nonce = 48

    const prk = HkdfSha256.extract(&salt, session_key);
    HkdfSha256.expand(derived[0..derived_len], info[0..info_len], prk);

    const message_key = derived[0..key_size];
    const iv = derived[key_size..derived_len];

    // Calculate number of chunks
    const num_full_chunks = plaintext.len / chunk_size;
    const last_chunk_size = plaintext.len % chunk_size;
    const num_chunks = num_full_chunks + (if (last_chunk_size > 0) @as(usize, 1) else @as(usize, 0));

    // Calculate total output size:
    // header: version(1) + sym(1) + aead(1) + chunk_size_octet(1) + salt(32) = 36
    // each chunk: chunk_data + tag(16)
    // final tag: tag(16)
    const header_size: usize = 36;
    var total_encrypted_size: usize = 0;
    for (0..num_chunks) |i| {
        const this_chunk_size = if (i < num_full_chunks) chunk_size else last_chunk_size;
        total_encrypted_size += this_chunk_size + tag_size;
    }
    total_encrypted_size += tag_size; // final authentication tag

    // Handle edge case: empty plaintext still gets a final tag
    if (num_chunks == 0) {
        total_encrypted_size = tag_size;
    }

    const result = allocator.alloc(u8, header_size + total_encrypted_size) catch
        return SeipdV2Error.OutOfMemory;
    errdefer allocator.free(result);

    // Write header
    result[0] = 2; // version
    result[1] = @intFromEnum(sym_algo);
    result[2] = @intFromEnum(aead_algo);
    result[3] = chunk_size_octet;
    @memcpy(result[4..36], &salt);

    // Encrypt each chunk
    var out_offset: usize = header_size;
    for (0..num_chunks) |chunk_idx| {
        const this_chunk_size = if (chunk_idx < num_full_chunks) chunk_size else last_chunk_size;
        const chunk_start = chunk_idx * chunk_size;
        const chunk_data = plaintext[chunk_start..][0..this_chunk_size];

        // Build nonce: IV prefix || (IV suffix XOR chunk_index)
        var nonce: [16]u8 = [_]u8{0} ** 16; // max nonce size
        @memcpy(nonce[0..nonce_size], iv[0..nonce_size]);
        xorChunkIndex(nonce[0..nonce_size], chunk_idx);

        // Build AD: version || sym || aead || chunk_size_octet || chunk_index(8 BE)
        var ad: [12]u8 = undefined;
        ad[0] = 2; // version
        ad[1] = @intFromEnum(sym_algo);
        ad[2] = @intFromEnum(aead_algo);
        ad[3] = chunk_size_octet;
        mem.writeInt(u64, ad[4..12], @intCast(chunk_idx), .big);

        // Encrypt chunk
        const enc_result = aead_mod.aeadEncrypt(
            allocator,
            sym_algo,
            aead_algo,
            message_key,
            nonce[0..nonce_size],
            chunk_data,
            &ad,
        ) catch return SeipdV2Error.OutOfMemory;
        defer enc_result.deinit(allocator);

        @memcpy(result[out_offset..][0..this_chunk_size], enc_result.ciphertext);
        out_offset += this_chunk_size;
        @memcpy(result[out_offset..][0..tag_size], &enc_result.tag);
        out_offset += tag_size;
    }

    // Final authentication tag (empty plaintext, chunk_index = num_chunks)
    {
        var nonce: [16]u8 = [_]u8{0} ** 16;
        @memcpy(nonce[0..nonce_size], iv[0..nonce_size]);
        xorChunkIndex(nonce[0..nonce_size], num_chunks);

        // AD for final tag includes total message byte count
        var ad: [20]u8 = undefined;
        ad[0] = 2;
        ad[1] = @intFromEnum(sym_algo);
        ad[2] = @intFromEnum(aead_algo);
        ad[3] = chunk_size_octet;
        mem.writeInt(u64, ad[4..12], @intCast(num_chunks), .big);
        mem.writeInt(u64, ad[12..20], @intCast(plaintext.len), .big);

        const enc_result = aead_mod.aeadEncrypt(
            allocator,
            sym_algo,
            aead_algo,
            message_key,
            nonce[0..nonce_size],
            "", // empty plaintext
            &ad,
        ) catch return SeipdV2Error.OutOfMemory;
        defer enc_result.deinit(allocator);

        @memcpy(result[out_offset..][0..tag_size], &enc_result.tag);
        out_offset += tag_size;
    }

    std.debug.assert(out_offset == result.len);
    return result;
}

/// Decrypt SEIPDv2 data.
///
/// `encrypted_data` is the complete SEIPD v2 packet body (including version byte).
/// Returns the decrypted plaintext.
pub fn seipdV2Decrypt(
    allocator: Allocator,
    encrypted_data: []const u8,
    session_key: []const u8,
) SeipdV2Error![]u8 {
    // Parse header: version(1) + sym(1) + aead(1) + chunk_size_octet(1) + salt(32) = 36
    if (encrypted_data.len < 36) return SeipdV2Error.InvalidData;

    const version = encrypted_data[0];
    if (version != 2) return SeipdV2Error.InvalidVersion;

    const sym_algo: SymmetricAlgorithm = @enumFromInt(encrypted_data[1]);
    const aead_algo: AeadAlgorithm = @enumFromInt(encrypted_data[2]);
    const chunk_size_octet = encrypted_data[3];
    const salt = encrypted_data[4..36];

    const key_size = sym_algo.keySize() orelse return SeipdV2Error.UnsupportedAlgorithm;
    const nonce_size = aead_algo.nonceSize() orelse return SeipdV2Error.UnsupportedAeadAlgorithm;
    const tag_size: usize = 16;

    if (session_key.len != key_size) return SeipdV2Error.KeySizeMismatch;

    const chunk_size: usize = @as(usize, 1) << @as(std.math.Log2Int(usize), @intCast(@as(u16, chunk_size_octet) + 6));

    // Derive message key and IV
    var info: [12]u8 = undefined;
    @memcpy(info[0..7], "OpenPGP");
    info[7] = 2;
    info[8] = @intFromEnum(sym_algo);
    info[9] = @intFromEnum(aead_algo);
    info[10] = chunk_size_octet;
    const info_len: usize = 11;

    const derived_len = key_size + nonce_size;
    var derived: [64]u8 = undefined;

    const prk = HkdfSha256.extract(salt, session_key);
    HkdfSha256.expand(derived[0..derived_len], info[0..info_len], prk);

    const message_key = derived[0..key_size];
    const iv = derived[key_size..derived_len];

    // Parse encrypted chunks
    const cipher_data = encrypted_data[36..];

    // The data consists of: chunk1_ct + chunk1_tag + chunk2_ct + chunk2_tag + ... + final_tag
    // We need to figure out the number of chunks.
    // Each full chunk is chunk_size + tag_size bytes.
    // The last chunk may be smaller.
    // Plus one final tag_size at the end.

    if (cipher_data.len < tag_size) return SeipdV2Error.InvalidData;

    // Total bytes of actual chunk data + tags (excluding final tag)
    const chunks_and_tags_len = cipher_data.len - tag_size;

    // Calculate how many full chunks fit
    const full_chunk_with_tag = chunk_size + tag_size;
    const num_full_chunks = chunks_and_tags_len / full_chunk_with_tag;
    const remainder = chunks_and_tags_len - num_full_chunks * full_chunk_with_tag;

    var num_chunks: usize = num_full_chunks;
    var last_chunk_data_size: usize = 0;

    if (remainder > 0) {
        // There's a partial last chunk
        if (remainder <= tag_size) return SeipdV2Error.InvalidData;
        last_chunk_data_size = remainder - tag_size;
        num_chunks += 1;
    }

    // Calculate total plaintext size
    const total_plaintext_size: usize = num_full_chunks * chunk_size + last_chunk_data_size;

    // Allocate plaintext buffer
    const plaintext = allocator.alloc(u8, total_plaintext_size) catch
        return SeipdV2Error.OutOfMemory;
    errdefer allocator.free(plaintext);

    // Decrypt each chunk
    var in_offset: usize = 0;
    var pt_offset: usize = 0;

    for (0..num_chunks) |chunk_idx| {
        const is_last = (chunk_idx == num_chunks - 1) and (last_chunk_data_size > 0 or num_full_chunks == 0);
        const this_chunk_size = if (is_last and last_chunk_data_size > 0) last_chunk_data_size else chunk_size;

        const chunk_ct = cipher_data[in_offset..][0..this_chunk_size];
        in_offset += this_chunk_size;
        const chunk_tag = cipher_data[in_offset..][0..tag_size];
        in_offset += tag_size;

        // Build nonce
        var nonce: [16]u8 = [_]u8{0} ** 16;
        @memcpy(nonce[0..nonce_size], iv[0..nonce_size]);
        xorChunkIndex(nonce[0..nonce_size], chunk_idx);

        // Build AD
        var ad: [12]u8 = undefined;
        ad[0] = 2;
        ad[1] = @intFromEnum(sym_algo);
        ad[2] = @intFromEnum(aead_algo);
        ad[3] = chunk_size_octet;
        mem.writeInt(u64, ad[4..12], @intCast(chunk_idx), .big);

        // Decrypt chunk
        const dec_result = aead_mod.aeadDecrypt(
            allocator,
            sym_algo,
            aead_algo,
            message_key,
            nonce[0..nonce_size],
            chunk_ct,
            chunk_tag,
            &ad,
        ) catch return SeipdV2Error.ChunkAuthenticationFailed;

        @memcpy(plaintext[pt_offset..][0..this_chunk_size], dec_result[0..this_chunk_size]);
        allocator.free(dec_result);
        pt_offset += this_chunk_size;
    }

    // Verify final authentication tag
    {
        const final_tag = cipher_data[in_offset..][0..tag_size];

        var nonce: [16]u8 = [_]u8{0} ** 16;
        @memcpy(nonce[0..nonce_size], iv[0..nonce_size]);
        xorChunkIndex(nonce[0..nonce_size], num_chunks);

        var ad: [20]u8 = undefined;
        ad[0] = 2;
        ad[1] = @intFromEnum(sym_algo);
        ad[2] = @intFromEnum(aead_algo);
        ad[3] = chunk_size_octet;
        mem.writeInt(u64, ad[4..12], @intCast(num_chunks), .big);
        mem.writeInt(u64, ad[12..20], @intCast(total_plaintext_size), .big);

        const final_dec = aead_mod.aeadDecrypt(
            allocator,
            sym_algo,
            aead_algo,
            message_key,
            nonce[0..nonce_size],
            "", // empty ciphertext
            final_tag,
            &ad,
        ) catch return SeipdV2Error.FinalTagMismatch;
        // aeadDecrypt returns a zero-length slice for empty ciphertext
        allocator.free(final_dec);
    }

    return plaintext;
}

/// XOR a big-endian 8-byte chunk index into the last 8 bytes of a nonce.
fn xorChunkIndex(nonce: []u8, chunk_idx: usize) void {
    if (nonce.len < 8) return;
    var idx_bytes: [8]u8 = undefined;
    mem.writeInt(u64, &idx_bytes, @intCast(chunk_idx), .big);
    const start = nonce.len - 8;
    for (0..8) |i| {
        nonce[start + i] ^= idx_bytes[i];
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "SEIPDv2 AES-128-EAX encrypt/decrypt round-trip" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const plaintext = "Hello, SEIPDv2 with AES-128-EAX!";

    const encrypted = try seipdV2Encrypt(allocator, plaintext, &key, .aes128, .eax, 6);
    defer allocator.free(encrypted);

    // Must start with version 2
    try std.testing.expectEqual(@as(u8, 2), encrypted[0]);
    try std.testing.expectEqual(@as(u8, @intFromEnum(SymmetricAlgorithm.aes128)), encrypted[1]);
    try std.testing.expectEqual(@as(u8, @intFromEnum(AeadAlgorithm.eax)), encrypted[2]);

    const decrypted = try seipdV2Decrypt(allocator, encrypted, &key);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "SEIPDv2 AES-256-GCM encrypt/decrypt round-trip" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0xAB} ** 32;
    const plaintext = "AES-256-GCM SEIPDv2 test with longer message data for chunked processing.";

    const encrypted = try seipdV2Encrypt(allocator, plaintext, &key, .aes256, .gcm, 6);
    defer allocator.free(encrypted);

    try std.testing.expectEqual(@as(u8, 2), encrypted[0]);

    const decrypted = try seipdV2Decrypt(allocator, encrypted, &key);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "SEIPDv2 AES-128-OCB encrypt/decrypt round-trip" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x77} ** 16;
    const plaintext = "OCB mode SEIPDv2 test";

    const encrypted = try seipdV2Encrypt(allocator, plaintext, &key, .aes128, .ocb, 6);
    defer allocator.free(encrypted);

    const decrypted = try seipdV2Decrypt(allocator, encrypted, &key);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "SEIPDv2 empty plaintext" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x01} ** 16;

    const encrypted = try seipdV2Encrypt(allocator, "", &key, .aes128, .eax, 6);
    defer allocator.free(encrypted);

    const decrypted = try seipdV2Decrypt(allocator, encrypted, &key);
    defer allocator.free(decrypted);

    try std.testing.expectEqual(@as(usize, 0), decrypted.len);
}

test "SEIPDv2 decrypt wrong key fails" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const wrong_key = [_]u8{0x99} ** 16;
    const plaintext = "Sensitive data";

    const encrypted = try seipdV2Encrypt(allocator, plaintext, &key, .aes128, .eax, 6);
    defer allocator.free(encrypted);

    const result = seipdV2Decrypt(allocator, encrypted, &wrong_key);
    try std.testing.expect(result == error.ChunkAuthenticationFailed or
        result == error.FinalTagMismatch);
}

test "SEIPDv2 decrypt invalid version fails" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x42} ** 16;

    var data: [50]u8 = undefined;
    data[0] = 1; // wrong version
    @memset(data[1..], 0xAA);

    const result = seipdV2Decrypt(allocator, &data, &key);
    try std.testing.expectError(SeipdV2Error.InvalidVersion, result);
}

test "SEIPDv2 decrypt data too short fails" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x42} ** 16;

    const data = [_]u8{ 2, 7, 1, 6 };
    const result = seipdV2Decrypt(allocator, &data, &key);
    try std.testing.expectError(SeipdV2Error.InvalidData, result);
}

test "SEIPDv2 key size mismatch" {
    const allocator = std.testing.allocator;
    const short_key = [_]u8{0x42} ** 8;

    const result = seipdV2Encrypt(allocator, "test", &short_key, .aes128, .eax, 6);
    try std.testing.expectError(SeipdV2Error.KeySizeMismatch, result);
}

test "SEIPDv2 two encryptions produce different ciphertext" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const plaintext = "Same plaintext";

    const enc1 = try seipdV2Encrypt(allocator, plaintext, &key, .aes128, .eax, 6);
    defer allocator.free(enc1);

    const enc2 = try seipdV2Encrypt(allocator, plaintext, &key, .aes128, .eax, 6);
    defer allocator.free(enc2);

    // Different random salt means different ciphertext
    try std.testing.expect(!mem.eql(u8, enc1, enc2));

    // But both decrypt to the same plaintext
    const dec1 = try seipdV2Decrypt(allocator, enc1, &key);
    defer allocator.free(dec1);
    const dec2 = try seipdV2Decrypt(allocator, enc2, &key);
    defer allocator.free(dec2);

    try std.testing.expectEqualStrings(plaintext, dec1);
    try std.testing.expectEqualStrings(plaintext, dec2);
}

test "SEIPDv2 multi-chunk message" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x55} ** 16;

    // Use chunk_size_octet=0, so chunk_size = 2^6 = 64 bytes
    // Create a message that spans multiple chunks
    const plaintext = try allocator.alloc(u8, 200);
    defer allocator.free(plaintext);
    @memset(plaintext, 0x42);

    const encrypted = try seipdV2Encrypt(allocator, plaintext, &key, .aes128, .eax, 0);
    defer allocator.free(encrypted);

    const decrypted = try seipdV2Decrypt(allocator, encrypted, &key);
    defer allocator.free(decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, decrypted);
}

test "SEIPDv2 tampered ciphertext fails" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x42} ** 16;
    const plaintext = "Integrity-protected data";

    const encrypted = try seipdV2Encrypt(allocator, plaintext, &key, .aes128, .gcm, 6);
    defer allocator.free(encrypted);

    // Tamper with encrypted data (past the header)
    const mid = 36 + (encrypted.len - 36) / 2;
    encrypted[mid] ^= 0xFF;

    const result = seipdV2Decrypt(allocator, encrypted, &key);
    try std.testing.expect(result == error.ChunkAuthenticationFailed or
        result == error.FinalTagMismatch);
}
