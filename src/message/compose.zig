// SPDX-License-Identifier: MIT
//! Message composition — creating OpenPGP messages.
//!
//! Provides functions to create literal data packets, compress data,
//! and build signed/encrypted message packet sequences.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const header_mod = @import("../packet/header.zig");
const PacketTag = @import("../packet/tags.zig").PacketTag;
const LiteralDataPacket = @import("../packets/literal_data.zig").LiteralDataPacket;
const OnePassSignaturePacket = @import("../packets/one_pass_sig.zig").OnePassSignaturePacket;
const CompressionAlgorithm = @import("../types/enums.zig").CompressionAlgorithm;
const SymmetricAlgorithm = @import("../types/enums.zig").SymmetricAlgorithm;
const HashAlgorithm = @import("../types/enums.zig").HashAlgorithm;
const PublicKeyAlgorithm = @import("../types/enums.zig").PublicKeyAlgorithm;
const Key = @import("../key/key.zig").Key;
const Mpi = @import("../types/mpi.zig").Mpi;
const session_key_mod = @import("../crypto/session_key.zig");
const seipd = @import("../crypto/seipd.zig");
const rsa = @import("../crypto/rsa.zig");
const sig_creation = @import("../signature/creation.zig");
const S2K = @import("../types/s2k.zig").S2K;

pub const ComposeError = error{
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
};

/// Create a literal data packet wrapping the given data.
///
/// Returns the complete packet (header + body) as a byte slice.
pub fn createLiteralData(
    allocator: Allocator,
    data: []const u8,
    filename: []const u8,
    binary: bool,
) ComposeError![]u8 {
    // Build the literal data packet body:
    //   format(1) + filename_len(1) + filename + timestamp(4) + data
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
    const hdr_bytes = hdr_fbs.getWritten();
    output.appendSlice(allocator, hdr_bytes) catch return error.OutOfMemory;

    // Write body
    output.append(allocator, if (binary) 'b' else 't') catch return error.OutOfMemory;
    output.append(allocator, filename_len) catch return error.OutOfMemory;
    if (actual_filename.len > 0) {
        output.appendSlice(allocator, actual_filename) catch return error.OutOfMemory;
    }
    // Timestamp: 0 (not specified)
    output.appendSlice(allocator, &[_]u8{ 0, 0, 0, 0 }) catch return error.OutOfMemory;
    if (data.len > 0) {
        output.appendSlice(allocator, data) catch return error.OutOfMemory;
    }

    return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Compress data using the specified algorithm.
///
/// Returns the complete Compressed Data packet (header + body).
/// Supports: uncompressed (algo 0), ZIP/deflate (algo 1), ZLIB (algo 2).
///
/// For ZIP and ZLIB, uses deflate "stored blocks" format which produces valid
/// deflate streams without actual compression. This ensures compatibility while
/// avoiding Zig 0.15's complex streaming compress API. A future version can
/// replace this with true LZ77 compression.
pub fn compressData(
    allocator: Allocator,
    data: []const u8,
    algo: CompressionAlgorithm,
) ComposeError![]u8 {
    switch (algo) {
        .uncompressed => {
            // Wrap in a compressed data packet with algorithm byte 0
            const body_len = 1 + data.len;
            var output: std.ArrayList(u8) = .empty;
            errdefer output.deinit(allocator);

            var hdr_buf: [6]u8 = undefined;
            var hdr_fbs = std.io.fixedBufferStream(&hdr_buf);
            header_mod.writeHeader(hdr_fbs.writer(), .compressed_data, @intCast(body_len)) catch
                return error.Overflow;
            output.appendSlice(allocator, hdr_fbs.getWritten()) catch return error.OutOfMemory;

            output.append(allocator, 0) catch return error.OutOfMemory; // algorithm byte
            output.appendSlice(allocator, data) catch return error.OutOfMemory;

            return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
        },
        .zip => {
            // ZIP = raw deflate (stored blocks)
            const compressed = deflateStoredBlocks(allocator, data) catch
                return error.CompressionFailed;
            defer allocator.free(compressed);

            const body_len = 1 + compressed.len;
            var output: std.ArrayList(u8) = .empty;
            errdefer output.deinit(allocator);

            var hdr_buf: [6]u8 = undefined;
            var hdr_fbs = std.io.fixedBufferStream(&hdr_buf);
            header_mod.writeHeader(hdr_fbs.writer(), .compressed_data, @intCast(body_len)) catch
                return error.Overflow;
            output.appendSlice(allocator, hdr_fbs.getWritten()) catch return error.OutOfMemory;

            output.append(allocator, 1) catch return error.OutOfMemory; // algorithm byte
            output.appendSlice(allocator, compressed) catch return error.OutOfMemory;

            return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
        },
        .zlib => {
            // ZLIB = zlib header + deflate stored blocks + adler32 footer
            const compressed = zlibStoredBlocks(allocator, data) catch
                return error.CompressionFailed;
            defer allocator.free(compressed);

            const body_len = 1 + compressed.len;
            var output: std.ArrayList(u8) = .empty;
            errdefer output.deinit(allocator);

            var hdr_buf: [6]u8 = undefined;
            var hdr_fbs = std.io.fixedBufferStream(&hdr_buf);
            header_mod.writeHeader(hdr_fbs.writer(), .compressed_data, @intCast(body_len)) catch
                return error.Overflow;
            output.appendSlice(allocator, hdr_fbs.getWritten()) catch return error.OutOfMemory;

            output.append(allocator, 2) catch return error.OutOfMemory; // algorithm byte
            output.appendSlice(allocator, compressed) catch return error.OutOfMemory;

            return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
        },
        .bzip2 => return error.InvalidAlgorithm,
        _ => return error.InvalidAlgorithm,
    }
}

/// Encode data as deflate "stored blocks" (no compression).
///
/// Deflate stored block format (RFC 1951 Section 3.2.4):
///   For each block (max 65535 bytes):
///     1 bit  BFINAL (1 if last block)
///     2 bits BTYPE  (00 = no compression)
///     -- byte aligned --
///     2 bytes LEN (little-endian)
///     2 bytes NLEN (one's complement of LEN, little-endian)
///     LEN bytes of literal data
fn deflateStoredBlocks(allocator: Allocator, data: []const u8) ![]u8 {
    const max_block_size: usize = 65535;
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    var offset: usize = 0;
    while (true) {
        const remaining = data.len - offset;
        const block_size: u16 = @intCast(@min(remaining, max_block_size));
        const is_final = (offset + block_size >= data.len);

        // BFINAL(1 bit) + BTYPE(2 bits) = 0b000 or 0b001, byte-aligned
        // For stored block: BTYPE=00, BFINAL=0 or 1
        const header_byte: u8 = if (is_final) 0x01 else 0x00;
        try output.append(allocator, header_byte);

        // LEN (2 bytes, little-endian)
        var len_bytes: [2]u8 = undefined;
        mem.writeInt(u16, &len_bytes, block_size, .little);
        try output.appendSlice(allocator, &len_bytes);

        // NLEN (one's complement of LEN, 2 bytes, little-endian)
        var nlen_bytes: [2]u8 = undefined;
        mem.writeInt(u16, &nlen_bytes, ~block_size, .little);
        try output.appendSlice(allocator, &nlen_bytes);

        // Literal data
        if (block_size > 0) {
            try output.appendSlice(allocator, data[offset .. offset + block_size]);
        }

        offset += block_size;
        if (is_final) break;
    }

    return try output.toOwnedSlice(allocator);
}

/// Encode data as zlib format: zlib header + deflate stored blocks + adler32.
///
/// Zlib format (RFC 1950):
///   CMF: 0x78 (CM=8 deflate, CINFO=7 32K window)
///   FLG: calculated for check (CMF*256 + FLG must be multiple of 31)
///   compressed data (deflate stored blocks)
///   Adler-32 checksum (4 bytes, big-endian)
fn zlibStoredBlocks(allocator: Allocator, data: []const u8) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // Zlib header: CMF=0x78 (deflate, 32K window), FLG chosen so (CMF*256+FLG)%31==0
    const cmf: u8 = 0x78;
    // FLG: FCHECK must make (0x78 * 256 + FLG) % 31 == 0
    // 0x7800 % 31 = 0x7800 = 30720, 30720 % 31 = 30720 - 991*31 = 30720 - 30721 = need to check
    // 30720 / 31 = 990 remainder 30720 - 990*31 = 30720 - 30690 = 30
    // So FCHECK = 31 - 30 = 1
    const flg: u8 = 0x01;
    try output.append(allocator, cmf);
    try output.append(allocator, flg);

    // Deflate stored blocks
    const deflated = try deflateStoredBlocks(allocator, data);
    defer allocator.free(deflated);
    try output.appendSlice(allocator, deflated);

    // Adler-32 checksum (big-endian)
    const adler = adler32(data);
    var adler_bytes: [4]u8 = undefined;
    mem.writeInt(u32, &adler_bytes, adler, .big);
    try output.appendSlice(allocator, &adler_bytes);

    return try output.toOwnedSlice(allocator);
}

/// Compute the Adler-32 checksum per RFC 1950.
fn adler32(data: []const u8) u32 {
    const MOD_ADLER: u32 = 65521;
    var a: u32 = 1;
    var b: u32 = 0;

    for (data) |byte| {
        a = (a + byte) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }

    return (b << 16) | a;
}

/// Create a signed message.
///
/// Returns the complete signed message as a packet sequence:
///   One-Pass Signature + Literal Data + Signature
///
/// For RSA keys, signs the document hash using PKCS#1 v1.5.
pub fn createSignedMessage(
    allocator: Allocator,
    data: []const u8,
    filename: []const u8,
    signer_key: *const Key,
    passphrase: ?[]const u8,
    hash_algo: HashAlgorithm,
) ComposeError![]u8 {
    _ = passphrase; // TODO: decrypt secret key if encrypted

    // Get the key's algorithm and key ID
    const pub_algo = signer_key.primary_key.algorithm;
    if (!pub_algo.canSign()) return error.InvalidKey;

    const key_id = signer_key.keyId();

    // Build the hashed subpackets: just a creation time subpacket
    var hashed_sp: [6]u8 = undefined;
    hashed_sp[0] = 5; // subpacket length
    hashed_sp[1] = 2; // signature creation time subpacket type
    // Current time (use 0 for now - epoch)
    const now: u32 = @truncate(@as(u64, @intCast(std.time.timestamp())));
    mem.writeInt(u32, hashed_sp[2..6], now, .big);

    // 1. Create One-Pass Signature packet
    const ops = OnePassSignaturePacket{
        .version = 3,
        .sig_type = 0x00, // binary document
        .hash_algo = hash_algo,
        .pub_algo = pub_algo,
        .key_id = key_id,
        .nested = 1, // last (not nested)
    };
    const ops_body = ops.serialize();

    // 2. Create Literal Data packet
    const literal_pkt = createLiteralData(allocator, data, filename, true) catch
        return error.OutOfMemory;
    defer allocator.free(literal_pkt);

    // 3. Compute the document hash
    const hash_result = sig_creation.computeDocumentHash(
        hash_algo,
        data,
        0x00, // binary document signature
        @intFromEnum(pub_algo),
        @intFromEnum(hash_algo),
        &hashed_sp,
        allocator,
    ) catch return error.SigningFailed;

    // 4. Create the signature
    const sig_body = createSignaturePacketBody(
        allocator,
        signer_key,
        pub_algo,
        hash_algo,
        &hashed_sp,
        key_id,
        &hash_result,
    ) catch return error.SigningFailed;
    defer allocator.free(sig_body);

    // 5. Concatenate: OPS packet + Literal Data packet + Signature packet
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // Write OPS packet header + body
    var hdr_buf: [6]u8 = undefined;
    var hdr_fbs = std.io.fixedBufferStream(&hdr_buf);
    header_mod.writeHeader(hdr_fbs.writer(), .one_pass_signature, 13) catch
        return error.Overflow;
    output.appendSlice(allocator, hdr_fbs.getWritten()) catch return error.OutOfMemory;
    output.appendSlice(allocator, &ops_body) catch return error.OutOfMemory;

    // Write Literal Data packet (already has header)
    output.appendSlice(allocator, literal_pkt) catch return error.OutOfMemory;

    // Write Signature packet header + body
    hdr_fbs = std.io.fixedBufferStream(&hdr_buf);
    header_mod.writeHeader(hdr_fbs.writer(), .signature, @intCast(sig_body.len)) catch
        return error.Overflow;
    output.appendSlice(allocator, hdr_fbs.getWritten()) catch return error.OutOfMemory;
    output.appendSlice(allocator, sig_body) catch return error.OutOfMemory;

    return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Build a v4 signature packet body for the given hash result.
fn createSignaturePacketBody(
    allocator: Allocator,
    signer_key: *const Key,
    pub_algo: PublicKeyAlgorithm,
    hash_algo: HashAlgorithm,
    hashed_subpackets: []const u8,
    key_id: [8]u8,
    hash_result: *const sig_creation.HashResult,
) ![]u8 {
    // Build unhashed subpackets: issuer key ID (subpacket type 16)
    var unhashed_sp: [10]u8 = undefined;
    unhashed_sp[0] = 9; // subpacket length
    unhashed_sp[1] = 16; // issuer key ID
    @memcpy(unhashed_sp[2..10], &key_id);

    // Create the signature MPI(s)
    var sig_mpi_data: []u8 = undefined;
    var sig_mpi_len: usize = 0;

    switch (pub_algo) {
        .rsa_encrypt_sign, .rsa_sign_only => {
            // RSA signing: need n, e, d from the key
            if (signer_key.primary_key.key_material.len < 2) return error.InvalidPacket;
            if (signer_key.secret_key == null) return error.InvalidPacket;

            const sk = signer_key.secret_key.?;
            // Parse secret MPIs from unencrypted secret data
            const secret_data = sk.secret_data;

            // Secret key MPIs for RSA: d, p, q, u
            // We need at least d (the first one)
            var sec_offset: usize = 0;
            if (sec_offset + 2 > secret_data.len) return error.InvalidPacket;
            const d_bits = mem.readInt(u16, secret_data[sec_offset..][0..2], .big);
            const d_len: usize = if (d_bits == 0) 0 else ((@as(usize, d_bits) + 7) / 8);
            sec_offset += 2;
            if (sec_offset + d_len > secret_data.len) return error.InvalidPacket;
            const d_data = secret_data[sec_offset .. sec_offset + d_len];

            const rsa_sk = rsa.RsaSecretKey{
                .n_bytes = signer_key.primary_key.key_material[0].data,
                .e_bytes = signer_key.primary_key.key_material[1].data,
                .d_bytes = d_data,
            };

            const mod_len = rsa_sk.n_bytes.len;
            const sig_buf = try allocator.alloc(u8, mod_len);
            errdefer allocator.free(sig_buf);

            rsa_sk.pkcs1v15Sign(hash_algo, hash_result.digestSlice(), sig_buf) catch
                return error.InvalidPacket;

            // Build MPI: bit_count + data
            const sig_mpi = Mpi.fromBytes(sig_buf);
            sig_mpi_len = sig_mpi.wireLen();
            sig_mpi_data = try allocator.alloc(u8, sig_mpi_len);
            mem.writeInt(u16, sig_mpi_data[0..2], sig_mpi.bit_count, .big);
            @memcpy(sig_mpi_data[2..], sig_buf);
            allocator.free(sig_buf);
        },
        else => return error.InvalidPacket,
    }
    defer allocator.free(sig_mpi_data);

    // Build complete signature packet body
    const body_len = 4 + // version + sig_type + pub_algo + hash_algo
        2 + hashed_subpackets.len + // hashed subpackets
        2 + unhashed_sp.len + // unhashed subpackets
        2 + // hash prefix
        sig_mpi_len;

    const body = try allocator.alloc(u8, body_len);
    errdefer allocator.free(body);

    body[0] = 4; // version
    body[1] = 0x00; // sig_type: binary document
    body[2] = @intFromEnum(pub_algo);
    body[3] = @intFromEnum(hash_algo);

    var offset: usize = 4;

    // Hashed subpackets
    mem.writeInt(u16, body[offset..][0..2], @intCast(hashed_subpackets.len), .big);
    offset += 2;
    @memcpy(body[offset .. offset + hashed_subpackets.len], hashed_subpackets);
    offset += hashed_subpackets.len;

    // Unhashed subpackets
    mem.writeInt(u16, body[offset..][0..2], @intCast(unhashed_sp.len), .big);
    offset += 2;
    @memcpy(body[offset .. offset + unhashed_sp.len], &unhashed_sp);
    offset += unhashed_sp.len;

    // Hash prefix
    body[offset] = hash_result.prefix[0];
    body[offset + 1] = hash_result.prefix[1];
    offset += 2;

    // Signature MPI(s)
    @memcpy(body[offset .. offset + sig_mpi_len], sig_mpi_data);

    return body;
}

/// Encrypt data for recipients (public key encryption).
///
/// Returns PKESK + SEIPD packet sequence.
/// The encryption flow:
///   1. Wrap plaintext in LiteralData packet
///   2. Optionally compress
///   3. Generate session key
///   4. For each recipient: create PKESK packet
///   5. Encrypt with seipdEncrypt
///   6. Wrap in SEIPD packet
///   7. Concatenate: PKESK packets + SEIPD packet
pub fn encryptMessage(
    allocator: Allocator,
    data: []const u8,
    filename: []const u8,
    recipients: []const *const Key,
    sym_algo: SymmetricAlgorithm,
    compress_algo: ?CompressionAlgorithm,
) ComposeError![]u8 {
    if (recipients.len == 0) return error.InvalidKey;

    // 1. Create literal data packet
    const literal_pkt = createLiteralData(allocator, data, filename, true) catch
        return error.OutOfMemory;
    defer allocator.free(literal_pkt);

    // 2. Optionally compress
    var inner_data: []u8 = undefined;
    var inner_owned = false;
    if (compress_algo) |calgo| {
        inner_data = compressData(allocator, literal_pkt, calgo) catch
            return error.CompressionFailed;
        inner_owned = true;
    } else {
        inner_data = literal_pkt;
    }
    defer if (inner_owned) allocator.free(inner_data);

    // 3. Generate session key
    const sk = session_key_mod.generateSessionKey(sym_algo) catch
        return error.InvalidAlgorithm;

    // 4. Build PKESK packets for each recipient
    var pkesk_packets: std.ArrayList([]u8) = .empty;
    defer {
        for (pkesk_packets.items) |pkt| allocator.free(pkt);
        pkesk_packets.deinit(allocator);
    }

    for (recipients) |recipient| {
        const pkesk_pkt = buildPkeskPacket(allocator, recipient, &sk, sym_algo) catch
            return error.EncryptionFailed;
        pkesk_packets.append(allocator, pkesk_pkt) catch return error.OutOfMemory;
    }

    // 5. Encrypt with SEIPD
    const seipd_body = seipd.seipdEncrypt(
        allocator,
        inner_data,
        sk.keySlice(),
        sym_algo,
    ) catch return error.EncryptionFailed;
    defer allocator.free(seipd_body);

    // 6. Build output: PKESK packets + SEIPD packet
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // Write PKESK packets
    for (pkesk_packets.items) |pkt_data| {
        var hdr_buf: [6]u8 = undefined;
        var hdr_fbs = std.io.fixedBufferStream(&hdr_buf);
        header_mod.writeHeader(hdr_fbs.writer(), .public_key_encrypted_session_key, @intCast(pkt_data.len)) catch
            return error.Overflow;
        output.appendSlice(allocator, hdr_fbs.getWritten()) catch return error.OutOfMemory;
        output.appendSlice(allocator, pkt_data) catch return error.OutOfMemory;
    }

    // Write SEIPD packet
    {
        var hdr_buf: [6]u8 = undefined;
        var hdr_fbs = std.io.fixedBufferStream(&hdr_buf);
        header_mod.writeHeader(hdr_fbs.writer(), .sym_encrypted_integrity_protected_data, @intCast(seipd_body.len)) catch
            return error.Overflow;
        output.appendSlice(allocator, hdr_fbs.getWritten()) catch return error.OutOfMemory;
        output.appendSlice(allocator, seipd_body) catch return error.OutOfMemory;
    }

    return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Build a PKESK v3 packet body for one recipient.
fn buildPkeskPacket(
    allocator: Allocator,
    recipient: *const Key,
    sk: *const session_key_mod.SessionKey,
    sym_algo: SymmetricAlgorithm,
) ![]u8 {
    const pub_algo = recipient.primary_key.algorithm;
    const key_id = recipient.keyId();

    // Build the session key data to encrypt:
    //   algo_byte + session_key_bytes + 2-byte checksum
    const key_data_len = 1 + sk.key_len + 2;
    var key_data: [35]u8 = undefined; // max: 1 + 32 + 2
    key_data[0] = @intFromEnum(sym_algo);
    @memcpy(key_data[1 .. 1 + sk.key_len], sk.key[0..sk.key_len]);
    const cksum = sk.checksum();
    mem.writeInt(u16, key_data[1 + sk.key_len ..][0..2], cksum, .big);

    // Encrypt the session key data
    switch (pub_algo) {
        .rsa_encrypt_sign, .rsa_encrypt_only => {
            if (recipient.primary_key.key_material.len < 2) return error.InvalidPacket;

            const rsa_pub = rsa.RsaPublicKey{
                .n_bytes = recipient.primary_key.key_material[0].data,
                .e_bytes = recipient.primary_key.key_material[1].data,
            };

            const mod_len = rsa_pub.n_bytes.len;
            const encrypted_key = try allocator.alloc(u8, mod_len);
            defer allocator.free(encrypted_key);

            rsa_pub.pkcs1v15Encrypt(key_data[0..key_data_len], encrypted_key) catch
                return error.InvalidPacket;

            // Build PKESK body: version(1) + key_id(8) + algo(1) + MPI
            const enc_mpi = Mpi.fromBytes(encrypted_key);
            const body_len = 1 + 8 + 1 + enc_mpi.wireLen();
            const body = try allocator.alloc(u8, body_len);
            errdefer allocator.free(body);

            body[0] = 3; // version
            @memcpy(body[1..9], &key_id);
            body[9] = @intFromEnum(pub_algo);
            mem.writeInt(u16, body[10..12], enc_mpi.bit_count, .big);
            @memcpy(body[12 .. 12 + encrypted_key.len], encrypted_key);

            return body;
        },
        else => return error.InvalidPacket,
    }
}

/// Encrypt data with passphrase (symmetric encryption).
///
/// Returns SKESK + SEIPD packet sequence.
///
/// Uses Iterated+Salted S2K (type 3) with SHA-256 to derive the
/// session key directly from the passphrase (no encrypted session key
/// in the SKESK packet).
pub fn encryptMessageSymmetric(
    allocator: Allocator,
    data: []const u8,
    filename: []const u8,
    passphrase: []const u8,
    sym_algo: SymmetricAlgorithm,
    compress_algo: ?CompressionAlgorithm,
) ComposeError![]u8 {
    const key_size = sym_algo.keySize() orelse return error.InvalidAlgorithm;

    // 1. Create literal data packet
    const literal_pkt = createLiteralData(allocator, data, filename, true) catch
        return error.OutOfMemory;
    defer allocator.free(literal_pkt);

    // 2. Optionally compress
    var inner_data: []u8 = undefined;
    var inner_owned = false;
    if (compress_algo) |calgo| {
        inner_data = compressData(allocator, literal_pkt, calgo) catch
            return error.CompressionFailed;
        inner_owned = true;
    } else {
        inner_data = literal_pkt;
    }
    defer if (inner_owned) allocator.free(inner_data);

    // 3. Build S2K and derive key from passphrase
    var salt: [8]u8 = undefined;
    std.crypto.random.bytes(&salt);

    const s2k_spec = S2K{
        .s2k_type = .iterated,
        .hash_algo = .sha256,
        .salt = salt,
        .coded_count = 96, // 65536 iterations
        .argon2_data = null,
    };

    var derived_key: [32]u8 = undefined;
    s2k_spec.deriveKey(passphrase, derived_key[0..key_size]) catch
        return error.EncryptionFailed;

    // 4. Build SKESK packet body (no encrypted session key - use derived key directly)
    //    version(1) + algo(1) + S2K specifier (11 bytes for iterated)
    const s2k_wire_size = s2k_spec.wireSize();
    const skesk_body_len = 2 + s2k_wire_size;
    var skesk_body: [13]u8 = undefined; // 2 + 11 max
    skesk_body[0] = 4; // version
    skesk_body[1] = @intFromEnum(sym_algo);

    // Write S2K specifier
    var s2k_fbs = std.io.fixedBufferStream(skesk_body[2..]);
    s2k_spec.writeTo(s2k_fbs.writer()) catch return error.EncryptionFailed;

    // 5. Encrypt with SEIPD using derived key
    const seipd_body = seipd.seipdEncrypt(
        allocator,
        inner_data,
        derived_key[0..key_size],
        sym_algo,
    ) catch return error.EncryptionFailed;
    defer allocator.free(seipd_body);

    // 6. Build output: SKESK packet + SEIPD packet
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // Write SKESK packet
    {
        var hdr_buf: [6]u8 = undefined;
        var hdr_fbs = std.io.fixedBufferStream(&hdr_buf);
        header_mod.writeHeader(hdr_fbs.writer(), .symmetric_key_encrypted_session_key, @intCast(skesk_body_len)) catch
            return error.Overflow;
        output.appendSlice(allocator, hdr_fbs.getWritten()) catch return error.OutOfMemory;
        output.appendSlice(allocator, skesk_body[0..skesk_body_len]) catch return error.OutOfMemory;
    }

    // Write SEIPD packet
    {
        var hdr_buf: [6]u8 = undefined;
        var hdr_fbs = std.io.fixedBufferStream(&hdr_buf);
        header_mod.writeHeader(hdr_fbs.writer(), .sym_encrypted_integrity_protected_data, @intCast(seipd_body.len)) catch
            return error.Overflow;
        output.appendSlice(allocator, hdr_fbs.getWritten()) catch return error.OutOfMemory;
        output.appendSlice(allocator, seipd_body) catch return error.OutOfMemory;
    }

    return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "createLiteralData binary" {
    const allocator = std.testing.allocator;

    const result = try createLiteralData(allocator, "Hello, PGP!", "test.txt", true);
    defer allocator.free(result);

    // Parse the result back: should start with a packet header for tag 11
    var fbs = std.io.fixedBufferStream(result);
    const hdr = try header_mod.readHeader(fbs.reader());
    try std.testing.expectEqual(PacketTag.literal_data, hdr.tag);

    const body_len = switch (hdr.body_length) {
        .fixed => |len| len,
        else => unreachable,
    };

    const body = result[fbs.pos .. fbs.pos + body_len];
    const pkt = try LiteralDataPacket.parse(allocator, body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@import("../packets/literal_data.zig").DataFormat.binary, pkt.format);
    try std.testing.expectEqualStrings("test.txt", pkt.filename);
    try std.testing.expectEqualStrings("Hello, PGP!", pkt.data);
}

test "createLiteralData text mode" {
    const allocator = std.testing.allocator;

    const result = try createLiteralData(allocator, "text data", "", false);
    defer allocator.free(result);

    var fbs = std.io.fixedBufferStream(result);
    const hdr = try header_mod.readHeader(fbs.reader());
    const body_len = switch (hdr.body_length) {
        .fixed => |len| len,
        else => unreachable,
    };

    const body = result[fbs.pos .. fbs.pos + body_len];
    const pkt = try LiteralDataPacket.parse(allocator, body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@import("../packets/literal_data.zig").DataFormat.text, pkt.format);
    try std.testing.expectEqualStrings("", pkt.filename);
    try std.testing.expectEqualStrings("text data", pkt.data);
}

test "createLiteralData empty data" {
    const allocator = std.testing.allocator;

    const result = try createLiteralData(allocator, "", "empty.bin", true);
    defer allocator.free(result);

    var fbs = std.io.fixedBufferStream(result);
    const hdr = try header_mod.readHeader(fbs.reader());
    const body_len = switch (hdr.body_length) {
        .fixed => |len| len,
        else => unreachable,
    };

    const body = result[fbs.pos .. fbs.pos + body_len];
    const pkt = try LiteralDataPacket.parse(allocator, body);
    defer pkt.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), pkt.data.len);
    try std.testing.expectEqualStrings("empty.bin", pkt.filename);
}

test "compressData uncompressed" {
    const allocator = std.testing.allocator;

    const input = "Hello, uncompressed world!";
    const result = try compressData(allocator, input, .uncompressed);
    defer allocator.free(result);

    // Parse back: should be tag 8 (compressed data)
    var fbs = std.io.fixedBufferStream(result);
    const hdr = try header_mod.readHeader(fbs.reader());
    try std.testing.expectEqual(PacketTag.compressed_data, hdr.tag);

    const body_len = switch (hdr.body_length) {
        .fixed => |len| len,
        else => unreachable,
    };

    const body = result[fbs.pos .. fbs.pos + body_len];
    try std.testing.expectEqual(@as(u8, 0), body[0]); // algorithm = uncompressed
    try std.testing.expectEqualStrings(input, body[1..]);
}

test "compressData ZIP deflate stored blocks" {
    const allocator = std.testing.allocator;

    const input = "Hello, compressed world!";
    const result = try compressData(allocator, input, .zip);
    defer allocator.free(result);

    // Parse back
    var fbs = std.io.fixedBufferStream(result);
    const hdr = try header_mod.readHeader(fbs.reader());
    try std.testing.expectEqual(PacketTag.compressed_data, hdr.tag);

    const body_len = switch (hdr.body_length) {
        .fixed => |len| len,
        else => unreachable,
    };

    const body = result[fbs.pos .. fbs.pos + body_len];
    try std.testing.expectEqual(@as(u8, 1), body[0]); // algorithm = ZIP

    // Verify the deflate stored block structure manually
    const deflated = body[1..];
    // First byte should be 0x01 (BFINAL=1, BTYPE=00 stored)
    try std.testing.expectEqual(@as(u8, 0x01), deflated[0]);

    // LEN (2 bytes, little-endian)
    const block_len = mem.readInt(u16, deflated[1..3], .little);
    try std.testing.expectEqual(@as(u16, @intCast(input.len)), block_len);

    // NLEN
    const nlen = mem.readInt(u16, deflated[3..5], .little);
    try std.testing.expectEqual(~@as(u16, @intCast(input.len)), nlen);

    // Data
    try std.testing.expectEqualStrings(input, deflated[5 .. 5 + input.len]);
}

test "compressData ZLIB stored blocks" {
    const allocator = std.testing.allocator;

    const input = "ZLIB compressed data test";
    const result = try compressData(allocator, input, .zlib);
    defer allocator.free(result);

    // Parse back
    var fbs = std.io.fixedBufferStream(result);
    const hdr = try header_mod.readHeader(fbs.reader());
    try std.testing.expectEqual(PacketTag.compressed_data, hdr.tag);

    const body_len = switch (hdr.body_length) {
        .fixed => |len| len,
        else => unreachable,
    };

    const body = result[fbs.pos .. fbs.pos + body_len];
    try std.testing.expectEqual(@as(u8, 2), body[0]); // algorithm = ZLIB

    const zlib_data = body[1..];

    // Check zlib header
    try std.testing.expectEqual(@as(u8, 0x78), zlib_data[0]); // CMF
    try std.testing.expectEqual(@as(u8, 0x01), zlib_data[1]); // FLG

    // Verify (CMF*256 + FLG) % 31 == 0
    const check = @as(u16, 0x78) * 256 + @as(u16, 0x01);
    try std.testing.expectEqual(@as(u16, 0), check % 31);

    // Check adler32 at end (last 4 bytes, big-endian)
    const expected_adler = adler32(input);
    const actual_adler = mem.readInt(u32, zlib_data[zlib_data.len - 4 ..][0..4], .big);
    try std.testing.expectEqual(expected_adler, actual_adler);
}

test "compressData bzip2 returns error" {
    const allocator = std.testing.allocator;
    const result = compressData(allocator, "test", .bzip2);
    try std.testing.expectError(error.InvalidAlgorithm, result);
}

test "compressData ZIP empty data" {
    const allocator = std.testing.allocator;

    const result = try compressData(allocator, "", .zip);
    defer allocator.free(result);

    var fbs = std.io.fixedBufferStream(result);
    const hdr = try header_mod.readHeader(fbs.reader());
    try std.testing.expectEqual(PacketTag.compressed_data, hdr.tag);
}

test "compressData ZLIB empty data" {
    const allocator = std.testing.allocator;

    const result = try compressData(allocator, "", .zlib);
    defer allocator.free(result);

    var fbs = std.io.fixedBufferStream(result);
    const hdr = try header_mod.readHeader(fbs.reader());
    try std.testing.expectEqual(PacketTag.compressed_data, hdr.tag);
}

test "deflateStoredBlocks round-trip structure" {
    const allocator = std.testing.allocator;

    const data = "Test data for deflate stored blocks";
    const deflated = try deflateStoredBlocks(allocator, data);
    defer allocator.free(deflated);

    // For data <= 65535, should be one block: 1 + 2 + 2 + data.len = 5 + data.len
    try std.testing.expectEqual(5 + data.len, deflated.len);
}

test "adler32 known values" {
    // Empty data: adler32 = 1
    try std.testing.expectEqual(@as(u32, 1), adler32(""));

    // "Wikipedia" example: known value
    // adler32("Wikipedia") = 0x11E60398
    try std.testing.expectEqual(@as(u32, 0x11E60398), adler32("Wikipedia"));
}

test "encryptMessage with no recipients returns InvalidKey" {
    const allocator = std.testing.allocator;
    const result = encryptMessage(allocator, "data", "file.txt", &[_]*const Key{}, .aes128, null);
    try std.testing.expectError(error.InvalidKey, result);
}

test "encryptMessageSymmetric produces valid packet stream" {
    const allocator = std.testing.allocator;
    const result = try encryptMessageSymmetric(allocator, "hello", "test.txt", "password", .aes128, null);
    defer allocator.free(result);

    // Should start with a packet header
    try std.testing.expect(result.len > 0);
    try std.testing.expect(result[0] & 0x80 != 0); // valid packet tag bit

    // Parse the result - first packet should be SKESK (tag 3)
    var fbs = std.io.fixedBufferStream(result);
    const hdr = try header_mod.readHeader(fbs.reader());
    try std.testing.expectEqual(PacketTag.symmetric_key_encrypted_session_key, hdr.tag);
}

test "encryptMessageSymmetric AES-256" {
    const allocator = std.testing.allocator;
    const result = try encryptMessageSymmetric(allocator, "secret data", "file.bin", "strong_passphrase", .aes256, null);
    defer allocator.free(result);
    try std.testing.expect(result.len > 0);
}
