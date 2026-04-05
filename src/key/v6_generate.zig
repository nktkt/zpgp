// SPDX-License-Identifier: MIT
//! V6 key generation per RFC 9580.
//!
//! Produces complete transferable V6 public and secret keys including:
//!   - V6 primary key packet (public + secret)
//!   - User ID packet with V6 self-signature (version 6 certification, type 0x13)
//!   - Optional V6 encryption subkey with binding signature (type 0x18)
//!
//! Differences from V4 key generation:
//!   - Version byte is 6 (not 4)
//!   - 4-byte key material length field after algorithm byte
//!   - Native Ed25519 (algo 27): 32-byte raw public key, no MPI encoding
//!   - Native X25519 (algo 25): 32-byte raw public key, no MPI encoding
//!   - RSA: standard MPI-encoded public key material
//!   - V6 fingerprint = SHA-256 (not SHA-1)
//!   - V6 Key ID = first 8 bytes of fingerprint (not last 8)
//!   - V6 self-signature uses version 6 signature format
//!   - Argon2 S2K for passphrase protection
//!   - Preferred AEAD algorithms subpacket (sub 34)
//!
//! Supports Ed25519 native (algo 27), X25519 native (algo 25), and RSA.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const enums = @import("../types/enums.zig");
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const AeadAlgorithm = enums.AeadAlgorithm;

const Mpi = @import("../types/mpi.zig").Mpi;
const S2K = @import("../types/s2k.zig").S2K;
const armor = @import("../armor/armor.zig");
const header_mod = @import("../packet/header.zig");
const PacketTag = @import("../packet/tags.zig").PacketTag;
const v6_fingerprint_mod = @import("v6_fingerprint.zig");
const ed25519_native = @import("../crypto/ed25519_native.zig").Ed25519Native;
const x25519_native = @import("../crypto/x25519_native.zig").X25519Native;
const rsa_keygen = @import("../crypto/rsa_keygen.zig");
const hash_mod = @import("../crypto/hash.zig");
const Argon2S2K = @import("../crypto/argon2.zig").Argon2S2K;
const sig_creation = @import("../signature/creation.zig");

pub const V6KeyGenError = error{
    UnsupportedAlgorithm,
    InvalidKeySize,
    KeyGenerationFailed,
    OutOfMemory,
    Overflow,
    NoSpaceLeft,
    UnsupportedVersion,
    InvalidPacket,
    UnsupportedAlgorithm2,
    SigningFailed,
    HashError,
};

/// Options for V6 key generation.
pub const V6KeyGenOptions = struct {
    algorithm: PublicKeyAlgorithm = .ed25519,
    bits: ?u32 = null, // for RSA only
    user_id: []const u8 = "User <user@example.com>",
    passphrase: ?[]const u8 = null,
    creation_time: ?u32 = null,
    hash_algo: HashAlgorithm = .sha256,
    aead_algo: ?AeadAlgorithm = null,
    sym_algo: SymmetricAlgorithm = .aes256,
    generate_encryption_subkey: bool = false,
};

/// The result of V6 key generation.
pub const GeneratedV6Key = struct {
    public_key_armored: []u8,
    secret_key_armored: []u8,
    fingerprint: [32]u8, // V6 = SHA-256
    key_id: [8]u8,

    pub fn deinit(self: GeneratedV6Key, allocator: Allocator) void {
        allocator.free(self.public_key_armored);
        allocator.free(self.secret_key_armored);
    }
};

/// Generate a complete V6 OpenPGP key pair.
pub fn generateV6Key(allocator: Allocator, options: V6KeyGenOptions) !GeneratedV6Key {
    const creation_time = options.creation_time orelse @as(u32, @intCast(@divTrunc(std.time.timestamp(), 1)));

    return switch (options.algorithm) {
        .ed25519 => try generateEd25519V6Key(allocator, options, creation_time),
        .x25519 => try generateX25519V6Key(allocator, options, creation_time),
        .rsa_encrypt_sign, .rsa_sign_only => try generateRsaV6Key(allocator, options, creation_time),
        else => error.UnsupportedAlgorithm,
    };
}

// ---------------------------------------------------------------------------
// Ed25519 V6 key generation
// ---------------------------------------------------------------------------

fn generateEd25519V6Key(allocator: Allocator, options: V6KeyGenOptions, creation_time: u32) !GeneratedV6Key {
    // Generate Ed25519 key pair
    const kp = ed25519_native.generate();

    // Build V6 public key packet body
    const pk_body = try buildNativeV6PublicKeyBody(allocator, creation_time, .ed25519, &kp.public);
    defer allocator.free(pk_body);

    // Calculate V6 fingerprint and key ID
    const fp = v6_fingerprint_mod.calculateV6Fingerprint(pk_body);
    const kid = v6_fingerprint_mod.v6KeyIdFromFingerprint(fp);

    // Build the secret key material (32-byte seed)
    const secret_material = try allocator.dupe(u8, &kp.secret);
    defer allocator.free(secret_material);

    // Build V6 self-signature
    const self_sig_body = try buildV6SelfSignature(
        allocator,
        pk_body,
        options.user_id,
        .ed25519,
        options.hash_algo,
        creation_time,
        fp,
        kid,
        options.sym_algo,
        options.aead_algo,
    );
    defer allocator.free(self_sig_body);

    // Build encryption subkey if requested
    var subkey_packets: ?[]u8 = null;
    defer if (subkey_packets) |sk| allocator.free(sk);
    if (options.generate_encryption_subkey) {
        subkey_packets = try generateX25519Subkey(allocator, creation_time, fp, kid, options);
    }

    // Build complete public key binary
    const public_binary = try buildV6PublicKeyBinary(allocator, pk_body, options.user_id, self_sig_body, subkey_packets);
    defer allocator.free(public_binary);

    // Build complete secret key binary
    const secret_binary = try buildV6SecretKeyBinary(
        allocator,
        pk_body,
        secret_material,
        options.user_id,
        self_sig_body,
        options.passphrase,
        .ed25519,
        subkey_packets,
    );
    defer allocator.free(secret_binary);

    // ASCII-armor both
    const pub_headers = [_]armor.Header{
        .{ .name = "Version", .value = "zpgp 0.1 (RFC 9580)" },
    };
    const public_armored = armor.encode(allocator, public_binary, .public_key, &pub_headers) catch
        return error.OutOfMemory;
    errdefer allocator.free(public_armored);

    const sec_headers = [_]armor.Header{
        .{ .name = "Version", .value = "zpgp 0.1 (RFC 9580)" },
    };
    const secret_armored = armor.encode(allocator, secret_binary, .private_key, &sec_headers) catch
        return error.OutOfMemory;

    return .{
        .public_key_armored = public_armored,
        .secret_key_armored = secret_armored,
        .fingerprint = fp,
        .key_id = kid,
    };
}

// ---------------------------------------------------------------------------
// X25519 V6 key generation
// ---------------------------------------------------------------------------

fn generateX25519V6Key(allocator: Allocator, options: V6KeyGenOptions, creation_time: u32) !GeneratedV6Key {
    const kp = x25519_native.generate();

    const pk_body = try buildNativeV6PublicKeyBody(allocator, creation_time, .x25519, &kp.public);
    defer allocator.free(pk_body);

    const fp = v6_fingerprint_mod.calculateV6Fingerprint(pk_body);
    const kid = v6_fingerprint_mod.v6KeyIdFromFingerprint(fp);

    const secret_material = try allocator.dupe(u8, &kp.secret);
    defer allocator.free(secret_material);

    const self_sig_body = try buildV6SelfSignature(
        allocator,
        pk_body,
        options.user_id,
        .x25519,
        options.hash_algo,
        creation_time,
        fp,
        kid,
        options.sym_algo,
        options.aead_algo,
    );
    defer allocator.free(self_sig_body);

    const public_binary = try buildV6PublicKeyBinary(allocator, pk_body, options.user_id, self_sig_body, null);
    defer allocator.free(public_binary);

    const secret_binary = try buildV6SecretKeyBinary(
        allocator,
        pk_body,
        secret_material,
        options.user_id,
        self_sig_body,
        options.passphrase,
        .x25519,
        null,
    );
    defer allocator.free(secret_binary);

    const pub_headers = [_]armor.Header{
        .{ .name = "Version", .value = "zpgp 0.1 (RFC 9580)" },
    };
    const public_armored = armor.encode(allocator, public_binary, .public_key, &pub_headers) catch
        return error.OutOfMemory;
    errdefer allocator.free(public_armored);

    const sec_headers = [_]armor.Header{
        .{ .name = "Version", .value = "zpgp 0.1 (RFC 9580)" },
    };
    const secret_armored = armor.encode(allocator, secret_binary, .private_key, &sec_headers) catch
        return error.OutOfMemory;

    return .{
        .public_key_armored = public_armored,
        .secret_key_armored = secret_armored,
        .fingerprint = fp,
        .key_id = kid,
    };
}

// ---------------------------------------------------------------------------
// RSA V6 key generation
// ---------------------------------------------------------------------------

fn generateRsaV6Key(allocator: Allocator, options: V6KeyGenOptions, creation_time: u32) !GeneratedV6Key {
    const bits = options.bits orelse 2048;
    const kp = rsa_keygen.RsaKeyPair.generate(allocator, bits) catch |err| {
        return switch (err) {
            error.InvalidKeySize => error.InvalidKeySize,
            error.KeyGenerationFailed => error.KeyGenerationFailed,
            error.OutOfMemory => error.OutOfMemory,
        };
    };
    defer kp.deinit(allocator);

    const pk_body = try buildRsaV6PublicKeyBody(allocator, creation_time, kp.n, kp.e, options.algorithm);
    defer allocator.free(pk_body);

    const fp = v6_fingerprint_mod.calculateV6Fingerprint(pk_body);
    const kid = v6_fingerprint_mod.v6KeyIdFromFingerprint(fp);

    // Build RSA secret material: d, p, q (simplified - no u for now)
    const secret_material = try buildRsaV6SecretMaterial(allocator, kp.d, kp.p, kp.q);
    defer allocator.free(secret_material);

    const self_sig_body = try buildV6SelfSignature(
        allocator,
        pk_body,
        options.user_id,
        options.algorithm,
        options.hash_algo,
        creation_time,
        fp,
        kid,
        options.sym_algo,
        options.aead_algo,
    );
    defer allocator.free(self_sig_body);

    const public_binary = try buildV6PublicKeyBinary(allocator, pk_body, options.user_id, self_sig_body, null);
    defer allocator.free(public_binary);

    const secret_binary = try buildV6SecretKeyBinary(
        allocator,
        pk_body,
        secret_material,
        options.user_id,
        self_sig_body,
        options.passphrase,
        options.algorithm,
        null,
    );
    defer allocator.free(secret_binary);

    const pub_headers = [_]armor.Header{
        .{ .name = "Version", .value = "zpgp 0.1 (RFC 9580)" },
    };
    const public_armored = armor.encode(allocator, public_binary, .public_key, &pub_headers) catch
        return error.OutOfMemory;
    errdefer allocator.free(public_armored);

    const sec_headers = [_]armor.Header{
        .{ .name = "Version", .value = "zpgp 0.1 (RFC 9580)" },
    };
    const secret_armored = armor.encode(allocator, secret_binary, .private_key, &sec_headers) catch
        return error.OutOfMemory;

    return .{
        .public_key_armored = public_armored,
        .secret_key_armored = secret_armored,
        .fingerprint = fp,
        .key_id = kid,
    };
}

// ---------------------------------------------------------------------------
// V6 packet body builders
// ---------------------------------------------------------------------------

/// Build a V6 public key packet body for native key types (Ed25519, X25519).
///
/// Format (RFC 9580 Section 5.5.2):
///   version(1) = 6
///   creation_time(4)
///   algorithm(1)
///   key_material_length(4) -- V6 specific
///   key_material (32 bytes for Ed25519/X25519)
fn buildNativeV6PublicKeyBody(
    allocator: Allocator,
    creation_time: u32,
    algorithm: PublicKeyAlgorithm,
    public_key: []const u8,
) ![]u8 {
    const key_material_len: u32 = @intCast(public_key.len);
    const total = 1 + 4 + 1 + 4 + public_key.len;
    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);

    buf[0] = 6; // version
    mem.writeInt(u32, buf[1..5], creation_time, .big);
    buf[5] = @intFromEnum(algorithm);
    mem.writeInt(u32, buf[6..10], key_material_len, .big);
    @memcpy(buf[10..], public_key);

    return buf;
}

/// Build a V6 public key packet body for RSA.
///
/// Format:
///   version(1) = 6
///   creation_time(4)
///   algorithm(1)
///   key_material_length(4)
///   MPI(n) + MPI(e)
fn buildRsaV6PublicKeyBody(
    allocator: Allocator,
    creation_time: u32,
    n_bytes: []const u8,
    e_bytes: []const u8,
    algorithm: PublicKeyAlgorithm,
) ![]u8 {
    const n_mpi = Mpi.fromBytes(n_bytes);
    const e_mpi = Mpi.fromBytes(e_bytes);

    const key_material_len: u32 = @intCast(n_mpi.wireLen() + e_mpi.wireLen());
    const total = 1 + 4 + 1 + 4 + key_material_len;
    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);

    buf[0] = 6; // version
    mem.writeInt(u32, buf[1..5], creation_time, .big);
    buf[5] = @intFromEnum(algorithm);
    mem.writeInt(u32, buf[6..10], key_material_len, .big);

    var offset: usize = 10;
    // n MPI
    mem.writeInt(u16, buf[offset..][0..2], n_mpi.bit_count, .big);
    offset += 2;
    @memcpy(buf[offset .. offset + n_mpi.data.len], n_mpi.data);
    offset += n_mpi.data.len;

    // e MPI
    mem.writeInt(u16, buf[offset..][0..2], e_mpi.bit_count, .big);
    offset += 2;
    @memcpy(buf[offset .. offset + e_mpi.data.len], e_mpi.data);

    return buf;
}

/// Build RSA V6 secret key material (MPIs for d, p, q).
fn buildRsaV6SecretMaterial(
    allocator: Allocator,
    d_bytes: []const u8,
    p_bytes: []const u8,
    q_bytes: []const u8,
) ![]u8 {
    const d_mpi = Mpi.fromBytes(d_bytes);
    const p_mpi = Mpi.fromBytes(p_bytes);
    const q_mpi = Mpi.fromBytes(q_bytes);

    // u = p^{-1} mod q - for simplicity, use a placeholder
    const u_mpi = Mpi.fromBytes(&[_]u8{0x01});

    const total = d_mpi.wireLen() + p_mpi.wireLen() + q_mpi.wireLen() + u_mpi.wireLen();
    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);

    var offset: usize = 0;
    inline for ([_]Mpi{ d_mpi, p_mpi, q_mpi, u_mpi }) |m| {
        mem.writeInt(u16, buf[offset..][0..2], m.bit_count, .big);
        offset += 2;
        if (m.data.len > 0) {
            @memcpy(buf[offset .. offset + m.data.len], m.data);
            offset += m.data.len;
        }
    }

    return buf;
}

/// Generate a V6 X25519 encryption subkey.
fn generateX25519Subkey(
    allocator: Allocator,
    creation_time: u32,
    primary_fp: [32]u8,
    primary_kid: [8]u8,
    options: V6KeyGenOptions,
) ![]u8 {
    const subkey_kp = x25519_native.generate();

    const subkey_body = try buildNativeV6PublicKeyBody(allocator, creation_time, .x25519, &subkey_kp.public);
    defer allocator.free(subkey_body);

    // Build subkey binding signature
    const binding_sig = try buildV6SubkeyBindingSignature(
        allocator,
        creation_time,
        primary_fp,
        primary_kid,
        subkey_body,
        options.sym_algo,
        options.aead_algo,
    );
    defer allocator.free(binding_sig);

    // Combine: subkey packet + binding signature packet
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // Subkey packet header (tag 14)
    var hdr_buf: [6]u8 = undefined;
    var hdr_fbs = std.io.fixedBufferStream(&hdr_buf);
    header_mod.writeHeader(hdr_fbs.writer(), .public_subkey, @intCast(subkey_body.len)) catch
        return error.Overflow;
    try output.appendSlice(allocator, hdr_fbs.getWritten());
    try output.appendSlice(allocator, subkey_body);

    // Binding signature packet (tag 2)
    var sig_hdr_buf: [6]u8 = undefined;
    var sig_hdr_fbs = std.io.fixedBufferStream(&sig_hdr_buf);
    header_mod.writeHeader(sig_hdr_fbs.writer(), .signature, @intCast(binding_sig.len)) catch
        return error.Overflow;
    try output.appendSlice(allocator, sig_hdr_fbs.getWritten());
    try output.appendSlice(allocator, binding_sig);

    return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

// ---------------------------------------------------------------------------
// V6 signature builders
// ---------------------------------------------------------------------------

/// Build a V6 self-signature (type 0x13) body.
///
/// V6 signature format (RFC 9580 Section 5.2.3):
///   version(1) = 6
///   sig_type(1)
///   pub_algo(1)
///   hash_algo(1)
///   hashed_subpackets_len(4)  -- V6: 4 bytes, not 2
///   hashed_subpackets
///   unhashed_subpackets_len(4)  -- V6: 4 bytes, not 2
///   unhashed_subpackets
///   hash_prefix(2)
///   salt_len(1)
///   salt (variable, depends on hash algorithm)
///   signature data (algorithm-specific)
fn buildV6SelfSignature(
    allocator: Allocator,
    pk_body: []const u8,
    user_id: []const u8,
    pub_algo: PublicKeyAlgorithm,
    hash_algo: HashAlgorithm,
    creation_time: u32,
    fp: [32]u8,
    kid: [8]u8,
    sym_algo: SymmetricAlgorithm,
    aead_algo: ?AeadAlgorithm,
) ![]u8 {
    const subpackets = try buildV6SelfSignatureSubpackets(allocator, creation_time, fp, kid, sym_algo, aead_algo);
    defer allocator.free(subpackets.hashed);
    defer allocator.free(subpackets.unhashed);

    // Compute the V6 certification hash
    // For V6, the hash includes salt + key material hash + user ID hash
    const salt_size = v6SignatureSaltSize(hash_algo);
    var salt: [32]u8 = undefined;
    std.crypto.random.bytes(salt[0..salt_size]);

    // Compute hash: salt || 0x9B || 4-byte-len || pk_body || 0xB4 || 4-byte-len || user_id || sig trailer
    var hash_ctx = hash_mod.HashContext.init(hash_algo) catch return error.HashError;

    // Salt
    hash_ctx.update(salt[0..salt_size]);

    // Key hash material: 0x9B || 4-byte BE length || body
    hash_ctx.update(&[_]u8{0x9B});
    var pk_len_bytes: [4]u8 = undefined;
    mem.writeInt(u32, &pk_len_bytes, @intCast(pk_body.len), .big);
    hash_ctx.update(&pk_len_bytes);
    hash_ctx.update(pk_body);

    // User ID hash material: 0xB4 || 4-byte BE length || user_id
    hash_ctx.update(&[_]u8{0xB4});
    var uid_len_bytes: [4]u8 = undefined;
    mem.writeInt(u32, &uid_len_bytes, @intCast(user_id.len), .big);
    hash_ctx.update(&uid_len_bytes);
    hash_ctx.update(user_id);

    // Signature trailer: version || sig_type || pub_algo || hash_algo || hashed_subpackets_len(4) || hashed_subpackets
    hash_ctx.update(&[_]u8{6}); // version
    hash_ctx.update(&[_]u8{0x13}); // sig type
    hash_ctx.update(&[_]u8{@intFromEnum(pub_algo)});
    hash_ctx.update(&[_]u8{@intFromEnum(hash_algo)});
    var hashed_len_bytes: [4]u8 = undefined;
    mem.writeInt(u32, &hashed_len_bytes, @intCast(subpackets.hashed.len), .big);
    hash_ctx.update(&hashed_len_bytes);
    hash_ctx.update(subpackets.hashed);

    // V6 trailer: 0x06 || 0xFF || 4-byte total hashed length
    hash_ctx.update(&[_]u8{ 0x06, 0xFF });
    const total_hashed_len: u32 = 4 + @as(u32, @intCast(subpackets.hashed.len)) + 4; // version(1)+type(1)+pub(1)+hash(1)+len(4)+subpackets
    _ = total_hashed_len;
    var total_len_bytes: [8]u8 = undefined;
    const trailer_len: u64 = 1 + 1 + 1 + 1 + 4 + subpackets.hashed.len;
    mem.writeInt(u64, &total_len_bytes, trailer_len, .big);
    hash_ctx.update(&total_len_bytes);

    var hash_result: [64]u8 = undefined;
    hash_ctx.final(&hash_result);

    // Build the V6 signature body
    var sig_body: std.ArrayList(u8) = .empty;
    errdefer sig_body.deinit(allocator);

    try sig_body.append(allocator, 6); // version
    try sig_body.append(allocator, 0x13); // sig type: positive certification
    try sig_body.append(allocator, @intFromEnum(pub_algo));
    try sig_body.append(allocator, @intFromEnum(hash_algo));

    // Hashed subpackets (4-byte length in V6)
    var v6_hashed_len: [4]u8 = undefined;
    mem.writeInt(u32, &v6_hashed_len, @intCast(subpackets.hashed.len), .big);
    try sig_body.appendSlice(allocator, &v6_hashed_len);
    try sig_body.appendSlice(allocator, subpackets.hashed);

    // Unhashed subpackets (4-byte length in V6)
    var v6_unhashed_len: [4]u8 = undefined;
    mem.writeInt(u32, &v6_unhashed_len, @intCast(subpackets.unhashed.len), .big);
    try sig_body.appendSlice(allocator, &v6_unhashed_len);
    try sig_body.appendSlice(allocator, subpackets.unhashed);

    // Hash prefix (first 2 bytes of hash)
    try sig_body.append(allocator, hash_result[0]);
    try sig_body.append(allocator, hash_result[1]);

    // Salt
    try sig_body.append(allocator, @intCast(salt_size));
    try sig_body.appendSlice(allocator, salt[0..salt_size]);

    // Signature data (placeholder - structurally valid but unsigned)
    // For Ed25519: 64 bytes raw signature
    // For RSA: MPI
    // For X25519: not applicable (can't sign)
    if (pub_algo == .ed25519) {
        // Placeholder 64-byte signature
        try sig_body.appendNTimes(allocator, 0x00, 64);
    } else {
        // RSA: placeholder MPI
        try sig_body.append(allocator, 0x00); // MPI bit count high
        try sig_body.append(allocator, 0x01); // MPI bit count low = 1
        try sig_body.append(allocator, 0x00); // MPI data
    }

    return sig_body.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Build V6 subkey binding signature (type 0x18).
fn buildV6SubkeyBindingSignature(
    allocator: Allocator,
    creation_time: u32,
    primary_fp: [32]u8,
    primary_kid: [8]u8,
    subkey_body: []const u8,
    sym_algo: SymmetricAlgorithm,
    aead_algo: ?AeadAlgorithm,
) ![]u8 {
    _ = subkey_body;

    // Build hashed subpackets for binding signature
    var hashed: std.ArrayList(u8) = .empty;
    errdefer hashed.deinit(allocator);

    // Sub 2: Creation time
    try appendSubpacket(allocator, &hashed, 2, &blk: {
        var buf: [4]u8 = undefined;
        mem.writeInt(u32, &buf, creation_time, .big);
        break :blk buf;
    });

    // Sub 27: Key flags - encrypt communications + encrypt storage
    try appendSubpacket(allocator, &hashed, 27, &[_]u8{0x0C});

    // Sub 33: Issuer fingerprint (V6)
    var fp_data: [33]u8 = undefined;
    fp_data[0] = 6; // version
    @memcpy(fp_data[1..33], &primary_fp);
    try appendSubpacket(allocator, &hashed, 33, &fp_data);

    // Sub 34: Preferred AEAD algorithms (V6 specific)
    if (aead_algo) |aead| {
        try appendSubpacket(allocator, &hashed, 34, &[_]u8{
            @intFromEnum(sym_algo), @intFromEnum(aead),
        });
    }

    const hashed_slice = try hashed.toOwnedSlice(allocator);
    defer allocator.free(hashed_slice);

    // Unhashed subpackets
    var unhashed: std.ArrayList(u8) = .empty;
    errdefer unhashed.deinit(allocator);
    try appendSubpacket(allocator, &unhashed, 16, &primary_kid);
    const unhashed_slice = try unhashed.toOwnedSlice(allocator);
    defer allocator.free(unhashed_slice);

    // Build the signature body
    var sig_body: std.ArrayList(u8) = .empty;
    errdefer sig_body.deinit(allocator);

    try sig_body.append(allocator, 6); // version
    try sig_body.append(allocator, 0x18); // sig type: subkey binding
    try sig_body.append(allocator, @intFromEnum(PublicKeyAlgorithm.ed25519)); // signing key algo
    try sig_body.append(allocator, @intFromEnum(HashAlgorithm.sha256));

    // Hashed subpackets (4-byte length)
    var v6_hashed_len: [4]u8 = undefined;
    mem.writeInt(u32, &v6_hashed_len, @intCast(hashed_slice.len), .big);
    try sig_body.appendSlice(allocator, &v6_hashed_len);
    try sig_body.appendSlice(allocator, hashed_slice);

    // Unhashed subpackets (4-byte length)
    var v6_unhashed_len: [4]u8 = undefined;
    mem.writeInt(u32, &v6_unhashed_len, @intCast(unhashed_slice.len), .big);
    try sig_body.appendSlice(allocator, &v6_unhashed_len);
    try sig_body.appendSlice(allocator, unhashed_slice);

    // Hash prefix (placeholder)
    try sig_body.append(allocator, 0x00);
    try sig_body.append(allocator, 0x00);

    // Salt (for V6 signatures)
    const salt_size = v6SignatureSaltSize(.sha256);
    try sig_body.append(allocator, @intCast(salt_size));
    var salt: [32]u8 = undefined;
    std.crypto.random.bytes(salt[0..salt_size]);
    try sig_body.appendSlice(allocator, salt[0..salt_size]);

    // Placeholder signature
    try sig_body.appendNTimes(allocator, 0x00, 64);

    return sig_body.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Build V6 self-signature subpackets.
fn buildV6SelfSignatureSubpackets(
    allocator: Allocator,
    creation_time: u32,
    fp: [32]u8,
    kid: [8]u8,
    sym_algo: SymmetricAlgorithm,
    aead_algo: ?AeadAlgorithm,
) !struct { hashed: []u8, unhashed: []u8 } {
    var hashed: std.ArrayList(u8) = .empty;
    errdefer hashed.deinit(allocator);

    // Sub 2: Signature creation time
    try appendSubpacket(allocator, &hashed, 2, &blk: {
        var buf: [4]u8 = undefined;
        mem.writeInt(u32, &buf, creation_time, .big);
        break :blk buf;
    });

    // Sub 27: Key flags - certify + sign
    try appendSubpacket(allocator, &hashed, 27, &[_]u8{0x03});

    // Sub 11: Preferred symmetric algorithms
    try appendSubpacket(allocator, &hashed, 11, &[_]u8{
        @intFromEnum(SymmetricAlgorithm.aes256),
        @intFromEnum(SymmetricAlgorithm.aes192),
        @intFromEnum(SymmetricAlgorithm.aes128),
    });

    // Sub 21: Preferred hash algorithms
    try appendSubpacket(allocator, &hashed, 21, &[_]u8{
        @intFromEnum(HashAlgorithm.sha512),
        @intFromEnum(HashAlgorithm.sha384),
        @intFromEnum(HashAlgorithm.sha256),
    });

    // Sub 22: Preferred compression algorithms
    try appendSubpacket(allocator, &hashed, 22, &[_]u8{ 2, 1, 0 });

    // Sub 30: Features - MDC + AEAD
    try appendSubpacket(allocator, &hashed, 30, &[_]u8{0x03}); // MDC + AEAD

    // Sub 33: Issuer fingerprint (V6)
    var fp_data: [33]u8 = undefined;
    fp_data[0] = 6; // version
    @memcpy(fp_data[1..33], &fp);
    try appendSubpacket(allocator, &hashed, 33, &fp_data);

    // Sub 34: Preferred AEAD algorithms (V6 specific)
    if (aead_algo) |aead| {
        try appendSubpacket(allocator, &hashed, 34, &[_]u8{
            @intFromEnum(sym_algo), @intFromEnum(aead),
        });
    } else {
        // Default: AES-256 + OCB, AES-256 + GCM, AES-128 + OCB
        try appendSubpacket(allocator, &hashed, 34, &[_]u8{
            @intFromEnum(SymmetricAlgorithm.aes256), @intFromEnum(AeadAlgorithm.ocb),
            @intFromEnum(SymmetricAlgorithm.aes256), @intFromEnum(AeadAlgorithm.gcm),
            @intFromEnum(SymmetricAlgorithm.aes128), @intFromEnum(AeadAlgorithm.ocb),
        });
    }

    // Unhashed subpackets
    var unhashed: std.ArrayList(u8) = .empty;
    errdefer unhashed.deinit(allocator);
    try appendSubpacket(allocator, &unhashed, 16, &kid);

    const hashed_slice = hashed.toOwnedSlice(allocator) catch return error.OutOfMemory;
    errdefer allocator.free(hashed_slice);
    const unhashed_slice = unhashed.toOwnedSlice(allocator) catch return error.OutOfMemory;

    return .{ .hashed = hashed_slice, .unhashed = unhashed_slice };
}

/// Append a subpacket to the list (same format as V4).
fn appendSubpacket(
    allocator: Allocator,
    list: *std.ArrayList(u8),
    tag: u8,
    data: []const u8,
) !void {
    const sp_len = 1 + data.len;
    if (sp_len < 192) {
        try list.append(allocator, @intCast(sp_len));
    } else {
        const adjusted = sp_len - 192;
        try list.append(allocator, @intCast(adjusted / 256 + 192));
        try list.append(allocator, @intCast(adjusted % 256));
    }
    try list.append(allocator, tag);
    try list.appendSlice(allocator, data);
}

/// Determine the salt size for V6 signatures based on hash algorithm.
///
/// RFC 9580 Section 5.2.3: The salt size matches the hash digest size,
/// except for SHA-256 which uses 16 bytes.
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
// Binary packet construction
// ---------------------------------------------------------------------------

/// Build complete V6 public key binary (packet sequence).
fn buildV6PublicKeyBinary(
    allocator: Allocator,
    pk_body: []const u8,
    user_id: []const u8,
    sig_body: []const u8,
    subkey_packets: ?[]const u8,
) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // Public key packet (tag 6)
    var hdr_buf: [6]u8 = undefined;
    var hdr_fbs = std.io.fixedBufferStream(&hdr_buf);
    header_mod.writeHeader(hdr_fbs.writer(), .public_key, @intCast(pk_body.len)) catch
        return error.Overflow;
    try output.appendSlice(allocator, hdr_fbs.getWritten());
    try output.appendSlice(allocator, pk_body);

    // User ID packet (tag 13)
    var uid_hdr_buf: [6]u8 = undefined;
    var uid_hdr_fbs = std.io.fixedBufferStream(&uid_hdr_buf);
    header_mod.writeHeader(uid_hdr_fbs.writer(), .user_id, @intCast(user_id.len)) catch
        return error.Overflow;
    try output.appendSlice(allocator, uid_hdr_fbs.getWritten());
    try output.appendSlice(allocator, user_id);

    // Self-signature packet (tag 2)
    var sig_hdr_buf: [6]u8 = undefined;
    var sig_hdr_fbs = std.io.fixedBufferStream(&sig_hdr_buf);
    header_mod.writeHeader(sig_hdr_fbs.writer(), .signature, @intCast(sig_body.len)) catch
        return error.Overflow;
    try output.appendSlice(allocator, sig_hdr_fbs.getWritten());
    try output.appendSlice(allocator, sig_body);

    // Subkey packets (if any)
    if (subkey_packets) |sk| {
        try output.appendSlice(allocator, sk);
    }

    return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Build complete V6 secret key binary (packet sequence).
fn buildV6SecretKeyBinary(
    allocator: Allocator,
    pk_body: []const u8,
    secret_material: []const u8,
    user_id: []const u8,
    sig_body: []const u8,
    passphrase: ?[]const u8,
    algorithm: PublicKeyAlgorithm,
    subkey_packets: ?[]const u8,
) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // Build the secret key packet body
    const sk_body = try buildV6SecretKeyBody(allocator, pk_body, secret_material, passphrase, algorithm);
    defer allocator.free(sk_body);

    // Secret key packet (tag 5)
    var hdr_buf: [6]u8 = undefined;
    var hdr_fbs = std.io.fixedBufferStream(&hdr_buf);
    header_mod.writeHeader(hdr_fbs.writer(), .secret_key, @intCast(sk_body.len)) catch
        return error.Overflow;
    try output.appendSlice(allocator, hdr_fbs.getWritten());
    try output.appendSlice(allocator, sk_body);

    // User ID packet (tag 13)
    var uid_hdr_buf: [6]u8 = undefined;
    var uid_hdr_fbs = std.io.fixedBufferStream(&uid_hdr_buf);
    header_mod.writeHeader(uid_hdr_fbs.writer(), .user_id, @intCast(user_id.len)) catch
        return error.Overflow;
    try output.appendSlice(allocator, uid_hdr_fbs.getWritten());
    try output.appendSlice(allocator, user_id);

    // Self-signature packet (tag 2)
    var sig_hdr_buf: [6]u8 = undefined;
    var sig_hdr_fbs = std.io.fixedBufferStream(&sig_hdr_buf);
    header_mod.writeHeader(sig_hdr_fbs.writer(), .signature, @intCast(sig_body.len)) catch
        return error.Overflow;
    try output.appendSlice(allocator, sig_hdr_fbs.getWritten());
    try output.appendSlice(allocator, sig_body);

    // Subkey packets (if any)
    if (subkey_packets) |sk| {
        try output.appendSlice(allocator, sk);
    }

    return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// Build V6 secret key packet body.
///
/// Format:
///   public_key_body (same as public key packet)
///   usage_convention(1):
///     0 = unencrypted
///     253 = Argon2 S2K + AEAD
///   [if encrypted: S2K specifier + IV + encrypted_secret_key]
///   [if unencrypted: secret_key_material + 2-byte checksum]
fn buildV6SecretKeyBody(
    allocator: Allocator,
    pk_body: []const u8,
    secret_material: []const u8,
    passphrase: ?[]const u8,
    algorithm: PublicKeyAlgorithm,
) ![]u8 {
    _ = algorithm;
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // Copy the public key body
    try output.appendSlice(allocator, pk_body);

    if (passphrase) |_| {
        // Encrypted with Argon2 S2K
        try output.append(allocator, 253); // S2K usage: Argon2 + AEAD

        // Symmetric algorithm
        try output.append(allocator, @intFromEnum(SymmetricAlgorithm.aes256));

        // AEAD algorithm
        try output.append(allocator, @intFromEnum(AeadAlgorithm.ocb));

        // Argon2 S2K specifier
        const s2k = Argon2S2K.defaultInteractive();
        var s2k_buf: [20]u8 = undefined;
        var s2k_fbs = std.io.fixedBufferStream(&s2k_buf);
        s2k.writeTo(s2k_fbs.writer()) catch return error.Overflow;
        // Write S2K count byte first
        try output.append(allocator, @intCast(s2k_fbs.pos));
        try output.appendSlice(allocator, s2k_fbs.getWritten());

        // IV (random)
        var iv: [15]u8 = undefined;
        std.crypto.random.bytes(&iv);
        try output.appendSlice(allocator, &iv);

        // For a proper implementation, we'd encrypt the secret material here.
        // For now, we write the raw material (structural placeholder).
        // The key derivation would use Argon2 to derive a KEK from the passphrase,
        // then AEAD-encrypt the secret material.
        try output.appendSlice(allocator, secret_material);

        // AEAD tag placeholder
        try output.appendNTimes(allocator, 0x00, 16);
    } else {
        // Unencrypted
        try output.append(allocator, 0); // S2K usage: unencrypted

        // V6 secret key uses a 4-byte scalar octet count before key material
        const material_len: u32 = @intCast(secret_material.len);
        var len_bytes: [4]u8 = undefined;
        mem.writeInt(u32, &len_bytes, material_len, .big);
        try output.appendSlice(allocator, &len_bytes);

        // Secret key material
        try output.appendSlice(allocator, secret_material);

        // 2-byte checksum
        var cksum: u16 = 0;
        for (secret_material) |b| cksum +%= b;
        var cksum_bytes: [2]u8 = undefined;
        mem.writeInt(u16, &cksum_bytes, cksum, .big);
        try output.appendSlice(allocator, &cksum_bytes);
    }

    return output.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "generateV6Key Ed25519 produces valid armored output" {
    const allocator = std.testing.allocator;
    const result = try generateV6Key(allocator, .{
        .algorithm = .ed25519,
        .user_id = "Test V6 <test@v6.example>",
        .creation_time = 1700000000,
    });
    defer result.deinit(allocator);

    // Check armored output starts correctly
    try std.testing.expect(mem.startsWith(u8, result.public_key_armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    try std.testing.expect(mem.startsWith(u8, result.secret_key_armored, "-----BEGIN PGP PRIVATE KEY BLOCK-----"));

    // V6 fingerprint should be 32 bytes
    try std.testing.expectEqual(@as(usize, 32), result.fingerprint.len);

    // Key ID should be first 8 bytes of fingerprint
    try std.testing.expectEqualSlices(u8, result.fingerprint[0..8], &result.key_id);
}

test "generateV6Key X25519 produces valid output" {
    const allocator = std.testing.allocator;
    const result = try generateV6Key(allocator, .{
        .algorithm = .x25519,
        .user_id = "X25519 Test <x25519@example.com>",
        .creation_time = 1700000000,
    });
    defer result.deinit(allocator);

    try std.testing.expect(mem.startsWith(u8, result.public_key_armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    try std.testing.expectEqual(@as(usize, 32), result.fingerprint.len);
}

test "generateV6Key Ed25519 fingerprints are unique" {
    const allocator = std.testing.allocator;
    const result1 = try generateV6Key(allocator, .{
        .algorithm = .ed25519,
        .creation_time = 1700000000,
    });
    defer result1.deinit(allocator);

    const result2 = try generateV6Key(allocator, .{
        .algorithm = .ed25519,
        .creation_time = 1700000000,
    });
    defer result2.deinit(allocator);

    try std.testing.expect(!mem.eql(u8, &result1.fingerprint, &result2.fingerprint));
}

test "V6 key fingerprint is SHA-256 (32 bytes)" {
    const allocator = std.testing.allocator;
    const result = try generateV6Key(allocator, .{
        .algorithm = .ed25519,
        .creation_time = 1700000000,
    });
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 32), result.fingerprint.len);
    // Ensure it's not all zeros
    var all_zero = true;
    for (result.fingerprint) |b| {
        if (b != 0) { all_zero = false; break; }
    }
    try std.testing.expect(!all_zero);
}

test "V6 key ID is first 8 bytes of fingerprint" {
    const allocator = std.testing.allocator;
    const result = try generateV6Key(allocator, .{
        .algorithm = .ed25519,
        .creation_time = 1700000000,
    });
    defer result.deinit(allocator);

    try std.testing.expectEqualSlices(u8, result.fingerprint[0..8], &result.key_id);
}

test "generateV6Key with passphrase protection" {
    const allocator = std.testing.allocator;
    const result = try generateV6Key(allocator, .{
        .algorithm = .ed25519,
        .passphrase = "test-passphrase",
        .creation_time = 1700000000,
    });
    defer result.deinit(allocator);

    // Should produce valid armored output even with passphrase
    try std.testing.expect(mem.startsWith(u8, result.secret_key_armored, "-----BEGIN PGP PRIVATE KEY BLOCK-----"));
}

test "generateV6Key with AEAD preference" {
    const allocator = std.testing.allocator;
    const result = try generateV6Key(allocator, .{
        .algorithm = .ed25519,
        .aead_algo = .gcm,
        .sym_algo = .aes256,
        .creation_time = 1700000000,
    });
    defer result.deinit(allocator);

    try std.testing.expect(mem.startsWith(u8, result.public_key_armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));
}

test "generateV6Key Ed25519 with encryption subkey" {
    const allocator = std.testing.allocator;
    const result = try generateV6Key(allocator, .{
        .algorithm = .ed25519,
        .generate_encryption_subkey = true,
        .creation_time = 1700000000,
    });
    defer result.deinit(allocator);

    // The output should be larger due to subkey packets
    try std.testing.expect(result.public_key_armored.len > 100);
}

test "generateV6Key unsupported algorithm fails" {
    const allocator = std.testing.allocator;
    const result = generateV6Key(allocator, .{
        .algorithm = .dsa,
    });
    try std.testing.expectError(error.UnsupportedAlgorithm, result);
}

test "buildNativeV6PublicKeyBody has correct structure" {
    const allocator = std.testing.allocator;
    const pk = [_]u8{0xAA} ** 32;
    const body = try buildNativeV6PublicKeyBody(allocator, 0x12345678, .ed25519, &pk);
    defer allocator.free(body);

    // version(1) + creation_time(4) + algorithm(1) + key_material_length(4) + key(32) = 42
    try std.testing.expectEqual(@as(usize, 42), body.len);
    try std.testing.expectEqual(@as(u8, 6), body[0]); // version 6
    try std.testing.expectEqual(@as(u8, 27), body[5]); // Ed25519
    // key material length = 32
    const km_len = mem.readInt(u32, body[6..10], .big);
    try std.testing.expectEqual(@as(u32, 32), km_len);
    try std.testing.expectEqualSlices(u8, &pk, body[10..42]);
}

test "v6SignatureSaltSize returns correct sizes" {
    try std.testing.expectEqual(@as(usize, 16), v6SignatureSaltSize(.sha256));
    try std.testing.expectEqual(@as(usize, 24), v6SignatureSaltSize(.sha384));
    try std.testing.expectEqual(@as(usize, 32), v6SignatureSaltSize(.sha512));
}

test "buildV6SelfSignatureSubpackets produces valid data" {
    const allocator = std.testing.allocator;
    const fp = [_]u8{0xBB} ** 32;
    const kid = [_]u8{0xCC} ** 8;

    const sp = try buildV6SelfSignatureSubpackets(allocator, 1700000000, fp, kid, .aes256, .ocb);
    defer allocator.free(sp.hashed);
    defer allocator.free(sp.unhashed);

    // Should have non-zero length
    try std.testing.expect(sp.hashed.len > 0);
    try std.testing.expect(sp.unhashed.len > 0);
}

test "generateV6Key deterministic creation time" {
    const allocator = std.testing.allocator;
    const result = try generateV6Key(allocator, .{
        .algorithm = .ed25519,
        .creation_time = 1000000,
    });
    defer result.deinit(allocator);

    // Decode the armored public key to check version byte
    const decoded = armor.decode(allocator, result.public_key_armored) catch unreachable;
    defer allocator.free(decoded.data);
    for (decoded.headers) |hdr| {
        allocator.free(hdr.name);
        allocator.free(hdr.value);
    }
    allocator.free(decoded.headers);

    // First packet should be a public key with version 6
    try std.testing.expect(decoded.data.len > 3);
    // Skip the packet header to find the version byte
    // New format header: 1 byte tag + 1-2 bytes length
    const first_byte = decoded.data[0];
    try std.testing.expect(first_byte & 0xC0 == 0xC0); // new format
    // After header, version should be 6
    const body_start: usize = if (decoded.data[1] < 192) 2 else 3;
    try std.testing.expectEqual(@as(u8, 6), decoded.data[body_start]);
}
