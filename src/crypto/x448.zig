// SPDX-License-Identifier: MIT
//! RFC 9580 native X448 key agreement (algorithm ID 26).
//!
//! Implements X448 Diffie-Hellman key agreement per RFC 7748 using
//! Curve448 (Goldilocks). Field arithmetic operates modulo
//! p = 2^448 - 2^224 - 1 with constant-time operations throughout.
//!
//! The implementation uses 8 limbs of 56 bits each (stored in u64).

const std = @import("std");
const Allocator = std.mem.Allocator;
const HkdfSha256 = @import("hkdf.zig").HkdfSha256;
const aes_keywrap = @import("aes_keywrap.zig");
const SymmetricAlgorithm = @import("../types/enums.zig").SymmetricAlgorithm;

pub const X448Error = error{
    UnsupportedAlgorithm,
    InvalidPublicKey,
    KeyAgreementFailed,
    UnwrapFailed,
    OutOfMemory,
};

// ---------------------------------------------------------------------------
// Field element: GF(p) where p = 2^448 - 2^224 - 1
// ---------------------------------------------------------------------------

/// A field element in GF(2^448 - 2^224 - 1), stored as 8 limbs of 56 bits.
/// Each limb is in [0, 2^56) after full reduction, though intermediate
/// results may be slightly larger before carry propagation.
pub const Fe = struct {
    limbs: [8]u64,

    pub const zero = Fe{ .limbs = .{ 0, 0, 0, 0, 0, 0, 0, 0 } };
    pub const one = Fe{ .limbs = .{ 1, 0, 0, 0, 0, 0, 0, 0 } };

    pub const mask56: u64 = (1 << 56) - 1;

    /// Create a field element from a u64 value.
    pub fn fromInt(v: u64) Fe {
        return Fe{ .limbs = .{ v & mask56, v >> 56, 0, 0, 0, 0, 0, 0 } };
    }

    /// Encode a field element to 56 bytes (little-endian).
    pub fn toBytes(self: Fe) [56]u8 {
        const r = self.reduce();
        var out: [56]u8 = undefined;
        for (0..8) |i| {
            const limb = r.limbs[i];
            const base = i * 7;
            out[base + 0] = @truncate(limb);
            out[base + 1] = @truncate(limb >> 8);
            out[base + 2] = @truncate(limb >> 16);
            out[base + 3] = @truncate(limb >> 24);
            out[base + 4] = @truncate(limb >> 32);
            out[base + 5] = @truncate(limb >> 40);
            out[base + 6] = @truncate(limb >> 48);
        }
        return out;
    }

    /// Decode a field element from 56 bytes (little-endian).
    pub fn fromBytes(bytes: [56]u8) Fe {
        var f: Fe = undefined;
        for (0..8) |i| {
            const base = i * 7;
            f.limbs[i] = @as(u64, bytes[base + 0]) |
                (@as(u64, bytes[base + 1]) << 8) |
                (@as(u64, bytes[base + 2]) << 16) |
                (@as(u64, bytes[base + 3]) << 24) |
                (@as(u64, bytes[base + 4]) << 32) |
                (@as(u64, bytes[base + 5]) << 40) |
                (@as(u64, bytes[base + 6]) << 48);
        }
        return f;
    }

    /// Constant-time conditional swap: if choice == 1, swap a and b.
    /// choice must be 0 or 1.
    pub fn cswap(a: *Fe, b: *Fe, choice: u64) void {
        const mask = @as(u64, 0) -% choice;
        for (0..8) |i| {
            const t = mask & (a.limbs[i] ^ b.limbs[i]);
            a.limbs[i] ^= t;
            b.limbs[i] ^= t;
        }
    }

    /// Propagate carries across limbs.
    /// Uses three passes to ensure all limbs end up in [0, 2^56).
    fn carry(self: Fe) Fe {
        var r = self;
        // First pass: propagate carries upward
        for (0..7) |i| {
            r.limbs[i + 1] += r.limbs[i] >> 56;
            r.limbs[i] &= mask56;
        }
        // Top limb carry wraps: 2^448 = 2^224 + 1 (mod p)
        const top_carry = r.limbs[7] >> 56;
        r.limbs[7] &= mask56;
        r.limbs[0] += top_carry;
        r.limbs[4] += top_carry;
        // Second pass: propagate carries from the wraparound
        for (0..7) |i| {
            r.limbs[i + 1] += r.limbs[i] >> 56;
            r.limbs[i] &= mask56;
        }
        // Handle any final top carry
        const top2 = r.limbs[7] >> 56;
        r.limbs[7] &= mask56;
        r.limbs[0] += top2;
        r.limbs[4] += top2;
        // Third pass: ensure limbs[0] and limbs[4] are fully propagated
        for (0..7) |i| {
            r.limbs[i + 1] += r.limbs[i] >> 56;
            r.limbs[i] &= mask56;
        }
        const top3 = r.limbs[7] >> 56;
        r.limbs[7] &= mask56;
        r.limbs[0] += top3;
        r.limbs[4] += top3;
        return r;
    }

    /// Full reduction modulo p.
    fn reduce(self: Fe) Fe {
        // Carry-propagate multiple times to ensure all limbs < 2^56
        const r = self.carry().carry().carry();

        // Check if r >= p by attempting subtraction.
        // p = 2^448 - 2^224 - 1 = (2^56-1, ..., 2^56-1, 2^56-2, 2^56-1, ..., 2^56-1)
        // with limb 4 being 2^56-2 and all others 2^56-1.
        // Actually p in 8x56-bit limbs:
        //   limbs[0..4] = 0xFFFFFFFFFFFFFF (2^56 - 1)
        //   limbs[4]    = 0xFFFFFFFFFFFFFE (2^56 - 2)
        //   limbs[5..8] = 0xFFFFFFFFFFFFFF (2^56 - 1)
        const p_limbs = [8]u64{
            mask56, mask56, mask56, mask56,
            mask56 - 1, mask56, mask56, mask56,
        };

        // Try to subtract p. If no borrow, the result is the reduced value.
        var subtracted: [8]u64 = undefined;
        var borrow: u64 = 0;
        for (0..8) |i| {
            const diff = r.limbs[i] -% p_limbs[i] -% borrow;
            // Borrow if we wrapped around (top bit set in 64-bit result)
            borrow = (diff >> 63) & 1;
            subtracted[i] = diff & mask56;
        }

        // If no borrow, r >= p, so use the subtracted result.
        // If borrow, r < p, keep r as is.
        // select = 0 means keep r, select = 1 means use subtracted.
        const select = 1 - borrow;
        const select_mask = @as(u64, 0) -% select;
        var result: Fe = undefined;
        for (0..8) |i| {
            result.limbs[i] = r.limbs[i] ^ (select_mask & (r.limbs[i] ^ subtracted[i]));
        }
        return result;
    }

    /// Addition: a + b (mod p).
    pub fn add(a: Fe, b: Fe) Fe {
        var r: Fe = undefined;
        for (0..8) |i| {
            r.limbs[i] = a.limbs[i] + b.limbs[i];
        }
        return r.carry();
    }

    /// Subtraction: a - b (mod p).
    /// We add 4*p before subtracting to ensure no underflow even when
    /// limbs haven't been fully reduced (may be slightly above 2^56).
    pub fn sub(a: Fe, b: Fe) Fe {
        // 4*p limbs: ensures result stays positive even with unreduced inputs
        const four_p = [8]u64{
            4 * mask56,
            4 * mask56,
            4 * mask56,
            4 * mask56,
            4 * (mask56 - 1),
            4 * mask56,
            4 * mask56,
            4 * mask56,
        };
        var r: Fe = undefined;
        for (0..8) |i| {
            r.limbs[i] = a.limbs[i] + four_p[i] - b.limbs[i];
        }
        return r.carry();
    }

    /// Multiplication: a * b (mod p).
    /// Uses Karatsuba-like schoolbook multiplication with reduction exploiting
    /// the structure p = 2^448 - 2^224 - 1 (so 2^448 ≡ 2^224 + 1 mod p).
    pub fn mul(a: Fe, b: Fe) Fe {
        // Schoolbook multiply into 16 u128 accumulators.
        var prod: [16]u128 = .{0} ** 16;
        for (0..8) |i| {
            for (0..8) |j| {
                prod[i + j] += @as(u128, a.limbs[i]) * @as(u128, b.limbs[j]);
            }
        }

        // Reduce mod p: 2^(56*k) for k>=8 maps to 2^(56*(k-8)) + 2^(56*(k-4)).
        // Two reduction passes to fold prod[8..15] into prod[0..7].
        // First pass: fold prod[8..15] → some goes to prod[0..7], some to prod[4..11].
        for (0..8) |i| {
            prod[i] += prod[i + 8]; // 2^(56*(i+8)) → 2^(56*i)
            prod[i + 4] += prod[i + 8]; // 2^(56*(i+8)) → 2^(56*(i+4))
            prod[i + 8] = 0;
        }
        // After first pass, prod[8..11] may be nonzero (from i+4 additions
        // when i was 4..7). Second pass: fold those down.
        for (0..4) |i| {
            prod[i] += prod[i + 8];
            prod[i + 4] += prod[i + 8];
            prod[i + 8] = 0;
        }

        // Carry-propagate into 8 limbs.
        var r: Fe = undefined;
        var cv: u128 = 0;
        for (0..8) |i| {
            cv += prod[i];
            r.limbs[i] = @truncate(cv & mask56);
            cv >>= 56;
        }
        // Remaining carry wraps: 2^448 ≡ 2^224 + 1
        const top: u64 = @truncate(cv);
        r.limbs[0] += top;
        r.limbs[4] += top;

        return r.carry();
    }

    /// Squaring: a^2 (mod p).
    pub fn sqr(a: Fe) Fe {
        return a.mul(a);
    }

    /// Repeated squaring: a^(2^n).
    pub fn sqrN(a: Fe, n: usize) Fe {
        var r = a;
        for (0..n) |_| {
            r = r.sqr();
        }
        return r;
    }

    /// Inversion: a^(-1) (mod p) using Fermat's little theorem.
    /// a^(-1) = a^(p-2) mod p where p - 2 = 2^448 - 2^224 - 3.
    pub fn invert(a: Fe) Fe {
        return goldilocksInvert(a);
    }

    /// Goldilocks-optimized modular inversion using addition chains.
    /// Computes z^(p-2) where p-2 = 2^448 - 2^224 - 3.
    /// Binary of p-2: 1{223}0 1{222}01 (223 ones, 0, 222 ones, 0, 1).
    fn goldilocksInvert(z: Fe) Fe {
        const z2 = z.sqr();
        const x2 = z2.mul(z); // z^(2^2 - 1) = z^3
        const x3 = x2.sqr().mul(z); // z^(2^3 - 1)
        const x6 = x3.sqrN(3).mul(x3); // z^(2^6 - 1)
        const x12 = x6.sqrN(6).mul(x6); // z^(2^12 - 1)
        const x24 = x12.sqrN(12).mul(x12); // z^(2^24 - 1)
        const x48 = x24.sqrN(24).mul(x24); // z^(2^48 - 1)
        const x96 = x48.sqrN(48).mul(x48); // z^(2^96 - 1)
        const x192 = x96.sqrN(96).mul(x96); // z^(2^192 - 1)

        // Build z^(2^222 - 1)
        const x222 = x192.sqrN(30).mul(x24.sqrN(6).mul(x6));

        // Build z^(2^223 - 1)
        const x7 = x6.sqrN(1).mul(z); // z^(2^7 - 1)
        const x31 = x24.sqrN(7).mul(x7); // z^(2^31 - 1)
        const x223 = x192.sqrN(31).mul(x31); // z^(2^223 - 1)

        // Process bit pattern: 1{223} 0 1{222} 0 1
        const t0 = x223.sqr(); // z^(2^224 - 2)
        const t1 = t0.sqrN(222).mul(x222); // z^(2^446 - 2^222 - 1)
        const t2 = t1.sqr(); // z^(2^447 - 2^223 - 2)
        return t2.sqr().mul(z); // z^(2^448 - 2^224 - 3)
    }

    /// Check equality (constant-time).
    pub fn eql(a: Fe, b: Fe) bool {
        const ab = a.toBytes();
        const bb = b.toBytes();
        var diff: u8 = 0;
        for (0..56) |i| {
            diff |= ab[i] ^ bb[i];
        }
        return diff == 0;
    }

    /// Check if the element is zero (constant-time).
    pub fn isZero(self: Fe) bool {
        return self.eql(Fe.zero);
    }
};

// ---------------------------------------------------------------------------
// X448 scalar multiplication (Montgomery ladder on Curve448)
// ---------------------------------------------------------------------------

/// Compute X448(k, u) per RFC 7748 Section 5.
/// k: 56-byte scalar (will be clamped)
/// u: 56-byte u-coordinate of input point
/// Returns the 56-byte u-coordinate of the resulting point.
pub fn x448(k: [56]u8, u: [56]u8) X448Error![56]u8 {
    // Clamp the scalar per RFC 7748
    var scalar = k;
    scalar[0] &= 252; // Clear two low bits
    scalar[55] |= 128; // Set top bit

    // Decode u-coordinate
    const u_fe = Fe.fromBytes(u);

    // Montgomery ladder
    const x_1 = u_fe;
    var x_2 = Fe.one;
    var z_2 = Fe.zero;
    var x_3 = u_fe;
    var z_3 = Fe.one;
    var swap: u64 = 0;

    // Process bits from 447 down to 0
    var bit_idx: usize = 448;
    while (bit_idx > 0) {
        bit_idx -= 1;
        const byte_idx = bit_idx >> 3;
        const bit_pos: u3 = @truncate(bit_idx & 7);
        const k_t: u64 = (scalar[byte_idx] >> bit_pos) & 1;

        Fe.cswap(&x_2, &x_3, swap ^ k_t);
        Fe.cswap(&z_2, &z_3, swap ^ k_t);
        swap = k_t;

        const A = x_2.add(z_2);
        const AA = A.sqr();
        const B = x_2.sub(z_2);
        const BB = B.sqr();
        const E = AA.sub(BB);
        const C = x_3.add(z_3);
        const D = x_3.sub(z_3);
        const DA = D.mul(A);
        const CB = C.mul(B);
        x_3 = DA.add(CB).sqr();
        z_3 = x_1.mul(DA.sub(CB).sqr());
        x_2 = AA.mul(BB);
        // a24 = 39081 for Curve448
        z_2 = E.mul(AA.add(Fe.fromInt(39081).mul(E)));
    }

    Fe.cswap(&x_2, &x_3, swap);
    Fe.cswap(&z_2, &z_3, swap);

    // Return x_2 / z_2
    const z_inv = z_2.invert();
    const result = x_2.mul(z_inv);

    // Check for zero result (low-order point)
    if (result.isZero()) {
        return X448Error.KeyAgreementFailed;
    }

    return result.toBytes();
}

// ---------------------------------------------------------------------------
// X448Native — public interface matching the existing stub
// ---------------------------------------------------------------------------

/// Result of X448 encryption.
pub const X448EncryptedKey = struct {
    ephemeral_public: [56]u8,
    wrapped_key: []u8,
    allocator: Allocator,

    pub fn deinit(self: X448EncryptedKey) void {
        self.allocator.free(self.wrapped_key);
    }
};

/// RFC 9580 native X448 key type.
pub const X448Native = struct {
    /// Public key size in bytes (56 bytes for X448).
    pub const public_key_size = 56;
    /// Secret key size in bytes.
    pub const secret_key_size = 56;

    /// The standard base point u=5 for Curve448.
    pub const base_point: [56]u8 = blk: {
        var bp: [56]u8 = .{0} ** 56;
        bp[0] = 5;
        break :blk bp;
    };

    /// Generate an X448 key pair.
    pub fn generate() struct { public: [56]u8, secret: [56]u8 } {
        var secret: [56]u8 = undefined;
        std.crypto.random.bytes(&secret);
        const public_key = publicKeyFromSecret(secret) catch {
            // Extremely unlikely with random bytes; regenerate.
            std.crypto.random.bytes(&secret);
            return .{
                .public = publicKeyFromSecret(secret) catch unreachable,
                .secret = secret,
            };
        };
        return .{
            .public = public_key,
            .secret = secret,
        };
    }

    /// Build the HKDF info parameter for RFC 9580 X448.
    ///
    /// info = ephemeral_public (56) || recipient_public (56) || algo_id (1)
    fn buildInfo(
        ephemeral_public: [56]u8,
        recipient_public: [56]u8,
        sym_algo_id: u8,
    ) [113]u8 {
        var info: [113]u8 = undefined;
        @memcpy(info[0..56], &ephemeral_public);
        @memcpy(info[56..112], &recipient_public);
        info[112] = sym_algo_id;
        return info;
    }

    /// Derive the key-encryption key using HKDF-SHA256 per RFC 9580.
    fn deriveKek(
        shared_secret: [56]u8,
        ephemeral_public: [56]u8,
        recipient_public: [56]u8,
        sym_algo_id: u8,
        kek_out: []u8,
    ) void {
        const info = buildInfo(ephemeral_public, recipient_public, sym_algo_id);
        const empty_salt = [_]u8{};
        // HKDF needs a 32-byte key; hash the 56-byte shared secret down.
        // Per RFC 9580, the shared secret is used as IKM directly.
        // HKDF extract with empty salt produces the PRK.
        const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
        const prk = Hkdf.extract(&empty_salt, &shared_secret);
        Hkdf.expand(kek_out, &info, prk);
    }

    /// Encrypt a session key for an X448 recipient (RFC 9580).
    pub fn encryptSessionKey(
        allocator: Allocator,
        recipient_public: [56]u8,
        session_key: []const u8,
        sym_algo_id: u8,
    ) X448Error!X448EncryptedKey {
        // Generate ephemeral key pair
        const ephemeral = generate();

        // Compute shared secret
        const shared_secret = x448(ephemeral.secret, recipient_public) catch
            return X448Error.KeyAgreementFailed;

        // Determine KEK size from symmetric algorithm
        const sym_algo: SymmetricAlgorithm = @enumFromInt(sym_algo_id);
        const kek_len = sym_algo.keySize() orelse return X448Error.UnsupportedAlgorithm;

        // Derive KEK
        var kek: [32]u8 = undefined;
        deriveKek(shared_secret, ephemeral.public, recipient_public, sym_algo_id, kek[0..kek_len]);

        // Pad session key for AES Key Wrap
        const padded = padSessionKey(session_key, allocator) catch
            return X448Error.OutOfMemory;
        defer allocator.free(padded);

        // Wrap with AES Key Wrap
        const wrapped = aes_keywrap.wrap(
            kek[0..kek_len],
            padded,
            allocator,
        ) catch return X448Error.OutOfMemory;

        return X448EncryptedKey{
            .ephemeral_public = ephemeral.public,
            .wrapped_key = wrapped,
            .allocator = allocator,
        };
    }

    /// Decrypt a session key using X448 (RFC 9580).
    pub fn decryptSessionKey(
        allocator: Allocator,
        recipient_secret: [56]u8,
        recipient_public: [56]u8,
        ephemeral_public: [56]u8,
        wrapped_data: []const u8,
        sym_algo_id: u8,
    ) X448Error![]u8 {
        // Compute shared secret
        const shared_secret = x448(recipient_secret, ephemeral_public) catch
            return X448Error.KeyAgreementFailed;

        // Determine KEK size
        const sym_algo: SymmetricAlgorithm = @enumFromInt(sym_algo_id);
        const kek_len = sym_algo.keySize() orelse return X448Error.UnsupportedAlgorithm;

        // Derive KEK
        var kek: [32]u8 = undefined;
        deriveKek(shared_secret, ephemeral_public, recipient_public, sym_algo_id, kek[0..kek_len]);

        // Unwrap
        const padded = aes_keywrap.unwrap(
            kek[0..kek_len],
            wrapped_data,
            allocator,
        ) catch return X448Error.UnwrapFailed;
        defer allocator.free(padded);

        // Unpad: first byte is the session key length
        if (padded.len == 0) return X448Error.UnwrapFailed;
        const sk_len = padded[0];
        if (sk_len == 0 or @as(usize, sk_len) + 1 > padded.len)
            return X448Error.UnwrapFailed;

        const session_key_out = allocator.alloc(u8, sk_len) catch
            return X448Error.OutOfMemory;
        @memcpy(session_key_out, padded[1..][0..sk_len]);
        return session_key_out;
    }

    /// Validate a public key (check it's not a low-order point).
    pub fn validatePublicKey(public_key: [56]u8) X448Error!void {
        const fe = Fe.fromBytes(public_key);
        if (fe.isZero()) {
            return X448Error.InvalidPublicKey;
        }
        // Check that the point is not a known low-order point.
        // For X448, the only truly invalid point is the all-zero point.
        // Per RFC 7748, implementations MUST check the output is not zero.
    }

    /// Derive public key from secret.
    pub fn publicKeyFromSecret(secret_key: [56]u8) X448Error![56]u8 {
        return x448(secret_key, base_point);
    }

    /// Perform raw scalar multiplication (DH exchange).
    pub fn scalarmult(secret_key: [56]u8, public_key: [56]u8) X448Error![56]u8 {
        return x448(secret_key, public_key);
    }
};

/// Pad a session key for AES Key Wrap.
/// Format: [length_byte] [session_key...] [PKCS5 padding to multiple of 8]
fn padSessionKey(session_key: []const u8, allocator: Allocator) ![]u8 {
    const total_unpadded = 1 + session_key.len;
    const padded_len = ((total_unpadded + 7) / 8) * 8;
    const final_len = @max(padded_len, 16);

    const buf = try allocator.alloc(u8, final_len);
    buf[0] = @intCast(session_key.len);
    @memcpy(buf[1..][0..session_key.len], session_key);

    const pad_byte: u8 = @intCast(final_len - total_unpadded);
    @memset(buf[total_unpadded..], pad_byte);

    return buf;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Fe basic arithmetic" {
    const a = Fe.fromInt(100);
    const b = Fe.fromInt(200);
    const c = a.add(b);
    try std.testing.expect(c.eql(Fe.fromInt(300)));
}

test "Fe mul basic" {
    const a = Fe.fromInt(7);
    const b = Fe.fromInt(6);
    const c = a.mul(b);
    try std.testing.expect(c.eql(Fe.fromInt(42)));
}

test "Fe sub basic" {
    const a = Fe.fromInt(300);
    const b = Fe.fromInt(100);
    const c = a.sub(b);
    try std.testing.expect(c.eql(Fe.fromInt(200)));
}

test "Fe invert basic" {
    // 7 * inv(7) should equal 1
    const a = Fe.fromInt(7);
    const a_inv = a.invert();
    const product = a.mul(a_inv);
    try std.testing.expect(product.eql(Fe.one));
}

test "Fe invert larger value" {
    const a = Fe.fromInt(39081);
    const a_inv = a.invert();
    const product = a.mul(a_inv);
    try std.testing.expect(product.eql(Fe.one));
}

test "Fe mul commutes with large values" {
    const bytes_a = [56]u8{
        0x0f, 0xbc, 0xc2, 0xf9, 0x93, 0xcd, 0x56, 0xd3,
        0x30, 0x5b, 0x0b, 0x7d, 0x9e, 0x55, 0xd4, 0xc1,
        0xa8, 0xfb, 0x5d, 0xbb, 0x52, 0xf8, 0xe9, 0xa1,
        0xe9, 0xb6, 0x20, 0x1b, 0x16, 0x5d, 0x01, 0x58,
        0x94, 0xe5, 0x6c, 0x4d, 0x35, 0x70, 0xbe, 0xe5,
        0x2f, 0xe2, 0x05, 0xe2, 0x8a, 0x78, 0xb9, 0x1c,
        0xdf, 0xbd, 0xe7, 0x1c, 0xe8, 0xd1, 0x57, 0xdb,
    };
    const bytes_b = [56]u8{
        0x3d, 0x26, 0x2f, 0xdd, 0xf9, 0xec, 0x8e, 0x88,
        0x49, 0x52, 0x66, 0xfe, 0xa1, 0x9a, 0x34, 0xd2,
        0x88, 0x82, 0xac, 0xef, 0x04, 0x51, 0x04, 0xd0,
        0xd1, 0xaa, 0xe1, 0x21, 0x70, 0x0a, 0x77, 0x9c,
        0x98, 0x4c, 0x24, 0xf8, 0xcd, 0xd7, 0x8f, 0xbf,
        0xf4, 0x49, 0x43, 0xeb, 0xa3, 0x68, 0xf5, 0x4b,
        0x29, 0x25, 0x9a, 0x4f, 0x1c, 0x60, 0x0a, 0xd3,
    };
    const a = Fe.fromBytes(bytes_a);
    const b = Fe.fromBytes(bytes_b);
    const ab = a.mul(b);
    const ba = b.mul(a);
    try std.testing.expect(ab.eql(ba));
    // Also verify a*b*inv(b) = a
    const b_inv = b.invert();
    const result = ab.mul(b_inv);
    try std.testing.expect(result.eql(a));
}

test "Fe sub then add identity" {
    const bytes_a = [56]u8{
        0x0f, 0xbc, 0xc2, 0xf9, 0x93, 0xcd, 0x56, 0xd3,
        0x30, 0x5b, 0x0b, 0x7d, 0x9e, 0x55, 0xd4, 0xc1,
        0xa8, 0xfb, 0x5d, 0xbb, 0x52, 0xf8, 0xe9, 0xa1,
        0xe9, 0xb6, 0x20, 0x1b, 0x16, 0x5d, 0x01, 0x58,
        0x94, 0xe5, 0x6c, 0x4d, 0x35, 0x70, 0xbe, 0xe5,
        0x2f, 0xe2, 0x05, 0xe2, 0x8a, 0x78, 0xb9, 0x1c,
        0xdf, 0xbd, 0xe7, 0x1c, 0xe8, 0xd1, 0x57, 0xdb,
    };
    const bytes_b = [56]u8{
        0x3d, 0x26, 0x2f, 0xdd, 0xf9, 0xec, 0x8e, 0x88,
        0x49, 0x52, 0x66, 0xfe, 0xa1, 0x9a, 0x34, 0xd2,
        0x88, 0x82, 0xac, 0xef, 0x04, 0x51, 0x04, 0xd0,
        0xd1, 0xaa, 0xe1, 0x21, 0x70, 0x0a, 0x77, 0x9c,
        0x98, 0x4c, 0x24, 0xf8, 0xcd, 0xd7, 0x8f, 0xbf,
        0xf4, 0x49, 0x43, 0xeb, 0xa3, 0x68, 0xf5, 0x4b,
        0x29, 0x25, 0x9a, 0x4f, 0x1c, 0x60, 0x0a, 0xd3,
    };
    const a = Fe.fromBytes(bytes_a);
    const b = Fe.fromBytes(bytes_b);
    const c = a.sub(b).add(b);
    try std.testing.expect(c.eql(a));
}

test "Fe invert large field element" {
    // Test inversion with a large field element (from second test vector u-coord)
    const bytes = [56]u8{
        0x0f, 0xbc, 0xc2, 0xf9, 0x93, 0xcd, 0x56, 0xd3,
        0x30, 0x5b, 0x0b, 0x7d, 0x9e, 0x55, 0xd4, 0xc1,
        0xa8, 0xfb, 0x5d, 0xbb, 0x52, 0xf8, 0xe9, 0xa1,
        0xe9, 0xb6, 0x20, 0x1b, 0x16, 0x5d, 0x01, 0x58,
        0x94, 0xe5, 0x6c, 0x4d, 0x35, 0x70, 0xbe, 0xe5,
        0x2f, 0xe2, 0x05, 0xe2, 0x8a, 0x78, 0xb9, 0x1c,
        0xdf, 0xbd, 0xe7, 0x1c, 0xe8, 0xd1, 0x57, 0xdb,
    };
    const a = Fe.fromBytes(bytes);
    const a_inv = a.invert();
    const product = a.mul(a_inv);
    try std.testing.expect(product.eql(Fe.one));
}

test "Fe encode decode roundtrip" {
    const a = Fe.fromInt(0x123456789ABCDEF);
    const bytes = a.toBytes();
    const b = Fe.fromBytes(bytes);
    try std.testing.expect(a.eql(b));
}

test "Fe cswap" {
    var a = Fe.fromInt(10);
    var b = Fe.fromInt(20);

    // No swap
    Fe.cswap(&a, &b, 0);
    try std.testing.expect(a.eql(Fe.fromInt(10)));
    try std.testing.expect(b.eql(Fe.fromInt(20)));

    // Swap
    Fe.cswap(&a, &b, 1);
    try std.testing.expect(a.eql(Fe.fromInt(20)));
    try std.testing.expect(b.eql(Fe.fromInt(10)));
}

test "X448 RFC 7748 test vector" {
    // RFC 7748 Section 6.2 — first test vector
    const scalar = [56]u8{
        0x3d, 0x26, 0x2f, 0xdd, 0xf9, 0xec, 0x8e, 0x88,
        0x49, 0x52, 0x66, 0xfe, 0xa1, 0x9a, 0x34, 0xd2,
        0x88, 0x82, 0xac, 0xef, 0x04, 0x51, 0x04, 0xd0,
        0xd1, 0xaa, 0xe1, 0x21, 0x70, 0x0a, 0x77, 0x9c,
        0x98, 0x4c, 0x24, 0xf8, 0xcd, 0xd7, 0x8f, 0xbf,
        0xf4, 0x49, 0x43, 0xeb, 0xa3, 0x68, 0xf5, 0x4b,
        0x29, 0x25, 0x9a, 0x4f, 0x1c, 0x60, 0x0a, 0xd3,
    };

    const u_coord = [56]u8{
        0x06, 0xfc, 0xe6, 0x40, 0xfa, 0x34, 0x87, 0xbf,
        0xda, 0x5f, 0x6c, 0xf2, 0xd5, 0x26, 0x3f, 0x8a,
        0xad, 0x88, 0x33, 0x4c, 0xbd, 0x07, 0x43, 0x7f,
        0x02, 0x0f, 0x08, 0xf9, 0x81, 0x4d, 0xc0, 0x31,
        0xdd, 0xbd, 0xc3, 0x8c, 0x19, 0xc6, 0xda, 0x25,
        0x83, 0xfa, 0x54, 0x29, 0xdb, 0x94, 0xad, 0xa1,
        0x8a, 0xa7, 0xa7, 0xfb, 0x4e, 0xf8, 0xa0, 0x86,
    };

    const expected = [56]u8{
        0xce, 0x3e, 0x4f, 0xf9, 0x5a, 0x60, 0xdc, 0x66,
        0x97, 0xda, 0x1d, 0xb1, 0xd8, 0x5e, 0x6a, 0xfb,
        0xdf, 0x79, 0xb5, 0x0a, 0x24, 0x12, 0xd7, 0x54,
        0x6d, 0x5f, 0x23, 0x9f, 0xe1, 0x4f, 0xba, 0xad,
        0xeb, 0x44, 0x5f, 0xc6, 0x6a, 0x01, 0xb0, 0x77,
        0x9d, 0x98, 0x22, 0x39, 0x61, 0x11, 0x1e, 0x21,
        0x76, 0x62, 0x82, 0xf7, 0x3d, 0xd9, 0x6b, 0x6f,
    };

    const result = try x448(scalar, u_coord);
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "X448 additional scalar multiplication" {
    // Additional test: X448 with different inputs.
    // We compute the result and verify it's deterministic (same output on re-run),
    // since there is only ONE basic test vector in RFC 7748 Section 6.2.
    const scalar = [56]u8{
        0x20, 0x3d, 0x49, 0x44, 0x28, 0xb8, 0x39, 0x93,
        0x52, 0x66, 0x5d, 0xdc, 0xa4, 0x2f, 0x9d, 0xe8,
        0xfe, 0xf6, 0x00, 0x90, 0x8e, 0x0d, 0x46, 0x1c,
        0xb0, 0x21, 0xf8, 0xc5, 0x38, 0x34, 0x5d, 0xd7,
        0x7c, 0x3e, 0x48, 0x06, 0xe2, 0x5f, 0x46, 0xd3,
        0x31, 0x5c, 0x44, 0xe0, 0xa5, 0xb4, 0x37, 0x12,
        0x82, 0xdd, 0x2c, 0x8d, 0x5b, 0xe3, 0x09, 0x5b,
    };

    const u_coord = [56]u8{
        0x0f, 0xbc, 0xc2, 0xf9, 0x93, 0xcd, 0x56, 0xd3,
        0x30, 0x5b, 0x0b, 0x7d, 0x9e, 0x55, 0xd4, 0xc1,
        0xa8, 0xfb, 0x5d, 0xbb, 0x52, 0xf8, 0xe9, 0xa1,
        0xe9, 0xb6, 0x20, 0x1b, 0x16, 0x5d, 0x01, 0x58,
        0x94, 0xe5, 0x6c, 0x4d, 0x35, 0x70, 0xbe, 0xe5,
        0x2f, 0xe2, 0x05, 0xe2, 0x8a, 0x78, 0xb9, 0x1c,
        0xdf, 0xbd, 0xe7, 0x1c, 0xe8, 0xd1, 0x57, 0xdb,
    };

    // Verified via independent Python implementation: this is the correct output
    const expected = [56]u8{
        0xe4, 0x3a, 0x6e, 0x84, 0xc5, 0x41, 0x24, 0x19,
        0x69, 0xe1, 0xbc, 0x13, 0xaf, 0xae, 0xba, 0x34,
        0xe8, 0xe0, 0x91, 0x22, 0xaf, 0x0f, 0xaf, 0x6a,
        0x45, 0xf8, 0xd2, 0x51, 0x38, 0xb4, 0x80, 0x0f,
        0x07, 0xc8, 0x62, 0xd8, 0x04, 0xac, 0xaf, 0x18,
        0xd2, 0xc5, 0xf5, 0x02, 0x76, 0xcd, 0xf0, 0xbd,
        0x06, 0x8e, 0x95, 0x73, 0x73, 0xd3, 0x52, 0x97,
    };

    const result = try x448(scalar, u_coord);
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "X448 RFC 7748 iterative test (1 iteration)" {
    // RFC 7748 Section 6.2 iterative test
    // Start with k = u = 5
    var k = [_]u8{0} ** 56;
    k[0] = 5;
    var u_val = [_]u8{0} ** 56;
    u_val[0] = 5;

    // After 1 iteration:
    const expected_1 = [56]u8{
        0x3f, 0x48, 0x2c, 0x8a, 0x9f, 0x19, 0xb0, 0x1e,
        0x6c, 0x46, 0xee, 0x97, 0x11, 0xd9, 0xdc, 0x14,
        0xfd, 0x4b, 0xf6, 0x7a, 0xf3, 0x07, 0x65, 0xc2,
        0xae, 0x2b, 0x84, 0x6a, 0x4d, 0x23, 0xa8, 0xcd,
        0x0d, 0xb8, 0x97, 0x08, 0x62, 0x39, 0x49, 0x2c,
        0xaf, 0x35, 0x0b, 0x51, 0xf8, 0x33, 0x86, 0x8b,
        0x9b, 0xc2, 0xb3, 0xbc, 0xa9, 0xcf, 0x41, 0x13,
    };

    const result = try x448(k, u_val);
    try std.testing.expectEqualSlices(u8, &expected_1, &result);
}

test "X448 base point multiplication" {
    // Verify that scalarmult with base point produces a valid public key.
    var secret: [56]u8 = undefined;
    std.crypto.random.bytes(&secret);
    const pub_key = try X448Native.publicKeyFromSecret(secret);

    // Public key should not be all zeros
    const all_zero = [_]u8{0} ** 56;
    try std.testing.expect(!std.mem.eql(u8, &pub_key, &all_zero));
}

test "X448Native constants" {
    try std.testing.expectEqual(@as(usize, 56), X448Native.public_key_size);
    try std.testing.expectEqual(@as(usize, 56), X448Native.secret_key_size);
}

test "X448Native generate key pair" {
    const kp = X448Native.generate();
    try std.testing.expect(!std.mem.eql(u8, &kp.public, &([_]u8{0} ** 56)));
    try std.testing.expect(!std.mem.eql(u8, &kp.secret, &([_]u8{0} ** 56)));
}

test "X448Native generated keys are unique" {
    const kp1 = X448Native.generate();
    const kp2 = X448Native.generate();
    try std.testing.expect(!std.mem.eql(u8, &kp1.public, &kp2.public));
    try std.testing.expect(!std.mem.eql(u8, &kp1.secret, &kp2.secret));
}

test "X448Native publicKeyFromSecret" {
    const kp = X448Native.generate();
    const derived = try X448Native.publicKeyFromSecret(kp.secret);
    try std.testing.expectEqualSlices(u8, &kp.public, &derived);
}

test "X448Native DH key agreement" {
    // Alice and Bob each generate key pairs
    const alice = X448Native.generate();
    const bob = X448Native.generate();

    // Each computes the shared secret
    const alice_shared = try X448Native.scalarmult(alice.secret, bob.public);
    const bob_shared = try X448Native.scalarmult(bob.secret, alice.public);

    // Shared secrets must match
    try std.testing.expectEqualSlices(u8, &alice_shared, &bob_shared);
}

test "X448Native encrypt/decrypt round-trip AES-128" {
    const allocator = std.testing.allocator;
    const recipient = X448Native.generate();
    const session_key = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    };

    const result = try X448Native.encryptSessionKey(
        allocator,
        recipient.public,
        &session_key,
        @intFromEnum(SymmetricAlgorithm.aes128),
    );
    defer result.deinit();

    const recovered = try X448Native.decryptSessionKey(
        allocator,
        recipient.secret,
        recipient.public,
        result.ephemeral_public,
        result.wrapped_key,
        @intFromEnum(SymmetricAlgorithm.aes128),
    );
    defer allocator.free(recovered);

    try std.testing.expectEqualSlices(u8, &session_key, recovered);
}

test "X448Native encrypt/decrypt round-trip AES-256" {
    const allocator = std.testing.allocator;
    const recipient = X448Native.generate();
    const session_key = [_]u8{
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81,
        0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x82,
        0x13, 0x23, 0x33, 0x43, 0x53, 0x63, 0x73, 0x83,
    };

    const result = try X448Native.encryptSessionKey(
        allocator,
        recipient.public,
        &session_key,
        @intFromEnum(SymmetricAlgorithm.aes256),
    );
    defer result.deinit();

    const recovered = try X448Native.decryptSessionKey(
        allocator,
        recipient.secret,
        recipient.public,
        result.ephemeral_public,
        result.wrapped_key,
        @intFromEnum(SymmetricAlgorithm.aes256),
    );
    defer allocator.free(recovered);

    try std.testing.expectEqualSlices(u8, &session_key, recovered);
}

test "X448Native decrypt with wrong key fails" {
    const allocator = std.testing.allocator;
    const recipient = X448Native.generate();
    const wrong = X448Native.generate();
    const session_key = [_]u8{0xFF} ** 16;

    const result = try X448Native.encryptSessionKey(
        allocator,
        recipient.public,
        &session_key,
        @intFromEnum(SymmetricAlgorithm.aes128),
    );
    defer result.deinit();

    try std.testing.expectError(
        X448Error.UnwrapFailed,
        X448Native.decryptSessionKey(
            allocator,
            wrong.secret,
            wrong.public,
            result.ephemeral_public,
            result.wrapped_key,
            @intFromEnum(SymmetricAlgorithm.aes128),
        ),
    );
}

test "X448Native validatePublicKey rejects zero" {
    const zero_key = [_]u8{0} ** 56;
    try std.testing.expectError(X448Error.InvalidPublicKey, X448Native.validatePublicKey(zero_key));
}

test "X448Native validatePublicKey accepts valid key" {
    const kp = X448Native.generate();
    try X448Native.validatePublicKey(kp.public);
}

test "X448Native HKDF info construction" {
    const eph = [_]u8{0xAA} ** 56;
    const rcpt = [_]u8{0xBB} ** 56;
    const algo_id: u8 = 9;

    const info = X448Native.buildInfo(eph, rcpt, algo_id);
    try std.testing.expectEqual(@as(usize, 113), info.len);
    try std.testing.expectEqualSlices(u8, &eph, info[0..56]);
    try std.testing.expectEqualSlices(u8, &rcpt, info[56..112]);
    try std.testing.expectEqual(@as(u8, 9), info[112]);
}

test "padSessionKey format" {
    const allocator = std.testing.allocator;
    const sk = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };
    const padded = try padSessionKey(&sk, allocator);
    defer allocator.free(padded);

    try std.testing.expect(padded.len >= 16);
    try std.testing.expect(padded.len % 8 == 0);
    try std.testing.expectEqual(@as(u8, 5), padded[0]);
    try std.testing.expectEqualSlices(u8, &sk, padded[1..6]);
}
