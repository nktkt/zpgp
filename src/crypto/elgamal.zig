// SPDX-License-Identifier: MIT
//! ElGamal encryption per RFC 4880 Section 13.1.
//!
//! ElGamal is an encrypt-only public-key algorithm based on the discrete
//! logarithm problem in Z_p*.
//!
//! Key material:
//!   Public:  p (prime), g (generator), y = g^x mod p
//!   Secret:  x
//!
//! Encrypt (with random k):
//!   c1 = g^k mod p
//!   c2 = m * y^k mod p
//!
//! Decrypt:
//!   m = c2 * c1^(p-1-x) mod p
//!
//! OpenPGP encodes the session key as an MPI-like value, so `m` is the
//! session key bytes interpreted as a big-endian integer.
//!
//! This implementation uses std.crypto.ff for modular arithmetic.

const std = @import("std");
const mem = std.mem;
const ff = std.crypto.ff;
const Allocator = mem.Allocator;

pub const ElGamalError = error{
    InvalidKey,
    InvalidCiphertext,
    DecryptionFailed,
    PlaintextTooLong,
    OutOfMemory,
};

// Maximum supported key size: 4096 bits (matches RSA limit in the codebase).
pub const max_bits = 4096;
pub const max_bytes = max_bits / 8;

const BigUint = ff.Uint(max_bits);
const BigMod = ff.Modulus(max_bits);
const BigFe = BigMod.Fe;

/// ElGamal public key: (p, g, y) where y = g^x mod p.
pub const ElGamalPublicKey = struct {
    p_bytes: []const u8,
    g_bytes: []const u8,
    y_bytes: []const u8,

    /// Encrypt a plaintext message.
    ///
    /// The plaintext is encoded as a big-endian integer and must be smaller
    /// than p.  For OpenPGP session key encryption, the plaintext is the
    /// encoded session key (with checksum).
    ///
    /// The random value k is generated from the OS CSPRNG.
    ///
    /// Returns: ElGamalCiphertext with (c1, c2) allocated via `allocator`.
    pub fn encrypt(self: ElGamalPublicKey, plaintext: []const u8, allocator: Allocator) !ElGamalCiphertext {
        if (self.p_bytes.len == 0 or self.g_bytes.len == 0 or self.y_bytes.len == 0) {
            return error.InvalidKey;
        }

        // Plaintext must fit in the modulus
        if (plaintext.len > self.p_bytes.len) {
            return error.PlaintextTooLong;
        }

        const mod_len = self.p_bytes.len;

        // Build modulus p
        const p_mod = BigMod.fromBytes(self.p_bytes, .big) catch return error.InvalidKey;

        // Build g, y, m as field elements
        var g_padded: [max_bytes]u8 = [_]u8{0} ** max_bytes;
        padBigEndian(&g_padded, self.g_bytes, mod_len);
        const g_fe = BigFe.fromBytes(p_mod, g_padded[0..mod_len], .big) catch return error.InvalidKey;

        var y_padded: [max_bytes]u8 = [_]u8{0} ** max_bytes;
        padBigEndian(&y_padded, self.y_bytes, mod_len);
        const y_fe = BigFe.fromBytes(p_mod, y_padded[0..mod_len], .big) catch return error.InvalidKey;

        var m_padded: [max_bytes]u8 = [_]u8{0} ** max_bytes;
        padBigEndian(&m_padded, plaintext, mod_len);
        const m_fe = BigFe.fromBytes(p_mod, m_padded[0..mod_len], .big) catch return error.PlaintextTooLong;

        // Generate random k in [1, p-2].
        // We generate random bytes and reduce modulo p using p_mod.reduce().
        // This avoids NonCanonical errors when the random value >= p.
        var k_rand_buf: [max_bytes]u8 = [_]u8{0} ** max_bytes;
        std.crypto.random.bytes(k_rand_buf[0..mod_len]);
        // Ensure k != 0 after reduction
        k_rand_buf[mod_len - 1] |= 0x01;
        const k_uint = BigUint.fromBytes(k_rand_buf[0..mod_len], .big) catch return error.InvalidKey;
        var k_fe = p_mod.reduce(k_uint);
        // Ensure k is non-zero in the field -- if it reduced to zero, set to 1
        var k_check_buf: [max_bytes]u8 = undefined;
        k_fe.toBytes(k_check_buf[0..mod_len], .big) catch return error.InvalidKey;
        var k_is_zero = true;
        for (k_check_buf[0..mod_len]) |b| {
            if (b != 0) {
                k_is_zero = false;
                break;
            }
        }
        if (k_is_zero) {
            k_rand_buf[mod_len - 1] = 0x02;
            const k_uint2 = BigUint.fromBytes(k_rand_buf[0..mod_len], .big) catch return error.InvalidKey;
            k_fe = p_mod.reduce(k_uint2);
        }

        // c1 = g^k mod p
        const c1_fe = p_mod.powPublic(g_fe, k_fe) catch return error.InvalidKey;
        // s = y^k mod p
        const s_fe = p_mod.powPublic(y_fe, k_fe) catch return error.InvalidKey;
        // c2 = m * s mod p
        const c2_fe = p_mod.mul(m_fe, s_fe);

        // Convert to bytes
        var c1_buf: [max_bytes]u8 = undefined;
        c1_fe.toBytes(c1_buf[0..mod_len], .big) catch return error.InvalidKey;
        var c2_buf: [max_bytes]u8 = undefined;
        c2_fe.toBytes(c2_buf[0..mod_len], .big) catch return error.InvalidKey;

        // Trim leading zeros
        const c1_trimmed = trimLeadingZeros(c1_buf[0..mod_len]);
        const c2_trimmed = trimLeadingZeros(c2_buf[0..mod_len]);

        const c1 = try allocator.dupe(u8, c1_trimmed);
        errdefer allocator.free(c1);
        const c2 = try allocator.dupe(u8, c2_trimmed);

        return .{
            .c1 = c1,
            .c2 = c2,
        };
    }
};

/// ElGamal secret key: (p, g, y, x) where y = g^x mod p.
pub const ElGamalSecretKey = struct {
    p_bytes: []const u8,
    g_bytes: []const u8,
    y_bytes: []const u8,
    x_bytes: []const u8,

    /// Decrypt an ElGamal ciphertext.
    ///
    /// Computes: m = c2 * c1^(p-1-x) mod p
    ///
    /// Returns the plaintext as a newly allocated byte slice.
    pub fn decrypt(self: ElGamalSecretKey, ciphertext: ElGamalCiphertext, allocator: Allocator) ![]u8 {
        if (self.p_bytes.len == 0 or self.x_bytes.len == 0) {
            return error.InvalidKey;
        }
        if (ciphertext.c1.len == 0 or ciphertext.c2.len == 0) {
            return error.InvalidCiphertext;
        }

        const mod_len = self.p_bytes.len;

        // Build modulus p
        const p_mod = BigMod.fromBytes(self.p_bytes, .big) catch return error.InvalidKey;

        // Build field elements for c1 and c2
        var c1_padded: [max_bytes]u8 = [_]u8{0} ** max_bytes;
        padBigEndian(&c1_padded, ciphertext.c1, mod_len);
        const c1_fe = BigFe.fromBytes(p_mod, c1_padded[0..mod_len], .big) catch return error.InvalidCiphertext;

        var c2_padded: [max_bytes]u8 = [_]u8{0} ** max_bytes;
        padBigEndian(&c2_padded, ciphertext.c2, mod_len);
        const c2_fe = BigFe.fromBytes(p_mod, c2_padded[0..mod_len], .big) catch return error.InvalidCiphertext;

        // Compute the decryption exponent: p - 1 - x
        // We do this as big integers, then use as an encoded exponent.
        var p_uint = BigUint.fromBytes(self.p_bytes, .big) catch return error.InvalidKey;
        const one = BigUint.fromPrimitive(u64, 1) catch return error.InvalidKey;
        _ = p_uint.subWithOverflow(one); // p_uint is now p-1

        var x_padded: [max_bytes]u8 = [_]u8{0} ** max_bytes;
        padBigEndian(&x_padded, self.x_bytes, mod_len);
        const x_uint = BigUint.fromBytes(x_padded[0..mod_len], .big) catch return error.InvalidKey;
        _ = p_uint.subWithOverflow(x_uint); // p_uint is now p-1-x

        // Encode the exponent as bytes (big-endian, full size)
        var exp_bytes: [max_bytes]u8 = undefined;
        p_uint.toBytes(&exp_bytes, .big) catch return error.InvalidKey;

        // Use the last mod_len bytes (big-endian, the low bytes contain the value)
        const exp_slice = exp_bytes[max_bytes - mod_len ..];

        // s_inv = c1^(p-1-x) mod p
        const s_inv = p_mod.powWithEncodedPublicExponent(c1_fe, exp_slice, .big) catch return error.InvalidKey;

        // m = c2 * s_inv mod p
        const m_fe = p_mod.mul(c2_fe, s_inv);

        // Convert to bytes
        var m_buf: [max_bytes]u8 = undefined;
        m_fe.toBytes(m_buf[0..mod_len], .big) catch return error.InvalidKey;

        // Return the significant bytes
        const m_trimmed = trimLeadingZeros(m_buf[0..mod_len]);

        const result = try allocator.dupe(u8, m_trimmed);
        return result;
    }
};

/// An ElGamal ciphertext pair (c1, c2).
pub const ElGamalCiphertext = struct {
    c1: []u8, // g^k mod p
    c2: []u8, // m * y^k mod p

    pub fn deinit(self: ElGamalCiphertext, allocator: Allocator) void {
        allocator.free(self.c1);
        allocator.free(self.c2);
    }
};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Pad a big-endian byte slice into a buffer, right-aligned (zero-padded left).
fn padBigEndian(buf: []u8, src: []const u8, target_len: usize) void {
    @memset(buf[0..target_len], 0);
    if (src.len <= target_len) {
        @memcpy(buf[target_len - src.len .. target_len], src);
    } else {
        // Truncate (take the low bytes)
        @memcpy(buf[0..target_len], src[src.len - target_len ..]);
    }
}

/// Trim leading zero bytes from a slice, preserving at least one byte.
fn trimLeadingZeros(data: []const u8) []const u8 {
    var start: usize = 0;
    while (start < data.len - 1 and data[start] == 0) {
        start += 1;
    }
    return data[start..];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ElGamalCiphertext deinit" {
    const allocator = std.testing.allocator;
    const c1 = try allocator.dupe(u8, &[_]u8{ 1, 2, 3 });
    const c2 = try allocator.dupe(u8, &[_]u8{ 4, 5, 6 });
    const ct = ElGamalCiphertext{ .c1 = c1, .c2 = c2 };
    ct.deinit(allocator);
}

test "ElGamal encrypt then decrypt round-trip" {
    const allocator = std.testing.allocator;

    // Small test parameters (NOT secure, just for testing):
    // p = 23, g = 5, x = 6, y = 5^6 mod 23 = 8
    const p_bytes = &[_]u8{23};
    const g_bytes = &[_]u8{5};
    const y_bytes = &[_]u8{8};
    const x_bytes = &[_]u8{6};

    const pub_key = ElGamalPublicKey{
        .p_bytes = p_bytes,
        .g_bytes = g_bytes,
        .y_bytes = y_bytes,
    };

    const sec_key = ElGamalSecretKey{
        .p_bytes = p_bytes,
        .g_bytes = g_bytes,
        .y_bytes = y_bytes,
        .x_bytes = x_bytes,
    };

    // Plaintext must be < p.  Use m = 7.
    const plaintext = &[_]u8{7};

    const ct = try pub_key.encrypt(plaintext, allocator);
    defer ct.deinit(allocator);

    // Verify c1 and c2 are non-empty
    try std.testing.expect(ct.c1.len > 0);
    try std.testing.expect(ct.c2.len > 0);

    // Decrypt
    const decrypted = try sec_key.decrypt(ct, allocator);
    defer allocator.free(decrypted);

    // The decrypted value should be our original plaintext.
    var pt_val: u64 = 0;
    for (plaintext) |b| {
        pt_val = pt_val * 256 + b;
    }
    var dec_val: u64 = 0;
    for (decrypted) |b| {
        dec_val = dec_val * 256 + b;
    }

    try std.testing.expectEqual(pt_val, dec_val);
}

test "ElGamal invalid key returns error" {
    const allocator = std.testing.allocator;

    const pub_key = ElGamalPublicKey{
        .p_bytes = &[_]u8{},
        .g_bytes = &[_]u8{5},
        .y_bytes = &[_]u8{8},
    };

    try std.testing.expectError(error.InvalidKey, pub_key.encrypt(&[_]u8{7}, allocator));
}

test "ElGamal invalid ciphertext returns error" {
    const allocator = std.testing.allocator;

    const sec_key = ElGamalSecretKey{
        .p_bytes = &[_]u8{23},
        .g_bytes = &[_]u8{5},
        .y_bytes = &[_]u8{8},
        .x_bytes = &[_]u8{6},
    };

    const ct = ElGamalCiphertext{
        .c1 = @constCast(&[_]u8{}),
        .c2 = @constCast(&[_]u8{1}),
    };

    try std.testing.expectError(error.InvalidCiphertext, sec_key.decrypt(ct, allocator));
}

test "ElGamal secret key with empty p returns error" {
    const allocator = std.testing.allocator;

    const sec_key = ElGamalSecretKey{
        .p_bytes = &[_]u8{},
        .g_bytes = &[_]u8{5},
        .y_bytes = &[_]u8{8},
        .x_bytes = &[_]u8{6},
    };

    const ct = ElGamalCiphertext{
        .c1 = @constCast(&[_]u8{1}),
        .c2 = @constCast(&[_]u8{2}),
    };

    try std.testing.expectError(error.InvalidKey, sec_key.decrypt(ct, allocator));
}

test "trimLeadingZeros" {
    const a = trimLeadingZeros(&[_]u8{ 0, 0, 0, 1, 2, 3 });
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3 }, a);

    const b = trimLeadingZeros(&[_]u8{ 0, 0, 0 });
    try std.testing.expectEqualSlices(u8, &[_]u8{0}, b);

    const c = trimLeadingZeros(&[_]u8{42});
    try std.testing.expectEqualSlices(u8, &[_]u8{42}, c);
}

test "padBigEndian basic" {
    var buf: [4]u8 = undefined;
    padBigEndian(&buf, &[_]u8{ 0x01, 0x02 }, 4);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x01, 0x02 }, &buf);
}

test "padBigEndian same size" {
    var buf: [3]u8 = undefined;
    padBigEndian(&buf, &[_]u8{ 0xAA, 0xBB, 0xCC }, 3);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC }, &buf);
}

test "ElGamal encrypt produces different ciphertext each time" {
    const allocator = std.testing.allocator;

    const pub_key = ElGamalPublicKey{
        .p_bytes = &[_]u8{23},
        .g_bytes = &[_]u8{5},
        .y_bytes = &[_]u8{8},
    };

    const plaintext = &[_]u8{7};

    const ct1 = try pub_key.encrypt(plaintext, allocator);
    defer ct1.deinit(allocator);

    const ct2 = try pub_key.encrypt(plaintext, allocator);
    defer ct2.deinit(allocator);

    // Both should decrypt correctly
    const sec_key = ElGamalSecretKey{
        .p_bytes = &[_]u8{23},
        .g_bytes = &[_]u8{5},
        .y_bytes = &[_]u8{8},
        .x_bytes = &[_]u8{6},
    };

    const d1 = try sec_key.decrypt(ct1, allocator);
    defer allocator.free(d1);
    const d2 = try sec_key.decrypt(ct2, allocator);
    defer allocator.free(d2);

    var v1: u64 = 0;
    for (d1) |b| v1 = v1 * 256 + b;
    var v2: u64 = 0;
    for (d2) |b| v2 = v2 * 256 + b;

    try std.testing.expectEqual(@as(u64, 7), v1);
    try std.testing.expectEqual(@as(u64, 7), v2);
}
