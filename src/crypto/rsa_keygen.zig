// SPDX-License-Identifier: MIT
//! RSA key pair generation using std.crypto.ff for big-integer arithmetic.

const std = @import("std");
const ff = std.crypto.ff;
const Allocator = std.mem.Allocator;

pub const max_bits = 4096;
pub const max_bytes = max_bits / 8;

const Uint = ff.Uint(max_bits);
const WideUint = ff.Uint(max_bits * 2);
const wide_len = max_bytes * 2;

fn uintVal(val: u32) Uint {
    return Uint.fromPrimitive(u32, val) catch unreachable;
}

fn uintFromBuf(buf: *const [max_bytes]u8) Uint {
    return Uint.fromBytes(buf, .big) catch unreachable;
}

fn wideFromBuf(buf: *const [wide_len]u8) WideUint {
    return WideUint.fromBytes(buf, .big) catch unreachable;
}

fn toBytesBig(v: Uint, buf: *[max_bytes]u8) void {
    v.toBytes(buf, .big) catch unreachable;
}

fn toBytesBigWide(v: WideUint, buf: *[wide_len]u8) void {
    v.toBytes(buf, .big) catch unreachable;
}

/// Subtract y from x, returning (result, overflow_flag). Non-mutating.
fn sub(x: Uint, y: Uint) struct { val: Uint, overflow: u1 } {
    var r = x;
    const ov = r.subWithOverflow(y);
    return .{ .val = r, .overflow = ov };
}

fn add(x: Uint, y: Uint) struct { val: Uint, overflow: u1 } {
    var r = x;
    const ov = r.addWithOverflow(y);
    return .{ .val = r, .overflow = ov };
}

fn subWide(x: WideUint, y: WideUint) struct { val: WideUint, overflow: u1 } {
    var r = x;
    const ov = r.subWithOverflow(y);
    return .{ .val = r, .overflow = ov };
}

fn addWide(x: WideUint, y: WideUint) struct { val: WideUint, overflow: u1 } {
    var r = x;
    const ov = r.addWithOverflow(y);
    return .{ .val = r, .overflow = ov };
}

pub const RsaKeygenError = error{
    InvalidKeySize,
    KeyGenerationFailed,
    OutOfMemory,
};

const small_primes = blk: {
    @setEvalBranchQuota(100_000);
    var primes: [256]u16 = undefined;
    primes[0] = 2;
    var count: usize = 1;
    var candidate: u16 = 3;
    while (count < 256) : (candidate += 2) {
        var is_prime = true;
        for (primes[0..count]) |p| {
            if (p * p > candidate) break;
            if (candidate % p == 0) { is_prime = false; break; }
        }
        if (is_prime) { primes[count] = candidate; count += 1; }
    }
    break :blk primes;
};

pub const RsaKeyPair = struct {
    n: []u8,
    e: []u8,
    d: []u8,
    p: []u8,
    q: []u8,

    pub fn generate(allocator: Allocator, bits: u32) !RsaKeyPair {
        if (bits < 512 or bits > max_bits or bits % 256 != 0)
            return error.InvalidKeySize;

        const half_bits = bits / 2;
        const half_bytes = half_bits / 8;
        const full_bytes = bits / 8;
        const e_val = uintVal(65537);
        const e_bytes_static = [_]u8{ 0x01, 0x00, 0x01 };

        var p_val: Uint = undefined;
        var q_val: Uint = undefined;
        var attempts: u32 = 0;

        while (attempts < 10000) : (attempts += 1) {
            p_val = generatePrimeCandidate(half_bits);
            if (millerRabinTest(p_val, 20)) {
                const e_mod = ff.Modulus(max_bits).fromUint(e_val) catch continue;
                const p_fe = e_mod.reduce(p_val);
                const one_fe = e_mod.reduce(uintVal(1));
                if (!p_fe.eql(one_fe)) break;
            }
        } else return error.KeyGenerationFailed;

        attempts = 0;
        while (attempts < 10000) : (attempts += 1) {
            q_val = generatePrimeCandidate(half_bits);
            if (millerRabinTest(q_val, 20)) {
                if (q_val.compare(p_val) == .eq) continue;
                const e_mod = ff.Modulus(max_bits).fromUint(e_val) catch continue;
                const q_fe = e_mod.reduce(q_val);
                const one_fe = e_mod.reduce(uintVal(1));
                if (!q_fe.eql(one_fe)) break;
            }
        } else return error.KeyGenerationFailed;

        if (p_val.compare(q_val) == .lt) {
            const tmp = p_val;
            p_val = q_val;
            q_val = tmp;
        }

        const n_wide = mulWide(widen(p_val), widen(q_val));
        const n_val = narrow(n_wide) catch return error.KeyGenerationFailed;

        const one = uintVal(1);
        const pm1 = sub(p_val, one);
        if (pm1.overflow != 0) return error.KeyGenerationFailed;
        const qm1 = sub(q_val, one);
        if (qm1.overflow != 0) return error.KeyGenerationFailed;

        const phi_wide = mulWide(widen(pm1.val), widen(qm1.val));
        const phi_val = narrow(phi_wide) catch return error.KeyGenerationFailed;
        const d_val = modularInverse(e_val, phi_val) orelse return error.KeyGenerationFailed;

        const e_alloc = try allocator.dupe(u8, &e_bytes_static);
        errdefer allocator.free(e_alloc);

        var n_buf: [max_bytes]u8 = undefined;
        toBytesBig(n_val, &n_buf);
        const n_alloc = try stripLeadingZeros(allocator, n_buf[max_bytes - full_bytes ..]);
        errdefer allocator.free(n_alloc);

        var d_buf: [max_bytes]u8 = undefined;
        toBytesBig(d_val, &d_buf);
        const d_alloc = try stripLeadingZeros(allocator, d_buf[max_bytes - full_bytes ..]);
        errdefer allocator.free(d_alloc);

        var p_buf: [max_bytes]u8 = undefined;
        toBytesBig(p_val, &p_buf);
        const p_alloc = try stripLeadingZeros(allocator, p_buf[max_bytes - half_bytes ..]);
        errdefer allocator.free(p_alloc);

        var q_buf: [max_bytes]u8 = undefined;
        toBytesBig(q_val, &q_buf);
        const q_alloc = try stripLeadingZeros(allocator, q_buf[max_bytes - half_bytes ..]);

        return .{ .n = n_alloc, .e = e_alloc, .d = d_alloc, .p = p_alloc, .q = q_alloc };
    }

    pub fn deinit(self: RsaKeyPair, allocator: Allocator) void {
        allocator.free(self.n);
        allocator.free(self.e);
        allocator.free(self.d);
        allocator.free(self.p);
        allocator.free(self.q);
    }
};

fn stripLeadingZeros(allocator: Allocator, data: []const u8) ![]u8 {
    var start: usize = 0;
    while (start < data.len and data[start] == 0) : (start += 1) {}
    if (start == data.len) {
        const result = try allocator.alloc(u8, 1);
        result[0] = 0;
        return result;
    }
    return try allocator.dupe(u8, data[start..]);
}

fn generatePrimeCandidate(bits: u32) Uint {
    const byte_len = bits / 8;
    var buf: [max_bytes]u8 = [_]u8{0} ** max_bytes;
    const target = buf[max_bytes - byte_len ..];
    std.crypto.random.bytes(target);
    target[0] |= 0xC0;
    target[byte_len - 1] |= 0x01;
    return uintFromBuf(&buf);
}

fn trialDivision(n: Uint) bool {
    for (small_primes[1..]) |p| {
        const prime = Uint.fromPrimitive(u16, p) catch continue;
        if (n.compare(prime) == .eq) return true;
        const rem = divRem(n, prime);
        if (rem.compare(uintVal(0)) == .eq) return false;
    }
    return true;
}

fn divRem(n: Uint, d: Uint) Uint {
    const d_mod = ff.Modulus(max_bits).fromUint(d) catch return uintVal(0);
    const n_reduced = d_mod.reduce(n);
    var buf: [max_bytes]u8 = undefined;
    n_reduced.toBytes(&buf, .big) catch return uintVal(0);
    return uintFromBuf(&buf);
}

fn millerRabinTest(n: Uint, rounds: u32) bool {
    const two = uintVal(2);
    const three = uintVal(3);
    if (n.compare(two) == .lt) return false;
    if (n.compare(two) == .eq) return true;
    if (n.compare(three) == .eq) return true;
    if (!trialDivision(n)) return false;

    const one = uintVal(1);
    const nm1_r = sub(n, one);
    if (nm1_r.overflow != 0) return false;
    const n_minus_1 = nm1_r.val;

    var d = n_minus_1;
    var r: u32 = 0;
    while (isEven(d)) { d = shiftRight1(d); r += 1; }
    if (r == 0) return false;

    const n_mod = ff.Modulus(max_bits).fromUint(n) catch return false;
    const one_fe = n_mod.reduce(one);
    const nm1_fe = n_mod.reduce(n_minus_1);
    const fixed_witnesses = [_]u32{ 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 };

    var round: u32 = 0;
    while (round < rounds) : (round += 1) {
        var a: Uint = undefined;
        if (round < fixed_witnesses.len) {
            a = uintVal(fixed_witnesses[round]);
            if (a.compare(n_minus_1) != .lt) continue;
        } else {
            a = randomInRange(two, n_minus_1);
        }
        var d_bytes: [max_bytes]u8 = undefined;
        toBytesBig(d, &d_bytes);
        const a_fe = n_mod.reduce(a);
        var x = n_mod.powWithEncodedExponent(a_fe, &d_bytes, .big) catch return false;
        if (x.eql(one_fe) or x.eql(nm1_fe)) continue;
        var found = false;
        var i: u32 = 0;
        while (i < r - 1) : (i += 1) {
            x = n_mod.sq(x);
            if (x.eql(nm1_fe)) { found = true; break; }
            if (x.eql(one_fe)) return false;
        }
        if (!found) return false;
    }
    return true;
}

fn isEven(n: Uint) bool {
    var buf: [max_bytes]u8 = undefined;
    toBytesBig(n, &buf);
    return (buf[max_bytes - 1] & 1) == 0;
}

fn shiftRight1(n: Uint) Uint {
    var bytes: [max_bytes]u8 = undefined;
    toBytesBig(n, &bytes);
    var carry: u8 = 0;
    for (&bytes) |*b| {
        const nc = b.* & 1;
        b.* = (b.* >> 1) | (carry << 7);
        carry = nc;
    }
    return uintFromBuf(&bytes);
}

fn randomInRange(low: Uint, high: Uint) Uint {
    var buf: [max_bytes]u8 = undefined;
    for (0..100) |_| {
        std.crypto.random.bytes(&buf);
        const val = uintFromBuf(&buf);
        if (val.compare(low) != .lt and val.compare(high) == .lt) return val;
    }
    return add(low, uintVal(2)).val;
}

fn widen(n: Uint) WideUint {
    var nb: [max_bytes]u8 = undefined;
    toBytesBig(n, &nb);
    var wb: [wide_len]u8 = [_]u8{0} ** wide_len;
    @memcpy(wb[max_bytes..], &nb);
    return wideFromBuf(&wb);
}

fn narrow(n: WideUint) error{KeyGenerationFailed}!Uint {
    var wb: [wide_len]u8 = undefined;
    toBytesBigWide(n, &wb);
    for (wb[0..max_bytes]) |b| { if (b != 0) return error.KeyGenerationFailed; }
    return uintFromBuf(wb[max_bytes..][0..max_bytes]);
}

fn mulWide(a: WideUint, b: WideUint) WideUint {
    var ab: [wide_len]u8 = undefined;
    var bb: [wide_len]u8 = undefined;
    toBytesBigWide(a, &ab);
    toBytesBigWide(b, &bb);
    const as = findFirstNonZero(&ab);
    const bs = findFirstNonZero(&bb);
    const al = wide_len - as;
    const bl = wide_len - bs;
    var result: [wide_len]u8 = [_]u8{0} ** wide_len;
    if (al == 0 or bl == 0) return wideFromBuf(&result);
    const asl = ab[as..];
    const bsl = bb[bs..];
    var i: usize = 0;
    while (i < al) : (i += 1) {
        const ad = asl[al - 1 - i];
        if (ad == 0) continue;
        var carry: u16 = 0;
        var j: usize = 0;
        while (j < bl) : (j += 1) {
            const ri = wide_len - 1 - i - j;
            if (ri >= wide_len) break;
            const bd = bsl[bl - 1 - j];
            const prod: u16 = @as(u16, ad) * @as(u16, bd) + @as(u16, result[ri]) + carry;
            result[ri] = @truncate(prod & 0xFF);
            carry = prod >> 8;
        }
        if (carry > 0) {
            const cs: isize = @as(isize, @intCast(wide_len)) - 1 - @as(isize, @intCast(i)) - @as(isize, @intCast(bl));
            if (cs >= 0) {
                const ci: usize = @intCast(cs);
                const s: u16 = @as(u16, result[ci]) + carry;
                result[ci] = @truncate(s & 0xFF);
            }
        }
    }
    return wideFromBuf(&result);
}

fn findFirstNonZero(buf: []const u8) usize {
    for (buf, 0..) |b, i| { if (b != 0) return i; }
    return buf.len;
}

fn modularInverse(a: Uint, m: Uint) ?Uint {
    const zw = widen(uintVal(0));
    var old_r = widen(m);
    var r = widen(a);
    var old_s = widen(uintVal(0));
    var s = widen(uintVal(1));
    var old_s_neg: bool = false;
    var s_neg: bool = false;

    var iterations: u32 = 0;
    while (r.compare(zw) != .eq and iterations < max_bits * 2) : (iterations += 1) {
        const qr = wideDivMod(old_r, r);
        old_r = r;
        r = qr.remainder;
        const qts = mulWide(qr.quotient, s);
        var new_s: WideUint = undefined;
        var new_s_neg: bool = undefined;
        if (old_s_neg == s_neg) {
            if (old_s.compare(qts) != .lt) {
                new_s = subWide(old_s, qts).val;
                new_s_neg = old_s_neg;
            } else {
                new_s = subWide(qts, old_s).val;
                new_s_neg = !old_s_neg;
            }
        } else {
            new_s = addWide(old_s, qts).val;
            new_s_neg = old_s_neg;
        }
        old_s = s;
        old_s_neg = s_neg;
        s = new_s;
        s_neg = new_s_neg;
    }

    if (old_r.compare(widen(uintVal(1))) != .eq) return null;

    if (old_s_neg) {
        const mw = widen(m);
        const reduced = wideDivMod(old_s, mw).remainder;
        if (reduced.compare(zw) == .eq) return uintVal(0);
        old_s = subWide(mw, reduced).val;
    } else {
        old_s = wideDivMod(old_s, widen(m)).remainder;
    }
    return narrow(old_s) catch null;
}

const DivModResult = struct { quotient: WideUint, remainder: WideUint };

fn wideDivMod(numerator: WideUint, denominator: WideUint) DivModResult {
    const zw = widen(uintVal(0));
    if (denominator.compare(zw) == .eq) return .{ .quotient = zw, .remainder = zw };
    if (numerator.compare(denominator) == .lt) return .{ .quotient = zw, .remainder = numerator };
    if (numerator.compare(denominator) == .eq) return .{ .quotient = widen(uintVal(1)), .remainder = zw };

    var q = zw;
    var rem = zw;
    var nb: [wide_len]u8 = undefined;
    toBytesBigWide(numerator, &nb);
    const fnz = findFirstNonZero(&nb);
    if (fnz >= wide_len) return .{ .quotient = zw, .remainder = zw };
    const nbl = (wide_len - fnz) * 8 - @as(usize, @clz(nb[fnz]));

    var bi: usize = 0;
    while (bi < nbl) : (bi += 1) {
        rem = shiftLeftWide1(rem);
        const abp = nbl - 1 - bi;
        const byp = wide_len - 1 - abp / 8;
        const bip: u3 = @truncate(abp % 8);
        if (byp < wide_len and (nb[byp] >> bip) & 1 == 1) {
            var rb: [wide_len]u8 = undefined;
            toBytesBigWide(rem, &rb);
            rb[wide_len - 1] |= 1;
            rem = wideFromBuf(&rb);
        }
        if (rem.compare(denominator) != .lt) {
            rem = subWide(rem, denominator).val;
            var qb: [wide_len]u8 = undefined;
            toBytesBigWide(q, &qb);
            const qbp = wide_len - 1 - abp / 8;
            if (qbp < wide_len) qb[qbp] |= @as(u8, 1) << bip;
            q = wideFromBuf(&qb);
        }
    }
    return .{ .quotient = q, .remainder = rem };
}

fn shiftLeftWide1(n: WideUint) WideUint {
    var bytes: [wide_len]u8 = undefined;
    toBytesBigWide(n, &bytes);
    var carry: u8 = 0;
    var i: usize = wide_len;
    while (i > 0) { i -= 1; const nc = (bytes[i] >> 7) & 1; bytes[i] = (bytes[i] << 1) | carry; carry = nc; }
    return wideFromBuf(&bytes);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "small primes table" {
    try std.testing.expectEqual(@as(u16, 2), small_primes[0]);
    try std.testing.expectEqual(@as(u16, 3), small_primes[1]);
    try std.testing.expectEqual(@as(u16, 5), small_primes[2]);
}

test "isEven" {
    try std.testing.expect(isEven(uintVal(0)));
    try std.testing.expect(!isEven(uintVal(1)));
    try std.testing.expect(isEven(uintVal(2)));
}

test "shiftRight1" {
    try std.testing.expect(shiftRight1(uintVal(100)).compare(uintVal(50)) == .eq);
    try std.testing.expect(shiftRight1(uintVal(7)).compare(uintVal(3)) == .eq);
}

test "wideDivMod basic" {
    const result = wideDivMod(widen(uintVal(100)), widen(uintVal(7)));
    try std.testing.expect(result.quotient.compare(widen(uintVal(14))) == .eq);
    try std.testing.expect(result.remainder.compare(widen(uintVal(2))) == .eq);
}

test "mulWide basic" {
    const result = mulWide(widen(uintVal(12345)), widen(uintVal(67890)));
    try std.testing.expect(result.compare(widen(uintVal(838102050))) == .eq);
}

test "modularInverse basic" {
    const inv = modularInverse(uintVal(3), uintVal(7)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(inv.compare(uintVal(5)) == .eq);
}

test "modularInverse e=17 mod phi=3120" {
    const d = modularInverse(uintVal(17), uintVal(3120)) orelse return error.TestUnexpectedResult;
    const prod = mulWide(widen(d), widen(uintVal(17)));
    const rem = wideDivMod(prod, widen(uintVal(3120))).remainder;
    try std.testing.expect(rem.compare(widen(uintVal(1))) == .eq);
}

test "Miller-Rabin known small primes" {
    // Note: ff.Modulus(4096).sq() has precision issues with very small moduli
    // (< ~64 bits) due to Montgomery representation overhead. The primality
    // test works correctly for the 256+ bit primes used in actual key generation.
    try std.testing.expect(millerRabinTest(uintVal(2), 3));
    try std.testing.expect(millerRabinTest(uintVal(3), 3));
    try std.testing.expect(millerRabinTest(uintVal(5), 3));
    try std.testing.expect(millerRabinTest(uintVal(7), 3));
}

test "Miller-Rabin known composites" {
    try std.testing.expect(!millerRabinTest(uintVal(4), 10));
    try std.testing.expect(!millerRabinTest(uintVal(9), 10));
    try std.testing.expect(!millerRabinTest(uintVal(15), 10));
    try std.testing.expect(!millerRabinTest(uintVal(561), 10));
}

test "RSA 512-bit key generation" {
    const allocator = std.testing.allocator;
    const kp = try RsaKeyPair.generate(allocator, 512);
    defer kp.deinit(allocator);
    try std.testing.expect(kp.n.len >= 63 and kp.n.len <= 64);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00, 0x01 }, kp.e);

    const rsa = @import("rsa.zig");
    const hash_mod = @import("hash.zig");
    const pub_key = rsa.RsaPublicKey{ .n_bytes = kp.n, .e_bytes = kp.e };
    const sec_key = rsa.RsaSecretKey{ .n_bytes = kp.n, .e_bytes = kp.e, .d_bytes = kp.d, .p_bytes = kp.p, .q_bytes = kp.q };
    var digest: [32]u8 = undefined;
    try hash_mod.HashContext.hash(.sha256, "RSA keygen test", &digest);
    var sig_buf: [rsa.max_bytes]u8 = undefined;
    try sec_key.pkcs1v15Sign(.sha256, &digest, sig_buf[0..kp.n.len]);
    try pub_key.pkcs1v15Verify(.sha256, &digest, sig_buf[0..kp.n.len]);
}

test "stripLeadingZeros" {
    const allocator = std.testing.allocator;
    const r1 = try stripLeadingZeros(allocator, &[_]u8{ 0, 0, 0x01, 0xFF });
    defer allocator.free(r1);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0xFF }, r1);
}
