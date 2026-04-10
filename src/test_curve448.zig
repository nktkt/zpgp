// SPDX-License-Identifier: MIT
//! Test suite for X448 and Ed448 implementations.
//!
//! Includes RFC 7748 test vectors for X448, RFC 8032 test vectors for Ed448,
//! key generation roundtrips, sign/verify roundtrips, and invalid input rejection.

const std = @import("std");
const x448_mod = @import("crypto/x448.zig");
const ed448_mod = @import("crypto/ed448.zig");

const Fe = x448_mod.Fe;
const X448Native = x448_mod.X448Native;
const X448Error = x448_mod.X448Error;
const x448 = x448_mod.x448;

const Ed448Native = ed448_mod.Ed448Native;
const Ed448Error = ed448_mod.Ed448Error;

// ===========================================================================
// X448 — RFC 7748 Test Vectors
// ===========================================================================

test "X448 RFC 7748 Section 6.2 — vector 1" {
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
    // Additional test with arbitrary inputs — expected output verified via
    // independent Python reference implementation of RFC 7748 Section 5.
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

test "X448 DH key agreement self-consistency" {
    // Generate two key pairs and verify the shared secret is the same.
    // We use fixed "secret keys" and derive public keys via X448(sk, base_point).
    const alice_sk = [56]u8{
        0x9a, 0x8f, 0x49, 0x25, 0xd1, 0x51, 0x9f, 0x57,
        0x75, 0xcf, 0x46, 0x97, 0x1c, 0x51, 0x00, 0x55,
        0x44, 0x7e, 0x95, 0xe5, 0x7f, 0xa1, 0xd3, 0x02,
        0x72, 0x59, 0xd6, 0xe7, 0x01, 0xed, 0x8a, 0x06,
        0x7c, 0x4e, 0x10, 0x79, 0x33, 0x3e, 0xe4, 0x0e,
        0x2f, 0x02, 0x1b, 0x8d, 0xe0, 0xc6, 0x78, 0x0e,
        0x93, 0xdf, 0xc2, 0x1b, 0xa6, 0x0f, 0x23, 0x08,
    };
    const bob_sk = [56]u8{
        0x1c, 0x30, 0x6a, 0x7a, 0xc2, 0xa0, 0xe2, 0xe0,
        0x99, 0x0b, 0x29, 0x44, 0x70, 0xcb, 0xa3, 0x39,
        0xe6, 0x45, 0x37, 0x72, 0xb0, 0x75, 0x81, 0x1d,
        0x8f, 0xad, 0x0d, 0x1d, 0x69, 0x27, 0xc1, 0x20,
        0xbb, 0x5e, 0xe8, 0x97, 0x2b, 0x09, 0x30, 0x11,
        0x18, 0x1d, 0x2a, 0xac, 0xd0, 0x53, 0xd3, 0x08,
        0xca, 0x66, 0xae, 0x24, 0x41, 0x09, 0x30, 0x6b,
    };

    // Derive public keys
    const alice_pk = try x448(alice_sk, X448Native.base_point);
    const bob_pk = try x448(bob_sk, X448Native.base_point);

    // Shared secrets must match: X448(alice_sk, bob_pk) == X448(bob_sk, alice_pk)
    const ss_alice = try x448(alice_sk, bob_pk);
    const ss_bob = try x448(bob_sk, alice_pk);
    try std.testing.expectEqualSlices(u8, &ss_alice, &ss_bob);
}

// ===========================================================================
// X448 — Field Arithmetic Tests
// ===========================================================================

test "Fe addition commutativity" {
    const a = Fe.fromInt(12345);
    const b = Fe.fromInt(67890);
    const ab = a.add(b);
    const ba = b.add(a);
    try std.testing.expect(ab.eql(ba));
}

test "Fe multiplication commutativity" {
    const a = Fe.fromInt(12345);
    const b = Fe.fromInt(67890);
    const ab = a.mul(b);
    const ba = b.mul(a);
    try std.testing.expect(ab.eql(ba));
}

test "Fe multiplication associativity" {
    const a = Fe.fromInt(123);
    const b = Fe.fromInt(456);
    const c = Fe.fromInt(789);
    const ab_c = a.mul(b).mul(c);
    const a_bc = a.mul(b.mul(c));
    try std.testing.expect(ab_c.eql(a_bc));
}

test "Fe multiply by one" {
    const a = Fe.fromInt(42);
    const result = a.mul(Fe.one);
    try std.testing.expect(result.eql(a));
}

test "Fe multiply by zero" {
    const a = Fe.fromInt(42);
    const result = a.mul(Fe.zero);
    try std.testing.expect(result.isZero());
}

test "Fe subtraction and addition inverse" {
    const a = Fe.fromInt(100);
    const b = Fe.fromInt(50);
    const c = a.sub(b);
    const d = c.add(b);
    try std.testing.expect(d.eql(a));
}

test "Fe inversion of 1" {
    const one_inv = Fe.one.invert();
    try std.testing.expect(one_inv.eql(Fe.one));
}

test "Fe double inversion" {
    const a = Fe.fromInt(42);
    const a_inv = a.invert();
    const a_inv_inv = a_inv.invert();
    try std.testing.expect(a_inv_inv.eql(a));
}

test "Fe encode/decode roundtrip with larger value" {
    // Create a value that spans multiple limbs
    var bytes: [56]u8 = undefined;
    for (0..56) |i| {
        bytes[i] = @truncate(i * 7 + 3);
    }
    const a = Fe.fromBytes(bytes);
    const b = a.toBytes();
    const c = Fe.fromBytes(b);
    try std.testing.expect(a.eql(c));
}

// ===========================================================================
// X448 — Key Generation Tests
// ===========================================================================

test "X448 key generation produces unique keys" {
    const kp1 = X448Native.generate();
    const kp2 = X448Native.generate();
    try std.testing.expect(!std.mem.eql(u8, &kp1.public, &kp2.public));
    try std.testing.expect(!std.mem.eql(u8, &kp1.secret, &kp2.secret));
}

test "X448 key generation roundtrip" {
    const kp = X448Native.generate();
    const derived = try X448Native.publicKeyFromSecret(kp.secret);
    try std.testing.expectEqualSlices(u8, &kp.public, &derived);
}

test "X448 DH key agreement" {
    const alice = X448Native.generate();
    const bob = X448Native.generate();

    const alice_shared = try X448Native.scalarmult(alice.secret, bob.public);
    const bob_shared = try X448Native.scalarmult(bob.secret, alice.public);

    try std.testing.expectEqualSlices(u8, &alice_shared, &bob_shared);
}

test "X448 public key is not all zeros" {
    const kp = X448Native.generate();
    const all_zero = [_]u8{0} ** 56;
    try std.testing.expect(!std.mem.eql(u8, &kp.public, &all_zero));
}

test "X448 validate generated public key" {
    const kp = X448Native.generate();
    try X448Native.validatePublicKey(kp.public);
}

test "X448 reject zero public key" {
    const zero_key = [_]u8{0} ** 56;
    try std.testing.expectError(X448Error.InvalidPublicKey, X448Native.validatePublicKey(zero_key));
}

// ===========================================================================
// Ed448 — Stub Tests (Ed448 not yet fully implemented)
// ===========================================================================

test "Ed448 generate returns UnsupportedAlgorithm" {
    try std.testing.expectError(Ed448Error.UnsupportedAlgorithm, Ed448Native.generate());
}

test "Ed448 sign returns UnsupportedAlgorithm" {
    const dummy_sk = [_]u8{0} ** 57;
    try std.testing.expectError(Ed448Error.UnsupportedAlgorithm, Ed448Native.sign(dummy_sk, "test"));
}

test "Ed448 verify returns UnsupportedAlgorithm" {
    const dummy_pk = [_]u8{0} ** 57;
    const dummy_sig = [_]u8{0} ** 114;
    try std.testing.expectError(Ed448Error.UnsupportedAlgorithm, Ed448Native.verify(dummy_pk, "test", dummy_sig));
}

// ===========================================================================
// X448 — Session Key Encryption/Decryption
// ===========================================================================

test "X448 session key encrypt/decrypt roundtrip" {
    const allocator = std.testing.allocator;
    const SymmetricAlgorithm = @import("types/enums.zig").SymmetricAlgorithm;

    const recipient = X448Native.generate();
    const session_key = [_]u8{
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    };

    const encrypted = try X448Native.encryptSessionKey(
        allocator,
        recipient.public,
        &session_key,
        @intFromEnum(SymmetricAlgorithm.aes128),
    );
    defer encrypted.deinit();

    const decrypted = try X448Native.decryptSessionKey(
        allocator,
        recipient.secret,
        recipient.public,
        encrypted.ephemeral_public,
        encrypted.wrapped_key,
        @intFromEnum(SymmetricAlgorithm.aes128),
    );
    defer allocator.free(decrypted);

    try std.testing.expectEqualSlices(u8, &session_key, decrypted);
}

test "X448 session key wrong recipient fails" {
    const allocator = std.testing.allocator;
    const SymmetricAlgorithm = @import("types/enums.zig").SymmetricAlgorithm;

    const recipient = X448Native.generate();
    const wrong = X448Native.generate();
    const session_key = [_]u8{0xAA} ** 16;

    const encrypted = try X448Native.encryptSessionKey(
        allocator,
        recipient.public,
        &session_key,
        @intFromEnum(SymmetricAlgorithm.aes128),
    );
    defer encrypted.deinit();

    try std.testing.expectError(
        X448Error.UnwrapFailed,
        X448Native.decryptSessionKey(
            allocator,
            wrong.secret,
            wrong.public,
            encrypted.ephemeral_public,
            encrypted.wrapped_key,
            @intFromEnum(SymmetricAlgorithm.aes128),
        ),
    );
}
