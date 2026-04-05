// SPDX-License-Identifier: MIT
//! GCM (Galois/Counter Mode) wrapper for OpenPGP AEAD.
//!
//! This module wraps Zig's standard library AES-GCM implementation
//! (std.crypto.aead.aes_gcm) to provide a consistent interface with
//! the other AEAD modes (EAX, OCB) used in RFC 9580.

const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;

/// GCM wrapper providing a consistent interface.
/// `StdGcm` must be std.crypto.aead.aes_gcm.Aes128Gcm or Aes256Gcm.
fn GcmWrapper(comptime StdGcm: type) type {
    return struct {
        const Self = @This();
        pub const block_size: usize = 16;
        pub const tag_size: usize = StdGcm.tag_length;
        pub const nonce_size: usize = StdGcm.nonce_length;
        pub const key_size: usize = StdGcm.key_length;

        key: [key_size]u8,

        pub fn init(key: [key_size]u8) Self {
            return .{ .key = key };
        }

        /// Encrypt plaintext and produce authentication tag.
        pub fn encrypt(
            self: Self,
            ciphertext: []u8,
            tag: *[tag_size]u8,
            plaintext: []const u8,
            nonce: []const u8,
            ad: []const u8,
        ) void {
            std.debug.assert(ciphertext.len == plaintext.len);
            std.debug.assert(nonce.len == nonce_size);

            StdGcm.encrypt(
                ciphertext,
                tag,
                plaintext,
                ad,
                nonce[0..nonce_size].*,
                self.key,
            );
        }

        /// Decrypt ciphertext and verify authentication tag.
        pub fn decrypt(
            self: Self,
            plaintext: []u8,
            ciphertext: []const u8,
            tag: [tag_size]u8,
            nonce: []const u8,
            ad: []const u8,
        ) !void {
            std.debug.assert(plaintext.len == ciphertext.len);
            std.debug.assert(nonce.len == nonce_size);

            StdGcm.decrypt(
                plaintext,
                ciphertext,
                tag,
                ad,
                nonce[0..nonce_size].*,
                self.key,
            ) catch return error.AuthenticationFailed;
        }
    };
}

pub const AesGcm128 = GcmWrapper(crypto.aead.aes_gcm.Aes128Gcm);
pub const AesGcm256 = GcmWrapper(crypto.aead.aes_gcm.Aes256Gcm);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "GCM AES-128 encrypt/decrypt round-trip" {
    const key = [_]u8{0x01} ** 16;
    const nonce = [_]u8{0x02} ** 12;
    const ad = "associated data";
    const plaintext = "Hello, GCM mode!";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    const gcm = AesGcm128.init(key);
    gcm.encrypt(&ciphertext, &tag, plaintext, &nonce, ad);

    try std.testing.expect(!mem.eql(u8, &ciphertext, plaintext));

    var decrypted: [plaintext.len]u8 = undefined;
    try gcm.decrypt(&decrypted, &ciphertext, tag, &nonce, ad);
    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "GCM AES-256 encrypt/decrypt round-trip" {
    const key = [_]u8{0xAB} ** 32;
    const nonce = [_]u8{0xCD} ** 12;
    const ad = "AES-256 GCM test header";
    const plaintext = "AES-256 GCM encryption test spanning several blocks of data for thorough verification.";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    const gcm = AesGcm256.init(key);
    gcm.encrypt(&ciphertext, &tag, plaintext, &nonce, ad);

    var decrypted: [plaintext.len]u8 = undefined;
    try gcm.decrypt(&decrypted, &ciphertext, tag, &nonce, ad);
    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "GCM wrong tag fails" {
    const key = [_]u8{0x42} ** 16;
    const nonce = [_]u8{0x33} ** 12;
    const plaintext = "sensitive data";
    const ad = "header";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    const gcm = AesGcm128.init(key);
    gcm.encrypt(&ciphertext, &tag, plaintext, &nonce, ad);

    tag[0] ^= 0xFF;

    var decrypted: [plaintext.len]u8 = undefined;
    const result = gcm.decrypt(&decrypted, &ciphertext, tag, &nonce, ad);
    try std.testing.expectError(error.AuthenticationFailed, result);
}

test "GCM empty plaintext" {
    const key = [_]u8{0x01} ** 16;
    const nonce = [_]u8{0x02} ** 12;
    const ad = "only associated data";

    var ciphertext: [0]u8 = .{};
    var tag: [16]u8 = undefined;

    const gcm = AesGcm128.init(key);
    gcm.encrypt(&ciphertext, &tag, "", &nonce, ad);

    try std.testing.expect(!mem.eql(u8, &tag, &([_]u8{0} ** 16)));

    var decrypted: [0]u8 = .{};
    try gcm.decrypt(&decrypted, &ciphertext, tag, &nonce, ad);
}

test "GCM empty ad" {
    const key = [_]u8{0x77} ** 16;
    const nonce = [_]u8{0x88} ** 12;
    const plaintext = "data with no associated data";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    const gcm = AesGcm128.init(key);
    gcm.encrypt(&ciphertext, &tag, plaintext, &nonce, "");

    var decrypted: [plaintext.len]u8 = undefined;
    try gcm.decrypt(&decrypted, &ciphertext, tag, &nonce, "");
    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "GCM tampered ciphertext fails" {
    const key = [_]u8{0x42} ** 16;
    const nonce = [_]u8{0x33} ** 12;
    const plaintext = "integrity check";
    const ad = "";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    const gcm = AesGcm128.init(key);
    gcm.encrypt(&ciphertext, &tag, plaintext, &nonce, ad);

    ciphertext[0] ^= 0x01;

    var decrypted: [plaintext.len]u8 = undefined;
    const result = gcm.decrypt(&decrypted, &ciphertext, tag, &nonce, ad);
    try std.testing.expectError(error.AuthenticationFailed, result);
}

test "GCM deterministic" {
    const key = [_]u8{0x42} ** 16;
    const nonce = [_]u8{0x33} ** 12;
    const plaintext = "deterministic test";
    const ad = "header";

    var ct1: [plaintext.len]u8 = undefined;
    var tag1: [16]u8 = undefined;
    var ct2: [plaintext.len]u8 = undefined;
    var tag2: [16]u8 = undefined;

    const gcm = AesGcm128.init(key);
    gcm.encrypt(&ct1, &tag1, plaintext, &nonce, ad);
    gcm.encrypt(&ct2, &tag2, plaintext, &nonce, ad);

    try std.testing.expectEqualSlices(u8, &ct1, &ct2);
    try std.testing.expectEqualSlices(u8, &tag1, &tag2);
}
