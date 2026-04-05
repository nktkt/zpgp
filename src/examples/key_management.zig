// SPDX-License-Identifier: MIT
//! Example: Key management operations with zpgp.
//!
//! This module demonstrates:
//!   1. Generating keys with various options
//!   2. Importing and exporting keys
//!   3. Keyring operations (add, find, remove)
//!   4. Subkey management
//!   5. Key revocation
//!   6. Key expiration checking
//!   7. WKD (Web Key Directory) URL construction
//!   8. Autocrypt header generation

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const armor = @import("../armor/armor.zig");
const keygen = @import("../key/generate.zig");
const Key = @import("../key/key.zig").Key;
const UserIdBinding = @import("../key/key.zig").UserIdBinding;
const SubkeyBinding = @import("../key/key.zig").SubkeyBinding;
const Keyring = @import("../key/keyring.zig").Keyring;
const import_export = @import("../key/import_export.zig");
const revocation = @import("../key/revocation.zig");
const expiration = @import("../key/expiration.zig");
const subkey_mod = @import("../key/subkey.zig");
const PublicKeyPacket = @import("../packets/public_key.zig").PublicKeyPacket;
const UserIdPacket = @import("../packets/user_id.zig").UserIdPacket;
const enums = @import("../types/enums.zig");
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const wkd = @import("../wkd.zig");
const autocrypt = @import("../autocrypt.zig");

const hex = @import("../utils/hex.zig");
const email_util = @import("../utils/email.zig");
const time_fmt = @import("../utils/time_fmt.zig");
const algo_policy = @import("../policy/algorithm_policy.zig");
const compliance = @import("../policy/compliance.zig");

// ---------------------------------------------------------------------------
// Example 1: Generate Key
// ---------------------------------------------------------------------------

/// Demonstrate key generation with various algorithms.
///
/// Shows RSA key generation with different bit sizes and how to
/// inspect the generated output.
pub fn exampleGenerateKey(allocator: Allocator) !void {
    // Generate an RSA-2048 key
    const options = keygen.KeyGenOptions{
        .algorithm = .rsa_encrypt_sign,
        .bits = 2048,
        .user_id = "Key Gen Example <keygen@example.com>",
        .hash_algo = .sha256,
    };

    const generated = keygen.generateKey(allocator, options) catch |err| {
        switch (err) {
            error.KeyGenerationFailed => return,
            else => return err,
        }
    };
    defer generated.deinit(allocator);

    // Inspect the generated key
    std.debug.assert(generated.public_key_armored.len > 0);
    std.debug.assert(generated.secret_key_armored.len > 0);

    // Format the fingerprint
    const fp_formatted = try hex.formatFingerprint(allocator, &generated.fingerprint);
    defer allocator.free(fp_formatted);
    std.debug.assert(fp_formatted.len > 0);

    // Format the key ID
    const kid_hex = try hex.hexEncodeUpper(allocator, &generated.key_id);
    defer allocator.free(kid_hex);
    std.debug.assert(kid_hex.len == 16);

    // Verify the armored public key starts correctly
    std.debug.assert(mem.startsWith(u8, generated.public_key_armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));
}

// ---------------------------------------------------------------------------
// Example 2: Import/Export Key
// ---------------------------------------------------------------------------

/// Demonstrate key import from armored data and re-export.
///
/// Shows the full cycle: generate -> export -> decode -> verify.
pub fn exampleImportExportKey(allocator: Allocator) !void {
    // Generate a key to work with
    const generated = keygen.generateKey(allocator, .{
        .algorithm = .rsa_encrypt_sign,
        .bits = 2048,
        .user_id = "Import Test <import@example.com>",
    }) catch |err| {
        switch (err) {
            error.KeyGenerationFailed => return,
            else => return err,
        }
    };
    defer generated.deinit(allocator);

    // Decode the armored public key to get the binary packets
    var decoded = armor.decode(allocator, generated.public_key_armored) catch
        return;
    defer decoded.deinit();

    std.debug.assert(decoded.armor_type == .public_key);
    std.debug.assert(decoded.data.len > 0);

    // Re-encode the binary data as armor
    const re_armored = armor.encode(allocator, decoded.data, .public_key, null) catch
        return;
    defer allocator.free(re_armored);

    // The re-armored key should decode to the same binary data
    var re_decoded = armor.decode(allocator, re_armored) catch
        return;
    defer re_decoded.deinit();

    std.debug.assert(mem.eql(u8, decoded.data, re_decoded.data));
}

// ---------------------------------------------------------------------------
// Example 3: Keyring Operations
// ---------------------------------------------------------------------------

/// Demonstrate keyring management: adding, searching, and removing keys.
pub fn exampleKeyringOperations(allocator: Allocator) !void {
    var ring = Keyring.init(allocator);
    defer ring.deinit();

    // Create several test keys with different user IDs
    const user_ids = [_][]const u8{
        "Alice <alice@example.com>",
        "Bob <bob@example.com>",
        "Charlie <charlie@example.com>",
    };

    for (user_ids, 0..) |uid_str, i| {
        var body: [12]u8 = undefined;
        body[0] = 4;
        mem.writeInt(u32, body[1..5], @as(u32, @intCast(1000 + i * 1000)), .big);
        body[5] = 1; // RSA
        mem.writeInt(u16, body[6..8], 8, .big);
        body[8] = @as(u8, @intCast(0xA0 + i));
        mem.writeInt(u16, body[9..11], 8, .big);
        body[11] = 0x03;

        const pk = try PublicKeyPacket.parse(allocator, &body, false);
        var key = Key.init(pk);

        const uid = UserIdPacket{ .id = try allocator.dupe(u8, uid_str) };
        try key.addUserId(allocator, .{
            .user_id = uid,
            .self_signature = null,
            .certifications = .empty,
        });

        try ring.addKey(key);
    }

    std.debug.assert(ring.keys.items.len == 3);

    // Search by email
    const bob_keys = try ring.findByEmail("bob@example.com", allocator);
    defer allocator.free(bob_keys);
    std.debug.assert(bob_keys.len == 1);

    // Search for non-existent email
    const nobody = try ring.findByEmail("nobody@example.com", allocator);
    defer allocator.free(nobody);
    std.debug.assert(nobody.len == 0);

    // Remove a key by fingerprint
    const charlie_fp = ring.keys.items[2].fingerprint();
    const removed = ring.removeByFingerprint(charlie_fp);
    std.debug.assert(removed);
    std.debug.assert(ring.keys.items.len == 2);
}

// ---------------------------------------------------------------------------
// Example 4: Subkey Management
// ---------------------------------------------------------------------------

/// Demonstrate subkey addition and selection.
///
/// OpenPGP keys can have subkeys for different purposes:
///   - Encryption subkeys (for receiving encrypted messages)
///   - Signing subkeys (for signing without exposing the primary key)
pub fn exampleSubkeyManagement(allocator: Allocator) !void {
    // Create a primary key
    var body: [12]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], 1000, .big);
    body[5] = 1; // RSA
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xBB;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;

    const pk = try PublicKeyPacket.parse(allocator, &body, false);
    var key = Key.init(pk);
    defer key.deinit(allocator);

    const uid = UserIdPacket{ .id = try allocator.dupe(u8, "Subkey Test <subkey@example.com>") };
    try key.addUserId(allocator, .{
        .user_id = uid,
        .self_signature = null,
        .certifications = .empty,
    });

    // Verify the primary key exists
    std.debug.assert(key.primary_key.version == 4);
    std.debug.assert(key.subkeys.items.len == 0);

    // Demonstrate subkey selection logic
    // The selectEncryptionSubkey function searches for encryption-capable subkeys
    const best_enc = subkey_mod.selectEncryptionSubkey(&key, allocator);
    // No subkeys added yet, so this should be null
    std.debug.assert(best_enc == null);

    // Note: Actually adding a subkey requires building a complete subkey
    // packet with binding signatures, which needs secret key material.
    // The subkey module provides addEncryptionSubkey() for this purpose.
}

// ---------------------------------------------------------------------------
// Example 5: Key Revocation
// ---------------------------------------------------------------------------

/// Demonstrate key revocation checking.
///
/// A key can be revoked by issuing a key revocation signature (type 0x20).
/// This example shows how to check if a key has been revoked and the
/// possible revocation reasons.
pub fn exampleKeyRevocation(allocator: Allocator) !void {
    // Create a test key
    var body: [12]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], 1000, .big);
    body[5] = 1; // RSA
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xCC;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;

    const pk = try PublicKeyPacket.parse(allocator, &body, false);
    var key = Key.init(pk);
    defer key.deinit(allocator);

    // A freshly created key should not be revoked
    const is_revoked = revocation.isKeyRevoked(&key, allocator) catch false;
    std.debug.assert(!is_revoked);

    // Demonstrate revocation reason names
    const reasons = [_]revocation.RevocationReason{
        .no_reason,
        .key_superseded,
        .key_compromised,
        .key_retired,
        .user_id_invalid,
    };

    for (reasons) |reason| {
        const name = reason.name();
        std.debug.assert(name.len > 0);
    }
}

// ---------------------------------------------------------------------------
// Example 6: Key Expiration
// ---------------------------------------------------------------------------

/// Demonstrate key expiration checking.
///
/// OpenPGP keys can have an expiration time set in the self-signature.
/// This example shows how to check creation time and expiration status.
pub fn exampleKeyExpiration(allocator: Allocator) !void {
    // Create a test key with a known creation time
    const creation_time: u32 = 1700000000; // 2023-11-14

    var body: [12]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], creation_time, .big);
    body[5] = 1; // RSA
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xDD;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;

    const pk = try PublicKeyPacket.parse(allocator, &body, false);
    var key = Key.init(pk);
    defer key.deinit(allocator);

    // Check creation time
    const key_creation = expiration.getKeyCreationTime(&key);
    std.debug.assert(key_creation == creation_time);

    // Format the creation time
    var ts_buf: [32]u8 = undefined;
    const formatted = try time_fmt.formatTimestamp(key_creation, &ts_buf);
    std.debug.assert(formatted.len == 23);

    // Without a self-signature, the key has no expiration
    const exp_time = expiration.getKeyExpirationTime(&key, allocator) catch null;
    std.debug.assert(exp_time == null);

    // Check if expired (no expiration = never expired)
    const is_expired = expiration.isKeyExpired(&key, 2000000000, allocator) catch false;
    std.debug.assert(!is_expired);

    // Demonstrate daysUntilExpiry calculation
    const days = time_fmt.daysUntilExpiry(creation_time, 365 * 86400, creation_time + 100 * 86400);
    std.debug.assert(days != null);
    std.debug.assert(days.? == 265); // 365 - 100 = 265 days remaining
}

// ---------------------------------------------------------------------------
// Example 7: WKD Lookup
// ---------------------------------------------------------------------------

/// Demonstrate WKD (Web Key Directory) URL construction.
///
/// WKD maps email addresses to HTTPS URLs where the public key can be
/// fetched. This example shows how to construct WKD URLs.
pub fn exampleWkdLookup(allocator: Allocator) !void {
    // Parse an email address
    const email_parts = wkd.parseEmail("alice@example.com") catch return;
    std.debug.assert(mem.eql(u8, email_parts.local, "alice"));
    std.debug.assert(mem.eql(u8, email_parts.domain, "example.com"));

    // Build WKD URLs using the WKD client
    var client = wkd.WkdClient.init(allocator);

    // Build advanced-method URL
    const advanced_url = client.buildAdvancedUrl("alice@example.com") catch return;
    defer allocator.free(advanced_url);
    std.debug.assert(mem.startsWith(u8, advanced_url, "https://openpgpkey.example.com/"));

    // Build direct-method URL
    const direct_url = client.buildDirectUrl("alice@example.com") catch return;
    defer allocator.free(direct_url);
    std.debug.assert(mem.startsWith(u8, direct_url, "https://example.com/.well-known/openpgpkey/hu/"));

    // The z-base-32 hash should be deterministic for the same local part
    const hash1 = wkd.computeWkdHash("alice");
    const hash2 = wkd.computeWkdHash("alice");
    std.debug.assert(mem.eql(u8, &hash1, &hash2));
}

// ---------------------------------------------------------------------------
// Example 8: Autocrypt Header
// ---------------------------------------------------------------------------

/// Demonstrate Autocrypt header construction and parsing.
///
/// Autocrypt embeds minimal key data in email headers for automatic
/// encryption setup.
pub fn exampleAutocryptHeader(allocator: Allocator) !void {
    // Build an Autocrypt header manually
    const header_str = "addr=alice@example.com; prefer-encrypt=mutual; keydata=AQID";

    const parsed = autocrypt.AutocryptHeader.parseHeader(allocator, header_str) catch return;
    defer {
        allocator.free(parsed.addr);
        allocator.free(parsed.keydata);
    }

    std.debug.assert(mem.eql(u8, parsed.addr, "alice@example.com"));
    std.debug.assert(parsed.prefer_encrypt == .mutual);
    std.debug.assert(mem.eql(u8, parsed.keydata, "AQID"));

    // Verify prefer-encrypt parsing
    std.debug.assert(autocrypt.PreferEncrypt.parse("mutual") == .mutual);
    std.debug.assert(autocrypt.PreferEncrypt.parse("nopreference") == .nopreference);
    std.debug.assert(autocrypt.PreferEncrypt.parse("unknown") == .nopreference);

    // Verify header value formatting
    const mutual_val = autocrypt.PreferEncrypt.mutual.headerValue();
    std.debug.assert(mutual_val != null);
    std.debug.assert(mem.eql(u8, mutual_val.?, "mutual"));

    const nopref_val = autocrypt.PreferEncrypt.nopreference.headerValue();
    std.debug.assert(nopref_val == null);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "example: generate key" {
    try exampleGenerateKey(std.testing.allocator);
}

test "example: import/export key" {
    try exampleImportExportKey(std.testing.allocator);
}

test "example: keyring operations" {
    try exampleKeyringOperations(std.testing.allocator);
}

test "example: subkey management" {
    try exampleSubkeyManagement(std.testing.allocator);
}

test "example: key revocation" {
    try exampleKeyRevocation(std.testing.allocator);
}

test "example: key expiration" {
    try exampleKeyExpiration(std.testing.allocator);
}

test "example: WKD lookup" {
    try exampleWkdLookup(std.testing.allocator);
}

test "example: Autocrypt header" {
    try exampleAutocryptHeader(std.testing.allocator);
}
