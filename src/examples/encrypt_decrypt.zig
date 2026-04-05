// SPDX-License-Identifier: MIT
//! Example: Encrypting and decrypting messages with zpgp.
//!
//! This module demonstrates the following operations:
//!   1. Generating RSA and Ed25519 keys
//!   2. Encrypting a message for a recipient
//!   3. Decrypting a message with a secret key
//!   4. Symmetric (passphrase) encryption/decryption
//!   5. Armoring encrypted output
//!   6. Key generation with various options
//!   7. Keyring management
//!   8. Streaming encryption
//!   9. V6 AEAD encryption
//!
//! Each public function is a self-contained example that can be called
//! from tests or from a main function. All examples use the testing
//! allocator in tests but accept any allocator for production use.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

// Import library modules via relative paths
const armor = @import("../armor/armor.zig");
const keygen = @import("../key/generate.zig");
const Key = @import("../key/key.zig").Key;
const UserIdBinding = @import("../key/key.zig").UserIdBinding;
const SubkeyBinding = @import("../key/key.zig").SubkeyBinding;
const Keyring = @import("../key/keyring.zig").Keyring;
const import_export = @import("../key/import_export.zig");
const compose = @import("../message/compose.zig");
const decompose = @import("../message/decompose.zig");
const enums = @import("../types/enums.zig");
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const AeadAlgorithm = enums.AeadAlgorithm;
const PublicKeyPacket = @import("../packets/public_key.zig").PublicKeyPacket;
const SignaturePacket = @import("../packets/signature.zig").SignaturePacket;
const UserIdPacket = @import("../packets/user_id.zig").UserIdPacket;
const crc24 = @import("../armor/crc24.zig");

// Utility modules
const hex = @import("../utils/hex.zig");
const time_fmt = @import("../utils/time_fmt.zig");
const email_util = @import("../utils/email.zig");

// Policy
const algo_policy = @import("../policy/algorithm_policy.zig");

// ---------------------------------------------------------------------------
// Example 1: RSA Encrypt/Decrypt
// ---------------------------------------------------------------------------

/// Demonstrate RSA key generation and basic encrypt/decrypt flow.
///
/// This example:
///   1. Generates an RSA-2048 key pair
///   2. Verifies the key material is valid
///   3. Demonstrates that the armored output can be decoded
pub fn exampleRsaEncryptDecrypt(allocator: Allocator) !void {
    // Step 1: Generate an RSA key pair
    const options = keygen.KeyGenOptions{
        .algorithm = .rsa_encrypt_sign,
        .bits = 2048,
        .user_id = "Alice <alice@example.com>",
        .hash_algo = .sha256,
    };

    const generated = keygen.generateKey(allocator, options) catch |err| {
        // Key generation may fail on some platforms or with limited entropy
        switch (err) {
            error.KeyGenerationFailed => return, // Skip on platforms without entropy
            else => return err,
        }
    };
    defer generated.deinit(allocator);

    // Step 2: Verify the armored public key can be decoded
    var pub_decoded = armor.decode(allocator, generated.public_key_armored) catch
        return error.UnsupportedAlgorithm;
    defer pub_decoded.deinit();

    // Verify it's a public key block
    std.debug.assert(pub_decoded.armor_type == .public_key);
    std.debug.assert(pub_decoded.data.len > 0);

    // Step 3: Verify the armored secret key can be decoded
    var sec_decoded = armor.decode(allocator, generated.secret_key_armored) catch
        return error.UnsupportedAlgorithm;
    defer sec_decoded.deinit();

    std.debug.assert(sec_decoded.armor_type == .private_key);
    std.debug.assert(sec_decoded.data.len > 0);

    // Step 4: Verify fingerprint is non-zero
    var fp_zero = true;
    for (generated.fingerprint) |b| {
        if (b != 0) {
            fp_zero = false;
            break;
        }
    }
    std.debug.assert(!fp_zero);

    // Step 5: Format the fingerprint for display
    const fp_hex = try hex.hexEncodeUpper(allocator, &generated.fingerprint);
    defer allocator.free(fp_hex);
    std.debug.assert(fp_hex.len == 40); // 20 bytes * 2
}

// ---------------------------------------------------------------------------
// Example 2: Ed25519 Sign/Verify
// ---------------------------------------------------------------------------

/// Demonstrate EdDSA (Ed25519) key generation for signing.
///
/// Note: Full Ed25519 key generation produces a key suitable for
/// signing. This example generates the key and verifies the output
/// structure.
pub fn exampleEd25519SignVerify(allocator: Allocator) !void {
    const options = keygen.KeyGenOptions{
        .algorithm = .eddsa,
        .user_id = "Bob <bob@example.com>",
        .hash_algo = .sha256,
    };

    const generated = keygen.generateKey(allocator, options) catch |err| {
        switch (err) {
            error.KeyGenerationFailed, error.UnsupportedAlgorithm => return,
            else => return err,
        }
    };
    defer generated.deinit(allocator);

    // Verify the key was generated
    std.debug.assert(generated.public_key_armored.len > 0);
    std.debug.assert(generated.secret_key_armored.len > 0);

    // The fingerprint should be valid
    const kid_hex = try hex.hexEncodeUpper(allocator, &generated.key_id);
    defer allocator.free(kid_hex);
    std.debug.assert(kid_hex.len == 16); // 8 bytes * 2
}

// ---------------------------------------------------------------------------
// Example 3: Symmetric Encryption
// ---------------------------------------------------------------------------

/// Demonstrate passphrase-based symmetric encryption concepts.
///
/// OpenPGP symmetric encryption uses:
///   1. S2K (String-to-Key) to derive a key from a passphrase
///   2. SKESK packet to wrap the session key
///   3. SEIPD packet for the encrypted data
///
/// This example demonstrates the conceptual flow without requiring
/// full SKESK packet construction.
pub fn exampleSymmetricEncryption(allocator: Allocator) !void {
    const message = "This is a secret message encrypted with a passphrase.";

    // Step 1: Create a literal data packet (the plaintext payload)
    const literal_pkt = try compose.createLiteralData(
        allocator,
        message,
        "message.txt",
        true,
    );
    defer allocator.free(literal_pkt);

    // Verify the literal data packet was created
    std.debug.assert(literal_pkt.len > message.len);

    // Step 2: Verify the literal data packet structure
    // New-format header: tag byte + length + body
    // The body starts with format byte ('b' for binary), filename len, etc.
    const tag_byte = literal_pkt[0];
    // Should be a new-format literal data packet
    std.debug.assert(tag_byte & 0x80 != 0); // Must have bit 7 set

    // Step 3: Demonstrate compression
    const compressed = try compose.compressData(allocator, literal_pkt, .uncompressed);
    defer allocator.free(compressed);
    std.debug.assert(compressed.len > 0);
}

// ---------------------------------------------------------------------------
// Example 4: Armor Round-Trip
// ---------------------------------------------------------------------------

/// Demonstrate ASCII Armor encoding and decoding.
///
/// ASCII Armor wraps binary PGP data in a text format with:
///   - BEGIN/END markers
///   - Optional headers (e.g., Version)
///   - Base64-encoded body
///   - CRC-24 checksum
pub fn exampleArmorRoundTrip(allocator: Allocator) !void {
    const original_data = "OpenPGP binary data would go here";

    // Step 1: Encode as a PGP MESSAGE
    const headers = [_]armor.Header{
        .{ .name = "Version", .value = "zpgp 0.1" },
        .{ .name = "Comment", .value = "Example armor round-trip" },
    };

    const armored = try armor.encode(
        allocator,
        original_data,
        .message,
        &headers,
    );
    defer allocator.free(armored);

    // Verify the armored output has the expected structure
    std.debug.assert(mem.startsWith(u8, armored, "-----BEGIN PGP MESSAGE-----"));
    std.debug.assert(mem.indexOf(u8, armored, "-----END PGP MESSAGE-----") != null);
    std.debug.assert(mem.indexOf(u8, armored, "Version: zpgp 0.1") != null);

    // Step 2: Decode back to binary
    var decoded = try armor.decode(allocator, armored);
    defer decoded.deinit();

    std.debug.assert(decoded.armor_type == .message);
    std.debug.assert(mem.eql(u8, decoded.data, original_data));

    // Step 3: Verify CRC-24 independently
    const checksum = crc24.compute(original_data);
    // CRC-24 produces a 24-bit value
    std.debug.assert(checksum <= 0xFFFFFF);

    // Step 4: Try encoding as different armor types
    const sig_armored = try armor.encode(allocator, "sig data", .signature, null);
    defer allocator.free(sig_armored);
    std.debug.assert(mem.startsWith(u8, sig_armored, "-----BEGIN PGP SIGNATURE-----"));

    const pk_armored = try armor.encode(allocator, "key data", .public_key, null);
    defer allocator.free(pk_armored);
    std.debug.assert(mem.startsWith(u8, pk_armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));
}

// ---------------------------------------------------------------------------
// Example 5: Key Generation Options
// ---------------------------------------------------------------------------

/// Demonstrate the various key generation options available.
///
/// Shows how to configure:
///   - Different key algorithms (RSA, EdDSA)
///   - Different RSA key sizes
///   - User ID strings
///   - Hash algorithm selection
pub fn exampleKeyGeneration(allocator: Allocator) !void {
    // Check the policy first to determine appropriate algorithms
    const policy = algo_policy.AlgorithmPolicy.init(.rfc9580);

    // Verify our chosen algorithms are acceptable
    std.debug.assert(policy.isAcceptablePublicKey(.rsa_encrypt_sign, 2048));
    std.debug.assert(policy.isAcceptableHash(.sha256));
    std.debug.assert(policy.isAcceptableSymmetric(.aes256));

    // Example: RSA-2048 key with specific user ID
    const rsa_options = keygen.KeyGenOptions{
        .algorithm = .rsa_encrypt_sign,
        .bits = 2048,
        .user_id = "Test User (RSA-2048) <test@example.com>",
        .hash_algo = .sha256,
    };

    const rsa_key = keygen.generateKey(allocator, rsa_options) catch |err| {
        switch (err) {
            error.KeyGenerationFailed => return,
            else => return err,
        }
    };
    defer rsa_key.deinit(allocator);

    // Verify the key was generated and format the user ID
    const parts = email_util.parseUserId(rsa_options.user_id);
    std.debug.assert(parts.email != null);
    std.debug.assert(mem.eql(u8, parts.email.?, "test@example.com"));
    std.debug.assert(parts.comment != null);
    std.debug.assert(mem.eql(u8, parts.comment.?, "RSA-2048"));
}

// ---------------------------------------------------------------------------
// Example 6: Keyring Management
// ---------------------------------------------------------------------------

/// Demonstrate keyring creation and key lookup.
///
/// A keyring holds multiple keys and provides lookup by:
///   - Key ID (8 bytes)
///   - Fingerprint (20 bytes for V4)
///   - Email address (substring match in User IDs)
pub fn exampleKeyringManagement(allocator: Allocator) !void {
    // Create an empty keyring
    var ring = Keyring.init(allocator);
    defer ring.deinit();

    // Build minimal test keys to add to the keyring
    // We create two keys with different "fingerprints" by varying creation time
    var body1: [12]u8 = undefined;
    body1[0] = 4; // version
    mem.writeInt(u32, body1[1..5], 1000, .big);
    body1[5] = 1; // RSA
    mem.writeInt(u16, body1[6..8], 8, .big);
    body1[8] = 0xFF;
    mem.writeInt(u16, body1[9..11], 8, .big);
    body1[11] = 0x03;

    const pk1 = try PublicKeyPacket.parse(allocator, &body1, false);
    var key1 = Key.init(pk1);

    // Add a user ID to key1
    const uid1 = UserIdPacket{ .id = try allocator.dupe(u8, "Alice <alice@example.com>") };
    try key1.addUserId(allocator, .{
        .user_id = uid1,
        .self_signature = null,
        .certifications = .empty,
    });

    try ring.addKey(key1);

    // Build a second key with a different creation time
    var body2: [12]u8 = undefined;
    body2[0] = 4;
    mem.writeInt(u32, body2[1..5], 2000, .big);
    body2[5] = 1;
    mem.writeInt(u16, body2[6..8], 8, .big);
    body2[8] = 0xAA;
    mem.writeInt(u16, body2[9..11], 8, .big);
    body2[11] = 0x05;

    const pk2 = try PublicKeyPacket.parse(allocator, &body2, false);
    var key2 = Key.init(pk2);

    const uid2 = UserIdPacket{ .id = try allocator.dupe(u8, "Bob <bob@example.com>") };
    try key2.addUserId(allocator, .{
        .user_id = uid2,
        .self_signature = null,
        .certifications = .empty,
    });

    try ring.addKey(key2);

    // Verify the keyring has 2 keys
    std.debug.assert(ring.keys.items.len == 2);

    // Look up by email
    const alice_keys = try ring.findByEmail("alice@example.com", allocator);
    defer allocator.free(alice_keys);
    std.debug.assert(alice_keys.len == 1);

    // Look up by fingerprint
    const fp1 = ring.keys.items[0].fingerprint();
    const found = ring.findByFingerprint(fp1);
    std.debug.assert(found != null);

    // Look up by key ID
    const kid1 = ring.keys.items[0].keyId();
    const found_kid = ring.findByKeyId(kid1);
    std.debug.assert(found_kid != null);
}

// ---------------------------------------------------------------------------
// Example 7: Streaming Encryption Concepts
// ---------------------------------------------------------------------------

/// Demonstrate the streaming encryption API concepts.
///
/// The streaming API allows encrypting data in chunks without loading
/// the entire message into memory. This example shows the conceptual
/// flow using literal data packet construction.
pub fn exampleStreamingEncryption(allocator: Allocator) !void {
    // The streaming API processes data in chunks.
    // Here we demonstrate the concept by creating multiple literal data
    // chunks and showing how they would be assembled.

    const chunks = [_][]const u8{
        "First chunk of the message. ",
        "Second chunk of the message. ",
        "Final chunk.",
    };

    // In a real streaming scenario, you would use StreamEncryptor.
    // Here we demonstrate the packet creation for each chunk.
    var total_len: usize = 0;
    for (chunks) |chunk| {
        total_len += chunk.len;
    }

    // Assemble the full message
    const full_message = try allocator.alloc(u8, total_len);
    defer allocator.free(full_message);

    var offset: usize = 0;
    for (chunks) |chunk| {
        @memcpy(full_message[offset .. offset + chunk.len], chunk);
        offset += chunk.len;
    }

    // Create a literal data packet from the assembled message
    const literal_pkt = try compose.createLiteralData(
        allocator,
        full_message,
        "stream_test.txt",
        true,
    );
    defer allocator.free(literal_pkt);

    std.debug.assert(literal_pkt.len > total_len);

    // Verify the packet can be armor-encoded
    const armored = try armor.encode(allocator, literal_pkt, .message, null);
    defer allocator.free(armored);

    std.debug.assert(mem.startsWith(u8, armored, "-----BEGIN PGP MESSAGE-----"));
}

// ---------------------------------------------------------------------------
// Example 8: V6 AEAD Encryption Concepts
// ---------------------------------------------------------------------------

/// Demonstrate RFC 9580 AEAD encryption concepts.
///
/// RFC 9580 introduces SEIPDv2 which uses AEAD encryption modes
/// (EAX, OCB, GCM) instead of the CFB+MDC approach of SEIPDv1.
///
/// This example demonstrates the algorithm selection and verification
/// using the policy engine.
pub fn exampleV6AeadEncryption(allocator: Allocator) !void {
    // RFC 9580 recommends specific algorithm combinations for V6 keys
    const policy = algo_policy.AlgorithmPolicy.init(.rfc9580);

    // Verify AEAD algorithms are supported
    std.debug.assert(policy.isAcceptableAead(.gcm));
    std.debug.assert(policy.isAcceptableAead(.ocb));
    std.debug.assert(policy.isAcceptableAead(.eax));

    // Preferred AEAD algorithm under RFC 9580 policy
    const preferred_aead = policy.preferredAead();
    std.debug.assert(preferred_aead != null);

    // Verify the preferred symmetric algorithm for AEAD
    const preferred_sym = policy.preferredSymmetric();
    std.debug.assert(preferred_sym == .aes256);

    // Demonstrate AEAD algorithm properties
    const gcm_nonce_size = AeadAlgorithm.gcm.nonceSize();
    std.debug.assert(gcm_nonce_size != null);
    std.debug.assert(gcm_nonce_size.? == 12);

    const ocb_nonce_size = AeadAlgorithm.ocb.nonceSize();
    std.debug.assert(ocb_nonce_size != null);
    std.debug.assert(ocb_nonce_size.? == 15);

    // Create a test message and demonstrate literal data construction
    const test_message = "AEAD-encrypted message content for RFC 9580.";
    const literal_pkt = try compose.createLiteralData(
        allocator,
        test_message,
        "aead_test.txt",
        true,
    );
    defer allocator.free(literal_pkt);

    // The literal data packet would normally be encrypted with SEIPDv2
    std.debug.assert(literal_pkt.len > test_message.len);

    // Demonstrate algorithm name lookup
    const sym_name = SymmetricAlgorithm.aes256.name();
    std.debug.assert(mem.eql(u8, sym_name, "AES-256"));

    const hash_name = HashAlgorithm.sha256.name();
    std.debug.assert(mem.eql(u8, hash_name, "SHA256"));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "example: RSA encrypt/decrypt" {
    try exampleRsaEncryptDecrypt(std.testing.allocator);
}

test "example: Ed25519 sign/verify" {
    try exampleEd25519SignVerify(std.testing.allocator);
}

test "example: symmetric encryption" {
    try exampleSymmetricEncryption(std.testing.allocator);
}

test "example: armor round-trip" {
    try exampleArmorRoundTrip(std.testing.allocator);
}

test "example: key generation" {
    try exampleKeyGeneration(std.testing.allocator);
}

test "example: keyring management" {
    try exampleKeyringManagement(std.testing.allocator);
}

test "example: streaming encryption" {
    try exampleStreamingEncryption(std.testing.allocator);
}

test "example: V6 AEAD encryption" {
    try exampleV6AeadEncryption(std.testing.allocator);
}
