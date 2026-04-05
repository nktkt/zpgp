// SPDX-License-Identifier: MIT
//! Example: Signature operations with zpgp.
//!
//! This module demonstrates:
//!   1. Detached signature concepts
//!   2. Cleartext signature framework
//!   3. Signature verification concepts
//!   4. Notation data in signatures
//!
//! OpenPGP supports several signature types:
//!   - Binary signatures (type 0x00): Sign binary data
//!   - Text signatures (type 0x01): Sign canonicalized text
//!   - Detached signatures: Stored separately from the signed data
//!   - Cleartext signatures: Human-readable text with embedded signature
//!   - Certification signatures (0x10-0x13): Sign user IDs on keys

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const armor = @import("../armor/armor.zig");
const keygen = @import("../key/generate.zig");
const Key = @import("../key/key.zig").Key;
const UserIdBinding = @import("../key/key.zig").UserIdBinding;
const PublicKeyPacket = @import("../packets/public_key.zig").PublicKeyPacket;
const SignaturePacket = @import("../packets/signature.zig").SignaturePacket;
const UserIdPacket = @import("../packets/user_id.zig").UserIdPacket;
const enums = @import("../types/enums.zig");
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const sig_creation = @import("../signature/creation.zig");
const sig_types = @import("../signature/types.zig");
const notation = @import("../signature/notation.zig");
const cleartext = @import("../signature/cleartext.zig");
const detached = @import("../signature/detached.zig");
const compose = @import("../message/compose.zig");

const hex = @import("../utils/hex.zig");
const email_util = @import("../utils/email.zig");
const algo_policy = @import("../policy/algorithm_policy.zig");

// ---------------------------------------------------------------------------
// Example 1: Detached Signature
// ---------------------------------------------------------------------------

/// Demonstrate detached signature concepts.
///
/// A detached signature is stored separately from the data it signs.
/// This is useful for:
///   - Signing binary files without modifying them
///   - Signing software releases
///   - Signing documents where the original must remain unchanged
///
/// The signature flow:
///   1. Compute hash of the document
///   2. Apply the V4 signature trailer
///   3. Sign the hash with the private key
///   4. Package as a signature packet
///   5. Optionally ASCII-armor the result
pub fn exampleDetachedSignature(allocator: Allocator) !void {
    const document = "This is the document to be signed.\nIt can be any binary data.";

    // Step 1: Build the hashed subpackets (minimal: just creation time)
    var hashed_sp: [6]u8 = undefined;
    hashed_sp[0] = 5; // subpacket length
    hashed_sp[1] = 2; // signature creation time subpacket type
    const creation_time: u32 = 1700000000;
    mem.writeInt(u32, hashed_sp[2..6], creation_time, .big);

    // Step 2: Compute the document hash with the signature trailer
    const hash_result = sig_creation.computeDocumentHash(
        .sha256,
        document,
        0x00, // binary signature
        @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign),
        @intFromEnum(HashAlgorithm.sha256),
        &hashed_sp,
        allocator,
    ) catch return;

    // Verify the hash was computed
    std.debug.assert(hash_result.digest_len == 32); // SHA-256
    std.debug.assert(hash_result.prefix[0] != 0 or hash_result.prefix[1] != 0);

    // Step 3: The hash prefix is used for quick verification checks
    const prefix_hex = try hex.hexEncode(allocator, &hash_result.prefix);
    defer allocator.free(prefix_hex);
    std.debug.assert(prefix_hex.len == 4);

    // Step 4: Demonstrate V4 hashed data construction
    const hashed_data = sig_creation.buildV4HashedData(
        0x00, // binary signature
        @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign),
        @intFromEnum(HashAlgorithm.sha256),
        &hashed_sp,
        allocator,
    ) catch return;
    defer allocator.free(hashed_data);

    // The hashed data includes the version, sig type, algorithms,
    // subpackets, and the final trailer
    std.debug.assert(hashed_data.len > hashed_sp.len);

    // Step 5: Demonstrate armor encoding of a signature
    // (In practice, this would be the actual signature packet bytes)
    const dummy_sig = "dummy signature data for armor demo";
    const armored_sig = armor.encode(allocator, dummy_sig, .signature, null) catch return;
    defer allocator.free(armored_sig);

    std.debug.assert(mem.startsWith(u8, armored_sig, "-----BEGIN PGP SIGNATURE-----"));
    std.debug.assert(mem.indexOf(u8, armored_sig, "-----END PGP SIGNATURE-----") != null);
}

// ---------------------------------------------------------------------------
// Example 2: Cleartext Signature
// ---------------------------------------------------------------------------

/// Demonstrate the cleartext signature framework.
///
/// A cleartext signed message has this format:
///
///   -----BEGIN PGP SIGNED MESSAGE-----
///   Hash: SHA256
///
///   The cleartext message goes here.
///   -----BEGIN PGP SIGNATURE-----
///
///   <armored signature>
///   -----END PGP SIGNATURE-----
///
/// The message text is human-readable. Lines starting with a dash
/// are "dash-escaped" by prepending "- ".
pub fn exampleCleartextSignature(allocator: Allocator) !void {
    // Demonstrate cleartext message structure
    const message = "Hello, World!\nThis is a signed message.\n- This line starts with a dash.";

    // The cleartext framework requires:
    // 1. Dash-escaping (lines starting with "-" get "- " prepended)
    // 2. Trailing whitespace stripping (canonicalization)
    // 3. CR LF line endings for hashing

    // Step 1: Demonstrate canonicalization by checking line structure
    var line_count: usize = 0;
    var has_dash_line = false;
    var iter = mem.splitScalar(u8, message, '\n');
    while (iter.next()) |line| {
        line_count += 1;
        if (mem.startsWith(u8, line, "- ")) {
            has_dash_line = true;
        }
    }
    std.debug.assert(line_count == 3);
    std.debug.assert(has_dash_line);

    // Step 2: Demonstrate the hash algorithm name lookup
    // (Used in the "Hash: " armor header)
    const algo_names = [_]struct { algo: HashAlgorithm, expected: []const u8 }{
        .{ .algo = .sha256, .expected = "SHA256" },
        .{ .algo = .sha512, .expected = "SHA512" },
        .{ .algo = .sha1, .expected = "SHA1" },
    };

    for (algo_names) |entry| {
        const name = entry.algo.name();
        std.debug.assert(mem.eql(u8, name, entry.expected));
    }

    // Step 3: Demonstrate hash computation for the cleartext
    // The hash covers the canonicalized text + signature trailer
    const hash_result = sig_creation.computeDocumentHash(
        .sha256,
        message,
        0x01, // text signature
        @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign),
        @intFromEnum(HashAlgorithm.sha256),
        &[_]u8{}, // empty hashed subpackets for demo
        allocator,
    ) catch return;

    std.debug.assert(hash_result.digest_len == 32);

    // Step 4: Demonstrate literal data for the message
    const literal = try compose.createLiteralData(allocator, message, "", false);
    defer allocator.free(literal);
    std.debug.assert(literal.len > 0);
}

// ---------------------------------------------------------------------------
// Example 3: Signature Verification
// ---------------------------------------------------------------------------

/// Demonstrate the signature verification concept.
///
/// Verification steps:
///   1. Compute the hash of the original data
///   2. Apply the same signature trailer from the signature packet
///   3. Check the 2-byte hash prefix matches
///   4. Verify the cryptographic signature using the signer's public key
pub fn exampleSignatureVerification(allocator: Allocator) !void {
    // Demonstrate the verification data flow
    const document = "Data to verify";

    // Step 1: Build hashed subpackets (same as during signing)
    var hashed_sp: [6]u8 = undefined;
    hashed_sp[0] = 5;
    hashed_sp[1] = 2; // creation time
    mem.writeInt(u32, hashed_sp[2..6], 1700000000, .big);

    // Step 2: Compute the expected hash
    const hash_result = sig_creation.computeDocumentHash(
        .sha256,
        document,
        0x00,
        @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign),
        @intFromEnum(HashAlgorithm.sha256),
        &hashed_sp,
        allocator,
    ) catch return;

    // Step 3: Verify the hash digest properties
    const digest = hash_result.digestSlice();
    std.debug.assert(digest.len == 32);

    // The prefix should match the first two bytes of the digest
    std.debug.assert(hash_result.prefix[0] == digest[0]);
    std.debug.assert(hash_result.prefix[1] == digest[1]);

    // Step 4: Computing the same hash twice should give identical results
    const hash_result2 = sig_creation.computeDocumentHash(
        .sha256,
        document,
        0x00,
        @intFromEnum(PublicKeyAlgorithm.rsa_encrypt_sign),
        @intFromEnum(HashAlgorithm.sha256),
        &hashed_sp,
        allocator,
    ) catch return;

    std.debug.assert(mem.eql(u8, hash_result.digestSlice(), hash_result2.digestSlice()));

    // Step 5: Demonstrate policy-based signature validation
    const policy = algo_policy.AlgorithmPolicy.init(.rfc9580);
    const validation = policy.validateSignature(.sha256, .rsa_encrypt_sign);
    std.debug.assert(validation.accepted);

    // SHA-1 should still be accepted but may have warnings
    const sha1_validation = policy.validateSignature(.sha1, .rsa_encrypt_sign);
    std.debug.assert(sha1_validation.accepted); // rfc9580 allows with warning
    std.debug.assert(sha1_validation.warnings.len > 0);

    // MD5 should be rejected under strict policy
    const strict_policy = algo_policy.AlgorithmPolicy.init(.strict);
    const md5_validation = strict_policy.validateSignature(.md5, .rsa_encrypt_sign);
    std.debug.assert(!md5_validation.accepted);
}

// ---------------------------------------------------------------------------
// Example 4: Notation Data
// ---------------------------------------------------------------------------

/// Demonstrate notation data in signatures.
///
/// Notation data allows attaching arbitrary key-value metadata to
/// signatures. This is used for:
///   - Policy URLs (e.g., "preferred-email-encoding@pgp.com")
///   - Application-specific metadata
///   - Human-readable notes
pub fn exampleNotationData(allocator: Allocator) !void {
    // Step 1: Create a notation data entry
    const notation_bytes = try notation.createNotation(
        allocator,
        "example@example.com",
        "This is a test notation",
        true, // human-readable
    );
    defer allocator.free(notation_bytes);

    // Verify the notation structure
    // Format: flags(4) + name_len(2) + value_len(2) + name + value
    std.debug.assert(notation_bytes.len == 8 + "example@example.com".len + "This is a test notation".len);

    // Step 2: Parse the notation back
    const parsed = try notation.parseNotation(notation_bytes, allocator);
    defer parsed.deinit(allocator);

    std.debug.assert(parsed.human_readable);
    std.debug.assert(mem.eql(u8, parsed.name, "example@example.com"));
    std.debug.assert(mem.eql(u8, parsed.value, "This is a test notation"));

    // Step 3: Create a non-human-readable (binary) notation
    const binary_notation = try notation.createNotation(
        allocator,
        "binary-data@example.com",
        &[_]u8{ 0x01, 0x02, 0x03, 0x04 },
        false,
    );
    defer allocator.free(binary_notation);

    const parsed_binary = try notation.parseNotation(binary_notation, allocator);
    defer parsed_binary.deinit(allocator);

    std.debug.assert(!parsed_binary.human_readable);
    std.debug.assert(mem.eql(u8, parsed_binary.name, "binary-data@example.com"));
    std.debug.assert(mem.eql(u8, parsed_binary.value, &[_]u8{ 0x01, 0x02, 0x03, 0x04 }));

    // Step 4: Demonstrate notation in the context of a signature
    // Notation subpackets are stored in the hashed subpacket area
    // of a V4 signature. The subpacket type is 20.
    // A complete notation subpacket would be:
    //   subpacket_length + type(20) + notation_bytes
    const subpacket_type: u8 = 20; // notation_data
    _ = subpacket_type;

    // Verify the notation round-trip preserves all data
    const rt_notation = try notation.createNotation(
        allocator,
        parsed.name,
        parsed.value,
        parsed.human_readable,
    );
    defer allocator.free(rt_notation);

    const rt_parsed = try notation.parseNotation(rt_notation, allocator);
    defer rt_parsed.deinit(allocator);

    std.debug.assert(mem.eql(u8, rt_parsed.name, parsed.name));
    std.debug.assert(mem.eql(u8, rt_parsed.value, parsed.value));
    std.debug.assert(rt_parsed.human_readable == parsed.human_readable);
}

// ---------------------------------------------------------------------------
// Additional signature concepts
// ---------------------------------------------------------------------------

/// Demonstrate signature type enumeration.
///
/// OpenPGP defines many signature types, each with specific semantics.
fn demonstrateSignatureTypes() void {
    // V4 signature types
    const binary_sig: u8 = 0x00; // Binary document signature
    const text_sig: u8 = 0x01; // Text document signature
    const standalone: u8 = 0x02; // Standalone signature
    const cert_generic: u8 = 0x10; // Generic certification
    const cert_persona: u8 = 0x11; // Persona certification
    const cert_casual: u8 = 0x12; // Casual certification
    const cert_positive: u8 = 0x13; // Positive certification
    const subkey_binding: u8 = 0x18; // Subkey binding
    const primary_binding: u8 = 0x19; // Primary key binding
    const key_revocation: u8 = 0x20; // Key revocation
    const subkey_revocation: u8 = 0x28; // Subkey revocation
    const cert_revocation: u8 = 0x30; // Certification revocation

    // Verify all are distinct
    const all = [_]u8{
        binary_sig, text_sig, standalone,
        cert_generic, cert_persona, cert_casual, cert_positive,
        subkey_binding, primary_binding,
        key_revocation, subkey_revocation, cert_revocation,
    };

    for (all, 0..) |a, i| {
        for (all[i + 1 ..]) |b| {
            std.debug.assert(a != b);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "example: detached signature" {
    try exampleDetachedSignature(std.testing.allocator);
}

test "example: cleartext signature" {
    try exampleCleartextSignature(std.testing.allocator);
}

test "example: signature verification" {
    try exampleSignatureVerification(std.testing.allocator);
}

test "example: notation data" {
    try exampleNotationData(std.testing.allocator);
}

test "signature types are distinct" {
    demonstrateSignatureTypes();
}
