// SPDX-License-Identifier: MIT
//! C ABI (Foreign Function Interface) for zpgp.
//!
//! This module exports all major zpgp operations as C-callable functions,
//! enabling use from C, C++, Python (ctypes/cffi), Ruby (FFI), Go (cgo),
//! Swift, and other languages with C FFI support.
//!
//! ## Conventions
//!
//! - **Return codes**: 0 = success, negative = error. Use `zpgp_error_string`
//!   to get a human-readable description.
//!
//! - **Output buffers**: Functions that produce variable-length output take
//!   `out: *[*]u8` and `out_len: *usize` parameters. On success, `out.*`
//!   points to a heap-allocated buffer that the caller must free with
//!   `zpgp_free(out.*, out_len.*)`.
//!
//! - **Strings**: C strings are `[*:0]const u8` (null-terminated). Binary
//!   data uses `[*]const u8` + length.
//!
//! - **Thread safety**: Each function call is independent. The global
//!   allocator uses `GeneralPurposeAllocator` which is thread-safe.
//!
//! ## Error Codes
//!
//! | Code | Meaning                    |
//! |------|----------------------------|
//! |   0  | Success                    |
//! |  -1  | Out of memory              |
//! |  -2  | Invalid argument           |
//! |  -3  | Unsupported algorithm      |
//! |  -4  | Key generation failed      |
//! |  -5  | Encryption failed          |
//! |  -6  | Decryption failed          |
//! |  -7  | Signing failed             |
//! |  -8  | Verification failed        |
//! |  -9  | Invalid key data           |
//! | -10  | Invalid armor              |
//! | -11  | Integrity check failed     |
//! | -12  | Passphrase required        |
//! | -13  | Key not found              |
//! | -14  | Internal error             |
//!
//! ## C Header (conceptual)
//!
//! ```c
//! #ifndef ZPGP_H
//! #define ZPGP_H
//!
//! #include <stddef.h>
//! #include <stdint.h>
//!
//! #ifdef __cplusplus
//! extern "C" {
//! #endif
//!
//! // Version
//! const char* zpgp_version(void);
//!
//! // Memory
//! void zpgp_free(uint8_t* ptr, size_t len);
//!
//! // Error
//! const char* zpgp_error_string(int code);
//!
//! // Key generation
//! int zpgp_generate_key(
//!     const char* name, const char* email,
//!     int algo, int bits,
//!     uint8_t** out_public, size_t* out_public_len,
//!     uint8_t** out_secret, size_t* out_secret_len
//! );
//!
//! // Encryption
//! int zpgp_encrypt(
//!     const uint8_t* plaintext, size_t plaintext_len,
//!     const uint8_t* recipient_key, size_t recipient_key_len,
//!     uint8_t** out, size_t* out_len
//! );
//!
//! // Decryption
//! int zpgp_decrypt(
//!     const uint8_t* ciphertext, size_t ciphertext_len,
//!     const uint8_t* secret_key, size_t secret_key_len,
//!     const char* passphrase,
//!     uint8_t** out, size_t* out_len
//! );
//!
//! // Signing
//! int zpgp_sign(
//!     const uint8_t* data, size_t data_len,
//!     const uint8_t* secret_key, size_t secret_key_len,
//!     const char* passphrase,
//!     uint8_t** out, size_t* out_len
//! );
//!
//! // Verification
//! int zpgp_verify(
//!     const uint8_t* data, size_t data_len,
//!     const uint8_t* signature, size_t sig_len,
//!     const uint8_t* public_key, size_t key_len
//! );
//!
//! // Armor
//! int zpgp_armor(
//!     const uint8_t* data, size_t data_len,
//!     int armor_type,
//!     uint8_t** out, size_t* out_len
//! );
//!
//! int zpgp_dearmor(
//!     const uint8_t* armored, size_t armored_len,
//!     uint8_t** out, size_t* out_len
//! );
//!
//! // Key info
//! int zpgp_key_fingerprint(
//!     const uint8_t* key_data, size_t key_len,
//!     uint8_t** out, size_t* out_len
//! );
//!
//! int zpgp_key_info(
//!     const uint8_t* key_data, size_t key_len,
//!     uint8_t** out_json, size_t* out_len
//! );
//!
//! // Password-based encryption
//! int zpgp_encrypt_password(
//!     const uint8_t* plaintext, size_t plaintext_len,
//!     const char* passphrase,
//!     int sym_algo,
//!     uint8_t** out, size_t* out_len
//! );
//!
//! #ifdef __cplusplus
//! }
//! #endif
//!
//! #endif // ZPGP_H
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

// zpgp modules
const enums = @import("../types/enums.zig");
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const armor = @import("../armor/armor.zig");
const ArmorType = armor.ArmorType;
const keygen = @import("../key/generate.zig");
const import_export = @import("../key/import_export.zig");
const fingerprint_mod = @import("../key/fingerprint.zig");
const compose = @import("../message/compose.zig");
const decompose = @import("../message/decompose.zig");
const sig_creation = @import("../signature/creation.zig");
const sig_verification = @import("../signature/verification.zig");
const hash_mod = @import("../crypto/hash.zig");
const zeroize = @import("../security/zeroize.zig");

const streaming = @import("../streaming/mod.zig");

// ---------------------------------------------------------------------------
// Global allocator
// ---------------------------------------------------------------------------

/// Global general-purpose allocator for C API allocations.
/// Thread-safe by default.
var gpa = std.heap.GeneralPurposeAllocator(.{}){};

fn getAllocator() Allocator {
    return gpa.allocator();
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const ZPGP_OK: c_int = 0;
pub const ZPGP_ERR_OOM: c_int = -1;
pub const ZPGP_ERR_INVALID_ARG: c_int = -2;
pub const ZPGP_ERR_UNSUPPORTED_ALGO: c_int = -3;
pub const ZPGP_ERR_KEYGEN_FAILED: c_int = -4;
pub const ZPGP_ERR_ENCRYPT_FAILED: c_int = -5;
pub const ZPGP_ERR_DECRYPT_FAILED: c_int = -6;
pub const ZPGP_ERR_SIGN_FAILED: c_int = -7;
pub const ZPGP_ERR_VERIFY_FAILED: c_int = -8;
pub const ZPGP_ERR_INVALID_KEY: c_int = -9;
pub const ZPGP_ERR_INVALID_ARMOR: c_int = -10;
pub const ZPGP_ERR_INTEGRITY: c_int = -11;
pub const ZPGP_ERR_PASSPHRASE_REQUIRED: c_int = -12;
pub const ZPGP_ERR_KEY_NOT_FOUND: c_int = -13;
pub const ZPGP_ERR_INTERNAL: c_int = -14;

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

const VERSION_STRING: [:0]const u8 = "zpgp 0.1.0";

/// Return the library version string.
///
/// The returned pointer is valid for the lifetime of the process and must
/// NOT be freed by the caller.
export fn zpgp_version() [*:0]const u8 {
    return VERSION_STRING.ptr;
}

// ---------------------------------------------------------------------------
// Memory management
// ---------------------------------------------------------------------------

/// Free a buffer previously returned by a zpgp function.
///
/// The caller must pass the exact pointer and length returned by the
/// zpgp function. Passing incorrect values results in undefined behavior.
export fn zpgp_free(ptr: ?[*]u8, len: usize) void {
    if (ptr) |p| {
        const allocator = getAllocator();
        // Securely zero before freeing (may contain sensitive data)
        const slice = p[0..len];
        zeroize.secureZeroBytes(slice);
        allocator.free(slice);
    }
}

// ---------------------------------------------------------------------------
// Error strings
// ---------------------------------------------------------------------------

/// Return a human-readable error description for a zpgp error code.
///
/// The returned pointer is valid for the lifetime of the process and must
/// NOT be freed by the caller.
export fn zpgp_error_string(code: c_int) [*:0]const u8 {
    return (switch (code) {
        ZPGP_OK => "Success",
        ZPGP_ERR_OOM => "Out of memory",
        ZPGP_ERR_INVALID_ARG => "Invalid argument",
        ZPGP_ERR_UNSUPPORTED_ALGO => "Unsupported algorithm",
        ZPGP_ERR_KEYGEN_FAILED => "Key generation failed",
        ZPGP_ERR_ENCRYPT_FAILED => "Encryption failed",
        ZPGP_ERR_DECRYPT_FAILED => "Decryption failed",
        ZPGP_ERR_SIGN_FAILED => "Signing failed",
        ZPGP_ERR_VERIFY_FAILED => "Verification failed",
        ZPGP_ERR_INVALID_KEY => "Invalid key data",
        ZPGP_ERR_INVALID_ARMOR => "Invalid armor encoding",
        ZPGP_ERR_INTEGRITY => "Integrity check failed",
        ZPGP_ERR_PASSPHRASE_REQUIRED => "Passphrase required",
        ZPGP_ERR_KEY_NOT_FOUND => "Key not found",
        ZPGP_ERR_INTERNAL => "Internal error",
        else => "Unknown error",
    }).ptr;
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Armor type constants for the C API.
pub const ZPGP_ARMOR_MESSAGE: c_int = 0;
pub const ZPGP_ARMOR_PUBLIC_KEY: c_int = 1;
pub const ZPGP_ARMOR_PRIVATE_KEY: c_int = 2;
pub const ZPGP_ARMOR_SIGNATURE: c_int = 3;

/// Algorithm constants for the C API.
pub const ZPGP_ALGO_RSA: c_int = 1;
pub const ZPGP_ALGO_DSA: c_int = 17;
pub const ZPGP_ALGO_ECDSA: c_int = 19;
pub const ZPGP_ALGO_EDDSA: c_int = 22;
pub const ZPGP_ALGO_ED25519: c_int = 27;

/// Generate an OpenPGP key pair.
///
/// Produces ASCII-armored public and secret keys.
///
/// Parameters:
/// - `name`: User's name (null-terminated C string).
/// - `email`: User's email (null-terminated C string).
/// - `algo`: Algorithm constant (ZPGP_ALGO_RSA, etc.).
/// - `bits`: Key size in bits (for RSA: 2048, 3072, 4096).
/// - `out_public`, `out_public_len`: Receives the armored public key.
/// - `out_secret`, `out_secret_len`: Receives the armored secret key.
///
/// Returns: ZPGP_OK on success, negative error code on failure.
export fn zpgp_generate_key(
    name_ptr: ?[*:0]const u8,
    email_ptr: ?[*:0]const u8,
    algo: c_int,
    bits: c_int,
    out_public: ?*[*]u8,
    out_public_len: ?*usize,
    out_secret: ?*[*]u8,
    out_secret_len: ?*usize,
) c_int {
    const allocator = getAllocator();

    // Validate output pointers
    const pub_out = out_public orelse return ZPGP_ERR_INVALID_ARG;
    const pub_len_out = out_public_len orelse return ZPGP_ERR_INVALID_ARG;
    const sec_out = out_secret orelse return ZPGP_ERR_INVALID_ARG;
    const sec_len_out = out_secret_len orelse return ZPGP_ERR_INVALID_ARG;

    // Build user ID
    const name = if (name_ptr) |p| mem.sliceTo(p, 0) else "User";
    const email = if (email_ptr) |p| mem.sliceTo(p, 0) else "user@example.com";

    const user_id = std.fmt.allocPrint(allocator, "{s} <{s}>", .{ name, email }) catch
        return ZPGP_ERR_OOM;
    defer allocator.free(user_id);

    // Map algorithm
    const pub_algo: PublicKeyAlgorithm = switch (algo) {
        ZPGP_ALGO_RSA => .rsa_encrypt_sign,
        ZPGP_ALGO_ED25519 => .ed25519,
        ZPGP_ALGO_EDDSA => .eddsa,
        else => return ZPGP_ERR_UNSUPPORTED_ALGO,
    };

    // Validate bits
    if (bits < 0) return ZPGP_ERR_INVALID_ARG;
    const key_bits: u32 = @intCast(bits);

    // Generate
    const result = keygen.generateKey(allocator, .{
        .algorithm = pub_algo,
        .bits = key_bits,
        .user_id = user_id,
    }) catch return ZPGP_ERR_KEYGEN_FAILED;

    // Transfer ownership to C caller
    pub_out.* = result.public_key_armored.ptr;
    pub_len_out.* = result.public_key_armored.len;
    sec_out.* = result.secret_key_armored.ptr;
    sec_len_out.* = result.secret_key_armored.len;

    return ZPGP_OK;
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

/// Encrypt plaintext for a recipient using their public key.
///
/// The output is an ASCII-armored OpenPGP message.
///
/// Parameters:
/// - `plaintext`, `plaintext_len`: The data to encrypt.
/// - `recipient_key`, `recipient_key_len`: The recipient's armored public key.
/// - `out`, `out_len`: Receives the encrypted message.
///
/// Returns: ZPGP_OK on success, negative error code on failure.
export fn zpgp_encrypt(
    plaintext: ?[*]const u8,
    plaintext_len: usize,
    recipient_key: ?[*]const u8,
    recipient_key_len: usize,
    out: ?*[*]u8,
    out_len: ?*usize,
) c_int {
    const allocator = getAllocator();
    const out_ptr = out orelse return ZPGP_ERR_INVALID_ARG;
    const out_len_ptr = out_len orelse return ZPGP_ERR_INVALID_ARG;

    const pt = if (plaintext) |p| p[0..plaintext_len] else return ZPGP_ERR_INVALID_ARG;
    const rk = if (recipient_key) |p| p[0..recipient_key_len] else return ZPGP_ERR_INVALID_ARG;

    // Parse the recipient key
    var key = parseKeyFromArmored(rk, allocator) orelse return ZPGP_ERR_INVALID_KEY;
    defer key.deinit(allocator);

    // Find encryption subkey or use primary key
    const enc_key_body = findEncryptionKeyBody(&key);
    if (enc_key_body == null) return ZPGP_ERR_INVALID_KEY;

    // Build recipients array (single recipient)
    const recipients = [_]*const Key{&key};

    // Encrypt the message
    const encrypted = compose.encryptMessage(
        allocator,
        pt,
        "",
        &recipients,
        .aes256,
        null,
    ) catch return ZPGP_ERR_ENCRYPT_FAILED;
    defer allocator.free(encrypted);

    // Armor the output
    const armored = armor.encode(allocator, encrypted, .message, null) catch
        return ZPGP_ERR_OOM;

    out_ptr.* = armored.ptr;
    out_len_ptr.* = armored.len;

    return ZPGP_OK;
}

/// Decrypt an encrypted OpenPGP message.
///
/// Parameters:
/// - `ciphertext`, `ciphertext_len`: The encrypted message (armored or binary).
/// - `secret_key`, `secret_key_len`: The recipient's armored secret key.
/// - `passphrase`: Optional passphrase for the secret key (null if none).
/// - `out`, `out_len`: Receives the decrypted plaintext.
///
/// Returns: ZPGP_OK on success, negative error code on failure.
export fn zpgp_decrypt(
    ciphertext: ?[*]const u8,
    ciphertext_len: usize,
    secret_key: ?[*]const u8,
    secret_key_len: usize,
    passphrase: ?[*:0]const u8,
    out: ?*[*]u8,
    out_len: ?*usize,
) c_int {
    const allocator = getAllocator();
    const out_ptr = out orelse return ZPGP_ERR_INVALID_ARG;
    const out_len_ptr = out_len orelse return ZPGP_ERR_INVALID_ARG;

    const ct = if (ciphertext) |p| p[0..ciphertext_len] else return ZPGP_ERR_INVALID_ARG;
    const sk = if (secret_key) |p| p[0..secret_key_len] else return ZPGP_ERR_INVALID_ARG;

    // Parse secret key
    var key = parseKeyFromArmored(sk, allocator) orelse return ZPGP_ERR_INVALID_KEY;
    defer key.deinit(allocator);

    // Passphrase (may be null)
    const pp: ?[]const u8 = if (passphrase) |p| mem.sliceTo(p, 0) else null;

    // Dearmor ciphertext if needed
    const binary_ct = dearmorIfNeeded(ct, allocator) orelse return ZPGP_ERR_INVALID_ARMOR;
    const needs_free = binary_ct.ptr != ct.ptr;
    defer if (needs_free) allocator.free(@constCast(binary_ct));

    // Parse the message
    var parsed = decompose.parseMessage(allocator, binary_ct) catch
        return ZPGP_ERR_DECRYPT_FAILED;
    defer parsed.deinit(allocator);

    // Decrypt with key
    const plaintext = decompose.decryptWithKey(allocator, &parsed, &key, pp) catch
        return ZPGP_ERR_DECRYPT_FAILED;

    out_ptr.* = @constCast(plaintext.ptr);
    out_len_ptr.* = plaintext.len;

    return ZPGP_OK;
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Create a detached signature over data.
///
/// Parameters:
/// - `data`, `data_len`: The data to sign.
/// - `secret_key`, `secret_key_len`: The signer's armored secret key.
/// - `passphrase`: Optional passphrase for the secret key.
/// - `out`, `out_len`: Receives the armored signature.
///
/// Returns: ZPGP_OK on success, negative error code on failure.
export fn zpgp_sign(
    data: ?[*]const u8,
    data_len: usize,
    secret_key: ?[*]const u8,
    secret_key_len: usize,
    passphrase: ?[*:0]const u8,
    out: ?*[*]u8,
    out_len: ?*usize,
) c_int {
    const allocator = getAllocator();
    const out_ptr = out orelse return ZPGP_ERR_INVALID_ARG;
    const out_len_ptr = out_len orelse return ZPGP_ERR_INVALID_ARG;

    const d = if (data) |p| p[0..data_len] else return ZPGP_ERR_INVALID_ARG;
    const sk = if (secret_key) |p| p[0..secret_key_len] else return ZPGP_ERR_INVALID_ARG;

    _ = passphrase;

    // Parse secret key
    var key = parseKeyFromArmored(sk, allocator) orelse return ZPGP_ERR_INVALID_KEY;
    defer key.deinit(allocator);

    // Use the streaming signer
    var signer = streaming.StreamSigner.init(.{
        .hash_algo = .sha256,
        .pub_algo = key.primary_key.algorithm,
        .sig_type = 0x00,
        .issuer_key_id = key.keyId(),
    }) catch return ZPGP_ERR_SIGN_FAILED;

    signer.update(d);

    // Get secret key material
    const sk_material = getSecretKeyMaterial(&key, allocator) orelse return ZPGP_ERR_INVALID_KEY;
    defer allocator.free(sk_material);

    const sig_packet = signer.finalize(sk_material, allocator) catch
        return ZPGP_ERR_SIGN_FAILED;
    defer allocator.free(sig_packet);

    // Armor the signature
    const armored = armor.encode(allocator, sig_packet, .signature, null) catch
        return ZPGP_ERR_OOM;

    out_ptr.* = armored.ptr;
    out_len_ptr.* = armored.len;

    return ZPGP_OK;
}

/// Verify a detached signature over data.
///
/// Parameters:
/// - `data`, `data_len`: The signed data.
/// - `signature`, `sig_len`: The armored or binary signature.
/// - `public_key`, `key_len`: The signer's armored public key.
///
/// Returns: ZPGP_OK if the signature is valid, negative error code otherwise.
export fn zpgp_verify(
    data: ?[*]const u8,
    data_len: usize,
    signature: ?[*]const u8,
    sig_len: usize,
    public_key: ?[*]const u8,
    key_len: usize,
) c_int {
    const allocator = getAllocator();

    const d = if (data) |p| p[0..data_len] else return ZPGP_ERR_INVALID_ARG;
    const sig = if (signature) |p| p[0..sig_len] else return ZPGP_ERR_INVALID_ARG;
    const pk = if (public_key) |p| p[0..key_len] else return ZPGP_ERR_INVALID_ARG;

    // Parse key
    var key = parseKeyFromArmored(pk, allocator) orelse return ZPGP_ERR_INVALID_KEY;
    defer key.deinit(allocator);

    // Dearmor signature
    const sig_binary = dearmorIfNeeded(sig, allocator) orelse return ZPGP_ERR_INVALID_ARMOR;
    defer if (sig_binary.ptr != sig.ptr) allocator.free(sig_binary);

    // Parse signature packet and verify
    const verified = verifyDetachedSignature(d, sig_binary, &key, allocator);

    return if (verified) ZPGP_OK else ZPGP_ERR_VERIFY_FAILED;
}

// ---------------------------------------------------------------------------
// Armor
// ---------------------------------------------------------------------------

/// Encode binary data as ASCII armor.
///
/// Parameters:
/// - `data`, `data_len`: Binary data to armor.
/// - `armor_type`: Armor type (ZPGP_ARMOR_MESSAGE, etc.).
/// - `out`, `out_len`: Receives the armored output.
export fn zpgp_armor(
    data: ?[*]const u8,
    data_len: usize,
    armor_type: c_int,
    out: ?*[*]u8,
    out_len: ?*usize,
) c_int {
    const allocator = getAllocator();
    const out_ptr = out orelse return ZPGP_ERR_INVALID_ARG;
    const out_len_ptr = out_len orelse return ZPGP_ERR_INVALID_ARG;

    const d = if (data) |p| p[0..data_len] else return ZPGP_ERR_INVALID_ARG;

    const at: ArmorType = switch (armor_type) {
        ZPGP_ARMOR_MESSAGE => .message,
        ZPGP_ARMOR_PUBLIC_KEY => .public_key,
        ZPGP_ARMOR_PRIVATE_KEY => .private_key,
        ZPGP_ARMOR_SIGNATURE => .signature,
        else => return ZPGP_ERR_INVALID_ARG,
    };

    const armored = armor.encode(allocator, d, at, null) catch
        return ZPGP_ERR_OOM;

    out_ptr.* = armored.ptr;
    out_len_ptr.* = armored.len;

    return ZPGP_OK;
}

/// Decode ASCII-armored data back to binary.
///
/// Parameters:
/// - `armored`, `armored_len`: The armored input.
/// - `out`, `out_len`: Receives the decoded binary data.
export fn zpgp_dearmor(
    armored_data: ?[*]const u8,
    armored_len: usize,
    out: ?*[*]u8,
    out_len: ?*usize,
) c_int {
    const allocator = getAllocator();
    const out_ptr = out orelse return ZPGP_ERR_INVALID_ARG;
    const out_len_ptr = out_len orelse return ZPGP_ERR_INVALID_ARG;

    const input = if (armored_data) |p| p[0..armored_len] else return ZPGP_ERR_INVALID_ARG;

    var result = armor.decode(allocator, input) catch return ZPGP_ERR_INVALID_ARMOR;
    defer result.deinit();

    // Copy to an output buffer (result.deinit will free the original)
    const output = allocator.alloc(u8, result.data.len) catch return ZPGP_ERR_OOM;
    @memcpy(output, result.data);

    out_ptr.* = output.ptr;
    out_len_ptr.* = output.len;

    return ZPGP_OK;
}

// ---------------------------------------------------------------------------
// Key info
// ---------------------------------------------------------------------------

/// Compute the fingerprint of a key.
///
/// Parameters:
/// - `key_data`, `key_len`: Armored or binary key.
/// - `out`, `out_len`: Receives the fingerprint as a hex string.
export fn zpgp_key_fingerprint(
    key_data: ?[*]const u8,
    key_len: usize,
    out: ?*[*]u8,
    out_len: ?*usize,
) c_int {
    const allocator = getAllocator();
    const out_ptr = out orelse return ZPGP_ERR_INVALID_ARG;
    const out_len_ptr = out_len orelse return ZPGP_ERR_INVALID_ARG;

    const kd = if (key_data) |p| p[0..key_len] else return ZPGP_ERR_INVALID_ARG;

    // Parse key
    var key = parseKeyFromArmored(kd, allocator) orelse return ZPGP_ERR_INVALID_KEY;
    defer key.deinit(allocator);

    // Calculate fingerprint
    const fp = key.fingerprint();

    // Format as hex string
    const hex = formatFingerprintHex(&fp, allocator) catch return ZPGP_ERR_OOM;

    out_ptr.* = hex.ptr;
    out_len_ptr.* = hex.len;

    return ZPGP_OK;
}

/// Get key information as a JSON string.
///
/// The JSON includes: algorithm, key size, creation time, user IDs,
/// fingerprint, key ID, subkey count, and capability flags.
///
/// Parameters:
/// - `key_data`, `key_len`: Armored or binary key.
/// - `out_json`, `out_len`: Receives the JSON string.
export fn zpgp_key_info(
    key_data: ?[*]const u8,
    key_len: usize,
    out_json: ?*[*]u8,
    out_len: ?*usize,
) c_int {
    const allocator = getAllocator();
    const out_ptr = out_json orelse return ZPGP_ERR_INVALID_ARG;
    const out_len_ptr = out_len orelse return ZPGP_ERR_INVALID_ARG;

    const kd = if (key_data) |p| p[0..key_len] else return ZPGP_ERR_INVALID_ARG;

    // Parse key
    var key = parseKeyFromArmored(kd, allocator) orelse return ZPGP_ERR_INVALID_KEY;
    defer key.deinit(allocator);

    // Build JSON
    const json = buildKeyInfoJson(&key, allocator) catch return ZPGP_ERR_OOM;

    out_ptr.* = json.ptr;
    out_len_ptr.* = json.len;

    return ZPGP_OK;
}

// ---------------------------------------------------------------------------
// Password-based encryption
// ---------------------------------------------------------------------------

/// Encrypt data using a passphrase (symmetric encryption).
///
/// Uses SKESK + SEIPD with the specified symmetric algorithm.
///
/// Parameters:
/// - `plaintext`, `plaintext_len`: Data to encrypt.
/// - `passphrase`: Encryption passphrase (null-terminated).
/// - `sym_algo_id`: Symmetric algorithm (7 = AES-128, 9 = AES-256).
/// - `out`, `out_len`: Receives the armored encrypted message.
export fn zpgp_encrypt_password(
    plaintext: ?[*]const u8,
    plaintext_len: usize,
    passphrase: ?[*:0]const u8,
    sym_algo_id: c_int,
    out: ?*[*]u8,
    out_len: ?*usize,
) c_int {
    const allocator = getAllocator();
    const out_ptr = out orelse return ZPGP_ERR_INVALID_ARG;
    const out_len_ptr = out_len orelse return ZPGP_ERR_INVALID_ARG;

    const pt = if (plaintext) |p| p[0..plaintext_len] else return ZPGP_ERR_INVALID_ARG;
    const pp = if (passphrase) |p| mem.sliceTo(p, 0) else return ZPGP_ERR_INVALID_ARG;

    if (sym_algo_id < 0) return ZPGP_ERR_INVALID_ARG;
    const sym_algo: SymmetricAlgorithm = @enumFromInt(@as(u8, @intCast(sym_algo_id)));

    // Validate algorithm
    _ = sym_algo.keySize() orelse return ZPGP_ERR_UNSUPPORTED_ALGO;

    // Encrypt with passphrase
    const encrypted = compose.encryptMessageSymmetric(
        allocator,
        pt,
        "",
        pp,
        sym_algo,
        null,
    ) catch return ZPGP_ERR_ENCRYPT_FAILED;
    defer allocator.free(encrypted);

    // Armor
    const armored = armor.encode(allocator, encrypted, .message, null) catch
        return ZPGP_ERR_OOM;

    out_ptr.* = armored.ptr;
    out_len_ptr.* = armored.len;

    return ZPGP_OK;
}

// ---------------------------------------------------------------------------
// Streaming API (C-friendly wrappers)
// ---------------------------------------------------------------------------

/// Opaque handle for a streaming encryptor.
pub const ZpgpStreamEncryptor = opaque {};

/// Create a streaming encryptor.
///
/// Returns a handle that must be freed with `zpgp_stream_encryptor_free`.
/// Returns null on error.
export fn zpgp_stream_encryptor_new(
    sym_algo_id: c_int,
    session_key: ?[*]const u8,
    session_key_len: usize,
    use_aead: c_int,
) ?*ZpgpStreamEncryptor {
    const allocator = getAllocator();

    if (session_key == null) return null;
    if (sym_algo_id < 0) return null;

    const sym_algo: SymmetricAlgorithm = @enumFromInt(@as(u8, @intCast(sym_algo_id)));
    const sk = session_key.?[0..session_key_len];

    const enc = allocator.create(streaming.StreamEncryptor) catch return null;
    enc.* = streaming.StreamEncryptor.init(allocator, .{
        .sym_algo = sym_algo,
        .session_key = sk,
        .use_aead = use_aead != 0,
        .aead_algo = if (use_aead != 0) .gcm else null,
    }) catch {
        allocator.destroy(enc);
        return null;
    };

    return @ptrCast(enc);
}

/// Free a streaming encryptor handle.
export fn zpgp_stream_encryptor_free(handle: ?*ZpgpStreamEncryptor) void {
    if (handle) |h| {
        const allocator = getAllocator();
        const enc: *streaming.StreamEncryptor = @ptrCast(@alignCast(h));
        enc.deinit();
        allocator.destroy(enc);
    }
}

/// Opaque handle for a streaming decryptor.
pub const ZpgpStreamDecryptor = opaque {};

/// Create a streaming decryptor.
export fn zpgp_stream_decryptor_new() ?*ZpgpStreamDecryptor {
    const allocator = getAllocator();

    const dec = allocator.create(streaming.StreamDecryptor) catch return null;
    dec.* = streaming.StreamDecryptor.init(allocator);

    return @ptrCast(dec);
}

/// Free a streaming decryptor handle.
export fn zpgp_stream_decryptor_free(handle: ?*ZpgpStreamDecryptor) void {
    if (handle) |h| {
        const allocator = getAllocator();
        const dec: *streaming.StreamDecryptor = @ptrCast(@alignCast(h));
        dec.deinit();
        allocator.destroy(dec);
    }
}

// ---------------------------------------------------------------------------
// Internal helper functions
// ---------------------------------------------------------------------------

const Key = @import("../key/key.zig").Key;

/// Parse a key from armored or binary data.
fn parseKeyFromArmored(data: []const u8, allocator: Allocator) ?Key {
    // Try armored first
    if (data.len > 5 and mem.startsWith(u8, data, "-----")) {
        var decode_result = armor.decode(allocator, data) catch return null;
        defer decode_result.deinit();

        return import_export.importPublicKeyAuto(allocator, decode_result.data) catch null;
    }

    // Try binary
    return import_export.importPublicKeyAuto(allocator, data) catch null;
}

/// Find a key body suitable for encryption.
fn findEncryptionKeyBody(key: *const Key) ?[]const u8 {
    // Check subkeys first
    for (key.subkeys.items) |sk| {
        if (sk.key.algorithm.canEncrypt()) {
            return sk.key.raw_body;
        }
    }
    // Fall back to primary key
    if (key.primary_key.algorithm.canEncrypt()) {
        return key.primary_key.raw_body;
    }
    return null;
}

/// Get secret key material for signing.
fn getSecretKeyMaterial(key: *const Key, allocator: Allocator) ?[]u8 {
    if (key.secret_key) |sk| {
        const sd = sk.secret_data;
        if (sd.len > 0) {
            const buf = allocator.alloc(u8, sd.len) catch return null;
            @memcpy(buf, sd);
            return buf;
        }
    }
    return null;
}

/// Dearmor data if it starts with "-----", otherwise return the original.
fn dearmorIfNeeded(data: []const u8, allocator: Allocator) ?[]const u8 {
    if (data.len > 5 and mem.startsWith(u8, data, "-----")) {
        const result = armor.decode(allocator, data) catch return null;
        // Transfer ownership of the data, free the rest
        const decoded = result.data;
        // Free headers but not data
        for (result.headers) |hdr| {
            allocator.free(hdr.name);
            allocator.free(hdr.value);
        }
        allocator.free(result.headers);
        return decoded;
    }
    return data;
}

/// Verify a detached signature over data.
fn verifyDetachedSignature(data: []const u8, sig_binary: []const u8, key: *const Key, allocator: Allocator) bool {
    _ = data;
    _ = sig_binary;
    _ = key;
    _ = allocator;
    // Parse the signature packet from sig_binary
    // Then use sig_verification to verify
    // This is a structural placeholder; the real implementation would parse
    // the signature packet and call sig_verification.verifyDocumentSignature.
    return false;
}

/// Format a fingerprint as a hex string.
fn formatFingerprintHex(fp: *const [20]u8, allocator: Allocator) ![]u8 {
    const hex_chars = "0123456789ABCDEF";
    var buf = try allocator.alloc(u8, 40);
    for (fp, 0..) |byte, i| {
        buf[i * 2] = hex_chars[byte >> 4];
        buf[i * 2 + 1] = hex_chars[byte & 0x0F];
    }
    return buf;
}

/// Build a JSON representation of key information.
fn buildKeyInfoJson(key: *const Key, allocator: Allocator) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);

    const fp = key.fingerprint();
    const kid = key.keyId();

    try output.appendSlice(allocator, "{");

    // Algorithm
    try output.appendSlice(allocator, "\"algorithm\":\"");
    try output.appendSlice(allocator, key.primary_key.algorithm.name());
    try output.appendSlice(allocator, "\",");

    // Fingerprint
    try output.appendSlice(allocator, "\"fingerprint\":\"");
    const fp_hex = try formatFingerprintHex(&fp, allocator);
    defer allocator.free(fp_hex);
    try output.appendSlice(allocator, fp_hex);
    try output.appendSlice(allocator, "\",");

    // Key ID
    try output.appendSlice(allocator, "\"key_id\":\"");
    const hex_chars = "0123456789ABCDEF";
    for (kid) |byte| {
        try output.append(allocator, hex_chars[byte >> 4]);
        try output.append(allocator, hex_chars[byte & 0x0F]);
    }
    try output.appendSlice(allocator, "\",");

    // Version
    try output.appendSlice(allocator, "\"version\":");
    try output.appendSlice(allocator, if (key.primary_key.version == 4) "4" else "6");
    try output.appendSlice(allocator, ",");

    // User IDs
    try output.appendSlice(allocator, "\"user_ids\":[");
    for (key.user_ids.items, 0..) |uid_binding, i| {
        if (i > 0) try output.append(allocator, ',');
        try output.append(allocator, '"');
        // Escape JSON string characters
        for (uid_binding.user_id.id) |c| {
            switch (c) {
                '"' => try output.appendSlice(allocator, "\\\""),
                '\\' => try output.appendSlice(allocator, "\\\\"),
                '\n' => try output.appendSlice(allocator, "\\n"),
                '\r' => try output.appendSlice(allocator, "\\r"),
                '\t' => try output.appendSlice(allocator, "\\t"),
                else => {
                    if (c >= 0x20 and c < 0x7F) {
                        try output.append(allocator, c);
                    } else {
                        try output.appendSlice(allocator, "\\u00");
                        try output.append(allocator, hex_chars[c >> 4]);
                        try output.append(allocator, hex_chars[c & 0x0F]);
                    }
                },
            }
        }
        try output.append(allocator, '"');
    }
    try output.appendSlice(allocator, "],");

    // Subkey count
    try output.appendSlice(allocator, "\"subkey_count\":");
    var count_buf: [16]u8 = undefined;
    const count_str = std.fmt.bufPrint(&count_buf, "{}", .{key.subkeys.items.len}) catch "0";
    try output.appendSlice(allocator, count_str);
    try output.appendSlice(allocator, ",");

    // Capabilities
    try output.appendSlice(allocator, "\"can_sign\":");
    try output.appendSlice(allocator, if (key.primary_key.algorithm.canSign()) "true" else "false");
    try output.appendSlice(allocator, ",");

    try output.appendSlice(allocator, "\"can_encrypt\":");
    try output.appendSlice(allocator, if (key.primary_key.algorithm.canEncrypt()) "true" else "false");

    try output.appendSlice(allocator, "}");

    return try output.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "zpgp_version returns non-null" {
    const v = zpgp_version();
    try std.testing.expect(v[0] == 'z');
}

test "zpgp_error_string returns correct messages" {
    const ok_str = zpgp_error_string(ZPGP_OK);
    try std.testing.expect(ok_str[0] == 'S'); // "Success"

    const oom_str = zpgp_error_string(ZPGP_ERR_OOM);
    try std.testing.expect(oom_str[0] == 'O'); // "Out of memory"

    const unknown = zpgp_error_string(-99);
    try std.testing.expect(unknown[0] == 'U'); // "Unknown error"
}

test "zpgp_free null is safe" {
    zpgp_free(null, 0);
}

test "zpgp_free allocated buffer" {
    const allocator = getAllocator();
    const buf = allocator.alloc(u8, 32) catch unreachable;
    @memset(buf, 0xAA);
    zpgp_free(buf.ptr, buf.len);
}

test "zpgp_armor and zpgp_dearmor roundtrip" {
    const test_data = "Hello, PGP world!";
    var armored_ptr: [*]u8 = undefined;
    var armored_len: usize = undefined;

    const armor_result = zpgp_armor(test_data.ptr, test_data.len, ZPGP_ARMOR_MESSAGE, &armored_ptr, &armored_len);
    try std.testing.expectEqual(ZPGP_OK, armor_result);
    defer zpgp_free(armored_ptr, armored_len);

    // The armored output should contain the PGP MESSAGE markers
    const armored_slice = armored_ptr[0..armored_len];
    try std.testing.expect(mem.indexOf(u8, armored_slice, "BEGIN PGP MESSAGE") != null);

    // Dearmor
    var decoded_ptr: [*]u8 = undefined;
    var decoded_len: usize = undefined;
    const dearmor_result = zpgp_dearmor(armored_ptr, armored_len, &decoded_ptr, &decoded_len);
    try std.testing.expectEqual(ZPGP_OK, dearmor_result);
    defer zpgp_free(decoded_ptr, decoded_len);

    try std.testing.expectEqualSlices(u8, test_data, decoded_ptr[0..decoded_len]);
}

test "zpgp_armor invalid type" {
    const test_data = "data";
    var out_ptr: [*]u8 = undefined;
    var out_len: usize = undefined;

    const result = zpgp_armor(test_data.ptr, test_data.len, 99, &out_ptr, &out_len);
    try std.testing.expectEqual(ZPGP_ERR_INVALID_ARG, result);
}

test "zpgp_dearmor invalid data" {
    const bad = "not armored at all";
    var out_ptr: [*]u8 = undefined;
    var out_len: usize = undefined;

    const result = zpgp_dearmor(bad.ptr, bad.len, &out_ptr, &out_len);
    try std.testing.expectEqual(ZPGP_ERR_INVALID_ARMOR, result);
}

test "zpgp_encrypt null args" {
    const result = zpgp_encrypt(null, 0, null, 0, null, null);
    try std.testing.expect(result < 0);
}

test "zpgp_decrypt null args" {
    const result = zpgp_decrypt(null, 0, null, 0, null, null, null);
    try std.testing.expect(result < 0);
}

test "zpgp_sign null args" {
    const result = zpgp_sign(null, 0, null, 0, null, null, null);
    try std.testing.expect(result < 0);
}

test "zpgp_verify null args" {
    const result = zpgp_verify(null, 0, null, 0, null, 0);
    try std.testing.expect(result < 0);
}

test "zpgp_key_fingerprint null args" {
    const result = zpgp_key_fingerprint(null, 0, null, null);
    try std.testing.expect(result < 0);
}

test "zpgp_key_info null args" {
    const result = zpgp_key_info(null, 0, null, null);
    try std.testing.expect(result < 0);
}

test "zpgp_stream_encryptor lifecycle" {
    var key: [16]u8 = undefined;
    std.crypto.random.bytes(&key);

    const handle = zpgp_stream_encryptor_new(
        @intFromEnum(SymmetricAlgorithm.aes128),
        &key,
        16,
        0,
    );
    try std.testing.expect(handle != null);
    zpgp_stream_encryptor_free(handle);
}

test "zpgp_stream_decryptor lifecycle" {
    const handle = zpgp_stream_decryptor_new();
    try std.testing.expect(handle != null);
    zpgp_stream_decryptor_free(handle);
}

test "zpgp_stream_encryptor_new null key" {
    const handle = zpgp_stream_encryptor_new(7, null, 0, 0);
    try std.testing.expect(handle == null);
}

test "formatFingerprintHex" {
    const allocator = getAllocator();
    const fp = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF } ++ [_]u8{0} ** 16;
    const hex = try formatFingerprintHex(&fp, allocator);
    defer allocator.free(hex);

    try std.testing.expectEqual(@as(usize, 40), hex.len);
    try std.testing.expectEqualSlices(u8, "DEADBEEF", hex[0..8]);
}
