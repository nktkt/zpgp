// SPDX-License-Identifier: MIT
//! High-level OpenPGP smart card operations.
//!
//! This module provides convenient wrappers around raw APDU commands for
//! common card operations such as signing, decrypting, key import/export,
//! and card administration.
//!
//! It also includes the KDF (Key Derivation Function) support for newer
//! cards that hash PINs before verification (OpenPGP card spec v3.4+).

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const openpgp_card = @import("openpgp_card.zig");
const ApduCommand = openpgp_card.ApduCommand;
const ApduResponse = openpgp_card.ApduResponse;
const PinType = openpgp_card.PinType;
const KeyRef = openpgp_card.KeyRef;
const CardError = openpgp_card.CardError;
const DataTag = openpgp_card.DataTag;
const CardInfo = openpgp_card.CardInfo;
const DigestInfoPrefix = openpgp_card.DigestInfoPrefix;

/// Hash algorithm identifiers per OpenPGP card specification.
pub const CardHashAlgorithm = enum(u8) {
    sha1 = 2,
    sha256 = 8,
    sha384 = 9,
    sha512 = 10,
    sha224 = 11,

    pub fn digestSize(self: CardHashAlgorithm) usize {
        return switch (self) {
            .sha1 => 20,
            .sha256 => 32,
            .sha384 => 48,
            .sha512 => 64,
            .sha224 => 28,
        };
    }

    pub fn name(self: CardHashAlgorithm) []const u8 {
        return switch (self) {
            .sha1 => "SHA-1",
            .sha256 => "SHA-256",
            .sha384 => "SHA-384",
            .sha512 => "SHA-512",
            .sha224 => "SHA-224",
        };
    }
};

/// Public key algorithm identifiers for card key attributes.
pub const CardKeyAlgorithm = enum(u8) {
    rsa = 0x01,
    ecdsa = 0x13,
    ecdh = 0x12,
    eddsa = 0x16,

    pub fn name(self: CardKeyAlgorithm) []const u8 {
        return switch (self) {
            .rsa => "RSA",
            .ecdsa => "ECDSA",
            .ecdh => "ECDH",
            .eddsa => "EdDSA",
        };
    }
};

/// OID constants for elliptic curves used by OpenPGP cards.
pub const CurveOid = struct {
    /// NIST P-256 (secp256r1)
    pub const nist_p256: []const u8 = &.{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
    /// NIST P-384 (secp384r1)
    pub const nist_p384: []const u8 = &.{ 0x2B, 0x81, 0x04, 0x00, 0x22 };
    /// NIST P-521 (secp521r1)
    pub const nist_p521: []const u8 = &.{ 0x2B, 0x81, 0x04, 0x00, 0x23 };
    /// Curve25519 for EdDSA (Ed25519)
    pub const ed25519: []const u8 = &.{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01 };
    /// Curve25519 for ECDH (X25519)
    pub const x25519: []const u8 = &.{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01 };
    /// brainpoolP256r1
    pub const brainpool_p256: []const u8 = &.{ 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07 };
    /// brainpoolP384r1
    pub const brainpool_p384: []const u8 = &.{ 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B };
    /// brainpoolP512r1
    pub const brainpool_p512: []const u8 = &.{ 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D };
};

// ---------------------------------------------------------------------------
// High-level card operations
// ---------------------------------------------------------------------------

/// High-level operations for OpenPGP smart cards.
///
/// These functions build APDU command sequences for common operations.
/// They do not perform actual card I/O; the caller is responsible for
/// transmitting the commands and processing responses.
pub const CardOperations = struct {
    /// Build the APDU command to sign a hash using the card's signature key.
    ///
    /// For RSA keys, the hash must be wrapped in a DigestInfo structure.
    /// For ECDSA/EdDSA keys, the raw hash is sent directly.
    ///
    /// Prerequisites:
    ///   1. SELECT OpenPGP application
    ///   2. VERIFY PW1 (0x81) for signing
    pub fn signWithCard(allocator: Allocator, hash: []const u8, hash_algo: CardHashAlgorithm, is_rsa: bool) !ApduCommand {
        if (is_rsa) {
            // RSA: wrap hash in DigestInfo
            const digest_info = try openpgp_card.buildDigestInfo(allocator, @intFromEnum(hash_algo), hash);
            return .{
                .cla = 0x00,
                .ins = 0x2A,
                .p1 = 0x9E,
                .p2 = 0x9A,
                .data = digest_info,
                .le = 256,
            };
        } else {
            // EC: send raw hash
            return openpgp_card.computeDigitalSignature(hash);
        }
    }

    /// Build the APDU command to decrypt data using the card's decryption key.
    ///
    /// For RSA: ciphertext is sent as-is with a padding indicator byte (0x00).
    /// For ECDH: the ephemeral public point is sent.
    ///
    /// Prerequisites:
    ///   1. SELECT OpenPGP application
    ///   2. VERIFY PW1 (0x82) for decryption
    pub fn decryptWithCard(allocator: Allocator, ciphertext: []const u8, is_rsa: bool) !ApduCommand {
        if (is_rsa) {
            // RSA: prepend padding indicator byte 0x00
            const data = try allocator.alloc(u8, 1 + ciphertext.len);
            data[0] = 0x00; // Padding indicator for RSA
            @memcpy(data[1..], ciphertext);
            return .{
                .cla = 0x00,
                .ins = 0x2A,
                .p1 = 0x80,
                .p2 = 0x86,
                .data = data,
                .le = 256,
            };
        } else {
            return openpgp_card.decipher(ciphertext);
        }
    }

    /// Build APDU commands to import a private key to the card.
    ///
    /// The key data must be formatted according to the card's expected format
    /// using formatKeyForImport(). The import may require multiple APDUs
    /// if the key is larger than the card's maximum command size.
    ///
    /// Prerequisites:
    ///   1. SELECT OpenPGP application
    ///   2. VERIFY PW3 (Admin PIN)
    ///   3. Set key attributes if needed
    pub fn importKey(allocator: Allocator, key_ref: KeyRef, key_data: []const u8) ![]ApduCommand {
        // Build the key import data with the CRT (Control Reference Template)
        // The extended header list for key import is:
        //   4D <len> <CRT tag> 00 <key data>
        const crt_tag = key_ref.crtTag();

        // Build the full DO for PUT DATA Extended (INS=DB, tag 3FFF)
        // Format: tag 4D, len, crt, 0x00, key_template
        const header_len = 2 + key_data.len; // CRT tag + 0x00 + key_data
        const total_len = if (header_len < 128) 2 + header_len // tag + 1-byte len + data
        else if (header_len < 256) 3 + header_len // tag + 0x81 + 1-byte len + data
        else 4 + header_len; // tag + 0x82 + 2-byte len + data

        const import_data = try allocator.alloc(u8, total_len);
        errdefer allocator.free(import_data);

        var offset: usize = 0;
        import_data[offset] = 0x4D; // Extended header list tag
        offset += 1;

        if (header_len < 128) {
            import_data[offset] = @intCast(header_len);
            offset += 1;
        } else if (header_len < 256) {
            import_data[offset] = 0x81;
            offset += 1;
            import_data[offset] = @intCast(header_len);
            offset += 1;
        } else {
            import_data[offset] = 0x82;
            offset += 1;
            mem.writeInt(u16, import_data[offset..][0..2], @intCast(header_len), .big);
            offset += 2;
        }

        import_data[offset] = crt_tag;
        offset += 1;
        import_data[offset] = 0x00;
        offset += 1;
        @memcpy(import_data[offset .. offset + key_data.len], key_data);

        // For now, return a single PUT DATA command
        // Larger keys might need command chaining (CLA=0x10)
        const max_cmd_size: usize = 255;

        if (import_data.len <= max_cmd_size) {
            const commands = try allocator.alloc(ApduCommand, 1);
            commands[0] = .{
                .cla = 0x00,
                .ins = 0xDB, // PUT DATA (odd INS for extended)
                .p1 = 0x3F,
                .p2 = 0xFF,
                .data = import_data,
                .le = null,
            };
            return commands;
        } else {
            // Command chaining for large key data
            var chain_count: usize = (import_data.len + max_cmd_size - 1) / max_cmd_size;
            if (chain_count == 0) chain_count = 1;

            const commands = try allocator.alloc(ApduCommand, chain_count);
            errdefer allocator.free(commands);

            var data_offset: usize = 0;
            for (commands, 0..) |*cmd, i| {
                const remaining = import_data.len - data_offset;
                const chunk_size = @min(remaining, max_cmd_size);
                const is_last = (i == chain_count - 1);

                cmd.* = .{
                    .cla = if (is_last) 0x00 else 0x10, // Command chaining
                    .ins = 0xDB,
                    .p1 = 0x3F,
                    .p2 = 0xFF,
                    .data = import_data[data_offset .. data_offset + chunk_size],
                    .le = null,
                };
                data_offset += chunk_size;
            }

            return commands;
        }
    }

    /// Build APDU command to read the public key from a card slot.
    ///
    /// This reads the existing public key without generating a new one.
    pub fn readPublicKey(key_ref: KeyRef) ApduCommand {
        return openpgp_card.readPublicKeyFromCard(key_ref);
    }

    /// Format RSA key material for card import.
    ///
    /// The card expects private key components in a specific TLV format:
    ///   - 7F48: Cardholder private key template
    ///   - 5F48: Concatenated key data
    ///
    /// For RSA, the template includes: e, p, q components.
    pub fn formatRsaKeyForImport(
        allocator: Allocator,
        public_exponent: []const u8,
        prime_p: []const u8,
        prime_q: []const u8,
    ) ![]u8 {
        // Build the private key template (tag 7F48)
        // Contains TLV entries describing the layout of the concatenated key data
        // 91 <len_e> 92 <len_p> 93 <len_q>
        const template_inner_len = 2 + 2 + 2; // 3 tags, each with 1-byte length
        const key_data_len = public_exponent.len + prime_p.len + prime_q.len;

        // 7F48 <len> <template>  5F48 <len> <keydata>
        const template_total = 3 + template_inner_len; // tag(2) + len(1) + inner
        const keydata_total = if (key_data_len < 128)
            3 + key_data_len // tag(2) + len(1) + data
        else if (key_data_len < 256)
            4 + key_data_len // tag(2) + 0x81 + len(1) + data
        else
            5 + key_data_len; // tag(2) + 0x82 + len(2) + data

        const result = try allocator.alloc(u8, template_total + keydata_total);
        errdefer allocator.free(result);

        var offset: usize = 0;

        // Private key template (tag 7F48)
        result[offset] = 0x7F;
        offset += 1;
        result[offset] = 0x48;
        offset += 1;
        result[offset] = @intCast(template_inner_len);
        offset += 1;

        // e length descriptor (tag 91)
        result[offset] = 0x91;
        offset += 1;
        result[offset] = @intCast(public_exponent.len);
        offset += 1;

        // p length descriptor (tag 92)
        result[offset] = 0x92;
        offset += 1;
        result[offset] = @intCast(prime_p.len);
        offset += 1;

        // q length descriptor (tag 93)
        result[offset] = 0x93;
        offset += 1;
        result[offset] = @intCast(prime_q.len);
        offset += 1;

        // Concatenated key data (tag 5F48)
        result[offset] = 0x5F;
        offset += 1;
        result[offset] = 0x48;
        offset += 1;

        if (key_data_len < 128) {
            result[offset] = @intCast(key_data_len);
            offset += 1;
        } else if (key_data_len < 256) {
            result[offset] = 0x81;
            offset += 1;
            result[offset] = @intCast(key_data_len);
            offset += 1;
        } else {
            result[offset] = 0x82;
            offset += 1;
            mem.writeInt(u16, result[offset..][0..2], @intCast(key_data_len), .big);
            offset += 2;
        }

        @memcpy(result[offset .. offset + public_exponent.len], public_exponent);
        offset += public_exponent.len;
        @memcpy(result[offset .. offset + prime_p.len], prime_p);
        offset += prime_p.len;
        @memcpy(result[offset .. offset + prime_q.len], prime_q);

        return result;
    }

    /// Format EC key material for card import (ECDSA, ECDH, Ed25519).
    ///
    /// For EC keys, the private key template contains just the private scalar.
    pub fn formatEcKeyForImport(
        allocator: Allocator,
        private_key: []const u8,
    ) ![]u8 {
        // 7F48 <len> 92 <len_priv>
        // 5F48 <len> <private_key>
        const template_inner_len: usize = 2; // tag(92) + len(1byte)
        const template_total: usize = 3 + template_inner_len; // 7F48 + len + inner

        const keydata_total: usize = if (private_key.len < 128)
            3 + private_key.len
        else
            4 + private_key.len;

        const result = try allocator.alloc(u8, template_total + keydata_total);
        errdefer allocator.free(result);

        var offset: usize = 0;

        // Private key template
        result[offset] = 0x7F;
        offset += 1;
        result[offset] = 0x48;
        offset += 1;
        result[offset] = @intCast(template_inner_len);
        offset += 1;
        result[offset] = 0x92;
        offset += 1;
        result[offset] = @intCast(private_key.len);
        offset += 1;

        // Concatenated key data
        result[offset] = 0x5F;
        offset += 1;
        result[offset] = 0x48;
        offset += 1;
        if (private_key.len < 128) {
            result[offset] = @intCast(private_key.len);
            offset += 1;
        } else {
            result[offset] = 0x81;
            offset += 1;
            result[offset] = @intCast(private_key.len);
            offset += 1;
        }
        @memcpy(result[offset .. offset + private_key.len], private_key);

        return result;
    }

    /// Build APDU command to set the cardholder name on the card.
    ///
    /// The name must be in the format "Surname<<Firstname" per ICAO convention.
    /// Maximum length is typically 39 bytes.
    pub fn setCardholderName(card_name: []const u8) ApduCommand {
        return openpgp_card.putData(DataTag.cardholder_name, card_name);
    }

    /// Build APDU command to set the key attributes for a key slot.
    ///
    /// For RSA: algorithm byte + 2-byte key size in bits + 2-byte exponent size + format
    /// For EC: algorithm byte + OID
    pub fn setRsaKeyAttributes(allocator: Allocator, key_ref: KeyRef, bits: u16) !ApduCommand {
        // RSA attributes: 01 <key_bits_2BE> <exp_bits_2BE> <format>
        const attrs = try allocator.alloc(u8, 6);
        attrs[0] = 0x01; // RSA
        mem.writeInt(u16, attrs[1..3], bits, .big);
        mem.writeInt(u16, attrs[3..5], 0x0020, .big); // 32-bit exponent (standard)
        attrs[5] = 0x00; // Standard format (e, p, q)
        return openpgp_card.putData(key_ref.attributesTag(), attrs);
    }

    /// Build APDU command to set EC key attributes for a key slot.
    pub fn setEcKeyAttributes(key_ref: KeyRef, algo: CardKeyAlgorithm, oid: []const u8) ApduCommand {
        // EC attributes: <algorithm_byte> <OID>
        // We use a buffer that's pre-formatted
        _ = algo;
        _ = oid;
        // Return a placeholder - real implementation would build the attribute data
        return openpgp_card.putData(key_ref.attributesTag(), &.{});
    }

    /// Build APDU command to set the URL for public key retrieval.
    pub fn setPublicKeyUrl(url: []const u8) ApduCommand {
        return openpgp_card.putData(DataTag.public_key_url, url);
    }

    /// Build APDU command to set login data.
    pub fn setLoginData(login: []const u8) ApduCommand {
        return openpgp_card.putData(DataTag.login_data, login);
    }

    /// Build APDU command to set the language preference.
    pub fn setLanguagePrefs(lang: []const u8) ApduCommand {
        return openpgp_card.putData(DataTag.language_prefs, lang);
    }

    /// Build APDU command to set the sex indicator.
    ///
    /// Values: '1' = male, '2' = female, '9' = not announced, '0' = not known
    pub fn setSex(sex: u8) ApduCommand {
        return openpgp_card.putData(DataTag.sex, &[_]u8{sex});
    }

    /// Build APDU command to set PW status bytes.
    ///
    /// This controls whether PW1 is valid for one signature or multiple.
    pub fn setPwStatus(multi_use: bool) ApduCommand {
        const status_byte: u8 = if (multi_use) 0x01 else 0x00;
        return openpgp_card.putData(DataTag.pw_status, &[_]u8{status_byte});
    }

    /// Build a sequence of APDU commands to perform a factory reset.
    ///
    /// This terminates and reactivates the OpenPGP application,
    /// restoring all data objects to their default values.
    ///
    /// WARNING: This destroys all keys and data on the card!
    pub fn factoryReset() [4]ApduCommand {
        return .{
            // Step 1: Verify PW1 with wrong PIN to exhaust retries
            // (Caller should repeat until card returns 6983)
            openpgp_card.verify(.admin, "00000000"),
            // Step 2: Verify PW3 with wrong PIN to exhaust retries
            openpgp_card.verify(.admin, "00000000"),
            // Step 3: TERMINATE DF
            openpgp_card.terminateDf(),
            // Step 4: ACTIVATE FILE
            openpgp_card.activateFile(),
        };
    }

    /// Build APDU commands for the complete signing sequence.
    ///
    /// Returns the sequence: SELECT, VERIFY PW1, PSO:CDS
    pub fn signSequence(hash: []const u8, pin: []const u8) [3]ApduCommand {
        return .{
            openpgp_card.selectOpenPgpApp(),
            openpgp_card.verify(.user, pin),
            openpgp_card.computeDigitalSignature(hash),
        };
    }

    /// Build APDU commands for the complete decryption sequence.
    ///
    /// Returns the sequence: SELECT, VERIFY PW1(decrypt), PSO:DEC
    pub fn decryptSequence(ciphertext: []const u8, pin: []const u8) [3]ApduCommand {
        return .{
            openpgp_card.selectOpenPgpApp(),
            openpgp_card.verify(.user_decrypt, pin),
            openpgp_card.decipher(ciphertext),
        };
    }

    /// Build APDU commands to read all card information.
    ///
    /// Returns commands to fetch: Application Related Data, Cardholder Data,
    /// Security Support Template.
    pub fn readCardInfoSequence() [4]ApduCommand {
        return .{
            openpgp_card.selectOpenPgpApp(),
            openpgp_card.getData(DataTag.application_related),
            openpgp_card.getData(DataTag.cardholder_related),
            openpgp_card.getData(DataTag.security_support),
        };
    }
};

// ---------------------------------------------------------------------------
// KDF (Key Derivation Function) for PIN
// ---------------------------------------------------------------------------

/// KDF data object for OpenPGP card spec v3.4+.
///
/// Newer cards can require PINs to be hashed before being sent to the card.
/// This provides additional protection against eavesdropping on the
/// card-reader communication channel.
pub const CardKdf = struct {
    /// KDF algorithm.
    algorithm: KdfAlgorithm,
    /// Number of iterations for the KDF.
    iterations: u32,
    /// Salt for user PIN derivation.
    salt_user: [8]u8,
    /// Salt for admin PIN derivation.
    salt_admin: [8]u8,
    /// Pre-computed hash of the initial user PIN (optional, for setup).
    hash_user: ?[32]u8,
    /// Pre-computed hash of the initial admin PIN (optional, for setup).
    hash_admin: ?[32]u8,

    pub const KdfAlgorithm = enum(u8) {
        /// No KDF - PIN sent in plaintext (default for older cards).
        none = 0x00,
        /// SHA-256 based KDF (KDF-ITERSALTED-S2K variant).
        sha256 = 0x08,
        /// SHA-512 based KDF.
        sha512 = 0x0A,

        pub fn name(self: KdfAlgorithm) []const u8 {
            return switch (self) {
                .none => "None",
                .sha256 => "SHA-256",
                .sha512 => "SHA-512",
            };
        }

        pub fn digestSize(self: KdfAlgorithm) usize {
            return switch (self) {
                .none => 0,
                .sha256 => 32,
                .sha512 => 64,
            };
        }
    };

    /// Create a KDF with default (no hashing) settings.
    pub fn initNone() CardKdf {
        return .{
            .algorithm = .none,
            .iterations = 0,
            .salt_user = [_]u8{0} ** 8,
            .salt_admin = [_]u8{0} ** 8,
            .hash_user = null,
            .hash_admin = null,
        };
    }

    /// Derive a PIN hash using the KDF parameters.
    ///
    /// Implements the iterated-salted S2K variant used by OpenPGP cards:
    ///   1. Concatenate salt + PIN
    ///   2. Repeat the concatenation to fill the iteration count
    ///   3. Hash the result
    ///
    /// Returns a 32-byte hash for SHA-256, or the first 32 bytes for SHA-512.
    pub fn derivePinHash(self: CardKdf, pin: []const u8, pin_type: PinType) ![32]u8 {
        if (self.algorithm == .none) {
            // No KDF - just return zero-padded PIN (not really hashed)
            var result: [32]u8 = [_]u8{0} ** 32;
            const copy_len = @min(pin.len, 32);
            @memcpy(result[0..copy_len], pin[0..copy_len]);
            return result;
        }

        const salt = switch (pin_type) {
            .user, .user_decrypt => self.salt_user,
            .admin => self.salt_admin,
        };

        // Build the salted data: salt || pin
        const salted_len = salt.len + pin.len;
        if (salted_len == 0) return [_]u8{0} ** 32;

        // Iterated hashing: hash (iterations) bytes of repeated (salt || pin)
        const count = @max(self.iterations, salted_len);

        switch (self.algorithm) {
            .sha256 => {
                var hasher = std.crypto.hash.sha2.Sha256.init(.{});
                var bytes_hashed: u64 = 0;
                while (bytes_hashed < count) {
                    // Feed salt
                    const salt_feed = @min(salt.len, count - bytes_hashed);
                    hasher.update(salt[0..salt_feed]);
                    bytes_hashed += salt_feed;

                    if (bytes_hashed >= count) break;

                    // Feed PIN
                    const pin_feed = @min(pin.len, count - bytes_hashed);
                    hasher.update(pin[0..pin_feed]);
                    bytes_hashed += pin_feed;
                }
                return hasher.finalResult();
            },
            .sha512 => {
                var hasher = std.crypto.hash.sha2.Sha512.init(.{});
                var bytes_hashed: u64 = 0;
                while (bytes_hashed < count) {
                    const salt_feed = @min(salt.len, count - bytes_hashed);
                    hasher.update(salt[0..salt_feed]);
                    bytes_hashed += salt_feed;

                    if (bytes_hashed >= count) break;

                    const pin_feed = @min(pin.len, count - bytes_hashed);
                    hasher.update(pin[0..pin_feed]);
                    bytes_hashed += pin_feed;
                }
                const full_hash = hasher.finalResult();
                return full_hash[0..32].*;
            },
            .none => unreachable,
        }
    }

    /// Parse a KDF data object from card response data.
    ///
    /// The KDF-DO (tag F9) has the following TLV structure:
    ///   81 01 <algo>          - KDF algorithm
    ///   82 01 <hash_algo>     - Hash algorithm
    ///   83 04 <iterations>    - Iteration count (4 bytes BE)
    ///   84 08 <salt_pw1>      - Salt for PW1
    ///   85 08 <salt_rc>       - Salt for Reset Code (ignored here)
    ///   86 08 <salt_pw3>      - Salt for PW3
    ///   87 20 <hash_pw1>      - Initial PW1 hash (optional)
    ///   88 20 <hash_pw3>      - Initial PW3 hash (optional)
    pub fn parseFromData(data: []const u8) !CardKdf {
        var kdf = CardKdf.initNone();

        var offset: usize = 0;
        while (offset + 2 <= data.len) {
            const tag = data[offset];
            const length = data[offset + 1];
            offset += 2;

            if (offset + length > data.len) break;
            const value = data[offset .. offset + length];

            switch (tag) {
                0x81 => {
                    // KDF algorithm
                    if (length >= 1) {
                        kdf.algorithm = switch (value[0]) {
                            0x00 => .none,
                            0x08 => .sha256,
                            0x0A => .sha512,
                            else => .none,
                        };
                    }
                },
                0x83 => {
                    // Iteration count
                    if (length >= 4) {
                        kdf.iterations = mem.readInt(u32, value[0..4], .big);
                    }
                },
                0x84 => {
                    // Salt for PW1
                    if (length >= 8) {
                        kdf.salt_user = value[0..8].*;
                    }
                },
                0x86 => {
                    // Salt for PW3
                    if (length >= 8) {
                        kdf.salt_admin = value[0..8].*;
                    }
                },
                0x87 => {
                    // Initial PW1 hash
                    if (length >= 32) {
                        kdf.hash_user = value[0..32].*;
                    }
                },
                0x88 => {
                    // Initial PW3 hash
                    if (length >= 32) {
                        kdf.hash_admin = value[0..32].*;
                    }
                },
                else => {},
            }

            offset += length;
        }

        return kdf;
    }

    /// Serialize KDF data for PUT DATA command.
    pub fn serialize(self: CardKdf, allocator: Allocator) ![]u8 {
        if (self.algorithm == .none) {
            // KDF-DO with "none" algorithm: 81 01 00
            const data = try allocator.alloc(u8, 3);
            data[0] = 0x81;
            data[1] = 0x01;
            data[2] = 0x00;
            return data;
        }

        // Calculate total size
        var total: usize = 0;
        total += 3; // 81 01 <algo>
        total += 3; // 82 01 <hash_algo>
        total += 6; // 83 04 <iterations>
        total += 10; // 84 08 <salt_pw1>
        total += 10; // 85 08 <salt_rc> (zeroed)
        total += 10; // 86 08 <salt_pw3>

        if (self.hash_user != null) total += 34; // 87 20 <hash>
        if (self.hash_admin != null) total += 34; // 88 20 <hash>

        const data = try allocator.alloc(u8, total);
        errdefer allocator.free(data);

        var offset: usize = 0;

        // Algorithm
        data[offset] = 0x81;
        data[offset + 1] = 0x01;
        data[offset + 2] = @intFromEnum(self.algorithm);
        offset += 3;

        // Hash algorithm (same as KDF algorithm for simplicity)
        data[offset] = 0x82;
        data[offset + 1] = 0x01;
        data[offset + 2] = @intFromEnum(self.algorithm);
        offset += 3;

        // Iterations
        data[offset] = 0x83;
        data[offset + 1] = 0x04;
        mem.writeInt(u32, data[offset + 2 ..][0..4], self.iterations, .big);
        offset += 6;

        // Salt PW1
        data[offset] = 0x84;
        data[offset + 1] = 0x08;
        @memcpy(data[offset + 2 .. offset + 10], &self.salt_user);
        offset += 10;

        // Salt RC (zeroed)
        data[offset] = 0x85;
        data[offset + 1] = 0x08;
        @memset(data[offset + 2 .. offset + 10], 0);
        offset += 10;

        // Salt PW3
        data[offset] = 0x86;
        data[offset + 1] = 0x08;
        @memcpy(data[offset + 2 .. offset + 10], &self.salt_admin);
        offset += 10;

        // Optional initial hashes
        if (self.hash_user) |hu| {
            data[offset] = 0x87;
            data[offset + 1] = 0x20;
            @memcpy(data[offset + 2 .. offset + 34], &hu);
            offset += 34;
        }
        if (self.hash_admin) |ha| {
            data[offset] = 0x88;
            data[offset + 1] = 0x20;
            @memcpy(data[offset + 2 .. offset + 34], &ha);
            offset += 34;
        }

        return data;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "CardHashAlgorithm properties" {
    try std.testing.expectEqual(@as(usize, 32), CardHashAlgorithm.sha256.digestSize());
    try std.testing.expectEqual(@as(usize, 64), CardHashAlgorithm.sha512.digestSize());
    try std.testing.expectEqual(@as(usize, 20), CardHashAlgorithm.sha1.digestSize());
    try std.testing.expectEqualStrings("SHA-256", CardHashAlgorithm.sha256.name());
}

test "CardKeyAlgorithm names" {
    try std.testing.expectEqualStrings("RSA", CardKeyAlgorithm.rsa.name());
    try std.testing.expectEqualStrings("EdDSA", CardKeyAlgorithm.eddsa.name());
    try std.testing.expectEqualStrings("ECDSA", CardKeyAlgorithm.ecdsa.name());
    try std.testing.expectEqualStrings("ECDH", CardKeyAlgorithm.ecdh.name());
}

test "CardOperations signSequence" {
    const hash = [_]u8{0xAB} ** 32;
    const pin = "123456";
    const seq = CardOperations.signSequence(&hash, pin);

    // First command is SELECT
    try std.testing.expectEqual(@as(u8, 0xA4), seq[0].ins);
    // Second is VERIFY
    try std.testing.expectEqual(@as(u8, 0x20), seq[1].ins);
    try std.testing.expectEqual(@as(u8, 0x81), seq[1].p2); // PW1 for signing
    // Third is PSO:CDS
    try std.testing.expectEqual(@as(u8, 0x2A), seq[2].ins);
    try std.testing.expectEqual(@as(u8, 0x9E), seq[2].p1);
}

test "CardOperations decryptSequence" {
    const ct = [_]u8{0xCD} ** 64;
    const pin = "123456";
    const seq = CardOperations.decryptSequence(&ct, pin);

    try std.testing.expectEqual(@as(u8, 0xA4), seq[0].ins); // SELECT
    try std.testing.expectEqual(@as(u8, 0x20), seq[1].ins); // VERIFY
    try std.testing.expectEqual(@as(u8, 0x82), seq[1].p2); // PW1 for decrypt
    try std.testing.expectEqual(@as(u8, 0x2A), seq[2].ins); // PSO:DEC
    try std.testing.expectEqual(@as(u8, 0x80), seq[2].p1);
}

test "CardOperations readCardInfoSequence" {
    const seq = CardOperations.readCardInfoSequence();
    try std.testing.expectEqual(@as(u8, 0xA4), seq[0].ins); // SELECT
    try std.testing.expectEqual(@as(u8, 0xCA), seq[1].ins); // GET DATA
    try std.testing.expectEqual(@as(u8, 0xCA), seq[2].ins); // GET DATA
    try std.testing.expectEqual(@as(u8, 0xCA), seq[3].ins); // GET DATA
}

test "CardOperations factoryReset" {
    const seq = CardOperations.factoryReset();
    try std.testing.expectEqual(@as(usize, 4), seq.len);
    try std.testing.expectEqual(@as(u8, 0x20), seq[0].ins); // VERIFY (wrong PIN)
    try std.testing.expectEqual(@as(u8, 0x20), seq[1].ins); // VERIFY (wrong PIN)
    try std.testing.expectEqual(@as(u8, 0xE6), seq[2].ins); // TERMINATE DF
    try std.testing.expectEqual(@as(u8, 0x44), seq[3].ins); // ACTIVATE FILE
}

test "CardOperations readPublicKey" {
    const cmd = CardOperations.readPublicKey(.signature);
    try std.testing.expectEqual(@as(u8, 0x47), cmd.ins);
    try std.testing.expectEqual(@as(u8, 0x81), cmd.p1); // Read existing
}

test "CardOperations setCardholderName" {
    const cmd = CardOperations.setCardholderName("Doe<<John");
    try std.testing.expectEqual(@as(u8, 0xDA), cmd.ins); // PUT DATA
    try std.testing.expectEqual(@as(u8, 0x5B), cmd.p2); // Cardholder name tag
}

test "CardOperations setPublicKeyUrl" {
    const cmd = CardOperations.setPublicKeyUrl("https://keys.example.com/key.asc");
    try std.testing.expectEqual(@as(u8, 0xDA), cmd.ins);
}

test "CardOperations setLoginData" {
    const cmd = CardOperations.setLoginData("johndoe");
    try std.testing.expectEqual(@as(u8, 0xDA), cmd.ins);
    try std.testing.expectEqual(@as(u8, 0x5E), cmd.p2);
}

test "CardOperations setPwStatus" {
    const cmd_multi = CardOperations.setPwStatus(true);
    try std.testing.expectEqual(@as(u8, 0xDA), cmd_multi.ins);
    try std.testing.expectEqual(@as(u8, 0x01), cmd_multi.data.?[0]);

    const cmd_single = CardOperations.setPwStatus(false);
    try std.testing.expectEqual(@as(u8, 0x00), cmd_single.data.?[0]);
}

test "CardOperations formatRsaKeyForImport" {
    const allocator = std.testing.allocator;

    const e = [_]u8{ 0x01, 0x00, 0x01 }; // 65537
    const p = [_]u8{0xAA} ** 16;
    const q = [_]u8{0xBB} ** 16;

    const result = try CardOperations.formatRsaKeyForImport(allocator, &e, &p, &q);
    defer allocator.free(result);

    // Check private key template header (7F 48)
    try std.testing.expectEqual(@as(u8, 0x7F), result[0]);
    try std.testing.expectEqual(@as(u8, 0x48), result[1]);

    // Template should contain tag 91 (e), 92 (p), 93 (q)
    try std.testing.expectEqual(@as(u8, 0x91), result[3]);
    try std.testing.expectEqual(@as(u8, 3), result[4]); // e length
    try std.testing.expectEqual(@as(u8, 0x92), result[5]);
    try std.testing.expectEqual(@as(u8, 16), result[6]); // p length
    try std.testing.expectEqual(@as(u8, 0x93), result[7]);
    try std.testing.expectEqual(@as(u8, 16), result[8]); // q length
}

test "CardOperations formatEcKeyForImport" {
    const allocator = std.testing.allocator;

    const priv = [_]u8{0xCC} ** 32;

    const result = try CardOperations.formatEcKeyForImport(allocator, &priv);
    defer allocator.free(result);

    // Check private key template header (7F 48)
    try std.testing.expectEqual(@as(u8, 0x7F), result[0]);
    try std.testing.expectEqual(@as(u8, 0x48), result[1]);

    // Template should contain tag 92 (private key)
    try std.testing.expectEqual(@as(u8, 0x92), result[3]);
    try std.testing.expectEqual(@as(u8, 32), result[4]); // private key length
}

test "CardOperations importKey single command" {
    const allocator = std.testing.allocator;

    const key_data = [_]u8{0x42} ** 32;
    const commands = try CardOperations.importKey(allocator, .signature, &key_data);
    defer allocator.free(commands);

    try std.testing.expectEqual(@as(usize, 1), commands.len);
    try std.testing.expectEqual(@as(u8, 0xDB), commands[0].ins); // PUT DATA extended
    try std.testing.expectEqual(@as(u8, 0x3F), commands[0].p1);
    try std.testing.expectEqual(@as(u8, 0xFF), commands[0].p2);
}

test "CardOperations signWithCard RSA" {
    const allocator = std.testing.allocator;
    const hash = [_]u8{0x42} ** 32;

    const cmd = try CardOperations.signWithCard(allocator, &hash, .sha256, true);
    // RSA wraps in DigestInfo
    allocator.free(cmd.data.?);

    try std.testing.expectEqual(@as(u8, 0x2A), cmd.ins);
    try std.testing.expectEqual(@as(u8, 0x9E), cmd.p1);
}

test "CardOperations signWithCard EC" {
    const allocator = std.testing.allocator;
    const hash = [_]u8{0x42} ** 32;

    const cmd = try CardOperations.signWithCard(allocator, &hash, .sha256, false);
    // EC sends raw hash
    try std.testing.expectEqual(@as(u8, 0x2A), cmd.ins);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x42} ** 32), cmd.data.?);
}

test "CardOperations decryptWithCard RSA" {
    const allocator = std.testing.allocator;
    const ct = [_]u8{0xBB} ** 64;

    const cmd = try CardOperations.decryptWithCard(allocator, &ct, true);
    defer allocator.free(cmd.data.?);

    try std.testing.expectEqual(@as(u8, 0x2A), cmd.ins);
    // RSA prepends padding indicator
    try std.testing.expectEqual(@as(u8, 0x00), cmd.data.?[0]);
    try std.testing.expectEqual(@as(usize, 65), cmd.data.?.len);
}

test "CardKdf initNone" {
    const kdf = CardKdf.initNone();
    try std.testing.expectEqual(CardKdf.KdfAlgorithm.none, kdf.algorithm);
    try std.testing.expectEqual(@as(u32, 0), kdf.iterations);
    try std.testing.expect(kdf.hash_user == null);
}

test "CardKdf derivePinHash none" {
    const kdf = CardKdf.initNone();
    const hash = try kdf.derivePinHash("123456", .user);

    // With "none" algorithm, result is zero-padded PIN
    try std.testing.expectEqual(@as(u8, '1'), hash[0]);
    try std.testing.expectEqual(@as(u8, '2'), hash[1]);
    try std.testing.expectEqual(@as(u8, '6'), hash[5]);
    try std.testing.expectEqual(@as(u8, 0), hash[6]);
}

test "CardKdf derivePinHash sha256" {
    var kdf = CardKdf.initNone();
    kdf.algorithm = .sha256;
    kdf.iterations = 100;
    kdf.salt_user = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    const hash = try kdf.derivePinHash("123456", .user);

    // Should produce a non-trivial 32-byte hash
    var all_zero = true;
    for (hash) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "CardKdf derivePinHash sha512" {
    var kdf = CardKdf.initNone();
    kdf.algorithm = .sha512;
    kdf.iterations = 200;
    kdf.salt_admin = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 };

    const hash = try kdf.derivePinHash("12345678", .admin);

    var all_zero = true;
    for (hash) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "CardKdf parseFromData" {
    // Minimal KDF-DO with SHA-256
    const data = [_]u8{
        0x81, 0x01, 0x08, // algorithm = SHA-256
        0x83, 0x04, 0x00, 0x00, 0x10, 0x00, // iterations = 4096
        0x84, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // salt PW1
        0x86, 0x08, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, // salt PW3
    };

    const kdf = try CardKdf.parseFromData(&data);
    try std.testing.expectEqual(CardKdf.KdfAlgorithm.sha256, kdf.algorithm);
    try std.testing.expectEqual(@as(u32, 4096), kdf.iterations);
    try std.testing.expectEqual(@as(u8, 0x01), kdf.salt_user[0]);
    try std.testing.expectEqual(@as(u8, 0xA1), kdf.salt_admin[0]);
    try std.testing.expect(kdf.hash_user == null);
}

test "CardKdf serialize none" {
    const allocator = std.testing.allocator;
    const kdf = CardKdf.initNone();

    const data = try kdf.serialize(allocator);
    defer allocator.free(data);

    try std.testing.expectEqual(@as(usize, 3), data.len);
    try std.testing.expectEqual(@as(u8, 0x81), data[0]);
    try std.testing.expectEqual(@as(u8, 0x01), data[1]);
    try std.testing.expectEqual(@as(u8, 0x00), data[2]);
}

test "CardKdf serialize sha256" {
    const allocator = std.testing.allocator;

    var kdf = CardKdf.initNone();
    kdf.algorithm = .sha256;
    kdf.iterations = 4096;
    kdf.salt_user = [_]u8{0x11} ** 8;
    kdf.salt_admin = [_]u8{0x22} ** 8;

    const data = try kdf.serialize(allocator);
    defer allocator.free(data);

    // Should contain: algo(3) + hash_algo(3) + iterations(6) + salt_pw1(10) + salt_rc(10) + salt_pw3(10)
    try std.testing.expectEqual(@as(usize, 42), data.len);
    try std.testing.expectEqual(@as(u8, 0x08), data[2]); // SHA-256 algorithm
}

test "CardKdf serialize with hashes" {
    const allocator = std.testing.allocator;

    var kdf = CardKdf.initNone();
    kdf.algorithm = .sha256;
    kdf.iterations = 4096;
    kdf.salt_user = [_]u8{0x11} ** 8;
    kdf.salt_admin = [_]u8{0x22} ** 8;
    kdf.hash_user = [_]u8{0xAA} ** 32;
    kdf.hash_admin = [_]u8{0xBB} ** 32;

    const data = try kdf.serialize(allocator);
    defer allocator.free(data);

    // Base(42) + hash_user(34) + hash_admin(34)
    try std.testing.expectEqual(@as(usize, 110), data.len);
}

test "CardKdf round trip" {
    const allocator = std.testing.allocator;

    var kdf = CardKdf.initNone();
    kdf.algorithm = .sha256;
    kdf.iterations = 8192;
    kdf.salt_user = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    kdf.salt_admin = [_]u8{ 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8 };

    const serialized = try kdf.serialize(allocator);
    defer allocator.free(serialized);

    const parsed = try CardKdf.parseFromData(serialized);
    try std.testing.expectEqual(kdf.algorithm, parsed.algorithm);
    try std.testing.expectEqual(kdf.iterations, parsed.iterations);
    try std.testing.expectEqualSlices(u8, &kdf.salt_user, &parsed.salt_user);
    try std.testing.expectEqualSlices(u8, &kdf.salt_admin, &parsed.salt_admin);
}

test "CurveOid constants" {
    try std.testing.expectEqual(@as(usize, 8), CurveOid.nist_p256.len);
    try std.testing.expectEqual(@as(usize, 5), CurveOid.nist_p384.len);
    try std.testing.expectEqual(@as(usize, 9), CurveOid.ed25519.len);
    try std.testing.expectEqual(@as(usize, 10), CurveOid.x25519.len);
}

test "CardOperations setRsaKeyAttributes" {
    const allocator = std.testing.allocator;

    const cmd = try CardOperations.setRsaKeyAttributes(allocator, .signature, 2048);
    defer allocator.free(cmd.data.?);

    try std.testing.expectEqual(@as(u8, 0xDA), cmd.ins);
    try std.testing.expectEqual(@as(u8, 0x01), cmd.data.?[0]); // RSA
    const bits = mem.readInt(u16, cmd.data.?[1..3], .big);
    try std.testing.expectEqual(@as(u16, 2048), bits);
}

test "CardKdf KdfAlgorithm properties" {
    try std.testing.expectEqualStrings("None", CardKdf.KdfAlgorithm.none.name());
    try std.testing.expectEqualStrings("SHA-256", CardKdf.KdfAlgorithm.sha256.name());
    try std.testing.expectEqual(@as(usize, 0), CardKdf.KdfAlgorithm.none.digestSize());
    try std.testing.expectEqual(@as(usize, 32), CardKdf.KdfAlgorithm.sha256.digestSize());
    try std.testing.expectEqual(@as(usize, 64), CardKdf.KdfAlgorithm.sha512.digestSize());
}
