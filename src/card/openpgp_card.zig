// SPDX-License-Identifier: MIT
//! OpenPGP smart card protocol (ISO 7816 APDUs) per the OpenPGP card specification.
//!
//! This module implements the low-level Application Protocol Data Unit (APDU)
//! commands and responses for interacting with OpenPGP-compatible smart cards
//! such as YubiKey, Nitrokey, and GnuPG smart cards.
//!
//! The OpenPGP card application (AID D2 76 00 01 24 01) provides:
//!   - Digital signature generation
//!   - Data decryption
//!   - Client/server authentication
//!   - Key generation on-card
//!   - PIN management
//!
//! Reference: OpenPGP Smart Card Application specification v3.4

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during smart card communication.
pub const CardError = error{
    /// No OpenPGP-compatible card was found.
    CardNotFound,
    /// PIN verification or authentication failed.
    AuthFailed,
    /// The provided PIN was invalid (wrong format or wrong value).
    InvalidPin,
    /// The card has been blocked due to too many failed PIN attempts.
    CardBlocked,
    /// Low-level communication error with the card reader.
    CommunicationError,
    /// The card does not support the requested operation.
    UnsupportedCard,
    /// The card returned an unexpected status word.
    UnexpectedStatus,
    /// The response data is malformed or truncated.
    MalformedResponse,
    /// A TLV structure in the response is invalid.
    InvalidTlv,
    /// Buffer too small for the requested operation.
    BufferTooSmall,
    /// Out of memory.
    OutOfMemory,
};

// ---------------------------------------------------------------------------
// PIN and Key references
// ---------------------------------------------------------------------------

/// PIN type for VERIFY and CHANGE REFERENCE DATA commands.
///
/// OpenPGP cards have two PIN types:
///   - PW1 (User PIN): Required for signing and decryption
///   - PW3 (Admin PIN): Required for key management and card administration
pub const PinType = enum(u8) {
    /// User PIN (PW1) - P2 reference 0x81 for signing, 0x82 for decryption
    user = 0x81,
    /// User PIN for decryption operations
    user_decrypt = 0x82,
    /// Admin PIN (PW3) - P2 reference 0x83
    admin = 0x83,

    pub fn name(self: PinType) []const u8 {
        return switch (self) {
            .user => "User PIN (PW1 Sign)",
            .user_decrypt => "User PIN (PW1 Decrypt)",
            .admin => "Admin PIN (PW3)",
        };
    }

    /// Default PIN values per OpenPGP card specification.
    pub fn defaultPin(self: PinType) []const u8 {
        return switch (self) {
            .user, .user_decrypt => "123456",
            .admin => "12345678",
        };
    }

    /// Minimum PIN length per specification.
    pub fn minLength(self: PinType) usize {
        return switch (self) {
            .user, .user_decrypt => 6,
            .admin => 8,
        };
    }

    /// Maximum PIN length per specification.
    pub fn maxLength(self: PinType) usize {
        return switch (self) {
            .user, .user_decrypt => 127,
            .admin => 127,
        };
    }
};

/// Key slot reference for key operations.
///
/// OpenPGP cards have three key slots:
///   - Signature key (SIG): Used for digital signatures
///   - Decryption key (DEC): Used for data decryption
///   - Authentication key (AUT): Used for authentication (e.g. SSH)
pub const KeyRef = enum(u8) {
    /// Signature key slot
    signature = 0xB6,
    /// Decryption key slot
    decryption = 0xB8,
    /// Authentication key slot
    authentication = 0xA4,

    pub fn name(self: KeyRef) []const u8 {
        return switch (self) {
            .signature => "Signature",
            .decryption => "Decryption",
            .authentication => "Authentication",
        };
    }

    /// Control reference template tag for this key.
    pub fn crtTag(self: KeyRef) u8 {
        return @intFromEnum(self);
    }

    /// Data object tag for key fingerprint.
    pub fn fingerprintTag(self: KeyRef) u16 {
        return switch (self) {
            .signature => 0x00C7,
            .decryption => 0x00C8,
            .authentication => 0x00C9,
        };
    }

    /// Data object tag for key generation timestamp.
    pub fn timestampTag(self: KeyRef) u16 {
        return switch (self) {
            .signature => 0x00CE,
            .decryption => 0x00CF,
            .authentication => 0x00D0,
        };
    }

    /// Data object tag for key attributes (algorithm info).
    pub fn attributesTag(self: KeyRef) u16 {
        return switch (self) {
            .signature => 0x00C1,
            .decryption => 0x00C2,
            .authentication => 0x00C3,
        };
    }
};

// ---------------------------------------------------------------------------
// APDU Command
// ---------------------------------------------------------------------------

/// An ISO 7816 APDU command.
///
/// The command APDU consists of:
///   - CLA (Class byte): Usually 0x00 for OpenPGP
///   - INS (Instruction byte): The command to execute
///   - P1, P2 (Parameter bytes): Command-specific parameters
///   - Data: Optional command data (Lc field is derived from data length)
///   - Le: Optional expected response length
pub const ApduCommand = struct {
    /// Class byte (CLA). Usually 0x00 for standard commands.
    cla: u8,
    /// Instruction byte (INS).
    ins: u8,
    /// Parameter 1 (P1).
    p1: u8,
    /// Parameter 2 (P2).
    p2: u8,
    /// Optional command data. When present, Lc is derived from its length.
    data: ?[]const u8,
    /// Optional expected response length (Le).
    le: ?u16,

    /// Serialize the APDU command to a byte buffer suitable for transmission.
    ///
    /// Format: CLA INS P1 P2 [Lc Data] [Le]
    /// Uses short encoding (Lc/Le as single byte) when possible,
    /// extended encoding (3 bytes for Lc, 2 bytes for Le) for larger payloads.
    pub fn serialize(self: ApduCommand, allocator: Allocator) ![]u8 {
        // Calculate total size
        var size: usize = 4; // CLA INS P1 P2

        const has_data = self.data != null and self.data.?.len > 0;
        const has_le = self.le != null;

        if (has_data) {
            const data_len = self.data.?.len;
            if (data_len > 65535) return error.BufferTooSmall;
            if (data_len <= 255) {
                size += 1 + data_len; // Lc (1 byte) + data
            } else {
                size += 3 + data_len; // Lc (3 bytes: 0x00 + 2 bytes) + data
            }
        }

        if (has_le) {
            if (!has_data and self.le.? > 256) {
                size += 3; // Le extended without data: 0x00 + 2 bytes
            } else if (has_data and self.data.?.len > 255) {
                size += 2; // Le extended with extended Lc
            } else {
                size += 1; // Le short
            }
        }

        const buf = try allocator.alloc(u8, size);
        errdefer allocator.free(buf);

        var offset: usize = 0;

        // Header
        buf[offset] = self.cla;
        offset += 1;
        buf[offset] = self.ins;
        offset += 1;
        buf[offset] = self.p1;
        offset += 1;
        buf[offset] = self.p2;
        offset += 1;

        // Lc + Data
        if (has_data) {
            const data_len = self.data.?.len;
            if (data_len <= 255) {
                buf[offset] = @intCast(data_len);
                offset += 1;
            } else {
                buf[offset] = 0x00;
                offset += 1;
                mem.writeInt(u16, buf[offset..][0..2], @intCast(data_len), .big);
                offset += 2;
            }
            @memcpy(buf[offset .. offset + data_len], self.data.?);
            offset += data_len;
        }

        // Le
        if (has_le) {
            const le_val = self.le.?;
            if (!has_data and le_val > 256) {
                buf[offset] = 0x00;
                offset += 1;
                mem.writeInt(u16, buf[offset..][0..2], le_val, .big);
                offset += 2;
            } else if (has_data and self.data.?.len > 255) {
                mem.writeInt(u16, buf[offset..][0..2], le_val, .big);
                offset += 2;
            } else {
                // Short Le: 0x00 means 256
                buf[offset] = if (le_val >= 256) 0x00 else @intCast(le_val);
                offset += 1;
            }
        }

        return buf;
    }

    /// Return the expected total serialized length.
    pub fn serializedLength(self: ApduCommand) usize {
        var size: usize = 4;
        const has_data = self.data != null and self.data.?.len > 0;
        if (has_data) {
            const data_len = self.data.?.len;
            if (data_len <= 255) {
                size += 1 + data_len;
            } else {
                size += 3 + data_len;
            }
        }
        if (self.le != null) {
            if (!has_data and self.le.? > 256) {
                size += 3;
            } else if (has_data and self.data.?.len > 255) {
                size += 2;
            } else {
                size += 1;
            }
        }
        return size;
    }
};

// ---------------------------------------------------------------------------
// APDU Response
// ---------------------------------------------------------------------------

/// An ISO 7816 APDU response.
///
/// The response APDU consists of:
///   - Response data (optional)
///   - SW1, SW2 (Status words): Indicate success/failure
pub const ApduResponse = struct {
    /// Response data (may be empty).
    data: []u8,
    /// Status word 1.
    sw1: u8,
    /// Status word 2.
    sw2: u8,

    /// Check if the response indicates success (SW=9000).
    pub fn isSuccess(self: ApduResponse) bool {
        return self.sw1 == 0x90 and self.sw2 == 0x00;
    }

    /// Check if the response indicates more data available (SW=61xx).
    pub fn hasMoreData(self: ApduResponse) bool {
        return self.sw1 == 0x61;
    }

    /// Get the number of remaining bytes when SW=61xx.
    pub fn remainingBytes(self: ApduResponse) ?u8 {
        if (self.hasMoreData()) return self.sw2;
        return null;
    }

    /// Check if authentication is required (SW=6982).
    pub fn needsAuth(self: ApduResponse) bool {
        return self.sw1 == 0x69 and self.sw2 == 0x82;
    }

    /// Check if the PIN is blocked (SW=6983).
    pub fn isPinBlocked(self: ApduResponse) bool {
        return self.sw1 == 0x69 and self.sw2 == 0x83;
    }

    /// Check if the wrong PIN was presented. SW=63Cx where x = retries left.
    pub fn isWrongPin(self: ApduResponse) bool {
        return self.sw1 == 0x63 and (self.sw2 & 0xF0) == 0xC0;
    }

    /// Get the number of remaining PIN retries (when SW=63Cx).
    pub fn pinRetriesLeft(self: ApduResponse) ?u8 {
        if (self.isWrongPin()) return self.sw2 & 0x0F;
        return null;
    }

    /// Return the combined 16-bit status word.
    pub fn statusWord(self: ApduResponse) u16 {
        return (@as(u16, self.sw1) << 8) | @as(u16, self.sw2);
    }

    /// Human-readable description of the status word.
    pub fn statusDescription(self: ApduResponse) []const u8 {
        return switch (self.statusWord()) {
            0x9000 => "Success",
            0x6285 => "Selected file in termination state",
            0x6581 => "Memory failure",
            0x6700 => "Wrong length",
            0x6882 => "Secure messaging not supported",
            0x6982 => "Security status not satisfied",
            0x6983 => "Authentication method blocked",
            0x6984 => "Referenced data invalidated",
            0x6985 => "Conditions of use not satisfied",
            0x6A80 => "Incorrect parameters in data field",
            0x6A82 => "File not found",
            0x6A88 => "Referenced data not found",
            0x6B00 => "Wrong parameters P1/P2",
            0x6D00 => "Instruction not supported",
            0x6E00 => "Class not supported",
            else => {
                if (self.sw1 == 0x61) return "More data available";
                if (self.sw1 == 0x63 and (self.sw2 & 0xF0) == 0xC0) return "Wrong PIN, retries remaining";
                return "Unknown status";
            },
        };
    }

    /// Free the response data.
    pub fn deinit(self: ApduResponse, allocator: Allocator) void {
        if (self.data.len > 0) {
            allocator.free(self.data);
        }
    }

    /// Parse a raw response buffer into an ApduResponse.
    ///
    /// The last 2 bytes are SW1/SW2; everything before is response data.
    pub fn parse(allocator: Allocator, raw: []const u8) !ApduResponse {
        if (raw.len < 2) return CardError.MalformedResponse;

        const data_len = raw.len - 2;
        const data = if (data_len > 0) blk: {
            const d = try allocator.alloc(u8, data_len);
            @memcpy(d, raw[0..data_len]);
            break :blk d;
        } else blk: {
            break :blk try allocator.alloc(u8, 0);
        };

        return .{
            .data = data,
            .sw1 = raw[raw.len - 2],
            .sw2 = raw[raw.len - 1],
        };
    }
};

// ---------------------------------------------------------------------------
// Card Information
// ---------------------------------------------------------------------------

/// Information extracted from the OpenPGP card's data objects.
pub const CardInfo = struct {
    /// Application Identifier (AID) - 16 bytes.
    aid: [16]u8,
    /// Card application version.
    version: struct { major: u8, minor: u8 },
    /// Manufacturer ID (from AID bytes 8-9).
    manufacturer: u16,
    /// Card serial number (from AID bytes 10-13).
    serial: u32,
    /// Fingerprint of the signature key, if present.
    sig_key_fingerprint: ?[20]u8,
    /// Fingerprint of the encryption key, if present.
    enc_key_fingerprint: ?[20]u8,
    /// Fingerprint of the authentication key, if present.
    auth_key_fingerprint: ?[20]u8,
    /// Number of signatures performed with the card.
    sig_count: u32,
    /// PIN retry counters.
    pin_retries: struct { user: u8, reset: u8, admin: u8 },

    /// Check if a key slot has a key loaded.
    pub fn hasSignatureKey(self: CardInfo) bool {
        return self.sig_key_fingerprint != null;
    }

    pub fn hasEncryptionKey(self: CardInfo) bool {
        return self.enc_key_fingerprint != null;
    }

    pub fn hasAuthenticationKey(self: CardInfo) bool {
        return self.auth_key_fingerprint != null;
    }

    /// Check if any key slot is populated.
    pub fn hasAnyKey(self: CardInfo) bool {
        return self.hasSignatureKey() or self.hasEncryptionKey() or self.hasAuthenticationKey();
    }

    /// Format the serial number as a hex string.
    pub fn serialHex(self: CardInfo, buf: *[8]u8) void {
        const hex_chars = "0123456789ABCDEF";
        const serial_bytes: [4]u8 = @bitCast(mem.nativeTo(u32, self.serial, .big));
        for (serial_bytes, 0..) |b, i| {
            buf[i * 2] = hex_chars[b >> 4];
            buf[i * 2 + 1] = hex_chars[b & 0x0F];
        }
    }
};

// ---------------------------------------------------------------------------
// APDU Command Builders
// ---------------------------------------------------------------------------

/// OpenPGP card Application ID.
pub const OPENPGP_AID: [6]u8 = .{ 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01 };

/// Well-known data object tags.
pub const DataTag = struct {
    /// Application Related Data
    pub const application_related = 0x006E;
    /// Cardholder Related Data
    pub const cardholder_related = 0x0065;
    /// Security Support Template
    pub const security_support = 0x007A;
    /// Fingerprints of all keys
    pub const fingerprints = 0x00C5;
    /// CA fingerprints
    pub const ca_fingerprints = 0x00C6;
    /// Key generation timestamps
    pub const generation_times = 0x00CD;
    /// Digital signature counter
    pub const sig_counter = 0x0093;
    /// Extended capabilities
    pub const extended_capabilities = 0x00C0;
    /// Algorithm attributes: signature
    pub const algo_attrs_sig = 0x00C1;
    /// Algorithm attributes: decryption
    pub const algo_attrs_dec = 0x00C2;
    /// Algorithm attributes: authentication
    pub const algo_attrs_auth = 0x00C3;
    /// PW status bytes
    pub const pw_status = 0x00C4;
    /// Cardholder name
    pub const cardholder_name = 0x005B;
    /// Language preferences
    pub const language_prefs = 0x005F2D;
    /// Sex indicator
    pub const sex = 0x5F35;
    /// URL for public key retrieval
    pub const public_key_url = 0x5F50;
    /// Login data
    pub const login_data = 0x005E;
    /// KDF data object (v3.4+)
    pub const kdf_do = 0x00F9;
    /// User Interaction Flag: SIG
    pub const uif_sig = 0x00D6;
    /// User Interaction Flag: DEC
    pub const uif_dec = 0x00D7;
    /// User Interaction Flag: AUT
    pub const uif_aut = 0x00D8;
};

/// SELECT command for the OpenPGP application.
///
/// Selects the OpenPGP application on the card using its AID.
/// This must be sent before any other OpenPGP commands.
pub fn selectOpenPgpApp() ApduCommand {
    return .{
        .cla = 0x00,
        .ins = 0xA4, // SELECT
        .p1 = 0x04, // Select by DF name
        .p2 = 0x00, // First or only occurrence
        .data = &OPENPGP_AID,
        .le = 256, // Expect response
    };
}

/// GET DATA command to retrieve a data object from the card.
///
/// The tag is split into P1 (high byte) and P2 (low byte).
pub fn getData(tag: u16) ApduCommand {
    return .{
        .cla = 0x00,
        .ins = 0xCA, // GET DATA
        .p1 = @intCast((tag >> 8) & 0xFF),
        .p2 = @intCast(tag & 0xFF),
        .data = null,
        .le = 256,
    };
}

/// VERIFY command to verify a PIN.
///
/// After successful verification, the card allows operations
/// requiring that PIN level.
pub fn verify(pin_type: PinType, pin: []const u8) ApduCommand {
    return .{
        .cla = 0x00,
        .ins = 0x20, // VERIFY
        .p1 = 0x00,
        .p2 = @intFromEnum(pin_type),
        .data = pin,
        .le = null,
    };
}

/// VERIFY command without data to check PIN status.
///
/// Returns:
///   - 9000: PIN already verified
///   - 63Cx: PIN not verified, x retries remaining
pub fn verifyStatus(pin_type: PinType) ApduCommand {
    return .{
        .cla = 0x00,
        .ins = 0x20, // VERIFY
        .p1 = 0x00,
        .p2 = @intFromEnum(pin_type),
        .data = null,
        .le = null,
    };
}

/// CHANGE REFERENCE DATA command to change a PIN.
pub fn changePin(pin_type: PinType, old_pin: []const u8, new_pin: []const u8) ApduCommand {
    // Concatenate old + new PIN into data field
    // We store both in a static buffer pattern since we can't allocate here.
    // The caller should serialize with the combined data.
    _ = old_pin;
    _ = new_pin;

    return .{
        .cla = 0x00,
        .ins = 0x24, // CHANGE REFERENCE DATA
        .p1 = 0x00,
        .p2 = @intFromEnum(pin_type),
        .data = null, // Caller must provide combined old+new
        .le = null,
    };
}

/// Build the data field for CHANGE REFERENCE DATA (old PIN || new PIN).
pub fn buildChangePinData(allocator: Allocator, old_pin: []const u8, new_pin: []const u8) ![]u8 {
    const data = try allocator.alloc(u8, old_pin.len + new_pin.len);
    @memcpy(data[0..old_pin.len], old_pin);
    @memcpy(data[old_pin.len..], new_pin);
    return data;
}

/// PERFORM SECURITY OPERATION: COMPUTE DIGITAL SIGNATURE (PSO:CDS).
///
/// Signs a hash digest using the card's signature key.
/// The card's user PIN (PW1 with 0x81) must be verified first.
pub fn computeDigitalSignature(hash: []const u8) ApduCommand {
    return .{
        .cla = 0x00,
        .ins = 0x2A, // PERFORM SECURITY OPERATION
        .p1 = 0x9E, // Return digital signature
        .p2 = 0x9A, // Input is hash/digest
        .data = hash,
        .le = 256,
    };
}

/// PERFORM SECURITY OPERATION: DECIPHER (PSO:DEC).
///
/// Decrypts data using the card's decryption key.
/// The card's user PIN (PW1 with 0x82) must be verified first.
pub fn decipher(data: []const u8) ApduCommand {
    return .{
        .cla = 0x00,
        .ins = 0x2A, // PERFORM SECURITY OPERATION
        .p1 = 0x80, // Return plaintext
        .p2 = 0x86, // Input is ciphertext
        .data = data,
        .le = 256,
    };
}

/// PUT DATA command to write a data object to the card.
///
/// Requires Admin PIN (PW3) verification for most objects.
pub fn putData(tag: u16, data: []const u8) ApduCommand {
    return .{
        .cla = 0x00,
        .ins = 0xDA, // PUT DATA
        .p1 = @intCast((tag >> 8) & 0xFF),
        .p2 = @intCast(tag & 0xFF),
        .data = data,
        .le = null,
    };
}

/// GENERATE ASYMMETRIC KEY PAIR command.
///
/// Generates a new key pair on the card for the specified key slot.
/// Requires Admin PIN (PW3) verification.
pub fn generateAsymmetricKey(key_ref: KeyRef) ApduCommand {
    return .{
        .cla = 0x00,
        .ins = 0x47, // GENERATE ASYMMETRIC KEY PAIR
        .p1 = 0x80, // Generate key pair
        .p2 = 0x00,
        .data = &[_]u8{ key_ref.crtTag(), 0x00 },
        .le = 256,
    };
}

/// READ PUBLIC KEY command (read existing key without generating).
pub fn readPublicKeyFromCard(key_ref: KeyRef) ApduCommand {
    return .{
        .cla = 0x00,
        .ins = 0x47, // GENERATE ASYMMETRIC KEY PAIR
        .p1 = 0x81, // Read existing public key
        .p2 = 0x00,
        .data = &[_]u8{ key_ref.crtTag(), 0x00 },
        .le = 256,
    };
}

/// INTERNAL AUTHENTICATE command.
///
/// Uses the authentication key for client authentication.
/// The card's user PIN (PW1 with 0x82) or PW1 (0x81) must be verified.
pub fn internalAuthenticate(data: []const u8) ApduCommand {
    return .{
        .cla = 0x00,
        .ins = 0x88, // INTERNAL AUTHENTICATE
        .p1 = 0x00,
        .p2 = 0x00,
        .data = data,
        .le = 256,
    };
}

/// GET RESPONSE command to fetch remaining data after a 61xx response.
pub fn getResponse(length: u8) ApduCommand {
    return .{
        .cla = 0x00,
        .ins = 0xC0, // GET RESPONSE
        .p1 = 0x00,
        .p2 = 0x00,
        .data = null,
        .le = @as(u16, length),
    };
}

/// RESET RETRY COUNTER command (unblock PW1 with PW3).
///
/// Requires Admin PIN (PW3) to be verified.
pub fn resetRetryCounter(new_pin: []const u8) ApduCommand {
    return .{
        .cla = 0x00,
        .ins = 0x2C, // RESET RETRY COUNTER
        .p1 = 0x02, // Reset by Admin PIN (PW3 must be verified)
        .p2 = 0x81, // PW1
        .data = new_pin,
        .le = null,
    };
}

/// TERMINATE DF command - terminates the OpenPGP application.
///
/// After this command, the card must be reactivated with ACTIVATE FILE.
pub fn terminateDf() ApduCommand {
    return .{
        .cla = 0x00,
        .ins = 0xE6, // TERMINATE DF
        .p1 = 0x00,
        .p2 = 0x00,
        .data = null,
        .le = null,
    };
}

/// ACTIVATE FILE command - reactivates the OpenPGP application after termination.
pub fn activateFile() ApduCommand {
    return .{
        .cla = 0x00,
        .ins = 0x44, // ACTIVATE FILE
        .p1 = 0x00,
        .p2 = 0x00,
        .data = null,
        .le = null,
    };
}

// ---------------------------------------------------------------------------
// Application Related Data parsing
// ---------------------------------------------------------------------------

/// Parsed Application Related Data (DO tag 6E).
pub const ApplicationData = struct {
    /// Application ID (16 bytes).
    aid: [16]u8,
    /// Historical bytes.
    historical_bytes: ?[]const u8,
    /// Extended capabilities.
    extended_capabilities: ?ExtendedCapabilities,
    /// Algorithm attributes for each key slot.
    algo_attrs_sig: ?[]const u8,
    algo_attrs_dec: ?[]const u8,
    algo_attrs_auth: ?[]const u8,
    /// PW status bytes.
    pw_status: ?PwStatus,
    /// Key fingerprints (60 bytes: 3 * 20).
    fingerprints: ?[60]u8,
    /// CA fingerprints (60 bytes: 3 * 20).
    ca_fingerprints: ?[60]u8,
    /// Key generation timestamps (12 bytes: 3 * 4).
    generation_times: ?[12]u8,
};

/// Extended capabilities of the card.
pub const ExtendedCapabilities = struct {
    /// Supports secure messaging.
    secure_messaging: bool,
    /// Supports GET CHALLENGE.
    get_challenge: bool,
    /// Supports key import.
    key_import: bool,
    /// Supports PW1 status change.
    pw1_status_change: bool,
    /// Supports private DOs.
    private_dos: bool,
    /// Supports algorithm attributes change.
    algo_attrs_change: bool,
    /// Supports PSO:DEC with AES.
    aes_dec: bool,
    /// Supports KDF-DO.
    kdf_do: bool,
    /// Maximum length of GET CHALLENGE.
    max_challenge_len: u16,
    /// Maximum length of cardholder certificate.
    max_cert_len: u16,
    /// Maximum length of special DOs.
    max_special_do_len: u16,
    /// PIN block 2 format supported.
    pin_block_2: bool,
    /// MSE command for key selection supported.
    mse_key_select: bool,

    pub fn parse(data: []const u8) ?ExtendedCapabilities {
        if (data.len < 10) return null;

        return .{
            .secure_messaging = (data[0] & 0x80) != 0,
            .get_challenge = (data[0] & 0x40) != 0,
            .key_import = (data[0] & 0x20) != 0,
            .pw1_status_change = (data[0] & 0x10) != 0,
            .private_dos = (data[0] & 0x08) != 0,
            .algo_attrs_change = (data[0] & 0x04) != 0,
            .aes_dec = (data[0] & 0x02) != 0,
            .kdf_do = (data[0] & 0x01) != 0,
            .max_challenge_len = mem.readInt(u16, data[2..4], .big),
            .max_cert_len = mem.readInt(u16, data[4..6], .big),
            .max_special_do_len = mem.readInt(u16, data[6..8], .big),
            .pin_block_2 = if (data.len > 8) (data[8] & 0x02) != 0 else false,
            .mse_key_select = if (data.len > 8) (data[8] & 0x01) != 0 else false,
        };
    }
};

/// PW Status Bytes - PIN policy information.
pub const PwStatus = struct {
    /// Whether PW1 is valid for multiple commands (vs single use).
    pw1_multi_use: bool,
    /// Maximum length of PW1 (user PIN).
    max_pw1_len: u8,
    /// Maximum length of Reset Code.
    max_rc_len: u8,
    /// Maximum length of PW3 (admin PIN).
    max_pw3_len: u8,
    /// Remaining retries for PW1.
    pw1_retries: u8,
    /// Remaining retries for Reset Code.
    rc_retries: u8,
    /// Remaining retries for PW3.
    pw3_retries: u8,

    pub fn parse(data: []const u8) ?PwStatus {
        if (data.len < 7) return null;
        return .{
            .pw1_multi_use = data[0] == 0x01,
            .max_pw1_len = data[1],
            .max_rc_len = data[2],
            .max_pw3_len = data[3],
            .pw1_retries = data[4],
            .rc_retries = data[5],
            .pw3_retries = data[6],
        };
    }
};

// ---------------------------------------------------------------------------
// TLV Parser
// ---------------------------------------------------------------------------

/// A single Tag-Length-Value entry.
pub const TlvEntry = struct {
    /// Tag (1 or 2 bytes).
    tag: u16,
    /// Value data (slice into the original buffer).
    value: []const u8,
};

/// Parse TLV-encoded data as used in OpenPGP card responses.
///
/// Supports 1-byte and 2-byte tags, and 1-byte, 2-byte, and 3-byte
/// length encodings per ISO 7816-4 / BER-TLV.
///
/// Returns a dynamically allocated slice of TlvEntry. The entries
/// reference the original data buffer and must not outlive it.
pub fn parseTlv(allocator: Allocator, data: []const u8) ![]TlvEntry {
    var entries = std.ArrayList(TlvEntry).init(allocator);
    errdefer entries.deinit();

    var offset: usize = 0;
    while (offset < data.len) {
        // Parse tag
        if (offset >= data.len) break;
        var tag: u16 = data[offset];
        offset += 1;

        // Two-byte tag: if low 5 bits of first byte are all 1s
        if ((tag & 0x1F) == 0x1F) {
            if (offset >= data.len) break;
            tag = (tag << 8) | data[offset];
            offset += 1;
        }

        // Parse length
        if (offset >= data.len) break;
        var length: usize = data[offset];
        offset += 1;

        if (length == 0x81) {
            // 2-byte length
            if (offset >= data.len) break;
            length = data[offset];
            offset += 1;
        } else if (length == 0x82) {
            // 3-byte length
            if (offset + 1 >= data.len) break;
            length = (@as(usize, data[offset]) << 8) | data[offset + 1];
            offset += 2;
        } else if (length >= 0x80) {
            // Invalid length encoding for our purposes
            break;
        }

        if (offset + length > data.len) break;

        try entries.append(.{
            .tag = tag,
            .value = data[offset .. offset + length],
        });

        offset += length;
    }

    return entries.toOwnedSlice();
}

/// Find a TLV entry with the given tag.
pub fn findTlvTag(entries: []const TlvEntry, tag: u16) ?[]const u8 {
    for (entries) |entry| {
        if (entry.tag == tag) return entry.value;
    }
    return null;
}

/// Parse card info from Application Related Data and other data objects.
///
/// This combines data from multiple GET DATA responses to build a CardInfo.
pub fn parseCardInfo(allocator: Allocator, app_data: []const u8) !CardInfo {
    const entries = try parseTlv(allocator, app_data);
    defer allocator.free(entries);

    var info = CardInfo{
        .aid = [_]u8{0} ** 16,
        .version = .{ .major = 0, .minor = 0 },
        .manufacturer = 0,
        .serial = 0,
        .sig_key_fingerprint = null,
        .enc_key_fingerprint = null,
        .auth_key_fingerprint = null,
        .sig_count = 0,
        .pin_retries = .{ .user = 0, .reset = 0, .admin = 0 },
    };

    // Look for the AID (tag 4F)
    if (findTlvTag(entries, 0x4F)) |aid_data| {
        if (aid_data.len >= 16) {
            @memcpy(&info.aid, aid_data[0..16]);
            info.version = .{
                .major = aid_data[6],
                .minor = aid_data[7],
            };
            info.manufacturer = mem.readInt(u16, aid_data[8..10], .big);
            info.serial = mem.readInt(u32, aid_data[10..14], .big);
        } else if (aid_data.len >= 14) {
            @memcpy(info.aid[0..aid_data.len], aid_data);
            info.version = .{
                .major = aid_data[6],
                .minor = aid_data[7],
            };
            info.manufacturer = mem.readInt(u16, aid_data[8..10], .big);
            info.serial = mem.readInt(u32, aid_data[10..14], .big);
        }
    }

    // Look for fingerprints (tag C5 - 60 bytes: 3 * 20)
    if (findTlvTag(entries, 0xC5)) |fp_data| {
        if (fp_data.len >= 60) {
            const sig_fp = fp_data[0..20];
            const enc_fp = fp_data[20..40];
            const auth_fp = fp_data[40..60];

            if (!isZero(sig_fp)) info.sig_key_fingerprint = sig_fp[0..20].*;
            if (!isZero(enc_fp)) info.enc_key_fingerprint = enc_fp[0..20].*;
            if (!isZero(auth_fp)) info.auth_key_fingerprint = auth_fp[0..20].*;
        }
    }

    // Look for PW status bytes (tag C4)
    if (findTlvTag(entries, 0xC4)) |pw_data| {
        if (pw_data.len >= 7) {
            info.pin_retries = .{
                .user = pw_data[4],
                .reset = pw_data[5],
                .admin = pw_data[6],
            };
        }
    }

    // Look for signature counter (tag 93)
    if (findTlvTag(entries, 0x93)) |counter_data| {
        if (counter_data.len >= 3) {
            info.sig_count = (@as(u32, counter_data[0]) << 16) |
                (@as(u32, counter_data[1]) << 8) |
                @as(u32, counter_data[2]);
        }
    }

    return info;
}

/// Parse Application Related Data (tag 6E) container.
pub fn parseApplicationData(allocator: Allocator, data: []const u8) !ApplicationData {
    const entries = try parseTlv(allocator, data);
    defer allocator.free(entries);

    var app_data = ApplicationData{
        .aid = [_]u8{0} ** 16,
        .historical_bytes = null,
        .extended_capabilities = null,
        .algo_attrs_sig = null,
        .algo_attrs_dec = null,
        .algo_attrs_auth = null,
        .pw_status = null,
        .fingerprints = null,
        .ca_fingerprints = null,
        .generation_times = null,
    };

    // AID (tag 4F)
    if (findTlvTag(entries, 0x4F)) |aid_data| {
        const copy_len = @min(aid_data.len, 16);
        @memcpy(app_data.aid[0..copy_len], aid_data[0..copy_len]);
    }

    // Historical bytes (tag 5F52)
    if (findTlvTag(entries, 0x5F52)) |hist| {
        app_data.historical_bytes = hist;
    }

    // Extended capabilities (tag C0)
    if (findTlvTag(entries, 0xC0)) |ext_cap| {
        app_data.extended_capabilities = ExtendedCapabilities.parse(ext_cap);
    }

    // Algorithm attributes
    if (findTlvTag(entries, 0xC1)) |aa| app_data.algo_attrs_sig = aa;
    if (findTlvTag(entries, 0xC2)) |aa| app_data.algo_attrs_dec = aa;
    if (findTlvTag(entries, 0xC3)) |aa| app_data.algo_attrs_auth = aa;

    // PW status (tag C4)
    if (findTlvTag(entries, 0xC4)) |pw| {
        app_data.pw_status = PwStatus.parse(pw);
    }

    // Fingerprints (tag C5)
    if (findTlvTag(entries, 0xC5)) |fp| {
        if (fp.len >= 60) {
            app_data.fingerprints = fp[0..60].*;
        }
    }

    // CA fingerprints (tag C6)
    if (findTlvTag(entries, 0xC6)) |cafp| {
        if (cafp.len >= 60) {
            app_data.ca_fingerprints = cafp[0..60].*;
        }
    }

    // Generation times (tag CD)
    if (findTlvTag(entries, 0xCD)) |gt| {
        if (gt.len >= 12) {
            app_data.generation_times = gt[0..12].*;
        }
    }

    return app_data;
}

// ---------------------------------------------------------------------------
// DigestInfo prefix for PKCS#1 v1.5 signature on card
// ---------------------------------------------------------------------------

/// Algorithm identifier for hash algorithms in DigestInfo (PKCS#1 v1.5).
/// OpenPGP cards expect the DigestInfo-wrapped hash for RSA signatures.
pub const DigestInfoPrefix = struct {
    pub const sha256: []const u8 = &.{
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20,
    };
    pub const sha384: []const u8 = &.{
        0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
        0x00, 0x04, 0x30,
    };
    pub const sha512: []const u8 = &.{
        0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
        0x00, 0x04, 0x40,
    };
    pub const sha1: []const u8 = &.{
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
        0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
    };

    /// Get the DigestInfo prefix for a hash algorithm.
    pub fn forAlgorithm(algo: u8) ?[]const u8 {
        return switch (algo) {
            2 => sha1,
            8 => sha256,
            9 => sha384,
            10 => sha512,
            else => null,
        };
    }
};

/// Build DigestInfo structure for RSA card signature.
///
/// Returns DigestInfo = SEQUENCE { AlgorithmIdentifier, OCTET STRING hash }
pub fn buildDigestInfo(allocator: Allocator, hash_algo: u8, hash: []const u8) ![]u8 {
    const prefix = DigestInfoPrefix.forAlgorithm(hash_algo) orelse return CardError.UnsupportedCard;
    const result = try allocator.alloc(u8, prefix.len + hash.len);
    @memcpy(result[0..prefix.len], prefix);
    @memcpy(result[prefix.len..], hash);
    return result;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check if a byte slice is all zeros.
fn isZero(data: []const u8) bool {
    for (data) |b| {
        if (b != 0) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ApduCommand serialize basic" {
    const allocator = std.testing.allocator;

    // Simple command with no data and no Le
    const cmd = ApduCommand{
        .cla = 0x00,
        .ins = 0xA4,
        .p1 = 0x04,
        .p2 = 0x00,
        .data = null,
        .le = null,
    };

    const serialized = try cmd.serialize(allocator);
    defer allocator.free(serialized);

    try std.testing.expectEqual(@as(usize, 4), serialized.len);
    try std.testing.expectEqual(@as(u8, 0x00), serialized[0]);
    try std.testing.expectEqual(@as(u8, 0xA4), serialized[1]);
    try std.testing.expectEqual(@as(u8, 0x04), serialized[2]);
    try std.testing.expectEqual(@as(u8, 0x00), serialized[3]);
}

test "ApduCommand serialize with data" {
    const allocator = std.testing.allocator;

    const data = [_]u8{ 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01 };
    const cmd = ApduCommand{
        .cla = 0x00,
        .ins = 0xA4,
        .p1 = 0x04,
        .p2 = 0x00,
        .data = &data,
        .le = null,
    };

    const serialized = try cmd.serialize(allocator);
    defer allocator.free(serialized);

    // CLA INS P1 P2 Lc Data = 4 + 1 + 6 = 11
    try std.testing.expectEqual(@as(usize, 11), serialized.len);
    try std.testing.expectEqual(@as(u8, 6), serialized[4]); // Lc
    try std.testing.expectEqualSlices(u8, &data, serialized[5..11]);
}

test "ApduCommand serialize with Le" {
    const allocator = std.testing.allocator;

    const cmd = ApduCommand{
        .cla = 0x00,
        .ins = 0xCA,
        .p1 = 0x00,
        .p2 = 0x6E,
        .data = null,
        .le = 256,
    };

    const serialized = try cmd.serialize(allocator);
    defer allocator.free(serialized);

    // CLA INS P1 P2 Le = 5
    try std.testing.expectEqual(@as(usize, 5), serialized.len);
    try std.testing.expectEqual(@as(u8, 0x00), serialized[4]); // Le=256 encodes as 0x00
}

test "ApduCommand serialize with data and Le" {
    const allocator = std.testing.allocator;

    const data = [_]u8{ 0x01, 0x02, 0x03 };
    const cmd = ApduCommand{
        .cla = 0x00,
        .ins = 0x2A,
        .p1 = 0x9E,
        .p2 = 0x9A,
        .data = &data,
        .le = 256,
    };

    const serialized = try cmd.serialize(allocator);
    defer allocator.free(serialized);

    // CLA INS P1 P2 Lc Data Le = 4 + 1 + 3 + 1 = 9
    try std.testing.expectEqual(@as(usize, 9), serialized.len);
    try std.testing.expectEqual(@as(u8, 3), serialized[4]); // Lc
    try std.testing.expectEqualSlices(u8, &data, serialized[5..8]);
    try std.testing.expectEqual(@as(u8, 0x00), serialized[8]); // Le=256
}

test "ApduCommand serializedLength matches serialize" {
    const allocator = std.testing.allocator;

    const data = [_]u8{ 0xAA, 0xBB };
    const cmd = ApduCommand{
        .cla = 0x00,
        .ins = 0x20,
        .p1 = 0x00,
        .p2 = 0x81,
        .data = &data,
        .le = 100,
    };

    const serialized = try cmd.serialize(allocator);
    defer allocator.free(serialized);

    try std.testing.expectEqual(serialized.len, cmd.serializedLength());
}

test "ApduResponse isSuccess" {
    const resp_ok = ApduResponse{ .data = &.{}, .sw1 = 0x90, .sw2 = 0x00 };
    try std.testing.expect(resp_ok.isSuccess());

    const resp_fail = ApduResponse{ .data = &.{}, .sw1 = 0x69, .sw2 = 0x82 };
    try std.testing.expect(!resp_fail.isSuccess());
}

test "ApduResponse hasMoreData" {
    const resp = ApduResponse{ .data = &.{}, .sw1 = 0x61, .sw2 = 0x40 };
    try std.testing.expect(resp.hasMoreData());
    try std.testing.expectEqual(@as(u8, 0x40), resp.remainingBytes().?);
}

test "ApduResponse wrong pin detection" {
    const resp = ApduResponse{ .data = &.{}, .sw1 = 0x63, .sw2 = 0xC3 };
    try std.testing.expect(resp.isWrongPin());
    try std.testing.expectEqual(@as(u8, 3), resp.pinRetriesLeft().?);
}

test "ApduResponse pin blocked detection" {
    const resp = ApduResponse{ .data = &.{}, .sw1 = 0x69, .sw2 = 0x83 };
    try std.testing.expect(resp.isPinBlocked());
    try std.testing.expect(!resp.isSuccess());
}

test "ApduResponse statusWord" {
    const resp = ApduResponse{ .data = &.{}, .sw1 = 0x90, .sw2 = 0x00 };
    try std.testing.expectEqual(@as(u16, 0x9000), resp.statusWord());
}

test "ApduResponse statusDescription" {
    const ok = ApduResponse{ .data = &.{}, .sw1 = 0x90, .sw2 = 0x00 };
    try std.testing.expectEqualStrings("Success", ok.statusDescription());

    const auth_needed = ApduResponse{ .data = &.{}, .sw1 = 0x69, .sw2 = 0x82 };
    try std.testing.expectEqualStrings("Security status not satisfied", auth_needed.statusDescription());

    const blocked = ApduResponse{ .data = &.{}, .sw1 = 0x69, .sw2 = 0x83 };
    try std.testing.expectEqualStrings("Authentication method blocked", blocked.statusDescription());
}

test "ApduResponse parse" {
    const allocator = std.testing.allocator;

    // Response with data
    const raw = [_]u8{ 0x01, 0x02, 0x03, 0x90, 0x00 };
    const resp = try ApduResponse.parse(allocator, &raw);
    defer resp.deinit(allocator);

    try std.testing.expect(resp.isSuccess());
    try std.testing.expectEqual(@as(usize, 3), resp.data.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, resp.data);
}

test "ApduResponse parse status only" {
    const allocator = std.testing.allocator;

    const raw = [_]u8{ 0x90, 0x00 };
    const resp = try ApduResponse.parse(allocator, &raw);
    defer resp.deinit(allocator);

    try std.testing.expect(resp.isSuccess());
    try std.testing.expectEqual(@as(usize, 0), resp.data.len);
}

test "ApduResponse parse too short" {
    const allocator = std.testing.allocator;
    const result = ApduResponse.parse(allocator, &[_]u8{0x90});
    try std.testing.expectError(CardError.MalformedResponse, result);
}

test "PinType properties" {
    try std.testing.expectEqual(@as(u8, 0x81), @intFromEnum(PinType.user));
    try std.testing.expectEqual(@as(u8, 0x83), @intFromEnum(PinType.admin));

    try std.testing.expectEqualStrings("123456", PinType.user.defaultPin());
    try std.testing.expectEqualStrings("12345678", PinType.admin.defaultPin());

    try std.testing.expectEqual(@as(usize, 6), PinType.user.minLength());
    try std.testing.expectEqual(@as(usize, 8), PinType.admin.minLength());
}

test "KeyRef properties" {
    try std.testing.expectEqual(@as(u8, 0xB6), @intFromEnum(KeyRef.signature));
    try std.testing.expectEqual(@as(u8, 0xB8), @intFromEnum(KeyRef.decryption));
    try std.testing.expectEqual(@as(u8, 0xA4), @intFromEnum(KeyRef.authentication));

    try std.testing.expectEqualStrings("Signature", KeyRef.signature.name());
    try std.testing.expectEqualStrings("Decryption", KeyRef.decryption.name());
    try std.testing.expectEqualStrings("Authentication", KeyRef.authentication.name());

    try std.testing.expectEqual(@as(u16, 0x00C7), KeyRef.signature.fingerprintTag());
    try std.testing.expectEqual(@as(u16, 0x00C8), KeyRef.decryption.fingerprintTag());
    try std.testing.expectEqual(@as(u16, 0x00C9), KeyRef.authentication.fingerprintTag());
}

test "selectOpenPgpApp command" {
    const cmd = selectOpenPgpApp();
    try std.testing.expectEqual(@as(u8, 0x00), cmd.cla);
    try std.testing.expectEqual(@as(u8, 0xA4), cmd.ins);
    try std.testing.expectEqual(@as(u8, 0x04), cmd.p1);
    try std.testing.expectEqualSlices(u8, &OPENPGP_AID, cmd.data.?);
}

test "getData command" {
    const cmd = getData(0x006E);
    try std.testing.expectEqual(@as(u8, 0xCA), cmd.ins);
    try std.testing.expectEqual(@as(u8, 0x00), cmd.p1);
    try std.testing.expectEqual(@as(u8, 0x6E), cmd.p2);
    try std.testing.expect(cmd.data == null);
    try std.testing.expectEqual(@as(u16, 256), cmd.le.?);
}

test "verify command" {
    const pin = "123456";
    const cmd = verify(.user, pin);
    try std.testing.expectEqual(@as(u8, 0x20), cmd.ins);
    try std.testing.expectEqual(@as(u8, 0x81), cmd.p2);
    try std.testing.expectEqualSlices(u8, pin, cmd.data.?);
}

test "computeDigitalSignature command" {
    const hash = [_]u8{0xAA} ** 32;
    const cmd = computeDigitalSignature(&hash);
    try std.testing.expectEqual(@as(u8, 0x2A), cmd.ins);
    try std.testing.expectEqual(@as(u8, 0x9E), cmd.p1);
    try std.testing.expectEqual(@as(u8, 0x9A), cmd.p2);
}

test "decipher command" {
    const ciphertext = [_]u8{0xBB} ** 64;
    const cmd = decipher(&ciphertext);
    try std.testing.expectEqual(@as(u8, 0x2A), cmd.ins);
    try std.testing.expectEqual(@as(u8, 0x80), cmd.p1);
    try std.testing.expectEqual(@as(u8, 0x86), cmd.p2);
}

test "putData command" {
    const data = [_]u8{ 0x01, 0x02 };
    const cmd = putData(0x005B, &data);
    try std.testing.expectEqual(@as(u8, 0xDA), cmd.ins);
    try std.testing.expectEqual(@as(u8, 0x00), cmd.p1);
    try std.testing.expectEqual(@as(u8, 0x5B), cmd.p2);
}

test "generateAsymmetricKey command" {
    const cmd = generateAsymmetricKey(.signature);
    try std.testing.expectEqual(@as(u8, 0x47), cmd.ins);
    try std.testing.expectEqual(@as(u8, 0x80), cmd.p1);
    try std.testing.expectEqual(@as(u8, 0xB6), cmd.data.?[0]);
}

test "readPublicKeyFromCard command" {
    const cmd = readPublicKeyFromCard(.decryption);
    try std.testing.expectEqual(@as(u8, 0x47), cmd.ins);
    try std.testing.expectEqual(@as(u8, 0x81), cmd.p1);
    try std.testing.expectEqual(@as(u8, 0xB8), cmd.data.?[0]);
}

test "TLV parser basic" {
    const allocator = std.testing.allocator;

    // Tag 4F, Length 6, Value: D2 76 00 01 24 01
    const data = [_]u8{ 0x4F, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01 };
    const entries = try parseTlv(allocator, &data);
    defer allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqual(@as(u16, 0x4F), entries[0].tag);
    try std.testing.expectEqual(@as(usize, 6), entries[0].value.len);
    try std.testing.expectEqualSlices(u8, &OPENPGP_AID, entries[0].value);
}

test "TLV parser multiple entries" {
    const allocator = std.testing.allocator;

    // Two entries: tag C0 len 2 val [FF 00], tag C1 len 1 val [01]
    const data = [_]u8{ 0xC0, 0x02, 0xFF, 0x00, 0xC1, 0x01, 0x01 };
    const entries = try parseTlv(allocator, &data);
    defer allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqual(@as(u16, 0xC0), entries[0].tag);
    try std.testing.expectEqual(@as(u16, 0xC1), entries[1].tag);
}

test "TLV parser two-byte tag" {
    const allocator = std.testing.allocator;

    // Two-byte tag: 5F 52 (historical bytes), length 3
    const data = [_]u8{ 0x5F, 0x52, 0x03, 0xAA, 0xBB, 0xCC };
    const entries = try parseTlv(allocator, &data);
    defer allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqual(@as(u16, 0x5F52), entries[0].tag);
    try std.testing.expectEqual(@as(usize, 3), entries[0].value.len);
}

test "TLV parser empty data" {
    const allocator = std.testing.allocator;

    const entries = try parseTlv(allocator, &[_]u8{});
    defer allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "TLV parser two-byte length" {
    const allocator = std.testing.allocator;

    // Tag C5 with 2-byte length encoding: 81 3C (60 bytes)
    var data: [63]u8 = undefined;
    data[0] = 0xC5;
    data[1] = 0x81;
    data[2] = 60;
    @memset(data[3..63], 0xAA);

    const entries = try parseTlv(allocator, &data);
    defer allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqual(@as(u16, 0xC5), entries[0].tag);
    try std.testing.expectEqual(@as(usize, 60), entries[0].value.len);
}

test "findTlvTag" {
    const allocator = std.testing.allocator;

    const data = [_]u8{ 0xC0, 0x02, 0xFF, 0x00, 0xC1, 0x01, 0x42 };
    const entries = try parseTlv(allocator, &data);
    defer allocator.free(entries);

    const c0_val = findTlvTag(entries, 0xC0);
    try std.testing.expect(c0_val != null);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0x00 }, c0_val.?);

    const c1_val = findTlvTag(entries, 0xC1);
    try std.testing.expect(c1_val != null);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x42}, c1_val.?);

    try std.testing.expect(findTlvTag(entries, 0xC2) == null);
}

test "isZero" {
    try std.testing.expect(isZero(&[_]u8{ 0, 0, 0 }));
    try std.testing.expect(!isZero(&[_]u8{ 0, 1, 0 }));
    try std.testing.expect(isZero(&[_]u8{}));
}

test "CardInfo serialHex" {
    var info = CardInfo{
        .aid = [_]u8{0} ** 16,
        .version = .{ .major = 3, .minor = 4 },
        .manufacturer = 0x0001,
        .serial = 0xDEADBEEF,
        .sig_key_fingerprint = null,
        .enc_key_fingerprint = null,
        .auth_key_fingerprint = null,
        .sig_count = 0,
        .pin_retries = .{ .user = 3, .reset = 0, .admin = 3 },
    };

    var buf: [8]u8 = undefined;
    info.serialHex(&buf);
    try std.testing.expectEqualStrings("DEADBEEF", &buf);
}

test "CardInfo hasKey" {
    var info = CardInfo{
        .aid = [_]u8{0} ** 16,
        .version = .{ .major = 3, .minor = 4 },
        .manufacturer = 0,
        .serial = 0,
        .sig_key_fingerprint = null,
        .enc_key_fingerprint = null,
        .auth_key_fingerprint = null,
        .sig_count = 0,
        .pin_retries = .{ .user = 3, .reset = 0, .admin = 3 },
    };

    try std.testing.expect(!info.hasAnyKey());
    try std.testing.expect(!info.hasSignatureKey());

    info.sig_key_fingerprint = [_]u8{0xAA} ** 20;
    try std.testing.expect(info.hasAnyKey());
    try std.testing.expect(info.hasSignatureKey());
    try std.testing.expect(!info.hasEncryptionKey());
}

test "buildDigestInfo SHA256" {
    const allocator = std.testing.allocator;
    const hash = [_]u8{0x42} ** 32;
    const di = try buildDigestInfo(allocator, 8, &hash);
    defer allocator.free(di);

    // SHA-256 DigestInfo prefix is 19 bytes + 32 byte hash = 51
    try std.testing.expectEqual(@as(usize, 51), di.len);
    try std.testing.expectEqualSlices(u8, DigestInfoPrefix.sha256, di[0..19]);
    try std.testing.expectEqualSlices(u8, &hash, di[19..51]);
}

test "buildDigestInfo unsupported" {
    const allocator = std.testing.allocator;
    const hash = [_]u8{0x42} ** 16;
    const result = buildDigestInfo(allocator, 99, &hash);
    try std.testing.expectError(CardError.UnsupportedCard, result);
}

test "buildChangePinData" {
    const allocator = std.testing.allocator;
    const data = try buildChangePinData(allocator, "123456", "654321");
    defer allocator.free(data);

    try std.testing.expectEqual(@as(usize, 12), data.len);
    try std.testing.expectEqualStrings("123456654321", data);
}

test "ExtendedCapabilities parse" {
    // Minimal 10-byte extended capabilities
    const data = [_]u8{ 0xFF, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00 };
    const caps = ExtendedCapabilities.parse(&data);
    try std.testing.expect(caps != null);
    try std.testing.expect(caps.?.secure_messaging);
    try std.testing.expect(caps.?.get_challenge);
    try std.testing.expect(caps.?.key_import);
    try std.testing.expect(caps.?.kdf_do);
    try std.testing.expectEqual(@as(u16, 0x0100), caps.?.max_challenge_len);
    try std.testing.expectEqual(@as(u16, 0x0200), caps.?.max_cert_len);
}

test "ExtendedCapabilities parse too short" {
    const data = [_]u8{ 0xFF, 0x00 };
    const caps = ExtendedCapabilities.parse(&data);
    try std.testing.expect(caps == null);
}

test "PwStatus parse" {
    const data = [_]u8{ 0x01, 0x7F, 0x20, 0x7F, 0x03, 0x00, 0x03 };
    const pw = PwStatus.parse(&data);
    try std.testing.expect(pw != null);
    try std.testing.expect(pw.?.pw1_multi_use);
    try std.testing.expectEqual(@as(u8, 0x7F), pw.?.max_pw1_len);
    try std.testing.expectEqual(@as(u8, 3), pw.?.pw1_retries);
    try std.testing.expectEqual(@as(u8, 0), pw.?.rc_retries);
    try std.testing.expectEqual(@as(u8, 3), pw.?.pw3_retries);
}

test "PwStatus parse too short" {
    const data = [_]u8{ 0x01, 0x7F };
    const pw = PwStatus.parse(&data);
    try std.testing.expect(pw == null);
}

test "terminateDf command" {
    const cmd = terminateDf();
    try std.testing.expectEqual(@as(u8, 0xE6), cmd.ins);
    try std.testing.expect(cmd.data == null);
}

test "activateFile command" {
    const cmd = activateFile();
    try std.testing.expectEqual(@as(u8, 0x44), cmd.ins);
    try std.testing.expect(cmd.data == null);
}

test "resetRetryCounter command" {
    const new_pin = "123456";
    const cmd = resetRetryCounter(new_pin);
    try std.testing.expectEqual(@as(u8, 0x2C), cmd.ins);
    try std.testing.expectEqual(@as(u8, 0x02), cmd.p1);
    try std.testing.expectEqual(@as(u8, 0x81), cmd.p2);
    try std.testing.expectEqualSlices(u8, new_pin, cmd.data.?);
}

test "internalAuthenticate command" {
    const data = [_]u8{0xCC} ** 20;
    const cmd = internalAuthenticate(&data);
    try std.testing.expectEqual(@as(u8, 0x88), cmd.ins);
    try std.testing.expectEqual(@as(u8, 0x00), cmd.p1);
}

test "verifyStatus command" {
    const cmd = verifyStatus(.admin);
    try std.testing.expectEqual(@as(u8, 0x20), cmd.ins);
    try std.testing.expectEqual(@as(u8, 0x83), cmd.p2);
    try std.testing.expect(cmd.data == null);
    try std.testing.expect(cmd.le == null);
}

test "getResponse command" {
    const cmd = getResponse(0x40);
    try std.testing.expectEqual(@as(u8, 0xC0), cmd.ins);
    try std.testing.expectEqual(@as(u16, 0x40), cmd.le.?);
}

test "DigestInfoPrefix forAlgorithm" {
    try std.testing.expect(DigestInfoPrefix.forAlgorithm(8) != null); // SHA256
    try std.testing.expect(DigestInfoPrefix.forAlgorithm(10) != null); // SHA512
    try std.testing.expect(DigestInfoPrefix.forAlgorithm(2) != null); // SHA1
    try std.testing.expect(DigestInfoPrefix.forAlgorithm(99) == null); // Unknown
}
