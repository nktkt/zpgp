// SPDX-License-Identifier: MIT
//! PKCS#11 Hardware Token Interface — Zig-native abstraction layer.
//!
//! Provides an abstract interface for interacting with PKCS#11 hardware
//! security modules (HSMs) and smart card tokens. This is a pure Zig
//! abstraction layer (not direct C FFI) designed to be implemented by
//! platform-specific backends.
//!
//! The design follows the PKCS#11 (Cryptoki) specification v2.40:
//!   - Slot and token management
//!   - Session handling
//!   - Key object discovery
//!   - Cryptographic operations (sign, verify)
//!   - PIN authentication
//!
//! This module can be plugged into the OpenPGP signing pipeline via
//! the `HardwareTokenProvider` interface.
//!
//! Reference: PKCS#11 v2.40 (OASIS Standard)
//!            RSA Laboratories PKCS#11 Cryptographic Token Interface

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

// ---------------------------------------------------------------------------
// PKCS#11 Error types
// ---------------------------------------------------------------------------

/// Errors corresponding to PKCS#11 CK_RV return values.
pub const Pkcs11Error = error{
    /// CKR_GENERAL_ERROR (0x00000005)
    GeneralError,
    /// CKR_SLOT_ID_INVALID (0x00000003)
    SlotIdInvalid,
    /// CKR_TOKEN_NOT_PRESENT (0x000000E0)
    TokenNotPresent,
    /// CKR_TOKEN_NOT_RECOGNIZED (0x000000E1)
    TokenNotRecognized,
    /// CKR_SESSION_HANDLE_INVALID (0x000000B3)
    SessionHandleInvalid,
    /// CKR_SESSION_CLOSED (0x000000B0)
    SessionClosed,
    /// CKR_SESSION_COUNT (0x000000B1)
    SessionLimitReached,
    /// CKR_PIN_INCORRECT (0x000000A0)
    PinIncorrect,
    /// CKR_PIN_LOCKED (0x000000A4)
    PinLocked,
    /// CKR_PIN_EXPIRED (0x000000A3)
    PinExpired,
    /// CKR_PIN_LEN_RANGE (0x000000A1)
    PinLenRange,
    /// CKR_USER_ALREADY_LOGGED_IN (0x00000100)
    UserAlreadyLoggedIn,
    /// CKR_USER_NOT_LOGGED_IN (0x00000101)
    UserNotLoggedIn,
    /// CKR_KEY_HANDLE_INVALID (0x00000060)
    KeyHandleInvalid,
    /// CKR_KEY_TYPE_INCONSISTENT (0x00000063)
    KeyTypeInconsistent,
    /// CKR_KEY_FUNCTION_NOT_PERMITTED (0x00000068)
    KeyFunctionNotPermitted,
    /// CKR_MECHANISM_INVALID (0x00000070)
    MechanismInvalid,
    /// CKR_MECHANISM_PARAM_INVALID (0x00000071)
    MechanismParamInvalid,
    /// CKR_OBJECT_HANDLE_INVALID (0x00000082)
    ObjectHandleInvalid,
    /// CKR_OPERATION_ACTIVE (0x00000090)
    OperationActive,
    /// CKR_OPERATION_NOT_INITIALIZED (0x00000091)
    OperationNotInitialized,
    /// CKR_DATA_LEN_RANGE (0x00000021)
    DataLenRange,
    /// CKR_SIGNATURE_INVALID (0x000000C0)
    SignatureInvalid,
    /// CKR_SIGNATURE_LEN_RANGE (0x000000C1)
    SignatureLenRange,
    /// CKR_BUFFER_TOO_SMALL (0x00000150)
    BufferTooSmall,
    /// CKR_DEVICE_ERROR (0x00000030)
    DeviceError,
    /// CKR_DEVICE_REMOVED (0x00000032)
    DeviceRemoved,
    /// CKR_DEVICE_MEMORY (0x00000031)
    DeviceMemory,
    /// CKR_FUNCTION_NOT_SUPPORTED (0x00000054)
    FunctionNotSupported,
    /// CKR_CRYPTOKI_NOT_INITIALIZED (0x00000190)
    CryptokiNotInitialized,
    /// CKR_CRYPTOKI_ALREADY_INITIALIZED (0x00000191)
    CryptokiAlreadyInitialized,
    /// Out of host memory.
    OutOfMemory,
    /// Backend-specific error not mapped to a standard CK_RV.
    BackendError,
};

/// Map a PKCS#11 CK_RV return value to a Zig error.
pub fn mapCkRv(rv: u32) Pkcs11Error {
    return switch (rv) {
        0x00000000 => unreachable, // CKR_OK should not be mapped to an error
        0x00000003 => Pkcs11Error.SlotIdInvalid,
        0x00000005 => Pkcs11Error.GeneralError,
        0x00000021 => Pkcs11Error.DataLenRange,
        0x00000030 => Pkcs11Error.DeviceError,
        0x00000031 => Pkcs11Error.DeviceMemory,
        0x00000032 => Pkcs11Error.DeviceRemoved,
        0x00000054 => Pkcs11Error.FunctionNotSupported,
        0x00000060 => Pkcs11Error.KeyHandleInvalid,
        0x00000063 => Pkcs11Error.KeyTypeInconsistent,
        0x00000068 => Pkcs11Error.KeyFunctionNotPermitted,
        0x00000070 => Pkcs11Error.MechanismInvalid,
        0x00000071 => Pkcs11Error.MechanismParamInvalid,
        0x00000082 => Pkcs11Error.ObjectHandleInvalid,
        0x00000090 => Pkcs11Error.OperationActive,
        0x00000091 => Pkcs11Error.OperationNotInitialized,
        0x000000A0 => Pkcs11Error.PinIncorrect,
        0x000000A1 => Pkcs11Error.PinLenRange,
        0x000000A3 => Pkcs11Error.PinExpired,
        0x000000A4 => Pkcs11Error.PinLocked,
        0x000000B0 => Pkcs11Error.SessionClosed,
        0x000000B1 => Pkcs11Error.SessionLimitReached,
        0x000000B3 => Pkcs11Error.SessionHandleInvalid,
        0x000000C0 => Pkcs11Error.SignatureInvalid,
        0x000000C1 => Pkcs11Error.SignatureLenRange,
        0x000000E0 => Pkcs11Error.TokenNotPresent,
        0x000000E1 => Pkcs11Error.TokenNotRecognized,
        0x00000100 => Pkcs11Error.UserAlreadyLoggedIn,
        0x00000101 => Pkcs11Error.UserNotLoggedIn,
        0x00000150 => Pkcs11Error.BufferTooSmall,
        0x00000190 => Pkcs11Error.CryptokiNotInitialized,
        0x00000191 => Pkcs11Error.CryptokiAlreadyInitialized,
        else => Pkcs11Error.GeneralError,
    };
}

// ---------------------------------------------------------------------------
// PKCS#11 Mechanism types
// ---------------------------------------------------------------------------

/// PKCS#11 mechanism type identifiers (CKM_*).
///
/// These correspond to the cryptographic mechanisms supported by tokens.
/// Only mechanisms relevant to OpenPGP operations are included.
pub const MechanismType = enum(u32) {
    /// CKM_RSA_PKCS — PKCS#1 v1.5 RSA
    rsa_pkcs = 0x00000001,
    /// CKM_RSA_9796 — ISO 9796 RSA
    rsa_9796 = 0x00000002,
    /// CKM_RSA_X_509 — Raw RSA
    rsa_x_509 = 0x00000003,
    /// CKM_MD5_RSA_PKCS
    md5_rsa_pkcs = 0x00000005,
    /// CKM_SHA1_RSA_PKCS
    sha1_rsa_pkcs = 0x00000006,
    /// CKM_SHA256_RSA_PKCS
    sha256_rsa_pkcs = 0x00000040,
    /// CKM_SHA384_RSA_PKCS
    sha384_rsa_pkcs = 0x00000041,
    /// CKM_SHA512_RSA_PKCS
    sha512_rsa_pkcs = 0x00000042,
    /// CKM_SHA224_RSA_PKCS
    sha224_rsa_pkcs = 0x00000046,
    /// CKM_RSA_PKCS_PSS — PKCS#1 PSS RSA
    rsa_pkcs_pss = 0x0000000D,
    /// CKM_SHA256_RSA_PKCS_PSS
    sha256_rsa_pkcs_pss = 0x00000043,
    /// CKM_SHA384_RSA_PKCS_PSS
    sha384_rsa_pkcs_pss = 0x00000044,
    /// CKM_SHA512_RSA_PKCS_PSS
    sha512_rsa_pkcs_pss = 0x00000045,
    /// CKM_DSA
    dsa = 0x00000011,
    /// CKM_DSA_SHA1
    dsa_sha1 = 0x00000012,
    /// CKM_DSA_SHA256
    dsa_sha256 = 0x00000013,
    /// CKM_ECDSA
    ecdsa = 0x00001041,
    /// CKM_ECDSA_SHA1
    ecdsa_sha1 = 0x00001042,
    /// CKM_ECDSA_SHA256
    ecdsa_sha256 = 0x00001043,
    /// CKM_ECDSA_SHA384
    ecdsa_sha384 = 0x00001044,
    /// CKM_ECDSA_SHA512
    ecdsa_sha512 = 0x00001045,
    /// CKM_EDDSA (Edwards-curve DSA)
    eddsa = 0x00001057,
    _,

    /// Human-readable name for the mechanism.
    pub fn name(self: MechanismType) []const u8 {
        return switch (self) {
            .rsa_pkcs => "CKM_RSA_PKCS",
            .rsa_9796 => "CKM_RSA_9796",
            .rsa_x_509 => "CKM_RSA_X_509",
            .md5_rsa_pkcs => "CKM_MD5_RSA_PKCS",
            .sha1_rsa_pkcs => "CKM_SHA1_RSA_PKCS",
            .sha256_rsa_pkcs => "CKM_SHA256_RSA_PKCS",
            .sha384_rsa_pkcs => "CKM_SHA384_RSA_PKCS",
            .sha512_rsa_pkcs => "CKM_SHA512_RSA_PKCS",
            .sha224_rsa_pkcs => "CKM_SHA224_RSA_PKCS",
            .rsa_pkcs_pss => "CKM_RSA_PKCS_PSS",
            .sha256_rsa_pkcs_pss => "CKM_SHA256_RSA_PKCS_PSS",
            .sha384_rsa_pkcs_pss => "CKM_SHA384_RSA_PKCS_PSS",
            .sha512_rsa_pkcs_pss => "CKM_SHA512_RSA_PKCS_PSS",
            .dsa => "CKM_DSA",
            .dsa_sha1 => "CKM_DSA_SHA1",
            .dsa_sha256 => "CKM_DSA_SHA256",
            .ecdsa => "CKM_ECDSA",
            .ecdsa_sha1 => "CKM_ECDSA_SHA1",
            .ecdsa_sha256 => "CKM_ECDSA_SHA256",
            .ecdsa_sha384 => "CKM_ECDSA_SHA384",
            .ecdsa_sha512 => "CKM_ECDSA_SHA512",
            .eddsa => "CKM_EDDSA",
            _ => "Unknown Mechanism",
        };
    }

    /// Whether this mechanism is an RSA-based mechanism.
    pub fn isRsa(self: MechanismType) bool {
        return switch (self) {
            .rsa_pkcs, .rsa_9796, .rsa_x_509 => true,
            .md5_rsa_pkcs, .sha1_rsa_pkcs => true,
            .sha256_rsa_pkcs, .sha384_rsa_pkcs, .sha512_rsa_pkcs, .sha224_rsa_pkcs => true,
            .rsa_pkcs_pss, .sha256_rsa_pkcs_pss, .sha384_rsa_pkcs_pss, .sha512_rsa_pkcs_pss => true,
            else => false,
        };
    }

    /// Whether this mechanism performs hashing internally.
    pub fn includesHash(self: MechanismType) bool {
        return switch (self) {
            .md5_rsa_pkcs, .sha1_rsa_pkcs => true,
            .sha256_rsa_pkcs, .sha384_rsa_pkcs, .sha512_rsa_pkcs, .sha224_rsa_pkcs => true,
            .sha256_rsa_pkcs_pss, .sha384_rsa_pkcs_pss, .sha512_rsa_pkcs_pss => true,
            .dsa_sha1, .dsa_sha256 => true,
            .ecdsa_sha1, .ecdsa_sha256, .ecdsa_sha384, .ecdsa_sha512 => true,
            else => false,
        };
    }

    /// Whether this mechanism can be used for signing.
    pub fn canSign(self: MechanismType) bool {
        return switch (self) {
            .rsa_pkcs, .rsa_9796, .rsa_x_509 => true,
            .md5_rsa_pkcs, .sha1_rsa_pkcs => true,
            .sha256_rsa_pkcs, .sha384_rsa_pkcs, .sha512_rsa_pkcs, .sha224_rsa_pkcs => true,
            .rsa_pkcs_pss, .sha256_rsa_pkcs_pss, .sha384_rsa_pkcs_pss, .sha512_rsa_pkcs_pss => true,
            .dsa, .dsa_sha1, .dsa_sha256 => true,
            .ecdsa, .ecdsa_sha1, .ecdsa_sha256, .ecdsa_sha384, .ecdsa_sha512 => true,
            .eddsa => true,
            _ => false,
        };
    }
};

/// Mechanism information describing capabilities and key size ranges.
pub const MechanismInfo = struct {
    /// Mechanism type.
    mechanism: MechanismType,
    /// Minimum key size in bits.
    min_key_size: u32,
    /// Maximum key size in bits.
    max_key_size: u32,
    /// CKF_SIGN: mechanism can be used for signing.
    can_sign: bool,
    /// CKF_VERIFY: mechanism can be used for verification.
    can_verify: bool,
    /// CKF_ENCRYPT: mechanism can be used for encryption.
    can_encrypt: bool,
    /// CKF_DECRYPT: mechanism can be used for decryption.
    can_decrypt: bool,
    /// CKF_HW: mechanism is performed in hardware.
    hardware: bool,
};

// ---------------------------------------------------------------------------
// Object types
// ---------------------------------------------------------------------------

/// PKCS#11 object class (CKO_*).
pub const ObjectClass = enum(u32) {
    /// CKO_DATA
    data = 0x00000000,
    /// CKO_CERTIFICATE
    certificate = 0x00000001,
    /// CKO_PUBLIC_KEY
    public_key = 0x00000002,
    /// CKO_PRIVATE_KEY
    private_key = 0x00000003,
    /// CKO_SECRET_KEY
    secret_key = 0x00000004,
    _,

    pub fn name(self: ObjectClass) []const u8 {
        return switch (self) {
            .data => "CKO_DATA",
            .certificate => "CKO_CERTIFICATE",
            .public_key => "CKO_PUBLIC_KEY",
            .private_key => "CKO_PRIVATE_KEY",
            .secret_key => "CKO_SECRET_KEY",
            _ => "Unknown",
        };
    }
};

/// PKCS#11 key type (CKK_*).
pub const KeyType = enum(u32) {
    /// CKK_RSA
    rsa = 0x00000000,
    /// CKK_DSA
    dsa = 0x00000001,
    /// CKK_DH
    dh = 0x00000002,
    /// CKK_EC
    ec = 0x00000003,
    /// CKK_EC_EDWARDS
    ec_edwards = 0x00000040,
    /// CKK_EC_MONTGOMERY
    ec_montgomery = 0x00000041,
    _,

    pub fn name(self: KeyType) []const u8 {
        return switch (self) {
            .rsa => "CKK_RSA",
            .dsa => "CKK_DSA",
            .dh => "CKK_DH",
            .ec => "CKK_EC",
            .ec_edwards => "CKK_EC_EDWARDS",
            .ec_montgomery => "CKK_EC_MONTGOMERY",
            _ => "Unknown",
        };
    }
};

/// PKCS#11 user type for login operations.
pub const UserType = enum(u32) {
    /// CKU_SO — Security Officer
    security_officer = 0,
    /// CKU_USER — Normal user
    user = 1,
    /// CKU_CONTEXT_SPECIFIC — Context-specific (for specific operations)
    context_specific = 2,
};

// ---------------------------------------------------------------------------
// Token information
// ---------------------------------------------------------------------------

/// Information about a PKCS#11 token, corresponding to CK_TOKEN_INFO.
pub const TokenInfo = struct {
    /// Token label (padded to 32 bytes per PKCS#11 spec).
    label: [32]u8,
    /// Manufacturer ID (padded to 32 bytes).
    manufacturer_id: [32]u8,
    /// Token model (padded to 16 bytes).
    model: [16]u8,
    /// Token serial number (padded to 16 bytes).
    serial_number: [16]u8,
    /// CKF_TOKEN_INITIALIZED
    initialized: bool,
    /// CKF_USER_PIN_INITIALIZED
    user_pin_initialized: bool,
    /// CKF_LOGIN_REQUIRED
    login_required: bool,
    /// CKF_PROTECTED_AUTHENTICATION_PATH (token has built-in PIN pad)
    protected_auth_path: bool,
    /// CKF_TOKEN_FLAGS raw value
    flags: u32,
    /// Maximum session count (0 = unlimited)
    max_session_count: u32,
    /// Current open session count
    session_count: u32,
    /// Maximum PIN length
    max_pin_len: u32,
    /// Minimum PIN length
    min_pin_len: u32,
    /// Total public memory on token (bytes, 0 = unavailable)
    total_public_memory: u64,
    /// Free public memory on token (bytes, 0 = unavailable)
    free_public_memory: u64,
    /// Total private memory on token (bytes, 0 = unavailable)
    total_private_memory: u64,
    /// Free private memory on token (bytes, 0 = unavailable)
    free_private_memory: u64,
    /// Hardware version
    hw_version: struct { major: u8, minor: u8 },
    /// Firmware version
    fw_version: struct { major: u8, minor: u8 },

    /// Get the label as a trimmed string (removes trailing spaces).
    pub fn labelStr(self: *const TokenInfo) []const u8 {
        return trimPkcs11String(&self.label);
    }

    /// Get the manufacturer as a trimmed string.
    pub fn manufacturerStr(self: *const TokenInfo) []const u8 {
        return trimPkcs11String(&self.manufacturer_id);
    }

    /// Get the model as a trimmed string.
    pub fn modelStr(self: *const TokenInfo) []const u8 {
        return trimPkcs11String(&self.model);
    }

    /// Get the serial number as a trimmed string.
    pub fn serialStr(self: *const TokenInfo) []const u8 {
        return trimPkcs11String(&self.serial_number);
    }
};

/// Trim trailing spaces from a PKCS#11 padded string.
fn trimPkcs11String(s: []const u8) []const u8 {
    var end = s.len;
    while (end > 0 and s[end - 1] == ' ') {
        end -= 1;
    }
    return s[0..end];
}

// ---------------------------------------------------------------------------
// Slot information
// ---------------------------------------------------------------------------

/// Information about a PKCS#11 slot, corresponding to CK_SLOT_INFO.
pub const SlotInfo = struct {
    /// Slot description (padded to 64 bytes).
    description: [64]u8,
    /// Manufacturer ID (padded to 32 bytes).
    manufacturer_id: [32]u8,
    /// CKF_TOKEN_PRESENT
    token_present: bool,
    /// CKF_REMOVABLE_DEVICE
    removable_device: bool,
    /// CKF_HW_SLOT
    hardware_slot: bool,
    /// Slot flags raw value
    flags: u32,
    /// Hardware version
    hw_version: struct { major: u8, minor: u8 },
    /// Firmware version
    fw_version: struct { major: u8, minor: u8 },

    /// Get the description as a trimmed string.
    pub fn descriptionStr(self: *const SlotInfo) []const u8 {
        return trimPkcs11String(&self.description);
    }

    /// Get the manufacturer as a trimmed string.
    pub fn manufacturerStr(self: *const SlotInfo) []const u8 {
        return trimPkcs11String(&self.manufacturer_id);
    }
};

// ---------------------------------------------------------------------------
// Key object handle
// ---------------------------------------------------------------------------

/// Opaque handle to a PKCS#11 object (CK_OBJECT_HANDLE).
pub const ObjectHandle = u64;

/// A key object found on the token.
pub const KeyObject = struct {
    /// Opaque PKCS#11 object handle.
    handle: ObjectHandle,
    /// Object class (public key, private key, etc.).
    class: ObjectClass,
    /// Key type.
    key_type: KeyType,
    /// Key ID attribute (CKA_ID), used to match public/private key pairs.
    id: [32]u8,
    /// Length of the key ID (actual bytes used in the id field).
    id_len: u8,
    /// Key label (CKA_LABEL), human-readable.
    label: [64]u8,
    /// Whether the key has CKA_SIGN = true.
    can_sign: bool,
    /// Whether the key has CKA_DECRYPT = true.
    can_decrypt: bool,
    /// Whether the key has CKA_ENCRYPT = true.
    can_encrypt: bool,
    /// Whether the key has CKA_VERIFY = true.
    can_verify: bool,
    /// Key size in bits (from CKA_MODULUS_BITS for RSA, etc.).
    key_size_bits: u32,

    /// Get the key ID as a slice.
    pub fn keyId(self: *const KeyObject) []const u8 {
        return self.id[0..self.id_len];
    }

    /// Get the label as a trimmed string.
    pub fn labelStr(self: *const KeyObject) []const u8 {
        return trimPkcs11String(&self.label);
    }
};

// ---------------------------------------------------------------------------
// Pkcs11Slot — represents a token slot
// ---------------------------------------------------------------------------

/// Represents a PKCS#11 slot with an optional token.
///
/// Slots are physical or logical readers that may contain a token
/// (smart card, HSM partition, etc.).
pub const Pkcs11Slot = struct {
    /// Slot ID assigned by the PKCS#11 library.
    slot_id: u64,
    /// Cached slot information.
    info: SlotInfo,
    /// Cached token information (if a token is present).
    token_info: ?TokenInfo,

    /// Create a slot descriptor from slot ID and info.
    pub fn init(slot_id: u64, info: SlotInfo, token_info: ?TokenInfo) Pkcs11Slot {
        return .{
            .slot_id = slot_id,
            .info = info,
            .token_info = token_info,
        };
    }

    /// Check if a token is present in this slot.
    pub fn hasToken(self: *const Pkcs11Slot) bool {
        return self.info.token_present and self.token_info != null;
    }

    /// Get the token label, or null if no token.
    pub fn tokenLabel(self: *const Pkcs11Slot) ?[]const u8 {
        if (self.token_info) |*ti| {
            return ti.labelStr();
        }
        return null;
    }

    /// Get the token serial number, or null if no token.
    pub fn tokenSerial(self: *const Pkcs11Slot) ?[]const u8 {
        if (self.token_info) |*ti| {
            return ti.serialStr();
        }
        return null;
    }

    /// Get the slot description.
    pub fn description(self: *const Pkcs11Slot) []const u8 {
        return self.info.descriptionStr();
    }
};

// ---------------------------------------------------------------------------
// Pkcs11Session — open session on a slot
// ---------------------------------------------------------------------------

/// Session type flags.
pub const SessionFlags = struct {
    /// CKF_RW_SESSION: session is read/write (vs read-only).
    rw_session: bool,
    /// CKF_SERIAL_SESSION: required by PKCS#11 spec.
    serial_session: bool,
};

/// Represents an open PKCS#11 session on a token.
///
/// Sessions are the context within which cryptographic operations
/// are performed and objects are accessed.
pub const Pkcs11Session = struct {
    /// Session handle assigned by the PKCS#11 library.
    handle: u64,
    /// Slot ID this session is on.
    slot_id: u64,
    /// Session flags.
    flags: SessionFlags,
    /// Whether a user is logged in on this session.
    logged_in: bool,
    /// The user type logged in (if logged_in is true).
    user_type: ?UserType,
    /// Whether a sign operation is in progress (C_SignInit called).
    sign_active: bool,
    /// The mechanism used for the active sign operation.
    sign_mechanism: ?MechanismType,
    /// Handle of the key used for the active sign operation.
    sign_key: ?ObjectHandle,

    /// Create a new session descriptor.
    pub fn init(handle: u64, slot_id: u64, flags: SessionFlags) Pkcs11Session {
        return .{
            .handle = handle,
            .slot_id = slot_id,
            .flags = flags,
            .logged_in = false,
            .user_type = null,
            .sign_active = false,
            .sign_mechanism = null,
            .sign_key = null,
        };
    }

    /// Check if this session is read/write.
    pub fn isRw(self: *const Pkcs11Session) bool {
        return self.flags.rw_session;
    }

    /// Record a successful login.
    pub fn setLoggedIn(self: *Pkcs11Session, user_type: UserType) void {
        self.logged_in = true;
        self.user_type = user_type;
    }

    /// Record a logout.
    pub fn setLoggedOut(self: *Pkcs11Session) void {
        self.logged_in = false;
        self.user_type = null;
    }

    /// Initialize a signing operation.
    pub fn signInit(self: *Pkcs11Session, mechanism: MechanismType, key: ObjectHandle) Pkcs11Error!void {
        if (self.sign_active) return Pkcs11Error.OperationActive;
        if (!self.logged_in) return Pkcs11Error.UserNotLoggedIn;
        if (!mechanism.canSign()) return Pkcs11Error.MechanismInvalid;

        self.sign_active = true;
        self.sign_mechanism = mechanism;
        self.sign_key = key;
    }

    /// Finalize a signing operation. In a real implementation, this would
    /// produce the signature via the token. Here it validates state.
    pub fn signFinalize(self: *Pkcs11Session) Pkcs11Error!void {
        if (!self.sign_active) return Pkcs11Error.OperationNotInitialized;
        self.sign_active = false;
        self.sign_mechanism = null;
        self.sign_key = null;
    }

    /// Cancel an active signing operation.
    pub fn signCancel(self: *Pkcs11Session) void {
        self.sign_active = false;
        self.sign_mechanism = null;
        self.sign_key = null;
    }
};

// ---------------------------------------------------------------------------
// HardwareTokenProvider — pluggable signing interface
// ---------------------------------------------------------------------------

/// Interface for hardware token signing operations.
///
/// This interface can be plugged into the OpenPGP signing pipeline to
/// delegate signature generation to a hardware token (HSM, smart card)
/// instead of using software-based RSA/DSA/ECDSA.
///
/// Implementations should:
///   1. Open a session to the token
///   2. Authenticate with PIN if required
///   3. Find the appropriate signing key
///   4. Perform C_SignInit + C_Sign
///   5. Return the raw signature bytes
pub const HardwareTokenProvider = struct {
    /// Opaque pointer to implementation-specific context.
    context: *anyopaque,

    /// V-table of function pointers for the implementation.
    vtable: *const VTable,

    pub const VTable = struct {
        /// Sign data using the hardware token.
        ///
        /// The implementation should:
        ///   - Initialize signing with the appropriate mechanism
        ///   - Hash the data if mechanism does not include hashing
        ///   - Return the raw signature bytes
        ///
        /// `key_id` identifies which key on the token to use.
        /// `mechanism` specifies the signing mechanism.
        /// `data` is the data (or hash) to sign.
        signFn: *const fn (
            ctx: *anyopaque,
            allocator: Allocator,
            key_id: []const u8,
            mechanism: MechanismType,
            data: []const u8,
        ) Pkcs11Error![]u8,

        /// Login to the token with a PIN.
        loginFn: *const fn (
            ctx: *anyopaque,
            user_type: UserType,
            pin: []const u8,
        ) Pkcs11Error!void,

        /// Logout from the token.
        logoutFn: *const fn (ctx: *anyopaque) Pkcs11Error!void,

        /// List available signing key IDs on the token.
        listKeysFn: *const fn (
            ctx: *anyopaque,
            allocator: Allocator,
        ) Pkcs11Error![]KeyObject,

        /// Get token information.
        getTokenInfoFn: *const fn (ctx: *anyopaque) Pkcs11Error!TokenInfo,

        /// Check if the provider is connected and ready.
        isReadyFn: *const fn (ctx: *anyopaque) bool,
    };

    /// Sign data using the hardware token.
    pub fn sign(
        self: *const HardwareTokenProvider,
        allocator: Allocator,
        key_id: []const u8,
        mechanism: MechanismType,
        data: []const u8,
    ) Pkcs11Error![]u8 {
        return self.vtable.signFn(self.context, allocator, key_id, mechanism, data);
    }

    /// Login to the token.
    pub fn login(self: *const HardwareTokenProvider, user_type: UserType, pin: []const u8) Pkcs11Error!void {
        return self.vtable.loginFn(self.context, user_type, pin);
    }

    /// Logout from the token.
    pub fn logout(self: *const HardwareTokenProvider) Pkcs11Error!void {
        return self.vtable.logoutFn(self.context);
    }

    /// List signing keys on the token.
    pub fn listKeys(self: *const HardwareTokenProvider, allocator: Allocator) Pkcs11Error![]KeyObject {
        return self.vtable.listKeysFn(self.context, allocator);
    }

    /// Get token information.
    pub fn getTokenInfo(self: *const HardwareTokenProvider) Pkcs11Error!TokenInfo {
        return self.vtable.getTokenInfoFn(self.context);
    }

    /// Check if the provider is ready.
    pub fn isReady(self: *const HardwareTokenProvider) bool {
        return self.vtable.isReadyFn(self.context);
    }
};

// ---------------------------------------------------------------------------
// Mock implementation (for testing)
// ---------------------------------------------------------------------------

/// Mock PKCS#11 token for testing.
///
/// Simulates a hardware token with configurable keys and behavior.
/// Signs data by returning a deterministic "signature" based on the input.
pub const MockToken = struct {
    /// Token info.
    token_info: TokenInfo,
    /// Available keys.
    keys: []const KeyObject,
    /// Whether the mock is "connected".
    connected: bool,
    /// Whether a user is logged in.
    logged_in: bool,
    /// Expected PIN for login.
    expected_pin: []const u8,
    /// Sign call count (for testing).
    sign_count: u32,

    /// Create a mock token with default settings.
    pub fn init() MockToken {
        var label: [32]u8 = .{' '} ** 32;
        @memcpy(label[0..10], "Mock Token");
        var mfr: [32]u8 = .{' '} ** 32;
        @memcpy(mfr[0..9], "Test Corp");
        var model: [16]u8 = .{' '} ** 16;
        @memcpy(model[0..6], "MT1000");
        var serial: [16]u8 = .{' '} ** 16;
        @memcpy(serial[0..8], "00000001");

        return .{
            .token_info = .{
                .label = label,
                .manufacturer_id = mfr,
                .model = model,
                .serial_number = serial,
                .initialized = true,
                .user_pin_initialized = true,
                .login_required = true,
                .protected_auth_path = false,
                .flags = 0x00000001,
                .max_session_count = 16,
                .session_count = 0,
                .max_pin_len = 32,
                .min_pin_len = 4,
                .total_public_memory = 65536,
                .free_public_memory = 32768,
                .total_private_memory = 32768,
                .free_private_memory = 16384,
                .hw_version = .{ .major = 1, .minor = 0 },
                .fw_version = .{ .major = 2, .minor = 1 },
            },
            .keys = &.{},
            .connected = true,
            .logged_in = false,
            .expected_pin = "1234",
            .sign_count = 0,
        };
    }

    /// Create a HardwareTokenProvider backed by this mock.
    pub fn provider(self: *MockToken) HardwareTokenProvider {
        return .{
            .context = @ptrCast(self),
            .vtable = &mock_vtable,
        };
    }

    fn mockSign(
        ctx: *anyopaque,
        allocator: Allocator,
        key_id: []const u8,
        mechanism: MechanismType,
        data: []const u8,
    ) Pkcs11Error![]u8 {
        const self: *MockToken = @ptrCast(@alignCast(ctx));
        if (!self.connected) return Pkcs11Error.DeviceRemoved;
        if (!self.logged_in) return Pkcs11Error.UserNotLoggedIn;
        _ = key_id;

        self.sign_count += 1;

        // Produce a deterministic "signature" for testing
        const sig_len: usize = if (mechanism.isRsa()) 256 else 64;
        const sig = allocator.alloc(u8, sig_len) catch return Pkcs11Error.OutOfMemory;

        // Fill with a hash-like pattern derived from input
        var hash: u32 = 0x12345678;
        for (data) |b| {
            hash = hash *% 31 +% @as(u32, b);
        }
        for (sig, 0..) |*byte, i| {
            byte.* = @truncate(hash +% @as(u32, @intCast(i)));
        }

        return sig;
    }

    fn mockLogin(ctx: *anyopaque, user_type: UserType, pin: []const u8) Pkcs11Error!void {
        const self: *MockToken = @ptrCast(@alignCast(ctx));
        if (!self.connected) return Pkcs11Error.DeviceRemoved;
        if (self.logged_in) return Pkcs11Error.UserAlreadyLoggedIn;
        _ = user_type;

        if (!mem.eql(u8, pin, self.expected_pin)) {
            return Pkcs11Error.PinIncorrect;
        }
        self.logged_in = true;
    }

    fn mockLogout(ctx: *anyopaque) Pkcs11Error!void {
        const self: *MockToken = @ptrCast(@alignCast(ctx));
        if (!self.logged_in) return Pkcs11Error.UserNotLoggedIn;
        self.logged_in = false;
    }

    fn mockListKeys(ctx: *anyopaque, allocator: Allocator) Pkcs11Error![]KeyObject {
        const self: *MockToken = @ptrCast(@alignCast(ctx));
        if (!self.connected) return Pkcs11Error.DeviceRemoved;

        const result = allocator.alloc(KeyObject, self.keys.len) catch return Pkcs11Error.OutOfMemory;
        @memcpy(result, self.keys);
        return result;
    }

    fn mockGetTokenInfo(ctx: *anyopaque) Pkcs11Error!TokenInfo {
        const self: *MockToken = @ptrCast(@alignCast(ctx));
        if (!self.connected) return Pkcs11Error.DeviceRemoved;
        return self.token_info;
    }

    fn mockIsReady(ctx: *anyopaque) bool {
        const self: *MockToken = @ptrCast(@alignCast(ctx));
        return self.connected;
    }

    const mock_vtable: HardwareTokenProvider.VTable = .{
        .signFn = &mockSign,
        .loginFn = &mockLogin,
        .logoutFn = &mockLogout,
        .listKeysFn = &mockListKeys,
        .getTokenInfoFn = &mockGetTokenInfo,
        .isReadyFn = &mockIsReady,
    };
};

/// Create a test KeyObject with the given parameters.
pub fn makeTestKey(
    handle: ObjectHandle,
    class: ObjectClass,
    key_type: KeyType,
    id_bytes: []const u8,
    label_str: []const u8,
) KeyObject {
    var key: KeyObject = .{
        .handle = handle,
        .class = class,
        .key_type = key_type,
        .id = .{0} ** 32,
        .id_len = @intCast(@min(id_bytes.len, 32)),
        .label = .{' '} ** 64,
        .can_sign = (class == .private_key),
        .can_decrypt = (class == .private_key),
        .can_encrypt = (class == .public_key),
        .can_verify = (class == .public_key),
        .key_size_bits = if (key_type == .rsa) 2048 else 256,
    };
    const id_copy_len = @min(id_bytes.len, 32);
    @memcpy(key.id[0..id_copy_len], id_bytes[0..id_copy_len]);
    const label_copy_len = @min(label_str.len, 64);
    @memcpy(key.label[0..label_copy_len], label_str[0..label_copy_len]);
    return key;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "mapCkRv known codes" {
    try std.testing.expectError(Pkcs11Error.SlotIdInvalid, @as(Pkcs11Error!void, mapCkRv(0x00000003)));
    try std.testing.expectError(Pkcs11Error.PinIncorrect, @as(Pkcs11Error!void, mapCkRv(0x000000A0)));
    try std.testing.expectError(Pkcs11Error.TokenNotPresent, @as(Pkcs11Error!void, mapCkRv(0x000000E0)));
    try std.testing.expectError(Pkcs11Error.UserAlreadyLoggedIn, @as(Pkcs11Error!void, mapCkRv(0x00000100)));
    try std.testing.expectError(Pkcs11Error.GeneralError, @as(Pkcs11Error!void, mapCkRv(0xFFFFFFFF))); // unknown
}

fn returnCkRvAsError(rv: u32) Pkcs11Error!void {
    return mapCkRv(rv);
}

test "MechanismType names" {
    try std.testing.expectEqualStrings("CKM_RSA_PKCS", MechanismType.rsa_pkcs.name());
    try std.testing.expectEqualStrings("CKM_SHA256_RSA_PKCS", MechanismType.sha256_rsa_pkcs.name());
    try std.testing.expectEqualStrings("CKM_ECDSA", MechanismType.ecdsa.name());
    try std.testing.expectEqualStrings("CKM_EDDSA", MechanismType.eddsa.name());
}

test "MechanismType properties" {
    try std.testing.expect(MechanismType.rsa_pkcs.isRsa());
    try std.testing.expect(MechanismType.sha256_rsa_pkcs.isRsa());
    try std.testing.expect(!MechanismType.ecdsa.isRsa());
    try std.testing.expect(!MechanismType.eddsa.isRsa());

    try std.testing.expect(MechanismType.sha256_rsa_pkcs.includesHash());
    try std.testing.expect(!MechanismType.rsa_pkcs.includesHash());

    try std.testing.expect(MechanismType.rsa_pkcs.canSign());
    try std.testing.expect(MechanismType.ecdsa.canSign());
    try std.testing.expect(MechanismType.eddsa.canSign());
}

test "ObjectClass and KeyType names" {
    try std.testing.expectEqualStrings("CKO_PRIVATE_KEY", ObjectClass.private_key.name());
    try std.testing.expectEqualStrings("CKO_PUBLIC_KEY", ObjectClass.public_key.name());
    try std.testing.expectEqualStrings("CKK_RSA", KeyType.rsa.name());
    try std.testing.expectEqualStrings("CKK_EC", KeyType.ec.name());
}

test "trimPkcs11String" {
    const padded = "Hello                           ";
    const trimmed = trimPkcs11String(padded);
    try std.testing.expectEqualStrings("Hello", trimmed);

    const no_pad = "NoSpaces";
    try std.testing.expectEqualStrings("NoSpaces", trimPkcs11String(no_pad));

    const all_spaces = "        ";
    try std.testing.expectEqualStrings("", trimPkcs11String(all_spaces));
}

test "TokenInfo string accessors" {
    var info: TokenInfo = undefined;
    info.label = .{' '} ** 32;
    @memcpy(info.label[0..4], "Test");
    info.manufacturer_id = .{' '} ** 32;
    @memcpy(info.manufacturer_id[0..5], "Maker");
    info.model = .{' '} ** 16;
    @memcpy(info.model[0..3], "HSM");
    info.serial_number = .{' '} ** 16;
    @memcpy(info.serial_number[0..8], "12345678");

    try std.testing.expectEqualStrings("Test", info.labelStr());
    try std.testing.expectEqualStrings("Maker", info.manufacturerStr());
    try std.testing.expectEqualStrings("HSM", info.modelStr());
    try std.testing.expectEqualStrings("12345678", info.serialStr());
}

test "SlotInfo string accessors" {
    var info: SlotInfo = undefined;
    info.description = .{' '} ** 64;
    @memcpy(info.description[0..11], "Card Reader");
    info.manufacturer_id = .{' '} ** 32;
    @memcpy(info.manufacturer_id[0..6], "Vendor");

    try std.testing.expectEqualStrings("Card Reader", info.descriptionStr());
    try std.testing.expectEqualStrings("Vendor", info.manufacturerStr());
}

test "Pkcs11Slot basic operations" {
    var desc: [64]u8 = .{' '} ** 64;
    @memcpy(desc[0..9], "Test Slot");
    var mfr: [32]u8 = .{' '} ** 32;
    @memcpy(mfr[0..4], "Test");

    const slot = Pkcs11Slot.init(42, .{
        .description = desc,
        .manufacturer_id = mfr,
        .token_present = true,
        .removable_device = true,
        .hardware_slot = true,
        .flags = 0x07,
        .hw_version = .{ .major = 1, .minor = 0 },
        .fw_version = .{ .major = 1, .minor = 0 },
    }, null);

    try std.testing.expectEqual(@as(u64, 42), slot.slot_id);
    try std.testing.expectEqualStrings("Test Slot", slot.description());
    // No token info set, so these return null
    try std.testing.expect(slot.tokenLabel() == null);
    try std.testing.expect(slot.tokenSerial() == null);
}

test "Pkcs11Session lifecycle" {
    var session = Pkcs11Session.init(1, 0, .{
        .rw_session = true,
        .serial_session = true,
    });

    try std.testing.expect(session.isRw());
    try std.testing.expect(!session.logged_in);

    // Login
    session.setLoggedIn(.user);
    try std.testing.expect(session.logged_in);
    try std.testing.expectEqual(UserType.user, session.user_type.?);

    // Sign init
    try session.signInit(.rsa_pkcs, 100);
    try std.testing.expect(session.sign_active);
    try std.testing.expectEqual(MechanismType.rsa_pkcs, session.sign_mechanism.?);

    // Double sign init should fail
    try std.testing.expectError(Pkcs11Error.OperationActive, session.signInit(.rsa_pkcs, 100));

    // Sign finalize
    try session.signFinalize();
    try std.testing.expect(!session.sign_active);

    // Finalize without init should fail
    try std.testing.expectError(Pkcs11Error.OperationNotInitialized, session.signFinalize());

    // Logout
    session.setLoggedOut();
    try std.testing.expect(!session.logged_in);

    // Sign init without login should fail
    try std.testing.expectError(Pkcs11Error.UserNotLoggedIn, session.signInit(.rsa_pkcs, 100));
}

test "Pkcs11Session sign cancel" {
    var session = Pkcs11Session.init(1, 0, .{
        .rw_session = false,
        .serial_session = true,
    });

    try std.testing.expect(!session.isRw());
    session.setLoggedIn(.user);
    try session.signInit(.sha256_rsa_pkcs, 200);
    try std.testing.expect(session.sign_active);

    session.signCancel();
    try std.testing.expect(!session.sign_active);
    try std.testing.expect(session.sign_mechanism == null);
}

test "KeyObject accessors" {
    const key = makeTestKey(
        1,
        .private_key,
        .rsa,
        &.{ 0x01, 0x02, 0x03, 0x04 },
        "My RSA Key",
    );

    try std.testing.expectEqual(@as(u8, 4), key.id_len);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x04 }, key.keyId());
    try std.testing.expectEqualStrings("My RSA Key", key.labelStr());
    try std.testing.expect(key.can_sign);
    try std.testing.expect(key.can_decrypt);
    try std.testing.expect(!key.can_encrypt);
    try std.testing.expect(!key.can_verify);
    try std.testing.expectEqual(@as(u32, 2048), key.key_size_bits);
}

test "MockToken provider login and sign" {
    const allocator = std.testing.allocator;

    var mock = MockToken.init();
    var prov = mock.provider();

    // Should be ready
    try std.testing.expect(prov.isReady());

    // Login with wrong PIN
    try std.testing.expectError(Pkcs11Error.PinIncorrect, prov.login(.user, "wrong"));

    // Login with correct PIN
    try prov.login(.user, "1234");

    // Double login should fail
    try std.testing.expectError(Pkcs11Error.UserAlreadyLoggedIn, prov.login(.user, "1234"));

    // Sign data
    const sig = try prov.sign(allocator, &.{0x01}, .rsa_pkcs, "test data");
    defer allocator.free(sig);

    try std.testing.expectEqual(@as(usize, 256), sig.len); // RSA mechanism -> 256 byte sig
    try std.testing.expectEqual(@as(u32, 1), mock.sign_count);

    // Logout
    try prov.logout();

    // Sign without login should fail
    try std.testing.expectError(Pkcs11Error.UserNotLoggedIn, prov.sign(allocator, &.{0x01}, .rsa_pkcs, "test data"));
}

test "MockToken token info" {
    var mock = MockToken.init();
    const prov = mock.provider();

    const info = try prov.getTokenInfo();
    try std.testing.expectEqualStrings("Mock Token", info.labelStr());
    try std.testing.expectEqualStrings("Test Corp", info.manufacturerStr());
    try std.testing.expectEqualStrings("MT1000", info.modelStr());
    try std.testing.expectEqualStrings("00000001", info.serialStr());
    try std.testing.expect(info.initialized);
    try std.testing.expect(info.login_required);
}

test "MockToken disconnected" {
    var mock = MockToken.init();
    mock.connected = false;
    const prov = mock.provider();

    try std.testing.expect(!prov.isReady());
    try std.testing.expectError(Pkcs11Error.DeviceRemoved, prov.login(.user, "1234"));
    try std.testing.expectError(Pkcs11Error.DeviceRemoved, prov.getTokenInfo());
}

test "MockToken list keys" {
    const allocator = std.testing.allocator;

    const test_keys = [_]KeyObject{
        makeTestKey(1, .private_key, .rsa, &.{ 0x01, 0x02 }, "RSA Sign Key"),
        makeTestKey(2, .public_key, .rsa, &.{ 0x01, 0x02 }, "RSA Verify Key"),
    };

    var mock = MockToken.init();
    mock.keys = &test_keys;
    const prov = mock.provider();

    const keys = try prov.listKeys(allocator);
    defer allocator.free(keys);

    try std.testing.expectEqual(@as(usize, 2), keys.len);
    try std.testing.expectEqualStrings("RSA Sign Key", keys[0].labelStr());
    try std.testing.expectEqualStrings("RSA Verify Key", keys[1].labelStr());
    try std.testing.expect(keys[0].can_sign);
    try std.testing.expect(!keys[1].can_sign);
}

test "MockToken EC signature size" {
    const allocator = std.testing.allocator;

    var mock = MockToken.init();
    mock.logged_in = true;
    const prov = mock.provider();

    const sig = try prov.sign(allocator, &.{0x01}, .ecdsa, "test data");
    defer allocator.free(sig);

    try std.testing.expectEqual(@as(usize, 64), sig.len); // EC mechanism -> 64 byte sig
}

test "MechanismInfo struct" {
    const info: MechanismInfo = .{
        .mechanism = .sha256_rsa_pkcs,
        .min_key_size = 1024,
        .max_key_size = 4096,
        .can_sign = true,
        .can_verify = true,
        .can_encrypt = false,
        .can_decrypt = false,
        .hardware = true,
    };

    try std.testing.expect(info.can_sign);
    try std.testing.expect(info.hardware);
    try std.testing.expect(!info.can_encrypt);
    try std.testing.expectEqual(@as(u32, 1024), info.min_key_size);
}

test "Pkcs11Slot with token" {
    var desc: [64]u8 = .{' '} ** 64;
    @memcpy(desc[0..11], "Smart Card ");
    var mfr: [32]u8 = .{' '} ** 32;
    @memcpy(mfr[0..8], "Yubico  ");

    var token_label: [32]u8 = .{' '} ** 32;
    @memcpy(token_label[0..8], "YubiKey ");
    var token_mfr: [32]u8 = .{' '} ** 32;
    @memcpy(token_mfr[0..11], "Yubico Inc ");
    var token_model: [16]u8 = .{' '} ** 16;
    @memcpy(token_model[0..5], "YK5  ");
    var token_serial: [16]u8 = .{' '} ** 16;
    @memcpy(token_serial[0..8], "12345678");

    const slot = Pkcs11Slot.init(0, .{
        .description = desc,
        .manufacturer_id = mfr,
        .token_present = true,
        .removable_device = true,
        .hardware_slot = true,
        .flags = 0x07,
        .hw_version = .{ .major = 5, .minor = 0 },
        .fw_version = .{ .major = 5, .minor = 4 },
    }, .{
        .label = token_label,
        .manufacturer_id = token_mfr,
        .model = token_model,
        .serial_number = token_serial,
        .initialized = true,
        .user_pin_initialized = true,
        .login_required = true,
        .protected_auth_path = false,
        .flags = 0x01,
        .max_session_count = 1,
        .session_count = 0,
        .max_pin_len = 127,
        .min_pin_len = 6,
        .total_public_memory = 0,
        .free_public_memory = 0,
        .total_private_memory = 0,
        .free_private_memory = 0,
        .hw_version = .{ .major = 5, .minor = 0 },
        .fw_version = .{ .major = 5, .minor = 4 },
    });

    try std.testing.expect(slot.hasToken());
    try std.testing.expectEqualStrings("YubiKey", slot.tokenLabel().?);
    try std.testing.expectEqualStrings("12345678", slot.tokenSerial().?);
}
