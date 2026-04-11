// SPDX-License-Identifier: MIT
//! YubiKey OpenPGP smart card integration.
//!
//! Provides high-level access to YubiKey hardware tokens through the
//! OpenPGP card application. Builds on the PCSC bridge and OpenPGP
//! card protocol abstractions.
//!
//! Supported operations:
//!   - YubiKey detection via ATR pattern matching
//!   - PIN management (verify, change, reset retry counter)
//!   - Cryptographic operations (sign, decrypt, authenticate)
//!   - Key management (import, on-card generation)
//!   - Touch policy configuration (YubiKey 4/5)
//!   - Version and capability detection
//!
//! Reference: Yubico OpenPGP card applet documentation

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const pcsc_bridge = @import("pcsc_bridge.zig");
const PcscReader = pcsc_bridge.PcscReader;
const MockPcscReader = pcsc_bridge.MockPcscReader;
const PcscError = pcsc_bridge.PcscError;
const Atr = pcsc_bridge.Atr;
const Protocol = pcsc_bridge.Protocol;
const ShareMode = pcsc_bridge.ShareMode;
const Disposition = pcsc_bridge.Disposition;
const CardState = pcsc_bridge.CardState;
const PcscContext = pcsc_bridge.PcscContext;
const ReaderInfo = pcsc_bridge.ReaderInfo;

const openpgp_card = @import("openpgp_card.zig");
const ApduCommand = openpgp_card.ApduCommand;
const ApduResponse = openpgp_card.ApduResponse;
const CardError = openpgp_card.CardError;
const PinType = openpgp_card.PinType;
const KeyRef = openpgp_card.KeyRef;
const DataTag = openpgp_card.DataTag;
const CardInfo = openpgp_card.CardInfo;
const ExtendedCapabilities = openpgp_card.ExtendedCapabilities;
const PwStatus = openpgp_card.PwStatus;

// ---------------------------------------------------------------------------
// YubiKey version and series
// ---------------------------------------------------------------------------

/// YubiKey hardware series.
pub const YubiKeySeries = enum {
    /// YubiKey 4 series (USB-A, USB-C, Nano)
    yk4,
    /// YubiKey 5 series (USB-A, USB-C, NFC, Nano, Bio)
    yk5,
    /// YubiKey NEO (legacy, NFC-enabled)
    neo,
    /// Unknown or unrecognized YubiKey model
    unknown,

    pub fn name(self: YubiKeySeries) []const u8 {
        return switch (self) {
            .yk4 => "YubiKey 4",
            .yk5 => "YubiKey 5",
            .neo => "YubiKey NEO",
            .unknown => "Unknown YubiKey",
        };
    }

    /// Whether the series supports touch policy configuration.
    pub fn supportsTouchPolicy(self: YubiKeySeries) bool {
        return self == .yk4 or self == .yk5;
    }

    /// Whether the series supports on-card key generation with ECC.
    pub fn supportsEcc(self: YubiKeySeries) bool {
        return self == .yk4 or self == .yk5;
    }

    /// Maximum RSA key size supported.
    pub fn maxRsaKeySize(self: YubiKeySeries) u16 {
        return switch (self) {
            .yk5 => 4096,
            .yk4 => 4096,
            .neo => 2048,
            .unknown => 2048,
        };
    }
};

/// Firmware version of a YubiKey.
pub const FirmwareVersion = struct {
    major: u8,
    minor: u8,
    patch: u8,

    /// Format the version as a string (e.g. "5.4.3").
    pub fn format(self: FirmwareVersion, buf: *[12]u8) []const u8 {
        var pos: usize = 0;
        pos += writeDecimal(buf[pos..], self.major);
        buf[pos] = '.';
        pos += 1;
        pos += writeDecimal(buf[pos..], self.minor);
        buf[pos] = '.';
        pos += 1;
        pos += writeDecimal(buf[pos..], self.patch);
        return buf[0..pos];
    }

    /// Determine the YubiKey series from the firmware version.
    pub fn series(self: FirmwareVersion) YubiKeySeries {
        if (self.major >= 5) return .yk5;
        if (self.major == 4) return .yk4;
        if (self.major == 3) return .neo;
        return .unknown;
    }

    /// Whether this firmware version supports a given feature.
    pub fn supports(self: FirmwareVersion, feature: Feature) bool {
        return switch (feature) {
            .touch_policy => self.major >= 4,
            .cached_touch => self.major >= 4 and self.minor >= 2,
            .attestation => self.major >= 5 and self.minor >= 2,
            .ecc_p384 => self.major >= 4,
            .ecc_p256 => self.major >= 4,
            .ed25519 => self.major >= 5 and self.minor >= 2,
            .x25519 => self.major >= 5 and self.minor >= 2,
            .rsa4096 => self.major >= 4,
            .kdf => self.major >= 5 and self.minor >= 2,
            .aes => self.major >= 5,
        };
    }
};

/// Features that may be supported depending on firmware version.
pub const Feature = enum {
    touch_policy,
    cached_touch,
    attestation,
    ecc_p384,
    ecc_p256,
    ed25519,
    x25519,
    rsa4096,
    kdf,
    aes,

    pub fn name(self: Feature) []const u8 {
        return switch (self) {
            .touch_policy => "Touch Policy",
            .cached_touch => "Cached Touch",
            .attestation => "Attestation",
            .ecc_p384 => "ECC P-384",
            .ecc_p256 => "ECC P-256",
            .ed25519 => "Ed25519",
            .x25519 => "X25519",
            .rsa4096 => "RSA 4096",
            .kdf => "KDF-DO",
            .aes => "AES",
        };
    }
};

// ---------------------------------------------------------------------------
// Touch policy
// ---------------------------------------------------------------------------

/// Touch policy for YubiKey key operations.
///
/// Controls when the user must physically touch the YubiKey to authorize
/// a cryptographic operation.
pub const TouchPolicy = enum(u8) {
    /// Touch is never required (default for most operations).
    off = 0x00,
    /// Touch is always required for each operation.
    on = 0x01,
    /// Touch is required, but the state is cached for 15 seconds.
    cached = 0x02,
    /// Touch policy is permanently set and cannot be changed.
    fixed = 0x03,
    /// Touch is cached with a fixed (non-changeable) policy.
    cached_fixed = 0x04,

    pub fn name(self: TouchPolicy) []const u8 {
        return switch (self) {
            .off => "Off",
            .on => "On (always)",
            .cached => "Cached (15s)",
            .fixed => "Fixed (permanent)",
            .cached_fixed => "Cached+Fixed",
        };
    }

    /// Whether this policy requires touch for at least the first operation.
    pub fn requiresTouch(self: TouchPolicy) bool {
        return self != .off;
    }
};

// ---------------------------------------------------------------------------
// ATR patterns
// ---------------------------------------------------------------------------

/// Known YubiKey ATR patterns for identification.
pub const AtrPatterns = struct {
    /// YubiKey 5 NFC ATR.
    pub const yk5_nfc: []const u8 = &.{
        0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE,
        0x15, 0x80, 0x73, 0xC0, 0x21, 0xC0, 0x57, 0x59,
        0x75, 0x62, 0x69, 0x4B, 0x65, 0x79,
    };

    /// YubiKey 5 USB ATR pattern prefix.
    pub const yk5_usb_prefix: []const u8 = &.{
        0x3B, 0xF8, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE,
        0x15, 0x59, 0x75, 0x62, 0x69,
    };

    /// YubiKey 4 ATR pattern prefix.
    pub const yk4_prefix: []const u8 = &.{
        0x3B, 0xF8, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE,
    };

    /// YubiKey NEO ATR pattern prefix.
    pub const neo_prefix: []const u8 = &.{
        0x3B, 0xFC, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE,
    };

    /// Yubico manufacturer ID in OpenPGP AID.
    pub const yubico_manufacturer_id: u16 = 0x0006;

    /// Check if an ATR matches any known YubiKey pattern.
    pub fn matchesYubiKey(atr_bytes: []const u8) bool {
        if (atr_bytes.len < 4) return false;

        // Check for "Yubi" or "YubiKey" in historical bytes.
        if (mem.indexOf(u8, atr_bytes, "Yubi") != null) return true;

        // Check known prefixes.
        if (atr_bytes.len >= yk5_nfc.len and
            mem.eql(u8, atr_bytes[0..yk5_nfc.len], yk5_nfc)) return true;

        if (atr_bytes.len >= yk5_usb_prefix.len and
            mem.eql(u8, atr_bytes[0..yk5_usb_prefix.len], yk5_usb_prefix)) return true;

        if (atr_bytes.len >= yk4_prefix.len and
            mem.eql(u8, atr_bytes[0..yk4_prefix.len], yk4_prefix)) return true;

        if (atr_bytes.len >= neo_prefix.len and
            mem.eql(u8, atr_bytes[0..neo_prefix.len], neo_prefix)) return true;

        return false;
    }

    /// Determine YubiKey series from ATR bytes.
    pub fn seriesFromAtr(atr_bytes: []const u8) YubiKeySeries {
        if (atr_bytes.len >= yk5_usb_prefix.len and
            mem.eql(u8, atr_bytes[0..yk5_usb_prefix.len], yk5_usb_prefix)) return .yk5;

        if (atr_bytes.len >= yk5_nfc.len and
            mem.eql(u8, atr_bytes[0..yk5_nfc.len], yk5_nfc)) return .yk5;

        // Check for "YubiKey" string to detect 5-series
        if (mem.indexOf(u8, atr_bytes, "YubiKey") != null) return .yk5;

        if (atr_bytes.len >= yk4_prefix.len and
            mem.eql(u8, atr_bytes[0..yk4_prefix.len], yk4_prefix)) return .yk4;

        if (atr_bytes.len >= neo_prefix.len and
            mem.eql(u8, atr_bytes[0..neo_prefix.len], neo_prefix)) return .neo;

        return .unknown;
    }
};

// ---------------------------------------------------------------------------
// YubiKey capabilities
// ---------------------------------------------------------------------------

/// Detected capabilities of a connected YubiKey.
pub const YubiKeyCapabilities = struct {
    /// Firmware version.
    firmware: FirmwareVersion,
    /// Hardware series.
    hw_series: YubiKeySeries,
    /// Supported key types for each slot.
    supported_algorithms: SupportedAlgorithms,
    /// Maximum RSA key size.
    max_rsa_bits: u16,
    /// Whether touch policy is available.
    touch_policy_available: bool,
    /// Whether attestation is supported.
    attestation_available: bool,
    /// Whether KDF-DO is supported.
    kdf_available: bool,
    /// Extended capabilities from the card.
    extended_caps: ?ExtendedCapabilities,

    pub const SupportedAlgorithms = struct {
        rsa2048: bool,
        rsa3072: bool,
        rsa4096: bool,
        ecc_p256: bool,
        ecc_p384: bool,
        ed25519: bool,
        x25519: bool,
    };

    /// Create capabilities from firmware version.
    pub fn fromFirmware(fw: FirmwareVersion) YubiKeyCapabilities {
        const hw = fw.series();
        return .{
            .firmware = fw,
            .hw_series = hw,
            .supported_algorithms = .{
                .rsa2048 = true,
                .rsa3072 = fw.major >= 4,
                .rsa4096 = fw.major >= 4,
                .ecc_p256 = fw.major >= 4,
                .ecc_p384 = fw.major >= 4,
                .ed25519 = fw.major >= 5 and fw.minor >= 2,
                .x25519 = fw.major >= 5 and fw.minor >= 2,
            },
            .max_rsa_bits = hw.maxRsaKeySize(),
            .touch_policy_available = hw.supportsTouchPolicy(),
            .attestation_available = fw.supports(.attestation),
            .kdf_available = fw.supports(.kdf),
            .extended_caps = null,
        };
    }
};

// ---------------------------------------------------------------------------
// YubiKey errors
// ---------------------------------------------------------------------------

/// YubiKey-specific errors.
pub const YubiKeyError = error{
    /// The connected card is not a YubiKey.
    NotAYubiKey,
    /// The YubiKey firmware does not support the requested operation.
    UnsupportedByFirmware,
    /// Touch was required but not received within the timeout.
    TouchTimeout,
    /// The requested key slot is empty.
    EmptySlot,
    /// Key import failed.
    KeyImportFailed,
    /// Key generation on card failed.
    KeyGenerationFailed,
    /// The touch policy value is invalid.
    InvalidTouchPolicy,
    /// The operation was cancelled by the user.
    OperationCancelled,
    /// The card communication failed.
    CommunicationFailed,
    /// PIN verification is required first.
    PinRequired,
    /// The PIN has been blocked.
    PinBlocked,
    /// Wrong PIN was entered.
    WrongPin,
    /// An allocator error occurred.
    OutOfMemory,
};

// ---------------------------------------------------------------------------
// YubiKey struct — main interface
// ---------------------------------------------------------------------------

/// Represents a connected YubiKey with OpenPGP application.
///
/// Provides high-level operations for cryptographic key management
/// and use through the YubiKey hardware token.
pub const YubiKey = struct {
    /// The PCSC reader interface.
    reader: PcscReader,
    /// Memory allocator.
    allocator: Allocator,
    /// Detected hardware capabilities.
    capabilities: ?YubiKeyCapabilities,
    /// Card information (AID, serial, fingerprints).
    card_info: ?CardInfo,
    /// Whether the OpenPGP application has been selected.
    app_selected: bool,
    /// Whether the user PIN has been verified for signing.
    user_pin_verified: bool,
    /// Whether the user PIN has been verified for decryption.
    user_dec_verified: bool,
    /// Whether the admin PIN has been verified.
    admin_pin_verified: bool,
    /// Cached touch policies for each slot.
    touch_policies: [3]?TouchPolicy,

    /// Initialize a YubiKey handle from a PCSC reader.
    pub fn init(allocator: Allocator, reader: PcscReader) YubiKey {
        return .{
            .reader = reader,
            .allocator = allocator,
            .capabilities = null,
            .card_info = null,
            .app_selected = false,
            .user_pin_verified = false,
            .user_dec_verified = false,
            .admin_pin_verified = false,
            .touch_policies = .{ null, null, null },
        };
    }

    /// Connect to the YubiKey and detect its capabilities.
    ///
    /// This selects the OpenPGP application, reads the AID and
    /// application data, and determines the hardware version.
    pub fn connect(self: *YubiKey) YubiKeyError!void {
        // Connect at the PCSC level
        self.reader.connect(self.allocator, .shared, .t1) catch
            return YubiKeyError.CommunicationFailed;

        // Verify this is a YubiKey via ATR
        const atr_bytes = self.reader.getAtr(self.allocator) catch
            return YubiKeyError.CommunicationFailed;
        defer self.allocator.free(atr_bytes);

        if (!AtrPatterns.matchesYubiKey(atr_bytes)) {
            return YubiKeyError.NotAYubiKey;
        }

        // Select OpenPGP application
        try self.selectApplication();

        // Read card info and determine capabilities
        try self.readCardInfo();
    }

    /// Disconnect from the YubiKey.
    pub fn disconnect(self: *YubiKey) void {
        self.reader.disconnect(.leave) catch {};
        self.app_selected = false;
        self.user_pin_verified = false;
        self.user_dec_verified = false;
        self.admin_pin_verified = false;
    }

    /// Select the OpenPGP application on the card.
    fn selectApplication(self: *YubiKey) YubiKeyError!void {
        const cmd = openpgp_card.selectOpenPgpApp();
        const resp = self.reader.transceive(self.allocator, cmd) catch
            return YubiKeyError.CommunicationFailed;
        defer resp.deinit(self.allocator);

        if (!resp.isSuccess()) return YubiKeyError.CommunicationFailed;
        self.app_selected = true;
    }

    /// Read card information (AID, serial number, fingerprints).
    fn readCardInfo(self: *YubiKey) YubiKeyError!void {
        // Read Application Related Data (tag 0x6E)
        const cmd = openpgp_card.getData(DataTag.application_related);
        const resp = self.reader.transceive(self.allocator, cmd) catch
            return YubiKeyError.CommunicationFailed;
        defer resp.deinit(self.allocator);

        if (!resp.isSuccess()) return YubiKeyError.CommunicationFailed;

        // Parse the AID from response data
        if (resp.data.len >= 16) {
            var info: CardInfo = .{
                .aid = undefined,
                .version = .{ .major = 0, .minor = 0 },
                .manufacturer = 0,
                .serial = 0,
                .sig_key_fingerprint = null,
                .enc_key_fingerprint = null,
                .auth_key_fingerprint = null,
                .sig_count = 0,
                .pin_retries = .{ .user = 3, .reset = 0, .admin = 3 },
            };

            // Parse AID: the first TLV in 6E response should contain AID
            // For simplicity, try to find the AID within the response data
            if (findTlvValue(resp.data, 0x4F)) |aid_data| {
                if (aid_data.len >= 16) {
                    @memcpy(&info.aid, aid_data[0..16]);
                    info.version = .{
                        .major = aid_data[6],
                        .minor = aid_data[7],
                    };
                    info.manufacturer = (@as(u16, aid_data[8]) << 8) | @as(u16, aid_data[9]);
                    info.serial = mem.readInt(u32, aid_data[10..14], .big);
                } else if (aid_data.len >= 10) {
                    @memset(&info.aid, 0);
                    @memcpy(info.aid[0..aid_data.len], aid_data);
                    info.version = .{
                        .major = aid_data[6],
                        .minor = aid_data[7],
                    };
                    info.manufacturer = (@as(u16, aid_data[8]) << 8) | @as(u16, aid_data[9]);
                }
            }

            // Parse fingerprints from C5 tag
            if (findTlvValue(resp.data, 0xC5)) |fp_data| {
                if (fp_data.len >= 60) {
                    var sig_fp: [20]u8 = undefined;
                    @memcpy(&sig_fp, fp_data[0..20]);
                    if (!isAllZeros(&sig_fp)) info.sig_key_fingerprint = sig_fp;

                    var enc_fp: [20]u8 = undefined;
                    @memcpy(&enc_fp, fp_data[20..40]);
                    if (!isAllZeros(&enc_fp)) info.enc_key_fingerprint = enc_fp;

                    var auth_fp: [20]u8 = undefined;
                    @memcpy(&auth_fp, fp_data[40..60]);
                    if (!isAllZeros(&auth_fp)) info.auth_key_fingerprint = auth_fp;
                }
            }

            // Parse PW status from C4 tag for retry counters
            if (findTlvValue(resp.data, 0xC4)) |pw_data| {
                if (pw_data.len >= 7) {
                    info.pin_retries = .{
                        .user = pw_data[4],
                        .reset = pw_data[5],
                        .admin = pw_data[6],
                    };
                }
            }

            self.card_info = info;

            // Determine capabilities from manufacturer and version
            if (info.manufacturer == AtrPatterns.yubico_manufacturer_id) {
                const fw = FirmwareVersion{
                    .major = info.version.major,
                    .minor = info.version.minor,
                    .patch = 0,
                };
                self.capabilities = YubiKeyCapabilities.fromFirmware(fw);
            }
        }
    }

    // ----- PIN Management -----

    /// Verify the user PIN for signing operations.
    pub fn verifyUserPin(self: *YubiKey, pin: []const u8) YubiKeyError!void {
        if (!self.app_selected) return YubiKeyError.CommunicationFailed;

        const cmd = openpgp_card.verify(.user, pin);
        const resp = self.reader.transceive(self.allocator, cmd) catch
            return YubiKeyError.CommunicationFailed;
        defer resp.deinit(self.allocator);

        if (resp.isSuccess()) {
            self.user_pin_verified = true;
            return;
        }
        if (resp.isWrongPin()) return YubiKeyError.WrongPin;
        if (resp.isPinBlocked()) return YubiKeyError.PinBlocked;
        return YubiKeyError.CommunicationFailed;
    }

    /// Verify the user PIN for decryption operations.
    pub fn verifyDecryptionPin(self: *YubiKey, pin: []const u8) YubiKeyError!void {
        if (!self.app_selected) return YubiKeyError.CommunicationFailed;

        const cmd = openpgp_card.verify(.user_decrypt, pin);
        const resp = self.reader.transceive(self.allocator, cmd) catch
            return YubiKeyError.CommunicationFailed;
        defer resp.deinit(self.allocator);

        if (resp.isSuccess()) {
            self.user_dec_verified = true;
            return;
        }
        if (resp.isWrongPin()) return YubiKeyError.WrongPin;
        if (resp.isPinBlocked()) return YubiKeyError.PinBlocked;
        return YubiKeyError.CommunicationFailed;
    }

    /// Verify the admin PIN.
    pub fn verifyAdminPin(self: *YubiKey, pin: []const u8) YubiKeyError!void {
        if (!self.app_selected) return YubiKeyError.CommunicationFailed;

        const cmd = openpgp_card.verify(.admin, pin);
        const resp = self.reader.transceive(self.allocator, cmd) catch
            return YubiKeyError.CommunicationFailed;
        defer resp.deinit(self.allocator);

        if (resp.isSuccess()) {
            self.admin_pin_verified = true;
            return;
        }
        if (resp.isWrongPin()) return YubiKeyError.WrongPin;
        if (resp.isPinBlocked()) return YubiKeyError.PinBlocked;
        return YubiKeyError.CommunicationFailed;
    }

    /// Change the user PIN.
    pub fn changeUserPin(self: *YubiKey, old_pin: []const u8, new_pin: []const u8) YubiKeyError!void {
        if (!self.app_selected) return YubiKeyError.CommunicationFailed;

        if (new_pin.len < PinType.user.minLength() or new_pin.len > PinType.user.maxLength()) {
            return YubiKeyError.WrongPin;
        }

        const data = openpgp_card.buildChangePinData(self.allocator, old_pin, new_pin) catch
            return YubiKeyError.OutOfMemory;
        defer self.allocator.free(data);

        const cmd = ApduCommand{
            .cla = 0x00,
            .ins = 0x24,
            .p1 = 0x00,
            .p2 = @intFromEnum(PinType.user),
            .data = data,
            .le = null,
        };

        const resp = self.reader.transceive(self.allocator, cmd) catch
            return YubiKeyError.CommunicationFailed;
        defer resp.deinit(self.allocator);

        if (resp.isSuccess()) return;
        if (resp.isWrongPin()) return YubiKeyError.WrongPin;
        return YubiKeyError.CommunicationFailed;
    }

    /// Change the admin PIN.
    pub fn changeAdminPin(self: *YubiKey, old_pin: []const u8, new_pin: []const u8) YubiKeyError!void {
        if (!self.app_selected) return YubiKeyError.CommunicationFailed;

        if (new_pin.len < PinType.admin.minLength() or new_pin.len > PinType.admin.maxLength()) {
            return YubiKeyError.WrongPin;
        }

        const data = openpgp_card.buildChangePinData(self.allocator, old_pin, new_pin) catch
            return YubiKeyError.OutOfMemory;
        defer self.allocator.free(data);

        const cmd = ApduCommand{
            .cla = 0x00,
            .ins = 0x24,
            .p1 = 0x00,
            .p2 = @intFromEnum(PinType.admin),
            .data = data,
            .le = null,
        };

        const resp = self.reader.transceive(self.allocator, cmd) catch
            return YubiKeyError.CommunicationFailed;
        defer resp.deinit(self.allocator);

        if (resp.isSuccess()) return;
        if (resp.isWrongPin()) return YubiKeyError.WrongPin;
        return YubiKeyError.CommunicationFailed;
    }

    /// Reset the user PIN retry counter (requires admin PIN).
    pub fn resetPinRetryCounter(self: *YubiKey, new_pin: []const u8) YubiKeyError!void {
        if (!self.app_selected) return YubiKeyError.CommunicationFailed;
        if (!self.admin_pin_verified) return YubiKeyError.PinRequired;

        const cmd = openpgp_card.resetRetryCounter(new_pin);
        const resp = self.reader.transceive(self.allocator, cmd) catch
            return YubiKeyError.CommunicationFailed;
        defer resp.deinit(self.allocator);

        if (resp.isSuccess()) return;
        return YubiKeyError.CommunicationFailed;
    }

    /// Get the number of remaining PIN retries.
    pub fn getPinRetries(self: *YubiKey) YubiKeyError!struct { user: u8, admin: u8 } {
        if (!self.app_selected) return YubiKeyError.CommunicationFailed;

        // Send VERIFY without data to check status
        const cmd = openpgp_card.verifyStatus(.user);
        const resp = self.reader.transceive(self.allocator, cmd) catch
            return YubiKeyError.CommunicationFailed;
        defer resp.deinit(self.allocator);

        const user_retries = resp.pinRetriesLeft() orelse 3;

        // Check admin PIN status
        const admin_cmd = openpgp_card.verifyStatus(.admin);
        const admin_resp = self.reader.transceive(self.allocator, admin_cmd) catch
            return YubiKeyError.CommunicationFailed;
        defer admin_resp.deinit(self.allocator);

        const admin_retries = admin_resp.pinRetriesLeft() orelse 3;

        return .{ .user = user_retries, .admin = admin_retries };
    }

    // ----- Cryptographic Operations -----

    /// Sign data using the card's signature key.
    ///
    /// The hash digest must be pre-computed by the caller. The user PIN
    /// for signing (PW1-81) must be verified first.
    pub fn sign(self: *YubiKey, hash_digest: []const u8) YubiKeyError![]u8 {
        if (!self.app_selected) return YubiKeyError.CommunicationFailed;
        if (!self.user_pin_verified) return YubiKeyError.PinRequired;

        // Check that signature key exists
        if (self.card_info) |info| {
            if (!info.hasSignatureKey()) return YubiKeyError.EmptySlot;
        }

        const cmd = openpgp_card.computeDigitalSignature(hash_digest);
        const resp = self.reader.transceive(self.allocator, cmd) catch
            return YubiKeyError.CommunicationFailed;

        if (resp.isSuccess()) {
            // Return owned signature data; caller must free
            return resp.data;
        }

        resp.deinit(self.allocator);

        if (resp.needsAuth()) return YubiKeyError.PinRequired;
        return YubiKeyError.CommunicationFailed;
    }

    /// Decrypt data using the card's decryption key.
    ///
    /// The ciphertext is the encrypted session key (PKESK payload).
    /// The user PIN for decryption (PW1-82) must be verified first.
    pub fn decrypt(self: *YubiKey, ciphertext: []const u8) YubiKeyError![]u8 {
        if (!self.app_selected) return YubiKeyError.CommunicationFailed;
        if (!self.user_dec_verified) return YubiKeyError.PinRequired;

        // Check that decryption key exists
        if (self.card_info) |info| {
            if (!info.hasEncryptionKey()) return YubiKeyError.EmptySlot;
        }

        const cmd = openpgp_card.decipher(ciphertext);
        const resp = self.reader.transceive(self.allocator, cmd) catch
            return YubiKeyError.CommunicationFailed;

        if (resp.isSuccess()) {
            return resp.data;
        }

        resp.deinit(self.allocator);

        if (resp.needsAuth()) return YubiKeyError.PinRequired;
        return YubiKeyError.CommunicationFailed;
    }

    /// Authenticate using the card's authentication key.
    ///
    /// Used for client authentication (e.g., SSH).
    pub fn authenticate(self: *YubiKey, challenge: []const u8) YubiKeyError![]u8 {
        if (!self.app_selected) return YubiKeyError.CommunicationFailed;
        if (!self.user_pin_verified and !self.user_dec_verified)
            return YubiKeyError.PinRequired;

        if (self.card_info) |info| {
            if (!info.hasAuthenticationKey()) return YubiKeyError.EmptySlot;
        }

        const cmd = openpgp_card.internalAuthenticate(challenge);
        const resp = self.reader.transceive(self.allocator, cmd) catch
            return YubiKeyError.CommunicationFailed;

        if (resp.isSuccess()) {
            return resp.data;
        }

        resp.deinit(self.allocator);
        return YubiKeyError.CommunicationFailed;
    }

    // ----- Key Management -----

    /// Generate a key pair on the card.
    ///
    /// Requires admin PIN verification. Returns the public key data
    /// from the card (which must be incorporated into an OpenPGP certificate).
    pub fn generateKey(self: *YubiKey, key_ref: KeyRef) YubiKeyError![]u8 {
        if (!self.app_selected) return YubiKeyError.CommunicationFailed;
        if (!self.admin_pin_verified) return YubiKeyError.PinRequired;

        const cmd = openpgp_card.generateAsymmetricKey(key_ref);
        const resp = self.reader.transceive(self.allocator, cmd) catch
            return YubiKeyError.CommunicationFailed;

        if (resp.isSuccess()) {
            return resp.data;
        }

        resp.deinit(self.allocator);
        return YubiKeyError.KeyGenerationFailed;
    }

    /// Read the public key from a key slot (without generating).
    pub fn readPublicKey(self: *YubiKey, key_ref: KeyRef) YubiKeyError![]u8 {
        if (!self.app_selected) return YubiKeyError.CommunicationFailed;

        const cmd = openpgp_card.readPublicKeyFromCard(key_ref);
        const resp = self.reader.transceive(self.allocator, cmd) catch
            return YubiKeyError.CommunicationFailed;

        if (resp.isSuccess()) {
            return resp.data;
        }

        resp.deinit(self.allocator);
        return YubiKeyError.EmptySlot;
    }

    /// Import a key to the card.
    ///
    /// The key_data must be in the format expected by the OpenPGP card
    /// PUT KEY command (constructed TLV with key material).
    /// Requires admin PIN verification.
    pub fn importKey(self: *YubiKey, key_ref: KeyRef, key_data: []const u8) YubiKeyError!void {
        if (!self.app_selected) return YubiKeyError.CommunicationFailed;
        if (!self.admin_pin_verified) return YubiKeyError.PinRequired;

        // Build extended header list for PUT KEY
        // CRT tag (B6/B8/A4) + key data
        var header_buf: [4]u8 = undefined;
        header_buf[0] = key_ref.crtTag();
        header_buf[1] = 0x00; // empty CRT

        // Construct the full command data: CRT + 7F48 (public key) + 5F48 (private key)
        const cmd = ApduCommand{
            .cla = 0x00,
            .ins = 0xDB, // PUT DATA (odd INS for key import)
            .p1 = 0x3F,
            .p2 = 0xFF,
            .data = key_data,
            .le = null,
        };

        const resp = self.reader.transceive(self.allocator, cmd) catch
            return YubiKeyError.CommunicationFailed;
        defer resp.deinit(self.allocator);

        if (resp.isSuccess()) return;
        return YubiKeyError.KeyImportFailed;
    }

    /// Set the key algorithm attributes for a slot.
    ///
    /// Must be set before importing a key if changing from the default RSA 2048.
    /// Requires admin PIN verification.
    pub fn setKeyAttributes(self: *YubiKey, key_ref: KeyRef, attrs: []const u8) YubiKeyError!void {
        if (!self.app_selected) return YubiKeyError.CommunicationFailed;
        if (!self.admin_pin_verified) return YubiKeyError.PinRequired;

        const tag = key_ref.attributesTag();
        const cmd = openpgp_card.putData(tag, attrs);
        const resp = self.reader.transceive(self.allocator, cmd) catch
            return YubiKeyError.CommunicationFailed;
        defer resp.deinit(self.allocator);

        if (resp.isSuccess()) return;
        return YubiKeyError.UnsupportedByFirmware;
    }

    // ----- Touch Policy -----

    /// Get the touch policy for a key slot.
    pub fn getTouchPolicy(self: *YubiKey, key_ref: KeyRef) YubiKeyError!TouchPolicy {
        if (!self.app_selected) return YubiKeyError.CommunicationFailed;

        const tag: u16 = switch (key_ref) {
            .signature => DataTag.uif_sig,
            .decryption => DataTag.uif_dec,
            .authentication => DataTag.uif_aut,
        };

        const cmd = openpgp_card.getData(tag);
        const resp = self.reader.transceive(self.allocator, cmd) catch
            return YubiKeyError.CommunicationFailed;
        defer resp.deinit(self.allocator);

        if (resp.isSuccess() and resp.data.len >= 1) {
            const policy: TouchPolicy = switch (resp.data[0]) {
                0x00 => .off,
                0x01 => .on,
                0x02 => .cached,
                0x03 => .fixed,
                0x04 => .cached_fixed,
                else => return YubiKeyError.InvalidTouchPolicy,
            };

            const slot_idx: usize = switch (key_ref) {
                .signature => 0,
                .decryption => 1,
                .authentication => 2,
            };
            self.touch_policies[slot_idx] = policy;
            return policy;
        }

        return YubiKeyError.UnsupportedByFirmware;
    }

    /// Set the touch policy for a key slot.
    ///
    /// Requires admin PIN verification. On YubiKey 4+.
    pub fn setTouchPolicy(self: *YubiKey, key_ref: KeyRef, policy: TouchPolicy) YubiKeyError!void {
        if (!self.app_selected) return YubiKeyError.CommunicationFailed;
        if (!self.admin_pin_verified) return YubiKeyError.PinRequired;

        if (self.capabilities) |caps| {
            if (!caps.touch_policy_available) return YubiKeyError.UnsupportedByFirmware;
        }

        const tag: u16 = switch (key_ref) {
            .signature => DataTag.uif_sig,
            .decryption => DataTag.uif_dec,
            .authentication => DataTag.uif_aut,
        };

        // UIF data: policy byte + 0x20 (touch button)
        const uif_data: [2]u8 = .{ @intFromEnum(policy), 0x20 };
        const cmd = openpgp_card.putData(tag, &uif_data);
        const resp = self.reader.transceive(self.allocator, cmd) catch
            return YubiKeyError.CommunicationFailed;
        defer resp.deinit(self.allocator);

        if (resp.isSuccess()) {
            const slot_idx: usize = switch (key_ref) {
                .signature => 0,
                .decryption => 1,
                .authentication => 2,
            };
            self.touch_policies[slot_idx] = policy;
            return;
        }

        return YubiKeyError.CommunicationFailed;
    }

    // ----- Information Queries -----

    /// Get the firmware version.
    pub fn getFirmwareVersion(self: *const YubiKey) ?FirmwareVersion {
        if (self.capabilities) |caps| return caps.firmware;
        return null;
    }

    /// Get the serial number.
    pub fn getSerialNumber(self: *const YubiKey) ?u32 {
        if (self.card_info) |info| return info.serial;
        return null;
    }

    /// Get the YubiKey series.
    pub fn getSeries(self: *const YubiKey) YubiKeySeries {
        if (self.capabilities) |caps| return caps.hw_series;
        return .unknown;
    }

    /// Check if a specific feature is supported.
    pub fn supportsFeature(self: *const YubiKey, feature: Feature) bool {
        if (self.capabilities) |caps| {
            return caps.firmware.supports(feature);
        }
        return false;
    }

    /// Get the card info (AID, serial, fingerprints etc).
    pub fn getCardInfo(self: *const YubiKey) ?CardInfo {
        return self.card_info;
    }

    /// Set cardholder name on the card (requires admin PIN).
    pub fn setCardholderName(self: *YubiKey, name_data: []const u8) YubiKeyError!void {
        if (!self.admin_pin_verified) return YubiKeyError.PinRequired;

        const cmd = openpgp_card.putData(DataTag.cardholder_name, name_data);
        const resp = self.reader.transceive(self.allocator, cmd) catch
            return YubiKeyError.CommunicationFailed;
        defer resp.deinit(self.allocator);

        if (!resp.isSuccess()) return YubiKeyError.CommunicationFailed;
    }

    /// Set the public key URL on the card (requires admin PIN).
    pub fn setPublicKeyUrl(self: *YubiKey, url: []const u8) YubiKeyError!void {
        if (!self.admin_pin_verified) return YubiKeyError.PinRequired;

        const cmd = openpgp_card.putData(DataTag.public_key_url, url);
        const resp = self.reader.transceive(self.allocator, cmd) catch
            return YubiKeyError.CommunicationFailed;
        defer resp.deinit(self.allocator);

        if (!resp.isSuccess()) return YubiKeyError.CommunicationFailed;
    }

    /// Factory reset the OpenPGP application on the YubiKey.
    ///
    /// WARNING: This erases all keys and resets all PINs to defaults.
    /// Both user and admin PINs must be blocked first (3 wrong attempts
    /// for user PIN, 3 for admin PIN), then TERMINATE DF + ACTIVATE FILE.
    pub fn factoryReset(self: *YubiKey) YubiKeyError!void {
        if (!self.app_selected) return YubiKeyError.CommunicationFailed;

        // Send TERMINATE DF
        const term_cmd = openpgp_card.terminateDf();
        const term_resp = self.reader.transceive(self.allocator, term_cmd) catch
            return YubiKeyError.CommunicationFailed;
        defer term_resp.deinit(self.allocator);

        // Send ACTIVATE FILE to reinitialize
        const act_cmd = openpgp_card.activateFile();
        const act_resp = self.reader.transceive(self.allocator, act_cmd) catch
            return YubiKeyError.CommunicationFailed;
        defer act_resp.deinit(self.allocator);

        // Reset internal state
        self.user_pin_verified = false;
        self.user_dec_verified = false;
        self.admin_pin_verified = false;
        self.card_info = null;
        self.capabilities = null;
        self.touch_policies = .{ null, null, null };

        // Re-select application and read info
        try self.selectApplication();
        try self.readCardInfo();
    }
};

// ---------------------------------------------------------------------------
// YubiKeyManager — multi-device handling
// ---------------------------------------------------------------------------

/// Manages multiple YubiKey devices connected to the system.
///
/// Enumerates PCSC readers, identifies which ones contain YubiKeys,
/// and provides access to individual devices.
pub const YubiKeyManager = struct {
    /// Memory allocator.
    allocator: Allocator,
    /// PCSC context for reader enumeration.
    context: PcscContext,
    /// Discovered YubiKey devices (indices into reader list).
    yubikey_indices: std.ArrayList(usize),

    /// Initialize the YubiKey manager.
    pub fn init(allocator: Allocator) YubiKeyManager {
        return .{
            .allocator = allocator,
            .context = PcscContext.init(),
            .yubikey_indices = .empty,
        };
    }

    /// Release all resources.
    pub fn deinit(self: *YubiKeyManager) void {
        self.yubikey_indices.deinit(self.allocator);
        self.context.release(self.allocator);
    }

    /// Establish connection to the PCSC subsystem.
    pub fn establish(self: *YubiKeyManager) YubiKeyError!void {
        self.context.establish() catch return YubiKeyError.CommunicationFailed;
    }

    /// Scan for connected YubiKey devices.
    ///
    /// After scanning, use `yubikeyCount()` and `getYubiKeyReader()` to
    /// access individual devices.
    pub fn scan(self: *YubiKeyManager) YubiKeyError!usize {
        // Clear previous scan results
        self.yubikey_indices.clearRetainingCapacity();

        // Check each reader for a YubiKey
        for (self.context.readers.items, 0..) |reader_info, idx| {
            if (!reader_info.card_present) continue;

            // Check ATR for YubiKey pattern
            if (reader_info.atr) |atr_bytes| {
                if (AtrPatterns.matchesYubiKey(atr_bytes)) {
                    self.yubikey_indices.append(self.allocator, idx) catch
                        return YubiKeyError.OutOfMemory;
                }
            }
        }

        return self.yubikey_indices.items.len;
    }

    /// Get the number of discovered YubiKeys.
    pub fn yubikeyCount(self: *const YubiKeyManager) usize {
        return self.yubikey_indices.items.len;
    }

    /// Get the reader info for a discovered YubiKey by index.
    pub fn getYubiKeyReaderInfo(self: *const YubiKeyManager, index: usize) ?ReaderInfo {
        if (index >= self.yubikey_indices.items.len) return null;
        const reader_idx = self.yubikey_indices.items[index];
        if (reader_idx >= self.context.readers.items.len) return null;
        return self.context.readers.items[reader_idx];
    }

    /// Get a list of serial numbers for all discovered YubiKeys.
    /// Returns a list of reader names that contain YubiKeys.
    pub fn listYubiKeyNames(self: *const YubiKeyManager, allocator: Allocator) YubiKeyError![][]const u8 {
        var names: std.ArrayList([]const u8) = .empty;
        errdefer names.deinit(allocator);

        for (self.yubikey_indices.items) |reader_idx| {
            if (reader_idx < self.context.readers.items.len) {
                const name = allocator.dupe(u8, self.context.readers.items[reader_idx].name) catch
                    return YubiKeyError.OutOfMemory;
                names.append(allocator, name) catch return YubiKeyError.OutOfMemory;
            }
        }

        return names.toOwnedSlice(allocator) catch return YubiKeyError.OutOfMemory;
    }
};

// ---------------------------------------------------------------------------
// Mock YubiKey reader (for testing)
// ---------------------------------------------------------------------------

/// Create a MockPcscReader pre-configured with YubiKey responses.
///
/// This sets up the ATR and basic application data responses to
/// simulate a YubiKey 5 device for testing purposes.
pub fn createMockYubiKey(allocator: Allocator) !MockPcscReader {
    // YubiKey 5 NFC-like ATR (contains "YubiKey" in historical bytes)
    const mock_atr: []const u8 = &.{
        0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE,
        0x15, 0x80, 0x73, 0xC0, 0x21, 0xC0, 0x57,
        // "YubiKey" in ASCII
        0x59, 0x75, 0x62, 0x69, 0x4B, 0x65, 0x79,
        0x40, // TCK
    };

    var mock = MockPcscReader.init("Yubico YubiKey OTP+FIDO+CCID", mock_atr);

    // SELECT OpenPGP application response (success + AID)
    // SELECT command prefix: 00 A4 04 00
    const select_response = comptime blk: {
        // Simulated response: AID + SW 90 00
        var resp: [18]u8 = undefined;
        // Minimal OpenPGP AID: D2 76 00 01 24 01 03 04 00 06 SERIAL 00 00
        resp[0] = 0xD2; // RID
        resp[1] = 0x76;
        resp[2] = 0x00;
        resp[3] = 0x01;
        resp[4] = 0x24;
        resp[5] = 0x01;
        resp[6] = 0x05; // Version 5.4
        resp[7] = 0x04;
        resp[8] = 0x00; // Manufacturer: Yubico (0x0006)
        resp[9] = 0x06;
        resp[10] = 0x12; // Serial number
        resp[11] = 0x34;
        resp[12] = 0x56;
        resp[13] = 0x78;
        resp[14] = 0x00;
        resp[15] = 0x00;
        resp[16] = 0x90; // SW1
        resp[17] = 0x00; // SW2
        break :blk resp;
    };
    try mock.addResponse(allocator, &.{ 0x00, 0xA4, 0x04, 0x00 }, &select_response);

    // GET DATA (Application Related Data, tag 6E) response
    // Command prefix: 00 CA 00 6E
    const app_data_response = comptime blk: {
        // Simplified response with AID (4F), C5 (fingerprints), C4 (PW status)
        var resp: [82]u8 = undefined;
        var i: usize = 0;

        // Tag 6E (Application Related Data) — wrapping
        resp[i] = 0x6E;
        i += 1;
        resp[i] = 78; // Length of contents
        i += 1;

        // AID (tag 4F)
        resp[i] = 0x4F;
        i += 1;
        resp[i] = 16; // length
        i += 1;
        resp[i] = 0xD2;
        i += 1;
        resp[i] = 0x76;
        i += 1;
        resp[i] = 0x00;
        i += 1;
        resp[i] = 0x01;
        i += 1;
        resp[i] = 0x24;
        i += 1;
        resp[i] = 0x01;
        i += 1;
        resp[i] = 0x05;
        i += 1; // Version 5.4
        resp[i] = 0x04;
        i += 1;
        resp[i] = 0x00;
        i += 1; // Manufacturer Yubico
        resp[i] = 0x06;
        i += 1;
        resp[i] = 0x12;
        i += 1; // Serial
        resp[i] = 0x34;
        i += 1;
        resp[i] = 0x56;
        i += 1;
        resp[i] = 0x78;
        i += 1;
        resp[i] = 0x00;
        i += 1;
        resp[i] = 0x00;
        i += 1;

        // Fingerprints (tag C5) - 60 bytes, all zeros (no keys loaded)
        resp[i] = 0xC5;
        i += 1;
        resp[i] = 60; // length
        i += 1;
        var j: usize = 0;
        while (j < 60) : (j += 1) {
            resp[i] = 0x00;
            i += 1;
        }

        // SW1 SW2
        resp[i] = 0x90;
        i += 1;
        resp[i] = 0x00;
        i += 1;

        break :blk resp;
    };
    try mock.addResponse(allocator, &.{ 0x00, 0xCA, 0x00, 0x6E }, &app_data_response);

    // VERIFY User PIN (command prefix: 00 20 00 81) - accept default PIN "123456"
    try mock.addResponse(allocator, &.{ 0x00, 0x20, 0x00, 0x81 }, &.{ 0x90, 0x00 });

    // VERIFY User PIN for decrypt (00 20 00 82) - accept
    try mock.addResponse(allocator, &.{ 0x00, 0x20, 0x00, 0x82 }, &.{ 0x90, 0x00 });

    // VERIFY Admin PIN (00 20 00 83) - accept
    try mock.addResponse(allocator, &.{ 0x00, 0x20, 0x00, 0x83 }, &.{ 0x90, 0x00 });

    // COMPUTE DIGITAL SIGNATURE (00 2A 9E 9A) - return mock signature
    const mock_sig: [34]u8 = .{
        // 32 bytes of mock signature data
        0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        // SW
        0x90, 0x00,
    };
    try mock.addResponse(allocator, &.{ 0x00, 0x2A, 0x9E, 0x9A }, &mock_sig);

    // DECIPHER (00 2A 80 86) - return mock decrypted data
    const mock_dec: [18]u8 = .{
        0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x90, 0x00,
    };
    try mock.addResponse(allocator, &.{ 0x00, 0x2A, 0x80, 0x86 }, &mock_dec);

    // INTERNAL AUTHENTICATE (00 88 00 00) - return mock auth response
    const mock_auth: [34]u8 = .{
        0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x90, 0x00,
    };
    try mock.addResponse(allocator, &.{ 0x00, 0x88, 0x00, 0x00 }, &mock_auth);

    // GENERATE KEY (00 47 80 00) - return mock public key
    const mock_genkey: [36]u8 = .{
        0x7F, 0x49, 0x20, // public key template
        0x86, 0x20, // EC point
        0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x90, 0x00,
    };
    try mock.addResponse(allocator, &.{ 0x00, 0x47, 0x80, 0x00 }, &mock_genkey);

    // GET DATA for UIF (touch policy, tag D6) - return touch off
    try mock.addResponse(allocator, &.{ 0x00, 0xCA, 0x00, 0xD6 }, &.{ 0x00, 0x20, 0x90, 0x00 });

    // PUT DATA success (for various operations)
    try mock.addResponse(allocator, &.{ 0x00, 0xDA }, &.{ 0x90, 0x00 });

    // TERMINATE DF
    try mock.addResponse(allocator, &.{ 0x00, 0xE6 }, &.{ 0x90, 0x00 });

    // ACTIVATE FILE
    try mock.addResponse(allocator, &.{ 0x00, 0x44 }, &.{ 0x90, 0x00 });

    return mock;
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Find a TLV value within a data buffer by tag.
/// Performs a simple linear scan; handles 1-byte tags and 1-byte lengths.
fn findTlvValue(data: []const u8, target_tag: u16) ?[]const u8 {
    var offset: usize = 0;

    while (offset < data.len) {
        // Read tag
        if (offset >= data.len) break;
        var tag: u16 = data[offset];
        offset += 1;

        // Two-byte tag
        if ((tag & 0x1F) == 0x1F) {
            if (offset >= data.len) break;
            tag = (tag << 8) | data[offset];
            offset += 1;
        }

        // Read length
        if (offset >= data.len) break;
        var length: usize = data[offset];
        offset += 1;

        if (length == 0x81) {
            if (offset >= data.len) break;
            length = data[offset];
            offset += 1;
        } else if (length == 0x82) {
            if (offset + 1 >= data.len) break;
            length = (@as(usize, data[offset]) << 8) | data[offset + 1];
            offset += 2;
        } else if (length >= 0x80) {
            break;
        }

        // Check if this is our tag
        if (tag == target_tag) {
            if (offset + length <= data.len) {
                return data[offset .. offset + length];
            }
            return null;
        }

        // Skip value — but also recurse into constructed tags (high bit set)
        if (tag & 0x20 != 0 or (tag >> 8) != 0) {
            // For constructed tags, search inside
            if (offset + length <= data.len) {
                if (findTlvValue(data[offset .. offset + length], target_tag)) |found| {
                    return found;
                }
            }
        }

        offset += length;
    }

    return null;
}

/// Check if all bytes in a slice are zero.
fn isAllZeros(data: []const u8) bool {
    for (data) |b| {
        if (b != 0) return false;
    }
    return true;
}

/// Write a decimal number to a buffer, returning the number of bytes written.
fn writeDecimal(buf: []u8, value: u8) usize {
    if (value >= 100) {
        buf[0] = '0' + (value / 100);
        buf[1] = '0' + ((value / 10) % 10);
        buf[2] = '0' + (value % 10);
        return 3;
    } else if (value >= 10) {
        buf[0] = '0' + (value / 10);
        buf[1] = '0' + (value % 10);
        return 2;
    } else {
        buf[0] = '0' + value;
        return 1;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ATR pattern matching" {
    const testing = std.testing;

    // YubiKey 5 NFC ATR should match
    try testing.expect(AtrPatterns.matchesYubiKey(AtrPatterns.yk5_nfc));

    // ATR containing "Yubi" should match
    const custom_atr: []const u8 = &.{ 0x3B, 0xF8, 0x13, 0x00, 0x59, 0x75, 0x62, 0x69 }; // "Yubi"
    try testing.expect(AtrPatterns.matchesYubiKey(custom_atr));

    // Random ATR should not match
    const random_atr: []const u8 = &.{ 0x3B, 0x00, 0x00, 0x00, 0x00 };
    try testing.expect(!AtrPatterns.matchesYubiKey(random_atr));

    // Too-short ATR should not match
    try testing.expect(!AtrPatterns.matchesYubiKey(&.{ 0x3B, 0x00 }));
}

test "YubiKey series detection from ATR" {
    const testing = std.testing;

    try testing.expectEqual(YubiKeySeries.yk5, AtrPatterns.seriesFromAtr(AtrPatterns.yk5_nfc));

    const random_atr: []const u8 = &.{ 0x3B, 0x00, 0x00, 0x00 };
    try testing.expectEqual(YubiKeySeries.unknown, AtrPatterns.seriesFromAtr(random_atr));
}

test "FirmwareVersion series detection" {
    const testing = std.testing;

    const v54 = FirmwareVersion{ .major = 5, .minor = 4, .patch = 3 };
    try testing.expectEqual(YubiKeySeries.yk5, v54.series());
    try testing.expect(v54.supports(.touch_policy));
    try testing.expect(v54.supports(.ed25519));
    try testing.expect(v54.supports(.attestation));

    const v43 = FirmwareVersion{ .major = 4, .minor = 3, .patch = 0 };
    try testing.expectEqual(YubiKeySeries.yk4, v43.series());
    try testing.expect(v43.supports(.touch_policy));
    try testing.expect(!v43.supports(.ed25519));
    try testing.expect(!v43.supports(.attestation));

    const v3 = FirmwareVersion{ .major = 3, .minor = 4, .patch = 0 };
    try testing.expectEqual(YubiKeySeries.neo, v3.series());
    try testing.expect(!v3.supports(.touch_policy));
}

test "FirmwareVersion format" {
    var buf: [12]u8 = undefined;
    const v = FirmwareVersion{ .major = 5, .minor = 4, .patch = 3 };
    const str = v.format(&buf);
    try std.testing.expectEqualStrings("5.4.3", str);
}

test "TouchPolicy properties" {
    const testing = std.testing;

    try testing.expect(!TouchPolicy.off.requiresTouch());
    try testing.expect(TouchPolicy.on.requiresTouch());
    try testing.expect(TouchPolicy.cached.requiresTouch());
    try testing.expect(TouchPolicy.fixed.requiresTouch());
}

test "YubiKeyCapabilities from firmware" {
    const caps = YubiKeyCapabilities.fromFirmware(.{ .major = 5, .minor = 4, .patch = 0 });

    try std.testing.expect(caps.supported_algorithms.rsa4096);
    try std.testing.expect(caps.supported_algorithms.ed25519);
    try std.testing.expect(caps.supported_algorithms.ecc_p256);
    try std.testing.expect(caps.touch_policy_available);
    try std.testing.expect(caps.attestation_available);
    try std.testing.expectEqual(@as(u16, 4096), caps.max_rsa_bits);
}

test "findTlvValue" {
    // Simple TLV: tag 4F, length 4, data
    const data: []const u8 = &.{
        0x4F, 0x04, 0x01, 0x02, 0x03, 0x04,
        0xC5, 0x02, 0xAB, 0xCD,
    };

    const found_4f = findTlvValue(data, 0x4F);
    try std.testing.expect(found_4f != null);
    try std.testing.expectEqual(@as(usize, 4), found_4f.?.len);
    try std.testing.expectEqual(@as(u8, 0x01), found_4f.?[0]);

    const found_c5 = findTlvValue(data, 0xC5);
    try std.testing.expect(found_c5 != null);
    try std.testing.expectEqual(@as(usize, 2), found_c5.?.len);

    // Tag not found
    const found_c6 = findTlvValue(data, 0xC6);
    try std.testing.expect(found_c6 == null);
}

test "isAllZeros" {
    try std.testing.expect(isAllZeros(&.{ 0, 0, 0, 0 }));
    try std.testing.expect(!isAllZeros(&.{ 0, 0, 1, 0 }));
    try std.testing.expect(isAllZeros(&.{}));
}

test "writeDecimal" {
    var buf: [4]u8 = undefined;

    try std.testing.expectEqual(@as(usize, 1), writeDecimal(&buf, 5));
    try std.testing.expectEqual(@as(u8, '5'), buf[0]);

    try std.testing.expectEqual(@as(usize, 2), writeDecimal(&buf, 42));
    try std.testing.expectEqualSlices(u8, "42", buf[0..2]);

    try std.testing.expectEqual(@as(usize, 3), writeDecimal(&buf, 123));
    try std.testing.expectEqualSlices(u8, "123", buf[0..3]);
}
