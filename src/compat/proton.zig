// SPDX-License-Identifier: MIT
//! Proton Mail / GopenPGP compatibility layer.
//!
//! Proton Mail uses OpenPGP internally but has specific conventions for
//! key management, message format, and session key handling. The GopenPGP
//! library (Go-based) implements these conventions.
//!
//! This module provides:
//!   - Proton Mail armored key format handling (with Proton-specific comments)
//!   - Message format compatibility (MIME wrapping, inline PGP)
//!   - Session key handling (AES-256 preference)
//!   - Address key encryption model
//!   - Key rotation with primary + address keys
//!   - Contact card encryption (vCard with contact keys)
//!   - GopenPGP KeyRing / SessionKey / PlainMessage / PGPMessage types
//!
//! Reference: GopenPGP library (github.com/ProtonMail/gopenpgp)
//!            Proton Mail key management documentation

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const enums = @import("../types/enums.zig");
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;

// =========================================================================
// Error types
// =========================================================================

/// Errors specific to Proton Mail compatibility.
pub const ProtonError = error{
    /// The key format is not recognized as Proton-compatible.
    InvalidKeyFormat,
    /// The armored data is malformed.
    InvalidArmor,
    /// The message format is not recognized.
    InvalidMessageFormat,
    /// A required header is missing from the message.
    MissingHeader,
    /// Session key handling error.
    SessionKeyError,
    /// The key ring is empty or invalid.
    InvalidKeyRing,
    /// Address key not found for the given email.
    AddressKeyNotFound,
    /// Contact card format error.
    ContactCardError,
    /// JSON parsing or generation error.
    JsonError,
    /// Out of memory.
    OutOfMemory,
};

// =========================================================================
// Proton Armor format
// =========================================================================

/// Proton Mail armor header comments.
pub const ProtonArmorHeaders = struct {
    /// Standard Proton Mail version header.
    pub const version_header = "Version: ProtonMail";
    /// GopenPGP version header prefix.
    pub const gopenpgp_prefix = "Version: GopenPGP";
    /// Proton comment prefix.
    pub const comment_prefix = "Comment: https://protonmail.com";

    /// Check if armor headers indicate Proton Mail origin.
    pub fn isProtonArmor(headers: []const u8) bool {
        if (mem.indexOf(u8, headers, "ProtonMail") != null) return true;
        if (mem.indexOf(u8, headers, "GopenPGP") != null) return true;
        if (mem.indexOf(u8, headers, "protonmail.com") != null) return true;
        if (mem.indexOf(u8, headers, "proton.me") != null) return true;
        return false;
    }

    /// Generate Proton-compatible armor headers.
    pub fn generateHeaders(allocator: Allocator) ProtonError![]u8 {
        return std.fmt.allocPrint(allocator,
            "Version: GopenPGP 2.7.5\r\nComment: https://protonmail.com\r\n", .{}) catch
            return ProtonError.OutOfMemory;
    }
};

/// Parse a Proton Mail armored key block.
///
/// Proton armored keys follow the standard OpenPGP armor format but
/// include Proton-specific Version and Comment headers.
pub const ProtonArmoredKey = struct {
    /// The key type (public or private).
    key_type: KeyType,
    /// Armor headers (Version, Comment lines).
    headers: []const u8,
    /// Base64-encoded key data.
    body: []const u8,
    /// Whether the key is a primary key (vs address key).
    is_primary: bool,
    /// Associated email address (for address keys).
    address: ?[]const u8,

    pub const KeyType = enum {
        public,
        private,

        pub fn armorTag(self: KeyType) []const u8 {
            return switch (self) {
                .public => "PGP PUBLIC KEY BLOCK",
                .private => "PGP PRIVATE KEY BLOCK",
            };
        }
    };

    /// Free allocated memory.
    pub fn deinit(self: *const ProtonArmoredKey, allocator: Allocator) void {
        if (self.headers.len > 0) allocator.free(self.headers);
        if (self.body.len > 0) allocator.free(self.body);
        if (self.address) |addr| allocator.free(addr);
    }

    /// Parse an armored key from text.
    pub fn parse(allocator: Allocator, armored_text: []const u8) ProtonError!ProtonArmoredKey {
        const trimmed = mem.trim(u8, armored_text, " \t\r\n");

        // Detect key type
        const key_type: KeyType = if (mem.indexOf(u8, trimmed, "BEGIN PGP PUBLIC KEY BLOCK") != null)
            .public
        else if (mem.indexOf(u8, trimmed, "BEGIN PGP PRIVATE KEY BLOCK") != null)
            .private
        else
            return ProtonError.InvalidKeyFormat;

        // Extract headers (between first line and empty line)
        var headers_buf: std.ArrayList(u8) = .empty;
        errdefer headers_buf.deinit(allocator);

        var body_buf: std.ArrayList(u8) = .empty;
        errdefer body_buf.deinit(allocator);

        var in_headers = false;
        var in_body = false;
        var lines = mem.splitSequence(u8, trimmed, "\n");

        while (lines.next()) |raw_line| {
            const line = mem.trim(u8, raw_line, "\r \t");

            if (mem.startsWith(u8, line, "-----BEGIN")) {
                in_headers = true;
                continue;
            }
            if (mem.startsWith(u8, line, "-----END")) {
                break;
            }

            if (in_headers) {
                if (line.len == 0) {
                    in_headers = false;
                    in_body = true;
                    continue;
                }
                // Accumulate header lines
                const hw = headers_buf.writer(allocator);
                hw.writeAll(line) catch return ProtonError.OutOfMemory;
                hw.writeByte('\n') catch return ProtonError.OutOfMemory;
            } else if (in_body) {
                // Skip the CRC line (starts with '=')
                if (line.len > 0 and line[0] == '=') continue;

                const bw = body_buf.writer(allocator);
                bw.writeAll(line) catch return ProtonError.OutOfMemory;
            }
        }

        const headers = headers_buf.toOwnedSlice(allocator) catch return ProtonError.OutOfMemory;
        const body = body_buf.toOwnedSlice(allocator) catch return ProtonError.OutOfMemory;

        return .{
            .key_type = key_type,
            .headers = headers,
            .body = body,
            .is_primary = true,
            .address = null,
        };
    }

    /// Serialize the key back to armored format.
    pub fn toArmored(self: *const ProtonArmoredKey, allocator: Allocator) ProtonError![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);
        const w = buf.writer(allocator);

        w.print("-----BEGIN {s}-----\r\n", .{self.key_type.armorTag()}) catch return ProtonError.OutOfMemory;

        // Write headers
        if (self.headers.len > 0) {
            w.writeAll(self.headers) catch return ProtonError.OutOfMemory;
        } else {
            // Default Proton headers
            w.writeAll("Version: GopenPGP 2.7.5\r\n") catch return ProtonError.OutOfMemory;
            w.writeAll("Comment: https://protonmail.com\r\n") catch return ProtonError.OutOfMemory;
        }
        w.writeAll("\r\n") catch return ProtonError.OutOfMemory;

        // Write body in 76-char lines
        var offset: usize = 0;
        while (offset < self.body.len) {
            const end = @min(offset + 76, self.body.len);
            w.writeAll(self.body[offset..end]) catch return ProtonError.OutOfMemory;
            w.writeAll("\r\n") catch return ProtonError.OutOfMemory;
            offset = end;
        }

        w.print("-----END {s}-----\r\n", .{self.key_type.armorTag()}) catch return ProtonError.OutOfMemory;

        return buf.toOwnedSlice(allocator) catch return ProtonError.OutOfMemory;
    }
};

// =========================================================================
// Proton Message Format
// =========================================================================

/// Proton Mail message types.
pub const ProtonMessageType = enum(u8) {
    /// Inline PGP message (encrypted body directly).
    inline_pgp = 0,
    /// MIME-wrapped PGP message (PGP/MIME with multipart/encrypted).
    mime = 1,
    /// Clear-signed message.
    clear_signed = 2,
    /// Signed and encrypted MIME message.
    signed_encrypted_mime = 3,

    pub fn name(self: ProtonMessageType) []const u8 {
        return switch (self) {
            .inline_pgp => "Inline PGP",
            .mime => "PGP/MIME",
            .clear_signed => "Clear-signed",
            .signed_encrypted_mime => "Signed+Encrypted MIME",
        };
    }
};

/// Proton Mail message metadata.
pub const ProtonMessageMeta = struct {
    /// Message type.
    msg_type: ProtonMessageType,
    /// Sender email address.
    sender: ?[]const u8,
    /// Recipient email addresses.
    recipients: []const []const u8,
    /// Subject line.
    subject: ?[]const u8,
    /// Timestamp (Unix epoch seconds).
    timestamp: u64,
    /// Whether the message has attachments.
    has_attachments: bool,
    /// Number of attachments.
    attachment_count: u32,

    /// Free allocated memory.
    pub fn deinit(self: *const ProtonMessageMeta, allocator: Allocator) void {
        if (self.sender) |s| allocator.free(s);
        if (self.subject) |s| allocator.free(s);
        for (self.recipients) |r| allocator.free(r);
        allocator.free(self.recipients);
    }
};

/// Proton Mail MIME message builder.
///
/// Builds PGP/MIME messages with the specific headers Proton Mail expects.
pub const ProtonMimeBuilder = struct {
    /// Memory allocator.
    allocator: Allocator,
    /// MIME boundary string.
    boundary: []const u8,
    /// Content parts.
    parts: std.ArrayList(MimePart),

    pub const MimePart = struct {
        content_type: []const u8,
        content: []const u8,
        filename: ?[]const u8,
        is_attachment: bool,

        pub fn deinit(self: *const MimePart, allocator: Allocator) void {
            allocator.free(self.content_type);
            allocator.free(self.content);
            if (self.filename) |f| allocator.free(f);
        }
    };

    /// Initialize with a boundary string.
    pub fn init(allocator: Allocator, boundary: []const u8) ProtonMimeBuilder {
        return .{
            .allocator = allocator,
            .boundary = boundary,
            .parts = .empty,
        };
    }

    /// Free all resources.
    pub fn deinit(self: *ProtonMimeBuilder) void {
        for (self.parts.items) |*part| part.deinit(self.allocator);
        self.parts.deinit(self.allocator);
    }

    /// Add a text part.
    pub fn addTextPart(self: *ProtonMimeBuilder, content: []const u8) ProtonError!void {
        const ct = self.allocator.dupe(u8, "text/plain; charset=utf-8") catch return ProtonError.OutOfMemory;
        errdefer self.allocator.free(ct);
        const body = self.allocator.dupe(u8, content) catch return ProtonError.OutOfMemory;
        errdefer self.allocator.free(body);

        self.parts.append(self.allocator, .{
            .content_type = ct,
            .content = body,
            .filename = null,
            .is_attachment = false,
        }) catch return ProtonError.OutOfMemory;
    }

    /// Add an HTML part.
    pub fn addHtmlPart(self: *ProtonMimeBuilder, content: []const u8) ProtonError!void {
        const ct = self.allocator.dupe(u8, "text/html; charset=utf-8") catch return ProtonError.OutOfMemory;
        errdefer self.allocator.free(ct);
        const body = self.allocator.dupe(u8, content) catch return ProtonError.OutOfMemory;
        errdefer self.allocator.free(body);

        self.parts.append(self.allocator, .{
            .content_type = ct,
            .content = body,
            .filename = null,
            .is_attachment = false,
        }) catch return ProtonError.OutOfMemory;
    }

    /// Add an attachment.
    pub fn addAttachment(self: *ProtonMimeBuilder, content_type_str: []const u8, filename: []const u8, content: []const u8) ProtonError!void {
        const ct = self.allocator.dupe(u8, content_type_str) catch return ProtonError.OutOfMemory;
        errdefer self.allocator.free(ct);
        const body = self.allocator.dupe(u8, content) catch return ProtonError.OutOfMemory;
        errdefer self.allocator.free(body);
        const fname = self.allocator.dupe(u8, filename) catch return ProtonError.OutOfMemory;
        errdefer self.allocator.free(fname);

        self.parts.append(self.allocator, .{
            .content_type = ct,
            .content = body,
            .filename = fname,
            .is_attachment = true,
        }) catch return ProtonError.OutOfMemory;
    }

    /// Build the MIME message body.
    pub fn build(self: *const ProtonMimeBuilder) ProtonError![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(self.allocator);
        const w = buf.writer(self.allocator);

        for (self.parts.items) |*part| {
            w.print("--{s}\r\n", .{self.boundary}) catch return ProtonError.OutOfMemory;
            w.print("Content-Type: {s}\r\n", .{part.content_type}) catch return ProtonError.OutOfMemory;

            if (part.is_attachment) {
                if (part.filename) |fname| {
                    w.print("Content-Disposition: attachment; filename=\"{s}\"\r\n", .{fname}) catch return ProtonError.OutOfMemory;
                }
                w.writeAll("Content-Transfer-Encoding: base64\r\n") catch return ProtonError.OutOfMemory;
            } else {
                w.writeAll("Content-Transfer-Encoding: quoted-printable\r\n") catch return ProtonError.OutOfMemory;
            }

            w.writeAll("\r\n") catch return ProtonError.OutOfMemory;
            w.writeAll(part.content) catch return ProtonError.OutOfMemory;
            w.writeAll("\r\n") catch return ProtonError.OutOfMemory;
        }

        w.print("--{s}--\r\n", .{self.boundary}) catch return ProtonError.OutOfMemory;

        return buf.toOwnedSlice(self.allocator) catch return ProtonError.OutOfMemory;
    }
};

// =========================================================================
// GopenPGP Session Key
// =========================================================================

/// Session key in GopenPGP format.
///
/// GopenPGP represents session keys as a struct with the raw key bytes
/// and the algorithm identifier. Proton Mail prefers AES-256.
pub const SessionKey = struct {
    /// Raw session key bytes.
    key: [32]u8,
    /// Key length in bytes (16 for AES-128, 24 for AES-192, 32 for AES-256).
    key_len: u8,
    /// Symmetric algorithm identifier.
    algorithm: SymmetricAlgorithm,

    /// Create a new AES-256 session key from raw bytes.
    pub fn fromAes256(key_bytes: [32]u8) SessionKey {
        return .{
            .key = key_bytes,
            .key_len = 32,
            .algorithm = .aes256,
        };
    }

    /// Create a session key from raw bytes and algorithm.
    pub fn fromRaw(key_bytes: []const u8, algorithm: SymmetricAlgorithm) SessionKey {
        var key: [32]u8 = std.mem.zeroes([32]u8);
        const copy_len = @min(key_bytes.len, 32);
        @memcpy(key[0..copy_len], key_bytes[0..copy_len]);
        return .{
            .key = key,
            .key_len = @intCast(copy_len),
            .algorithm = algorithm,
        };
    }

    /// Get the effective key bytes.
    pub fn keyBytes(self: *const SessionKey) []const u8 {
        return self.key[0..self.key_len];
    }

    /// Check if this is the Proton-preferred algorithm (AES-256).
    pub fn isProtonPreferred(self: *const SessionKey) bool {
        return self.algorithm == .aes256 and self.key_len == 32;
    }

    /// Encode to GopenPGP JSON-compatible format.
    pub fn toJson(self: *const SessionKey, allocator: Allocator) ProtonError![]u8 {
        const hex = encodeHex(allocator, self.keyBytes()) catch return ProtonError.OutOfMemory;
        defer allocator.free(hex);

        return std.fmt.allocPrint(allocator,
            "{{\"Key\":\"{s}\",\"Algo\":\"{s}\"}}", .{
            hex,
            self.algorithm.name(),
        }) catch return ProtonError.OutOfMemory;
    }

    /// Zeroize the key material.
    pub fn zeroize(self: *SessionKey) void {
        @memset(&self.key, 0);
        self.key_len = 0;
    }
};

// =========================================================================
// GopenPGP Message Types
// =========================================================================

/// GopenPGP PlainMessage — unencrypted message with metadata.
pub const PlainMessage = struct {
    /// Message body (text or binary data).
    data: []const u8,
    /// Whether the content is text (vs binary).
    is_text: bool,
    /// Optional filename for binary data.
    filename: ?[]const u8,
    /// Modification time (Unix timestamp).
    time: u64,

    /// Create a text message.
    pub fn text(allocator: Allocator, content: []const u8) ProtonError!PlainMessage {
        const data = allocator.dupe(u8, content) catch return ProtonError.OutOfMemory;
        return .{
            .data = data,
            .is_text = true,
            .filename = null,
            .time = 0,
        };
    }

    /// Create a binary message.
    pub fn binary(allocator: Allocator, content: []const u8, filename: ?[]const u8) ProtonError!PlainMessage {
        const data = allocator.dupe(u8, content) catch return ProtonError.OutOfMemory;
        errdefer allocator.free(data);
        const fname = if (filename) |f|
            allocator.dupe(u8, f) catch return ProtonError.OutOfMemory
        else
            null;
        return .{
            .data = data,
            .is_text = false,
            .filename = fname,
            .time = 0,
        };
    }

    /// Free allocated memory.
    pub fn deinit(self: *const PlainMessage, allocator: Allocator) void {
        allocator.free(self.data);
        if (self.filename) |f| allocator.free(f);
    }

    /// Get the text content (returns null if binary).
    pub fn getText(self: *const PlainMessage) ?[]const u8 {
        if (self.is_text) return self.data;
        return null;
    }

    /// Get the binary content.
    pub fn getBinary(self: *const PlainMessage) []const u8 {
        return self.data;
    }
};

/// GopenPGP PGPMessage — encrypted OpenPGP message.
pub const PGPMessage = struct {
    /// Armored or raw encrypted message data.
    data: []const u8,
    /// Whether the data is armored.
    is_armored: bool,

    /// Create from armored text.
    pub fn fromArmored(allocator: Allocator, armored: []const u8) ProtonError!PGPMessage {
        const data = allocator.dupe(u8, armored) catch return ProtonError.OutOfMemory;
        return .{
            .data = data,
            .is_armored = true,
        };
    }

    /// Create from raw binary packets.
    pub fn fromBinary(allocator: Allocator, raw: []const u8) ProtonError!PGPMessage {
        const data = allocator.dupe(u8, raw) catch return ProtonError.OutOfMemory;
        return .{
            .data = data,
            .is_armored = false,
        };
    }

    /// Free allocated memory.
    pub fn deinit(self: *const PGPMessage, allocator: Allocator) void {
        allocator.free(self.data);
    }

    /// Get the armored representation.
    pub fn getArmored(self: *const PGPMessage) ?[]const u8 {
        if (self.is_armored) return self.data;
        return null;
    }
};

/// GopenPGP PGPSignature — detached signature.
pub const PGPSignature = struct {
    /// Signature data (armored or raw).
    data: []const u8,
    /// Whether the data is armored.
    is_armored: bool,

    /// Create from armored text.
    pub fn fromArmored(allocator: Allocator, armored: []const u8) ProtonError!PGPSignature {
        const data = allocator.dupe(u8, armored) catch return ProtonError.OutOfMemory;
        return .{
            .data = data,
            .is_armored = true,
        };
    }

    /// Free allocated memory.
    pub fn deinit(self: *const PGPSignature, allocator: Allocator) void {
        allocator.free(self.data);
    }
};

// =========================================================================
// GopenPGP KeyRing
// =========================================================================

/// An entry in a GopenPGP KeyRing.
pub const KeyRingEntry = struct {
    /// Key fingerprint (hex string).
    fingerprint: []const u8,
    /// Whether this is a primary key.
    is_primary: bool,
    /// Armored key data.
    armored_key: []const u8,
    /// Associated email address.
    email: ?[]const u8,
    /// Whether the key can sign.
    can_sign: bool,
    /// Whether the key can encrypt.
    can_encrypt: bool,
    /// Whether this entry contains a private key.
    is_private: bool,

    /// Free allocated memory.
    pub fn deinit(self: *const KeyRingEntry, allocator: Allocator) void {
        allocator.free(self.fingerprint);
        allocator.free(self.armored_key);
        if (self.email) |e| allocator.free(e);
    }
};

/// GopenPGP KeyRing — collection of OpenPGP keys.
///
/// In the Proton model, each user has a primary key and one or more
/// address keys. The KeyRing manages these collectively.
pub const KeyRing = struct {
    /// Keys in the ring.
    entries: std.ArrayList(KeyRingEntry),
    /// Allocator.
    allocator: Allocator,

    /// Initialize an empty key ring.
    pub fn init(allocator: Allocator) KeyRing {
        return .{
            .entries = .empty,
            .allocator = allocator,
        };
    }

    /// Free all resources.
    pub fn deinit(self: *KeyRing) void {
        for (self.entries.items) |*entry| entry.deinit(self.allocator);
        self.entries.deinit(self.allocator);
    }

    /// Add a key to the ring.
    pub fn addKey(
        self: *KeyRing,
        fingerprint: []const u8,
        armored_key: []const u8,
        email: ?[]const u8,
        is_primary: bool,
        can_sign: bool,
        can_encrypt: bool,
        is_private: bool,
    ) ProtonError!void {
        const fp = self.allocator.dupe(u8, fingerprint) catch return ProtonError.OutOfMemory;
        errdefer self.allocator.free(fp);
        const ak = self.allocator.dupe(u8, armored_key) catch return ProtonError.OutOfMemory;
        errdefer self.allocator.free(ak);
        const em = if (email) |e|
            self.allocator.dupe(u8, e) catch return ProtonError.OutOfMemory
        else
            null;

        self.entries.append(self.allocator, .{
            .fingerprint = fp,
            .armored_key = ak,
            .email = em,
            .is_primary = is_primary,
            .can_sign = can_sign,
            .can_encrypt = can_encrypt,
            .is_private = is_private,
        }) catch return ProtonError.OutOfMemory;
    }

    /// Get the count of keys in the ring.
    pub fn count(self: *const KeyRing) usize {
        return self.entries.items.len;
    }

    /// Find the primary key.
    pub fn getPrimaryKey(self: *const KeyRing) ?*const KeyRingEntry {
        for (self.entries.items) |*entry| {
            if (entry.is_primary) return entry;
        }
        return null;
    }

    /// Find a key by email address.
    pub fn findByEmail(self: *const KeyRing, target_email: []const u8) ?*const KeyRingEntry {
        for (self.entries.items) |*entry| {
            if (entry.email) |email| {
                if (mem.eql(u8, email, target_email)) return entry;
            }
        }
        return null;
    }

    /// Find a key by fingerprint.
    pub fn findByFingerprint(self: *const KeyRing, fp: []const u8) ?*const KeyRingEntry {
        for (self.entries.items) |*entry| {
            if (mem.eql(u8, entry.fingerprint, fp)) return entry;
        }
        return null;
    }

    /// Get all signing keys.
    pub fn getSigningKeys(self: *const KeyRing, allocator: Allocator) ProtonError![]const KeyRingEntry {
        var result: std.ArrayList(KeyRingEntry) = .empty;
        errdefer result.deinit(allocator);

        for (self.entries.items) |entry| {
            if (entry.can_sign and entry.is_private) {
                result.append(allocator, entry) catch return ProtonError.OutOfMemory;
            }
        }

        return result.toOwnedSlice(allocator) catch return ProtonError.OutOfMemory;
    }

    /// Get all encryption keys.
    pub fn getEncryptionKeys(self: *const KeyRing, allocator: Allocator) ProtonError![]const KeyRingEntry {
        var result: std.ArrayList(KeyRingEntry) = .empty;
        errdefer result.deinit(allocator);

        for (self.entries.items) |entry| {
            if (entry.can_encrypt) {
                result.append(allocator, entry) catch return ProtonError.OutOfMemory;
            }
        }

        return result.toOwnedSlice(allocator) catch return ProtonError.OutOfMemory;
    }

    /// Serialize the key ring metadata to a JSON-compatible format.
    pub fn toJsonMeta(self: *const KeyRing, allocator: Allocator) ProtonError![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);
        const w = buf.writer(allocator);

        w.writeAll("{\"Keys\":[") catch return ProtonError.OutOfMemory;

        for (self.entries.items, 0..) |*entry, i| {
            if (i > 0) w.writeByte(',') catch return ProtonError.OutOfMemory;
            w.writeAll("{") catch return ProtonError.OutOfMemory;
            w.print("\"Fingerprint\":\"{s}\"", .{entry.fingerprint}) catch return ProtonError.OutOfMemory;
            w.print(",\"Primary\":{s}", .{if (entry.is_primary) "true" else "false"}) catch return ProtonError.OutOfMemory;
            w.print(",\"CanSign\":{s}", .{if (entry.can_sign) "true" else "false"}) catch return ProtonError.OutOfMemory;
            w.print(",\"CanEncrypt\":{s}", .{if (entry.can_encrypt) "true" else "false"}) catch return ProtonError.OutOfMemory;
            if (entry.email) |email| {
                w.print(",\"Email\":\"{s}\"", .{email}) catch return ProtonError.OutOfMemory;
            }
            w.writeAll("}") catch return ProtonError.OutOfMemory;
        }

        w.writeAll("]}") catch return ProtonError.OutOfMemory;

        return buf.toOwnedSlice(allocator) catch return ProtonError.OutOfMemory;
    }
};

// =========================================================================
// Proton Contact Card
// =========================================================================

/// Proton Mail contact card types.
pub const ContactCardType = enum(u8) {
    /// Plain text vCard (Type 0).
    plain = 0,
    /// Encrypted-only vCard (Type 1) — encrypted with contact key.
    encrypted = 1,
    /// Signed-only vCard (Type 2) — signed with user's key.
    signed = 2,
    /// Signed and encrypted vCard (Type 3).
    signed_encrypted = 3,

    pub fn name(self: ContactCardType) []const u8 {
        return switch (self) {
            .plain => "Plain",
            .encrypted => "Encrypted",
            .signed => "Signed",
            .signed_encrypted => "Signed+Encrypted",
        };
    }

    /// Whether the card type requires encryption.
    pub fn isEncrypted(self: ContactCardType) bool {
        return self == .encrypted or self == .signed_encrypted;
    }

    /// Whether the card type requires a signature.
    pub fn isSigned(self: ContactCardType) bool {
        return self == .signed or self == .signed_encrypted;
    }
};

/// A Proton Mail contact card.
pub const ContactCard = struct {
    /// Card type.
    card_type: ContactCardType,
    /// Card data (vCard format, possibly encrypted/signed).
    data: []const u8,
    /// Signature (for signed card types).
    signature: ?[]const u8,

    /// Free allocated memory.
    pub fn deinit(self: *const ContactCard, allocator: Allocator) void {
        allocator.free(self.data);
        if (self.signature) |sig| allocator.free(sig);
    }
};

// =========================================================================
// Proton Compatibility Checker
// =========================================================================

/// Proton Mail compatibility analysis.
pub const ProtonCompat = struct {
    /// Check if a key is compatible with Proton Mail.
    pub fn checkKeyCompatibility(allocator: Allocator, algorithm: PublicKeyAlgorithm, key_bits: u16) ProtonError!ProtonKeyCompat {
        var result = ProtonKeyCompat{
            .compatible = true,
            .preferred = false,
            .issues = .empty,
        };
        errdefer result.deinit(allocator);

        // Proton supports RSA 2048+, ECC (P-256, P-384, P-521), Ed25519, X25519
        switch (algorithm) {
            .rsa_encrypt_sign, .rsa_sign_only, .rsa_encrypt_only => {
                if (key_bits < 2048) {
                    result.compatible = false;
                    try addCompIssue(allocator, &result.issues, "RSA key must be at least 2048 bits for Proton Mail");
                } else if (key_bits == 4096) {
                    result.preferred = true;
                    try addCompIssue(allocator, &result.issues, "RSA-4096 is the preferred RSA key size for Proton Mail");
                }
            },
            .ed25519, .eddsa => {
                result.preferred = true;
                try addCompIssue(allocator, &result.issues, "Ed25519 is fully supported by Proton Mail");
            },
            .x25519, .ecdh => {
                result.compatible = true;
                try addCompIssue(allocator, &result.issues, "X25519/ECDH is supported for encryption");
            },
            .ecdsa => {
                result.compatible = true;
                try addCompIssue(allocator, &result.issues, "ECDSA is supported by Proton Mail");
            },
            .dsa => {
                result.compatible = false;
                try addCompIssue(allocator, &result.issues, "DSA keys are not supported by Proton Mail");
            },
            .elgamal => {
                result.compatible = false;
                try addCompIssue(allocator, &result.issues, "ElGamal keys are not supported by Proton Mail");
            },
            else => {
                result.compatible = false;
                try addCompIssue(allocator, &result.issues, "Unknown algorithm; may not be supported by Proton Mail");
            },
        }

        return result;
    }

    /// Check if a symmetric algorithm is Proton-preferred.
    pub fn isPreferredSymmetric(algo: SymmetricAlgorithm) bool {
        return algo == .aes256;
    }

    /// Get the Proton-preferred compression algorithm.
    /// GopenPGP uses no compression by default since GopenPGP v2.
    pub fn preferredCompression() u8 {
        return 0; // Uncompressed
    }

    /// Check if an armored message appears to be from Proton Mail.
    pub fn isProtonMessage(data: []const u8) bool {
        return ProtonArmorHeaders.isProtonArmor(data);
    }

    /// Get the recommended session key algorithm for Proton Mail.
    pub fn recommendedSessionKeyAlgo() SymmetricAlgorithm {
        return .aes256;
    }

    /// Get recommended hash algorithm for Proton Mail.
    pub fn recommendedHashAlgo() HashAlgorithm {
        return .sha256;
    }
};

/// Result of Proton key compatibility check.
pub const ProtonKeyCompat = struct {
    /// Whether the key works with Proton Mail.
    compatible: bool,
    /// Whether the key is in Proton's preferred format.
    preferred: bool,
    /// Compatibility notes.
    issues: std.ArrayList([]const u8),

    /// Free all resources.
    pub fn deinit(self: *ProtonKeyCompat, allocator: Allocator) void {
        for (self.issues.items) |issue| allocator.free(issue);
        self.issues.deinit(allocator);
    }
};

// =========================================================================
// Address Key model
// =========================================================================

/// Proton Mail address key model.
///
/// Each Proton user has:
///   - One primary key (used for the main account)
///   - One or more address keys (one per email address/alias)
///   - Keys may be rotated independently
pub const AddressKeyManager = struct {
    /// Primary key fingerprint.
    primary_fingerprint: ?[]const u8,
    /// Mapping of email address to key fingerprint.
    address_keys: std.ArrayList(AddressKeyEntry),
    /// Allocator.
    allocator: Allocator,

    pub const AddressKeyEntry = struct {
        email: []const u8,
        fingerprint: []const u8,
        is_active: bool,
        key_version: u32,

        pub fn deinit(self: *const AddressKeyEntry, allocator: Allocator) void {
            allocator.free(self.email);
            allocator.free(self.fingerprint);
        }
    };

    /// Initialize an empty address key manager.
    pub fn init(allocator: Allocator) AddressKeyManager {
        return .{
            .primary_fingerprint = null,
            .address_keys = .empty,
            .allocator = allocator,
        };
    }

    /// Free all resources.
    pub fn deinit(self: *AddressKeyManager) void {
        if (self.primary_fingerprint) |fp| self.allocator.free(fp);
        for (self.address_keys.items) |*entry| entry.deinit(self.allocator);
        self.address_keys.deinit(self.allocator);
    }

    /// Set the primary key.
    pub fn setPrimaryKey(self: *AddressKeyManager, fingerprint: []const u8) ProtonError!void {
        if (self.primary_fingerprint) |old| self.allocator.free(old);
        self.primary_fingerprint = self.allocator.dupe(u8, fingerprint) catch return ProtonError.OutOfMemory;
    }

    /// Add an address key.
    pub fn addAddressKey(
        self: *AddressKeyManager,
        email: []const u8,
        fingerprint: []const u8,
        version: u32,
    ) ProtonError!void {
        const em = self.allocator.dupe(u8, email) catch return ProtonError.OutOfMemory;
        errdefer self.allocator.free(em);
        const fp = self.allocator.dupe(u8, fingerprint) catch return ProtonError.OutOfMemory;

        self.address_keys.append(self.allocator, .{
            .email = em,
            .fingerprint = fp,
            .is_active = true,
            .key_version = version,
        }) catch return ProtonError.OutOfMemory;
    }

    /// Find the key fingerprint for an email address.
    pub fn findKeyForAddress(self: *const AddressKeyManager, email: []const u8) ?[]const u8 {
        for (self.address_keys.items) |*entry| {
            if (entry.is_active and mem.eql(u8, entry.email, email)) {
                return entry.fingerprint;
            }
        }
        return null;
    }

    /// Rotate a key for an address (deactivate old, activate new).
    pub fn rotateKey(
        self: *AddressKeyManager,
        email: []const u8,
        new_fingerprint: []const u8,
        new_version: u32,
    ) ProtonError!void {
        // Deactivate old keys for this address
        for (self.address_keys.items) |*entry| {
            if (mem.eql(u8, entry.email, email)) {
                entry.is_active = false;
            }
        }

        // Add new key
        try self.addAddressKey(email, new_fingerprint, new_version);
    }

    /// Get the count of active address keys.
    pub fn activeKeyCount(self: *const AddressKeyManager) usize {
        var count: usize = 0;
        for (self.address_keys.items) |*entry| {
            if (entry.is_active) count += 1;
        }
        return count;
    }
};

// =========================================================================
// Helper functions
// =========================================================================

/// Encode bytes as hexadecimal string.
fn encodeHex(allocator: Allocator, data: []const u8) ![]u8 {
    const hex_chars = "0123456789abcdef";
    const result = try allocator.alloc(u8, data.len * 2);
    for (data, 0..) |b, i| {
        result[i * 2] = hex_chars[b >> 4];
        result[i * 2 + 1] = hex_chars[b & 0x0F];
    }
    return result;
}

/// Add a compatibility issue string to an issue list.
fn addCompIssue(allocator: Allocator, issues: *std.ArrayList([]const u8), msg: []const u8) ProtonError!void {
    const copy = allocator.dupe(u8, msg) catch return ProtonError.OutOfMemory;
    issues.append(allocator, copy) catch return ProtonError.OutOfMemory;
}

// =========================================================================
// Tests
// =========================================================================

test "ProtonArmorHeaders detection" {
    const testing = std.testing;

    try testing.expect(ProtonArmorHeaders.isProtonArmor("Version: ProtonMail\n"));
    try testing.expect(ProtonArmorHeaders.isProtonArmor("Version: GopenPGP 2.7.5\n"));
    try testing.expect(ProtonArmorHeaders.isProtonArmor("Comment: https://protonmail.com\n"));
    try testing.expect(!ProtonArmorHeaders.isProtonArmor("Version: GnuPG v2\n"));
}

test "ProtonArmoredKey parse and serialize" {
    const allocator = std.testing.allocator;

    const armored =
        \\-----BEGIN PGP PUBLIC KEY BLOCK-----
        \\Version: GopenPGP 2.7.5
        \\Comment: https://protonmail.com
        \\
        \\bWVzc2FnZQ==
        \\-----END PGP PUBLIC KEY BLOCK-----
    ;

    var key = try ProtonArmoredKey.parse(allocator, armored);
    defer key.deinit(allocator);

    try std.testing.expectEqual(ProtonArmoredKey.KeyType.public, key.key_type);
    try std.testing.expect(key.headers.len > 0);
    try std.testing.expect(ProtonArmorHeaders.isProtonArmor(key.headers));

    // Round-trip
    const re_armored = try key.toArmored(allocator);
    defer allocator.free(re_armored);
    try std.testing.expect(re_armored.len > 0);
    try std.testing.expect(mem.indexOf(u8, re_armored, "BEGIN PGP PUBLIC KEY BLOCK") != null);
}

test "SessionKey creation and properties" {
    const key_bytes: [32]u8 = .{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };

    const sk = SessionKey.fromAes256(key_bytes);
    try std.testing.expect(sk.isProtonPreferred());
    try std.testing.expectEqual(@as(u8, 32), sk.key_len);
    try std.testing.expectEqual(SymmetricAlgorithm.aes256, sk.algorithm);

    // Test keyBytes
    const kb = sk.keyBytes();
    try std.testing.expectEqual(@as(usize, 32), kb.len);
    try std.testing.expectEqual(@as(u8, 0x01), kb[0]);
}

test "SessionKey from raw" {
    const raw: [16]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const sk = SessionKey.fromRaw(&raw, .aes128);
    try std.testing.expectEqual(@as(u8, 16), sk.key_len);
    try std.testing.expect(!sk.isProtonPreferred());
}

test "SessionKey JSON" {
    const allocator = std.testing.allocator;
    var sk = SessionKey.fromAes256(std.mem.zeroes([32]u8));
    const json = try sk.toJson(allocator);
    defer allocator.free(json);

    try std.testing.expect(json.len > 0);
    try std.testing.expect(mem.indexOf(u8, json, "\"Key\"") != null);
    try std.testing.expect(mem.indexOf(u8, json, "\"Algo\"") != null);
}

test "SessionKey zeroize" {
    var sk = SessionKey.fromAes256(.{
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    });
    sk.zeroize();
    try std.testing.expectEqual(@as(u8, 0), sk.key_len);
    try std.testing.expectEqual(@as(u8, 0), sk.key[0]);
}

test "PlainMessage text" {
    const allocator = std.testing.allocator;
    const msg = try PlainMessage.text(allocator, "Hello, world!");
    defer msg.deinit(allocator);

    try std.testing.expect(msg.is_text);
    try std.testing.expectEqualStrings("Hello, world!", msg.getText().?);
}

test "PlainMessage binary" {
    const allocator = std.testing.allocator;
    const data: [4]u8 = .{ 0xDE, 0xAD, 0xBE, 0xEF };
    const msg = try PlainMessage.binary(allocator, &data, "test.bin");
    defer msg.deinit(allocator);

    try std.testing.expect(!msg.is_text);
    try std.testing.expect(msg.getText() == null);
    try std.testing.expectEqual(@as(usize, 4), msg.getBinary().len);
    try std.testing.expectEqualStrings("test.bin", msg.filename.?);
}

test "PGPMessage creation" {
    const allocator = std.testing.allocator;

    const armored = "-----BEGIN PGP MESSAGE-----\ndata\n-----END PGP MESSAGE-----";
    const msg = try PGPMessage.fromArmored(allocator, armored);
    defer msg.deinit(allocator);

    try std.testing.expect(msg.is_armored);
    try std.testing.expectEqualStrings(armored, msg.getArmored().?);

    const raw_msg = try PGPMessage.fromBinary(allocator, &.{ 0xC0, 0x01 });
    defer raw_msg.deinit(allocator);
    try std.testing.expect(!raw_msg.is_armored);
    try std.testing.expect(raw_msg.getArmored() == null);
}

test "KeyRing operations" {
    const allocator = std.testing.allocator;
    var ring = KeyRing.init(allocator);
    defer ring.deinit();

    try ring.addKey("AABB", "armored-primary", "alice@proton.me", true, true, false, true);
    try ring.addKey("CCDD", "armored-enc", "alice@proton.me", false, false, true, false);

    try std.testing.expectEqual(@as(usize, 2), ring.count());

    // Primary key
    const primary = ring.getPrimaryKey();
    try std.testing.expect(primary != null);
    try std.testing.expectEqualStrings("AABB", primary.?.fingerprint);

    // Find by email
    const by_email = ring.findByEmail("alice@proton.me");
    try std.testing.expect(by_email != null);

    // Find by fingerprint
    const by_fp = ring.findByFingerprint("CCDD");
    try std.testing.expect(by_fp != null);
    try std.testing.expect(by_fp.?.can_encrypt);

    // Not found
    try std.testing.expect(ring.findByFingerprint("EEFF") == null);
}

test "KeyRing JSON metadata" {
    const allocator = std.testing.allocator;
    var ring = KeyRing.init(allocator);
    defer ring.deinit();

    try ring.addKey("AABBCCDD", "key-data", "user@proton.me", true, true, true, true);

    const json = try ring.toJsonMeta(allocator);
    defer allocator.free(json);

    try std.testing.expect(json.len > 0);
    try std.testing.expect(mem.indexOf(u8, json, "AABBCCDD") != null);
    try std.testing.expect(mem.indexOf(u8, json, "\"Primary\":true") != null);
}

test "ContactCardType properties" {
    try std.testing.expect(!ContactCardType.plain.isEncrypted());
    try std.testing.expect(!ContactCardType.plain.isSigned());
    try std.testing.expect(ContactCardType.encrypted.isEncrypted());
    try std.testing.expect(!ContactCardType.encrypted.isSigned());
    try std.testing.expect(ContactCardType.signed.isSigned());
    try std.testing.expect(ContactCardType.signed_encrypted.isEncrypted());
    try std.testing.expect(ContactCardType.signed_encrypted.isSigned());
}

test "ProtonCompat key compatibility" {
    const allocator = std.testing.allocator;

    // Ed25519 should be preferred
    var ed_compat = try ProtonCompat.checkKeyCompatibility(allocator, .ed25519, 256);
    defer ed_compat.deinit(allocator);
    try std.testing.expect(ed_compat.compatible);
    try std.testing.expect(ed_compat.preferred);

    // RSA-4096 should be preferred RSA
    var rsa_compat = try ProtonCompat.checkKeyCompatibility(allocator, .rsa_encrypt_sign, 4096);
    defer rsa_compat.deinit(allocator);
    try std.testing.expect(rsa_compat.compatible);
    try std.testing.expect(rsa_compat.preferred);

    // RSA-1024 should not be compatible
    var weak_rsa = try ProtonCompat.checkKeyCompatibility(allocator, .rsa_encrypt_sign, 1024);
    defer weak_rsa.deinit(allocator);
    try std.testing.expect(!weak_rsa.compatible);

    // DSA should not be compatible
    var dsa_compat = try ProtonCompat.checkKeyCompatibility(allocator, .dsa, 2048);
    defer dsa_compat.deinit(allocator);
    try std.testing.expect(!dsa_compat.compatible);
}

test "ProtonCompat algorithm preferences" {
    try std.testing.expect(ProtonCompat.isPreferredSymmetric(.aes256));
    try std.testing.expect(!ProtonCompat.isPreferredSymmetric(.aes128));
    try std.testing.expectEqual(@as(u8, 0), ProtonCompat.preferredCompression());
    try std.testing.expectEqual(SymmetricAlgorithm.aes256, ProtonCompat.recommendedSessionKeyAlgo());
    try std.testing.expectEqual(HashAlgorithm.sha256, ProtonCompat.recommendedHashAlgo());
}

test "AddressKeyManager operations" {
    const allocator = std.testing.allocator;
    var mgr = AddressKeyManager.init(allocator);
    defer mgr.deinit();

    try mgr.setPrimaryKey("PRIMARY_FP");
    try mgr.addAddressKey("alice@proton.me", "ADDR_FP_1", 1);
    try mgr.addAddressKey("alias@proton.me", "ADDR_FP_2", 1);

    try std.testing.expectEqual(@as(usize, 2), mgr.activeKeyCount());
    try std.testing.expectEqualStrings("PRIMARY_FP", mgr.primary_fingerprint.?);

    // Find key for address
    const fp = mgr.findKeyForAddress("alice@proton.me");
    try std.testing.expect(fp != null);
    try std.testing.expectEqualStrings("ADDR_FP_1", fp.?);

    // Not found
    try std.testing.expect(mgr.findKeyForAddress("unknown@proton.me") == null);

    // Key rotation
    try mgr.rotateKey("alice@proton.me", "ADDR_FP_3", 2);
    const new_fp = mgr.findKeyForAddress("alice@proton.me");
    try std.testing.expect(new_fp != null);
    try std.testing.expectEqualStrings("ADDR_FP_3", new_fp.?);

    // Old key should be deactivated, new one active
    try std.testing.expectEqual(@as(usize, 2), mgr.activeKeyCount());
}

test "ProtonMimeBuilder" {
    const allocator = std.testing.allocator;
    var builder = ProtonMimeBuilder.init(allocator, "----boundary123");
    defer builder.deinit();

    try builder.addTextPart("Hello, world!");
    try builder.addHtmlPart("<p>Hello, world!</p>");

    const mime = try builder.build();
    defer allocator.free(mime);

    try std.testing.expect(mime.len > 0);
    try std.testing.expect(mem.indexOf(u8, mime, "----boundary123") != null);
    try std.testing.expect(mem.indexOf(u8, mime, "text/plain") != null);
    try std.testing.expect(mem.indexOf(u8, mime, "text/html") != null);
}

test "ProtonMessageType names" {
    try std.testing.expectEqualStrings("Inline PGP", ProtonMessageType.inline_pgp.name());
    try std.testing.expectEqualStrings("PGP/MIME", ProtonMessageType.mime.name());
}

test "encodeHex" {
    const allocator = std.testing.allocator;
    const hex = try encodeHex(allocator, &.{ 0xAB, 0xCD, 0xEF });
    defer allocator.free(hex);
    try std.testing.expectEqualStrings("abcdef", hex);
}
