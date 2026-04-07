// SPDX-License-Identifier: MIT
//! OpenPGP preferences system for algorithm negotiation.
//!
//! When sending encrypted messages to multiple recipients, the sender must
//! choose algorithms that all recipients support. This module implements
//! the preference negotiation logic described in RFC 4880 Section 13.2
//! and extended in RFC 9580.
//!
//! Preferences are stored as ordered lists where earlier entries are more
//! preferred. The negotiation process finds the first algorithm that is
//! acceptable to all parties.
//!
//! Features flags indicate support for optional protocol features like
//! modification detection (MDC), AEAD encryption, and V5 key formats.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const enums = @import("../types/enums.zig");
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const CompressionAlgorithm = enums.CompressionAlgorithm;
const AeadAlgorithm = enums.AeadAlgorithm;

// ---------------------------------------------------------------------------
// Feature flags
// ---------------------------------------------------------------------------

/// OpenPGP implementation features as advertised in the Features
/// signature subpacket (type 30). See RFC 4880 Section 5.2.3.24
/// and RFC 9580 Section 5.2.3.25.
pub const Features = packed struct(u8) {
    /// Modification Detection Code (MDC) support.
    /// Indicates the key holder prefers SEIPD packets (tag 18) over
    /// legacy SE packets (tag 9).
    modification_detection: bool = false,

    /// AEAD Encrypted Data support (RFC 9580).
    /// Indicates the key holder supports SEIPDv2 with AEAD.
    aead: bool = false,

    /// Version 5 public key format support (legacy draft).
    /// Included for compatibility but superseded by V6 in RFC 9580.
    v5_keys: bool = false,

    /// Reserved bits, must be zero.
    _padding: u5 = 0,

    /// Return a Features value with all supported features enabled.
    pub fn all() Features {
        return .{
            .modification_detection = true,
            .aead = true,
            .v5_keys = false,
            ._padding = 0,
        };
    }

    /// Return a Features value suitable for V4 keys.
    pub fn v4Default() Features {
        return .{
            .modification_detection = true,
            .aead = false,
            .v5_keys = false,
            ._padding = 0,
        };
    }

    /// Return a Features value suitable for V6 keys (RFC 9580).
    pub fn v6Default() Features {
        return .{
            .modification_detection = true,
            .aead = true,
            .v5_keys = false,
            ._padding = 0,
        };
    }

    /// Check whether two feature sets are compatible.
    /// Returns the intersection of features.
    pub fn intersect(a: Features, b: Features) Features {
        return .{
            .modification_detection = a.modification_detection and b.modification_detection,
            .aead = a.aead and b.aead,
            .v5_keys = a.v5_keys and b.v5_keys,
            ._padding = 0,
        };
    }

    /// Return the raw byte value for serialization.
    pub fn toByte(self: Features) u8 {
        return @bitCast(self);
    }

    /// Parse a Features value from a raw byte.
    pub fn fromByte(byte: u8) Features {
        return @bitCast(byte);
    }

    /// Human-readable description of enabled features.
    pub fn describe(self: Features, allocator: Allocator) ![]u8 {
        var parts: std.ArrayList([]const u8) = .empty;
        defer parts.deinit(allocator);

        if (self.modification_detection) try parts.append(allocator, "MDC");
        if (self.aead) try parts.append(allocator, "AEAD");
        if (self.v5_keys) try parts.append(allocator, "V5Keys");

        if (parts.items.len == 0) {
            const result = try allocator.alloc(u8, 4);
            @memcpy(result, "none");
            return result;
        }

        // Calculate total length
        var total_len: usize = 0;
        for (parts.items, 0..) |part, i| {
            total_len += part.len;
            if (i < parts.items.len - 1) total_len += 2; // ", "
        }

        const result = try allocator.alloc(u8, total_len);
        var offset: usize = 0;
        for (parts.items, 0..) |part, i| {
            @memcpy(result[offset .. offset + part.len], part);
            offset += part.len;
            if (i < parts.items.len - 1) {
                result[offset] = ',';
                result[offset + 1] = ' ';
                offset += 2;
            }
        }
        return result;
    }
};

// ---------------------------------------------------------------------------
// Negotiated result
// ---------------------------------------------------------------------------

/// The result of algorithm negotiation between sender and recipient(s).
///
/// Contains the "best" algorithm for each category that all parties support.
pub const NegotiatedAlgorithms = struct {
    /// The symmetric cipher to use for encryption.
    symmetric: SymmetricAlgorithm,
    /// The hash algorithm to use for signatures.
    hash: HashAlgorithm,
    /// The compression algorithm to use.
    compression: CompressionAlgorithm,
    /// The AEAD mode, if both parties support AEAD; null otherwise.
    aead: ?AeadAlgorithm,

    /// Describe the negotiated algorithms as a human-readable string.
    pub fn describe(self: NegotiatedAlgorithms, allocator: Allocator) ![]u8 {
        const sym_name = self.symmetric.name();
        const hash_name = self.hash.name();
        const comp_name = self.compression.name();
        const aead_name = if (self.aead) |a| a.name() else "none";

        const total_len = sym_name.len + hash_name.len + comp_name.len + aead_name.len + 40;
        var buf = try allocator.alloc(u8, total_len);

        const written = std.fmt.bufPrint(buf, "sym={s} hash={s} comp={s} aead={s}", .{
            sym_name, hash_name, comp_name, aead_name,
        }) catch {
            allocator.free(buf);
            return error.OutOfMemory;
        };

        // Shrink to actual size
        if (written.len < buf.len) {
            buf = allocator.realloc(buf, written.len) catch buf;
        }
        return buf;
    }
};

// ---------------------------------------------------------------------------
// Preferences
// ---------------------------------------------------------------------------

/// Algorithm preferences associated with an OpenPGP key.
///
/// These are typically extracted from the self-signature subpackets of a key's
/// primary user ID. They indicate which algorithms the key holder's
/// implementation supports, in order of preference (most preferred first).
pub const Preferences = struct {
    /// Preferred symmetric algorithms, ordered by preference (most preferred first).
    symmetric: []SymmetricAlgorithm,
    /// Preferred hash algorithms, ordered by preference (most preferred first).
    hash: []HashAlgorithm,
    /// Preferred compression algorithms, ordered by preference (most preferred first).
    compression: []CompressionAlgorithm,
    /// Preferred AEAD algorithms (RFC 9580). Null if AEAD is not supported.
    aead: ?[]AeadAlgorithm,
    /// Features flags from the Features subpacket.
    features: Features,

    /// Default preferences for V4 keys (RFC 4880 compatibility).
    ///
    /// Returns preferences with widely-supported algorithms:
    /// - Symmetric: AES-256, AES-128, CAST5, Triple-DES
    /// - Hash: SHA-256, SHA-512, SHA-1
    /// - Compression: ZLIB, ZIP, Uncompressed
    /// - AEAD: none (V4 keys do not use AEAD by default)
    pub fn default() Preferences {
        return .{
            .symmetric = @constCast(&default_symmetric_v4),
            .hash = @constCast(&default_hash_v4),
            .compression = @constCast(&default_compression_v4),
            .aead = null,
            .features = Features.v4Default(),
        };
    }

    /// Default preferences for V6 keys (RFC 9580).
    ///
    /// Returns preferences with modern algorithms:
    /// - Symmetric: AES-256, AES-128
    /// - Hash: SHA-512, SHA-256
    /// - Compression: ZLIB, ZIP, Uncompressed
    /// - AEAD: OCB, GCM, EAX
    pub fn defaultV6() Preferences {
        return .{
            .symmetric = @constCast(&default_symmetric_v6),
            .hash = @constCast(&default_hash_v6),
            .compression = @constCast(&default_compression_v6),
            .aead = @constCast(&default_aead_v6),
            .features = Features.v6Default(),
        };
    }

    /// Create empty preferences (no algorithms specified).
    pub fn empty() Preferences {
        return .{
            .symmetric = &.{},
            .hash = &.{},
            .compression = &.{},
            .aead = null,
            .features = .{},
        };
    }

    /// Negotiate algorithms between sender and recipient preferences.
    ///
    /// For each algorithm category, selects the first algorithm in the
    /// sender's preference list that also appears in the recipient's list.
    /// If no common algorithm is found, falls back to mandatory-to-implement
    /// algorithms per the RFC.
    ///
    /// AEAD is only negotiated if both parties advertise AEAD support in
    /// their Features flags and have AEAD preference lists.
    pub fn negotiate(sender: Preferences, recipient: Preferences) NegotiatedAlgorithms {
        const sym = negotiateSymmetric(sender.symmetric, recipient.symmetric);
        const h = negotiateHash(sender.hash, recipient.hash);
        const comp = negotiateCompression(sender.compression, recipient.compression);
        const aead_result = negotiateAead(sender, recipient);

        return .{
            .symmetric = sym,
            .hash = h,
            .compression = comp,
            .aead = aead_result,
        };
    }

    /// Extract preferences from raw signature subpacket data.
    ///
    /// Parses the following subpacket types:
    /// - Type 11: Preferred Symmetric Algorithms
    /// - Type 21: Preferred Hash Algorithms
    /// - Type 22: Preferred Compression Algorithms
    /// - Type 30: Features
    /// - Type 34: Preferred AEAD Algorithms (RFC 9580)
    ///
    /// The key_data should be the raw subpacket area bytes from a
    /// self-signature.
    pub fn fromSubpacketData(subpacket_data: []const u8, allocator: Allocator) !Preferences {
        var prefs = Preferences{
            .symmetric = &.{},
            .hash = &.{},
            .compression = &.{},
            .aead = null,
            .features = .{},
        };

        var offset: usize = 0;
        while (offset < subpacket_data.len) {
            // Parse subpacket length
            if (offset >= subpacket_data.len) break;
            const len_result = parseSubpacketLength(subpacket_data[offset..]) catch break;
            offset += len_result.header_len;

            if (len_result.body_len == 0) continue;
            if (offset + len_result.body_len > subpacket_data.len) break;

            const body = subpacket_data[offset .. offset + len_result.body_len];
            offset += len_result.body_len;

            if (body.len == 0) continue;

            // Tag byte (strip critical bit)
            const tag = body[0] & 0x7F;
            const payload = body[1..];

            switch (tag) {
                // Preferred Symmetric Algorithms (type 11)
                11 => {
                    if (payload.len > 0) {
                        const sym_list = try allocator.alloc(SymmetricAlgorithm, payload.len);
                        for (payload, 0..) |byte, i| {
                            sym_list[i] = @enumFromInt(byte);
                        }
                        prefs.symmetric = sym_list;
                    }
                },
                // Preferred Hash Algorithms (type 21)
                21 => {
                    if (payload.len > 0) {
                        const hash_list = try allocator.alloc(HashAlgorithm, payload.len);
                        for (payload, 0..) |byte, i| {
                            hash_list[i] = @enumFromInt(byte);
                        }
                        prefs.hash = hash_list;
                    }
                },
                // Preferred Compression Algorithms (type 22)
                22 => {
                    if (payload.len > 0) {
                        const comp_list = try allocator.alloc(CompressionAlgorithm, payload.len);
                        for (payload, 0..) |byte, i| {
                            comp_list[i] = @enumFromInt(byte);
                        }
                        prefs.compression = comp_list;
                    }
                },
                // Features (type 30)
                30 => {
                    if (payload.len >= 1) {
                        prefs.features = Features.fromByte(payload[0]);
                    }
                },
                // Preferred AEAD Ciphersuites (type 34, RFC 9580)
                // Each entry is 2 bytes: symmetric_algo + aead_algo
                39 => {
                    // Preferred AEAD Algorithms (RFC 9580 type 39)
                    if (payload.len > 0) {
                        const aead_list = try allocator.alloc(AeadAlgorithm, payload.len);
                        for (payload, 0..) |byte, i| {
                            aead_list[i] = @enumFromInt(byte);
                        }
                        prefs.aead = aead_list;
                    }
                },
                else => {
                    // Ignore unknown subpacket types
                },
            }
        }

        return prefs;
    }

    /// Serialize preferences as signature subpacket data.
    ///
    /// Generates subpackets for:
    /// - Type 11: Preferred Symmetric Algorithms
    /// - Type 21: Preferred Hash Algorithms
    /// - Type 22: Preferred Compression Algorithms
    /// - Type 30: Features
    /// - Type 39: Preferred AEAD Algorithms (if present)
    pub fn toSubpackets(self: Preferences, allocator: Allocator) ![]u8 {
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(allocator);

        // Preferred Symmetric Algorithms (type 11)
        if (self.symmetric.len > 0) {
            try writeSubpacket(allocator, &output, 11, self.symmetric.len, struct {
                sym: []SymmetricAlgorithm,
                fn write(ctx: @This(), buf: *std.ArrayList(u8), alloc: Allocator) !void {
                    for (ctx.sym) |algo| {
                        try buf.append(alloc, @intFromEnum(algo));
                    }
                }
            }{ .sym = self.symmetric });
        }

        // Preferred Hash Algorithms (type 21)
        if (self.hash.len > 0) {
            try writeSubpacket(allocator, &output, 21, self.hash.len, struct {
                h: []HashAlgorithm,
                fn write(ctx: @This(), buf: *std.ArrayList(u8), alloc: Allocator) !void {
                    for (ctx.h) |algo| {
                        try buf.append(alloc, @intFromEnum(algo));
                    }
                }
            }{ .h = self.hash });
        }

        // Preferred Compression Algorithms (type 22)
        if (self.compression.len > 0) {
            try writeSubpacket(allocator, &output, 22, self.compression.len, struct {
                comp: []CompressionAlgorithm,
                fn write(ctx: @This(), buf: *std.ArrayList(u8), alloc: Allocator) !void {
                    for (ctx.comp) |algo| {
                        try buf.append(alloc, @intFromEnum(algo));
                    }
                }
            }{ .comp = self.compression });
        }

        // Features (type 30)
        {
            const feat_byte = self.features.toByte();
            if (feat_byte != 0) {
                try writeSubpacket(allocator, &output, 30, 1, struct {
                    feat: u8,
                    fn write(ctx: @This(), buf: *std.ArrayList(u8), alloc: Allocator) !void {
                        try buf.append(alloc, ctx.feat);
                    }
                }{ .feat = feat_byte });
            }
        }

        // Preferred AEAD Algorithms (type 39, RFC 9580)
        if (self.aead) |aead_list| {
            if (aead_list.len > 0) {
                try writeSubpacket(allocator, &output, 39, aead_list.len, struct {
                    a: []AeadAlgorithm,
                    fn write(ctx: @This(), buf: *std.ArrayList(u8), alloc: Allocator) !void {
                        for (ctx.a) |algo| {
                            try buf.append(alloc, @intFromEnum(algo));
                        }
                    }
                }{ .a = aead_list });
            }
        }

        return output.toOwnedSlice(allocator);
    }

    /// Free dynamically allocated preference arrays.
    ///
    /// Only frees arrays that were allocated (i.e., not the static defaults).
    /// Caller must track which Preferences were created with an allocator
    /// vs. returned from default()/defaultV6().
    pub fn deinit(self: *Preferences, allocator: Allocator) void {
        if (self.symmetric.len > 0 and !isStaticSymmetric(self.symmetric)) {
            allocator.free(self.symmetric);
        }
        if (self.hash.len > 0 and !isStaticHash(self.hash)) {
            allocator.free(self.hash);
        }
        if (self.compression.len > 0 and !isStaticCompression(self.compression)) {
            allocator.free(self.compression);
        }
        if (self.aead) |aead_list| {
            if (aead_list.len > 0 and !isStaticAead(aead_list)) {
                allocator.free(aead_list);
            }
        }
        self.* = empty();
    }

    /// Check if the preferences have any algorithms specified.
    pub fn isEmpty(self: *const Preferences) bool {
        return self.symmetric.len == 0 and
            self.hash.len == 0 and
            self.compression.len == 0 and
            self.aead == null;
    }

    /// Return the most preferred symmetric algorithm, or a fallback.
    pub fn preferredSymmetric(self: *const Preferences) SymmetricAlgorithm {
        if (self.symmetric.len > 0) return self.symmetric[0];
        return .aes128; // RFC 4880 mandatory-to-implement
    }

    /// Return the most preferred hash algorithm, or a fallback.
    pub fn preferredHash(self: *const Preferences) HashAlgorithm {
        if (self.hash.len > 0) return self.hash[0];
        return .sha256; // RFC 9580 recommended default
    }

    /// Return the most preferred compression algorithm, or a fallback.
    pub fn preferredCompression(self: *const Preferences) CompressionAlgorithm {
        if (self.compression.len > 0) return self.compression[0];
        return .uncompressed;
    }

    /// Return the most preferred AEAD algorithm, or null.
    pub fn preferredAead(self: *const Preferences) ?AeadAlgorithm {
        if (self.aead) |aead_list| {
            if (aead_list.len > 0) return aead_list[0];
        }
        return null;
    }

    /// Check if a symmetric algorithm is in the preference list.
    pub fn supportsSymmetric(self: *const Preferences, algo: SymmetricAlgorithm) bool {
        for (self.symmetric) |s| {
            if (s == algo) return true;
        }
        return false;
    }

    /// Check if a hash algorithm is in the preference list.
    pub fn supportsHash(self: *const Preferences, algo: HashAlgorithm) bool {
        for (self.hash) |h| {
            if (h == algo) return true;
        }
        return false;
    }

    /// Check if a compression algorithm is in the preference list.
    pub fn supportsCompression(self: *const Preferences, algo: CompressionAlgorithm) bool {
        for (self.compression) |c| {
            if (c == algo) return true;
        }
        return false;
    }

    /// Check if an AEAD algorithm is in the preference list.
    pub fn supportsAead(self: *const Preferences, algo: AeadAlgorithm) bool {
        if (self.aead) |aead_list| {
            for (aead_list) |a| {
                if (a == algo) return true;
            }
        }
        return false;
    }

    /// Merge two preference sets, keeping algorithms from both but
    /// preferring the order from `primary`.
    pub fn merge(primary: Preferences, secondary: Preferences, allocator: Allocator) !Preferences {
        return .{
            .symmetric = try mergeSymmetricLists(allocator, primary.symmetric, secondary.symmetric),
            .hash = try mergeHashLists(allocator, primary.hash, secondary.hash),
            .compression = try mergeCompressionLists(allocator, primary.compression, secondary.compression),
            .aead = try mergeAeadLists(allocator, primary.aead, secondary.aead),
            .features = Features.intersect(primary.features, secondary.features),
        };
    }
};

// ---------------------------------------------------------------------------
// Multi-recipient negotiation
// ---------------------------------------------------------------------------

/// Negotiate algorithms for multiple recipients.
///
/// Finds the first algorithm in each category that all recipients support.
/// If a recipient has no preferences for a category, it is assumed to
/// support the mandatory-to-implement algorithms.
///
/// This implements the recommendation from RFC 4880 Section 13.2:
/// "If the user does not have the recipient's public key, the sender
/// should use the defaults."
pub fn negotiateForRecipients(allocator: Allocator, recipient_prefs: []const Preferences) !NegotiatedAlgorithms {
    if (recipient_prefs.len == 0) {
        // No recipients; return defaults.
        return .{
            .symmetric = .aes128,
            .hash = .sha256,
            .compression = .uncompressed,
            .aead = null,
        };
    }

    if (recipient_prefs.len == 1) {
        // Single recipient; use their first preferred or fallback.
        const r = recipient_prefs[0];
        return .{
            .symmetric = if (r.symmetric.len > 0) r.symmetric[0] else .aes128,
            .hash = if (r.hash.len > 0) r.hash[0] else .sha256,
            .compression = if (r.compression.len > 0) r.compression[0] else .uncompressed,
            .aead = if (r.features.aead) blk: {
                if (r.aead) |al| {
                    break :blk if (al.len > 0) al[0] else null;
                }
                break :blk null;
            } else null,
        };
    }

    // Multi-recipient: find common algorithms.
    const sym = try negotiateSymmetricMulti(allocator, recipient_prefs);
    const h = try negotiateHashMulti(allocator, recipient_prefs);
    const comp = try negotiateCompressionMulti(allocator, recipient_prefs);
    const aead_result = try negotiateAeadMulti(allocator, recipient_prefs);

    return .{
        .symmetric = sym,
        .hash = h,
        .compression = comp,
        .aead = aead_result,
    };
}

// ---------------------------------------------------------------------------
// Algorithm ranking and scoring
// ---------------------------------------------------------------------------

/// Assign a security score to a symmetric algorithm (higher is better).
pub fn symmetricScore(algo: SymmetricAlgorithm) u8 {
    return switch (algo) {
        .aes256 => 100,
        .camellia256 => 98,
        .twofish => 95,
        .aes192 => 90,
        .camellia192 => 88,
        .aes128 => 80,
        .camellia128 => 78,
        .cast5 => 40,
        .blowfish => 35,
        .triple_des => 30,
        .idea => 25,
        .plaintext => 0,
        _ => 0,
    };
}

/// Assign a security score to a hash algorithm (higher is better).
pub fn hashScore(algo: HashAlgorithm) u8 {
    return switch (algo) {
        .sha512 => 100,
        .sha384 => 95,
        .sha256 => 90,
        .sha224 => 70,
        .ripemd160 => 40,
        .sha1 => 30,
        .md5 => 10,
        _ => 0,
    };
}

/// Assign a security score to a compression algorithm (higher is better).
pub fn compressionScore(algo: CompressionAlgorithm) u8 {
    return switch (algo) {
        .zlib => 80,
        .bzip2 => 75,
        .zip => 70,
        .uncompressed => 50,
        _ => 0,
    };
}

/// Assign a security score to an AEAD algorithm (higher is better).
pub fn aeadScore(algo: AeadAlgorithm) u8 {
    return switch (algo) {
        .ocb => 100,
        .gcm => 90,
        .eax => 80,
        _ => 0,
    };
}

// ---------------------------------------------------------------------------
// Static default preference arrays
// ---------------------------------------------------------------------------

const default_symmetric_v4 = [_]SymmetricAlgorithm{ .aes256, .aes128, .cast5, .triple_des };
const default_hash_v4 = [_]HashAlgorithm{ .sha256, .sha512, .sha1 };
const default_compression_v4 = [_]CompressionAlgorithm{ .zlib, .zip, .uncompressed };

const default_symmetric_v6 = [_]SymmetricAlgorithm{ .aes256, .aes128 };
const default_hash_v6 = [_]HashAlgorithm{ .sha512, .sha256 };
const default_compression_v6 = [_]CompressionAlgorithm{ .zlib, .zip, .uncompressed };
const default_aead_v6 = [_]AeadAlgorithm{ .ocb, .gcm, .eax };

// ---------------------------------------------------------------------------
// Static pointer checks (to avoid freeing compile-time slices)
// ---------------------------------------------------------------------------

fn isStaticSymmetric(ptr: []SymmetricAlgorithm) bool {
    const static_ptr: [*]const SymmetricAlgorithm = &default_symmetric_v4;
    const static_ptr_v6: [*]const SymmetricAlgorithm = &default_symmetric_v6;
    return @intFromPtr(ptr.ptr) == @intFromPtr(static_ptr) or
        @intFromPtr(ptr.ptr) == @intFromPtr(static_ptr_v6);
}

fn isStaticHash(ptr: []HashAlgorithm) bool {
    const static_ptr: [*]const HashAlgorithm = &default_hash_v4;
    const static_ptr_v6: [*]const HashAlgorithm = &default_hash_v6;
    return @intFromPtr(ptr.ptr) == @intFromPtr(static_ptr) or
        @intFromPtr(ptr.ptr) == @intFromPtr(static_ptr_v6);
}

fn isStaticCompression(ptr: []CompressionAlgorithm) bool {
    const static_ptr: [*]const CompressionAlgorithm = &default_compression_v4;
    const static_ptr_v6: [*]const CompressionAlgorithm = &default_compression_v6;
    return @intFromPtr(ptr.ptr) == @intFromPtr(static_ptr) or
        @intFromPtr(ptr.ptr) == @intFromPtr(static_ptr_v6);
}

fn isStaticAead(ptr: []AeadAlgorithm) bool {
    const static_ptr: [*]const AeadAlgorithm = &default_aead_v6;
    return @intFromPtr(ptr.ptr) == @intFromPtr(static_ptr);
}

// ---------------------------------------------------------------------------
// Two-party negotiation helpers
// ---------------------------------------------------------------------------

fn negotiateSymmetric(sender: []SymmetricAlgorithm, recipient: []SymmetricAlgorithm) SymmetricAlgorithm {
    // Try sender's preferences in order, looking for a match in recipient's list.
    for (sender) |s| {
        for (recipient) |r| {
            if (s == r) return s;
        }
    }
    // Fallback: AES-128 is mandatory to implement per RFC 9580.
    return .aes128;
}

fn negotiateHash(sender: []HashAlgorithm, recipient: []HashAlgorithm) HashAlgorithm {
    for (sender) |s| {
        for (recipient) |r| {
            if (s == r) return s;
        }
    }
    // Fallback: SHA-256 is mandatory per RFC 9580.
    return .sha256;
}

fn negotiateCompression(sender: []CompressionAlgorithm, recipient: []CompressionAlgorithm) CompressionAlgorithm {
    for (sender) |s| {
        for (recipient) |r| {
            if (s == r) return s;
        }
    }
    // Fallback: uncompressed is always valid.
    return .uncompressed;
}

fn negotiateAead(sender: Preferences, recipient: Preferences) ?AeadAlgorithm {
    // Both must support AEAD.
    if (!sender.features.aead or !recipient.features.aead) return null;

    const sender_aead = sender.aead orelse return null;
    const recipient_aead = recipient.aead orelse return null;

    for (sender_aead) |s| {
        for (recipient_aead) |r| {
            if (s == r) return s;
        }
    }
    return null;
}

// ---------------------------------------------------------------------------
// Multi-recipient negotiation helpers
// ---------------------------------------------------------------------------

fn negotiateSymmetricMulti(allocator: Allocator, prefs: []const Preferences) !SymmetricAlgorithm {
    _ = allocator;
    // Use the first recipient's list as candidate order.
    if (prefs.len == 0) return .aes128;
    const candidates = prefs[0].symmetric;

    for (candidates) |candidate| {
        var all_support = true;
        for (prefs[1..]) |p| {
            if (p.symmetric.len == 0) continue; // No prefs = accept anything
            var found = false;
            for (p.symmetric) |s| {
                if (s == candidate) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                all_support = false;
                break;
            }
        }
        if (all_support) return candidate;
    }
    return .aes128;
}

fn negotiateHashMulti(allocator: Allocator, prefs: []const Preferences) !HashAlgorithm {
    _ = allocator;
    if (prefs.len == 0) return .sha256;
    const candidates = prefs[0].hash;

    for (candidates) |candidate| {
        var all_support = true;
        for (prefs[1..]) |p| {
            if (p.hash.len == 0) continue;
            var found = false;
            for (p.hash) |h| {
                if (h == candidate) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                all_support = false;
                break;
            }
        }
        if (all_support) return candidate;
    }
    return .sha256;
}

fn negotiateCompressionMulti(allocator: Allocator, prefs: []const Preferences) !CompressionAlgorithm {
    _ = allocator;
    if (prefs.len == 0) return .uncompressed;
    const candidates = prefs[0].compression;

    for (candidates) |candidate| {
        var all_support = true;
        for (prefs[1..]) |p| {
            if (p.compression.len == 0) continue;
            var found = false;
            for (p.compression) |c| {
                if (c == candidate) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                all_support = false;
                break;
            }
        }
        if (all_support) return candidate;
    }
    return .uncompressed;
}

fn negotiateAeadMulti(allocator: Allocator, prefs: []const Preferences) !?AeadAlgorithm {
    _ = allocator;
    // All recipients must support AEAD.
    for (prefs) |p| {
        if (!p.features.aead) return null;
        if (p.aead == null) return null;
    }

    if (prefs.len == 0) return null;
    const candidates = prefs[0].aead orelse return null;

    for (candidates) |candidate| {
        var all_support = true;
        for (prefs[1..]) |p| {
            const aead_list = p.aead orelse {
                all_support = false;
                break;
            };
            var found = false;
            for (aead_list) |a| {
                if (a == candidate) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                all_support = false;
                break;
            }
        }
        if (all_support) return candidate;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Subpacket serialization helpers
// ---------------------------------------------------------------------------

const SubpacketLengthResult = struct {
    body_len: usize,
    header_len: usize,
};

fn parseSubpacketLength(data: []const u8) !SubpacketLengthResult {
    if (data.len == 0) return error.InvalidData;

    const first = data[0];
    if (first < 192) {
        return .{ .body_len = first, .header_len = 1 };
    } else if (first < 255) {
        if (data.len < 2) return error.InvalidData;
        const len = (@as(usize, first - 192) << 8) + @as(usize, data[1]) + 192;
        return .{ .body_len = len, .header_len = 2 };
    } else {
        if (data.len < 5) return error.InvalidData;
        const len = mem.readInt(u32, data[1..5], .big);
        return .{ .body_len = len, .header_len = 5 };
    }
}

fn writeSubpacket(
    allocator: Allocator,
    output: *std.ArrayList(u8),
    tag: u8,
    payload_len: usize,
    writer: anytype,
) !void {
    const body_len = payload_len + 1; // +1 for tag byte

    // Write subpacket length
    if (body_len < 192) {
        try output.append(allocator, @intCast(body_len));
    } else if (body_len < 8384) {
        const adjusted = body_len - 192;
        try output.append(allocator, @intCast((adjusted >> 8) + 192));
        try output.append(allocator, @intCast(adjusted & 0xFF));
    } else {
        try output.append(allocator, 255);
        const len_bytes = mem.toBytes(mem.nativeTo(u32, @intCast(body_len), .big));
        try output.appendSlice(allocator, &len_bytes);
    }

    // Write tag byte
    try output.append(allocator, tag);

    // Write payload
    try writer.write(output, allocator);
}

// ---------------------------------------------------------------------------
// Merge helpers
// ---------------------------------------------------------------------------

fn mergeSymmetricLists(allocator: Allocator, primary: []SymmetricAlgorithm, secondary: []SymmetricAlgorithm) ![]SymmetricAlgorithm {
    var result: std.ArrayList(SymmetricAlgorithm) = .empty;
    errdefer result.deinit(allocator);

    // Add all from primary
    for (primary) |algo| {
        try result.append(allocator, algo);
    }

    // Add from secondary if not already present
    for (secondary) |algo| {
        var found = false;
        for (primary) |p| {
            if (p == algo) {
                found = true;
                break;
            }
        }
        if (!found) {
            try result.append(allocator, algo);
        }
    }

    return result.toOwnedSlice(allocator);
}

fn mergeHashLists(allocator: Allocator, primary: []HashAlgorithm, secondary: []HashAlgorithm) ![]HashAlgorithm {
    var result: std.ArrayList(HashAlgorithm) = .empty;
    errdefer result.deinit(allocator);

    for (primary) |algo| {
        try result.append(allocator, algo);
    }

    for (secondary) |algo| {
        var found = false;
        for (primary) |p| {
            if (p == algo) {
                found = true;
                break;
            }
        }
        if (!found) {
            try result.append(allocator, algo);
        }
    }

    return result.toOwnedSlice(allocator);
}

fn mergeCompressionLists(allocator: Allocator, primary: []CompressionAlgorithm, secondary: []CompressionAlgorithm) ![]CompressionAlgorithm {
    var result: std.ArrayList(CompressionAlgorithm) = .empty;
    errdefer result.deinit(allocator);

    for (primary) |algo| {
        try result.append(allocator, algo);
    }

    for (secondary) |algo| {
        var found = false;
        for (primary) |p| {
            if (p == algo) {
                found = true;
                break;
            }
        }
        if (!found) {
            try result.append(allocator, algo);
        }
    }

    return result.toOwnedSlice(allocator);
}

fn mergeAeadLists(allocator: Allocator, primary: ?[]AeadAlgorithm, secondary: ?[]AeadAlgorithm) !?[]AeadAlgorithm {
    const p = primary orelse {
        if (secondary) |sec| return try allocator.dupe(AeadAlgorithm, sec);
        return null;
    };
    const s = secondary orelse return try allocator.dupe(AeadAlgorithm, p);

    var result: std.ArrayList(AeadAlgorithm) = .empty;
    errdefer result.deinit(allocator);

    for (p) |algo| {
        try result.append(allocator, algo);
    }

    for (s) |algo| {
        var found = false;
        for (p) |pa| {
            if (pa == algo) {
                found = true;
                break;
            }
        }
        if (!found) {
            try result.append(allocator, algo);
        }
    }

    const slice = try result.toOwnedSlice(allocator);
    return slice;
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

const InvalidData = error{InvalidData};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "preferences: default v4 preferences" {
    const prefs = Preferences.default();
    try std.testing.expect(prefs.symmetric.len == 4);
    try std.testing.expect(prefs.symmetric[0] == .aes256);
    try std.testing.expect(prefs.hash.len == 3);
    try std.testing.expect(prefs.hash[0] == .sha256);
    try std.testing.expect(prefs.compression.len == 3);
    try std.testing.expect(prefs.aead == null);
    try std.testing.expect(prefs.features.modification_detection);
    try std.testing.expect(!prefs.features.aead);
}

test "preferences: default v6 preferences" {
    const prefs = Preferences.defaultV6();
    try std.testing.expect(prefs.symmetric.len == 2);
    try std.testing.expect(prefs.symmetric[0] == .aes256);
    try std.testing.expect(prefs.hash.len == 2);
    try std.testing.expect(prefs.hash[0] == .sha512);
    try std.testing.expect(prefs.aead != null);
    try std.testing.expect(prefs.features.aead);
    try std.testing.expect(prefs.features.modification_detection);
}

test "preferences: empty preferences" {
    const prefs = Preferences.empty();
    try std.testing.expect(prefs.isEmpty());
    try std.testing.expect(prefs.symmetric.len == 0);
    try std.testing.expect(prefs.hash.len == 0);
    try std.testing.expect(prefs.compression.len == 0);
    try std.testing.expect(prefs.aead == null);
}

test "preferences: negotiate same preferences" {
    const v4 = Preferences.default();
    const result = v4.negotiate(v4);
    try std.testing.expect(result.symmetric == .aes256);
    try std.testing.expect(result.hash == .sha256);
    try std.testing.expect(result.compression == .zlib);
    try std.testing.expect(result.aead == null);
}

test "preferences: negotiate v4 and v6" {
    const v4 = Preferences.default();
    const v6 = Preferences.defaultV6();
    const result = v4.negotiate(v6);
    // AES-256 is first in v4 and present in v6
    try std.testing.expect(result.symmetric == .aes256);
    // AEAD requires both to support it; v4 does not
    try std.testing.expect(result.aead == null);
}

test "preferences: features intersect" {
    const a = Features{ .modification_detection = true, .aead = true };
    const b = Features{ .modification_detection = true, .aead = false };
    const c = Features.intersect(a, b);
    try std.testing.expect(c.modification_detection);
    try std.testing.expect(!c.aead);
}

test "preferences: features byte round-trip" {
    const orig = Features{ .modification_detection = true, .aead = true, .v5_keys = false };
    const byte = orig.toByte();
    const recovered = Features.fromByte(byte);
    try std.testing.expect(recovered.modification_detection == orig.modification_detection);
    try std.testing.expect(recovered.aead == orig.aead);
    try std.testing.expect(recovered.v5_keys == orig.v5_keys);
}

test "preferences: symmetric score ordering" {
    try std.testing.expect(symmetricScore(.aes256) > symmetricScore(.aes128));
    try std.testing.expect(symmetricScore(.aes128) > symmetricScore(.cast5));
    try std.testing.expect(symmetricScore(.cast5) > symmetricScore(.triple_des));
    try std.testing.expect(symmetricScore(.plaintext) == 0);
}

test "preferences: hash score ordering" {
    try std.testing.expect(hashScore(.sha512) > hashScore(.sha256));
    try std.testing.expect(hashScore(.sha256) > hashScore(.sha1));
    try std.testing.expect(hashScore(.sha1) > hashScore(.md5));
}

test "preferences: preferred algorithm accessors" {
    const prefs = Preferences.default();
    try std.testing.expect(prefs.preferredSymmetric() == .aes256);
    try std.testing.expect(prefs.preferredHash() == .sha256);
    try std.testing.expect(prefs.preferredCompression() == .zlib);
    try std.testing.expect(prefs.preferredAead() == null);
}

test "preferences: supports algorithm checks" {
    const prefs = Preferences.default();
    try std.testing.expect(prefs.supportsSymmetric(.aes256));
    try std.testing.expect(prefs.supportsSymmetric(.aes128));
    try std.testing.expect(prefs.supportsSymmetric(.cast5));
    try std.testing.expect(!prefs.supportsSymmetric(.twofish));
    try std.testing.expect(prefs.supportsHash(.sha256));
    try std.testing.expect(!prefs.supportsHash(.md5));
}

test "preferences: subpacket round-trip" {
    const allocator = std.testing.allocator;

    // Create preferences with known values
    var sym_list = try allocator.alloc(SymmetricAlgorithm, 2);
    sym_list[0] = .aes256;
    sym_list[1] = .aes128;

    var hash_list = try allocator.alloc(HashAlgorithm, 2);
    hash_list[0] = .sha256;
    hash_list[1] = .sha512;

    var comp_list = try allocator.alloc(CompressionAlgorithm, 1);
    comp_list[0] = .zlib;

    var prefs = Preferences{
        .symmetric = sym_list,
        .hash = hash_list,
        .compression = comp_list,
        .aead = null,
        .features = Features.v4Default(),
    };

    // Serialize to subpackets
    const subpacket_data = try prefs.toSubpackets(allocator);
    defer allocator.free(subpacket_data);

    // Parse back
    const parsed = try Preferences.fromSubpacketData(subpacket_data, allocator);

    // Verify round-trip
    try std.testing.expect(parsed.symmetric.len == 2);
    try std.testing.expect(parsed.symmetric[0] == .aes256);
    try std.testing.expect(parsed.symmetric[1] == .aes128);
    try std.testing.expect(parsed.hash.len == 2);
    try std.testing.expect(parsed.hash[0] == .sha256);
    try std.testing.expect(parsed.compression.len == 1);
    try std.testing.expect(parsed.features.modification_detection);

    // Clean up
    allocator.free(parsed.symmetric);
    allocator.free(parsed.hash);
    allocator.free(parsed.compression);
    allocator.free(sym_list);
    allocator.free(hash_list);
    allocator.free(comp_list);
}
