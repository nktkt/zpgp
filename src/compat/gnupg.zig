// SPDX-License-Identifier: MIT
//! GnuPG compatibility layer.
//!
//! Provides interoperability with GnuPG's on-disk structures and status
//! protocol. This module can:
//!   - Locate and parse GnuPG home directory files (pubring, secring, trustdb)
//!   - Read GnuPG trust database records
//!   - Parse and generate GnuPG status-fd protocol messages
//!
//! The status-fd protocol is used by GnuPG's `--status-fd` and `--status-file`
//! options to emit machine-readable progress and result indicators. Many
//! frontends (e.g., Enigmail, GPGTools) depend on these messages.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const enums = @import("../types/enums.zig");
const HashAlgorithm = enums.HashAlgorithm;
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const SymmetricAlgorithm = enums.SymmetricAlgorithm;

// =========================================================================
// GnuPG home directory
// =========================================================================

/// GnuPG home directory structure.
///
/// By default GnuPG stores its files under `~/.gnupg`. This struct
/// provides path helpers for the well-known files inside that directory.
pub const GnupgHome = struct {
    path: []const u8,

    /// Return the default GnuPG home directory (`$GNUPGHOME` or `~/.gnupg`).
    pub fn default(allocator: Allocator) !GnupgHome {
        // Check GNUPGHOME environment variable first.
        if (std.posix.getenv("GNUPGHOME")) |env_path| {
            return GnupgHome{ .path = env_path };
        }
        // Fall back to ~/.gnupg
        if (std.posix.getenv("HOME")) |home| {
            const path = try std.fmt.allocPrint(allocator, "{s}/.gnupg", .{home});
            return GnupgHome{ .path = path };
        }
        return error.HomeNotFound;
    }

    /// Path to the public keyring (`pubring.kbx` or `pubring.gpg`).
    pub fn pubringPath(self: GnupgHome, allocator: Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/pubring.kbx", .{self.path});
    }

    /// Path to the secret keyring (legacy `secring.gpg`).
    pub fn secringPath(self: GnupgHome, allocator: Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/secring.gpg", .{self.path});
    }

    /// Path to the trust database (`trustdb.gpg`).
    pub fn trustdbPath(self: GnupgHome, allocator: Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/trustdb.gpg", .{self.path});
    }

    /// Path to the main configuration file (`gpg.conf`).
    pub fn configPath(self: GnupgHome, allocator: Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/gpg.conf", .{self.path});
    }

    /// Path to the agent configuration file (`gpg-agent.conf`).
    pub fn agentConfigPath(self: GnupgHome, allocator: Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/gpg-agent.conf", .{self.path});
    }

    /// Path to the dirmngr configuration file (`dirmngr.conf`).
    pub fn dirmngrConfigPath(self: GnupgHome, allocator: Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/dirmngr.conf", .{self.path});
    }

    /// Path to the private keys directory (`private-keys-v1.d/`).
    pub fn privateKeysDir(self: GnupgHome, allocator: Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/private-keys-v1.d", .{self.path});
    }

    /// Path to the random seed file.
    pub fn randomSeedPath(self: GnupgHome, allocator: Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/random_seed", .{self.path});
    }
};

// =========================================================================
// GnuPG trust database reader
// =========================================================================

/// Trust record types in the GnuPG trust database.
pub const RecordType = enum(u8) {
    /// Version record (always first).
    version = 1,
    /// Free/unused record slot.
    free = 2,
    /// Hash table bucket.
    hash_table = 10,
    /// Trust record for a key.
    trust = 12,
    /// Validity record for a user ID.
    valid = 13,
    /// Catch-all for unknown record types.
    _,

    pub fn name(self: RecordType) []const u8 {
        return switch (self) {
            .version => "Version",
            .free => "Free",
            .hash_table => "Hash Table",
            .trust => "Trust",
            .valid => "Valid",
            _ => "Unknown",
        };
    }
};

/// A single record from the GnuPG trust database.
pub const TrustRecord = struct {
    /// The type of this record.
    record_type: RecordType,
    /// Record number (position in the file).
    record_number: u32,
    /// Raw record data (excluding the type byte).
    data: []u8,

    pub fn deinit(self: TrustRecord, allocator: Allocator) void {
        allocator.free(self.data);
    }
};

/// Parsed GnuPG trust database.
pub const TrustDatabase = struct {
    /// Trust database format version.
    version: u8,
    /// Creation timestamp (from the version record).
    created: u32,
    /// Next check timestamp.
    next_check: u32,
    /// Marginals needed for validity.
    marginals: u8,
    /// Completes needed for validity.
    completes: u8,
    /// Maximum certification depth.
    max_cert_depth: u8,
    /// Trust model in use (0 = classic, 1 = PGP).
    trust_model: u8,
    /// Minimum key size for trust calculations.
    min_key_size: u16,
    /// All records in the database.
    records: std.ArrayList(TrustRecord),

    /// Free all memory associated with this trust database.
    pub fn deinit(self: *TrustDatabase, allocator: Allocator) void {
        for (self.records.items) |record| record.deinit(allocator);
        self.records.deinit(allocator);
    }

    /// Count records of a specific type.
    pub fn countRecordsByType(self: *const TrustDatabase, record_type: RecordType) usize {
        var count: usize = 0;
        for (self.records.items) |record| {
            if (record.record_type == record_type) count += 1;
        }
        return count;
    }

    /// Find all trust records (type 12).
    pub fn trustRecords(self: *const TrustDatabase) []const TrustRecord {
        // Return a view into the records list filtered by type.
        // Since we can't return a filtered view without allocation,
        // callers should iterate and check record_type themselves.
        return self.records.items;
    }
};

/// GnuPG trust database reader.
///
/// The trust database (`trustdb.gpg`) uses fixed-size 40-byte records.
/// The first record is always a version record containing metadata.
pub const TrustDbReader = struct {
    /// Size of each record in the trust database.
    const RECORD_SIZE: usize = 40;

    /// Parse a trust database from raw bytes.
    pub fn parseFromBytes(allocator: Allocator, data: []const u8) !TrustDatabase {
        if (data.len < RECORD_SIZE) {
            return error.InvalidTrustDb;
        }

        var db = TrustDatabase{
            .version = 0,
            .created = 0,
            .next_check = 0,
            .marginals = 3,
            .completes = 1,
            .max_cert_depth = 5,
            .trust_model = 0,
            .min_key_size = 0,
            .records = .empty,
        };
        errdefer db.deinit(allocator);

        var offset: usize = 0;
        var record_number: u32 = 0;

        while (offset + RECORD_SIZE <= data.len) : ({
            offset += RECORD_SIZE;
            record_number += 1;
        }) {
            const record_data = data[offset .. offset + RECORD_SIZE];
            const rtype: RecordType = @enumFromInt(record_data[0]);

            // Parse the version record specially.
            if (record_number == 0 and rtype == .version) {
                db.version = record_data[1];
                if (record_data.len >= 10) {
                    db.created = mem.readInt(u32, record_data[2..6], .big);
                    db.next_check = mem.readInt(u32, record_data[6..10], .big);
                }
                if (record_data.len >= 13) {
                    db.marginals = record_data[10];
                    db.completes = record_data[11];
                    db.max_cert_depth = record_data[12];
                }
                if (record_data.len >= 14) {
                    db.trust_model = record_data[13];
                }
                if (record_data.len >= 16) {
                    db.min_key_size = mem.readInt(u16, record_data[14..16], .big);
                }
            }

            // Store all records with their raw data.
            const raw_copy = try allocator.alloc(u8, RECORD_SIZE - 1);
            @memcpy(raw_copy, record_data[1..RECORD_SIZE]);

            try db.records.append(allocator, .{
                .record_type = rtype,
                .record_number = record_number,
                .data = raw_copy,
            });
        }

        return db;
    }

    /// Extract a trust level from a trust record.
    ///
    /// Trust records store the owner trust value at offset 1 within
    /// the record body (offset 2 from the start of the raw record).
    pub fn extractTrustLevel(record: TrustRecord) ?u8 {
        if (record.record_type != .trust) return null;
        if (record.data.len < 21) return null;
        // The owner trust byte is at offset 20 in the record data
        // (which is offset 21 from the raw record start).
        return record.data[20];
    }

    /// Extract the fingerprint from a trust record.
    ///
    /// Trust records contain a 20-byte fingerprint starting at offset 3
    /// in the record (offset 2 in the data after the type byte).
    pub fn extractFingerprint(record: TrustRecord) ?[20]u8 {
        if (record.record_type != .trust) return null;
        if (record.data.len < 22) return null;
        // Fingerprint starts at offset 2 in the data (offset 3 in the raw record).
        var fp: [20]u8 = undefined;
        @memcpy(&fp, record.data[2..22]);
        return fp;
    }
};

// =========================================================================
// GnuPG status protocol
// =========================================================================

/// GnuPG status-fd protocol keywords.
///
/// These are the machine-readable status messages emitted by GnuPG on the
/// status-fd file descriptor. See GnuPG's `doc/DETAILS` for the complete list.
pub const Keyword = enum(u16) {
    // Signature verification
    GOODSIG,
    BADSIG,
    ERRSIG,
    EXPSIG,
    EXPKEYSIG,
    REVKEYSIG,
    VALIDSIG,
    SIG_ID,
    NEWSIG,

    // Trust levels
    TRUST_ULTIMATE,
    TRUST_FULLY,
    TRUST_MARGINAL,
    TRUST_NEVER,
    TRUST_UNDEFINED,

    // Key operations
    KEY_CREATED,
    KEY_NOT_CREATED,
    KEY_CONSIDERED,

    // Passphrase handling
    NEED_PASSPHRASE,
    MISSING_PASSPHRASE,
    BAD_PASSPHRASE,
    GOOD_PASSPHRASE,
    GOT_IT,

    // Signing
    SIG_CREATED,
    BEGIN_SIGNING,

    // Encryption/Decryption
    BEGIN_ENCRYPTION,
    END_ENCRYPTION,
    BEGIN_DECRYPTION,
    END_DECRYPTION,
    DECRYPTION_OKAY,
    DECRYPTION_FAILED,
    DECRYPTION_INFO,
    ENC_TO,

    // Key not found
    NO_PUBKEY,
    NO_SECKEY,
    INV_RECP,
    INV_SGNR,

    // Import
    IMPORTED,
    IMPORT_OK,
    IMPORT_PROBLEM,
    IMPORT_RES,

    // Misc
    USERID_HINT,
    PLAINTEXT,
    PLAINTEXT_LENGTH,
    PROGRESS,
    PINENTRY_LAUNCHED,
    FILE_START,
    FILE_DONE,
    SESSION_KEY,
    NOTATION_NAME,
    NOTATION_DATA,
    NOTATION_FLAGS,

    // Unknown keyword
    _,

    /// Return the string representation of this keyword.
    pub fn toString(self: Keyword) []const u8 {
        return switch (self) {
            .GOODSIG => "GOODSIG",
            .BADSIG => "BADSIG",
            .ERRSIG => "ERRSIG",
            .EXPSIG => "EXPSIG",
            .EXPKEYSIG => "EXPKEYSIG",
            .REVKEYSIG => "REVKEYSIG",
            .VALIDSIG => "VALIDSIG",
            .SIG_ID => "SIG_ID",
            .NEWSIG => "NEWSIG",
            .TRUST_ULTIMATE => "TRUST_ULTIMATE",
            .TRUST_FULLY => "TRUST_FULLY",
            .TRUST_MARGINAL => "TRUST_MARGINAL",
            .TRUST_NEVER => "TRUST_NEVER",
            .TRUST_UNDEFINED => "TRUST_UNDEFINED",
            .KEY_CREATED => "KEY_CREATED",
            .KEY_NOT_CREATED => "KEY_NOT_CREATED",
            .KEY_CONSIDERED => "KEY_CONSIDERED",
            .NEED_PASSPHRASE => "NEED_PASSPHRASE",
            .MISSING_PASSPHRASE => "MISSING_PASSPHRASE",
            .BAD_PASSPHRASE => "BAD_PASSPHRASE",
            .GOOD_PASSPHRASE => "GOOD_PASSPHRASE",
            .GOT_IT => "GOT_IT",
            .SIG_CREATED => "SIG_CREATED",
            .BEGIN_SIGNING => "BEGIN_SIGNING",
            .BEGIN_ENCRYPTION => "BEGIN_ENCRYPTION",
            .END_ENCRYPTION => "END_ENCRYPTION",
            .BEGIN_DECRYPTION => "BEGIN_DECRYPTION",
            .END_DECRYPTION => "END_DECRYPTION",
            .DECRYPTION_OKAY => "DECRYPTION_OKAY",
            .DECRYPTION_FAILED => "DECRYPTION_FAILED",
            .DECRYPTION_INFO => "DECRYPTION_INFO",
            .ENC_TO => "ENC_TO",
            .NO_PUBKEY => "NO_PUBKEY",
            .NO_SECKEY => "NO_SECKEY",
            .INV_RECP => "INV_RECP",
            .INV_SGNR => "INV_SGNR",
            .IMPORTED => "IMPORTED",
            .IMPORT_OK => "IMPORT_OK",
            .IMPORT_PROBLEM => "IMPORT_PROBLEM",
            .IMPORT_RES => "IMPORT_RES",
            .USERID_HINT => "USERID_HINT",
            .PLAINTEXT => "PLAINTEXT",
            .PLAINTEXT_LENGTH => "PLAINTEXT_LENGTH",
            .PROGRESS => "PROGRESS",
            .PINENTRY_LAUNCHED => "PINENTRY_LAUNCHED",
            .FILE_START => "FILE_START",
            .FILE_DONE => "FILE_DONE",
            .SESSION_KEY => "SESSION_KEY",
            .NOTATION_NAME => "NOTATION_NAME",
            .NOTATION_DATA => "NOTATION_DATA",
            .NOTATION_FLAGS => "NOTATION_FLAGS",
            _ => "UNKNOWN",
        };
    }

    /// Parse a keyword from its string representation.
    pub fn fromString(s: []const u8) Keyword {
        const map = .{
            .{ "GOODSIG", Keyword.GOODSIG },
            .{ "BADSIG", Keyword.BADSIG },
            .{ "ERRSIG", Keyword.ERRSIG },
            .{ "EXPSIG", Keyword.EXPSIG },
            .{ "EXPKEYSIG", Keyword.EXPKEYSIG },
            .{ "REVKEYSIG", Keyword.REVKEYSIG },
            .{ "VALIDSIG", Keyword.VALIDSIG },
            .{ "SIG_ID", Keyword.SIG_ID },
            .{ "NEWSIG", Keyword.NEWSIG },
            .{ "TRUST_ULTIMATE", Keyword.TRUST_ULTIMATE },
            .{ "TRUST_FULLY", Keyword.TRUST_FULLY },
            .{ "TRUST_MARGINAL", Keyword.TRUST_MARGINAL },
            .{ "TRUST_NEVER", Keyword.TRUST_NEVER },
            .{ "TRUST_UNDEFINED", Keyword.TRUST_UNDEFINED },
            .{ "KEY_CREATED", Keyword.KEY_CREATED },
            .{ "KEY_NOT_CREATED", Keyword.KEY_NOT_CREATED },
            .{ "KEY_CONSIDERED", Keyword.KEY_CONSIDERED },
            .{ "NEED_PASSPHRASE", Keyword.NEED_PASSPHRASE },
            .{ "MISSING_PASSPHRASE", Keyword.MISSING_PASSPHRASE },
            .{ "BAD_PASSPHRASE", Keyword.BAD_PASSPHRASE },
            .{ "GOOD_PASSPHRASE", Keyword.GOOD_PASSPHRASE },
            .{ "GOT_IT", Keyword.GOT_IT },
            .{ "SIG_CREATED", Keyword.SIG_CREATED },
            .{ "BEGIN_SIGNING", Keyword.BEGIN_SIGNING },
            .{ "BEGIN_ENCRYPTION", Keyword.BEGIN_ENCRYPTION },
            .{ "END_ENCRYPTION", Keyword.END_ENCRYPTION },
            .{ "BEGIN_DECRYPTION", Keyword.BEGIN_DECRYPTION },
            .{ "END_DECRYPTION", Keyword.END_DECRYPTION },
            .{ "DECRYPTION_OKAY", Keyword.DECRYPTION_OKAY },
            .{ "DECRYPTION_FAILED", Keyword.DECRYPTION_FAILED },
            .{ "DECRYPTION_INFO", Keyword.DECRYPTION_INFO },
            .{ "ENC_TO", Keyword.ENC_TO },
            .{ "NO_PUBKEY", Keyword.NO_PUBKEY },
            .{ "NO_SECKEY", Keyword.NO_SECKEY },
            .{ "INV_RECP", Keyword.INV_RECP },
            .{ "INV_SGNR", Keyword.INV_SGNR },
            .{ "IMPORTED", Keyword.IMPORTED },
            .{ "IMPORT_OK", Keyword.IMPORT_OK },
            .{ "IMPORT_PROBLEM", Keyword.IMPORT_PROBLEM },
            .{ "IMPORT_RES", Keyword.IMPORT_RES },
            .{ "USERID_HINT", Keyword.USERID_HINT },
            .{ "PLAINTEXT", Keyword.PLAINTEXT },
            .{ "PLAINTEXT_LENGTH", Keyword.PLAINTEXT_LENGTH },
            .{ "PROGRESS", Keyword.PROGRESS },
            .{ "PINENTRY_LAUNCHED", Keyword.PINENTRY_LAUNCHED },
            .{ "FILE_START", Keyword.FILE_START },
            .{ "FILE_DONE", Keyword.FILE_DONE },
            .{ "SESSION_KEY", Keyword.SESSION_KEY },
            .{ "NOTATION_NAME", Keyword.NOTATION_NAME },
            .{ "NOTATION_DATA", Keyword.NOTATION_DATA },
            .{ "NOTATION_FLAGS", Keyword.NOTATION_FLAGS },
        };

        inline for (map) |entry| {
            if (mem.eql(u8, s, entry[0])) return entry[1];
        }
        return @enumFromInt(@as(u16, 65535));
    }
};

/// A parsed GnuPG status-fd protocol message.
///
/// Status messages have the format:
///   `[GNUPG:] <KEYWORD> [<ARGS>]`
pub const StatusMessage = struct {
    /// The status keyword.
    keyword: Keyword,
    /// Arguments following the keyword (may be empty).
    args: []const u8,

    /// The standard prefix for status-fd lines.
    const PREFIX = "[GNUPG:] ";

    /// Parse a status message from a line of text.
    ///
    /// Expects the format: `[GNUPG:] KEYWORD [args...]`
    pub fn parse(allocator: Allocator, line: []const u8) !StatusMessage {
        const trimmed = mem.trim(u8, line, " \t\r\n");

        // Check for the [GNUPG:] prefix.
        if (!mem.startsWith(u8, trimmed, PREFIX)) {
            return error.InvalidStatusLine;
        }

        const after_prefix = trimmed[PREFIX.len..];

        // Split into keyword and optional arguments.
        if (mem.indexOfScalar(u8, after_prefix, ' ')) |space_idx| {
            const keyword_str = after_prefix[0..space_idx];
            const args_str = after_prefix[space_idx + 1 ..];
            const args_copy = try allocator.dupe(u8, args_str);
            return StatusMessage{
                .keyword = Keyword.fromString(keyword_str),
                .args = args_copy,
            };
        } else {
            // Keyword only, no arguments.
            return StatusMessage{
                .keyword = Keyword.fromString(after_prefix),
                .args = try allocator.dupe(u8, ""),
            };
        }
    }

    /// Format this status message as a GnuPG status-fd line.
    pub fn format(self: StatusMessage, allocator: Allocator) ![]u8 {
        const kw = self.keyword.toString();
        if (self.args.len > 0) {
            return std.fmt.allocPrint(allocator, "{s}{s} {s}", .{ PREFIX, kw, self.args });
        } else {
            return std.fmt.allocPrint(allocator, "{s}{s}", .{ PREFIX, kw });
        }
    }

    /// Free the args string if it was allocated.
    pub fn deinit(self: StatusMessage, allocator: Allocator) void {
        allocator.free(self.args);
    }
};

// =========================================================================
// Status generation for zpgp operations
// =========================================================================

/// Types of operations for which we can generate GnuPG-compatible status output.
pub const OperationType = enum {
    sign,
    verify,
    encrypt,
    decrypt,
    import_key,
    generate_key,
};

/// Details for each operation type.
pub const OperationDetails = union(enum) {
    verify: VerifyDetails,
    decrypt: DecryptDetails,
    sign: SignDetails,
    import_key: ImportDetails,
    generate_key: GenerateKeyDetails,
    encrypt: EncryptDetails,
};

pub const VerifyDetails = struct {
    valid: bool,
    key_id: [8]u8,
    user_id: ?[]const u8,
    trust: u8,
    fingerprint: ?[20]u8,
    sig_creation_time: ?u32,
    sig_expiration_time: ?u32,
    hash_algo: ?HashAlgorithm,
    pub_algo: ?PublicKeyAlgorithm,
};

pub const DecryptDetails = struct {
    success: bool,
    key_id: ?[8]u8,
    sym_algo: ?SymmetricAlgorithm,
    is_session_key: bool,
};

pub const SignDetails = struct {
    key_id: [8]u8,
    hash_algo: HashAlgorithm,
    pub_algo: ?PublicKeyAlgorithm,
    sig_class: ?u8,
    timestamp: ?u32,
    fingerprint: ?[20]u8,
};

pub const ImportDetails = struct {
    imported: u32,
    unchanged: u32,
    no_user_id: u32,
    new_user_ids: u32,
    new_subkeys: u32,
    new_signatures: u32,
    new_revocations: u32,
    secret_read: u32,
    secret_imported: u32,
    secret_unchanged: u32,
    not_imported: u32,
    fingerprint: ?[20]u8,
};

pub const GenerateKeyDetails = struct {
    fingerprint: [20]u8,
    algorithm: []const u8,
    key_type: []const u8,
};

pub const EncryptDetails = struct {
    recipients: []const [8]u8,
    sym_algo: ?SymmetricAlgorithm,
    uses_aead: bool,
};

/// Generate GnuPG-compatible status messages for an operation.
///
/// Returns a list of status messages that a GnuPG frontend would expect.
/// Caller must `deinit()` each message and the list itself.
pub fn generateStatus(
    allocator: Allocator,
    operation: OperationType,
    details: OperationDetails,
) !std.ArrayList(StatusMessage) {
    var messages: std.ArrayList(StatusMessage) = .empty;
    errdefer {
        for (messages.items) |msg| msg.deinit(allocator);
        messages.deinit(allocator);
    }

    switch (operation) {
        .verify => {
            const v = details.verify;
            try messages.append(allocator, StatusMessage{
                .keyword = .NEWSIG,
                .args = try allocator.dupe(u8, ""),
            });

            const key_id_hex = try formatHex(allocator, &v.key_id);
            defer allocator.free(key_id_hex);

            if (v.valid) {
                const user_str = v.user_id orelse "unknown";
                const args = try std.fmt.allocPrint(allocator, "{s} {s}", .{ key_id_hex, user_str });
                try messages.append(allocator, StatusMessage{
                    .keyword = .GOODSIG,
                    .args = args,
                });

                // Add VALIDSIG if we have a fingerprint.
                if (v.fingerprint) |fp| {
                    const fp_hex = try formatHex(allocator, &fp);
                    const validsig_args = try std.fmt.allocPrint(
                        allocator,
                        "{s} {d} {d} 00 {d} {d}",
                        .{
                            fp_hex,
                            v.sig_creation_time orelse 0,
                            v.sig_expiration_time orelse 0,
                            @intFromEnum(v.hash_algo orelse .sha256),
                            @intFromEnum(v.pub_algo orelse .rsa_encrypt_sign),
                        },
                    );
                    allocator.free(fp_hex);
                    try messages.append(allocator, StatusMessage{
                        .keyword = .VALIDSIG,
                        .args = validsig_args,
                    });
                }

                // Add trust level.
                const trust_kw: Keyword = switch (v.trust) {
                    4 => .TRUST_ULTIMATE,
                    3 => .TRUST_FULLY,
                    2 => .TRUST_MARGINAL,
                    1 => .TRUST_NEVER,
                    else => .TRUST_UNDEFINED,
                };
                try messages.append(allocator, StatusMessage{
                    .keyword = trust_kw,
                    .args = try allocator.dupe(u8, "0 pgp"),
                });
            } else {
                const user_str = v.user_id orelse "unknown";
                const args = try std.fmt.allocPrint(allocator, "{s} {s}", .{ key_id_hex, user_str });
                try messages.append(allocator, StatusMessage{
                    .keyword = .BADSIG,
                    .args = args,
                });
            }
        },
        .decrypt => {
            const d = details.decrypt;
            try messages.append(allocator, StatusMessage{
                .keyword = .BEGIN_DECRYPTION,
                .args = try allocator.dupe(u8, ""),
            });

            if (d.key_id) |kid| {
                const kid_hex = try formatHex(allocator, &kid);
                const enc_to_args = try std.fmt.allocPrint(
                    allocator,
                    "{s} {d} 0",
                    .{ kid_hex, @intFromEnum(d.sym_algo orelse .aes256) },
                );
                allocator.free(kid_hex);
                try messages.append(allocator, StatusMessage{
                    .keyword = .ENC_TO,
                    .args = enc_to_args,
                });
            }

            if (d.success) {
                try messages.append(allocator, StatusMessage{
                    .keyword = .DECRYPTION_OKAY,
                    .args = try allocator.dupe(u8, ""),
                });
            } else {
                try messages.append(allocator, StatusMessage{
                    .keyword = .DECRYPTION_FAILED,
                    .args = try allocator.dupe(u8, ""),
                });
            }

            try messages.append(allocator, StatusMessage{
                .keyword = .END_DECRYPTION,
                .args = try allocator.dupe(u8, ""),
            });
        },
        .sign => {
            const s = details.sign;
            try messages.append(allocator, StatusMessage{
                .keyword = .BEGIN_SIGNING,
                .args = try std.fmt.allocPrint(allocator, "H{d}", .{@intFromEnum(s.hash_algo)}),
            });

            const kid_hex = try formatHex(allocator, &s.key_id);
            const sig_args = try std.fmt.allocPrint(
                allocator,
                "D {d} {d} {s} {d} --",
                .{
                    @intFromEnum(s.pub_algo orelse .rsa_encrypt_sign),
                    @intFromEnum(s.hash_algo),
                    kid_hex,
                    s.timestamp orelse 0,
                },
            );
            allocator.free(kid_hex);
            try messages.append(allocator, StatusMessage{
                .keyword = .SIG_CREATED,
                .args = sig_args,
            });
        },
        .encrypt => {
            const e = details.encrypt;
            for (e.recipients) |recipient| {
                const kid_hex = try formatHex(allocator, &recipient);
                const enc_args = try std.fmt.allocPrint(
                    allocator,
                    "{s} {d} 0",
                    .{ kid_hex, @intFromEnum(e.sym_algo orelse .aes256) },
                );
                allocator.free(kid_hex);
                try messages.append(allocator, StatusMessage{
                    .keyword = .ENC_TO,
                    .args = enc_args,
                });
            }

            try messages.append(allocator, StatusMessage{
                .keyword = .BEGIN_ENCRYPTION,
                .args = try allocator.dupe(u8, ""),
            });

            try messages.append(allocator, StatusMessage{
                .keyword = .END_ENCRYPTION,
                .args = try allocator.dupe(u8, ""),
            });
        },
        .import_key => {
            const i = details.import_key;
            if (i.fingerprint) |fp| {
                const fp_hex = try formatHex(allocator, &fp);
                const import_ok_args = try std.fmt.allocPrint(allocator, "1 {s}", .{fp_hex});
                allocator.free(fp_hex);
                try messages.append(allocator, StatusMessage{
                    .keyword = .IMPORT_OK,
                    .args = import_ok_args,
                });
            }

            // IMPORT_RES summary
            const res_args = try std.fmt.allocPrint(
                allocator,
                "{d} {d} {d} {d} {d} {d} {d} {d} {d} {d} {d} 0 0",
                .{
                    i.imported + i.unchanged,
                    i.no_user_id,
                    i.imported,
                    @as(u32, 0), // imported_rsa
                    i.unchanged,
                    i.new_user_ids,
                    i.new_subkeys,
                    i.new_signatures,
                    i.new_revocations,
                    i.secret_read,
                    i.secret_imported,
                },
            );
            try messages.append(allocator, StatusMessage{
                .keyword = .IMPORT_RES,
                .args = res_args,
            });
        },
        .generate_key => {
            const g = details.generate_key;
            const fp_hex = try formatHex(allocator, &g.fingerprint);
            const key_args = try std.fmt.allocPrint(
                allocator,
                "{s} {s} {s}",
                .{ g.key_type, fp_hex, g.algorithm },
            );
            allocator.free(fp_hex);
            try messages.append(allocator, StatusMessage{
                .keyword = .KEY_CREATED,
                .args = key_args,
            });
        },
    }

    return messages;
}

// =========================================================================
// Status output formatting
// =========================================================================

/// Format a list of status messages as a multi-line string.
///
/// Each line is in the format: `[GNUPG:] KEYWORD args...`
pub fn formatStatusOutput(allocator: Allocator, messages: []const StatusMessage) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    for (messages) |msg| {
        try w.print("{s}{s}", .{ StatusMessage.PREFIX, msg.keyword.toString() });
        if (msg.args.len > 0) {
            try w.print(" {s}", .{msg.args});
        }
        try w.writeByte('\n');
    }

    return buf.toOwnedSlice(allocator);
}

/// Parse multiple status lines from a multi-line string.
pub fn parseStatusOutput(allocator: Allocator, output: []const u8) !std.ArrayList(StatusMessage) {
    var messages: std.ArrayList(StatusMessage) = .empty;
    errdefer {
        for (messages.items) |msg| msg.deinit(allocator);
        messages.deinit(allocator);
    }

    var iter = mem.splitScalar(u8, output, '\n');
    while (iter.next()) |line| {
        const trimmed = mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        if (!mem.startsWith(u8, trimmed, StatusMessage.PREFIX)) continue;

        const msg = StatusMessage.parse(allocator, trimmed) catch continue;
        try messages.append(allocator, msg);
    }

    return messages;
}

// =========================================================================
// GnuPG version detection
// =========================================================================

/// Detected GnuPG version information.
pub const GnupgVersion = struct {
    major: u16,
    minor: u16,
    patch: u16,
    version_string: []const u8,

    /// Check if this version is at least the specified version.
    pub fn isAtLeast(self: GnupgVersion, major: u16, minor: u16, patch: u16) bool {
        if (self.major > major) return true;
        if (self.major < major) return false;
        if (self.minor > minor) return true;
        if (self.minor < minor) return false;
        return self.patch >= patch;
    }

    /// Check if this version supports the Keybox format (>= 2.1).
    pub fn supportsKeybox(self: GnupgVersion) bool {
        return self.isAtLeast(2, 1, 0);
    }

    /// Check if this version supports AEAD (>= 2.3).
    pub fn supportsAead(self: GnupgVersion) bool {
        return self.isAtLeast(2, 3, 0);
    }

    /// Check if this version supports v5/v6 keys (>= 2.4).
    pub fn supportsV6Keys(self: GnupgVersion) bool {
        return self.isAtLeast(2, 4, 0);
    }
};

/// Parse a GnuPG version string (e.g., "2.4.3").
pub fn parseGnupgVersion(allocator: Allocator, version_str: []const u8) !GnupgVersion {
    var parts: [3]u16 = .{ 0, 0, 0 };
    var idx: usize = 0;

    var iter = mem.splitScalar(u8, version_str, '.');
    while (iter.next()) |part| {
        if (idx >= 3) break;
        const trimmed = mem.trim(u8, part, " \t\r\n");
        parts[idx] = std.fmt.parseInt(u16, trimmed, 10) catch 0;
        idx += 1;
    }

    return GnupgVersion{
        .major = parts[0],
        .minor = parts[1],
        .patch = parts[2],
        .version_string = try allocator.dupe(u8, version_str),
    };
}

// =========================================================================
// Helpers
// =========================================================================

/// Format a byte slice as uppercase hexadecimal.
fn formatHex(allocator: Allocator, bytes: []const u8) ![]u8 {
    const hex_chars = "0123456789ABCDEF";
    const result = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0F];
    }
    return result;
}

// =========================================================================
// Tests
// =========================================================================

test "gnupg: GnupgHome path construction" {
    const allocator = std.testing.allocator;

    const home = GnupgHome{ .path = "/home/user/.gnupg" };

    const pubring = try home.pubringPath(allocator);
    defer allocator.free(pubring);
    try std.testing.expectEqualStrings("/home/user/.gnupg/pubring.kbx", pubring);

    const secring = try home.secringPath(allocator);
    defer allocator.free(secring);
    try std.testing.expectEqualStrings("/home/user/.gnupg/secring.gpg", secring);

    const trustdb = try home.trustdbPath(allocator);
    defer allocator.free(trustdb);
    try std.testing.expectEqualStrings("/home/user/.gnupg/trustdb.gpg", trustdb);

    const config = try home.configPath(allocator);
    defer allocator.free(config);
    try std.testing.expectEqualStrings("/home/user/.gnupg/gpg.conf", config);

    const agent = try home.agentConfigPath(allocator);
    defer allocator.free(agent);
    try std.testing.expectEqualStrings("/home/user/.gnupg/gpg-agent.conf", agent);

    const privkeys = try home.privateKeysDir(allocator);
    defer allocator.free(privkeys);
    try std.testing.expectEqualStrings("/home/user/.gnupg/private-keys-v1.d", privkeys);
}

test "gnupg: StatusMessage parse and format round-trip" {
    const allocator = std.testing.allocator;

    const line = "[GNUPG:] GOODSIG DEADBEEF01234567 Test User <test@example.com>";
    const msg = try StatusMessage.parse(allocator, line);
    defer msg.deinit(allocator);

    try std.testing.expect(msg.keyword == .GOODSIG);
    try std.testing.expectEqualStrings("DEADBEEF01234567 Test User <test@example.com>", msg.args);

    const formatted = try msg.format(allocator);
    defer allocator.free(formatted);
    try std.testing.expectEqualStrings(line, formatted);
}

test "gnupg: StatusMessage parse keyword only" {
    const allocator = std.testing.allocator;

    const line = "[GNUPG:] DECRYPTION_OKAY";
    const msg = try StatusMessage.parse(allocator, line);
    defer msg.deinit(allocator);

    try std.testing.expect(msg.keyword == .DECRYPTION_OKAY);
    try std.testing.expectEqualStrings("", msg.args);
}

test "gnupg: StatusMessage parse invalid prefix" {
    const allocator = std.testing.allocator;

    const result = StatusMessage.parse(allocator, "NOT_A_STATUS_LINE");
    try std.testing.expectError(error.InvalidStatusLine, result);
}

test "gnupg: Keyword fromString and toString round-trip" {
    const keywords = [_]Keyword{
        .GOODSIG,       .BADSIG,           .ERRSIG,        .VALIDSIG,
        .TRUST_ULTIMATE, .TRUST_FULLY,     .TRUST_MARGINAL, .TRUST_NEVER,
        .DECRYPTION_OKAY, .DECRYPTION_FAILED, .BEGIN_SIGNING, .SIG_CREATED,
        .ENC_TO,        .NO_PUBKEY,        .IMPORT_OK,      .KEY_CREATED,
    };

    for (keywords) |kw| {
        const str = kw.toString();
        const parsed = Keyword.fromString(str);
        try std.testing.expect(parsed == kw);
    }
}

test "gnupg: TrustDbReader parse minimal trust database" {
    const allocator = std.testing.allocator;

    // Construct a minimal trust database with one version record.
    var data: [40]u8 = undefined;
    @memset(&data, 0);
    data[0] = 1; // record type: version
    data[1] = 3; // version number
    // created timestamp at bytes 2..6
    data[2] = 0x60;
    data[3] = 0x00;
    data[4] = 0x00;
    data[5] = 0x00;
    // next_check at bytes 6..10
    data[6] = 0x61;
    data[7] = 0x00;
    data[8] = 0x00;
    data[9] = 0x00;
    data[10] = 3; // marginals
    data[11] = 1; // completes
    data[12] = 5; // max cert depth
    data[13] = 0; // trust model (classic)

    var db = try TrustDbReader.parseFromBytes(allocator, &data);
    defer db.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 3), db.version);
    try std.testing.expectEqual(@as(u32, 0x60000000), db.created);
    try std.testing.expectEqual(@as(u32, 0x61000000), db.next_check);
    try std.testing.expectEqual(@as(u8, 3), db.marginals);
    try std.testing.expectEqual(@as(u8, 1), db.completes);
    try std.testing.expectEqual(@as(u8, 5), db.max_cert_depth);
    try std.testing.expectEqual(@as(usize, 1), db.records.items.len);
}

test "gnupg: TrustDbReader parse multiple records" {
    const allocator = std.testing.allocator;

    // Two records: version + trust
    var data: [80]u8 = undefined;
    @memset(&data, 0);
    // Version record
    data[0] = 1;
    data[1] = 3;
    // Trust record at offset 40
    data[40] = 12; // record type: trust

    var db = try TrustDbReader.parseFromBytes(allocator, &data);
    defer db.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), db.records.items.len);
    try std.testing.expect(db.records.items[0].record_type == .version);
    try std.testing.expect(db.records.items[1].record_type == .trust);
    try std.testing.expectEqual(@as(usize, 1), db.countRecordsByType(.trust));
}

test "gnupg: parseGnupgVersion parses version string" {
    const allocator = std.testing.allocator;

    const v = try parseGnupgVersion(allocator, "2.4.3");
    defer allocator.free(v.version_string);

    try std.testing.expectEqual(@as(u16, 2), v.major);
    try std.testing.expectEqual(@as(u16, 4), v.minor);
    try std.testing.expectEqual(@as(u16, 3), v.patch);
    try std.testing.expect(v.isAtLeast(2, 4, 0));
    try std.testing.expect(v.isAtLeast(2, 4, 3));
    try std.testing.expect(!v.isAtLeast(2, 4, 4));
    try std.testing.expect(!v.isAtLeast(2, 5, 0));
    try std.testing.expect(!v.isAtLeast(3, 0, 0));
    try std.testing.expect(v.supportsKeybox());
    try std.testing.expect(v.supportsAead());
    try std.testing.expect(v.supportsV6Keys());
}

test "gnupg: parseGnupgVersion older version" {
    const allocator = std.testing.allocator;

    const v = try parseGnupgVersion(allocator, "2.0.30");
    defer allocator.free(v.version_string);

    try std.testing.expect(!v.supportsKeybox());
    try std.testing.expect(!v.supportsAead());
    try std.testing.expect(!v.supportsV6Keys());
}

test "gnupg: formatHex produces correct output" {
    const allocator = std.testing.allocator;

    const input = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const hex = try formatHex(allocator, &input);
    defer allocator.free(hex);
    try std.testing.expectEqualStrings("DEADBEEF", hex);
}

test "gnupg: formatStatusOutput" {
    const allocator = std.testing.allocator;

    const args1 = try allocator.dupe(u8, "data1");
    defer allocator.free(args1);
    const args2 = try allocator.dupe(u8, "");
    defer allocator.free(args2);

    const messages = [_]StatusMessage{
        .{ .keyword = .GOODSIG, .args = args1 },
        .{ .keyword = .TRUST_ULTIMATE, .args = args2 },
    };

    const output = try formatStatusOutput(allocator, &messages);
    defer allocator.free(output);

    try std.testing.expect(mem.indexOf(u8, output, "[GNUPG:] GOODSIG data1\n") != null);
    try std.testing.expect(mem.indexOf(u8, output, "[GNUPG:] TRUST_ULTIMATE\n") != null);
}

test "gnupg: parseStatusOutput round-trip" {
    const allocator = std.testing.allocator;

    const input =
        \\[GNUPG:] NEWSIG
        \\[GNUPG:] GOODSIG ABCD1234 Test
        \\[GNUPG:] TRUST_FULLY 0 pgp
        \\
    ;

    var messages = try parseStatusOutput(allocator, input);
    defer {
        for (messages.items) |msg| msg.deinit(allocator);
        messages.deinit(allocator);
    }

    try std.testing.expectEqual(@as(usize, 3), messages.items.len);
    try std.testing.expect(messages.items[0].keyword == .NEWSIG);
    try std.testing.expect(messages.items[1].keyword == .GOODSIG);
    try std.testing.expect(messages.items[2].keyword == .TRUST_FULLY);
}

test "gnupg: RecordType name" {
    try std.testing.expectEqualStrings("Version", RecordType.version.name());
    try std.testing.expectEqualStrings("Free", RecordType.free.name());
    try std.testing.expectEqualStrings("Hash Table", RecordType.hash_table.name());
    try std.testing.expectEqualStrings("Trust", RecordType.trust.name());
    try std.testing.expectEqualStrings("Valid", RecordType.valid.name());
}

test "gnupg: generateStatus for verify operation" {
    const allocator = std.testing.allocator;

    var messages = try generateStatus(allocator, .verify, .{
        .verify = .{
            .valid = true,
            .key_id = .{ 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67 },
            .user_id = "Test User",
            .trust = 4,
            .fingerprint = null,
            .sig_creation_time = null,
            .sig_expiration_time = null,
            .hash_algo = null,
            .pub_algo = null,
        },
    });
    defer {
        for (messages.items) |msg| msg.deinit(allocator);
        messages.deinit(allocator);
    }

    // Should have: NEWSIG, GOODSIG, TRUST_ULTIMATE
    try std.testing.expect(messages.items.len >= 3);
    try std.testing.expect(messages.items[0].keyword == .NEWSIG);
    try std.testing.expect(messages.items[1].keyword == .GOODSIG);
    try std.testing.expect(messages.items[2].keyword == .TRUST_ULTIMATE);
}

test "gnupg: generateStatus for failed verify" {
    const allocator = std.testing.allocator;

    var messages = try generateStatus(allocator, .verify, .{
        .verify = .{
            .valid = false,
            .key_id = .{ 0xAB, 0xCD, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC },
            .user_id = null,
            .trust = 0,
            .fingerprint = null,
            .sig_creation_time = null,
            .sig_expiration_time = null,
            .hash_algo = null,
            .pub_algo = null,
        },
    });
    defer {
        for (messages.items) |msg| msg.deinit(allocator);
        messages.deinit(allocator);
    }

    try std.testing.expect(messages.items.len >= 2);
    try std.testing.expect(messages.items[0].keyword == .NEWSIG);
    try std.testing.expect(messages.items[1].keyword == .BADSIG);
}

test "gnupg: generateStatus for decrypt" {
    const allocator = std.testing.allocator;

    var messages = try generateStatus(allocator, .decrypt, .{
        .decrypt = .{
            .success = true,
            .key_id = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
            .sym_algo = .aes256,
            .is_session_key = false,
        },
    });
    defer {
        for (messages.items) |msg| msg.deinit(allocator);
        messages.deinit(allocator);
    }

    // Should have: BEGIN_DECRYPTION, ENC_TO, DECRYPTION_OKAY, END_DECRYPTION
    try std.testing.expect(messages.items.len >= 4);
    try std.testing.expect(messages.items[0].keyword == .BEGIN_DECRYPTION);
    try std.testing.expect(messages.items[1].keyword == .ENC_TO);
    try std.testing.expect(messages.items[2].keyword == .DECRYPTION_OKAY);
    try std.testing.expect(messages.items[3].keyword == .END_DECRYPTION);
}
