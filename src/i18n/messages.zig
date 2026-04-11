// SPDX-License-Identifier: MIT
//! Internationalization (i18n) support for zpgp error messages.
//!
//! Provides a simple, comptime-driven localization system for error messages
//! used throughout the library. Each error code maps to a human-readable
//! message in each supported locale.
//!
//! Supported locales:
//!   - `.en` — English (default)
//!   - `.ja` — Japanese
//!
//! Usage:
//! ```zig
//! const msg = getMessage(.key_not_found, .en);
//! // => "Key not found"
//!
//! const formatted = try formatError(allocator, .expired_key, .ja, .{"2024-01-15"});
//! defer allocator.free(formatted);
//! // => "鍵の有効期限が切れています: 2024-01-15"
//! ```
//!
//! Integration with DiagnosticCollector:
//! The i18n system can be used to localize diagnostic messages produced by
//! `error_report.zig`. Call `getLocalizedDiagnostic()` to translate a
//! diagnostic code to the appropriate locale.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// Enumeration of all major error types in zpgp.
///
/// These codes cover cryptographic operations, key management, packet
/// parsing, armor handling, and policy violations. Each code has a
/// corresponding message in every supported locale.
pub const ErrorCode = enum(u8) {
    // Key errors
    key_not_found = 0,
    invalid_key = 1,
    expired_key = 2,
    revoked_key = 3,
    weak_key = 4,
    key_generation_failed = 5,
    no_encryption_key = 6,
    no_signing_key = 7,
    key_import_failed = 8,
    key_export_failed = 9,

    // Signature errors
    invalid_signature = 10,
    signature_expired = 11,
    signature_creation_failed = 12,
    unknown_signer = 13,

    // Encryption/decryption errors
    decryption_failed = 14,
    encryption_failed = 15,
    session_key_error = 16,
    passphrase_required = 17,
    wrong_passphrase = 18,

    // Algorithm errors
    unsupported_algorithm = 19,
    deprecated_algorithm = 20,
    algorithm_policy_violation = 21,

    // Data integrity errors
    integrity_check_failed = 22,
    crc_mismatch = 23,
    block_crc_mismatch = 24,
    stream_crc_mismatch = 25,

    // Packet errors
    malformed_packet = 26,
    unsupported_packet_version = 27,
    missing_packet = 28,
    invalid_packet_length = 29,

    // Armor errors
    invalid_armor = 30,
    armor_crc_failed = 31,
    missing_armor_header = 32,

    // Compression errors
    compression_failed = 33,
    decompression_failed = 34,
    invalid_compressed_data = 35,

    // S2K errors
    invalid_s2k = 36,
    weak_s2k_parameters = 37,

    // Trust and policy errors
    untrusted_key = 38,
    policy_violation = 39,

    // Miscellaneous
    out_of_memory = 40,
    internal_error = 41,
    not_implemented = 42,
    data_too_large = 43,
    invalid_argument = 44,
    operation_cancelled = 45,
    timeout = 46,
    io_error = 47,

    /// Get the machine-readable diagnostic code string (e.g., "ZPGP-E003").
    pub fn diagnosticCode(self: ErrorCode) []const u8 {
        return switch (self) {
            .key_not_found => "ZPGP-E013",
            .invalid_key => "ZPGP-E006",
            .expired_key => "ZPGP-W002",
            .revoked_key => "ZPGP-W003",
            .weak_key => "ZPGP-W005",
            .key_generation_failed => "ZPGP-E013",
            .no_encryption_key => "ZPGP-E015",
            .no_signing_key => "ZPGP-E016",
            .key_import_failed => "ZPGP-E017",
            .key_export_failed => "ZPGP-E017",
            .invalid_signature => "ZPGP-E002",
            .signature_expired => "ZPGP-W002",
            .signature_creation_failed => "ZPGP-E002",
            .unknown_signer => "ZPGP-E002",
            .decryption_failed => "ZPGP-E003",
            .encryption_failed => "ZPGP-E005",
            .session_key_error => "ZPGP-E012",
            .passphrase_required => "ZPGP-E012",
            .wrong_passphrase => "ZPGP-E003",
            .unsupported_algorithm => "ZPGP-E001",
            .deprecated_algorithm => "ZPGP-W001",
            .algorithm_policy_violation => "ZPGP-W001",
            .integrity_check_failed => "ZPGP-E004",
            .crc_mismatch => "ZPGP-E010",
            .block_crc_mismatch => "ZPGP-E004",
            .stream_crc_mismatch => "ZPGP-E004",
            .malformed_packet => "ZPGP-E005",
            .unsupported_packet_version => "ZPGP-E008",
            .missing_packet => "ZPGP-E007",
            .invalid_packet_length => "ZPGP-E005",
            .invalid_armor => "ZPGP-E009",
            .armor_crc_failed => "ZPGP-E010",
            .missing_armor_header => "ZPGP-E009",
            .compression_failed => "ZPGP-E005",
            .decompression_failed => "ZPGP-E005",
            .invalid_compressed_data => "ZPGP-E005",
            .invalid_s2k => "ZPGP-E011",
            .weak_s2k_parameters => "ZPGP-W012",
            .untrusted_key => "ZPGP-W003",
            .policy_violation => "ZPGP-W001",
            .out_of_memory => "ZPGP-E014",
            .internal_error => "ZPGP-E014",
            .not_implemented => "ZPGP-E001",
            .data_too_large => "ZPGP-E005",
            .invalid_argument => "ZPGP-E014",
            .operation_cancelled => "ZPGP-E014",
            .timeout => "ZPGP-E014",
            .io_error => "ZPGP-E014",
        };
    }
};

// ---------------------------------------------------------------------------
// Locale
// ---------------------------------------------------------------------------

/// Supported locales.
pub const Locale = enum {
    /// English (default)
    en,
    /// Japanese
    ja,

    /// Get the display name of the locale.
    pub fn displayName(self: Locale) []const u8 {
        return switch (self) {
            .en => "English",
            .ja => "日本語",
        };
    }

    /// Get the ISO 639-1 language code.
    pub fn code(self: Locale) []const u8 {
        return switch (self) {
            .en => "en",
            .ja => "ja",
        };
    }

    /// Parse a locale from a string. Returns `.en` as fallback.
    pub fn fromString(s: []const u8) Locale {
        if (s.len >= 2) {
            if (s[0] == 'j' and s[1] == 'a') return .ja;
        }
        return .en;
    }
};

// ---------------------------------------------------------------------------
// English message table
// ---------------------------------------------------------------------------

/// English message strings, indexed by ErrorCode ordinal.
const en_messages = [_][]const u8{
    // Key errors
    "Key not found",
    "Invalid key material",
    "Key has expired",
    "Key has been revoked",
    "Key is too weak for current security policy",
    "Key generation failed",
    "No suitable encryption subkey found",
    "No suitable signing subkey found",
    "Key import failed",
    "Key export failed",

    // Signature errors
    "Signature verification failed",
    "Signature has expired",
    "Signature creation failed",
    "Signer key is unknown or untrusted",

    // Encryption/decryption errors
    "Decryption failed",
    "Encryption failed",
    "Session key error",
    "Passphrase is required to unlock this key",
    "Wrong passphrase",

    // Algorithm errors
    "Unsupported algorithm",
    "Algorithm is deprecated and should not be used",
    "Algorithm violates security policy",

    // Data integrity errors
    "Data integrity check failed",
    "CRC checksum mismatch",
    "Block CRC mismatch in compressed data",
    "Stream CRC mismatch in compressed data",

    // Packet errors
    "Malformed packet",
    "Unsupported packet version",
    "Required packet is missing",
    "Invalid packet length",

    // Armor errors
    "Invalid ASCII armor encoding",
    "Armor CRC-24 checksum failed",
    "Missing armor header",

    // Compression errors
    "Compression failed",
    "Decompression failed",
    "Invalid compressed data",

    // S2K errors
    "Invalid string-to-key parameters",
    "String-to-key parameters are below recommended strength",

    // Trust and policy
    "Key is not trusted",
    "Operation violates security policy",

    // Miscellaneous
    "Out of memory",
    "Internal error",
    "Feature not implemented",
    "Data exceeds maximum allowed size",
    "Invalid argument",
    "Operation was cancelled",
    "Operation timed out",
    "I/O error",
};

// ---------------------------------------------------------------------------
// Japanese message table
// ---------------------------------------------------------------------------

/// Japanese message strings, indexed by ErrorCode ordinal.
const ja_messages = [_][]const u8{
    // Key errors
    "鍵が見つかりません",
    "鍵データが不正です",
    "鍵の有効期限が切れています",
    "鍵は失効しています",
    "鍵がセキュリティポリシーに対して弱すぎます",
    "鍵の生成に失敗しました",
    "適切な暗号化用サブ鍵が見つかりません",
    "適切な署名用サブ鍵が見つかりません",
    "鍵のインポートに失敗しました",
    "鍵のエクスポートに失敗しました",

    // Signature errors
    "署名の検証に失敗しました",
    "署名の有効期限が切れています",
    "署名の作成に失敗しました",
    "署名者の鍵が不明または信頼されていません",

    // Encryption/decryption errors
    "復号に失敗しました",
    "暗号化に失敗しました",
    "セッション鍵エラー",
    "この鍵のロック解除にはパスフレーズが必要です",
    "パスフレーズが間違っています",

    // Algorithm errors
    "サポートされていないアルゴリズムです",
    "このアルゴリズムは非推奨です",
    "アルゴリズムがセキュリティポリシーに違反しています",

    // Data integrity errors
    "データの整合性チェックに失敗しました",
    "CRCチェックサムが一致しません",
    "圧縮データのブロックCRCが一致しません",
    "圧縮データのストリームCRCが一致しません",

    // Packet errors
    "不正なパケットです",
    "サポートされていないパケットバージョンです",
    "必要なパケットが見つかりません",
    "パケット長が不正です",

    // Armor errors
    "不正なASCIIアーマーエンコーディングです",
    "アーマーCRC-24チェックサムに失敗しました",
    "アーマーヘッダーがありません",

    // Compression errors
    "圧縮に失敗しました",
    "解凍に失敗しました",
    "圧縮データが不正です",

    // S2K errors
    "S2Kパラメータが不正です",
    "S2Kパラメータが推奨強度を下回っています",

    // Trust and policy
    "鍵が信頼されていません",
    "操作がセキュリティポリシーに違反しています",

    // Miscellaneous
    "メモリ不足です",
    "内部エラー",
    "機能が実装されていません",
    "データが最大許容サイズを超えています",
    "引数が不正です",
    "操作がキャンセルされました",
    "操作がタイムアウトしました",
    "入出力エラー",
};

// Compile-time assertion that both tables have the same number of entries
comptime {
    if (en_messages.len != ja_messages.len) {
        @compileError("English and Japanese message tables must have the same number of entries");
    }
    const num_codes = @typeInfo(ErrorCode).@"enum".fields.len;
    if (en_messages.len != num_codes) {
        @compileError("Message tables must have entries for every ErrorCode");
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Get the localized message for an error code.
///
/// This is a pure function that returns a comptime-known string slice.
/// No allocation is needed.
pub fn getMessage(error_code: ErrorCode, locale: Locale) []const u8 {
    const idx = @intFromEnum(error_code);
    return switch (locale) {
        .en => en_messages[idx],
        .ja => ja_messages[idx],
    };
}

/// Get the English message for an error code (convenience function).
pub fn getMessageEn(error_code: ErrorCode) []const u8 {
    return getMessage(error_code, .en);
}

/// Get the Japanese message for an error code (convenience function).
pub fn getMessageJa(error_code: ErrorCode) []const u8 {
    return getMessage(error_code, .ja);
}

/// Format an error message with optional context parameter.
///
/// Produces a string of the form: "message: context"
/// or just "message" if context is null.
///
/// The caller owns the returned slice and must free it.
pub fn formatError(
    allocator: Allocator,
    error_code: ErrorCode,
    locale: Locale,
    context: ?[]const u8,
) ![]u8 {
    const msg = getMessage(error_code, locale);

    if (context) |ctx| {
        const total_len = msg.len + 2 + ctx.len; // ": " separator
        const buf = try allocator.alloc(u8, total_len);
        @memcpy(buf[0..msg.len], msg);
        buf[msg.len] = ':';
        buf[msg.len + 1] = ' ';
        @memcpy(buf[msg.len + 2 ..], ctx);
        return buf;
    } else {
        return try allocator.dupe(u8, msg);
    }
}

/// Format an error message with a diagnostic code prefix.
///
/// Produces: "[ZPGP-E003] message: context"
///
/// The caller owns the returned slice.
pub fn formatDiagnostic(
    allocator: Allocator,
    error_code: ErrorCode,
    locale: Locale,
    context: ?[]const u8,
) ![]u8 {
    const diag_code = error_code.diagnosticCode();
    const msg = getMessage(error_code, locale);

    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // "[CODE] "
    try output.append(allocator, '[');
    try output.appendSlice(allocator, diag_code);
    try output.appendSlice(allocator, "] ");

    // message
    try output.appendSlice(allocator, msg);

    // optional context
    if (context) |ctx| {
        try output.appendSlice(allocator, ": ");
        try output.appendSlice(allocator, ctx);
    }

    return output.toOwnedSlice(allocator);
}

/// Format an error with multiple context arguments.
///
/// Each argument is appended separated by ", ".
/// Produces: "message: arg1, arg2, arg3"
///
/// The caller owns the returned slice.
pub fn formatErrorMulti(
    allocator: Allocator,
    error_code: ErrorCode,
    locale: Locale,
    args: []const []const u8,
) ![]u8 {
    const msg = getMessage(error_code, locale);

    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    try output.appendSlice(allocator, msg);

    if (args.len > 0) {
        try output.appendSlice(allocator, ": ");
        for (args, 0..) |arg, i| {
            try output.appendSlice(allocator, arg);
            if (i + 1 < args.len) {
                try output.appendSlice(allocator, ", ");
            }
        }
    }

    return output.toOwnedSlice(allocator);
}

/// Get a localized message for a diagnostic code string (e.g., "ZPGP-E003").
///
/// This bridges the existing `error_report.codes` namespace with the i18n
/// system. Returns null if the code is not recognized.
pub fn getLocalizedDiagnostic(diag_code: []const u8, locale: Locale) ?[]const u8 {
    // Map diagnostic code -> ErrorCode
    const error_code = diagnosticToErrorCode(diag_code) orelse return null;
    return getMessage(error_code, locale);
}

/// Map a diagnostic code string to an ErrorCode.
///
/// Recognizes the standard ZPGP-Xnnn codes from error_report.zig.
fn diagnosticToErrorCode(diag_code: []const u8) ?ErrorCode {
    if (diag_code.len < 8) return null;
    if (!mem.startsWith(u8, diag_code, "ZPGP-")) return null;

    const MapEntry = struct { code: []const u8, err: ErrorCode };
    const mappings = [_]MapEntry{
        .{ .code = "ZPGP-E001", .err = .unsupported_algorithm },
        .{ .code = "ZPGP-E002", .err = .invalid_signature },
        .{ .code = "ZPGP-E003", .err = .decryption_failed },
        .{ .code = "ZPGP-E004", .err = .integrity_check_failed },
        .{ .code = "ZPGP-E005", .err = .malformed_packet },
        .{ .code = "ZPGP-E006", .err = .invalid_key },
        .{ .code = "ZPGP-E007", .err = .missing_packet },
        .{ .code = "ZPGP-E008", .err = .unsupported_packet_version },
        .{ .code = "ZPGP-E009", .err = .invalid_armor },
        .{ .code = "ZPGP-E010", .err = .crc_mismatch },
        .{ .code = "ZPGP-E011", .err = .invalid_s2k },
        .{ .code = "ZPGP-E012", .err = .session_key_error },
        .{ .code = "ZPGP-E013", .err = .key_not_found },
        .{ .code = "ZPGP-E014", .err = .internal_error },
        .{ .code = "ZPGP-E015", .err = .no_encryption_key },
        .{ .code = "ZPGP-E016", .err = .no_signing_key },
        .{ .code = "ZPGP-E017", .err = .key_import_failed },
        .{ .code = "ZPGP-E018", .err = .invalid_signature },
        .{ .code = "ZPGP-E019", .err = .integrity_check_failed },
        .{ .code = "ZPGP-E020", .err = .session_key_error },
        .{ .code = "ZPGP-W001", .err = .deprecated_algorithm },
        .{ .code = "ZPGP-W002", .err = .expired_key },
        .{ .code = "ZPGP-W003", .err = .revoked_key },
        .{ .code = "ZPGP-W004", .err = .integrity_check_failed },
        .{ .code = "ZPGP-W005", .err = .weak_key },
        .{ .code = "ZPGP-W006", .err = .deprecated_algorithm },
        .{ .code = "ZPGP-W007", .err = .deprecated_algorithm },
        .{ .code = "ZPGP-W008", .err = .invalid_signature },
        .{ .code = "ZPGP-W009", .err = .invalid_signature },
        .{ .code = "ZPGP-W010", .err = .deprecated_algorithm },
        .{ .code = "ZPGP-W011", .err = .deprecated_algorithm },
        .{ .code = "ZPGP-W012", .err = .weak_s2k_parameters },
        .{ .code = "ZPGP-W013", .err = .invalid_argument },
        .{ .code = "ZPGP-W014", .err = .malformed_packet },
        .{ .code = "ZPGP-W015", .err = .expired_key },
    };

    for (mappings) |m| {
        if (mem.eql(u8, diag_code, m.code)) {
            return m.err;
        }
    }
    return null;
}

/// Check if all error codes have non-empty messages in the given locale.
///
/// This is useful for validation in tests.
pub fn validateMessages(locale: Locale) bool {
    const fields = @typeInfo(ErrorCode).@"enum".fields;
    inline for (fields) |field| {
        const code: ErrorCode = @enumFromInt(field.value);
        const msg = getMessage(code, locale);
        if (msg.len == 0) return false;
    }
    return true;
}

/// Get the total number of error codes.
pub fn errorCodeCount() usize {
    return @typeInfo(ErrorCode).@"enum".fields.len;
}

// ---------------------------------------------------------------------------
// Integration: Locale-aware diagnostics
// ---------------------------------------------------------------------------

/// A locale-aware diagnostic context that wraps error code lookups.
///
/// This can be stored alongside a DiagnosticCollector to provide
/// locale-specific message rendering.
pub const LocaleContext = struct {
    locale: Locale,

    pub fn init(locale: Locale) LocaleContext {
        return .{ .locale = locale };
    }

    /// Get a message for the given error code in this context's locale.
    pub fn message(self: LocaleContext, error_code: ErrorCode) []const u8 {
        return getMessage(error_code, self.locale);
    }

    /// Format an error with context.
    pub fn format(
        self: LocaleContext,
        allocator: Allocator,
        error_code: ErrorCode,
        context: ?[]const u8,
    ) ![]u8 {
        return formatError(allocator, error_code, self.locale, context);
    }

    /// Translate a diagnostic code string.
    pub fn translateDiagnostic(self: LocaleContext, diag_code: []const u8) ?[]const u8 {
        return getLocalizedDiagnostic(diag_code, self.locale);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "getMessage returns non-empty for all codes in English" {
    try std.testing.expect(validateMessages(.en));
}

test "getMessage returns non-empty for all codes in Japanese" {
    try std.testing.expect(validateMessages(.ja));
}

test "getMessage specific codes" {
    try std.testing.expectEqualStrings("Key not found", getMessage(.key_not_found, .en));
    try std.testing.expectEqualStrings("鍵が見つかりません", getMessage(.key_not_found, .ja));

    try std.testing.expectEqualStrings("Signature verification failed", getMessage(.invalid_signature, .en));
    try std.testing.expectEqualStrings("署名の検証に失敗しました", getMessage(.invalid_signature, .ja));

    try std.testing.expectEqualStrings("Decryption failed", getMessage(.decryption_failed, .en));
    try std.testing.expectEqualStrings("復号に失敗しました", getMessage(.decryption_failed, .ja));
}

test "formatError with context" {
    const allocator = std.testing.allocator;

    const result = try formatError(allocator, .expired_key, .en, "KeyID: ABCD1234");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Key has expired: KeyID: ABCD1234", result);
}

test "formatError without context" {
    const allocator = std.testing.allocator;

    const result = try formatError(allocator, .out_of_memory, .ja, null);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("メモリ不足です", result);
}

test "formatDiagnostic" {
    const allocator = std.testing.allocator;

    const result = try formatDiagnostic(allocator, .decryption_failed, .en, "AES-256");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("[ZPGP-E003] Decryption failed: AES-256", result);
}

test "formatErrorMulti" {
    const allocator = std.testing.allocator;

    const args = [_][]const u8{ "RSA", "2048-bit", "SHA-1" };
    const result = try formatErrorMulti(allocator, .deprecated_algorithm, .en, &args);
    defer allocator.free(result);
    try std.testing.expectEqualStrings(
        "Algorithm is deprecated and should not be used: RSA, 2048-bit, SHA-1",
        result,
    );
}

test "getLocalizedDiagnostic mapping" {
    const msg = getLocalizedDiagnostic("ZPGP-E002", .en);
    try std.testing.expect(msg != null);
    try std.testing.expectEqualStrings("Signature verification failed", msg.?);

    const msg_ja = getLocalizedDiagnostic("ZPGP-E003", .ja);
    try std.testing.expect(msg_ja != null);
    try std.testing.expectEqualStrings("復号に失敗しました", msg_ja.?);
}

test "getLocalizedDiagnostic unknown code" {
    const msg = getLocalizedDiagnostic("ZPGP-E999", .en);
    try std.testing.expect(msg == null);

    const msg2 = getLocalizedDiagnostic("short", .en);
    try std.testing.expect(msg2 == null);
}

test "Locale parsing" {
    try std.testing.expectEqual(Locale.ja, Locale.fromString("ja"));
    try std.testing.expectEqual(Locale.ja, Locale.fromString("ja_JP"));
    try std.testing.expectEqual(Locale.en, Locale.fromString("en"));
    try std.testing.expectEqual(Locale.en, Locale.fromString("fr")); // fallback
    try std.testing.expectEqual(Locale.en, Locale.fromString("")); // fallback
}

test "ErrorCode diagnosticCode roundtrip" {
    // Verify that every ErrorCode has a valid diagnostic code
    const fields = @typeInfo(ErrorCode).@"enum".fields;
    inline for (fields) |field| {
        const code: ErrorCode = @enumFromInt(field.value);
        const diag = code.diagnosticCode();
        try std.testing.expect(diag.len > 0);
        try std.testing.expect(mem.startsWith(u8, diag, "ZPGP-"));
    }
}

test "LocaleContext usage" {
    const ctx = LocaleContext.init(.ja);
    const msg = ctx.message(.key_not_found);
    try std.testing.expectEqualStrings("鍵が見つかりません", msg);

    const allocator = std.testing.allocator;
    const formatted = try ctx.format(allocator, .expired_key, "test-key");
    defer allocator.free(formatted);
    try std.testing.expectEqualStrings("鍵の有効期限が切れています: test-key", formatted);
}

test "errorCodeCount matches enum" {
    const count = errorCodeCount();
    try std.testing.expectEqual(en_messages.len, count);
    try std.testing.expectEqual(ja_messages.len, count);
}

test "Locale display names" {
    try std.testing.expectEqualStrings("English", Locale.en.displayName());
    try std.testing.expectEqualStrings("日本語", Locale.ja.displayName());
    try std.testing.expectEqualStrings("en", Locale.en.code());
    try std.testing.expectEqualStrings("ja", Locale.ja.code());
}
