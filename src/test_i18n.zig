// SPDX-License-Identifier: MIT
//! Tests for the internationalization (i18n) message system.
//!
//! Validates:
//!   - All error codes have messages in both locales
//!   - No empty messages
//!   - Message formatting with parameters
//!   - Diagnostic code mapping
//!   - Locale parsing and display names

const std = @import("std");
const messages = @import("i18n/messages.zig");

// ---------------------------------------------------------------------------
// Completeness tests
// ---------------------------------------------------------------------------

test "all error codes have non-empty English messages" {
    const fields = @typeInfo(messages.ErrorCode).@"enum".fields;
    inline for (fields) |field| {
        const code: messages.ErrorCode = @enumFromInt(field.value);
        const msg = messages.getMessage(code, .en);
        try std.testing.expect(msg.len > 0);
    }
}

test "all error codes have non-empty Japanese messages" {
    const fields = @typeInfo(messages.ErrorCode).@"enum".fields;
    inline for (fields) |field| {
        const code: messages.ErrorCode = @enumFromInt(field.value);
        const msg = messages.getMessage(code, .ja);
        try std.testing.expect(msg.len > 0);
    }
}

test "English and Japanese messages are different" {
    // At least some messages should differ (they are in different languages)
    var differ_count: usize = 0;
    const fields = @typeInfo(messages.ErrorCode).@"enum".fields;
    inline for (fields) |field| {
        const code: messages.ErrorCode = @enumFromInt(field.value);
        const en = messages.getMessage(code, .en);
        const ja = messages.getMessage(code, .ja);
        if (!std.mem.eql(u8, en, ja)) differ_count += 1;
    }
    // All messages should differ since they are in different scripts
    try std.testing.expectEqual(messages.errorCodeCount(), differ_count);
}

test "validateMessages returns true for both locales" {
    try std.testing.expect(messages.validateMessages(.en));
    try std.testing.expect(messages.validateMessages(.ja));
}

test "errorCodeCount matches number of enum fields" {
    const count = messages.errorCodeCount();
    try std.testing.expect(count > 0);
    // Should be 48 (0..47 inclusive)
    try std.testing.expectEqual(@as(usize, 48), count);
}

// ---------------------------------------------------------------------------
// Specific message tests
// ---------------------------------------------------------------------------

test "key error messages" {
    try std.testing.expectEqualStrings("Key not found", messages.getMessage(.key_not_found, .en));
    try std.testing.expectEqualStrings("鍵が見つかりません", messages.getMessage(.key_not_found, .ja));

    try std.testing.expectEqualStrings("Invalid key material", messages.getMessage(.invalid_key, .en));
    try std.testing.expectEqualStrings("鍵データが不正です", messages.getMessage(.invalid_key, .ja));

    try std.testing.expectEqualStrings("Key has expired", messages.getMessage(.expired_key, .en));
    try std.testing.expectEqualStrings("鍵の有効期限が切れています", messages.getMessage(.expired_key, .ja));

    try std.testing.expectEqualStrings("Key has been revoked", messages.getMessage(.revoked_key, .en));
    try std.testing.expectEqualStrings("鍵は失効しています", messages.getMessage(.revoked_key, .ja));
}

test "signature error messages" {
    try std.testing.expectEqualStrings("Signature verification failed", messages.getMessage(.invalid_signature, .en));
    try std.testing.expectEqualStrings("署名の検証に失敗しました", messages.getMessage(.invalid_signature, .ja));
}

test "encryption/decryption error messages" {
    try std.testing.expectEqualStrings("Decryption failed", messages.getMessage(.decryption_failed, .en));
    try std.testing.expectEqualStrings("復号に失敗しました", messages.getMessage(.decryption_failed, .ja));

    try std.testing.expectEqualStrings("Encryption failed", messages.getMessage(.encryption_failed, .en));
    try std.testing.expectEqualStrings("暗号化に失敗しました", messages.getMessage(.encryption_failed, .ja));
}

test "algorithm error messages" {
    try std.testing.expectEqualStrings("Unsupported algorithm", messages.getMessage(.unsupported_algorithm, .en));
    try std.testing.expectEqualStrings("サポートされていないアルゴリズムです", messages.getMessage(.unsupported_algorithm, .ja));
}

test "integrity error messages" {
    try std.testing.expectEqualStrings("Data integrity check failed", messages.getMessage(.integrity_check_failed, .en));
    try std.testing.expectEqualStrings("データの整合性チェックに失敗しました", messages.getMessage(.integrity_check_failed, .ja));
}

test "compression error messages" {
    try std.testing.expectEqualStrings("Compression failed", messages.getMessage(.compression_failed, .en));
    try std.testing.expectEqualStrings("圧縮に失敗しました", messages.getMessage(.compression_failed, .ja));

    try std.testing.expectEqualStrings("Decompression failed", messages.getMessage(.decompression_failed, .en));
    try std.testing.expectEqualStrings("解凍に失敗しました", messages.getMessage(.decompression_failed, .ja));
}

test "miscellaneous error messages" {
    try std.testing.expectEqualStrings("Out of memory", messages.getMessage(.out_of_memory, .en));
    try std.testing.expectEqualStrings("メモリ不足です", messages.getMessage(.out_of_memory, .ja));

    try std.testing.expectEqualStrings("Internal error", messages.getMessage(.internal_error, .en));
    try std.testing.expectEqualStrings("内部エラー", messages.getMessage(.internal_error, .ja));
}

// ---------------------------------------------------------------------------
// Convenience function tests
// ---------------------------------------------------------------------------

test "getMessageEn convenience" {
    const msg = messages.getMessageEn(.key_not_found);
    try std.testing.expectEqualStrings("Key not found", msg);
}

test "getMessageJa convenience" {
    const msg = messages.getMessageJa(.key_not_found);
    try std.testing.expectEqualStrings("鍵が見つかりません", msg);
}

// ---------------------------------------------------------------------------
// Formatting tests
// ---------------------------------------------------------------------------

test "formatError with context" {
    const allocator = std.testing.allocator;

    const result = try messages.formatError(allocator, .expired_key, .en, "KeyID: 0xABCD1234");
    defer allocator.free(result);

    try std.testing.expectEqualStrings("Key has expired: KeyID: 0xABCD1234", result);
}

test "formatError Japanese with context" {
    const allocator = std.testing.allocator;

    const result = try messages.formatError(allocator, .expired_key, .ja, "KeyID: 0xABCD1234");
    defer allocator.free(result);

    try std.testing.expectEqualStrings("鍵の有効期限が切れています: KeyID: 0xABCD1234", result);
}

test "formatError without context" {
    const allocator = std.testing.allocator;

    const result = try messages.formatError(allocator, .out_of_memory, .en, null);
    defer allocator.free(result);

    try std.testing.expectEqualStrings("Out of memory", result);
}

test "formatDiagnostic with code prefix" {
    const allocator = std.testing.allocator;

    const result = try messages.formatDiagnostic(allocator, .decryption_failed, .en, "AES-256");
    defer allocator.free(result);

    try std.testing.expectEqualStrings("[ZPGP-E003] Decryption failed: AES-256", result);
}

test "formatDiagnostic without context" {
    const allocator = std.testing.allocator;

    const result = try messages.formatDiagnostic(allocator, .invalid_key, .ja, null);
    defer allocator.free(result);

    try std.testing.expectEqualStrings("[ZPGP-E006] 鍵データが不正です", result);
}

test "formatErrorMulti with multiple args" {
    const allocator = std.testing.allocator;

    const args = [_][]const u8{ "RSA-2048", "SHA-1", "packet 5" };
    const result = try messages.formatErrorMulti(allocator, .deprecated_algorithm, .en, &args);
    defer allocator.free(result);

    try std.testing.expectEqualStrings(
        "Algorithm is deprecated and should not be used: RSA-2048, SHA-1, packet 5",
        result,
    );
}

test "formatErrorMulti with no args" {
    const allocator = std.testing.allocator;

    const result = try messages.formatErrorMulti(allocator, .out_of_memory, .en, &.{});
    defer allocator.free(result);

    try std.testing.expectEqualStrings("Out of memory", result);
}

test "formatErrorMulti with single arg" {
    const allocator = std.testing.allocator;

    const args = [_][]const u8{"extra info"};
    const result = try messages.formatErrorMulti(allocator, .invalid_armor, .ja, &args);
    defer allocator.free(result);

    try std.testing.expectEqualStrings(
        "不正なASCIIアーマーエンコーディングです: extra info",
        result,
    );
}

// ---------------------------------------------------------------------------
// Diagnostic code mapping tests
// ---------------------------------------------------------------------------

test "diagnosticCode returns valid codes" {
    const fields = @typeInfo(messages.ErrorCode).@"enum".fields;
    inline for (fields) |field| {
        const code: messages.ErrorCode = @enumFromInt(field.value);
        const diag = code.diagnosticCode();
        try std.testing.expect(diag.len > 0);
        try std.testing.expect(std.mem.startsWith(u8, diag, "ZPGP-"));
    }
}

test "getLocalizedDiagnostic known codes" {
    // Standard error codes from error_report.zig
    const codes_to_test = [_][]const u8{
        "ZPGP-E001", "ZPGP-E002", "ZPGP-E003", "ZPGP-E004",
        "ZPGP-E005", "ZPGP-E006", "ZPGP-E007", "ZPGP-E008",
        "ZPGP-E009", "ZPGP-E010", "ZPGP-E011", "ZPGP-E012",
        "ZPGP-E013", "ZPGP-E014", "ZPGP-E015", "ZPGP-E016",
        "ZPGP-E017", "ZPGP-E018", "ZPGP-E019", "ZPGP-E020",
        "ZPGP-W001", "ZPGP-W002", "ZPGP-W003", "ZPGP-W004",
        "ZPGP-W005",
    };

    for (codes_to_test) |code| {
        const msg_en = messages.getLocalizedDiagnostic(code, .en);
        try std.testing.expect(msg_en != null);
        try std.testing.expect(msg_en.?.len > 0);

        const msg_ja = messages.getLocalizedDiagnostic(code, .ja);
        try std.testing.expect(msg_ja != null);
        try std.testing.expect(msg_ja.?.len > 0);
    }
}

test "getLocalizedDiagnostic unknown codes" {
    try std.testing.expect(messages.getLocalizedDiagnostic("ZPGP-E999", .en) == null);
    try std.testing.expect(messages.getLocalizedDiagnostic("INVALID", .en) == null);
    try std.testing.expect(messages.getLocalizedDiagnostic("", .en) == null);
    try std.testing.expect(messages.getLocalizedDiagnostic("ZPGP", .en) == null);
}

// ---------------------------------------------------------------------------
// Locale tests
// ---------------------------------------------------------------------------

test "Locale fromString parsing" {
    try std.testing.expectEqual(messages.Locale.ja, messages.Locale.fromString("ja"));
    try std.testing.expectEqual(messages.Locale.ja, messages.Locale.fromString("ja_JP"));
    try std.testing.expectEqual(messages.Locale.ja, messages.Locale.fromString("ja-JP"));
    try std.testing.expectEqual(messages.Locale.en, messages.Locale.fromString("en"));
    try std.testing.expectEqual(messages.Locale.en, messages.Locale.fromString("en_US"));
    try std.testing.expectEqual(messages.Locale.en, messages.Locale.fromString("de")); // fallback
    try std.testing.expectEqual(messages.Locale.en, messages.Locale.fromString("")); // fallback
    try std.testing.expectEqual(messages.Locale.en, messages.Locale.fromString("x")); // too short
}

test "Locale display names" {
    try std.testing.expectEqualStrings("English", messages.Locale.en.displayName());
    try std.testing.expectEqualStrings("日本語", messages.Locale.ja.displayName());
}

test "Locale codes" {
    try std.testing.expectEqualStrings("en", messages.Locale.en.code());
    try std.testing.expectEqualStrings("ja", messages.Locale.ja.code());
}

// ---------------------------------------------------------------------------
// LocaleContext tests
// ---------------------------------------------------------------------------

test "LocaleContext English" {
    const ctx = messages.LocaleContext.init(.en);

    const msg = ctx.message(.key_not_found);
    try std.testing.expectEqualStrings("Key not found", msg);

    const allocator = std.testing.allocator;
    const formatted = try ctx.format(allocator, .expired_key, "test");
    defer allocator.free(formatted);
    try std.testing.expectEqualStrings("Key has expired: test", formatted);
}

test "LocaleContext Japanese" {
    const ctx = messages.LocaleContext.init(.ja);

    const msg = ctx.message(.decryption_failed);
    try std.testing.expectEqualStrings("復号に失敗しました", msg);
}

test "LocaleContext translateDiagnostic" {
    const ctx = messages.LocaleContext.init(.en);

    const msg = ctx.translateDiagnostic("ZPGP-E003");
    try std.testing.expect(msg != null);
    try std.testing.expectEqualStrings("Decryption failed", msg.?);

    const unknown = ctx.translateDiagnostic("ZPGP-E999");
    try std.testing.expect(unknown == null);
}
