// SPDX-License-Identifier: MIT
//! Tests for diagnostic modules (error_report, operation_log).
//!
//! Exercises the diagnostic collection, formatting, error-to-diagnostic
//! conversion, operation logging, and all related helper utilities.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

const error_report = @import("diag/error_report.zig");
const DiagnosticLevel = error_report.DiagnosticLevel;
const Diagnostic = error_report.Diagnostic;
const DiagnosticCollector = error_report.DiagnosticCollector;
const DiagnosticBuilder = error_report.DiagnosticBuilder;
const SourceLocation = error_report.SourceLocation;
const codes = error_report.codes;

const operation_log = @import("diag/operation_log.zig");
const OperationLog = operation_log.OperationLog;
const LogEntry = operation_log.LogEntry;

// =========================================================================
// DiagnosticLevel
// =========================================================================

test "diag: level ordering" {
    // trace < debug < info < warning < err < fatal
    try testing.expect(@intFromEnum(DiagnosticLevel.trace) < @intFromEnum(DiagnosticLevel.debug));
    try testing.expect(@intFromEnum(DiagnosticLevel.debug) < @intFromEnum(DiagnosticLevel.info));
    try testing.expect(@intFromEnum(DiagnosticLevel.info) < @intFromEnum(DiagnosticLevel.warning));
    try testing.expect(@intFromEnum(DiagnosticLevel.warning) < @intFromEnum(DiagnosticLevel.err));
    try testing.expect(@intFromEnum(DiagnosticLevel.err) < @intFromEnum(DiagnosticLevel.fatal));
}

test "diag: level isError" {
    try testing.expect(!DiagnosticLevel.trace.isError());
    try testing.expect(!DiagnosticLevel.debug.isError());
    try testing.expect(!DiagnosticLevel.info.isError());
    try testing.expect(!DiagnosticLevel.warning.isError());
    try testing.expect(DiagnosticLevel.err.isError());
    try testing.expect(DiagnosticLevel.fatal.isError());
}

test "diag: level isAtLeast" {
    try testing.expect(DiagnosticLevel.fatal.isAtLeast(.trace));
    try testing.expect(DiagnosticLevel.err.isAtLeast(.err));
    try testing.expect(!DiagnosticLevel.debug.isAtLeast(.info));
}

test "diag: level prefix" {
    try testing.expectEqualStrings("[T]", DiagnosticLevel.trace.prefix());
    try testing.expectEqualStrings("[D]", DiagnosticLevel.debug.prefix());
    try testing.expectEqualStrings("[I]", DiagnosticLevel.info.prefix());
    try testing.expectEqualStrings("[W]", DiagnosticLevel.warning.prefix());
    try testing.expectEqualStrings("[E]", DiagnosticLevel.err.prefix());
    try testing.expectEqualStrings("[F]", DiagnosticLevel.fatal.prefix());
}

// =========================================================================
// Diagnostic formatting
// =========================================================================

test "diag: format line — minimal" {
    const allocator = testing.allocator;
    const diag = Diagnostic{
        .level = .err,
        .code = "ZPGP-E001",
        .message = "Test error",
    };

    const line = try diag.formatLine(allocator);
    defer allocator.free(line);

    try testing.expect(mem.indexOf(u8, line, "[E]") != null);
    try testing.expect(mem.indexOf(u8, line, "ZPGP-E001") != null);
    try testing.expect(mem.indexOf(u8, line, "Test error") != null);
}

test "diag: format line — with all fields" {
    const allocator = testing.allocator;
    const diag = Diagnostic{
        .level = .warning,
        .code = codes.WEAK_ALGORITHM,
        .message = "CAST5 is deprecated",
        .context = "packet #3",
        .source_location = .{ .module = "crypto.cfb", .operation = "decrypt" },
        .suggestion = "Use AES-256",
    };

    const line = try diag.formatLine(allocator);
    defer allocator.free(line);

    try testing.expect(mem.indexOf(u8, line, "[W]") != null);
    try testing.expect(mem.indexOf(u8, line, "ZPGP-W001") != null);
    try testing.expect(mem.indexOf(u8, line, "CAST5 is deprecated") != null);
    try testing.expect(mem.indexOf(u8, line, "packet #3") != null);
    try testing.expect(mem.indexOf(u8, line, "crypto.cfb::decrypt") != null);
    try testing.expect(mem.indexOf(u8, line, "Use AES-256") != null);
}

test "diag: isError and isWarning" {
    const err_diag = Diagnostic{ .level = .err, .code = "E", .message = "err" };
    const warn_diag = Diagnostic{ .level = .warning, .code = "W", .message = "warn" };
    const info_diag = Diagnostic{ .level = .info, .code = "I", .message = "info" };

    try testing.expect(err_diag.isError());
    try testing.expect(!err_diag.isWarning());
    try testing.expect(!warn_diag.isError());
    try testing.expect(warn_diag.isWarning());
    try testing.expect(!info_diag.isError());
    try testing.expect(!info_diag.isWarning());
}

// =========================================================================
// DiagnosticCollector — basic operations
// =========================================================================

test "diag: collector — empty" {
    const allocator = testing.allocator;
    var c = DiagnosticCollector.init(allocator, .trace);
    defer c.deinit();

    try testing.expect(c.count() == 0);
    try testing.expect(!c.hasErrors());
    try testing.expect(!c.hasWarnings());
    try testing.expect(c.firstError() == null);
}

test "diag: collector — filtering by min level" {
    const allocator = testing.allocator;
    var c = DiagnosticCollector.init(allocator, .err);
    defer c.deinit();

    try c.addInfo("I001", "info");
    try c.addWarning("W001", "warning");
    try testing.expect(c.count() == 0);

    try c.addError("E001", "error");
    try testing.expect(c.count() == 1);
}

test "diag: collector — count by level" {
    const allocator = testing.allocator;
    var c = DiagnosticCollector.init(allocator, .trace);
    defer c.deinit();

    try c.addInfo("I001", "a");
    try c.addInfo("I002", "b");
    try c.addWarning("W001", "c");
    try c.addWarning("W002", "d");
    try c.addWarning("W003", "e");
    try c.addError("E001", "f");

    try testing.expect(c.count() == 6);
    try testing.expect(c.countByLevel(.info) == 2);
    try testing.expect(c.countByLevel(.warning) == 3);
    try testing.expect(c.countByLevel(.err) == 1);
    try testing.expect(c.errorCount() == 1);
    try testing.expect(c.warningCount() == 3);
}

test "diag: collector — firstError" {
    const allocator = testing.allocator;
    var c = DiagnosticCollector.init(allocator, .trace);
    defer c.deinit();

    try c.addWarning("W001", "first warning");
    try c.addWarning("W002", "second warning");
    try testing.expect(c.firstError() == null);

    try c.addError("E001", "first error");
    try c.addError("E002", "second error");

    const first = c.firstError().?;
    try testing.expectEqualStrings("E001", first.code);
    try testing.expectEqualStrings("first error", first.message);
}

test "diag: collector — clear" {
    const allocator = testing.allocator;
    var c = DiagnosticCollector.init(allocator, .trace);
    defer c.deinit();

    try c.addError("E001", "err");
    try c.addWarning("W001", "warn");
    try testing.expect(c.count() == 2);

    c.clear();
    try testing.expect(c.count() == 0);
    try testing.expect(!c.hasErrors());
}

// =========================================================================
// DiagnosticCollector — advanced add methods
// =========================================================================

test "diag: collector — addErrorWithLocation" {
    const allocator = testing.allocator;
    var c = DiagnosticCollector.init(allocator, .trace);
    defer c.deinit();

    try c.addErrorWithLocation(codes.MALFORMED_PACKET, "bad header", "packet", "parse");
    try testing.expect(c.count() == 1);

    const diag = c.diagnostics.items[0];
    try testing.expect(diag.source_location != null);
    try testing.expectEqualStrings("packet", diag.source_location.?.module);
    try testing.expectEqualStrings("parse", diag.source_location.?.operation);
}

test "diag: collector — addWarningWithSuggestion" {
    const allocator = testing.allocator;
    var c = DiagnosticCollector.init(allocator, .trace);
    defer c.deinit();

    try c.addWarningWithSuggestion(codes.WEAK_ALGORITHM, "SHA-1", "Use SHA-256");
    try testing.expect(c.count() == 1);

    const diag = c.diagnostics.items[0];
    try testing.expect(diag.suggestion != null);
    try testing.expectEqualStrings("Use SHA-256", diag.suggestion.?);
}

test "diag: collector — addFull" {
    const allocator = testing.allocator;
    var c = DiagnosticCollector.init(allocator, .trace);
    defer c.deinit();

    try c.addFull(
        .err,
        codes.DECRYPTION_FAILED,
        "Cannot decrypt",
        "session key",
        "crypto.pkesk",
        "decrypt",
        "Check recipient key",
    );

    try testing.expect(c.count() == 1);
    const diag = c.diagnostics.items[0];
    try testing.expect(diag.level == .err);
    try testing.expectEqualStrings(codes.DECRYPTION_FAILED, diag.code);
    try testing.expectEqualStrings("session key", diag.context.?);
    try testing.expectEqualStrings("crypto.pkesk", diag.source_location.?.module);
    try testing.expectEqualStrings("Check recipient key", diag.suggestion.?);
}

// =========================================================================
// DiagnosticCollector — formatting
// =========================================================================

test "diag: collector — format report structure" {
    const allocator = testing.allocator;
    var c = DiagnosticCollector.init(allocator, .trace);
    defer c.deinit();

    try c.addWarning(codes.WEAK_ALGORITHM, "CAST5 used");
    try c.addError(codes.INVALID_SIGNATURE, "Bad signature");
    try c.addInfo(codes.ALGO_NEGOTIATED, "Selected AES-256");

    const report = try c.format(allocator);
    defer allocator.free(report);

    // Must contain header
    try testing.expect(mem.indexOf(u8, report, "zpgp Diagnostic Report") != null);
    // Must contain all three diagnostics
    try testing.expect(mem.indexOf(u8, report, "ZPGP-W001") != null);
    try testing.expect(mem.indexOf(u8, report, "ZPGP-E002") != null);
    try testing.expect(mem.indexOf(u8, report, "ZPGP-I001") != null);
    // Must contain summary
    try testing.expect(mem.indexOf(u8, report, "1 error(s)") != null);
    try testing.expect(mem.indexOf(u8, report, "1 warning(s)") != null);
    try testing.expect(mem.indexOf(u8, report, "1 info(s)") != null);
}

test "diag: collector — format summary" {
    const allocator = testing.allocator;
    var c = DiagnosticCollector.init(allocator, .trace);
    defer c.deinit();

    try c.addError("E", "e1");
    try c.addError("E", "e2");
    try c.addWarning("W", "w1");

    const summary = try c.formatSummary(allocator);
    defer allocator.free(summary);

    try testing.expect(mem.indexOf(u8, summary, "2 error(s)") != null);
    try testing.expect(mem.indexOf(u8, summary, "1 warning(s)") != null);
    try testing.expect(mem.indexOf(u8, summary, "3 diagnostic(s)") != null);
}

// =========================================================================
// Error-to-diagnostic conversion
// =========================================================================

test "diag: errorToDiagnostic — AuthenticationFailed" {
    const diag = error_report.errorToDiagnostic(error.AuthenticationFailed);
    try testing.expectEqualStrings(codes.INTEGRITY_FAILED, diag.code);
    try testing.expect(diag.level == .err);
    try testing.expect(diag.suggestion != null);
}

test "diag: errorToDiagnostic — InvalidSignature" {
    const diag = error_report.errorToDiagnostic(error.InvalidSignature);
    try testing.expectEqualStrings(codes.INVALID_SIGNATURE, diag.code);
}

test "diag: errorToDiagnostic — UnsupportedAlgorithm" {
    const diag = error_report.errorToDiagnostic(error.UnsupportedAlgorithm);
    try testing.expectEqualStrings(codes.UNKNOWN_ALGORITHM, diag.code);
}

test "diag: errorToDiagnostic — OutOfMemory" {
    const diag = error_report.errorToDiagnostic(error.OutOfMemory);
    try testing.expect(diag.level == .fatal);
}

test "diag: errorToDiagnostic — unknown error" {
    const diag = error_report.errorToDiagnostic(error.Unexpected);
    try testing.expect(diag.level == .err);
}

// =========================================================================
// DiagnosticBuilder
// =========================================================================

test "diag: builder — minimal" {
    const diag = DiagnosticBuilder.init(.err, "E001", "error message").build();
    try testing.expect(diag.level == .err);
    try testing.expectEqualStrings("E001", diag.code);
    try testing.expect(diag.context == null);
    try testing.expect(diag.source_location == null);
    try testing.expect(diag.suggestion == null);
}

test "diag: builder — full chain" {
    const diag = DiagnosticBuilder.init(.warning, codes.WEAK_ALGORITHM, "3DES used")
        .withContext("SEIPD v1 packet")
        .withLocation("crypto.cfb", "decrypt")
        .withSuggestion("Upgrade to AES-256")
        .build();

    try testing.expectEqualStrings(codes.WEAK_ALGORITHM, diag.code);
    try testing.expectEqualStrings("SEIPD v1 packet", diag.context.?);
    try testing.expectEqualStrings("crypto.cfb", diag.source_location.?.module);
    try testing.expectEqualStrings("decrypt", diag.source_location.?.operation);
    try testing.expectEqualStrings("Upgrade to AES-256", diag.suggestion.?);
}

test "diag: builder — addTo collector" {
    const allocator = testing.allocator;
    var c = DiagnosticCollector.init(allocator, .trace);
    defer c.deinit();

    try DiagnosticBuilder.init(.err, codes.MALFORMED_PACKET, "truncated")
        .withContext("offset 42")
        .addTo(&c);

    try testing.expect(c.count() == 1);
    try testing.expect(c.hasErrors());
}

// =========================================================================
// Diagnostic codes
// =========================================================================

test "diag: code level mapping" {
    try testing.expect(error_report.codeLevel(codes.WEAK_ALGORITHM) == .warning);
    try testing.expect(error_report.codeLevel(codes.EXPIRED_KEY) == .warning);
    try testing.expect(error_report.codeLevel(codes.UNKNOWN_ALGORITHM) == .err);
    try testing.expect(error_report.codeLevel(codes.INVALID_SIGNATURE) == .err);
    try testing.expect(error_report.codeLevel(codes.ALGO_NEGOTIATED) == .info);
    try testing.expect(error_report.codeLevel(codes.KEY_IMPORTED) == .info);
}

test "diag: standard warning codes exist" {
    try testing.expect(codes.WEAK_ALGORITHM.len > 0);
    try testing.expect(codes.EXPIRED_KEY.len > 0);
    try testing.expect(codes.REVOKED_KEY.len > 0);
    try testing.expect(codes.NO_MDC.len > 0);
    try testing.expect(codes.SHORT_KEY.len > 0);
    try testing.expect(codes.DEPRECATED_HASH.len > 0);
    try testing.expect(codes.LEGACY_KEY_FORMAT.len > 0);
    try testing.expect(codes.MISSING_BINDING_SIG.len > 0);
    try testing.expect(codes.WEAK_S2K.len > 0);
    try testing.expect(codes.EXPIRING_SOON.len > 0);
}

test "diag: standard error codes exist" {
    try testing.expect(codes.UNKNOWN_ALGORITHM.len > 0);
    try testing.expect(codes.INVALID_SIGNATURE.len > 0);
    try testing.expect(codes.DECRYPTION_FAILED.len > 0);
    try testing.expect(codes.INTEGRITY_FAILED.len > 0);
    try testing.expect(codes.MALFORMED_PACKET.len > 0);
    try testing.expect(codes.INVALID_KEY.len > 0);
    try testing.expect(codes.INVALID_ARMOR.len > 0);
    try testing.expect(codes.CRC_MISMATCH.len > 0);
    try testing.expect(codes.AEAD_AUTH_FAILED.len > 0);
    try testing.expect(codes.KDF_ERROR.len > 0);
}

// =========================================================================
// SourceLocation
// =========================================================================

test "diag: source location format" {
    const allocator = testing.allocator;
    const loc = SourceLocation{ .module = "key.generate", .operation = "createV6" };
    const formatted = try loc.format(allocator);
    defer allocator.free(formatted);
    try testing.expectEqualStrings("key.generate::createV6", formatted);
}

// =========================================================================
// OperationLog — basic operations
// =========================================================================

test "diag: oplog — empty" {
    const allocator = testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    try testing.expect(oplog.count() == 0);
    try testing.expect(oplog.lastEntry() == null);
    try testing.expect(oplog.getEntry(0) == null);
    try testing.expect(oplog.totalTimedDuration() == 0);
}

test "diag: oplog — log entries" {
    const allocator = testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    try oplog.log("step1", "first");
    try oplog.log("step2", "second");
    try oplog.log("step3", "third");

    try testing.expect(oplog.count() == 3);
    try testing.expectEqualStrings("step1", oplog.getEntry(0).?.operation);
    try testing.expectEqualStrings("step3", oplog.lastEntry().?.operation);
}

test "diag: oplog — timed entries" {
    const allocator = testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    try oplog.logTimed("fast_op", "details", 1000);
    try oplog.logTimed("slow_op", "details", 99_000);

    try testing.expect(oplog.totalTimedDuration() == 100_000);
}

test "diag: oplog — sequence numbers" {
    const allocator = testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    try oplog.log("a", "");
    try oplog.log("b", "");
    try oplog.log("c", "");

    try testing.expect(oplog.getEntry(0).?.sequence == 0);
    try testing.expect(oplog.getEntry(1).?.sequence == 1);
    try testing.expect(oplog.getEntry(2).?.sequence == 2);
}

test "diag: oplog — countOperation" {
    const allocator = testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    try oplog.log("parse", "a");
    try oplog.log("decrypt", "b");
    try oplog.log("parse", "c");
    try oplog.log("verify", "d");
    try oplog.log("parse", "e");

    try testing.expect(oplog.countOperation("parse") == 3);
    try testing.expect(oplog.countOperation("decrypt") == 1);
    try testing.expect(oplog.countOperation("verify") == 1);
    try testing.expect(oplog.countOperation("missing") == 0);
}

test "diag: oplog — clear" {
    const allocator = testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    try oplog.log("a", "");
    try oplog.log("b", "");
    oplog.clear();

    try testing.expect(oplog.count() == 0);
    try oplog.log("c", "");
    try testing.expect(oplog.getEntry(0).?.sequence == 0);
}

test "diag: oplog — reset" {
    const allocator = testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    try oplog.log("a", "");
    oplog.reset();

    try testing.expect(oplog.count() == 0);
}

// =========================================================================
// OperationLog — formatting
// =========================================================================

test "diag: oplog — format report" {
    const allocator = testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    try oplog.log("parse_header", "SEIPD v2");
    try oplog.logTimed("decrypt_session_key", "RSA-2048", 50_000_000);
    try oplog.logTimed("decrypt_data", "AES-256-OCB", 200_000_000);
    try oplog.log("verify_mdc", "SHA-256");

    const report = try oplog.format(allocator);
    defer allocator.free(report);

    try testing.expect(mem.indexOf(u8, report, "Operation Log") != null);
    try testing.expect(mem.indexOf(u8, report, "parse_header") != null);
    try testing.expect(mem.indexOf(u8, report, "decrypt_session_key") != null);
    try testing.expect(mem.indexOf(u8, report, "decrypt_data") != null);
    try testing.expect(mem.indexOf(u8, report, "Total timed") != null);
}

test "diag: oplog — format summary" {
    const allocator = testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    try oplog.log("a", "");
    try oplog.log("b", "");
    try oplog.log("c", "");

    const summary = try oplog.formatSummary(allocator);
    defer allocator.free(summary);

    try testing.expect(mem.indexOf(u8, summary, "3 operations") != null);
}

// =========================================================================
// OperationLog — helpers
// =========================================================================

test "diag: oplog — helper logPacketParse" {
    const allocator = testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    try operation_log.logPacketParse(&oplog, "SEIPD", 1024);
    try testing.expect(oplog.count() == 1);
    try testing.expectEqualStrings("parse_packet", oplog.getEntry(0).?.operation);
}

test "diag: oplog — helper logCryptoOp" {
    const allocator = testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    try operation_log.logCryptoOp(&oplog, "AES-256", "encrypt", 5000);
    try testing.expect(oplog.count() == 1);
    try testing.expectEqualStrings("crypto", oplog.getEntry(0).?.operation);
    try testing.expect(oplog.getEntry(0).?.duration_ns.? == 5000);
}

test "diag: oplog — helper logKeyOp" {
    const allocator = testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    try operation_log.logKeyOp(&oplog, "import", "0xDEADBEEF");
    try testing.expect(oplog.count() == 1);
    try testing.expectEqualStrings("import", oplog.getEntry(0).?.operation);
    try testing.expectEqualStrings("0xDEADBEEF", oplog.getEntry(0).?.details);
}

// =========================================================================
// OperationLog — section markers
// =========================================================================

test "diag: oplog — sections" {
    const allocator = testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    try oplog.section("Decryption Phase");
    try oplog.log("decrypt", "AES");
    try oplog.section("Verification Phase");
    try oplog.log("verify", "Ed25519");

    try testing.expect(oplog.count() == 4);
    try testing.expectEqualStrings("--- section ---", oplog.getEntry(0).?.operation);
    try testing.expectEqualStrings("Decryption Phase", oplog.getEntry(0).?.details);
}

// =========================================================================
// OperationLog — timer
// =========================================================================

test "diag: oplog — timer" {
    const allocator = testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    const timer = oplog.startTimer("expensive_op", "with args");
    try timer.stop();

    try testing.expect(oplog.count() == 1);
    const entry = oplog.getEntry(0).?;
    try testing.expectEqualStrings("expensive_op", entry.operation);
    try testing.expect(entry.duration_ns != null);
}

// =========================================================================
// LogEntry — formatting
// =========================================================================

test "diag: log entry — format with nanoseconds" {
    const allocator = testing.allocator;
    const entry = LogEntry{
        .timestamp_ns = 500_000,
        .operation = "test",
        .details = "detail",
        .duration_ns = 500,
        .sequence = 0,
    };

    const formatted = try entry.format(allocator);
    defer allocator.free(formatted);

    try testing.expect(mem.indexOf(u8, formatted, "500ns") != null);
}

test "diag: log entry — format with microseconds" {
    const allocator = testing.allocator;
    const entry = LogEntry{
        .timestamp_ns = 1_000_000,
        .operation = "test",
        .details = "",
        .duration_ns = 50_000,
        .sequence = 1,
    };

    const formatted = try entry.format(allocator);
    defer allocator.free(formatted);

    try testing.expect(mem.indexOf(u8, formatted, "50us") != null);
}

test "diag: log entry — format with milliseconds" {
    const allocator = testing.allocator;
    const entry = LogEntry{
        .timestamp_ns = 5_000_000_000,
        .operation = "slow_op",
        .details = "big data",
        .duration_ns = 5_000_000,
        .sequence = 99,
    };

    const formatted = try entry.format(allocator);
    defer allocator.free(formatted);

    try testing.expect(mem.indexOf(u8, formatted, "5ms") != null);
    try testing.expect(mem.indexOf(u8, formatted, "[  99]") != null);
}

test "diag: log entry — format without duration" {
    const allocator = testing.allocator;
    const entry = LogEntry{
        .timestamp_ns = 100_000,
        .operation = "quick",
        .details = "",
        .duration_ns = null,
        .sequence = 0,
    };

    const formatted = try entry.format(allocator);
    defer allocator.free(formatted);

    try testing.expect(mem.indexOf(u8, formatted, "quick") != null);
    // Should not contain duration markers
    try testing.expect(mem.indexOf(u8, formatted, "ns)") == null);
    try testing.expect(mem.indexOf(u8, formatted, "us)") == null);
    try testing.expect(mem.indexOf(u8, formatted, "ms)") == null);
}
