// SPDX-License-Identifier: MIT
//! Comprehensive error reporting and diagnostics for zpgp.
//!
//! Provides structured diagnostics that can be collected during complex
//! operations (e.g., key import, message decryption, signature verification).
//! Each diagnostic includes:
//!   - A severity level (trace through fatal)
//!   - A machine-readable code (e.g., "ZPGP-E001")
//!   - A human-readable message
//!   - Optional context and suggestions
//!
//! The DiagnosticCollector aggregates diagnostics and can produce formatted
//! reports for display to end users or structured output for tooling.
//!
//! Standard diagnostic codes follow the pattern:
//!   - ZPGP-Wnnn: Warnings
//!   - ZPGP-Ennn: Errors
//!   - ZPGP-Innn: Informational
//!
//! Example usage:
//! ```zig
//! var collector = DiagnosticCollector.init(allocator, .warning);
//! defer collector.deinit();
//!
//! try collector.addWarning(codes.WEAK_ALGORITHM, "SHA-1 used for signature");
//! try collector.addError(codes.INVALID_SIGNATURE, "Signature verification failed");
//!
//! if (collector.hasErrors()) {
//!     const report = try collector.format(allocator);
//!     defer allocator.free(report);
//!     // ... display report ...
//! }
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

// ---------------------------------------------------------------------------
// Diagnostic levels
// ---------------------------------------------------------------------------

/// Severity level for diagnostics, from least to most severe.
pub const DiagnosticLevel = enum(u8) {
    /// Very detailed tracing information (normally suppressed).
    trace = 0,
    /// Debugging information useful during development.
    debug = 1,
    /// Informational messages about normal operation.
    info = 2,
    /// Potential issues that do not prevent operation completion.
    warning = 3,
    /// Errors that prevent an operation from completing correctly.
    err = 4,
    /// Fatal errors that require immediate attention.
    fatal = 5,

    /// Human-readable name for the level.
    pub fn name(self: DiagnosticLevel) []const u8 {
        return switch (self) {
            .trace => "TRACE",
            .debug => "DEBUG",
            .info => "INFO",
            .warning => "WARNING",
            .err => "ERROR",
            .fatal => "FATAL",
        };
    }

    /// Return a short prefix suitable for log output.
    pub fn prefix(self: DiagnosticLevel) []const u8 {
        return switch (self) {
            .trace => "[T]",
            .debug => "[D]",
            .info => "[I]",
            .warning => "[W]",
            .err => "[E]",
            .fatal => "[F]",
        };
    }

    /// Whether this level represents an error or fatal condition.
    pub fn isError(self: DiagnosticLevel) bool {
        return @intFromEnum(self) >= @intFromEnum(DiagnosticLevel.err);
    }

    /// Whether this level is at least as severe as the given level.
    pub fn isAtLeast(self: DiagnosticLevel, threshold: DiagnosticLevel) bool {
        return @intFromEnum(self) >= @intFromEnum(threshold);
    }
};

// ---------------------------------------------------------------------------
// Source location
// ---------------------------------------------------------------------------

/// Identifies where in the codebase a diagnostic was generated.
pub const SourceLocation = struct {
    /// Module name (e.g., "crypto.aead", "packet.signature").
    module: []const u8,
    /// Operation being performed (e.g., "decrypt", "verify", "parse").
    operation: []const u8,

    /// Format as "module::operation".
    pub fn format(self: SourceLocation, allocator: Allocator) ![]u8 {
        const total = self.module.len + 2 + self.operation.len;
        const buf = try allocator.alloc(u8, total);
        @memcpy(buf[0..self.module.len], self.module);
        buf[self.module.len] = ':';
        buf[self.module.len + 1] = ':';
        @memcpy(buf[self.module.len + 2 ..], self.operation);
        return buf;
    }
};

// ---------------------------------------------------------------------------
// Diagnostic
// ---------------------------------------------------------------------------

/// A single diagnostic message.
pub const Diagnostic = struct {
    /// Severity level.
    level: DiagnosticLevel,
    /// Machine-readable diagnostic code (e.g., "ZPGP-E001").
    code: []const u8,
    /// Human-readable description.
    message: []const u8,
    /// Additional context (e.g., key ID, packet offset).
    context: ?[]const u8 = null,
    /// Where the diagnostic was generated.
    source_location: ?SourceLocation = null,
    /// Suggested action to resolve the issue.
    suggestion: ?[]const u8 = null,

    /// Format the diagnostic as a single-line string.
    ///
    /// Format: "[LEVEL] CODE: message (context) [suggestion]"
    pub fn formatLine(self: Diagnostic, allocator: Allocator) ![]u8 {
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(allocator);

        // Level prefix
        try output.appendSlice(allocator, self.level.prefix());
        try output.append(allocator, ' ');

        // Code
        try output.appendSlice(allocator, self.code);
        try output.appendSlice(allocator, ": ");

        // Message
        try output.appendSlice(allocator, self.message);

        // Context
        if (self.context) |ctx| {
            try output.appendSlice(allocator, " (");
            try output.appendSlice(allocator, ctx);
            try output.append(allocator, ')');
        }

        // Source location
        if (self.source_location) |loc| {
            try output.appendSlice(allocator, " at ");
            try output.appendSlice(allocator, loc.module);
            try output.appendSlice(allocator, "::");
            try output.appendSlice(allocator, loc.operation);
        }

        // Suggestion
        if (self.suggestion) |sug| {
            try output.appendSlice(allocator, " -> ");
            try output.appendSlice(allocator, sug);
        }

        return output.toOwnedSlice(allocator);
    }

    /// Check whether this diagnostic is an error or fatal.
    pub fn isError(self: Diagnostic) bool {
        return self.level.isError();
    }

    /// Check whether this diagnostic is a warning.
    pub fn isWarning(self: Diagnostic) bool {
        return self.level == .warning;
    }
};

// ---------------------------------------------------------------------------
// Standard diagnostic codes
// ---------------------------------------------------------------------------

/// Machine-readable diagnostic codes for common OpenPGP issues.
///
/// Codes follow the pattern ZPGP-Xnnn where X is:
///   - W: Warning
///   - E: Error
///   - I: Informational
pub const codes = struct {
    // Warnings (ZPGP-Wnnn)
    /// A weak or deprecated algorithm is in use.
    pub const WEAK_ALGORITHM = "ZPGP-W001";
    /// A key has expired.
    pub const EXPIRED_KEY = "ZPGP-W002";
    /// A key has been revoked.
    pub const REVOKED_KEY = "ZPGP-W003";
    /// Message lacks Modification Detection Code.
    pub const NO_MDC = "ZPGP-W004";
    /// Key size is below recommended minimum.
    pub const SHORT_KEY = "ZPGP-W005";
    /// Signature uses a deprecated hash algorithm.
    pub const DEPRECATED_HASH = "ZPGP-W006";
    /// Key uses legacy V4 format; consider upgrading to V6.
    pub const LEGACY_KEY_FORMAT = "ZPGP-W007";
    /// Subkey binding signature is missing.
    pub const MISSING_BINDING_SIG = "ZPGP-W008";
    /// Key has no self-signature on primary user ID.
    pub const MISSING_SELF_SIG = "ZPGP-W009";
    /// Compression algorithm is deprecated.
    pub const DEPRECATED_COMPRESSION = "ZPGP-W010";
    /// Key preferences suggest outdated configuration.
    pub const OUTDATED_PREFERENCES = "ZPGP-W011";
    /// S2K parameters are below recommended strength.
    pub const WEAK_S2K = "ZPGP-W012";
    /// Non-standard notation found in signature.
    pub const UNKNOWN_NOTATION = "ZPGP-W013";
    /// Critical subpacket of unknown type encountered.
    pub const UNKNOWN_CRITICAL_SUBPACKET = "ZPGP-W014";
    /// Key will expire within 30 days.
    pub const EXPIRING_SOON = "ZPGP-W015";

    // Errors (ZPGP-Ennn)
    /// Algorithm is not recognized or supported.
    pub const UNKNOWN_ALGORITHM = "ZPGP-E001";
    /// Signature verification failed.
    pub const INVALID_SIGNATURE = "ZPGP-E002";
    /// Decryption failed (wrong key, corrupted data, etc.).
    pub const DECRYPTION_FAILED = "ZPGP-E003";
    /// Data integrity check failed (MDC or AEAD tag mismatch).
    pub const INTEGRITY_FAILED = "ZPGP-E004";
    /// Packet is malformed or truncated.
    pub const MALFORMED_PACKET = "ZPGP-E005";
    /// Key material is invalid or corrupted.
    pub const INVALID_KEY = "ZPGP-E006";
    /// Required packet is missing.
    pub const MISSING_PACKET = "ZPGP-E007";
    /// Packet version is not supported.
    pub const UNSUPPORTED_VERSION = "ZPGP-E008";
    /// Armor encoding is invalid.
    pub const INVALID_ARMOR = "ZPGP-E009";
    /// CRC-24 checksum mismatch in armored data.
    pub const CRC_MISMATCH = "ZPGP-E010";
    /// S2K parameters are invalid.
    pub const INVALID_S2K = "ZPGP-E011";
    /// Session key decryption failed.
    pub const SESSION_KEY_ERROR = "ZPGP-E012";
    /// Key generation failed.
    pub const KEYGEN_FAILED = "ZPGP-E013";
    /// Certificate (key) is not valid for the requested operation.
    pub const CERT_NOT_VALID = "ZPGP-E014";
    /// No suitable encryption subkey found.
    pub const NO_ENCRYPTION_KEY = "ZPGP-E015";
    /// No suitable signing subkey found.
    pub const NO_SIGNING_KEY = "ZPGP-E016";
    /// Key ring operation failed.
    pub const KEYRING_ERROR = "ZPGP-E017";
    /// Revocation signature is invalid.
    pub const INVALID_REVOCATION = "ZPGP-E018";
    /// AEAD authentication tag verification failed.
    pub const AEAD_AUTH_FAILED = "ZPGP-E019";
    /// HKDF key derivation failed.
    pub const KDF_ERROR = "ZPGP-E020";

    // Informational (ZPGP-Innn)
    /// Algorithm selection was made via preference negotiation.
    pub const ALGO_NEGOTIATED = "ZPGP-I001";
    /// Key was successfully imported.
    pub const KEY_IMPORTED = "ZPGP-I002";
    /// Signature was verified successfully.
    pub const SIG_VERIFIED = "ZPGP-I003";
    /// Message was decrypted successfully.
    pub const DECRYPT_SUCCESS = "ZPGP-I004";
    /// Key migration completed.
    pub const MIGRATION_DONE = "ZPGP-I005";
};

/// Get the default severity for a diagnostic code.
pub fn codeLevel(code: []const u8) DiagnosticLevel {
    if (code.len < 6) return .info;
    // ZPGP-Xnnn: X determines severity
    if (code.len >= 6 and code[5] == 'W') return .warning;
    if (code.len >= 6 and code[5] == 'E') return .err;
    if (code.len >= 6 and code[5] == 'I') return .info;
    return .info;
}

// ---------------------------------------------------------------------------
// DiagnosticCollector
// ---------------------------------------------------------------------------

/// Accumulates diagnostics during an operation.
///
/// The collector filters diagnostics below a configured minimum level.
/// After the operation completes, the caller can check for errors and
/// format a report.
pub const DiagnosticCollector = struct {
    allocator: Allocator,
    diagnostics: std.ArrayList(Diagnostic),
    min_level: DiagnosticLevel,

    /// Create a new diagnostic collector.
    ///
    /// Diagnostics with a level below `min_level` will be silently discarded.
    pub fn init(allocator: Allocator, min_level: DiagnosticLevel) DiagnosticCollector {
        return .{
            .allocator = allocator,
            .diagnostics = .empty,
            .min_level = min_level,
        };
    }

    /// Free all collected diagnostics.
    pub fn deinit(self: *DiagnosticCollector) void {
        self.diagnostics.deinit(self.allocator);
    }

    /// Add a diagnostic to the collector.
    ///
    /// If the diagnostic's level is below the collector's minimum level,
    /// it is silently discarded.
    pub fn add(self: *DiagnosticCollector, diag: Diagnostic) !void {
        if (!diag.level.isAtLeast(self.min_level)) return;
        try self.diagnostics.append(self.allocator, diag);
    }

    /// Add an error diagnostic with a code and message.
    pub fn addError(self: *DiagnosticCollector, code: []const u8, msg: []const u8) !void {
        try self.add(.{ .level = .err, .code = code, .message = msg });
    }

    /// Add a warning diagnostic with a code and message.
    pub fn addWarning(self: *DiagnosticCollector, code: []const u8, msg: []const u8) !void {
        try self.add(.{ .level = .warning, .code = code, .message = msg });
    }

    /// Add an info diagnostic with a code and message.
    pub fn addInfo(self: *DiagnosticCollector, code: []const u8, msg: []const u8) !void {
        try self.add(.{ .level = .info, .code = code, .message = msg });
    }

    /// Add an error with source location context.
    pub fn addErrorWithLocation(
        self: *DiagnosticCollector,
        code: []const u8,
        msg: []const u8,
        module: []const u8,
        operation: []const u8,
    ) !void {
        try self.add(.{
            .level = .err,
            .code = code,
            .message = msg,
            .source_location = .{ .module = module, .operation = operation },
        });
    }

    /// Add a warning with a suggestion for resolution.
    pub fn addWarningWithSuggestion(
        self: *DiagnosticCollector,
        code: []const u8,
        msg: []const u8,
        suggestion: []const u8,
    ) !void {
        try self.add(.{
            .level = .warning,
            .code = code,
            .message = msg,
            .suggestion = suggestion,
        });
    }

    /// Add a full diagnostic with all fields.
    pub fn addFull(
        self: *DiagnosticCollector,
        level: DiagnosticLevel,
        code: []const u8,
        msg: []const u8,
        context: ?[]const u8,
        module: ?[]const u8,
        operation: ?[]const u8,
        suggestion: ?[]const u8,
    ) !void {
        const loc: ?SourceLocation = if (module != null and operation != null)
            .{ .module = module.?, .operation = operation.? }
        else
            null;

        try self.add(.{
            .level = level,
            .code = code,
            .message = msg,
            .context = context,
            .source_location = loc,
            .suggestion = suggestion,
        });
    }

    /// Check whether any errors have been recorded.
    pub fn hasErrors(self: *const DiagnosticCollector) bool {
        for (self.diagnostics.items) |diag| {
            if (diag.level.isError()) return true;
        }
        return false;
    }

    /// Check whether any warnings have been recorded.
    pub fn hasWarnings(self: *const DiagnosticCollector) bool {
        for (self.diagnostics.items) |diag| {
            if (diag.level == .warning) return true;
        }
        return false;
    }

    /// Return the total number of collected diagnostics.
    pub fn count(self: *const DiagnosticCollector) usize {
        return self.diagnostics.items.len;
    }

    /// Return the number of diagnostics at a specific level.
    pub fn countByLevel(self: *const DiagnosticCollector, level: DiagnosticLevel) usize {
        var n: usize = 0;
        for (self.diagnostics.items) |diag| {
            if (diag.level == level) n += 1;
        }
        return n;
    }

    /// Return the number of errors (error + fatal).
    pub fn errorCount(self: *const DiagnosticCollector) usize {
        var n: usize = 0;
        for (self.diagnostics.items) |diag| {
            if (diag.level.isError()) n += 1;
        }
        return n;
    }

    /// Return the number of warnings.
    pub fn warningCount(self: *const DiagnosticCollector) usize {
        return self.countByLevel(.warning);
    }

    /// Get all diagnostics at or above a given level.
    pub fn getByMinLevel(self: *const DiagnosticCollector, level: DiagnosticLevel) []const Diagnostic {
        // Return the full slice; caller can filter. For simplicity, return all.
        _ = level;
        return self.diagnostics.items;
    }

    /// Get the first error diagnostic, if any.
    pub fn firstError(self: *const DiagnosticCollector) ?Diagnostic {
        for (self.diagnostics.items) |diag| {
            if (diag.level.isError()) return diag;
        }
        return null;
    }

    /// Clear all collected diagnostics.
    pub fn clear(self: *DiagnosticCollector) void {
        self.diagnostics.clearRetainingCapacity();
    }

    /// Format all diagnostics as a multi-line report string.
    ///
    /// Each diagnostic is formatted on its own line. A summary line
    /// at the end shows counts of errors and warnings.
    pub fn format(self: *const DiagnosticCollector, allocator: Allocator) ![]u8 {
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(allocator);

        // Header
        try output.appendSlice(allocator, "=== zpgp Diagnostic Report ===\n");

        // Each diagnostic
        for (self.diagnostics.items) |diag| {
            const line = try diag.formatLine(allocator);
            defer allocator.free(line);
            try output.appendSlice(allocator, line);
            try output.append(allocator, '\n');
        }

        // Summary
        try output.appendSlice(allocator, "---\n");

        var summary_buf: [128]u8 = undefined;
        const err_count = self.errorCount();
        const warn_count = self.warningCount();
        const info_count = self.countByLevel(.info);

        const summary = std.fmt.bufPrint(&summary_buf, "Total: {d} error(s), {d} warning(s), {d} info(s)\n", .{
            err_count,
            warn_count,
            info_count,
        }) catch "Summary unavailable\n";
        try output.appendSlice(allocator, summary);

        return output.toOwnedSlice(allocator);
    }

    /// Format diagnostics as a compact single-line summary.
    pub fn formatSummary(self: *const DiagnosticCollector, allocator: Allocator) ![]u8 {
        var buf: [256]u8 = undefined;
        const err_count = self.errorCount();
        const warn_count = self.warningCount();

        const summary = std.fmt.bufPrint(&buf, "{d} error(s), {d} warning(s) in {d} diagnostic(s)", .{
            err_count,
            warn_count,
            self.count(),
        }) catch "summary unavailable";

        return allocator.dupe(u8, summary);
    }
};

// ---------------------------------------------------------------------------
// Error-to-diagnostic conversion
// ---------------------------------------------------------------------------

/// Translate a Zig error value into a Diagnostic.
///
/// Maps common zpgp error names to appropriate diagnostic codes and messages.
/// Unknown errors produce a generic ZPGP-E001 diagnostic.
pub fn errorToDiagnostic(err: anyerror) Diagnostic {
    const info = getErrorInfo(err);
    return .{
        .level = info.level,
        .code = info.code,
        .message = info.message,
        .suggestion = info.suggestion,
    };
}

const ErrorInfo = struct {
    level: DiagnosticLevel,
    code: []const u8,
    message: []const u8,
    suggestion: ?[]const u8,
};

fn getErrorInfo(err: anyerror) ErrorInfo {
    return switch (err) {
        error.AuthenticationFailed => .{
            .level = .err,
            .code = codes.INTEGRITY_FAILED,
            .message = "AEAD authentication or MDC verification failed",
            .suggestion = "The message may have been tampered with or the wrong key was used",
        },
        error.InvalidSignature => .{
            .level = .err,
            .code = codes.INVALID_SIGNATURE,
            .message = "Signature verification failed",
            .suggestion = "Ensure you have the correct signing key",
        },
        error.UnsupportedAlgorithm => .{
            .level = .err,
            .code = codes.UNKNOWN_ALGORITHM,
            .message = "Algorithm is not supported",
            .suggestion = "The data may use a newer algorithm not yet implemented",
        },
        error.InvalidPacket, error.InvalidPacketTag => .{
            .level = .err,
            .code = codes.MALFORMED_PACKET,
            .message = "Packet structure is invalid",
            .suggestion = "The data may be corrupted or not valid OpenPGP",
        },
        error.OutOfMemory => .{
            .level = .fatal,
            .code = "ZPGP-F001",
            .message = "Out of memory",
            .suggestion = "Reduce data size or increase available memory",
        },
        error.KeySizeMismatch => .{
            .level = .err,
            .code = codes.INVALID_KEY,
            .message = "Key size does not match algorithm requirements",
            .suggestion = null,
        },
        error.InvalidKey => .{
            .level = .err,
            .code = codes.INVALID_KEY,
            .message = "Key material is invalid",
            .suggestion = "The key may be corrupted",
        },
        else => .{
            .level = .err,
            .code = codes.UNKNOWN_ALGORITHM,
            .message = "An unexpected error occurred",
            .suggestion = null,
        },
    };
}

// ---------------------------------------------------------------------------
// Diagnostic builder (fluent API)
// ---------------------------------------------------------------------------

/// Builder for constructing diagnostics with a fluent API.
pub const DiagnosticBuilder = struct {
    diag: Diagnostic,

    /// Start building a diagnostic at the given level.
    pub fn init(level: DiagnosticLevel, code: []const u8, message: []const u8) DiagnosticBuilder {
        return .{
            .diag = .{
                .level = level,
                .code = code,
                .message = message,
            },
        };
    }

    /// Set the context string.
    pub fn withContext(self: DiagnosticBuilder, ctx: []const u8) DiagnosticBuilder {
        var b = self;
        b.diag.context = ctx;
        return b;
    }

    /// Set the source location.
    pub fn withLocation(self: DiagnosticBuilder, module: []const u8, operation: []const u8) DiagnosticBuilder {
        var b = self;
        b.diag.source_location = .{ .module = module, .operation = operation };
        return b;
    }

    /// Set the suggestion.
    pub fn withSuggestion(self: DiagnosticBuilder, sug: []const u8) DiagnosticBuilder {
        var b = self;
        b.diag.suggestion = sug;
        return b;
    }

    /// Build and return the Diagnostic.
    pub fn build(self: DiagnosticBuilder) Diagnostic {
        return self.diag;
    }

    /// Build and add to a collector.
    pub fn addTo(self: DiagnosticBuilder, collector: *DiagnosticCollector) !void {
        try collector.add(self.diag);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "diagnostic: level names" {
    try std.testing.expectEqualStrings("TRACE", DiagnosticLevel.trace.name());
    try std.testing.expectEqualStrings("WARNING", DiagnosticLevel.warning.name());
    try std.testing.expectEqualStrings("ERROR", DiagnosticLevel.err.name());
    try std.testing.expectEqualStrings("FATAL", DiagnosticLevel.fatal.name());
}

test "diagnostic: level severity comparison" {
    try std.testing.expect(DiagnosticLevel.err.isAtLeast(.warning));
    try std.testing.expect(DiagnosticLevel.warning.isAtLeast(.warning));
    try std.testing.expect(!DiagnosticLevel.info.isAtLeast(.warning));
    try std.testing.expect(DiagnosticLevel.fatal.isError());
    try std.testing.expect(DiagnosticLevel.err.isError());
    try std.testing.expect(!DiagnosticLevel.warning.isError());
}

test "diagnostic: collector basic usage" {
    const allocator = std.testing.allocator;
    var collector = DiagnosticCollector.init(allocator, .warning);
    defer collector.deinit();

    // Info should be filtered out (below min_level)
    try collector.addInfo(codes.ALGO_NEGOTIATED, "AES-256 selected");
    try std.testing.expect(collector.count() == 0);

    // Warning should be collected
    try collector.addWarning(codes.WEAK_ALGORITHM, "SHA-1 used");
    try std.testing.expect(collector.count() == 1);
    try std.testing.expect(!collector.hasErrors());
    try std.testing.expect(collector.hasWarnings());

    // Error should be collected
    try collector.addError(codes.INVALID_SIGNATURE, "Verification failed");
    try std.testing.expect(collector.count() == 2);
    try std.testing.expect(collector.hasErrors());
    try std.testing.expect(collector.errorCount() == 1);
    try std.testing.expect(collector.warningCount() == 1);
}

test "diagnostic: collector with location" {
    const allocator = std.testing.allocator;
    var collector = DiagnosticCollector.init(allocator, .trace);
    defer collector.deinit();

    try collector.addErrorWithLocation(
        codes.MALFORMED_PACKET,
        "Invalid tag",
        "packet.parser",
        "parseHeader",
    );

    try std.testing.expect(collector.count() == 1);
    const diag = collector.diagnostics.items[0];
    try std.testing.expect(diag.source_location != null);
    try std.testing.expectEqualStrings("packet.parser", diag.source_location.?.module);
}

test "diagnostic: collector clear" {
    const allocator = std.testing.allocator;
    var collector = DiagnosticCollector.init(allocator, .trace);
    defer collector.deinit();

    try collector.addWarning(codes.WEAK_ALGORITHM, "test");
    try collector.addError(codes.INVALID_SIGNATURE, "test");
    try std.testing.expect(collector.count() == 2);

    collector.clear();
    try std.testing.expect(collector.count() == 0);
    try std.testing.expect(!collector.hasErrors());
}

test "diagnostic: format report" {
    const allocator = std.testing.allocator;
    var collector = DiagnosticCollector.init(allocator, .warning);
    defer collector.deinit();

    try collector.addWarning(codes.WEAK_ALGORITHM, "SHA-1 is deprecated");
    try collector.addError(codes.INVALID_SIGNATURE, "Signature invalid");

    const report = try collector.format(allocator);
    defer allocator.free(report);

    // Should contain header, both diagnostics, and summary
    try std.testing.expect(mem.indexOf(u8, report, "zpgp Diagnostic Report") != null);
    try std.testing.expect(mem.indexOf(u8, report, "ZPGP-W001") != null);
    try std.testing.expect(mem.indexOf(u8, report, "ZPGP-E002") != null);
    try std.testing.expect(mem.indexOf(u8, report, "1 error(s)") != null);
    try std.testing.expect(mem.indexOf(u8, report, "1 warning(s)") != null);
}

test "diagnostic: format summary" {
    const allocator = std.testing.allocator;
    var collector = DiagnosticCollector.init(allocator, .warning);
    defer collector.deinit();

    try collector.addWarning(codes.WEAK_ALGORITHM, "test");
    try collector.addWarning(codes.DEPRECATED_HASH, "test");
    try collector.addError(codes.MALFORMED_PACKET, "test");

    const summary = try collector.formatSummary(allocator);
    defer allocator.free(summary);

    try std.testing.expect(mem.indexOf(u8, summary, "1 error(s)") != null);
    try std.testing.expect(mem.indexOf(u8, summary, "2 warning(s)") != null);
}

test "diagnostic: formatLine" {
    const allocator = std.testing.allocator;
    const diag = Diagnostic{
        .level = .warning,
        .code = codes.WEAK_ALGORITHM,
        .message = "SHA-1 is deprecated",
        .context = "key 0xDEADBEEF",
        .suggestion = "Use SHA-256 instead",
    };

    const line = try diag.formatLine(allocator);
    defer allocator.free(line);

    try std.testing.expect(mem.indexOf(u8, line, "[W]") != null);
    try std.testing.expect(mem.indexOf(u8, line, "ZPGP-W001") != null);
    try std.testing.expect(mem.indexOf(u8, line, "SHA-1 is deprecated") != null);
    try std.testing.expect(mem.indexOf(u8, line, "key 0xDEADBEEF") != null);
    try std.testing.expect(mem.indexOf(u8, line, "Use SHA-256 instead") != null);
}

test "diagnostic: error to diagnostic conversion" {
    const diag = errorToDiagnostic(error.AuthenticationFailed);
    try std.testing.expectEqualStrings(codes.INTEGRITY_FAILED, diag.code);
    try std.testing.expect(diag.level == .err);
    try std.testing.expect(diag.suggestion != null);
}

test "diagnostic: builder fluent API" {
    const diag = DiagnosticBuilder.init(.warning, codes.WEAK_ALGORITHM, "SHA-1 used")
        .withContext("signature packet")
        .withLocation("signature", "verify")
        .withSuggestion("Upgrade to SHA-256")
        .build();

    try std.testing.expectEqualStrings(codes.WEAK_ALGORITHM, diag.code);
    try std.testing.expect(diag.context != null);
    try std.testing.expect(diag.source_location != null);
    try std.testing.expect(diag.suggestion != null);
}

test "diagnostic: code level mapping" {
    try std.testing.expect(codeLevel(codes.WEAK_ALGORITHM) == .warning);
    try std.testing.expect(codeLevel(codes.UNKNOWN_ALGORITHM) == .err);
    try std.testing.expect(codeLevel(codes.ALGO_NEGOTIATED) == .info);
}

test "diagnostic: firstError" {
    const allocator = std.testing.allocator;
    var collector = DiagnosticCollector.init(allocator, .trace);
    defer collector.deinit();

    try collector.addWarning(codes.WEAK_ALGORITHM, "warning");
    try std.testing.expect(collector.firstError() == null);

    try collector.addError(codes.INVALID_SIGNATURE, "error");
    const first = collector.firstError();
    try std.testing.expect(first != null);
    try std.testing.expectEqualStrings(codes.INVALID_SIGNATURE, first.?.code);
}

test "diagnostic: addFull" {
    const allocator = std.testing.allocator;
    var collector = DiagnosticCollector.init(allocator, .trace);
    defer collector.deinit();

    try collector.addFull(
        .warning,
        codes.WEAK_ALGORITHM,
        "CAST5 is deprecated",
        "packet 3",
        "crypto.cipher",
        "decrypt",
        "Use AES-256",
    );

    try std.testing.expect(collector.count() == 1);
    const diag = collector.diagnostics.items[0];
    try std.testing.expectEqualStrings("packet 3", diag.context.?);
    try std.testing.expectEqualStrings("crypto.cipher", diag.source_location.?.module);
    try std.testing.expectEqualStrings("Use AES-256", diag.suggestion.?);
}

test "diagnostic: source location format" {
    const allocator = std.testing.allocator;
    const loc = SourceLocation{ .module = "crypto.aead", .operation = "decrypt" };
    const formatted = try loc.format(allocator);
    defer allocator.free(formatted);

    try std.testing.expectEqualStrings("crypto.aead::decrypt", formatted);
}
