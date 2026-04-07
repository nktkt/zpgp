// SPDX-License-Identifier: MIT
//! Operation logging for debugging and performance analysis.
//!
//! Records a timestamped sequence of operations performed during a complex
//! zpgp workflow (e.g., decrypting a message with multiple recipients,
//! or importing a keyring). Each entry captures:
//!   - A monotonic timestamp (relative to the log's creation)
//!   - An operation name (e.g., "parse_packet", "decrypt_session_key")
//!   - Free-form details
//!   - Optional duration for timed operations
//!
//! The operation log is useful for:
//!   - Debugging: understanding the sequence of steps in an operation
//!   - Performance: identifying slow steps in complex workflows
//!   - Audit: recording what was done during key management operations
//!
//! Example:
//! ```zig
//! var log = OperationLog.init(allocator);
//! defer log.deinit();
//!
//! try log.log("parse_header", "SEIPD v2 packet, 1024 bytes");
//! // ... perform work ...
//! try log.logTimed("decrypt", "AES-256-OCB", elapsed_ns);
//!
//! const report = try log.format(allocator);
//! defer allocator.free(report);
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

// ---------------------------------------------------------------------------
// LogEntry
// ---------------------------------------------------------------------------

/// A single entry in the operation log.
pub const LogEntry = struct {
    /// Monotonic timestamp in nanoseconds relative to the log start.
    timestamp_ns: i128,
    /// Short operation name (e.g., "parse_packet", "verify_sig").
    operation: []const u8,
    /// Free-form details about the operation.
    details: []const u8,
    /// Duration of the operation in nanoseconds (null if not timed).
    duration_ns: ?u64,
    /// Sequence number (0-based).
    sequence: usize,

    /// Format the entry as a human-readable string.
    pub fn format(self: LogEntry, allocator: Allocator) ![]u8 {
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(allocator);

        // Sequence number
        var seq_buf: [16]u8 = undefined;
        const seq_str = std.fmt.bufPrint(&seq_buf, "[{d:>4}]", .{self.sequence}) catch "[????]";
        try output.appendSlice(allocator, seq_str);

        // Timestamp
        var ts_buf: [32]u8 = undefined;
        const ms = @divTrunc(self.timestamp_ns, 1_000_000);
        const ts_str = std.fmt.bufPrint(&ts_buf, " +{d}ms", .{ms}) catch " +???ms";
        try output.appendSlice(allocator, ts_str);

        // Operation name
        try output.appendSlice(allocator, " | ");
        try output.appendSlice(allocator, self.operation);

        // Details
        if (self.details.len > 0) {
            try output.appendSlice(allocator, ": ");
            try output.appendSlice(allocator, self.details);
        }

        // Duration
        if (self.duration_ns) |dur| {
            var dur_buf: [32]u8 = undefined;
            if (dur < 1_000) {
                const dur_str = std.fmt.bufPrint(&dur_buf, " ({d}ns)", .{dur}) catch "";
                try output.appendSlice(allocator, dur_str);
            } else if (dur < 1_000_000) {
                const us = dur / 1_000;
                const dur_str = std.fmt.bufPrint(&dur_buf, " ({d}us)", .{us}) catch "";
                try output.appendSlice(allocator, dur_str);
            } else {
                const ms_dur = dur / 1_000_000;
                const dur_str = std.fmt.bufPrint(&dur_buf, " ({d}ms)", .{ms_dur}) catch "";
                try output.appendSlice(allocator, dur_str);
            }
        }

        return output.toOwnedSlice(allocator);
    }
};

// ---------------------------------------------------------------------------
// Timer
// ---------------------------------------------------------------------------

/// A scoped timer that records its duration when stopped.
pub const Timer = struct {
    log: *OperationLog,
    operation: []const u8,
    details: []const u8,
    start_ns: i128,

    /// Stop the timer and record the elapsed duration.
    pub fn stop(self: Timer) !void {
        const now = std.time.nanoTimestamp();
        const elapsed = @as(u64, @intCast(@max(0, now - self.start_ns)));
        try self.log.logTimed(self.operation, self.details, elapsed);
    }
};

// ---------------------------------------------------------------------------
// OperationLog
// ---------------------------------------------------------------------------

/// Accumulates a log of operations for debugging and performance analysis.
pub const OperationLog = struct {
    allocator: Allocator,
    entries: std.ArrayList(LogEntry),
    /// The timestamp at which this log was created (nanoTimestamp).
    start_time: i128,
    /// Counter for assigning sequence numbers.
    next_sequence: usize,

    /// Create a new operation log.
    pub fn init(allocator: Allocator) OperationLog {
        return .{
            .allocator = allocator,
            .entries = .empty,
            .start_time = std.time.nanoTimestamp(),
            .next_sequence = 0,
        };
    }

    /// Free all log entries.
    pub fn deinit(self: *OperationLog) void {
        self.entries.deinit(self.allocator);
    }

    /// Record an operation without timing information.
    pub fn log(self: *OperationLog, operation: []const u8, details: []const u8) !void {
        const now = std.time.nanoTimestamp();
        const relative = now - self.start_time;

        try self.entries.append(self.allocator, .{
            .timestamp_ns = relative,
            .operation = operation,
            .details = details,
            .duration_ns = null,
            .sequence = self.next_sequence,
        });
        self.next_sequence += 1;
    }

    /// Record an operation with a known duration.
    pub fn logTimed(self: *OperationLog, operation: []const u8, details: []const u8, duration_ns: u64) !void {
        const now = std.time.nanoTimestamp();
        const relative = now - self.start_time;

        try self.entries.append(self.allocator, .{
            .timestamp_ns = relative,
            .operation = operation,
            .details = details,
            .duration_ns = duration_ns,
            .sequence = self.next_sequence,
        });
        self.next_sequence += 1;
    }

    /// Start a scoped timer. Call .stop() on the returned Timer to record the entry.
    pub fn startTimer(self: *OperationLog, operation: []const u8, details: []const u8) Timer {
        return .{
            .log = self,
            .operation = operation,
            .details = details,
            .start_ns = std.time.nanoTimestamp(),
        };
    }

    /// Record a section separator with a label.
    pub fn section(self: *OperationLog, label: []const u8) !void {
        try self.log("--- section ---", label);
    }

    /// Return the total number of log entries.
    pub fn count(self: *const OperationLog) usize {
        return self.entries.items.len;
    }

    /// Return the total wall-clock duration from log creation to now.
    pub fn totalDuration(self: *const OperationLog) i128 {
        return std.time.nanoTimestamp() - self.start_time;
    }

    /// Return the total wall-clock duration from log creation to the last entry.
    pub fn totalDurationToLastEntry(self: *const OperationLog) i128 {
        if (self.entries.items.len == 0) return 0;
        return self.entries.items[self.entries.items.len - 1].timestamp_ns;
    }

    /// Sum the durations of all timed entries.
    pub fn totalTimedDuration(self: *const OperationLog) u64 {
        var total: u64 = 0;
        for (self.entries.items) |entry| {
            if (entry.duration_ns) |dur| {
                total += dur;
            }
        }
        return total;
    }

    /// Count entries matching a specific operation name.
    pub fn countOperation(self: *const OperationLog, operation: []const u8) usize {
        var n: usize = 0;
        for (self.entries.items) |entry| {
            if (mem.eql(u8, entry.operation, operation)) n += 1;
        }
        return n;
    }

    /// Get the last entry, if any.
    pub fn lastEntry(self: *const OperationLog) ?LogEntry {
        if (self.entries.items.len == 0) return null;
        return self.entries.items[self.entries.items.len - 1];
    }

    /// Get the entry at a specific index.
    pub fn getEntry(self: *const OperationLog, index: usize) ?LogEntry {
        if (index >= self.entries.items.len) return null;
        return self.entries.items[index];
    }

    /// Clear all entries but keep the start time.
    pub fn clear(self: *OperationLog) void {
        self.entries.clearRetainingCapacity();
        self.next_sequence = 0;
    }

    /// Reset the log entirely (clear entries and reset start time).
    pub fn reset(self: *OperationLog) void {
        self.clear();
        self.start_time = std.time.nanoTimestamp();
    }

    /// Format all log entries as a multi-line report.
    pub fn format(self: *const OperationLog, allocator: Allocator) ![]u8 {
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(allocator);

        // Header
        try output.appendSlice(allocator, "=== zpgp Operation Log ===\n");

        var total_buf: [64]u8 = undefined;
        const total_ms = @divTrunc(self.totalDuration(), 1_000_000);
        const total_str = std.fmt.bufPrint(&total_buf, "Entries: {d}, Total time: {d}ms\n", .{
            self.entries.items.len,
            total_ms,
        }) catch "Entries: ?, Total time: ?ms\n";
        try output.appendSlice(allocator, total_str);
        try output.appendSlice(allocator, "---\n");

        // Each entry
        for (self.entries.items) |entry| {
            const line = try entry.format(allocator);
            defer allocator.free(line);
            try output.appendSlice(allocator, line);
            try output.append(allocator, '\n');
        }

        // Timed summary
        const timed_total = self.totalTimedDuration();
        if (timed_total > 0) {
            try output.appendSlice(allocator, "---\n");
            var timed_buf: [64]u8 = undefined;
            const timed_ms = timed_total / 1_000_000;
            const timed_str = std.fmt.bufPrint(&timed_buf, "Total timed: {d}ms\n", .{timed_ms}) catch "Total timed: ?ms\n";
            try output.appendSlice(allocator, timed_str);
        }

        return output.toOwnedSlice(allocator);
    }

    /// Format a compact summary of the log.
    pub fn formatSummary(self: *const OperationLog, allocator: Allocator) ![]u8 {
        var buf: [256]u8 = undefined;
        const total_ms = @divTrunc(self.totalDuration(), 1_000_000);
        const summary = std.fmt.bufPrint(&buf, "{d} operations in {d}ms", .{
            self.entries.items.len,
            total_ms,
        }) catch "? operations in ?ms";
        return allocator.dupe(u8, summary);
    }
};

// ---------------------------------------------------------------------------
// Helpers for common operation patterns
// ---------------------------------------------------------------------------

/// Create a log entry for a packet parse operation.
pub fn logPacketParse(oplog: *OperationLog, tag_name: []const u8, size: usize) !void {
    var buf: [64]u8 = undefined;
    const details = std.fmt.bufPrint(&buf, "{s}, {d} bytes", .{ tag_name, size }) catch tag_name;
    try oplog.log("parse_packet", details);
}

/// Create a log entry for a crypto operation.
pub fn logCryptoOp(oplog: *OperationLog, algorithm: []const u8, operation: []const u8, duration_ns: u64) !void {
    var buf: [64]u8 = undefined;
    const details = std.fmt.bufPrint(&buf, "{s} ({s})", .{ algorithm, operation }) catch algorithm;
    try oplog.logTimed("crypto", details, duration_ns);
}

/// Create a log entry for a key operation.
pub fn logKeyOp(oplog: *OperationLog, operation: []const u8, key_id: []const u8) !void {
    try oplog.log(operation, key_id);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "operation_log: basic logging" {
    const allocator = std.testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    try oplog.log("parse_header", "SEIPD v2 packet");
    try oplog.log("decrypt", "AES-256-OCB");

    try std.testing.expect(oplog.count() == 2);

    const entry0 = oplog.getEntry(0).?;
    try std.testing.expectEqualStrings("parse_header", entry0.operation);
    try std.testing.expectEqualStrings("SEIPD v2 packet", entry0.details);
    try std.testing.expect(entry0.duration_ns == null);
    try std.testing.expect(entry0.sequence == 0);

    const entry1 = oplog.getEntry(1).?;
    try std.testing.expect(entry1.sequence == 1);
}

test "operation_log: timed logging" {
    const allocator = std.testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    try oplog.logTimed("encrypt", "AES-256", 500_000);
    try oplog.logTimed("hash", "SHA-256", 100_000);

    try std.testing.expect(oplog.count() == 2);
    try std.testing.expect(oplog.totalTimedDuration() == 600_000);

    const entry = oplog.getEntry(0).?;
    try std.testing.expect(entry.duration_ns.? == 500_000);
}

test "operation_log: section markers" {
    const allocator = std.testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    try oplog.section("Decryption");
    try oplog.log("step1", "detail1");
    try oplog.section("Verification");
    try oplog.log("step2", "detail2");

    try std.testing.expect(oplog.count() == 4);
}

test "operation_log: countOperation" {
    const allocator = std.testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    try oplog.log("parse_packet", "tag 1");
    try oplog.log("parse_packet", "tag 2");
    try oplog.log("decrypt", "aes");
    try oplog.log("parse_packet", "tag 3");

    try std.testing.expect(oplog.countOperation("parse_packet") == 3);
    try std.testing.expect(oplog.countOperation("decrypt") == 1);
    try std.testing.expect(oplog.countOperation("unknown") == 0);
}

test "operation_log: lastEntry" {
    const allocator = std.testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    try std.testing.expect(oplog.lastEntry() == null);

    try oplog.log("first", "");
    try oplog.log("second", "");
    try oplog.log("third", "");

    const last = oplog.lastEntry().?;
    try std.testing.expectEqualStrings("third", last.operation);
}

test "operation_log: clear and reset" {
    const allocator = std.testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    try oplog.log("test", "data");
    try std.testing.expect(oplog.count() == 1);

    oplog.clear();
    try std.testing.expect(oplog.count() == 0);

    try oplog.log("after_clear", "");
    try std.testing.expect(oplog.getEntry(0).?.sequence == 0);
}

test "operation_log: format report" {
    const allocator = std.testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    try oplog.log("parse", "header");
    try oplog.logTimed("decrypt", "AES-256", 5_000_000);
    try oplog.log("verify", "Ed25519");

    const report = try oplog.format(allocator);
    defer allocator.free(report);

    try std.testing.expect(mem.indexOf(u8, report, "Operation Log") != null);
    try std.testing.expect(mem.indexOf(u8, report, "parse") != null);
    try std.testing.expect(mem.indexOf(u8, report, "decrypt") != null);
    try std.testing.expect(mem.indexOf(u8, report, "verify") != null);
}

test "operation_log: format summary" {
    const allocator = std.testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    try oplog.log("a", "");
    try oplog.log("b", "");

    const summary = try oplog.formatSummary(allocator);
    defer allocator.free(summary);

    try std.testing.expect(mem.indexOf(u8, summary, "2 operations") != null);
}

test "operation_log: entry format" {
    const allocator = std.testing.allocator;
    const entry = LogEntry{
        .timestamp_ns = 1_500_000,
        .operation = "decrypt",
        .details = "AES-256",
        .duration_ns = 500_000,
        .sequence = 3,
    };

    const formatted = try entry.format(allocator);
    defer allocator.free(formatted);

    try std.testing.expect(mem.indexOf(u8, formatted, "[   3]") != null);
    try std.testing.expect(mem.indexOf(u8, formatted, "decrypt") != null);
    try std.testing.expect(mem.indexOf(u8, formatted, "AES-256") != null);
    try std.testing.expect(mem.indexOf(u8, formatted, "500us") != null);
}

test "operation_log: helper functions" {
    const allocator = std.testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    try logPacketParse(&oplog, "SEIPD", 1024);
    try logCryptoOp(&oplog, "AES-256", "encrypt", 1000);
    try logKeyOp(&oplog, "import", "0xDEADBEEF");

    try std.testing.expect(oplog.count() == 3);
    try std.testing.expectEqualStrings("parse_packet", oplog.getEntry(0).?.operation);
    try std.testing.expectEqualStrings("crypto", oplog.getEntry(1).?.operation);
    try std.testing.expectEqualStrings("import", oplog.getEntry(2).?.operation);
}

test "operation_log: timer" {
    const allocator = std.testing.allocator;
    var oplog = OperationLog.init(allocator);
    defer oplog.deinit();

    const timer = oplog.startTimer("heavy_op", "test");
    // Simulate some work (just stop immediately in test)
    try timer.stop();

    try std.testing.expect(oplog.count() == 1);
    const entry = oplog.getEntry(0).?;
    try std.testing.expectEqualStrings("heavy_op", entry.operation);
    try std.testing.expect(entry.duration_ns != null);
}
