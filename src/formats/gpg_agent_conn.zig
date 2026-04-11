// SPDX-License-Identifier: MIT
//! GPG agent socket communication layer.
//!
//! Implements the Assuan protocol transport for communicating with a
//! running gpg-agent process via its Unix domain socket. Builds on the
//! protocol parsing from gpg_agent.zig by adding:
//!
//! - Socket connection management
//! - Line-based read/write with proper framing
//! - High-level command wrappers (GET_PASSPHRASE, HAVEKEY, PKSIGN, etc.)
//! - Multi-line data response accumulation
//! - INQUIRE handling
//!
//! All socket operations use std.net.Stream (Unix domain sockets)
//! or can be mocked with any reader/writer pair for testing.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const gpg_agent = @import("gpg_agent.zig");
const AssuanCommand = gpg_agent.AssuanCommand;
const AssuanResponse = gpg_agent.AssuanResponse;
const ResponseStatus = gpg_agent.ResponseStatus;

// ---------------------------------------------------------------------------
// Assuan line reader — works with any std.io reader
// ---------------------------------------------------------------------------

/// Maximum length of an Assuan protocol line.
/// The spec recommends 1000 bytes; we use a generous limit.
pub const MAX_LINE_LENGTH = 4096;

/// Errors specific to the agent connection.
pub const AgentError = error{
    ConnectionFailed,
    SocketNotFound,
    ProtocolError,
    ServerError,
    Timeout,
    LineTooLong,
    UnexpectedResponse,
    InquireNotHandled,
    KeyNotAvailable,
    OperationCancelled,
    InvalidState,
    OutOfMemory,
};

/// Read a single LF-terminated line from a reader.
///
/// Returns the line without the trailing LF. Returns null on EOF.
pub fn readLine(allocator: Allocator, reader: anytype) !?[]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    var count: usize = 0;
    while (count < MAX_LINE_LENGTH) : (count += 1) {
        const byte = reader.readByte() catch |err| {
            switch (err) {
                error.EndOfStream => {
                    if (buf.items.len > 0) {
                        return try buf.toOwnedSlice(allocator);
                    }
                    buf.deinit(allocator);
                    return null;
                },
                else => {
                    buf.deinit(allocator);
                    return AgentError.ConnectionFailed;
                },
            }
        };
        if (byte == '\n') {
            return try buf.toOwnedSlice(allocator);
        }
        try buf.append(allocator, byte);
    }

    buf.deinit(allocator);
    return AgentError.LineTooLong;
}

/// Write a command line to a writer, appending LF if not present.
pub fn writeLine(writer: anytype, data: []const u8) !void {
    try writer.writeAll(data);
    if (data.len == 0 or data[data.len - 1] != '\n') {
        try writer.writeAll("\n");
    }
}

// ---------------------------------------------------------------------------
// Multi-line response accumulator
// ---------------------------------------------------------------------------

/// Result of reading a complete response (all D lines + final OK/ERR).
pub const FullResponse = struct {
    /// Final status (ok or err).
    status: ResponseStatus,
    /// Accumulated data from all D lines (concatenated).
    data: ?[]u8,
    /// Error code if status == .err.
    error_code: u32,
    /// Error description if status == .err.
    error_description: ?[]u8,
    /// Status info lines received.
    status_lines: []StatusInfo,

    pub fn deinit(self: *FullResponse, allocator: Allocator) void {
        if (self.data) |d| allocator.free(d);
        if (self.error_description) |d| allocator.free(d);
        for (self.status_lines) |*s| s.deinit(allocator);
        allocator.free(self.status_lines);
    }

    /// Check if the command succeeded.
    pub fn isOk(self: *const FullResponse) bool {
        return self.status == .ok;
    }
};

/// A status info line from the server.
pub const StatusInfo = struct {
    keyword: []u8,
    value: ?[]u8,

    pub fn deinit(self: *StatusInfo, allocator: Allocator) void {
        allocator.free(self.keyword);
        if (self.value) |v| allocator.free(v);
    }
};

/// Read a complete multi-line Assuan response from a reader.
///
/// Accumulates all D (data) lines and S (status) lines until an OK or
/// ERR line is received.
pub fn readFullResponse(allocator: Allocator, reader: anytype) !FullResponse {
    var data_parts: std.ArrayList([]u8) = .empty;
    defer {
        for (data_parts.items) |part| allocator.free(part);
        data_parts.deinit(allocator);
    }

    var status_lines: std.ArrayList(StatusInfo) = .empty;
    errdefer {
        for (status_lines.items) |*s| s.deinit(allocator);
        status_lines.deinit(allocator);
    }

    while (true) {
        const line = (try readLine(allocator, reader)) orelse {
            return FullResponse{
                .status = .err,
                .data = null,
                .error_code = 0,
                .error_description = try allocator.dupe(u8, "unexpected EOF"),
                .status_lines = try status_lines.toOwnedSlice(allocator),
            };
        };
        defer allocator.free(line);

        var resp = try AssuanResponse.parse(allocator, line);

        switch (resp.status) {
            .ok => {
                resp.deinit(allocator);
                // Concatenate all data parts
                const data = try concatenateData(allocator, data_parts.items);
                return FullResponse{
                    .status = .ok,
                    .data = data,
                    .error_code = 0,
                    .error_description = null,
                    .status_lines = try status_lines.toOwnedSlice(allocator),
                };
            },
            .err => {
                const desc = resp.data;
                resp.data = null; // transfer ownership
                const data = try concatenateData(allocator, data_parts.items);
                errdefer if (data) |d| allocator.free(d);
                const s = try status_lines.toOwnedSlice(allocator);
                return FullResponse{
                    .status = .err,
                    .data = data,
                    .error_code = resp.error_code,
                    .error_description = desc,
                    .status_lines = s,
                };
            },
            .data_line => {
                if (resp.data) |d| {
                    const copy = try allocator.dupe(u8, d);
                    try data_parts.append(allocator, copy);
                }
                resp.deinit(allocator);
            },
            .status => {
                const kw = if (resp.keyword) |k|
                    try allocator.dupe(u8, k)
                else
                    try allocator.dupe(u8, "");

                const val = resp.data;
                resp.data = null; // transfer ownership
                try status_lines.append(allocator, .{ .keyword = kw, .value = val });
            },
            .inquire => {
                resp.deinit(allocator);
                // We don't handle inquires in the basic reader;
                // the caller should handle them via the connection struct.
                return FullResponse{
                    .status = .err,
                    .data = null,
                    .error_code = 0,
                    .error_description = try allocator.dupe(u8, "unhandled INQUIRE"),
                    .status_lines = try status_lines.toOwnedSlice(allocator),
                };
            },
            .comment, .unknown => {
                resp.deinit(allocator);
                // Skip comments and unknown lines
            },
        }
    }
}

/// Concatenate multiple data parts into a single buffer.
fn concatenateData(allocator: Allocator, parts: []const []u8) !?[]u8 {
    if (parts.len == 0) return null;

    var total: usize = 0;
    for (parts) |p| total += p.len;

    const result = try allocator.alloc(u8, total);
    var offset: usize = 0;
    for (parts) |p| {
        @memcpy(result[offset .. offset + p.len], p);
        offset += p.len;
    }
    return result;
}

// ---------------------------------------------------------------------------
// High-level agent command helpers (work with any reader/writer)
// ---------------------------------------------------------------------------

/// Send a command and read the full response.
pub fn sendCommandAndRead(allocator: Allocator, writer: anytype, reader: anytype, cmd: AssuanCommand) !FullResponse {
    const serialized = try cmd.serialize(allocator);
    defer allocator.free(serialized);
    try writer.writeAll(serialized);
    return readFullResponse(allocator, reader);
}

/// Send a raw command string and read the full response.
pub fn sendRawCommandAndRead(allocator: Allocator, writer: anytype, reader: anytype, command: []const u8) !FullResponse {
    try writeLine(writer, command);
    return readFullResponse(allocator, reader);
}

/// Check if the agent has a secret key by keygrip.
///
/// Sends HAVEKEY <keygrip> and returns true if OK, false if ERR.
pub fn checkHaveKey(allocator: Allocator, writer: anytype, reader: anytype, keygrip: []const u8) !bool {
    const cmd = gpg_agent.haveSecretKey(keygrip);
    var resp = try sendCommandAndRead(allocator, writer, reader, cmd);
    defer resp.deinit(allocator);
    return resp.isOk();
}

/// Request a passphrase from the agent.
///
/// Sends GET_PASSPHRASE and returns the passphrase data (percent-decoded).
/// Returns null if the user cancelled or the agent returned an error.
pub fn requestPassphrase(
    allocator: Allocator,
    writer: anytype,
    reader: anytype,
    cache_id: []const u8,
    error_msg: []const u8,
    prompt: []const u8,
    description: []const u8,
) !?[]u8 {
    const cmd = try gpg_agent.getPassphrase(allocator, cache_id, error_msg, prompt, description);
    defer allocator.free(cmd.args.?);

    var resp = try sendCommandAndRead(allocator, writer, reader, cmd);
    defer resp.deinit(allocator);

    if (!resp.isOk()) return null;
    if (resp.data) |d| {
        return try allocator.dupe(u8, d);
    }
    return null;
}

/// Clear a cached passphrase.
pub fn clearCachedPassphrase(allocator: Allocator, writer: anytype, reader: anytype, cache_id: []const u8) !bool {
    const cmd = gpg_agent.clearPassphrase(cache_id);
    var resp = try sendCommandAndRead(allocator, writer, reader, cmd);
    defer resp.deinit(allocator);
    return resp.isOk();
}

/// Get agent version information.
pub fn getAgentVersion(allocator: Allocator, writer: anytype, reader: anytype) !?[]u8 {
    const cmd = gpg_agent.getInfo("version");
    var resp = try sendCommandAndRead(allocator, writer, reader, cmd);
    defer resp.deinit(allocator);

    if (!resp.isOk()) return null;
    if (resp.data) |d| {
        return try allocator.dupe(u8, d);
    }
    return null;
}

/// Send BYE to close the connection gracefully.
pub fn sendBye(allocator: Allocator, writer: anytype, reader: anytype) !void {
    const cmd = gpg_agent.bye();
    var resp = try sendCommandAndRead(allocator, writer, reader, cmd);
    resp.deinit(allocator);
}

/// Send RESET to reset the connection state.
pub fn sendReset(allocator: Allocator, writer: anytype, reader: anytype) !void {
    const cmd = gpg_agent.reset();
    var resp = try sendCommandAndRead(allocator, writer, reader, cmd);
    resp.deinit(allocator);
}

/// Set an agent option.
pub fn setOption(allocator: Allocator, writer: anytype, reader: anytype, name: []const u8, value: []const u8) !bool {
    const cmd = try gpg_agent.option(allocator, name, value);
    defer allocator.free(cmd.args.?);
    var resp = try sendCommandAndRead(allocator, writer, reader, cmd);
    defer resp.deinit(allocator);
    return resp.isOk();
}

/// Perform PKSIGN: set the signing key, set the hash, and sign.
///
/// This sends the sequence: SIGKEY, SETHASH, PKSIGN and returns
/// the signature data.
pub fn performSign(
    allocator: Allocator,
    writer: anytype,
    reader: anytype,
    keygrip: []const u8,
    hash_algo: u8,
    hash_hex: []const u8,
) !?[]u8 {
    // SIGKEY
    const sigkey_cmd = gpg_agent.signKey(keygrip);
    var sigkey_resp = try sendCommandAndRead(allocator, writer, reader, sigkey_cmd);
    defer sigkey_resp.deinit(allocator);
    if (!sigkey_resp.isOk()) return null;

    // SETHASH
    const sethash_cmd = try gpg_agent.setHash(allocator, hash_algo, hash_hex);
    defer allocator.free(sethash_cmd.args.?);
    var sethash_resp = try sendCommandAndRead(allocator, writer, reader, sethash_cmd);
    defer sethash_resp.deinit(allocator);
    if (!sethash_resp.isOk()) return null;

    // PKSIGN
    const pksign_cmd = gpg_agent.pkSign();
    var pksign_resp = try sendCommandAndRead(allocator, writer, reader, pksign_cmd);
    defer pksign_resp.deinit(allocator);

    if (!pksign_resp.isOk()) return null;
    if (pksign_resp.data) |d| {
        return try allocator.dupe(u8, d);
    }
    return null;
}

/// Perform PKDECRYPT: set the decryption key and decrypt.
pub fn performDecrypt(
    allocator: Allocator,
    writer: anytype,
    reader: anytype,
    keygrip: []const u8,
) !?[]u8 {
    // SETKEY
    const setkey_cmd = gpg_agent.setKey(keygrip);
    var setkey_resp = try sendCommandAndRead(allocator, writer, reader, setkey_cmd);
    defer setkey_resp.deinit(allocator);
    if (!setkey_resp.isOk()) return null;

    // PKDECRYPT
    const decrypt_cmd = gpg_agent.pkDecrypt();
    var decrypt_resp = try sendCommandAndRead(allocator, writer, reader, decrypt_cmd);
    defer decrypt_resp.deinit(allocator);

    if (!decrypt_resp.isOk()) return null;
    if (decrypt_resp.data) |d| {
        return try allocator.dupe(u8, d);
    }
    return null;
}

/// Get key information from the agent.
pub fn getKeyInfo(allocator: Allocator, writer: anytype, reader: anytype, keygrip: []const u8) !?[]u8 {
    const cmd = gpg_agent.keyInfo(keygrip);
    var resp = try sendCommandAndRead(allocator, writer, reader, cmd);
    defer resp.deinit(allocator);

    if (!resp.isOk()) return null;
    if (resp.data) |d| {
        return try allocator.dupe(u8, d);
    }
    // Check status lines for key info
    for (resp.status_lines) |s| {
        if (mem.eql(u8, s.keyword, "KEYINFO")) {
            if (s.value) |v| return try allocator.dupe(u8, v);
        }
    }
    return null;
}

// ---------------------------------------------------------------------------
// Socket path utilities
// ---------------------------------------------------------------------------

/// Detect the GPG agent socket path.
///
/// Checks, in order:
/// 1. GPG_AGENT_INFO environment variable
/// 2. GNUPGHOME/S.gpg-agent
/// 3. ~/.gnupg/S.gpg-agent
///
/// Returns the socket path or null if no socket is found.
pub fn detectAgentSocket(allocator: Allocator) !?[]u8 {
    // 1. Check GPG_AGENT_INFO (format: "/path/to/socket:pid:protocol")
    if (std.posix.getenv("GPG_AGENT_INFO")) |info| {
        if (mem.indexOf(u8, info, ":")) |colon| {
            const path = info[0..colon];
            if (path.len > 0) {
                return try allocator.dupe(u8, path);
            }
        } else if (info.len > 0) {
            return try allocator.dupe(u8, info);
        }
    }

    // 2. Use gpgHomeDir + socket name
    const socket_path = gpg_agent.agentSocketPath(allocator) catch return null;
    return socket_path;
}

/// Validate that a socket path looks reasonable.
pub fn isValidSocketPath(path: []const u8) bool {
    if (path.len == 0) return false;
    if (path[0] != '/') return false;
    if (path.len > 1024) return false;
    // Must end with a socket name, not a directory
    if (path[path.len - 1] == '/') return false;
    return true;
}

// ---------------------------------------------------------------------------
// Mock connection for testing
// ---------------------------------------------------------------------------

/// A mock GPG agent connection backed by in-memory buffers.
///
/// Use this for testing without an actual gpg-agent process.
pub const MockAgentConnection = struct {
    /// Buffer for data written (commands sent to agent).
    output: std.ArrayList(u8),
    /// Pre-loaded responses (data to read from agent).
    input_data: []const u8,
    input_pos: usize,

    pub fn init(allocator: Allocator, responses: []const u8) MockAgentConnection {
        return .{
            .output = std.ArrayList(u8).empty,
            .input_data = responses,
            .input_pos = 0,
        };
    }

    pub fn deinit(self: *MockAgentConnection, allocator: Allocator) void {
        self.output.deinit(allocator);
    }

    /// Get a reader for the mock input (simulated agent responses).
    pub fn reader(self: *MockAgentConnection) MockReader {
        return .{ .conn = self };
    }

    /// Get a writer for the mock output (commands sent to agent).
    pub fn writer(self: *MockAgentConnection, allocator: Allocator) MockWriter {
        return .{ .conn = self, .allocator = allocator };
    }

    pub const MockReader = struct {
        conn: *MockAgentConnection,

        pub fn readByte(self: *MockReader) error{EndOfStream}!u8 {
            if (self.conn.input_pos >= self.conn.input_data.len) {
                return error.EndOfStream;
            }
            const byte = self.conn.input_data[self.conn.input_pos];
            self.conn.input_pos += 1;
            return byte;
        }
    };

    pub const MockWriter = struct {
        conn: *MockAgentConnection,
        allocator: Allocator,

        pub fn writeAll(self: *MockWriter, data: []const u8) !void {
            try self.conn.output.appendSlice(self.allocator, data);
        }
    };
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "readLine simple" {
    const allocator = std.testing.allocator;
    var stream = std.io.fixedBufferStream("OK Pleased to meet you\n");
    const r = stream.reader();
    const line = (try readLine(allocator, r)).?;
    defer allocator.free(line);
    try std.testing.expectEqualStrings("OK Pleased to meet you", line);
}

test "readLine with CR LF" {
    const allocator = std.testing.allocator;
    var stream = std.io.fixedBufferStream("OK\r\n");
    const r = stream.reader();
    const line = (try readLine(allocator, r)).?;
    defer allocator.free(line);
    // Note: readLine strips LF but not CR
    try std.testing.expectEqualStrings("OK\r", line);
}

test "readLine EOF" {
    const allocator = std.testing.allocator;
    var stream = std.io.fixedBufferStream("");
    const r = stream.reader();
    const line = try readLine(allocator, r);
    try std.testing.expect(line == null);
}

test "readLine EOF mid-line" {
    const allocator = std.testing.allocator;
    var stream = std.io.fixedBufferStream("partial");
    const r = stream.reader();
    const line = (try readLine(allocator, r)).?;
    defer allocator.free(line);
    try std.testing.expectEqualStrings("partial", line);
}

test "readLine multiple lines" {
    const allocator = std.testing.allocator;
    var stream = std.io.fixedBufferStream("line1\nline2\nline3\n");
    const r = stream.reader();

    const l1 = (try readLine(allocator, r)).?;
    defer allocator.free(l1);
    try std.testing.expectEqualStrings("line1", l1);

    const l2 = (try readLine(allocator, r)).?;
    defer allocator.free(l2);
    try std.testing.expectEqualStrings("line2", l2);

    const l3 = (try readLine(allocator, r)).?;
    defer allocator.free(l3);
    try std.testing.expectEqualStrings("line3", l3);

    const l4 = try readLine(allocator, r);
    try std.testing.expect(l4 == null);
}

test "readFullResponse OK" {
    const allocator = std.testing.allocator;
    var stream = std.io.fixedBufferStream("OK\n");
    const r = stream.reader();

    var resp = try readFullResponse(allocator, r);
    defer resp.deinit(allocator);
    try std.testing.expect(resp.isOk());
    try std.testing.expect(resp.data == null);
}

test "readFullResponse OK with text" {
    const allocator = std.testing.allocator;
    var stream = std.io.fixedBufferStream("OK Pleased to meet you\n");
    const r = stream.reader();

    var resp = try readFullResponse(allocator, r);
    defer resp.deinit(allocator);
    try std.testing.expect(resp.isOk());
}

test "readFullResponse ERR" {
    const allocator = std.testing.allocator;
    var stream = std.io.fixedBufferStream("ERR 100 not found\n");
    const r = stream.reader();

    var resp = try readFullResponse(allocator, r);
    defer resp.deinit(allocator);
    try std.testing.expect(!resp.isOk());
    try std.testing.expectEqual(@as(u32, 100), resp.error_code);
    try std.testing.expectEqualStrings("not found", resp.error_description.?);
}

test "readFullResponse with data lines" {
    const allocator = std.testing.allocator;
    var stream = std.io.fixedBufferStream("D hello\nD  world\nOK\n");
    const r = stream.reader();

    var resp = try readFullResponse(allocator, r);
    defer resp.deinit(allocator);
    try std.testing.expect(resp.isOk());
    try std.testing.expectEqualStrings("hello world", resp.data.?);
}

test "readFullResponse with status lines" {
    const allocator = std.testing.allocator;
    var stream = std.io.fixedBufferStream("S PROGRESS 50/100\nOK\n");
    const r = stream.reader();

    var resp = try readFullResponse(allocator, r);
    defer resp.deinit(allocator);
    try std.testing.expect(resp.isOk());
    try std.testing.expectEqual(@as(usize, 1), resp.status_lines.len);
    try std.testing.expectEqualStrings("PROGRESS", resp.status_lines[0].keyword);
}

test "readFullResponse with comments" {
    const allocator = std.testing.allocator;
    var stream = std.io.fixedBufferStream("# comment\nOK\n");
    const r = stream.reader();

    var resp = try readFullResponse(allocator, r);
    defer resp.deinit(allocator);
    try std.testing.expect(resp.isOk());
}

test "readFullResponse EOF" {
    const allocator = std.testing.allocator;
    var stream = std.io.fixedBufferStream("");
    const r = stream.reader();

    var resp = try readFullResponse(allocator, r);
    defer resp.deinit(allocator);
    try std.testing.expect(!resp.isOk());
}

test "MockAgentConnection basic" {
    const allocator = std.testing.allocator;
    var mock = MockAgentConnection.init(allocator, "OK ready\n");
    defer mock.deinit(allocator);

    var r = mock.reader();
    var w = mock.writer(allocator);

    try w.writeAll("GETINFO version\n");

    const line = (try readLine(allocator, &r)).?;
    defer allocator.free(line);
    try std.testing.expectEqualStrings("OK ready", line);

    try std.testing.expect(mem.indexOf(u8, mock.output.items, "GETINFO version") != null);
}

test "MockAgentConnection sendCommandAndRead" {
    const allocator = std.testing.allocator;
    var mock = MockAgentConnection.init(allocator, "OK\n");
    defer mock.deinit(allocator);

    var r = mock.reader();
    var w = mock.writer(allocator);

    const cmd = gpg_agent.reset();
    var resp = try sendCommandAndRead(allocator, &w, &r, cmd);
    defer resp.deinit(allocator);
    try std.testing.expect(resp.isOk());
}

test "MockAgentConnection checkHaveKey true" {
    const allocator = std.testing.allocator;
    var mock = MockAgentConnection.init(allocator, "OK\n");
    defer mock.deinit(allocator);

    var r = mock.reader();
    var w = mock.writer(allocator);

    const result = try checkHaveKey(allocator, &w, &r, "AABBCCDD11223344AABBCCDD11223344AABBCCDD");
    try std.testing.expect(result);
}

test "MockAgentConnection checkHaveKey false" {
    const allocator = std.testing.allocator;
    var mock = MockAgentConnection.init(allocator, "ERR 67108881 No secret key\n");
    defer mock.deinit(allocator);

    var r = mock.reader();
    var w = mock.writer(allocator);

    const result = try checkHaveKey(allocator, &w, &r, "0000000000000000000000000000000000000000");
    try std.testing.expect(!result);
}

test "MockAgentConnection clearCachedPassphrase" {
    const allocator = std.testing.allocator;
    var mock = MockAgentConnection.init(allocator, "OK\n");
    defer mock.deinit(allocator);

    var r = mock.reader();
    var w = mock.writer(allocator);

    const result = try clearCachedPassphrase(allocator, &w, &r, "test-cache-id");
    try std.testing.expect(result);
}

test "MockAgentConnection getAgentVersion" {
    const allocator = std.testing.allocator;
    var mock = MockAgentConnection.init(allocator, "D 2.4.3\nOK\n");
    defer mock.deinit(allocator);

    var r = mock.reader();
    var w = mock.writer(allocator);

    const version = try getAgentVersion(allocator, &w, &r);
    defer if (version) |v| allocator.free(v);
    try std.testing.expect(version != null);
    try std.testing.expectEqualStrings("2.4.3", version.?);
}

test "MockAgentConnection performSign OK" {
    const allocator = std.testing.allocator;
    // Three OK responses for SIGKEY, SETHASH, PKSIGN
    var mock = MockAgentConnection.init(allocator, "OK\nOK\nD AABB\nOK\n");
    defer mock.deinit(allocator);

    var r = mock.reader();
    var w = mock.writer(allocator);

    const sig = try performSign(allocator, &w, &r, "GRIP", 8, "DEADBEEF");
    defer if (sig) |s| allocator.free(s);
    try std.testing.expect(sig != null);
}

test "MockAgentConnection performSign failure" {
    const allocator = std.testing.allocator;
    // SIGKEY fails
    var mock = MockAgentConnection.init(allocator, "ERR 100 no key\n");
    defer mock.deinit(allocator);

    var r = mock.reader();
    var w = mock.writer(allocator);

    const sig = try performSign(allocator, &w, &r, "GRIP", 8, "DEADBEEF");
    try std.testing.expect(sig == null);
}

test "MockAgentConnection setOption" {
    const allocator = std.testing.allocator;
    var mock = MockAgentConnection.init(allocator, "OK\n");
    defer mock.deinit(allocator);

    var r = mock.reader();
    var w = mock.writer(allocator);

    const ok = try setOption(allocator, &w, &r, "display", ":0");
    try std.testing.expect(ok);
    try std.testing.expect(mem.indexOf(u8, mock.output.items, "OPTION display=:0") != null);
}

test "isValidSocketPath" {
    try std.testing.expect(isValidSocketPath("/home/user/.gnupg/S.gpg-agent"));
    try std.testing.expect(isValidSocketPath("/tmp/socket"));
    try std.testing.expect(!isValidSocketPath(""));
    try std.testing.expect(!isValidSocketPath("relative/path"));
    try std.testing.expect(!isValidSocketPath("/path/to/dir/"));
}

test "concatenateData" {
    const allocator = std.testing.allocator;

    // Empty
    const empty = try concatenateData(allocator, &.{});
    try std.testing.expect(empty == null);

    // Single part
    const single = (try concatenateData(allocator, &.{@as([]const u8, "hello")})).?;
    defer allocator.free(single);
    try std.testing.expectEqualStrings("hello", single);

    // Multiple parts
    const multi = (try concatenateData(allocator, &.{
        @as([]const u8, "hello"),
        @as([]const u8, " "),
        @as([]const u8, "world"),
    })).?;
    defer allocator.free(multi);
    try std.testing.expectEqualStrings("hello world", multi);
}

test "writeLine adds LF" {
    const allocator = std.testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    var w = buf.writer(allocator);
    try writeLine(&w, "RESET");
    try std.testing.expectEqualStrings("RESET\n", buf.items);
}

test "writeLine does not double LF" {
    const allocator = std.testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    var w = buf.writer(allocator);
    try writeLine(&w, "RESET\n");
    try std.testing.expectEqualStrings("RESET\n", buf.items);
}
