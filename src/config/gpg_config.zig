// SPDX-License-Identifier: MIT
//! GnuPG configuration file parser and serializer.
//!
//! Parses gpg.conf-style configuration files used by GnuPG. These files
//! contain one option per line, with optional values separated by whitespace.
//! Lines starting with '#' are comments.
//!
//! Supported directives:
//!   - default-key <KEYID>
//!   - keyserver <URI>
//!   - armor (boolean flag)
//!   - compress-algo <ALGO>
//!   - cipher-algo <ALGO>
//!   - digest-algo <ALGO>
//!   - personal-cipher-preferences <ALGO> [<ALGO>...]
//!   - personal-digest-preferences <ALGO> [<ALGO>...]
//!   - personal-compress-preferences <ALGO> [<ALGO>...]
//!   - keyserver-options <KEY>=<VALUE> [...]
//!   - auto-key-retrieve (boolean flag)
//!   - use-agent (boolean flag)
//!   - no-emit-version (boolean flag)
//!   - no-comments (boolean flag)
//!   - throw-keyids (boolean flag)
//!   - s2k-cipher-algo <ALGO>
//!   - s2k-digest-algo <ALGO>
//!   - s2k-mode <MODE>
//!   - s2k-count <COUNT>
//!   - cert-digest-algo <ALGO>
//!   - default-recipient <KEYID>
//!   - default-recipient-self (boolean flag)
//!
//! Unknown directives are stored in the extra_options map.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const enums = @import("../types/enums.zig");
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const CompressionAlgorithm = enums.CompressionAlgorithm;

// ---------------------------------------------------------------------------
// Keyserver options
// ---------------------------------------------------------------------------

/// Options controlling keyserver behavior.
pub const KeyserverOptions = struct {
    /// Automatically retrieve keys from keyserver when verifying signatures.
    auto_key_retrieve: bool = false,
    /// Honor the preferred keyserver URL in a key's self-signature.
    honor_keyserver_url: bool = true,
    /// Include revoked keys in search results.
    include_revoked: bool = false,
    /// Include subkeys in search results.
    include_subkeys: bool = false,
    /// Use temporary files for keyserver communication.
    use_temp_files: bool = false,
    /// HTTP proxy for keyserver connections.
    http_proxy: ?[]const u8 = null,

    /// Parse keyserver-options from a comma-separated or space-separated value string.
    pub fn parse(value: []const u8) KeyserverOptions {
        var opts = KeyserverOptions{};
        var iter = TokenIterator.init(value);
        while (iter.next()) |token| {
            if (mem.eql(u8, token, "auto-key-retrieve")) {
                opts.auto_key_retrieve = true;
            } else if (mem.eql(u8, token, "no-auto-key-retrieve")) {
                opts.auto_key_retrieve = false;
            } else if (mem.eql(u8, token, "honor-keyserver-url")) {
                opts.honor_keyserver_url = true;
            } else if (mem.eql(u8, token, "no-honor-keyserver-url")) {
                opts.honor_keyserver_url = false;
            } else if (mem.eql(u8, token, "include-revoked")) {
                opts.include_revoked = true;
            } else if (mem.eql(u8, token, "no-include-revoked")) {
                opts.include_revoked = false;
            } else if (mem.eql(u8, token, "include-subkeys")) {
                opts.include_subkeys = true;
            } else if (mem.eql(u8, token, "no-include-subkeys")) {
                opts.include_subkeys = false;
            }
        }
        return opts;
    }

    /// Serialize keyserver options back to a space-separated string.
    pub fn serialize(self: KeyserverOptions, allocator: Allocator) ![]u8 {
        var parts: std.ArrayList([]const u8) = .empty;
        defer parts.deinit(allocator);

        if (self.auto_key_retrieve) try parts.append(allocator, "auto-key-retrieve");
        if (!self.honor_keyserver_url) try parts.append(allocator, "no-honor-keyserver-url");
        if (self.include_revoked) try parts.append(allocator, "include-revoked");
        if (self.include_subkeys) try parts.append(allocator, "include-subkeys");

        if (parts.items.len == 0) {
            const result = try allocator.alloc(u8, 0);
            return result;
        }

        var total_len: usize = 0;
        for (parts.items, 0..) |part, i| {
            total_len += part.len;
            if (i < parts.items.len - 1) total_len += 1;
        }

        const result = try allocator.alloc(u8, total_len);
        var offset: usize = 0;
        for (parts.items, 0..) |part, i| {
            @memcpy(result[offset .. offset + part.len], part);
            offset += part.len;
            if (i < parts.items.len - 1) {
                result[offset] = ' ';
                offset += 1;
            }
        }
        return result;
    }
};

// ---------------------------------------------------------------------------
// Token iterator (handles comma and space separation)
// ---------------------------------------------------------------------------

const TokenIterator = struct {
    data: []const u8,
    pos: usize,

    fn init(data: []const u8) TokenIterator {
        return .{ .data = data, .pos = 0 };
    }

    fn next(self: *TokenIterator) ?[]const u8 {
        // Skip separators
        while (self.pos < self.data.len and (self.data[self.pos] == ' ' or
            self.data[self.pos] == ',' or
            self.data[self.pos] == '\t'))
        {
            self.pos += 1;
        }
        if (self.pos >= self.data.len) return null;

        const start = self.pos;
        while (self.pos < self.data.len and
            self.data[self.pos] != ' ' and
            self.data[self.pos] != ',' and
            self.data[self.pos] != '\t')
        {
            self.pos += 1;
        }
        if (self.pos > start) {
            return self.data[start..self.pos];
        }
        return null;
    }
};

// ---------------------------------------------------------------------------
// GpgConfig
// ---------------------------------------------------------------------------

/// Parsed GnuPG configuration.
///
/// Represents the contents of a gpg.conf file. Boolean flags are set when
/// the corresponding directive is present. Algorithm preferences are stored
/// as slices of the corresponding enum types.
pub const GpgConfig = struct {
    /// Default key ID for signing operations.
    default_key: ?[]const u8 = null,
    /// Keyserver URI (e.g., "hkps://keys.openpgp.org").
    keyserver: ?[]const u8 = null,
    /// Whether to ASCII-armor output by default.
    armor: bool = false,
    /// Override compression algorithm.
    compress_algo: ?CompressionAlgorithm = null,
    /// Override symmetric cipher algorithm.
    cipher_algo: ?SymmetricAlgorithm = null,
    /// Override digest (hash) algorithm.
    digest_algo: ?HashAlgorithm = null,
    /// Personal cipher preferences (ordered).
    personal_cipher_preferences: []SymmetricAlgorithm = &.{},
    /// Personal digest preferences (ordered).
    personal_digest_preferences: []HashAlgorithm = &.{},
    /// Personal compress preferences (ordered).
    personal_compress_preferences: []CompressionAlgorithm = &.{},
    /// Keyserver-specific options.
    keyserver_options: KeyserverOptions = .{},
    /// Automatically retrieve keys when verifying.
    auto_key_retrieve: bool = false,
    /// Use gpg-agent for passphrase caching.
    use_agent: bool = false,
    /// Do not emit version header in armor output.
    no_emit_version: bool = false,
    /// Do not emit comment headers in armor output.
    no_comments: bool = false,
    /// Throw away recipient key IDs in encrypted messages.
    throw_keyids: bool = false,
    /// S2K cipher algorithm override.
    s2k_cipher_algo: ?SymmetricAlgorithm = null,
    /// S2K digest algorithm override.
    s2k_digest_algo: ?HashAlgorithm = null,
    /// S2K mode (0=simple, 1=salted, 3=iterated+salted).
    s2k_mode: ?u8 = null,
    /// S2K iteration count.
    s2k_count: ?u32 = null,
    /// Certificate digest algorithm.
    cert_digest_algo: ?HashAlgorithm = null,
    /// Default recipient key ID.
    default_recipient: ?[]const u8 = null,
    /// Use own key as default recipient.
    default_recipient_self: bool = false,
    /// Additional options not explicitly modeled.
    extra_options: std.StringHashMap([]const u8),
    /// Allocator used for dynamic allocations.
    _allocator: Allocator,

    /// Parse a GnuPG configuration from file contents.
    ///
    /// Each line is either:
    ///   - Empty or whitespace-only (ignored)
    ///   - A comment starting with '#' (ignored)
    ///   - A directive: <name> [<value>]
    pub fn parse(allocator: Allocator, content: []const u8) !GpgConfig {
        var config = GpgConfig{
            .extra_options = std.StringHashMap([]const u8).init(allocator),
            ._allocator = allocator,
        };
        errdefer config.deinit();

        var line_start: usize = 0;
        while (line_start < content.len) {
            // Find end of line
            var line_end = line_start;
            while (line_end < content.len and content[line_end] != '\n') {
                line_end += 1;
            }

            const line = mem.trim(u8, content[line_start..line_end], &[_]u8{ ' ', '\t', '\r' });
            line_start = line_end + 1;

            // Skip empty lines and comments
            if (line.len == 0) continue;
            if (line[0] == '#') continue;

            // Split into directive and value
            const directive_end = mem.indexOfAny(u8, line, &[_]u8{ ' ', '\t' }) orelse line.len;
            const directive = line[0..directive_end];
            const value = if (directive_end < line.len)
                mem.trim(u8, line[directive_end..], &[_]u8{ ' ', '\t' })
            else
                "";

            try config.processDirective(allocator, directive, value);
        }

        return config;
    }

    /// Parse a GnuPG configuration from a file path.
    ///
    /// Reads the file contents and delegates to parse().
    pub fn parseFile(allocator: Allocator, path: []const u8) !GpgConfig {
        const file = std.fs.openFileAbsolute(path, .{}) catch |err| {
            return switch (err) {
                error.FileNotFound => error.FileNotFound,
                else => error.AccessDenied,
            };
        };
        defer file.close();

        const content = file.readToEndAlloc(allocator, 1024 * 1024) catch {
            return error.OutOfMemory;
        };
        defer allocator.free(content);

        return parse(allocator, content);
    }

    /// Serialize the configuration back to gpg.conf format.
    pub fn serialize(self: *const GpgConfig, allocator: Allocator) ![]u8 {
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(allocator);

        try appendLine(allocator, &output, "# GnuPG configuration (generated by zpgp)");

        if (self.default_key) |key| {
            try appendDirective(allocator, &output, "default-key", key);
        }

        if (self.keyserver) |ks| {
            try appendDirective(allocator, &output, "keyserver", ks);
        }

        if (self.armor) {
            try appendLine(allocator, &output, "armor");
        }

        if (self.compress_algo) |algo| {
            try appendDirective(allocator, &output, "compress-algo", algoNameCompression(algo));
        }

        if (self.cipher_algo) |algo| {
            try appendDirective(allocator, &output, "cipher-algo", algoNameSymmetric(algo));
        }

        if (self.digest_algo) |algo| {
            try appendDirective(allocator, &output, "digest-algo", algoNameHash(algo));
        }

        if (self.personal_cipher_preferences.len > 0) {
            try appendAlgoListSymmetric(allocator, &output, "personal-cipher-preferences", self.personal_cipher_preferences);
        }

        if (self.personal_digest_preferences.len > 0) {
            try appendAlgoListHash(allocator, &output, "personal-digest-preferences", self.personal_digest_preferences);
        }

        if (self.personal_compress_preferences.len > 0) {
            try appendAlgoListCompression(allocator, &output, "personal-compress-preferences", self.personal_compress_preferences);
        }

        if (self.auto_key_retrieve) {
            try appendLine(allocator, &output, "auto-key-retrieve");
        }

        if (self.use_agent) {
            try appendLine(allocator, &output, "use-agent");
        }

        if (self.no_emit_version) {
            try appendLine(allocator, &output, "no-emit-version");
        }

        if (self.no_comments) {
            try appendLine(allocator, &output, "no-comments");
        }

        if (self.throw_keyids) {
            try appendLine(allocator, &output, "throw-keyids");
        }

        if (self.s2k_cipher_algo) |algo| {
            try appendDirective(allocator, &output, "s2k-cipher-algo", algoNameSymmetric(algo));
        }

        if (self.s2k_digest_algo) |algo| {
            try appendDirective(allocator, &output, "s2k-digest-algo", algoNameHash(algo));
        }

        if (self.s2k_mode) |mode| {
            var buf: [4]u8 = undefined;
            const mode_str = std.fmt.bufPrint(&buf, "{d}", .{mode}) catch "0";
            try appendDirective(allocator, &output, "s2k-mode", mode_str);
        }

        if (self.cert_digest_algo) |algo| {
            try appendDirective(allocator, &output, "cert-digest-algo", algoNameHash(algo));
        }

        if (self.default_recipient) |r| {
            try appendDirective(allocator, &output, "default-recipient", r);
        }

        if (self.default_recipient_self) {
            try appendLine(allocator, &output, "default-recipient-self");
        }

        // Extra options
        var it = self.extra_options.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.len > 0) {
                try appendDirective(allocator, &output, entry.key_ptr.*, entry.value_ptr.*);
            } else {
                try appendLine(allocator, &output, entry.key_ptr.*);
            }
        }

        return output.toOwnedSlice(allocator);
    }

    /// Free all memory associated with this configuration.
    pub fn deinit(self: *GpgConfig) void {
        const allocator = self._allocator;

        if (self.default_key) |key| allocator.free(key);
        if (self.keyserver) |ks| allocator.free(ks);
        if (self.default_recipient) |r| allocator.free(r);

        if (self.personal_cipher_preferences.len > 0) {
            allocator.free(self.personal_cipher_preferences);
        }
        if (self.personal_digest_preferences.len > 0) {
            allocator.free(self.personal_digest_preferences);
        }
        if (self.personal_compress_preferences.len > 0) {
            allocator.free(self.personal_compress_preferences);
        }

        if (self.keyserver_options.http_proxy) |proxy| allocator.free(proxy);

        // Free extra options
        var it = self.extra_options.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            if (entry.value_ptr.*.len > 0) {
                allocator.free(entry.value_ptr.*);
            }
        }
        self.extra_options.deinit();
    }

    /// Get an option value by directive name.
    pub fn getOption(self: *const GpgConfig, name: []const u8) ?[]const u8 {
        if (mem.eql(u8, name, "default-key")) return self.default_key;
        if (mem.eql(u8, name, "keyserver")) return self.keyserver;
        if (mem.eql(u8, name, "default-recipient")) return self.default_recipient;
        return self.extra_options.get(name);
    }

    /// Check if a boolean option is set.
    pub fn isEnabled(self: *const GpgConfig, name: []const u8) bool {
        if (mem.eql(u8, name, "armor")) return self.armor;
        if (mem.eql(u8, name, "auto-key-retrieve")) return self.auto_key_retrieve;
        if (mem.eql(u8, name, "use-agent")) return self.use_agent;
        if (mem.eql(u8, name, "no-emit-version")) return self.no_emit_version;
        if (mem.eql(u8, name, "no-comments")) return self.no_comments;
        if (mem.eql(u8, name, "throw-keyids")) return self.throw_keyids;
        if (mem.eql(u8, name, "default-recipient-self")) return self.default_recipient_self;
        return self.extra_options.contains(name);
    }

    // -----------------------------------------------------------------------
    // Internal directive processing
    // -----------------------------------------------------------------------

    fn processDirective(self: *GpgConfig, allocator: Allocator, directive: []const u8, value: []const u8) !void {
        if (mem.eql(u8, directive, "default-key")) {
            if (self.default_key) |old| allocator.free(old);
            self.default_key = try allocator.dupe(u8, value);
        } else if (mem.eql(u8, directive, "keyserver")) {
            if (self.keyserver) |old| allocator.free(old);
            self.keyserver = try allocator.dupe(u8, value);
        } else if (mem.eql(u8, directive, "armor")) {
            self.armor = true;
        } else if (mem.eql(u8, directive, "no-armor")) {
            self.armor = false;
        } else if (mem.eql(u8, directive, "compress-algo")) {
            self.compress_algo = parseCompressionAlgo(value);
        } else if (mem.eql(u8, directive, "cipher-algo")) {
            self.cipher_algo = parseSymmetricAlgo(value);
        } else if (mem.eql(u8, directive, "digest-algo")) {
            self.digest_algo = parseHashAlgo(value);
        } else if (mem.eql(u8, directive, "personal-cipher-preferences")) {
            if (self.personal_cipher_preferences.len > 0) {
                allocator.free(self.personal_cipher_preferences);
            }
            self.personal_cipher_preferences = try parseSymmetricAlgoList(allocator, value);
        } else if (mem.eql(u8, directive, "personal-digest-preferences")) {
            if (self.personal_digest_preferences.len > 0) {
                allocator.free(self.personal_digest_preferences);
            }
            self.personal_digest_preferences = try parseHashAlgoList(allocator, value);
        } else if (mem.eql(u8, directive, "personal-compress-preferences")) {
            if (self.personal_compress_preferences.len > 0) {
                allocator.free(self.personal_compress_preferences);
            }
            self.personal_compress_preferences = try parseCompressionAlgoList(allocator, value);
        } else if (mem.eql(u8, directive, "keyserver-options")) {
            self.keyserver_options = KeyserverOptions.parse(value);
        } else if (mem.eql(u8, directive, "auto-key-retrieve")) {
            self.auto_key_retrieve = true;
        } else if (mem.eql(u8, directive, "use-agent")) {
            self.use_agent = true;
        } else if (mem.eql(u8, directive, "no-emit-version")) {
            self.no_emit_version = true;
        } else if (mem.eql(u8, directive, "no-comments")) {
            self.no_comments = true;
        } else if (mem.eql(u8, directive, "throw-keyids")) {
            self.throw_keyids = true;
        } else if (mem.eql(u8, directive, "s2k-cipher-algo")) {
            self.s2k_cipher_algo = parseSymmetricAlgo(value);
        } else if (mem.eql(u8, directive, "s2k-digest-algo")) {
            self.s2k_digest_algo = parseHashAlgo(value);
        } else if (mem.eql(u8, directive, "s2k-mode")) {
            self.s2k_mode = std.fmt.parseInt(u8, value, 10) catch null;
        } else if (mem.eql(u8, directive, "s2k-count")) {
            self.s2k_count = std.fmt.parseInt(u32, value, 10) catch null;
        } else if (mem.eql(u8, directive, "cert-digest-algo")) {
            self.cert_digest_algo = parseHashAlgo(value);
        } else if (mem.eql(u8, directive, "default-recipient")) {
            if (self.default_recipient) |old| allocator.free(old);
            self.default_recipient = try allocator.dupe(u8, value);
        } else if (mem.eql(u8, directive, "default-recipient-self")) {
            self.default_recipient_self = true;
        } else {
            // Store unknown directives in extra_options
            const key = try allocator.dupe(u8, directive);
            errdefer allocator.free(key);
            const val = if (value.len > 0) try allocator.dupe(u8, value) else try allocator.alloc(u8, 0);
            errdefer allocator.free(val);
            try self.extra_options.put(key, val);
        }
    }
};

// ---------------------------------------------------------------------------
// Algorithm name parsing
// ---------------------------------------------------------------------------

/// Parse a symmetric algorithm name (case-insensitive).
pub fn parseSymmetricAlgo(name: []const u8) ?SymmetricAlgorithm {
    if (asciiEql(name, "AES") or asciiEql(name, "AES128")) return .aes128;
    if (asciiEql(name, "AES192")) return .aes192;
    if (asciiEql(name, "AES256")) return .aes256;
    if (asciiEql(name, "3DES") or asciiEql(name, "TRIPLEDES")) return .triple_des;
    if (asciiEql(name, "CAST5")) return .cast5;
    if (asciiEql(name, "BLOWFISH")) return .blowfish;
    if (asciiEql(name, "IDEA")) return .idea;
    if (asciiEql(name, "TWOFISH")) return .twofish;
    if (asciiEql(name, "CAMELLIA128")) return .camellia128;
    if (asciiEql(name, "CAMELLIA192")) return .camellia192;
    if (asciiEql(name, "CAMELLIA256")) return .camellia256;
    return null;
}

/// Parse a hash algorithm name (case-insensitive).
pub fn parseHashAlgo(name: []const u8) ?HashAlgorithm {
    if (asciiEql(name, "SHA256") or asciiEql(name, "SHA-256")) return .sha256;
    if (asciiEql(name, "SHA512") or asciiEql(name, "SHA-512")) return .sha512;
    if (asciiEql(name, "SHA384") or asciiEql(name, "SHA-384")) return .sha384;
    if (asciiEql(name, "SHA224") or asciiEql(name, "SHA-224")) return .sha224;
    if (asciiEql(name, "SHA1") or asciiEql(name, "SHA-1")) return .sha1;
    if (asciiEql(name, "RIPEMD160")) return .ripemd160;
    if (asciiEql(name, "MD5")) return .md5;
    return null;
}

/// Parse a compression algorithm name (case-insensitive).
pub fn parseCompressionAlgo(name: []const u8) ?CompressionAlgorithm {
    if (asciiEql(name, "UNCOMPRESSED") or asciiEql(name, "NONE")) return .uncompressed;
    if (asciiEql(name, "ZIP")) return .zip;
    if (asciiEql(name, "ZLIB")) return .zlib;
    if (asciiEql(name, "BZIP2")) return .bzip2;
    return null;
}

/// Parse a space-separated list of symmetric algorithm names.
fn parseSymmetricAlgoList(allocator: Allocator, value: []const u8) ![]SymmetricAlgorithm {
    var result: std.ArrayList(SymmetricAlgorithm) = .empty;
    errdefer result.deinit(allocator);

    var iter = TokenIterator.init(value);
    while (iter.next()) |token| {
        if (parseSymmetricAlgo(token)) |algo| {
            try result.append(allocator, algo);
        }
    }

    return result.toOwnedSlice(allocator);
}

/// Parse a space-separated list of hash algorithm names.
fn parseHashAlgoList(allocator: Allocator, value: []const u8) ![]HashAlgorithm {
    var result: std.ArrayList(HashAlgorithm) = .empty;
    errdefer result.deinit(allocator);

    var iter = TokenIterator.init(value);
    while (iter.next()) |token| {
        if (parseHashAlgo(token)) |algo| {
            try result.append(allocator, algo);
        }
    }

    return result.toOwnedSlice(allocator);
}

/// Parse a space-separated list of compression algorithm names.
fn parseCompressionAlgoList(allocator: Allocator, value: []const u8) ![]CompressionAlgorithm {
    var result: std.ArrayList(CompressionAlgorithm) = .empty;
    errdefer result.deinit(allocator);

    var iter = TokenIterator.init(value);
    while (iter.next()) |token| {
        if (parseCompressionAlgo(token)) |algo| {
            try result.append(allocator, algo);
        }
    }

    return result.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Algorithm name serialization
// ---------------------------------------------------------------------------

fn algoNameSymmetric(algo: SymmetricAlgorithm) []const u8 {
    return switch (algo) {
        .aes128 => "AES",
        .aes192 => "AES192",
        .aes256 => "AES256",
        .triple_des => "3DES",
        .cast5 => "CAST5",
        .blowfish => "BLOWFISH",
        .idea => "IDEA",
        .twofish => "TWOFISH",
        .camellia128 => "CAMELLIA128",
        .camellia192 => "CAMELLIA192",
        .camellia256 => "CAMELLIA256",
        .plaintext => "NONE",
        _ => "UNKNOWN",
    };
}

fn algoNameHash(algo: HashAlgorithm) []const u8 {
    return switch (algo) {
        .sha256 => "SHA256",
        .sha512 => "SHA512",
        .sha384 => "SHA384",
        .sha224 => "SHA224",
        .sha1 => "SHA1",
        .ripemd160 => "RIPEMD160",
        .md5 => "MD5",
        _ => "UNKNOWN",
    };
}

fn algoNameCompression(algo: CompressionAlgorithm) []const u8 {
    return switch (algo) {
        .uncompressed => "Uncompressed",
        .zip => "ZIP",
        .zlib => "ZLIB",
        .bzip2 => "BZIP2",
        _ => "UNKNOWN",
    };
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

fn appendLine(allocator: Allocator, output: *std.ArrayList(u8), line: []const u8) !void {
    try output.appendSlice(allocator, line);
    try output.append(allocator, '\n');
}

fn appendDirective(allocator: Allocator, output: *std.ArrayList(u8), directive: []const u8, value: []const u8) !void {
    try output.appendSlice(allocator, directive);
    try output.append(allocator, ' ');
    try output.appendSlice(allocator, value);
    try output.append(allocator, '\n');
}

fn appendAlgoListSymmetric(allocator: Allocator, output: *std.ArrayList(u8), directive: []const u8, algos: []SymmetricAlgorithm) !void {
    try output.appendSlice(allocator, directive);
    for (algos) |algo| {
        try output.append(allocator, ' ');
        try output.appendSlice(allocator, algoNameSymmetric(algo));
    }
    try output.append(allocator, '\n');
}

fn appendAlgoListHash(allocator: Allocator, output: *std.ArrayList(u8), directive: []const u8, algos: []HashAlgorithm) !void {
    try output.appendSlice(allocator, directive);
    for (algos) |algo| {
        try output.append(allocator, ' ');
        try output.appendSlice(allocator, algoNameHash(algo));
    }
    try output.append(allocator, '\n');
}

fn appendAlgoListCompression(allocator: Allocator, output: *std.ArrayList(u8), directive: []const u8, algos: []CompressionAlgorithm) !void {
    try output.appendSlice(allocator, directive);
    for (algos) |algo| {
        try output.append(allocator, ' ');
        try output.appendSlice(allocator, algoNameCompression(algo));
    }
    try output.append(allocator, '\n');
}

// ---------------------------------------------------------------------------
// Case-insensitive comparison
// ---------------------------------------------------------------------------

fn asciiEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (asciiToLower(ca) != asciiToLower(cb)) return false;
    }
    return true;
}

fn asciiToLower(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "gpg_config: parse empty config" {
    const allocator = std.testing.allocator;
    var config = try GpgConfig.parse(allocator, "");
    defer config.deinit();

    try std.testing.expect(config.default_key == null);
    try std.testing.expect(config.keyserver == null);
    try std.testing.expect(!config.armor);
}

test "gpg_config: parse comments and blank lines" {
    const allocator = std.testing.allocator;
    const content =
        \\# This is a comment
        \\
        \\# Another comment
        \\armor
        \\
    ;
    var config = try GpgConfig.parse(allocator, content);
    defer config.deinit();

    try std.testing.expect(config.armor);
}

test "gpg_config: parse basic directives" {
    const allocator = std.testing.allocator;
    const content =
        \\default-key ABC123
        \\keyserver hkps://keys.openpgp.org
        \\armor
        \\cipher-algo AES256
        \\digest-algo SHA512
        \\compress-algo ZLIB
        \\use-agent
        \\auto-key-retrieve
        \\no-emit-version
        \\no-comments
        \\
    ;
    var config = try GpgConfig.parse(allocator, content);
    defer config.deinit();

    try std.testing.expectEqualStrings("ABC123", config.default_key.?);
    try std.testing.expectEqualStrings("hkps://keys.openpgp.org", config.keyserver.?);
    try std.testing.expect(config.armor);
    try std.testing.expect(config.cipher_algo.? == .aes256);
    try std.testing.expect(config.digest_algo.? == .sha512);
    try std.testing.expect(config.compress_algo.? == .zlib);
    try std.testing.expect(config.use_agent);
    try std.testing.expect(config.auto_key_retrieve);
    try std.testing.expect(config.no_emit_version);
    try std.testing.expect(config.no_comments);
}

test "gpg_config: parse personal preferences" {
    const allocator = std.testing.allocator;
    const content =
        \\personal-cipher-preferences AES256 AES192 AES
        \\personal-digest-preferences SHA512 SHA256
        \\personal-compress-preferences ZLIB ZIP
        \\
    ;
    var config = try GpgConfig.parse(allocator, content);
    defer config.deinit();

    try std.testing.expect(config.personal_cipher_preferences.len == 3);
    try std.testing.expect(config.personal_cipher_preferences[0] == .aes256);
    try std.testing.expect(config.personal_cipher_preferences[1] == .aes192);
    try std.testing.expect(config.personal_cipher_preferences[2] == .aes128);

    try std.testing.expect(config.personal_digest_preferences.len == 2);
    try std.testing.expect(config.personal_digest_preferences[0] == .sha512);
    try std.testing.expect(config.personal_digest_preferences[1] == .sha256);

    try std.testing.expect(config.personal_compress_preferences.len == 2);
    try std.testing.expect(config.personal_compress_preferences[0] == .zlib);
    try std.testing.expect(config.personal_compress_preferences[1] == .zip);
}

test "gpg_config: parse keyserver options" {
    const allocator = std.testing.allocator;
    const content =
        \\keyserver-options auto-key-retrieve no-honor-keyserver-url include-revoked
        \\
    ;
    var config = try GpgConfig.parse(allocator, content);
    defer config.deinit();

    try std.testing.expect(config.keyserver_options.auto_key_retrieve);
    try std.testing.expect(!config.keyserver_options.honor_keyserver_url);
    try std.testing.expect(config.keyserver_options.include_revoked);
}

test "gpg_config: parse s2k options" {
    const allocator = std.testing.allocator;
    const content =
        \\s2k-cipher-algo AES256
        \\s2k-digest-algo SHA512
        \\s2k-mode 3
        \\s2k-count 65536
        \\
    ;
    var config = try GpgConfig.parse(allocator, content);
    defer config.deinit();

    try std.testing.expect(config.s2k_cipher_algo.? == .aes256);
    try std.testing.expect(config.s2k_digest_algo.? == .sha512);
    try std.testing.expect(config.s2k_mode.? == 3);
    try std.testing.expect(config.s2k_count.? == 65536);
}

test "gpg_config: parse unknown directives" {
    const allocator = std.testing.allocator;
    const content =
        \\custom-option some-value
        \\
    ;
    var config = try GpgConfig.parse(allocator, content);
    defer config.deinit();

    const val = config.extra_options.get("custom-option");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("some-value", val.?);
}

test "gpg_config: isEnabled checks" {
    const allocator = std.testing.allocator;
    const content =
        \\armor
        \\use-agent
        \\
    ;
    var config = try GpgConfig.parse(allocator, content);
    defer config.deinit();

    try std.testing.expect(config.isEnabled("armor"));
    try std.testing.expect(config.isEnabled("use-agent"));
    try std.testing.expect(!config.isEnabled("throw-keyids"));
}

test "gpg_config: getOption" {
    const allocator = std.testing.allocator;
    const content =
        \\default-key DEADBEEF
        \\
    ;
    var config = try GpgConfig.parse(allocator, content);
    defer config.deinit();

    try std.testing.expectEqualStrings("DEADBEEF", config.getOption("default-key").?);
    try std.testing.expect(config.getOption("keyserver") == null);
}

test "gpg_config: serialize round-trip" {
    const allocator = std.testing.allocator;
    const content =
        \\default-key ABC123
        \\armor
        \\cipher-algo AES256
        \\use-agent
        \\
    ;
    var config = try GpgConfig.parse(allocator, content);
    defer config.deinit();

    const serialized = try config.serialize(allocator);
    defer allocator.free(serialized);

    // Parse the serialized output again
    var config2 = try GpgConfig.parse(allocator, serialized);
    defer config2.deinit();

    try std.testing.expectEqualStrings("ABC123", config2.default_key.?);
    try std.testing.expect(config2.armor);
    try std.testing.expect(config2.cipher_algo.? == .aes256);
    try std.testing.expect(config2.use_agent);
}

test "gpg_config: algorithm name parsing case insensitive" {
    try std.testing.expect(parseSymmetricAlgo("aes256").? == .aes256);
    try std.testing.expect(parseSymmetricAlgo("AES256").? == .aes256);
    try std.testing.expect(parseSymmetricAlgo("Aes256").? == .aes256);

    try std.testing.expect(parseHashAlgo("sha256").? == .sha256);
    try std.testing.expect(parseHashAlgo("SHA256").? == .sha256);
    try std.testing.expect(parseHashAlgo("SHA-256").? == .sha256);

    try std.testing.expect(parseCompressionAlgo("zlib").? == .zlib);
    try std.testing.expect(parseCompressionAlgo("ZLIB").? == .zlib);
    try std.testing.expect(parseCompressionAlgo("none").? == .uncompressed);
}

test "gpg_config: keyserver options serialize" {
    const allocator = std.testing.allocator;
    const opts = KeyserverOptions{
        .auto_key_retrieve = true,
        .honor_keyserver_url = false,
        .include_revoked = true,
    };
    const serialized = try opts.serialize(allocator);
    defer allocator.free(serialized);

    // Parse back
    const parsed = KeyserverOptions.parse(serialized);
    try std.testing.expect(parsed.auto_key_retrieve);
    try std.testing.expect(!parsed.honor_keyserver_url);
    try std.testing.expect(parsed.include_revoked);
}
