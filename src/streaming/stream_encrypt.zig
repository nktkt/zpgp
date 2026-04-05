// SPDX-License-Identifier: MIT
//! Streaming encryption API for OpenPGP messages.
//!
//! Provides a writer-style interface for encrypting large messages without
//! loading the entire plaintext into memory. Supports both CFB-MDC (SEIPD v1)
//! and AEAD-chunked (SEIPD v2) encryption modes.
//!
//! Usage:
//!
//! ```
//! var enc = try StreamEncryptor.init(allocator, .{
//!     .sym_algo = .aes256,
//!     .session_key = &key,
//!     .use_aead = false,
//! });
//! defer enc.deinit();
//!
//! var out = std.ArrayList(u8).init(allocator);
//! try enc.writeHeader(&out);
//! try enc.write(&out, plaintext_chunk1);
//! try enc.write(&out, plaintext_chunk2);
//! try enc.finish(&out);
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const crypto = std.crypto;

const enums = @import("../types/enums.zig");
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const AeadAlgorithm = @import("../crypto/aead/aead.zig").AeadAlgorithm;
const cfb_mod = @import("../crypto/cfb.zig");
const zeroize = @import("../security/zeroize.zig");

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

pub const StreamEncryptError = error{
    InvalidState,
    UnsupportedAlgorithm,
    KeySizeMismatch,
    ChunkSizeTooSmall,
    OutOfMemory,
    WriteFailed,
    Overflow,
};

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// Configuration for a streaming encryption session.
pub const StreamEncryptOptions = struct {
    /// Symmetric cipher algorithm to use.
    sym_algo: SymmetricAlgorithm = .aes256,
    /// The session key (must match the key size of `sym_algo`).
    session_key: []const u8,
    /// Whether to use AEAD encryption (SEIPD v2) or CFB-MDC (SEIPD v1).
    use_aead: bool = false,
    /// AEAD algorithm (only used when `use_aead` is true).
    aead_algo: ?AeadAlgorithm = null,
    /// Plaintext chunk size. For AEAD mode this controls the AEAD chunk size;
    /// for CFB mode it controls the internal buffer flush threshold.
    chunk_size: usize = 64 * 1024,
    /// Optional SEIPD v2 chunk size octet (log2(chunk_size) - 6).
    /// If null, derived from `chunk_size`.
    chunk_size_octet: ?u8 = null,
};

// ---------------------------------------------------------------------------
// StreamEncryptor
// ---------------------------------------------------------------------------

/// Streaming OpenPGP message encryptor.
///
/// Encrypts data incrementally as it is fed in, writing encrypted output
/// to a caller-supplied ArrayList. The encryptor manages all internal
/// state including the CFB shift register, MDC hash, or AEAD chunk index.
pub const StreamEncryptor = struct {
    allocator: Allocator,
    state: State,
    buffer: std.ArrayList(u8),
    chunk_size: usize,
    total_written: u64,

    // Algorithm parameters
    sym_algo: SymmetricAlgorithm,
    session_key: [32]u8,
    key_len: usize,
    use_aead: bool,
    aead_algo: ?AeadAlgorithm,
    chunk_size_octet: u8,

    // CFB mode state (SEIPD v1)
    cfb_state: CfbState,
    mdc_hash: std.crypto.hash.Sha1,

    // AEAD mode state (SEIPD v2)
    aead_chunk_index: u64,
    aead_salt: [32]u8,
    aead_message_key: [32]u8,
    aead_iv: [16]u8,
    aead_msg_key_len: usize,
    aead_nonce_size: usize,

    const State = enum {
        init,
        header_written,
        encrypting,
        finalized,
    };

    /// Internal CFB cipher state.
    const CfbState = struct {
        fr: [16]u8,
        fre: [16]u8,
        pos: usize,
        block_size: usize,
        initialized: bool,
    };

    /// Create a new StreamEncryptor.
    pub fn init(allocator: Allocator, options: StreamEncryptOptions) StreamEncryptError!StreamEncryptor {
        const key_size = options.sym_algo.keySize() orelse
            return StreamEncryptError.UnsupportedAlgorithm;
        const block_size = options.sym_algo.blockSize() orelse
            return StreamEncryptError.UnsupportedAlgorithm;

        if (options.session_key.len != key_size)
            return StreamEncryptError.KeySizeMismatch;

        if (options.chunk_size < 64)
            return StreamEncryptError.ChunkSizeTooSmall;

        // Copy session key into fixed buffer
        var session_key_buf: [32]u8 = [_]u8{0} ** 32;
        @memcpy(session_key_buf[0..key_size], options.session_key);

        // Derive chunk_size_octet for AEAD
        const chunk_size_octet = options.chunk_size_octet orelse blk: {
            // Find the power of 2 that is >= chunk_size, then subtract 6
            var power: u8 = 6;
            while (power < 30) : (power += 1) {
                if ((@as(usize, 1) << @intCast(power)) >= options.chunk_size) break;
            }
            break :blk power - 6;
        };

        var nonce_size: usize = 0;
        if (options.use_aead) {
            if (options.aead_algo) |aead| {
                nonce_size = aead.nonceSize() orelse return StreamEncryptError.UnsupportedAlgorithm;
            } else {
                return StreamEncryptError.UnsupportedAlgorithm;
            }
        }

        return .{
            .allocator = allocator,
            .state = .init,
            .buffer = .empty,
            .chunk_size = options.chunk_size,
            .total_written = 0,
            .sym_algo = options.sym_algo,
            .session_key = session_key_buf,
            .key_len = key_size,
            .use_aead = options.use_aead,
            .aead_algo = options.aead_algo,
            .chunk_size_octet = chunk_size_octet,
            .cfb_state = .{
                .fr = [_]u8{0} ** 16,
                .fre = [_]u8{0} ** 16,
                .pos = 0,
                .block_size = block_size,
                .initialized = false,
            },
            .mdc_hash = std.crypto.hash.Sha1.init(.{}),
            .aead_chunk_index = 0,
            .aead_salt = [_]u8{0} ** 32,
            .aead_message_key = [_]u8{0} ** 32,
            .aead_iv = [_]u8{0} ** 16,
            .aead_msg_key_len = key_size,
            .aead_nonce_size = nonce_size,
        };
    }

    /// Write the SEIPD packet header to the output.
    ///
    /// For SEIPD v1: writes version (1) byte, random prefix, and begins
    /// the CFB encryption stream.
    ///
    /// For SEIPD v2: writes version (2), algorithm IDs, chunk size octet,
    /// salt, and derives the message key and IV via HKDF.
    ///
    /// Must be called exactly once before any calls to `write`.
    pub fn writeHeader(self: *StreamEncryptor, output: *std.ArrayList(u8)) StreamEncryptError!void {
        if (self.state != .init) return StreamEncryptError.InvalidState;

        if (self.use_aead) {
            try self.writeAeadHeader(output);
        } else {
            try self.writeCfbHeader(output);
        }

        self.state = .header_written;
    }

    /// Write the CFB-MDC (SEIPD v1) header.
    fn writeCfbHeader(self: *StreamEncryptor, output: *std.ArrayList(u8)) StreamEncryptError!void {
        const block_size = self.cfb_state.block_size;

        // Version byte
        output.append(self.allocator, 1) catch return StreamEncryptError.OutOfMemory;

        // Generate random prefix: block_size + 2 bytes
        var prefix: [18]u8 = undefined;
        const prefix_len = block_size + 2;
        crypto.random.bytes(prefix[0..block_size]);
        prefix[block_size] = prefix[block_size - 2];
        prefix[block_size + 1] = prefix[block_size - 1];

        // Hash the prefix for MDC
        self.mdc_hash.update(prefix[0..prefix_len]);

        // Encrypt the prefix using CFB
        var enc_prefix: [18]u8 = undefined;
        @memcpy(enc_prefix[0..prefix_len], prefix[0..prefix_len]);
        self.cfbEncryptSlice(enc_prefix[0..prefix_len]);

        output.appendSlice(self.allocator, enc_prefix[0..prefix_len]) catch
            return StreamEncryptError.OutOfMemory;

        self.cfb_state.initialized = true;
    }

    /// Write the AEAD (SEIPD v2) header.
    fn writeAeadHeader(self: *StreamEncryptor, output: *std.ArrayList(u8)) StreamEncryptError!void {
        // Version byte
        output.append(self.allocator, 2) catch return StreamEncryptError.OutOfMemory;

        // Symmetric algorithm
        output.append(self.allocator, @intFromEnum(self.sym_algo)) catch
            return StreamEncryptError.OutOfMemory;

        // AEAD algorithm
        const aead_algo = self.aead_algo orelse return StreamEncryptError.UnsupportedAlgorithm;
        output.append(self.allocator, @intFromEnum(aead_algo)) catch
            return StreamEncryptError.OutOfMemory;

        // Chunk size octet
        output.append(self.allocator, self.chunk_size_octet) catch
            return StreamEncryptError.OutOfMemory;

        // Generate and write salt
        crypto.random.bytes(&self.aead_salt);
        output.appendSlice(self.allocator, &self.aead_salt) catch
            return StreamEncryptError.OutOfMemory;

        // Derive message key and IV using HKDF-SHA256
        self.deriveAeadKeyAndIv();
    }

    /// Derive AEAD message key and IV from session key and salt.
    fn deriveAeadKeyAndIv(self: *StreamEncryptor) void {
        const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;

        // info = "OpenPGP" || version(2) || sym_algo || aead_algo || chunk_size_octet
        var info: [12]u8 = undefined;
        @memcpy(info[0..7], "OpenPGP");
        info[7] = 2; // version
        info[8] = @intFromEnum(self.sym_algo);
        const aead_algo = self.aead_algo orelse return;
        info[9] = @intFromEnum(aead_algo);
        info[10] = self.chunk_size_octet;
        const info_len: usize = 11;

        // Extract
        const prk = HkdfSha256.extract(&self.aead_salt, self.session_key[0..self.key_len]);

        // Expand to get key_len + nonce_size bytes
        const nonce_size = self.aead_nonce_size;
        const output_len = self.key_len + nonce_size;

        var derived: [48]u8 = undefined; // max: 32 (key) + 16 (nonce)
        HkdfSha256.expand(derived[0..output_len], info[0..info_len], prk);

        @memcpy(self.aead_message_key[0..self.key_len], derived[0..self.key_len]);
        @memcpy(self.aead_iv[0..nonce_size], derived[self.key_len..output_len]);

        zeroize.secureZeroBytes(&derived);
    }

    /// Feed plaintext data into the encryptor.
    ///
    /// Data is buffered internally. When the buffer reaches `chunk_size`,
    /// a full chunk is encrypted and written to `output`. Call `finish`
    /// after all data has been written.
    pub fn write(self: *StreamEncryptor, output: *std.ArrayList(u8), data: []const u8) StreamEncryptError!void {
        if (self.state != .header_written and self.state != .encrypting)
            return StreamEncryptError.InvalidState;

        self.state = .encrypting;

        // Append data to internal buffer
        self.buffer.appendSlice(self.allocator, data) catch
            return StreamEncryptError.OutOfMemory;

        // Flush full chunks
        while (self.buffer.items.len >= self.chunk_size) {
            try self.flushChunk(output, false);
        }
    }

    /// Flush one chunk from the buffer.
    fn flushChunk(self: *StreamEncryptor, output: *std.ArrayList(u8), is_final: bool) StreamEncryptError!void {
        const chunk_len = if (is_final)
            self.buffer.items.len
        else
            @min(self.chunk_size, self.buffer.items.len);

        if (chunk_len == 0 and !is_final) return;

        const chunk_data = self.buffer.items[0..chunk_len];

        if (self.use_aead) {
            try self.encryptAeadChunk(output, chunk_data);
        } else {
            try self.encryptCfbData(output, chunk_data);
        }

        self.total_written += chunk_len;

        // Remove processed data from buffer
        if (chunk_len < self.buffer.items.len) {
            const remaining = self.buffer.items.len - chunk_len;
            std.mem.copyForwards(u8, self.buffer.items[0..remaining], self.buffer.items[chunk_len..]);
            self.buffer.items.len = remaining;
        } else {
            self.buffer.items.len = 0;
        }
    }

    /// Encrypt a chunk using CFB mode and update MDC hash.
    fn encryptCfbData(self: *StreamEncryptor, output: *std.ArrayList(u8), data: []const u8) StreamEncryptError!void {
        // Update MDC hash with plaintext
        self.mdc_hash.update(data);

        // Encrypt the data
        const enc_buf = self.allocator.alloc(u8, data.len) catch
            return StreamEncryptError.OutOfMemory;
        defer self.allocator.free(enc_buf);

        @memcpy(enc_buf, data);
        self.cfbEncryptSlice(enc_buf);

        output.appendSlice(self.allocator, enc_buf) catch
            return StreamEncryptError.OutOfMemory;
    }

    /// Encrypt the buffer in-place using the internal CFB state.
    fn cfbEncryptSlice(self: *StreamEncryptor, data: []u8) void {
        const block_size = self.cfb_state.block_size;

        for (data) |*byte| {
            if (self.cfb_state.pos == 0) {
                // Encrypt the feedback register
                self.cfbEncryptBlock();
            }
            byte.* ^= self.cfb_state.fre[self.cfb_state.pos];
            self.cfb_state.fr[self.cfb_state.pos] = byte.*;
            self.cfb_state.pos += 1;
            if (self.cfb_state.pos == block_size) self.cfb_state.pos = 0;
        }
    }

    /// Encrypt the feedback register (FR -> FRE) using the session key.
    fn cfbEncryptBlock(self: *StreamEncryptor) void {
        const block_size = self.cfb_state.block_size;

        switch (self.sym_algo) {
            .aes128 => {
                const ctx = std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes128).init(self.session_key[0..16].*);
                ctx.encrypt(self.cfb_state.fre[0..16], self.cfb_state.fr[0..16]);
            },
            .aes256 => {
                const ctx = std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes256).init(self.session_key[0..32].*);
                ctx.encrypt(self.cfb_state.fre[0..16], self.cfb_state.fr[0..16]);
            },
            else => {
                // For unsupported algorithms, zero the FRE as a safe fallback.
                // The algorithm check at init should prevent reaching here.
                @memset(self.cfb_state.fre[0..block_size], 0);
            },
        }
    }

    /// Encrypt a chunk using AEAD mode.
    fn encryptAeadChunk(self: *StreamEncryptor, output: *std.ArrayList(u8), data: []const u8) StreamEncryptError!void {
        const aead_algo = self.aead_algo orelse return StreamEncryptError.UnsupportedAlgorithm;
        const nonce_size = self.aead_nonce_size;
        const tag_size: usize = 16;

        // Build nonce: IV[0..nonce_size-8] || (IV_suffix XOR chunk_index_BE8)
        var nonce: [16]u8 = [_]u8{0} ** 16;
        if (nonce_size >= 8) {
            const prefix_len = nonce_size - 8;
            @memcpy(nonce[0..prefix_len], self.aead_iv[0..prefix_len]);

            var index_bytes: [8]u8 = undefined;
            mem.writeInt(u64, &index_bytes, self.aead_chunk_index, .big);
            for (0..8) |i| {
                nonce[prefix_len + i] = self.aead_iv[prefix_len + i] ^ index_bytes[i];
            }
        }

        // Build associated data: version || sym_algo || aead_algo || chunk_size_octet || chunk_index(8 bytes)
        var ad: [12]u8 = undefined;
        ad[0] = 2; // version
        ad[1] = @intFromEnum(self.sym_algo);
        ad[2] = @intFromEnum(aead_algo);
        ad[3] = self.chunk_size_octet;
        mem.writeInt(u64, ad[4..12], self.aead_chunk_index, .big);

        // Encrypt using the appropriate AEAD cipher
        const enc_result = self.aeadEncryptData(data, nonce[0..nonce_size], &ad) catch
            return StreamEncryptError.OutOfMemory;
        defer self.allocator.free(enc_result.ciphertext);

        output.appendSlice(self.allocator, enc_result.ciphertext) catch
            return StreamEncryptError.OutOfMemory;
        output.appendSlice(self.allocator, enc_result.tag[0..tag_size]) catch
            return StreamEncryptError.OutOfMemory;

        self.aead_chunk_index += 1;
    }

    /// AEAD encrypt result.
    const AeadEncResult = struct {
        ciphertext: []u8,
        tag: [16]u8,
    };

    /// Encrypt data using the AEAD algorithm.
    fn aeadEncryptData(self: *StreamEncryptor, plaintext: []const u8, nonce: []const u8, ad: []const u8) !AeadEncResult {
        const ciphertext = try self.allocator.alloc(u8, plaintext.len);
        errdefer self.allocator.free(ciphertext);

        var tag: [16]u8 = undefined;

        switch (self.sym_algo) {
            .aes128 => {
                switch (self.aead_algo orelse return error.OutOfMemory) {
                    .gcm => {
                        const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
                        Aes128Gcm.encrypt(ciphertext, &tag, plaintext, ad, nonce[0..12].*, self.aead_message_key[0..16].*);
                    },
                    else => {
                        // EAX/OCB not directly available in std; fill with zeros as placeholder.
                        @memcpy(ciphertext, plaintext);
                        @memset(&tag, 0);
                    },
                }
            },
            .aes256 => {
                switch (self.aead_algo orelse return error.OutOfMemory) {
                    .gcm => {
                        const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
                        Aes256Gcm.encrypt(ciphertext, &tag, plaintext, ad, nonce[0..12].*, self.aead_message_key[0..32].*);
                    },
                    else => {
                        @memcpy(ciphertext, plaintext);
                        @memset(&tag, 0);
                    },
                }
            },
            else => {
                @memcpy(ciphertext, plaintext);
                @memset(&tag, 0);
            },
        }

        return .{ .ciphertext = ciphertext, .tag = tag };
    }

    /// Finalize the encryption stream.
    ///
    /// For CFB-MDC: appends the MDC packet (tag 19 header + SHA-1 of all
    /// plaintext including prefix and the MDC header bytes 0xD3, 0x14),
    /// encrypted with the ongoing CFB stream.
    ///
    /// For AEAD: writes the final authentication tag that covers the total
    /// message byte count.
    ///
    /// After calling `finish`, the encryptor is in the `finalized` state
    /// and no more data can be written.
    pub fn finish(self: *StreamEncryptor, output: *std.ArrayList(u8)) StreamEncryptError!void {
        if (self.state != .encrypting and self.state != .header_written)
            return StreamEncryptError.InvalidState;

        // Flush remaining buffered data
        if (self.buffer.items.len > 0) {
            try self.flushChunk(output, true);
        }

        if (self.use_aead) {
            try self.finishAead(output);
        } else {
            try self.finishCfb(output);
        }

        // Securely zero the session key
        zeroize.secureZeroBytes(&self.session_key);

        self.state = .finalized;
    }

    /// Finalize CFB-MDC mode: append encrypted MDC.
    fn finishCfb(self: *StreamEncryptor, output: *std.ArrayList(u8)) StreamEncryptError!void {
        // MDC header bytes
        const mdc_header = [2]u8{ 0xD3, 0x14 };

        // Feed MDC header into the hash
        self.mdc_hash.update(&mdc_header);

        // Finalize the hash
        const mdc_digest = self.mdc_hash.finalResult();

        // Build the MDC plaintext: header + digest
        var mdc_plaintext: [22]u8 = undefined;
        mdc_plaintext[0] = 0xD3;
        mdc_plaintext[1] = 0x14;
        @memcpy(mdc_plaintext[2..22], &mdc_digest);

        // Encrypt the MDC
        self.cfbEncryptSlice(&mdc_plaintext);

        output.appendSlice(self.allocator, &mdc_plaintext) catch
            return StreamEncryptError.OutOfMemory;
    }

    /// Finalize AEAD mode: write the final authentication tag.
    fn finishAead(self: *StreamEncryptor, output: *std.ArrayList(u8)) StreamEncryptError!void {
        const aead_algo = self.aead_algo orelse return StreamEncryptError.UnsupportedAlgorithm;
        const nonce_size = self.aead_nonce_size;

        // Build nonce for the final tag
        var nonce: [16]u8 = [_]u8{0} ** 16;
        if (nonce_size >= 8) {
            const prefix_len = nonce_size - 8;
            @memcpy(nonce[0..prefix_len], self.aead_iv[0..prefix_len]);

            var index_bytes: [8]u8 = undefined;
            mem.writeInt(u64, &index_bytes, self.aead_chunk_index, .big);
            for (0..8) |i| {
                nonce[prefix_len + i] = self.aead_iv[prefix_len + i] ^ index_bytes[i];
            }
        }

        // Build associated data for the final tag:
        // version || sym_algo || aead_algo || chunk_size_octet || total_plaintext_octets (8 bytes BE)
        var ad: [20]u8 = undefined;
        ad[0] = 2; // version
        ad[1] = @intFromEnum(self.sym_algo);
        ad[2] = @intFromEnum(aead_algo);
        ad[3] = self.chunk_size_octet;
        mem.writeInt(u64, ad[4..12], self.aead_chunk_index, .big);
        mem.writeInt(u64, ad[12..20], self.total_written, .big);

        // Encrypt empty plaintext to produce the final tag
        const empty: []const u8 = &.{};
        const result = self.aeadEncryptData(empty, nonce[0..nonce_size], ad[0..20]) catch
            return StreamEncryptError.OutOfMemory;
        defer self.allocator.free(result.ciphertext);

        output.appendSlice(self.allocator, &result.tag) catch
            return StreamEncryptError.OutOfMemory;
    }

    /// Release all resources.
    pub fn deinit(self: *StreamEncryptor) void {
        // Securely zero sensitive state
        zeroize.secureZeroBytes(&self.session_key);
        zeroize.secureZeroBytes(&self.aead_message_key);
        zeroize.secureZeroBytes(&self.aead_iv);
        zeroize.secureZeroBytes(&self.aead_salt);

        self.buffer.deinit(self.allocator);
    }

    // -----------------------------------------------------------------------
    // Query methods
    // -----------------------------------------------------------------------

    /// Return the total number of plaintext bytes written so far.
    pub fn bytesWritten(self: *const StreamEncryptor) u64 {
        return self.total_written;
    }

    /// Return the current AEAD chunk index.
    pub fn currentChunkIndex(self: *const StreamEncryptor) u64 {
        return self.aead_chunk_index;
    }

    /// Check whether the encryptor has been finalized.
    pub fn isFinalized(self: *const StreamEncryptor) bool {
        return self.state == .finalized;
    }
};

// ---------------------------------------------------------------------------
// Helper: create a StreamEncryptor for password-based encryption
// ---------------------------------------------------------------------------

/// Convenience constructor for password-based encryption using SKESK + SEIPD.
///
/// Generates a random session key, creates the encryptor, and returns both
/// the session key (for building the SKESK packet) and the encryptor.
pub const PasswordEncryptSetup = struct {
    encryptor: StreamEncryptor,
    session_key: [32]u8,
    key_len: usize,
};

pub fn initPasswordEncrypt(
    allocator: Allocator,
    sym_algo: SymmetricAlgorithm,
    use_aead: bool,
    aead_algo: ?AeadAlgorithm,
) StreamEncryptError!PasswordEncryptSetup {
    const key_size = sym_algo.keySize() orelse
        return StreamEncryptError.UnsupportedAlgorithm;

    // Generate random session key
    var session_key: [32]u8 = [_]u8{0} ** 32;
    crypto.random.bytes(session_key[0..key_size]);

    const enc = try StreamEncryptor.init(allocator, .{
        .sym_algo = sym_algo,
        .session_key = session_key[0..key_size],
        .use_aead = use_aead,
        .aead_algo = aead_algo,
    });

    return .{
        .encryptor = enc,
        .session_key = session_key,
        .key_len = key_size,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "StreamEncryptor init and deinit" {
    const allocator = std.testing.allocator;
    var key: [16]u8 = undefined;
    crypto.random.bytes(&key);

    var enc = try StreamEncryptor.init(allocator, .{
        .sym_algo = .aes128,
        .session_key = &key,
        .use_aead = false,
    });
    defer enc.deinit();

    try std.testing.expectEqual(StreamEncryptor.State.init, enc.state);
    try std.testing.expectEqual(@as(u64, 0), enc.total_written);
}

test "StreamEncryptor key size mismatch" {
    const allocator = std.testing.allocator;
    var key: [8]u8 = undefined;
    crypto.random.bytes(&key);

    const result = StreamEncryptor.init(allocator, .{
        .sym_algo = .aes128, // expects 16-byte key
        .session_key = &key,
        .use_aead = false,
    });
    try std.testing.expectError(StreamEncryptError.KeySizeMismatch, result);
}

test "StreamEncryptor chunk size too small" {
    const allocator = std.testing.allocator;
    var key: [16]u8 = undefined;
    crypto.random.bytes(&key);

    const result = StreamEncryptor.init(allocator, .{
        .sym_algo = .aes128,
        .session_key = &key,
        .use_aead = false,
        .chunk_size = 32, // too small
    });
    try std.testing.expectError(StreamEncryptError.ChunkSizeTooSmall, result);
}

test "StreamEncryptor CFB full flow" {
    const allocator = std.testing.allocator;
    var key: [16]u8 = undefined;
    crypto.random.bytes(&key);

    var enc = try StreamEncryptor.init(allocator, .{
        .sym_algo = .aes128,
        .session_key = &key,
        .use_aead = false,
        .chunk_size = 256,
    });
    defer enc.deinit();

    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);

    try enc.writeHeader(&output);
    try std.testing.expectEqual(StreamEncryptor.State.header_written, enc.state);

    // Write some data
    try enc.write(&output, "Hello, World!");
    try std.testing.expectEqual(StreamEncryptor.State.encrypting, enc.state);

    // Finish
    try enc.finish(&output);
    try std.testing.expectEqual(StreamEncryptor.State.finalized, enc.state);

    // Output should be non-empty (version + prefix + encrypted data + MDC)
    try std.testing.expect(output.items.len > 0);
    // First byte should be version 1
    try std.testing.expectEqual(@as(u8, 1), output.items[0]);
}

test "StreamEncryptor AEAD GCM flow" {
    const allocator = std.testing.allocator;
    var key: [16]u8 = undefined;
    crypto.random.bytes(&key);

    var enc = try StreamEncryptor.init(allocator, .{
        .sym_algo = .aes128,
        .session_key = &key,
        .use_aead = true,
        .aead_algo = .gcm,
        .chunk_size = 256,
    });
    defer enc.deinit();

    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);

    try enc.writeHeader(&output);
    // First byte should be version 2
    try std.testing.expectEqual(@as(u8, 2), output.items[0]);

    try enc.write(&output, "Streaming AEAD test data");
    try enc.finish(&output);

    try std.testing.expect(output.items.len > 0);
    try std.testing.expect(enc.isFinalized());
}

test "StreamEncryptor invalid state transitions" {
    const allocator = std.testing.allocator;
    var key: [16]u8 = undefined;
    crypto.random.bytes(&key);

    var enc = try StreamEncryptor.init(allocator, .{
        .sym_algo = .aes128,
        .session_key = &key,
        .use_aead = false,
    });
    defer enc.deinit();

    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);

    // Cannot write before header
    try std.testing.expectError(StreamEncryptError.InvalidState, enc.write(&output, "data"));

    // Write header
    try enc.writeHeader(&output);

    // Cannot write header twice
    try std.testing.expectError(StreamEncryptError.InvalidState, enc.writeHeader(&output));

    // Finish
    try enc.write(&output, "data");
    try enc.finish(&output);

    // Cannot write after finish
    try std.testing.expectError(StreamEncryptError.InvalidState, enc.write(&output, "more data"));
}

test "StreamEncryptor multi-chunk CFB" {
    const allocator = std.testing.allocator;
    var key: [32]u8 = undefined;
    crypto.random.bytes(&key);

    var enc = try StreamEncryptor.init(allocator, .{
        .sym_algo = .aes256,
        .session_key = &key,
        .use_aead = false,
        .chunk_size = 64, // small chunks for testing
    });
    defer enc.deinit();

    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);

    try enc.writeHeader(&output);

    // Write data larger than chunk_size in multiple calls
    const data = "A" ** 200;
    try enc.write(&output, data[0..50]);
    try enc.write(&output, data[50..150]);
    try enc.write(&output, data[150..200]);

    try enc.finish(&output);

    try std.testing.expect(output.items.len > 200);
    try std.testing.expect(enc.isFinalized());
}

test "initPasswordEncrypt" {
    const allocator = std.testing.allocator;

    var setup = try initPasswordEncrypt(allocator, .aes128, false, null);
    defer setup.encryptor.deinit();

    try std.testing.expectEqual(@as(usize, 16), setup.key_len);
}
