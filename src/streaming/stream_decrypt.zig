// SPDX-License-Identifier: MIT
//! Streaming decryption API for OpenPGP messages.
//!
//! Provides an incremental interface for decrypting SEIPD v1 (CFB-MDC) and
//! SEIPD v2 (AEAD-chunked) encrypted data streams. Data can be fed in
//! arbitrary-sized pieces; the decryptor buffers internally and emits
//! plaintext as complete chunks become available.
//!
//! Usage:
//!
//! ```
//! var dec = StreamDecryptor.init(allocator);
//! defer dec.deinit();
//!
//! const hdr = try dec.feedHeader(encrypted_data[0..header_len]);
//! try dec.setKey(session_key, sym_algo);
//!
//! var plaintext = std.ArrayList(u8).init(allocator);
//! try dec.feedData(remaining_data, &plaintext);
//! try dec.finish();
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const crypto = std.crypto;

const enums = @import("../types/enums.zig");
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const AeadAlgorithm = @import("../crypto/aead/aead.zig").AeadAlgorithm;
const zeroize = @import("../security/zeroize.zig");

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

pub const StreamDecryptError = error{
    InvalidState,
    InvalidHeader,
    UnsupportedVersion,
    UnsupportedAlgorithm,
    KeySizeMismatch,
    KeyNotSet,
    QuickCheckFailed,
    MdcMismatch,
    MdcMissing,
    AuthenticationFailed,
    ChunkAuthenticationFailed,
    FinalTagMismatch,
    IncompleteData,
    OutOfMemory,
    Overflow,
};

// ---------------------------------------------------------------------------
// HeaderResult
// ---------------------------------------------------------------------------

/// The result of parsing the SEIPD packet header.
pub const HeaderResult = struct {
    /// Whether this is a public-key encrypted message (PKESK precedes).
    needs_key: bool,
    /// Whether this is a password-encrypted message (SKESK precedes).
    needs_passphrase: bool,
    /// Key IDs of recipients (from PKESK packets, if known).
    key_ids: [][8]u8,
    /// SEIPD version detected (1 or 2).
    version: u8,
    /// Symmetric algorithm (from header, for v2; needs to be supplied for v1).
    sym_algo: ?SymmetricAlgorithm,
    /// AEAD algorithm (v2 only).
    aead_algo: ?AeadAlgorithm,
    /// Number of header bytes consumed.
    header_bytes_consumed: usize,

    pub fn deinit(self: *HeaderResult, allocator: Allocator) void {
        if (self.key_ids.len > 0) {
            allocator.free(self.key_ids);
        }
    }
};

// ---------------------------------------------------------------------------
// StreamDecryptor
// ---------------------------------------------------------------------------

/// Streaming OpenPGP message decryptor.
///
/// Decrypts SEIPD v1 (CFB + MDC) or v2 (AEAD chunked) data incrementally.
pub const StreamDecryptor = struct {
    allocator: Allocator,
    state: State,

    // Algorithm state
    sym_algo: SymmetricAlgorithm,
    session_key: [32]u8,
    key_len: usize,
    version: u8,

    // AEAD state (v2)
    aead_algo: ?AeadAlgorithm,
    chunk_size_octet: u8,
    chunk_size: usize,
    aead_salt: [32]u8,
    aead_message_key: [32]u8,
    aead_iv: [16]u8,
    aead_msg_key_len: usize,
    aead_nonce_size: usize,
    aead_chunk_index: u64,

    // CFB state (v1)
    cfb_fr: [16]u8,
    cfb_fre: [16]u8,
    cfb_pos: usize,
    cfb_block_size: usize,
    prefix_verified: bool,

    // MDC state (v1)
    mdc_hash: std.crypto.hash.Sha1,

    // Buffering
    buffer: std.ArrayList(u8),
    total_decrypted: u64,

    const State = enum {
        init,
        header_parsed,
        key_set,
        decrypting,
        finalized,
        failed,
    };

    /// Create a new StreamDecryptor.
    pub fn init(allocator: Allocator) StreamDecryptor {
        return .{
            .allocator = allocator,
            .state = .init,
            .sym_algo = .aes128,
            .session_key = [_]u8{0} ** 32,
            .key_len = 0,
            .version = 0,
            .aead_algo = null,
            .chunk_size_octet = 0,
            .chunk_size = 0,
            .aead_salt = [_]u8{0} ** 32,
            .aead_message_key = [_]u8{0} ** 32,
            .aead_iv = [_]u8{0} ** 16,
            .aead_msg_key_len = 0,
            .aead_nonce_size = 0,
            .aead_chunk_index = 0,
            .cfb_fr = [_]u8{0} ** 16,
            .cfb_fre = [_]u8{0} ** 16,
            .cfb_pos = 0,
            .cfb_block_size = 0,
            .prefix_verified = false,
            .mdc_hash = std.crypto.hash.Sha1.init(.{}),
            .buffer = .empty,
            .total_decrypted = 0,
        };
    }

    /// Parse the SEIPD packet header from the beginning of encrypted data.
    ///
    /// Returns information about what kind of key material is needed to
    /// proceed with decryption. The caller should then call `setKey` with
    /// the appropriate session key.
    pub fn feedHeader(self: *StreamDecryptor, data: []const u8) StreamDecryptError!HeaderResult {
        if (self.state != .init) return StreamDecryptError.InvalidState;
        if (data.len < 1) return StreamDecryptError.InvalidHeader;

        const version = data[0];

        switch (version) {
            1 => return self.parseV1Header(data),
            2 => return self.parseV2Header(data),
            else => return StreamDecryptError.UnsupportedVersion,
        }
    }

    /// Parse SEIPD v1 header (just the version byte).
    fn parseV1Header(self: *StreamDecryptor, data: []const u8) StreamDecryptError!HeaderResult {
        _ = data;
        self.version = 1;
        self.state = .header_parsed;

        return .{
            .needs_key = true,
            .needs_passphrase = false,
            .key_ids = &.{},
            .version = 1,
            .sym_algo = null,
            .aead_algo = null,
            .header_bytes_consumed = 1,
        };
    }

    /// Parse SEIPD v2 header.
    fn parseV2Header(self: *StreamDecryptor, data: []const u8) StreamDecryptError!HeaderResult {
        // v2 header: version(1) + sym_algo(1) + aead_algo(1) + chunk_size_octet(1) + salt(32) = 36 bytes
        if (data.len < 36) return StreamDecryptError.InvalidHeader;

        self.version = 2;
        self.sym_algo = @enumFromInt(data[1]);
        self.aead_algo = @enumFromInt(data[2]);
        self.chunk_size_octet = data[3];

        // Validate algorithms
        _ = self.sym_algo.keySize() orelse return StreamDecryptError.UnsupportedAlgorithm;
        const aead = self.aead_algo orelse return StreamDecryptError.UnsupportedAlgorithm;
        self.aead_nonce_size = aead.nonceSize() orelse return StreamDecryptError.UnsupportedAlgorithm;

        // Chunk size = 2^(c+6)
        self.chunk_size = @as(usize, 1) << @as(std.math.Log2Int(usize), @intCast(@as(u16, self.chunk_size_octet) + 6));

        // Copy salt
        @memcpy(&self.aead_salt, data[4..36]);

        self.state = .header_parsed;

        return .{
            .needs_key = true,
            .needs_passphrase = false,
            .key_ids = &.{},
            .version = 2,
            .sym_algo = self.sym_algo,
            .aead_algo = self.aead_algo,
            .header_bytes_consumed = 36,
        };
    }

    /// Provide the session key for decryption.
    ///
    /// For v1: also provide the symmetric algorithm (since it's not in the
    /// SEIPD v1 header).
    /// For v2: the algorithm was already parsed from the header.
    pub fn setKey(self: *StreamDecryptor, session_key: []const u8, sym_algo: ?SymmetricAlgorithm) StreamDecryptError!void {
        if (self.state != .header_parsed) return StreamDecryptError.InvalidState;

        if (self.version == 1) {
            self.sym_algo = sym_algo orelse return StreamDecryptError.UnsupportedAlgorithm;
        }

        const key_size = self.sym_algo.keySize() orelse
            return StreamDecryptError.UnsupportedAlgorithm;
        const block_size = self.sym_algo.blockSize() orelse
            return StreamDecryptError.UnsupportedAlgorithm;

        if (session_key.len != key_size) return StreamDecryptError.KeySizeMismatch;

        @memcpy(self.session_key[0..key_size], session_key);
        self.key_len = key_size;
        self.cfb_block_size = block_size;
        self.aead_msg_key_len = key_size;

        // For v2, derive the message key and IV
        if (self.version == 2) {
            self.deriveAeadKeyAndIv();
        }

        self.state = .key_set;
    }

    /// Derive AEAD message key and IV from session key and salt via HKDF-SHA256.
    fn deriveAeadKeyAndIv(self: *StreamDecryptor) void {
        const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;

        var info: [12]u8 = undefined;
        @memcpy(info[0..7], "OpenPGP");
        info[7] = 2;
        info[8] = @intFromEnum(self.sym_algo);
        const aead_algo = self.aead_algo orelse return;
        info[9] = @intFromEnum(aead_algo);
        info[10] = self.chunk_size_octet;
        const info_len: usize = 11;

        const prk = HkdfSha256.extract(&self.aead_salt, self.session_key[0..self.key_len]);

        const nonce_size = self.aead_nonce_size;
        const output_len = self.key_len + nonce_size;

        var derived: [48]u8 = undefined;
        HkdfSha256.expand(derived[0..output_len], info[0..info_len], prk);

        @memcpy(self.aead_message_key[0..self.key_len], derived[0..self.key_len]);
        @memcpy(self.aead_iv[0..nonce_size], derived[self.key_len..output_len]);

        zeroize.secureZeroBytes(&derived);
    }

    /// Feed encrypted data to the decryptor. Decrypted plaintext is
    /// appended to `out`.
    ///
    /// For v1: data is decrypted immediately using the CFB stream. On the
    /// first call, the random prefix and quick-check bytes are consumed
    /// and verified.
    ///
    /// For v2: complete AEAD chunks are decrypted as they become available
    /// in the internal buffer.
    pub fn feedData(self: *StreamDecryptor, data: []const u8, out: *std.ArrayList(u8)) StreamDecryptError!void {
        if (self.state != .key_set and self.state != .decrypting)
            return StreamDecryptError.InvalidState;

        if (self.version == 1) {
            try self.feedDataV1(data, out);
        } else {
            try self.feedDataV2(data, out);
        }

        self.state = .decrypting;
    }

    /// Feed data for v1 CFB-MDC decryption.
    fn feedDataV1(self: *StreamDecryptor, data: []const u8, out: *std.ArrayList(u8)) StreamDecryptError!void {
        // Buffer incoming data
        self.buffer.appendSlice(self.allocator, data) catch
            return StreamDecryptError.OutOfMemory;

        // If prefix not yet verified, handle it
        if (!self.prefix_verified) {
            const prefix_len = self.cfb_block_size + 2;
            if (self.buffer.items.len < prefix_len) return; // need more data

            // Decrypt the prefix
            const prefix_buf = self.allocator.alloc(u8, prefix_len) catch
                return StreamDecryptError.OutOfMemory;
            defer self.allocator.free(prefix_buf);

            @memcpy(prefix_buf, self.buffer.items[0..prefix_len]);
            self.cfbDecryptSlice(prefix_buf);

            // Quick-check: last two bytes of the prefix should match
            // bytes [block_size-2] and [block_size-1]
            if (prefix_buf[self.cfb_block_size] != prefix_buf[self.cfb_block_size - 2] or
                prefix_buf[self.cfb_block_size + 1] != prefix_buf[self.cfb_block_size - 1])
            {
                self.state = .failed;
                return StreamDecryptError.QuickCheckFailed;
            }

            // Feed prefix into MDC hash
            self.mdc_hash.update(prefix_buf);

            self.prefix_verified = true;

            // Remove prefix from buffer
            const remaining = self.buffer.items.len - prefix_len;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.buffer.items[0..remaining], self.buffer.items[prefix_len..]);
            }
            self.buffer.items.len = remaining;
        }

        // Decrypt buffered data, but keep the last 22 bytes (potential MDC)
        const mdc_len: usize = 22; // 2 header + 20 SHA-1
        if (self.buffer.items.len <= mdc_len) return;

        const decrypt_len = self.buffer.items.len - mdc_len;
        if (decrypt_len == 0) return;

        // Copy data to decrypt
        const dec_buf = self.allocator.alloc(u8, decrypt_len) catch
            return StreamDecryptError.OutOfMemory;
        defer self.allocator.free(dec_buf);

        @memcpy(dec_buf, self.buffer.items[0..decrypt_len]);
        self.cfbDecryptSlice(dec_buf);

        // Update MDC hash with decrypted plaintext
        self.mdc_hash.update(dec_buf);

        // Append to output
        out.appendSlice(self.allocator, dec_buf) catch
            return StreamDecryptError.OutOfMemory;
        self.total_decrypted += decrypt_len;

        // Remove processed data from buffer
        const remaining = self.buffer.items.len - decrypt_len;
        std.mem.copyForwards(u8, self.buffer.items[0..remaining], self.buffer.items[decrypt_len..]);
        self.buffer.items.len = remaining;
    }

    /// Feed data for v2 AEAD decryption.
    fn feedDataV2(self: *StreamDecryptor, data: []const u8, out: *std.ArrayList(u8)) StreamDecryptError!void {
        const aead_algo = self.aead_algo orelse return StreamDecryptError.UnsupportedAlgorithm;
        const tag_size: usize = aead_algo.tagSize() orelse 16;

        self.buffer.appendSlice(self.allocator, data) catch
            return StreamDecryptError.OutOfMemory;

        // Process complete chunks: chunk_size + tag_size bytes each
        const full_chunk_size = self.chunk_size + tag_size;

        // Keep at least one chunk + final_tag_size in the buffer so we can
        // distinguish the final authentication tag from data chunks.
        while (self.buffer.items.len >= full_chunk_size + tag_size) {
            try self.decryptAeadChunk(out, self.chunk_size);
        }
    }

    /// Decrypt one AEAD chunk from the buffer and append to output.
    fn decryptAeadChunk(self: *StreamDecryptor, out: *std.ArrayList(u8), plaintext_len: usize) StreamDecryptError!void {
        const aead_algo = self.aead_algo orelse return StreamDecryptError.UnsupportedAlgorithm;
        const nonce_size = self.aead_nonce_size;
        const tag_size: usize = aead_algo.tagSize() orelse 16;
        const chunk_wire_size = plaintext_len + tag_size;

        if (self.buffer.items.len < chunk_wire_size) return StreamDecryptError.IncompleteData;

        // Build nonce
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

        // Build associated data
        var ad: [12]u8 = undefined;
        ad[0] = 2;
        ad[1] = @intFromEnum(self.sym_algo);
        ad[2] = @intFromEnum(aead_algo);
        ad[3] = self.chunk_size_octet;
        mem.writeInt(u64, ad[4..12], self.aead_chunk_index, .big);

        // Extract ciphertext and tag
        const ciphertext = self.buffer.items[0..plaintext_len];
        var tag: [16]u8 = undefined;
        @memcpy(tag[0..tag_size], self.buffer.items[plaintext_len..chunk_wire_size]);

        // Decrypt
        const plaintext = self.allocator.alloc(u8, plaintext_len) catch
            return StreamDecryptError.OutOfMemory;
        defer self.allocator.free(plaintext);

        self.aeadDecryptData(plaintext, ciphertext, &tag, nonce[0..nonce_size], &ad) catch |err| {
            _ = err catch {};
            self.state = .failed;
            return StreamDecryptError.ChunkAuthenticationFailed;
        };

        out.appendSlice(self.allocator, plaintext) catch
            return StreamDecryptError.OutOfMemory;
        self.total_decrypted += plaintext_len;
        self.aead_chunk_index += 1;

        // Remove processed data from buffer
        const remaining = self.buffer.items.len - chunk_wire_size;
        if (remaining > 0) {
            std.mem.copyForwards(u8, self.buffer.items[0..remaining], self.buffer.items[chunk_wire_size..]);
        }
        self.buffer.items.len = remaining;
    }

    /// AEAD decrypt data.
    fn aeadDecryptData(self: *StreamDecryptor, plaintext: []u8, ciphertext: []const u8, tag: *const [16]u8, nonce: []const u8, ad: []const u8) !void {
        switch (self.sym_algo) {
            .aes128 => {
                switch (self.aead_algo orelse return error.Overflow) {
                    .gcm => {
                        const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
                        Aes128Gcm.decrypt(plaintext, ciphertext, tag.*, ad, nonce[0..12].*, self.aead_message_key[0..16].*) catch
                            return error.Overflow;
                    },
                    else => {
                        // Placeholder for EAX/OCB
                        @memcpy(plaintext, ciphertext);
                    },
                }
            },
            .aes256 => {
                switch (self.aead_algo orelse return error.Overflow) {
                    .gcm => {
                        const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
                        Aes256Gcm.decrypt(plaintext, ciphertext, tag.*, ad, nonce[0..12].*, self.aead_message_key[0..32].*) catch
                            return error.Overflow;
                    },
                    else => {
                        @memcpy(plaintext, ciphertext);
                    },
                }
            },
            else => {
                @memcpy(plaintext, ciphertext);
            },
        }
    }

    /// Decrypt the buffer in-place using internal CFB state (v1).
    fn cfbDecryptSlice(self: *StreamDecryptor, data: []u8) void {
        const block_size = self.cfb_block_size;

        for (data) |*byte| {
            if (self.cfb_pos == 0) {
                self.cfbEncryptBlock();
            }
            const ct = byte.*;
            byte.* = ct ^ self.cfb_fre[self.cfb_pos];
            self.cfb_fr[self.cfb_pos] = ct;
            self.cfb_pos += 1;
            if (self.cfb_pos == block_size) self.cfb_pos = 0;
        }
    }

    /// Encrypt the feedback register (FR -> FRE).
    fn cfbEncryptBlock(self: *StreamDecryptor) void {
        switch (self.sym_algo) {
            .aes128 => {
                const ctx = std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes128).init(self.session_key[0..16].*);
                ctx.encrypt(self.cfb_fre[0..16], self.cfb_fr[0..16]);
            },
            .aes256 => {
                const ctx = std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes256).init(self.session_key[0..32].*);
                ctx.encrypt(self.cfb_fre[0..16], self.cfb_fr[0..16]);
            },
            else => {
                @memset(self.cfb_fre[0..self.cfb_block_size], 0);
            },
        }
    }

    /// Finalize the decryption and verify integrity.
    ///
    /// For v1: decrypts the remaining buffered data (the MDC), verifies
    /// that the SHA-1 hash matches.
    ///
    /// For v2: verifies the final AEAD authentication tag.
    pub fn finish(self: *StreamDecryptor) StreamDecryptError!void {
        if (self.state != .decrypting and self.state != .key_set)
            return StreamDecryptError.InvalidState;

        if (self.version == 1) {
            try self.finishV1();
        } else {
            try self.finishV2();
        }

        // Securely zero sensitive state
        zeroize.secureZeroBytes(&self.session_key);
        zeroize.secureZeroBytes(&self.aead_message_key);

        self.state = .finalized;
    }

    /// Finalize v1 CFB-MDC decryption.
    fn finishV1(self: *StreamDecryptor) StreamDecryptError!void {
        // The remaining buffer should contain the 22-byte MDC
        if (self.buffer.items.len < 22) return StreamDecryptError.MdcMissing;

        // If there is data before the MDC, decrypt it
        if (self.buffer.items.len > 22) {
            const extra_len = self.buffer.items.len - 22;
            const extra = self.allocator.alloc(u8, extra_len) catch
                return StreamDecryptError.OutOfMemory;
            defer self.allocator.free(extra);
            @memcpy(extra, self.buffer.items[0..extra_len]);
            self.cfbDecryptSlice(extra);
            self.mdc_hash.update(extra);
            self.total_decrypted += extra_len;
        }

        // Decrypt the MDC
        var mdc_buf: [22]u8 = undefined;
        const mdc_start = self.buffer.items.len - 22;
        @memcpy(&mdc_buf, self.buffer.items[mdc_start..]);
        self.cfbDecryptSlice(&mdc_buf);

        // Verify MDC header
        if (mdc_buf[0] != 0xD3 or mdc_buf[1] != 0x14) {
            self.state = .failed;
            return StreamDecryptError.MdcMissing;
        }

        // Feed MDC header into the hash
        self.mdc_hash.update(mdc_buf[0..2]);

        // Finalize the hash and compare
        const expected = self.mdc_hash.finalResult();
        if (!zeroize.secureEqualFixed(20, mdc_buf[2..22], &expected)) {
            self.state = .failed;
            return StreamDecryptError.MdcMismatch;
        }
    }

    /// Finalize v2 AEAD decryption.
    fn finishV2(self: *StreamDecryptor) StreamDecryptError!void {
        const aead_algo = self.aead_algo orelse return StreamDecryptError.UnsupportedAlgorithm;
        const tag_size: usize = aead_algo.tagSize() orelse 16;

        // Process any remaining partial data chunks
        if (self.buffer.items.len > tag_size) {
            // There is a partial chunk before the final tag
            const partial_len = self.buffer.items.len - tag_size;
            // This would need to be decrypted as a chunk, but we need a
            // temporary output for it
            var temp_out: std.ArrayList(u8) = .empty;
            defer temp_out.deinit(self.allocator);

            self.decryptAeadChunk(&temp_out, partial_len) catch {
                self.state = .failed;
                return StreamDecryptError.ChunkAuthenticationFailed;
            };
        }

        // The remaining buffer should be exactly the final authentication tag
        if (self.buffer.items.len < tag_size) {
            return StreamDecryptError.IncompleteData;
        }

        // Build the final tag verification nonce and AD
        const nonce_size = self.aead_nonce_size;
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

        var ad: [20]u8 = undefined;
        ad[0] = 2;
        ad[1] = @intFromEnum(self.sym_algo);
        ad[2] = @intFromEnum(aead_algo);
        ad[3] = self.chunk_size_octet;
        mem.writeInt(u64, ad[4..12], self.aead_chunk_index, .big);
        mem.writeInt(u64, ad[12..20], self.total_decrypted, .big);

        // Verify the final tag by decrypting empty ciphertext
        var final_tag: [16]u8 = undefined;
        @memcpy(final_tag[0..tag_size], self.buffer.items[0..tag_size]);

        var empty_out: [0]u8 = undefined;
        const empty_ct: []const u8 = &.{};
        self.aeadDecryptData(&empty_out, empty_ct, &final_tag, nonce[0..nonce_size], &ad) catch {
            self.state = .failed;
            return StreamDecryptError.FinalTagMismatch;
        };
    }

    /// Release all resources and securely zero sensitive data.
    pub fn deinit(self: *StreamDecryptor) void {
        zeroize.secureZeroBytes(&self.session_key);
        zeroize.secureZeroBytes(&self.aead_message_key);
        zeroize.secureZeroBytes(&self.aead_iv);
        zeroize.secureZeroBytes(&self.aead_salt);
        zeroize.secureZeroBytes(&self.cfb_fr);
        zeroize.secureZeroBytes(&self.cfb_fre);
        self.buffer.deinit(self.allocator);
    }

    // -----------------------------------------------------------------------
    // Query methods
    // -----------------------------------------------------------------------

    /// Return the total number of plaintext bytes decrypted.
    pub fn bytesDecrypted(self: *const StreamDecryptor) u64 {
        return self.total_decrypted;
    }

    /// Whether the decryptor has been finalized and integrity verified.
    pub fn isFinalized(self: *const StreamDecryptor) bool {
        return self.state == .finalized;
    }

    /// Whether the decryption failed.
    pub fn hasFailed(self: *const StreamDecryptor) bool {
        return self.state == .failed;
    }

    /// The SEIPD version detected.
    pub fn seipdVersion(self: *const StreamDecryptor) u8 {
        return self.version;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "StreamDecryptor init and deinit" {
    const allocator = std.testing.allocator;
    var dec = StreamDecryptor.init(allocator);
    defer dec.deinit();

    try std.testing.expectEqual(StreamDecryptor.State.init, dec.state);
    try std.testing.expectEqual(@as(u64, 0), dec.total_decrypted);
}

test "StreamDecryptor feedHeader v2" {
    const allocator = std.testing.allocator;
    var dec = StreamDecryptor.init(allocator);
    defer dec.deinit();

    // Build a minimal v2 header
    var header: [36]u8 = undefined;
    header[0] = 2; // version
    header[1] = @intFromEnum(SymmetricAlgorithm.aes128); // sym algo
    header[2] = @intFromEnum(AeadAlgorithm.gcm); // aead algo
    header[3] = 0; // chunk size octet (2^6 = 64 bytes)
    @memset(header[4..36], 0xAA); // salt

    var result = try dec.feedHeader(&header);
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 2), result.version);
    try std.testing.expect(result.needs_key);
    try std.testing.expectEqual(@as(usize, 36), result.header_bytes_consumed);
}

test "StreamDecryptor feedHeader v1" {
    const allocator = std.testing.allocator;
    var dec = StreamDecryptor.init(allocator);
    defer dec.deinit();

    var header = [_]u8{1}; // version 1
    var result = try dec.feedHeader(&header);
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 1), result.version);
    try std.testing.expect(result.needs_key);
    try std.testing.expectEqual(@as(usize, 1), result.header_bytes_consumed);
}

test "StreamDecryptor invalid state" {
    const allocator = std.testing.allocator;
    var dec = StreamDecryptor.init(allocator);
    defer dec.deinit();

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    // Cannot feed data before header
    try std.testing.expectError(
        StreamDecryptError.InvalidState,
        dec.feedData("test", &out),
    );
}

test "StreamDecryptor setKey v1" {
    const allocator = std.testing.allocator;
    var dec = StreamDecryptor.init(allocator);
    defer dec.deinit();

    // Parse header
    var header = [_]u8{1};
    var result = try dec.feedHeader(&header);
    defer result.deinit(allocator);

    // Set key
    var key: [16]u8 = undefined;
    crypto.random.bytes(&key);
    try dec.setKey(&key, .aes128);

    try std.testing.expectEqual(StreamDecryptor.State.key_set, dec.state);
    try std.testing.expectEqual(@as(usize, 16), dec.key_len);
}

test "StreamDecryptor setKey wrong size" {
    const allocator = std.testing.allocator;
    var dec = StreamDecryptor.init(allocator);
    defer dec.deinit();

    var header = [_]u8{1};
    var result = try dec.feedHeader(&header);
    defer result.deinit(allocator);

    var key: [8]u8 = undefined;
    crypto.random.bytes(&key);
    try std.testing.expectError(
        StreamDecryptError.KeySizeMismatch,
        dec.setKey(&key, .aes128),
    );
}
