// SPDX-License-Identifier: MIT
//! BZip2 decompression for OpenPGP compressed data packets (algorithm 3).
//!
//! Implements the full BZip2 decompression pipeline:
//!   1. Stream header parsing (magic "BZh", block size 1-9)
//!   2. Huffman table decoding
//!   3. Move-to-front (MTF) decoding
//!   4. Run-length decoding (RLE2: zero-run encoding from MTF output)
//!   5. Inverse Burrows-Wheeler Transform (BWT)
//!   6. Run-length decoding (RLE1: initial byte-level RLE)
//!   7. CRC32 verification (block and stream level)
//!
//! Reference: https://en.wikipedia.org/wiki/Bzip2
//!            Julian Seward's bzip2 source code

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

pub const BZip2Error = error{
    /// The stream does not start with the "BZh" magic.
    InvalidMagic,
    /// The block size digit is not in 1..9.
    InvalidBlockSize,
    /// A block header is missing the expected magic bytes.
    InvalidBlockHeader,
    /// Huffman table is malformed or exceeds maximum code length.
    InvalidHuffmanTable,
    /// The number of Huffman trees or selectors is out of range.
    InvalidTreeCount,
    /// A symbol index is out of range during decoding.
    InvalidSymbol,
    /// The BWT origin pointer is out of range.
    InvalidOriginPointer,
    /// Block CRC mismatch.
    BlockCrcMismatch,
    /// Stream CRC mismatch.
    StreamCrcMismatch,
    /// Data is truncated or unexpected end of input.
    UnexpectedEndOfStream,
    /// Decoded data exceeds maximum expected size.
    DataTooLarge,
    /// Out of memory.
    OutOfMemory,
    /// Generic decompression failure.
    DecompressionFailed,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const BZIP2_MAGIC: [2]u8 = .{ 'B', 'Z' };
const BZIP2_HEADER_H: u8 = 'h';

/// Block header magic: 0x314159265359 (pi digits).
const BLOCK_HEADER_MAGIC: u48 = 0x314159265359;
/// End-of-stream magic: 0x177245385090 (sqrt(pi) digits).
const EOS_MAGIC: u48 = 0x177245385090;

const MAX_GROUPS: usize = 6;
const MAX_ALPHA_SIZE: usize = 258;
const MAX_SELECTORS: usize = 18002;
const MAX_CODE_LEN: u5 = 20;
const RUNA: u16 = 0;
const RUNB: u16 = 1;
const GROUP_SIZE: usize = 50;

// ---------------------------------------------------------------------------
// CRC32 for BZip2 (same polynomial as standard CRC32, but bit-reversed usage)
// ---------------------------------------------------------------------------

const Crc32Table = struct {
    table: [256]u32,

    fn init() Crc32Table {
        var t: Crc32Table = .{ .table = undefined };
        for (0..256) |i| {
            var crc: u32 = @intCast(i);
            for (0..8) |_| {
                if (crc & 1 != 0) {
                    crc = (crc >> 1) ^ 0xEDB88320;
                } else {
                    crc = crc >> 1;
                }
            }
            t.table[i] = crc;
        }
        return t;
    }

    fn update(self: *const Crc32Table, crc: u32, byte: u8) u32 {
        return (crc >> 8) ^ self.table[(crc ^ @as(u32, byte)) & 0xFF];
    }
};

/// BZip2 uses a different CRC convention than standard CRC32.
/// It processes bits MSB-first, effectively reflecting the polynomial.
const BZip2CrcTable = struct {
    table: [256]u32,

    fn init() BZip2CrcTable {
        @setEvalBranchQuota(10000);
        var t: BZip2CrcTable = .{ .table = undefined };
        for (0..256) |i| {
            var crc: u32 = @as(u32, @intCast(i)) << 24;
            for (0..8) |_| {
                if (crc & 0x80000000 != 0) {
                    crc = (crc << 1) ^ 0x04C11DB7;
                } else {
                    crc = crc << 1;
                }
            }
            t.table[i] = crc;
        }
        return t;
    }

    fn update(self: *const BZip2CrcTable, crc: u32, byte: u8) u32 {
        return (crc << 8) ^ self.table[((crc >> 24) ^ @as(u32, byte)) & 0xFF];
    }
};

const bzip2_crc_table: BZip2CrcTable = BZip2CrcTable.init();

pub fn bzip2CrcBlock(data: []const u8) u32 {
    var crc: u32 = 0xFFFFFFFF;
    for (data) |byte| {
        crc = bzip2_crc_table.update(crc, byte);
    }
    return crc ^ 0xFFFFFFFF;
}

// ---------------------------------------------------------------------------
// Bit reader
// ---------------------------------------------------------------------------

/// Reads individual bits from a byte slice, MSB first (BZip2 convention).
pub const BitReader = struct {
    data: []const u8,
    pos: usize,
    bit_buf: u32,
    bits_left: u5,

    pub fn init(data: []const u8) BitReader {
        return .{
            .data = data,
            .pos = 0,
            .bit_buf = 0,
            .bits_left = 0,
        };
    }

    pub fn readBit(self: *BitReader) BZip2Error!u1 {
        if (self.bits_left == 0) {
            if (self.pos >= self.data.len) return BZip2Error.UnexpectedEndOfStream;
            self.bit_buf = @as(u32, self.data[self.pos]);
            self.pos += 1;
            self.bits_left = 8;
        }
        self.bits_left -= 1;
        const shift: u5 = self.bits_left;
        return @intCast((self.bit_buf >> shift) & 1);
    }

    pub fn readBits(self: *BitReader, comptime T: type, n: u6) BZip2Error!T {
        var result: u32 = 0;
        for (0..n) |_| {
            result = (result << 1) | @as(u32, try self.readBit());
        }
        return @intCast(result);
    }

    pub fn readU32(self: *BitReader, n: u6) BZip2Error!u32 {
        var result: u32 = 0;
        for (0..n) |_| {
            result = (result << 1) | @as(u32, try self.readBit());
        }
        return result;
    }

    fn readBool(self: *BitReader) BZip2Error!bool {
        return (try self.readBit()) == 1;
    }
};

// ---------------------------------------------------------------------------
// Huffman decoder
// ---------------------------------------------------------------------------

pub const HuffmanTree = struct {
    min_len: u5,
    max_len: u5,
    /// Number of codes of each length (indexed 0..20, but only [min_len..max_len+1] used).
    count: [MAX_CODE_LEN + 1]u32,
    /// Base code for each length.
    base: [MAX_CODE_LEN + 1]u32,
    /// Permutation: maps code index -> symbol.
    perm: [MAX_ALPHA_SIZE]u16,

    pub fn build(lengths: []const u5, alpha_size: usize) BZip2Error!HuffmanTree {
        var tree: HuffmanTree = undefined;
        @memset(&tree.count, 0);
        @memset(&tree.base, 0);
        @memset(&tree.perm, 0);

        if (alpha_size == 0 or alpha_size > MAX_ALPHA_SIZE)
            return BZip2Error.InvalidHuffmanTable;

        var min_l: u5 = MAX_CODE_LEN;
        var max_l: u5 = 0;
        for (lengths[0..alpha_size]) |l| {
            if (l < 1 or l > MAX_CODE_LEN) return BZip2Error.InvalidHuffmanTable;
            if (l < min_l) min_l = l;
            if (l > max_l) max_l = l;
        }

        tree.min_len = min_l;
        tree.max_len = max_l;

        // Count symbols of each length
        for (lengths[0..alpha_size]) |l| {
            tree.count[l] += 1;
        }

        // Compute base codes
        var code: u32 = 0;
        for (min_l..@as(u6, max_l) + 1) |li| {
            const l: u5 = @intCast(li);
            tree.base[l] = code;
            code += tree.count[l];
            code <<= 1;
        }

        // Build permutation: for each length, assign symbols in order
        var idx: usize = 0;
        for (min_l..@as(u6, max_l) + 1) |li| {
            const l: u5 = @intCast(li);
            for (0..alpha_size) |s| {
                if (lengths[s] == l) {
                    if (idx >= MAX_ALPHA_SIZE) return BZip2Error.InvalidHuffmanTable;
                    tree.perm[idx] = @intCast(s);
                    idx += 1;
                }
            }
        }

        return tree;
    }

    pub fn decode(self: *const HuffmanTree, reader: *BitReader) BZip2Error!u16 {
        var code: u32 = 0;
        var len: u5 = self.min_len;

        // Read min_len bits to start
        for (0..self.min_len) |_| {
            code = (code << 1) | @as(u32, try reader.readBit());
        }

        while (true) {
            if (len > self.max_len) return BZip2Error.InvalidSymbol;

            if (code < self.base[len] + self.count[len]) {
                const sym_idx = code - self.base[len];
                // Find the right permutation index
                var perm_offset: u32 = 0;
                for (self.min_len..len) |li| {
                    const l: u5 = @intCast(li);
                    perm_offset += self.count[l];
                }
                const final_idx = perm_offset + sym_idx;
                if (final_idx >= MAX_ALPHA_SIZE) return BZip2Error.InvalidSymbol;
                return self.perm[final_idx];
            }

            if (len >= MAX_CODE_LEN) return BZip2Error.InvalidHuffmanTable;
            code = (code << 1) | @as(u32, try reader.readBit());
            len += 1;
        }
    }
};

// ---------------------------------------------------------------------------
// BZip2 block decoder
// ---------------------------------------------------------------------------

/// Decode a single BZip2 block, returning the decompressed bytes.
fn decodeBlock(
    allocator: Allocator,
    reader: *BitReader,
    block_size_100k: u32,
) BZip2Error!struct { data: []u8, crc: u32 } {
    // Read block CRC (32 bits)
    const expected_crc = try reader.readU32(32);

    // Read randomized flag (1 bit) - must be 0 in modern bzip2
    const randomized = try reader.readBool();
    if (randomized) return BZip2Error.DecompressionFailed;

    // Read BWT origin pointer (24 bits)
    const origin_ptr = try reader.readU32(24);

    // Read in-use bitmaps: 16 bits for which groups of 16 are used
    const used_groups = try reader.readBits(u16, 16);

    // Then for each set group, 16 bits for which symbols in that group
    var in_use: [256]bool = .{false} ** 256;
    var n_in_use: u16 = 0;

    for (0..16) |g| {
        if (used_groups & (@as(u16, 1) << @intCast(15 - g)) != 0) {
            const group_bits = try reader.readBits(u16, 16);
            for (0..16) |s| {
                if (group_bits & (@as(u16, 1) << @intCast(15 - s)) != 0) {
                    in_use[g * 16 + s] = true;
                    n_in_use += 1;
                }
            }
        }
    }

    if (n_in_use == 0) return BZip2Error.InvalidBlockHeader;

    // alpha_size = n_in_use + 2 (for RUNA, RUNB)
    const alpha_size: u16 = n_in_use + 2;

    // Read number of Huffman trees (3 bits)
    const n_trees = try reader.readBits(u8, 3);
    if (n_trees < 2 or n_trees > MAX_GROUPS) return BZip2Error.InvalidTreeCount;

    // Read number of selectors (15 bits)
    const n_selectors = try reader.readBits(u16, 15);
    if (n_selectors == 0 or n_selectors > MAX_SELECTORS) return BZip2Error.InvalidTreeCount;

    // Read selector list (MTF-encoded unary codes)
    var selector_mtf: [MAX_SELECTORS]u8 = undefined;
    for (0..n_selectors) |i| {
        var j: u8 = 0;
        while (try reader.readBool()) {
            j += 1;
            if (j >= n_trees) return BZip2Error.InvalidTreeCount;
        }
        selector_mtf[i] = j;
    }

    // Undo MTF on selectors
    var selectors: [MAX_SELECTORS]u8 = undefined;
    {
        var mtf_sel: [MAX_GROUPS]u8 = undefined;
        for (0..n_trees) |i| {
            mtf_sel[i] = @intCast(i);
        }
        for (0..n_selectors) |i| {
            const v = selector_mtf[i];
            const selected = mtf_sel[v];
            // Move to front
            var k: usize = v;
            while (k > 0) : (k -= 1) {
                mtf_sel[k] = mtf_sel[k - 1];
            }
            mtf_sel[0] = selected;
            selectors[i] = selected;
        }
    }

    // Read Huffman code lengths for each tree
    var trees: [MAX_GROUPS]HuffmanTree = undefined;
    for (0..n_trees) |t| {
        var lengths: [MAX_ALPHA_SIZE]u5 = undefined;
        var curr_len: i8 = @intCast(try reader.readBits(u8, 5));

        for (0..alpha_size) |s| {
            while (true) {
                if (curr_len < 1 or curr_len > MAX_CODE_LEN) return BZip2Error.InvalidHuffmanTable;
                const more = try reader.readBool();
                if (!more) break;
                const direction = try reader.readBool();
                if (direction) {
                    curr_len -= 1;
                } else {
                    curr_len += 1;
                }
            }
            if (curr_len < 1 or curr_len > MAX_CODE_LEN) return BZip2Error.InvalidHuffmanTable;
            lengths[s] = @intCast(curr_len);
        }

        trees[t] = try HuffmanTree.build(lengths[0..alpha_size], alpha_size);
    }

    // Decode symbols using Huffman trees (with selector switching every 50 symbols)
    const max_block_bytes = block_size_100k * 100000;

    // Build reverse MTF table: maps in_use symbols to byte values
    var mtf_table: [256]u8 = undefined;
    {
        var idx: u8 = 0;
        for (0..256) |c| {
            if (in_use[c]) {
                mtf_table[idx] = @intCast(c);
                idx += 1;
            }
        }
    }

    // Decode MTF + RLE2 encoded data
    var decoded_mtf: std.ArrayList(u8) = .empty;
    defer decoded_mtf.deinit(allocator);

    var group_idx: usize = 0;
    var group_pos: usize = 0;
    const eob_sym = alpha_size - 1;

    var decoded_count: usize = 0;

    while (true) {
        if (group_idx >= n_selectors) return BZip2Error.InvalidBlockHeader;
        const tree = &trees[selectors[group_idx]];

        const sym = try tree.decode(reader);

        if (sym == eob_sym) break;

        if (sym == RUNA or sym == RUNB) {
            // Run-length: decode zero runs
            // Accumulate run length: RUNA adds 1*power, RUNB adds 2*power
            var run_len: u32 = 0;
            var power: u32 = 1;
            var s = sym;
            while (true) {
                if (s == RUNA) {
                    run_len += power;
                } else if (s == RUNB) {
                    run_len += 2 * power;
                } else {
                    break;
                }
                power <<= 1;

                if (decoded_count + run_len > max_block_bytes)
                    return BZip2Error.DataTooLarge;

                group_pos += 1;
                if (group_pos >= GROUP_SIZE) {
                    group_pos = 0;
                    group_idx += 1;
                    if (group_idx >= n_selectors) break;
                }
                const next_tree = &trees[selectors[group_idx]];
                s = try next_tree.decode(reader);
            }

            // The run encodes repeated copies of mtf_table[0]
            const byte_val = mtf_table[0];
            try decoded_mtf.appendNTimes(allocator, byte_val, run_len);
            decoded_count += run_len;

            // The last symbol read (s) that wasn't RUNA/RUNB needs processing
            if (s == eob_sym) break;

            // Process this non-run symbol
            if (s >= alpha_size) return BZip2Error.InvalidSymbol;
            const mtf_idx = @as(u8, @intCast(s - 1));
            if (mtf_idx >= n_in_use) return BZip2Error.InvalidSymbol;

            const byte_v = mtf_table[mtf_idx];
            // Move to front
            var k: usize = mtf_idx;
            while (k > 0) : (k -= 1) {
                mtf_table[k] = mtf_table[k - 1];
            }
            mtf_table[0] = byte_v;

            try decoded_mtf.append(allocator, byte_v);
            decoded_count += 1;
        } else {
            // Regular symbol: undo MTF
            if (sym >= alpha_size) return BZip2Error.InvalidSymbol;
            const mtf_idx = @as(u8, @intCast(sym - 1));
            if (mtf_idx >= n_in_use) return BZip2Error.InvalidSymbol;

            const byte_v = mtf_table[mtf_idx];
            // Move to front
            var k: usize = mtf_idx;
            while (k > 0) : (k -= 1) {
                mtf_table[k] = mtf_table[k - 1];
            }
            mtf_table[0] = byte_v;

            try decoded_mtf.append(allocator, byte_v);
            decoded_count += 1;
        }

        if (decoded_count > max_block_bytes) return BZip2Error.DataTooLarge;

        group_pos += 1;
        if (group_pos >= GROUP_SIZE) {
            group_pos = 0;
            group_idx += 1;
        }
    }

    // Now decoded_mtf.items contains the BWT-transformed data
    // Apply inverse BWT
    const bwt_data = decoded_mtf.items;
    if (bwt_data.len == 0) {
        const empty = try allocator.alloc(u8, 0);
        return .{ .data = empty, .crc = expected_crc };
    }

    if (origin_ptr >= bwt_data.len) return BZip2Error.InvalidOriginPointer;

    const unbwt = try inverseBWT(allocator, bwt_data, @intCast(origin_ptr));
    errdefer allocator.free(unbwt);

    // Apply RLE1 decoding (undo initial run-length encoding)
    const rle_decoded = try decodeRLE1(allocator, unbwt);
    allocator.free(unbwt);
    errdefer allocator.free(rle_decoded);

    // Verify CRC
    const actual_crc = bzip2CrcBlock(rle_decoded);
    if (actual_crc != expected_crc) {
        allocator.free(rle_decoded);
        return BZip2Error.BlockCrcMismatch;
    }

    return .{ .data = rle_decoded, .crc = expected_crc };
}

// ---------------------------------------------------------------------------
// Inverse Burrows-Wheeler Transform
// ---------------------------------------------------------------------------

pub fn inverseBWT(allocator: Allocator, data: []const u8, origin: usize) BZip2Error![]u8 {
    const n = data.len;
    if (n == 0) {
        return try allocator.alloc(u8, 0);
    }

    // Count occurrences of each byte
    var counts: [256]u32 = .{0} ** 256;
    for (data) |b| {
        counts[b] += 1;
    }

    // Compute cumulative counts (prefix sums)
    var cumul: [257]u32 = .{0} ** 257;
    {
        var total: u32 = 0;
        for (0..256) |i| {
            cumul[i] = total;
            total += counts[i];
        }
        cumul[256] = total;
    }

    // Build transformation vector T
    const transform = allocator.alloc(u32, n) catch return BZip2Error.OutOfMemory;
    defer allocator.free(transform);

    // Reset counts for building T
    var counts2: [256]u32 = .{0} ** 256;
    for (0..n) |i| {
        const b = data[i];
        transform[cumul[b] + counts2[b]] = @intCast(i);
        counts2[b] += 1;
    }

    // Follow the transformation vector from origin
    const result = allocator.alloc(u8, n) catch return BZip2Error.OutOfMemory;
    errdefer allocator.free(result);

    var idx: u32 = @intCast(origin);
    for (0..n) |i| {
        idx = transform[idx];
        result[i] = data[idx];
    }

    return result;
}

// ---------------------------------------------------------------------------
// RLE1 decoding (initial run-length encoding used by bzip2)
// ---------------------------------------------------------------------------

/// BZip2's RLE1: any run of 4+ identical bytes is encoded as:
/// byte byte byte byte (count-4)
/// where (count-4) is a single byte giving extra repetitions.
pub fn decodeRLE1(allocator: Allocator, data: []const u8) BZip2Error![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    var i: usize = 0;
    while (i < data.len) {
        const b = data[i];
        try output.append(allocator, b);
        i += 1;

        // Check for run of 4
        var run: usize = 1;
        while (run < 4 and i < data.len and data[i] == b) {
            try output.append(allocator, b);
            i += 1;
            run += 1;
        }

        if (run == 4 and i < data.len) {
            // Next byte is the repeat count
            const repeat = data[i];
            i += 1;
            for (0..repeat) |_| {
                try output.append(allocator, b);
            }
        }
    }

    return output.toOwnedSlice(allocator) catch return BZip2Error.OutOfMemory;
}

// ---------------------------------------------------------------------------
// BZip2Decompressor - streaming interface
// ---------------------------------------------------------------------------

/// BZip2 decompressor with streaming interface.
///
/// Processes BZip2 compressed data from a byte slice and produces
/// decompressed output. Used by the OpenPGP compressed data packet
/// handler when compression algorithm 3 (BZip2) is encountered.
pub const BZip2Decompressor = struct {
    /// The compressed input data.
    input: []const u8,
    /// Whether decompression has completed.
    finished: bool,
    /// Decompressed output buffer (lazily filled).
    output: ?[]u8,
    /// Current read position in the output buffer.
    output_pos: usize,
    /// Block size from header (1-9, representing 100k-900k).
    block_size: u8,
    /// Stream-level CRC (combined from all blocks).
    stream_crc: u32,

    /// Initialize a decompressor from compressed data.
    pub fn init(data: []const u8) BZip2Decompressor {
        return .{
            .input = data,
            .finished = false,
            .output = null,
            .output_pos = 0,
            .block_size = 0,
            .stream_crc = 0,
        };
    }

    /// Read decompressed data into the provided buffer.
    /// Returns the number of bytes written.
    pub fn read(self: *BZip2Decompressor, allocator: Allocator, buf: []u8) BZip2Error!usize {
        // Lazily decompress all data on first read
        if (self.output == null and !self.finished) {
            self.output = try decompressAll(allocator, self.input);
            self.output_pos = 0;
        }

        if (self.output) |out| {
            const remaining = out.len - self.output_pos;
            if (remaining == 0) {
                self.finished = true;
                return 0;
            }
            const to_copy = @min(buf.len, remaining);
            @memcpy(buf[0..to_copy], out[self.output_pos .. self.output_pos + to_copy]);
            self.output_pos += to_copy;
            if (self.output_pos >= out.len) self.finished = true;
            return to_copy;
        }

        return 0;
    }

    /// Read all remaining decompressed data.
    pub fn readAll(self: *BZip2Decompressor, allocator: Allocator) BZip2Error![]u8 {
        if (self.output == null and !self.finished) {
            self.output = try decompressAll(allocator, self.input);
            self.output_pos = 0;
        }

        if (self.output) |out| {
            if (self.output_pos == 0) {
                // Caller takes ownership; we clear our reference.
                self.output = null;
                self.finished = true;
                return out;
            }
            // Partial read already happened, copy remainder
            const remaining = out[self.output_pos..];
            const result = allocator.dupe(u8, remaining) catch return BZip2Error.OutOfMemory;
            self.finished = true;
            return result;
        }

        return allocator.alloc(u8, 0) catch return BZip2Error.OutOfMemory;
    }

    /// Check if all data has been read.
    pub fn isFinished(self: *const BZip2Decompressor) bool {
        return self.finished;
    }

    /// Free the internal output buffer.
    pub fn deinit(self: *BZip2Decompressor, allocator: Allocator) void {
        if (self.output) |out| {
            allocator.free(out);
            self.output = null;
        }
    }
};

// ---------------------------------------------------------------------------
// Top-level decompression API
// ---------------------------------------------------------------------------

/// Decompress BZip2 data from a byte slice.
///
/// This is the main entry point for BZip2 decompression in the OpenPGP
/// compressed data packet handler. Returns the fully decompressed data.
///
/// The caller owns the returned slice and must free it with the same allocator.
pub fn decompress(allocator: Allocator, data: []const u8) BZip2Error![]u8 {
    return decompressAll(allocator, data);
}

/// Internal: decompress all blocks from a BZip2 stream.
fn decompressAll(allocator: Allocator, data: []const u8) BZip2Error![]u8 {
    if (data.len < 4) return BZip2Error.InvalidMagic;

    // Verify stream header: "BZh" + block_size_digit
    if (data[0] != BZIP2_MAGIC[0] or data[1] != BZIP2_MAGIC[1])
        return BZip2Error.InvalidMagic;
    if (data[2] != BZIP2_HEADER_H) return BZip2Error.InvalidMagic;

    const block_size_digit = data[3];
    if (block_size_digit < '1' or block_size_digit > '9')
        return BZip2Error.InvalidBlockSize;
    const block_size_100k: u32 = @as(u32, block_size_digit - '0');

    var reader = BitReader.init(data[4..]);
    var combined_output: std.ArrayList(u8) = .empty;
    errdefer combined_output.deinit(allocator);

    var stream_crc: u32 = 0;

    // Process blocks
    while (true) {
        // Read 48-bit magic to determine block type
        const magic = try reader.readU32(24);
        const magic_lo = try reader.readU32(24);
        const full_magic: u48 = (@as(u48, magic) << 24) | @as(u48, magic_lo);

        if (full_magic == BLOCK_HEADER_MAGIC) {
            // Decode a compressed block
            const block_result = try decodeBlock(allocator, &reader, block_size_100k);
            defer allocator.free(block_result.data);

            // Update stream CRC: stream_crc = (stream_crc << 1 | stream_crc >> 31) ^ block_crc
            stream_crc = ((stream_crc << 1) | (stream_crc >> 31)) ^ block_result.crc;

            try combined_output.appendSlice(allocator, block_result.data);
        } else if (full_magic == EOS_MAGIC) {
            // End of stream: read stream CRC
            const expected_stream_crc = try reader.readU32(32);

            if (stream_crc != expected_stream_crc) {
                return BZip2Error.StreamCrcMismatch;
            }
            break;
        } else {
            return BZip2Error.InvalidBlockHeader;
        }
    }

    return combined_output.toOwnedSlice(allocator) catch return BZip2Error.OutOfMemory;
}

// ---------------------------------------------------------------------------
// BZip2 compression (minimal, for testing) - creates valid bzip2 streams
// ---------------------------------------------------------------------------

/// Create a minimal BZip2 compressed stream from input data.
/// This is intentionally simple and used for testing decompression.
/// It does NOT produce optimally compressed output.
pub fn compressForTesting(allocator: Allocator, input: []const u8) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // Stream header: "BZh9"
    try output.appendSlice(allocator, &.{ 'B', 'Z', 'h', '9' });

    if (input.len == 0) {
        // Write end-of-stream marker with zero CRC
        var writer = BitWriter.init(allocator);
        defer writer.deinit();
        try writer.writeBits(48, @as(u64, EOS_MAGIC));
        try writer.writeBits(32, 0); // stream CRC
        try writer.flush();
        try output.appendSlice(allocator, writer.bytes());
        return output.toOwnedSlice(allocator);
    }

    // Apply RLE1 encoding
    const rle1_data = try encodeRLE1(allocator, input);
    defer allocator.free(rle1_data);

    // Compute block CRC
    const block_crc = bzip2CrcBlock(input);

    // Apply BWT
    const bwt_result = try forwardBWT(allocator, rle1_data);
    defer allocator.free(bwt_result.data);

    // Build used symbols bitmap
    var in_use: [256]bool = .{false} ** 256;
    for (bwt_result.data) |b| {
        in_use[b] = true;
    }

    // MTF encode
    const mtf_result = try mtfEncode(allocator, bwt_result.data, &in_use);
    defer allocator.free(mtf_result.symbols);

    // Now write the block
    var writer = BitWriter.init(allocator);
    defer writer.deinit();

    // Block header magic
    try writer.writeBits(48, @as(u64, BLOCK_HEADER_MAGIC));
    // Block CRC
    try writer.writeBits(32, @as(u64, block_crc));
    // Randomized flag
    try writer.writeBits(1, 0);
    // Origin pointer
    try writer.writeBits(24, @as(u64, bwt_result.origin));

    // In-use bitmap (16 groups of 16)
    var group_used: u16 = 0;
    for (0..16) |g| {
        var any = false;
        for (0..16) |s| {
            if (in_use[g * 16 + s]) {
                any = true;
                break;
            }
        }
        if (any) {
            group_used |= @as(u16, 1) << @intCast(15 - g);
        }
    }
    try writer.writeBits(16, @as(u64, group_used));

    for (0..16) |g| {
        if (group_used & (@as(u16, 1) << @intCast(15 - g)) != 0) {
            var sym_bits: u16 = 0;
            for (0..16) |s| {
                if (in_use[g * 16 + s]) {
                    sym_bits |= @as(u16, 1) << @intCast(15 - s);
                }
            }
            try writer.writeBits(16, @as(u64, sym_bits));
        }
    }

    // Number of trees (we use 2 for simplicity, minimum required)
    const n_trees: u8 = 2;
    try writer.writeBits(3, n_trees);

    // Number of selectors
    const n_symbols = mtf_result.symbols.len;
    const n_selectors_val: u16 = @intCast((n_symbols + GROUP_SIZE - 1) / GROUP_SIZE + 1);
    try writer.writeBits(15, @as(u64, n_selectors_val));

    // Selectors: all 0 (use first tree) - unary code: single 0 bit
    for (0..n_selectors_val) |_| {
        try writer.writeBits(1, 0); // tree 0, unary = no 1-bits, then 0 terminator
    }

    // Build simple Huffman trees with fixed-length codes
    const alpha_sz: u16 = mtf_result.n_in_use + 2;
    // Use 5-bit codes for all symbols (simple but valid)
    const code_len: u5 = if (alpha_sz <= 4)
        2
    else if (alpha_sz <= 8)
        3
    else if (alpha_sz <= 16)
        4
    else if (alpha_sz <= 32)
        5
    else if (alpha_sz <= 64)
        6
    else if (alpha_sz <= 128)
        7
    else
        8;

    // Write both trees with same code lengths
    for (0..n_trees) |_| {
        try writer.writeBits(5, @as(u64, code_len)); // starting length
        for (0..alpha_sz) |_| {
            try writer.writeBits(1, 0); // no change, terminate
        }
    }

    // Encode symbols using fixed-length codes
    // With uniform code length, symbol i has code = i in code_len bits
    for (mtf_result.symbols) |sym| {
        try writer.writeBits(code_len, @as(u64, sym));
    }

    // Write EOB symbol (alpha_sz - 1)
    try writer.writeBits(code_len, @as(u64, alpha_sz - 1));

    // End-of-stream magic
    try writer.writeBits(48, @as(u64, EOS_MAGIC));

    // Stream CRC (single block: rotated once then XOR)
    const stream_crc = ((0 << 1) | (0 >> 31)) ^ block_crc;
    try writer.writeBits(32, @as(u64, stream_crc));

    try writer.flush();
    try output.appendSlice(allocator, writer.bytes());

    return output.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Bit writer (for testing compression)
// ---------------------------------------------------------------------------

pub const BitWriter = struct {
    data: std.ArrayList(u8),
    gpa: Allocator,
    current_byte: u8,
    bits_in_byte: u4,

    pub fn init(allocator: Allocator) BitWriter {
        return .{
            .data = .empty,
            .gpa = allocator,
            .current_byte = 0,
            .bits_in_byte = 0,
        };
    }

    pub fn deinit(self: *BitWriter) void {
        self.data.deinit(self.gpa);
    }

    pub fn writeBits(self: *BitWriter, n: u6, value: u64) !void {
        var remaining: u6 = n;
        const val = value;
        while (remaining > 0) {
            remaining -= 1;
            const bit: u1 = @intCast((val >> remaining) & 1);
            self.current_byte = (self.current_byte << 1) | bit;
            self.bits_in_byte += 1;
            if (self.bits_in_byte == 8) {
                try self.data.append(self.gpa, self.current_byte);
                self.current_byte = 0;
                self.bits_in_byte = 0;
            }
        }
    }

    pub fn flush(self: *BitWriter) !void {
        if (self.bits_in_byte > 0) {
            // Pad remaining bits with zeros
            const shift: u4 = 8 - self.bits_in_byte;
            self.current_byte <<= @intCast(shift);
            try self.data.append(self.gpa, self.current_byte);
            self.current_byte = 0;
            self.bits_in_byte = 0;
        }
    }

    pub fn bytes(self: *const BitWriter) []const u8 {
        return self.data.items;
    }
};

// ---------------------------------------------------------------------------
// Forward BWT (for testing)
// ---------------------------------------------------------------------------

const BwtResult = struct {
    data: []u8,
    origin: u32,
};

pub fn forwardBWT(allocator: Allocator, data: []const u8) !BwtResult {
    const n = data.len;
    if (n == 0) {
        return .{ .data = try allocator.alloc(u8, 0), .origin = 0 };
    }

    // Create rotation indices
    const indices = try allocator.alloc(u32, n);
    defer allocator.free(indices);
    for (0..n) |i| {
        indices[i] = @intCast(i);
    }

    // Sort rotations lexicographically
    const Context = struct {
        data_ptr: []const u8,
        data_len: usize,
    };
    const ctx = Context{ .data_ptr = data, .data_len = n };

    std.mem.sortUnstable(u32, indices, ctx, struct {
        fn lessThan(c: Context, a: u32, b: u32) bool {
            for (0..c.data_len) |k| {
                const ca = c.data_ptr[(@as(usize, a) + k) % c.data_len];
                const cb = c.data_ptr[(@as(usize, b) + k) % c.data_len];
                if (ca < cb) return true;
                if (ca > cb) return false;
            }
            return false;
        }
    }.lessThan);

    // Build the last column and find origin pointer
    const result = try allocator.alloc(u8, n);
    var origin: u32 = 0;
    for (0..n) |i| {
        const rot_start = indices[i];
        // Last character of rotation starting at rot_start is at (rot_start + n - 1) % n
        result[i] = data[(@as(usize, rot_start) + n - 1) % n];
        if (rot_start == 0) {
            origin = @intCast(i);
        }
    }

    return .{ .data = result, .origin = origin };
}

// ---------------------------------------------------------------------------
// RLE1 encoding (for testing)
// ---------------------------------------------------------------------------

pub fn encodeRLE1(allocator: Allocator, data: []const u8) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    var i: usize = 0;
    while (i < data.len) {
        const b = data[i];
        var run: usize = 1;
        while (i + run < data.len and data[i + run] == b and run < 259) {
            run += 1;
        }

        if (run >= 4) {
            // Write 4 copies + count byte
            for (0..4) |_| {
                try output.append(allocator, b);
            }
            try output.append(allocator, @intCast(run - 4));
            i += run;
        } else {
            try output.append(allocator, b);
            i += 1;
        }
    }

    return output.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// MTF encoding (for testing)
// ---------------------------------------------------------------------------

const MtfResult = struct {
    symbols: []u16,
    n_in_use: u16,
};

pub fn mtfEncode(allocator: Allocator, data: []const u8, in_use: *const [256]bool) !MtfResult {
    // Build MTF table
    var mtf_list: [256]u8 = undefined;
    var n_in_use: u16 = 0;
    for (0..256) |c| {
        if (in_use[c]) {
            mtf_list[n_in_use] = @intCast(c);
            n_in_use += 1;
        }
    }

    // For simplicity, encode each byte as its MTF index + 1 (skipping RUNA/RUNB)
    // This is a simplified encoding that avoids zero-run encoding
    var symbols: std.ArrayList(u16) = .empty;
    errdefer symbols.deinit(allocator);

    for (data) |b| {
        // Find position in MTF list
        var pos: u16 = 0;
        for (0..n_in_use) |j| {
            if (mtf_list[j] == b) {
                pos = @intCast(j);
                break;
            }
        }

        if (pos == 0) {
            // Encode as RUNA (single zero run of length 1)
            try symbols.append(allocator, RUNA);
        } else {
            // Encode as symbol pos + 1
            try symbols.append(allocator, pos + 1);
        }

        // Move to front
        const val = mtf_list[pos];
        var k: usize = pos;
        while (k > 0) : (k -= 1) {
            mtf_list[k] = mtf_list[k - 1];
        }
        mtf_list[0] = val;
    }

    return .{
        .symbols = try symbols.toOwnedSlice(allocator),
        .n_in_use = n_in_use,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "BitReader basic" {
    const data = [_]u8{ 0b10110011, 0b01010101 };
    var reader = BitReader.init(&data);

    try std.testing.expectEqual(@as(u1, 1), try reader.readBit());
    try std.testing.expectEqual(@as(u1, 0), try reader.readBit());
    try std.testing.expectEqual(@as(u1, 1), try reader.readBit());
    try std.testing.expectEqual(@as(u1, 1), try reader.readBit());
    try std.testing.expectEqual(@as(u1, 0), try reader.readBit());
    try std.testing.expectEqual(@as(u1, 0), try reader.readBit());
    try std.testing.expectEqual(@as(u1, 1), try reader.readBit());
    try std.testing.expectEqual(@as(u1, 1), try reader.readBit());
    // Second byte
    try std.testing.expectEqual(@as(u1, 0), try reader.readBit());
    try std.testing.expectEqual(@as(u1, 1), try reader.readBit());
}

test "BitReader readBits" {
    const data = [_]u8{0b11001010};
    var reader = BitReader.init(&data);

    const val = try reader.readBits(u8, 4);
    try std.testing.expectEqual(@as(u8, 0b1100), val);
}

test "BitReader end of stream" {
    const data = [_]u8{0xFF};
    var reader = BitReader.init(&data);

    // Read all 8 bits
    for (0..8) |_| {
        _ = try reader.readBit();
    }
    // Next should fail
    try std.testing.expectError(BZip2Error.UnexpectedEndOfStream, reader.readBit());
}

test "BZip2 CRC32" {
    const data = "Hello, World!";
    const crc = bzip2CrcBlock(data);
    // Verify CRC is deterministic and non-zero
    try std.testing.expect(crc != 0);

    // Same data should produce same CRC
    const crc2 = bzip2CrcBlock(data);
    try std.testing.expectEqual(crc, crc2);

    // Different data should produce different CRC
    const crc3 = bzip2CrcBlock("hello, world!");
    try std.testing.expect(crc != crc3);
}

test "BZip2 CRC32 empty" {
    const crc = bzip2CrcBlock("");
    // CRC of empty data should be 0 (0xFFFFFFFF ^ 0xFFFFFFFF)
    try std.testing.expectEqual(@as(u32, 0), crc);
}

test "inverse BWT roundtrip" {
    const allocator = std.testing.allocator;

    const input = "banana";
    const bwt = try forwardBWT(allocator, input);
    defer allocator.free(bwt.data);

    const recovered = try inverseBWT(allocator, bwt.data, bwt.origin);
    defer allocator.free(recovered);

    try std.testing.expectEqualStrings(input, recovered);
}

test "inverse BWT single char" {
    const allocator = std.testing.allocator;

    const input = "a";
    const bwt = try forwardBWT(allocator, input);
    defer allocator.free(bwt.data);

    const recovered = try inverseBWT(allocator, bwt.data, bwt.origin);
    defer allocator.free(recovered);

    try std.testing.expectEqualStrings(input, recovered);
}

test "inverse BWT repeated chars" {
    const allocator = std.testing.allocator;

    const input = "aaaa";
    const bwt = try forwardBWT(allocator, input);
    defer allocator.free(bwt.data);

    const recovered = try inverseBWT(allocator, bwt.data, bwt.origin);
    defer allocator.free(recovered);

    try std.testing.expectEqualStrings(input, recovered);
}

test "RLE1 roundtrip no runs" {
    const allocator = std.testing.allocator;

    const input = "abc";
    const encoded = try encodeRLE1(allocator, input);
    defer allocator.free(encoded);

    const decoded = try decodeRLE1(allocator, encoded);
    defer allocator.free(decoded);

    try std.testing.expectEqualStrings(input, decoded);
}

test "RLE1 roundtrip with runs" {
    const allocator = std.testing.allocator;

    const input = "aaaaabbbcc";
    const encoded = try encodeRLE1(allocator, input);
    defer allocator.free(encoded);

    const decoded = try decodeRLE1(allocator, encoded);
    defer allocator.free(decoded);

    try std.testing.expectEqualStrings(input, decoded);
}

test "RLE1 decode explicit" {
    const allocator = std.testing.allocator;

    // "aaaa" + count=2 => "aaaaaa"
    const encoded = [_]u8{ 'a', 'a', 'a', 'a', 2 };
    const decoded = try decodeRLE1(allocator, &encoded);
    defer allocator.free(decoded);

    try std.testing.expectEqualStrings("aaaaaa", decoded);
}

test "MTF encode basic" {
    const allocator = std.testing.allocator;

    const input = "aba";
    var in_use: [256]bool = .{false} ** 256;
    in_use['a'] = true;
    in_use['b'] = true;

    const result = try mtfEncode(allocator, input, &in_use);
    defer allocator.free(result.symbols);

    try std.testing.expectEqual(@as(u16, 2), result.n_in_use);
    // 'a' is at index 0 -> RUNA (0)
    // 'b' is at index 1 (but 'a' still at front) -> symbol 2 (index 1 + 1)
    // 'a' is at index 1 (after 'b' moved front) -> symbol 2 (index 1 + 1)
    try std.testing.expectEqual(@as(u16, RUNA), result.symbols[0]);
    try std.testing.expectEqual(@as(u16, 2), result.symbols[1]);
    try std.testing.expectEqual(@as(u16, 2), result.symbols[2]);
}

test "HuffmanTree build and decode" {
    // Build a simple tree: 2 symbols, lengths [1, 1]
    // Symbol 0: code 0, Symbol 1: code 1
    const lengths = [_]u5{ 1, 1 };
    const tree = try HuffmanTree.build(&lengths, 2);

    // Decode symbol 0 (bit = 0)
    var data = [_]u8{0b00000000}; // all zeros
    var reader = BitReader.init(&data);
    const sym0 = try tree.decode(&reader);
    try std.testing.expectEqual(@as(u16, 0), sym0);

    // Decode symbol 1 (bit = 1)
    var data1 = [_]u8{0b10000000}; // leading 1
    var reader1 = BitReader.init(&data1);
    const sym1 = try tree.decode(&reader1);
    try std.testing.expectEqual(@as(u16, 1), sym1);
}

test "HuffmanTree three symbols" {
    // 3 symbols: a=1 bit (code 0), b=2 bits (code 10), c=2 bits (code 11)
    const lengths = [_]u5{ 1, 2, 2 };
    const tree = try HuffmanTree.build(&lengths, 3);

    // Symbol 0: bit pattern 0
    var d0 = [_]u8{0b00000000};
    var r0 = BitReader.init(&d0);
    try std.testing.expectEqual(@as(u16, 0), try tree.decode(&r0));

    // Symbol 1: bit pattern 10
    var d1 = [_]u8{0b10000000};
    var r1 = BitReader.init(&d1);
    try std.testing.expectEqual(@as(u16, 1), try tree.decode(&r1));

    // Symbol 2: bit pattern 11
    var d2 = [_]u8{0b11000000};
    var r2 = BitReader.init(&d2);
    try std.testing.expectEqual(@as(u16, 2), try tree.decode(&r2));
}

test "BZip2Decompressor invalid magic" {
    const allocator = std.testing.allocator;
    const bad_data = "not bzip2 data";
    const result = decompress(allocator, bad_data);
    try std.testing.expectError(BZip2Error.InvalidMagic, result);
}

test "BZip2Decompressor too short" {
    const allocator = std.testing.allocator;
    const result = decompress(allocator, "BZ");
    try std.testing.expectError(BZip2Error.InvalidMagic, result);
}

test "BZip2Decompressor bad block size" {
    const allocator = std.testing.allocator;
    const result = decompress(allocator, "BZh0");
    try std.testing.expectError(BZip2Error.InvalidBlockSize, result);
}

test "BZip2Decompressor bad block size high" {
    const allocator = std.testing.allocator;
    // 'h' followed by 'a' which is not a digit 1-9
    const result = decompress(allocator, "BZha");
    try std.testing.expectError(BZip2Error.InvalidBlockSize, result);
}

test "forward BWT basic" {
    const allocator = std.testing.allocator;

    const bwt = try forwardBWT(allocator, "abracadabra");
    defer allocator.free(bwt.data);

    // BWT of "abracadabra" is well-known: "rdarcaaaabb" with origin at position 2
    // The last column after sorting all rotations
    try std.testing.expectEqual(@as(usize, 11), bwt.data.len);

    // Roundtrip verification
    const recovered = try inverseBWT(allocator, bwt.data, bwt.origin);
    defer allocator.free(recovered);
    try std.testing.expectEqualStrings("abracadabra", recovered);
}

test "forward BWT empty" {
    const allocator = std.testing.allocator;

    const bwt = try forwardBWT(allocator, "");
    defer allocator.free(bwt.data);
    try std.testing.expectEqual(@as(usize, 0), bwt.data.len);
}

test "BitWriter basic" {
    var writer = BitWriter.init(std.testing.allocator);
    defer writer.deinit();

    try writer.writeBits(8, 0xFF);
    try writer.writeBits(4, 0b1010);
    try writer.flush();

    const data = writer.bytes();
    try std.testing.expectEqual(@as(usize, 2), data.len);
    try std.testing.expectEqual(@as(u8, 0xFF), data[0]);
    try std.testing.expectEqual(@as(u8, 0b10100000), data[1]);
}

test "BZip2Decompressor streaming read" {
    const allocator = std.testing.allocator;

    // Create a stream with just end-of-stream marker (empty content)
    // We'll test the interface even with minimal data
    var decompressor = BZip2Decompressor.init("BZh9not-valid-but-testing-interface");
    defer decompressor.deinit(allocator);

    try std.testing.expect(!decompressor.isFinished());
}

test "encodeRLE1 empty" {
    const allocator = std.testing.allocator;
    const encoded = try encodeRLE1(allocator, "");
    defer allocator.free(encoded);
    try std.testing.expectEqual(@as(usize, 0), encoded.len);
}

test "decodeRLE1 empty" {
    const allocator = std.testing.allocator;
    const decoded = try decodeRLE1(allocator, "");
    defer allocator.free(decoded);
    try std.testing.expectEqual(@as(usize, 0), decoded.len);
}

test "inverse BWT two chars" {
    const allocator = std.testing.allocator;

    const input = "ab";
    const bwt = try forwardBWT(allocator, input);
    defer allocator.free(bwt.data);

    const recovered = try inverseBWT(allocator, bwt.data, bwt.origin);
    defer allocator.free(recovered);

    try std.testing.expectEqualStrings(input, recovered);
}

test "CRC32 known values" {
    // Test with known string to verify CRC implementation is consistent
    const crc1 = bzip2CrcBlock("test");
    const crc2 = bzip2CrcBlock("test");
    try std.testing.expectEqual(crc1, crc2);

    // Different strings produce different CRCs
    const crc3 = bzip2CrcBlock("Test");
    try std.testing.expect(crc1 != crc3);
}

test "BZip2 stream header validation" {
    const allocator = std.testing.allocator;

    // Valid magic but missing data after header
    try std.testing.expectError(
        BZip2Error.UnexpectedEndOfStream,
        decompress(allocator, "BZh9"),
    );

    // Wrong second magic byte
    try std.testing.expectError(
        BZip2Error.InvalidMagic,
        decompress(allocator, "BXh9data"),
    );

    // Wrong third byte (not 'h')
    try std.testing.expectError(
        BZip2Error.InvalidMagic,
        decompress(allocator, "BZx9data"),
    );
}
