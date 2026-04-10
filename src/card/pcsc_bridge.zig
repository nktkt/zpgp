// SPDX-License-Identifier: MIT
//! PC/SC bridge for OpenPGP smart card communication.
//!
//! Provides an abstraction layer between the OpenPGP card protocol
//! (APDU commands) and PC/SC (Personal Computer/Smart Card) readers.
//!
//! This module handles:
//!   - PCSC context management (reader enumeration)
//!   - ATR (Answer To Reset) parsing
//!   - APDU command/response framing for T=0 and T=1 protocols
//!   - Card detection and connection management
//!   - Integration with openpgp_card.zig types
//!
//! The implementation is platform-independent — it defines interfaces
//! that platform-specific backends (WinSCard, pcsclite, CryptoTokenKit)
//! can implement.
//!
//! Reference: PC/SC Specification Part 3 (Requirements for PC-Connected
//!            Interface Devices), ISO 7816-3/4

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const openpgp_card = @import("openpgp_card.zig");
const ApduCommand = openpgp_card.ApduCommand;
const ApduResponse = openpgp_card.ApduResponse;
const CardError = openpgp_card.CardError;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors specific to PCSC operations.
pub const PcscError = error{
    /// PC/SC subsystem is not available.
    PcscNotAvailable,
    /// No readers are connected to the system.
    NoReadersAvailable,
    /// The specified reader was not found.
    ReaderNotFound,
    /// Failed to establish a context with the PC/SC subsystem.
    ContextEstablishFailed,
    /// The PC/SC context is invalid or has been released.
    InvalidContext,
    /// Failed to connect to the card in the reader.
    ConnectionFailed,
    /// The card was removed during an operation.
    CardRemoved,
    /// The card did not respond (timeout).
    CardUnresponsive,
    /// The transmitted APDU is malformed.
    InvalidApdu,
    /// The response from the card is malformed.
    InvalidResponse,
    /// Protocol negotiation failed.
    ProtocolMismatch,
    /// The ATR (Answer To Reset) is invalid or unrecognized.
    InvalidAtr,
    /// A transmit operation failed.
    TransmitFailed,
    /// The card was reset unexpectedly.
    CardReset,
    /// Sharing violation (another application has exclusive access).
    SharingViolation,
    /// Out of memory.
    OutOfMemory,
    /// Generic communication error.
    CommunicationError,
};

// ---------------------------------------------------------------------------
// Smart card protocol types
// ---------------------------------------------------------------------------

/// Smart card communication protocol.
pub const Protocol = enum(u8) {
    /// T=0: Character-oriented half-duplex protocol (ISO 7816-3).
    t0 = 0,
    /// T=1: Block-oriented half-duplex protocol (ISO 7816-3).
    t1 = 1,
    /// Raw protocol (direct communication).
    raw = 255,

    pub fn name(self: Protocol) []const u8 {
        return switch (self) {
            .t0 => "T=0",
            .t1 => "T=1",
            .raw => "Raw",
        };
    }
};

/// Card disposition action when disconnecting.
pub const Disposition = enum(u8) {
    /// Leave the card in its current state.
    leave = 0,
    /// Reset the card.
    reset = 1,
    /// Power down the card.
    unpower = 2,
    /// Eject the card (if supported by the reader).
    eject = 3,
};

/// Share mode for card connections.
pub const ShareMode = enum(u8) {
    /// Exclusive access (no other applications can connect).
    exclusive = 1,
    /// Shared access (multiple applications can connect).
    shared = 2,
    /// Direct access to the reader (no card communication).
    direct = 3,
};

/// Card state as reported by the PCSC subsystem.
pub const CardState = enum(u8) {
    /// Reader is empty (no card inserted).
    absent = 0,
    /// Card is present but not powered.
    present = 1,
    /// Card is present and powered but not negotiated.
    swallowed = 2,
    /// Card is ready for communication (ATR received).
    powered = 3,
    /// Card is in a negotiable state.
    negotiable = 4,
    /// Card is in a specific protocol state (T=0 or T=1).
    specific = 5,

    pub fn name(self: CardState) []const u8 {
        return switch (self) {
            .absent => "Absent",
            .present => "Present",
            .swallowed => "Swallowed",
            .powered => "Powered",
            .negotiable => "Negotiable",
            .specific => "Specific",
        };
    }

    /// Whether a card is present and potentially usable.
    pub fn isPresent(self: CardState) bool {
        return self != .absent;
    }

    /// Whether the card is ready for APDU communication.
    pub fn isReady(self: CardState) bool {
        return switch (self) {
            .powered, .negotiable, .specific => true,
            else => false,
        };
    }
};

// ---------------------------------------------------------------------------
// ATR (Answer To Reset) parsing
// ---------------------------------------------------------------------------

/// Maximum ATR length per ISO 7816-3.
const MAX_ATR_LEN: usize = 33;

/// Parsed ATR (Answer To Reset) from a smart card.
///
/// The ATR is the first response from a card after reset and contains
/// information about the card's communication parameters.
///
/// Structure: TS T0 [TA1 TB1 TC1 TD1 [TA2...]] [T1 T2 ... TK] [TCK]
pub const Atr = struct {
    /// Raw ATR bytes.
    raw: [MAX_ATR_LEN]u8,
    /// Length of the ATR.
    len: u8,
    /// Initial character (TS): 0x3B = direct convention, 0x3F = inverse.
    ts: u8,
    /// Format byte (T0): indicates which interface bytes follow and
    /// number of historical bytes.
    t0: u8,
    /// Number of historical bytes (from T0 lower nibble).
    historical_len: u4,
    /// Supported protocols (extracted from TD bytes).
    protocols: ProtocolSupport,
    /// Whether the card supports T=0.
    supports_t0: bool,
    /// Whether the card supports T=1.
    supports_t1: bool,
    /// Fi/Di speed parameters (from TA1, if present).
    fi_di: ?struct { fi: u4, di: u4 },
    /// Extra guard time (from TC1, if present).
    extra_guard_time: ?u8,
    /// Historical bytes (T1..TK).
    historical: [15]u8,
    /// Check byte (TCK), if present.
    tck: ?u8,
    /// Whether the ATR uses direct convention.
    direct_convention: bool,

    /// Protocol support information extracted from TD bytes.
    pub const ProtocolSupport = struct {
        t0: bool,
        t1: bool,
        /// Other protocols indicated in the ATR.
        other: u8,
    };

    /// Parse an ATR from raw bytes.
    pub fn parse(data: []const u8) PcscError!Atr {
        if (data.len < 2) return PcscError.InvalidAtr;
        if (data.len > MAX_ATR_LEN) return PcscError.InvalidAtr;

        var atr: Atr = undefined;
        @memset(&atr.raw, 0);
        @memset(&atr.historical, 0);
        @memcpy(atr.raw[0..data.len], data);
        atr.len = @intCast(data.len);

        // TS byte
        atr.ts = data[0];
        atr.direct_convention = (atr.ts == 0x3B);
        if (atr.ts != 0x3B and atr.ts != 0x3F) return PcscError.InvalidAtr;

        // T0 byte
        atr.t0 = data[1];
        atr.historical_len = @intCast(atr.t0 & 0x0F);

        // Parse interface bytes
        var offset: usize = 2;
        var td_byte = atr.t0;
        atr.supports_t0 = true; // T=0 is always implied if no TD1
        atr.supports_t1 = false;
        atr.fi_di = null;
        atr.extra_guard_time = null;
        atr.tck = null;
        atr.protocols = .{ .t0 = true, .t1 = false, .other = 0 };

        var first_td = true;
        var need_tck = false;

        while (true) {
            const y = (td_byte >> 4) & 0x0F;

            // TA(i) present?
            if (y & 0x01 != 0) {
                if (offset >= data.len) return PcscError.InvalidAtr;
                if (first_td) {
                    // TA1: Fi/Di
                    atr.fi_di = .{
                        .fi = @intCast((data[offset] >> 4) & 0x0F),
                        .di = @intCast(data[offset] & 0x0F),
                    };
                }
                offset += 1;
            }

            // TB(i) present?
            if (y & 0x02 != 0) {
                if (offset >= data.len) return PcscError.InvalidAtr;
                offset += 1;
            }

            // TC(i) present?
            if (y & 0x04 != 0) {
                if (offset >= data.len) return PcscError.InvalidAtr;
                if (first_td) {
                    atr.extra_guard_time = data[offset];
                }
                offset += 1;
            }

            // TD(i) present?
            if (y & 0x08 != 0) {
                if (offset >= data.len) return PcscError.InvalidAtr;
                td_byte = data[offset];
                offset += 1;

                const protocol = td_byte & 0x0F;
                if (protocol == 0) {
                    atr.supports_t0 = true;
                    atr.protocols.t0 = true;
                } else if (protocol == 1) {
                    atr.supports_t1 = true;
                    atr.protocols.t1 = true;
                    need_tck = true;
                } else {
                    atr.protocols.other = protocol;
                    need_tck = true;
                }
                first_td = false;
            } else {
                break;
            }
        }

        // Historical bytes
        const hist_len: usize = atr.historical_len;
        if (offset + hist_len > data.len) return PcscError.InvalidAtr;
        if (hist_len > 0) {
            @memcpy(atr.historical[0..hist_len], data[offset .. offset + hist_len]);
        }
        offset += hist_len;

        // TCK (check byte) - present when T=1 or other protocols are indicated
        if (need_tck) {
            if (offset < data.len) {
                atr.tck = data[offset];
                // Verify TCK: XOR of all bytes from T0 to TCK should be 0
                var check: u8 = 0;
                for (data[1 .. offset + 1]) |b| {
                    check ^= b;
                }
                if (check != 0) return PcscError.InvalidAtr;
            }
        }

        return atr;
    }

    /// Get the raw ATR bytes.
    pub fn rawBytes(self: *const Atr) []const u8 {
        return self.raw[0..self.len];
    }

    /// Get the historical bytes.
    pub fn historicalBytes(self: *const Atr) []const u8 {
        return self.historical[0..self.historical_len];
    }

    /// Get the preferred protocol.
    pub fn preferredProtocol(self: *const Atr) Protocol {
        if (self.supports_t1) return .t1;
        return .t0;
    }

    /// Check if the ATR matches an OpenPGP card pattern.
    ///
    /// OpenPGP cards typically have specific historical bytes that
    /// include the application identifier.
    pub fn isOpenPgpCard(self: *const Atr) bool {
        const hist = self.historicalBytes();
        if (hist.len == 0) return false;

        // Check for OpenPGP AID prefix in historical bytes
        // Common pattern: category indicator 0x80, followed by compact-TLV
        if (hist[0] == 0x80) return true;

        // Also check for the "OpenPGP" string pattern
        if (hist.len >= 7) {
            if (mem.indexOf(u8, hist, "OpenPGP") != null) return true;
        }

        return false;
    }
};

// ---------------------------------------------------------------------------
// T=0 protocol framing
// ---------------------------------------------------------------------------

/// T=0 protocol APDU framing.
///
/// In T=0, the transport handles APDU case detection:
///   - Case 1: CLA INS P1 P2 (no data, no response expected)
///   - Case 2: CLA INS P1 P2 Le (response expected)
///   - Case 3: CLA INS P1 P2 Lc Data (data sent, no response)
///   - Case 4: CLA INS P1 P2 Lc Data Le (data sent, response expected)
///
/// For Case 4 in T=0, the card responds with SW1=61xx after the data
/// is sent, and the reader must issue GET RESPONSE to fetch the data.
pub const T0Framing = struct {
    /// Frame an APDU command for T=0 transmission.
    ///
    /// Returns the command bytes to send. For Case 4, only the Case 3
    /// portion is returned (the caller must handle GET RESPONSE).
    pub fn frameCommand(allocator: Allocator, cmd: ApduCommand) PcscError![]u8 {
        const has_data = cmd.data != null and cmd.data.?.len > 0;
        const has_le = cmd.le != null;

        if (!has_data and !has_le) {
            // Case 1: CLA INS P1 P2
            const buf = allocator.alloc(u8, 4) catch return PcscError.OutOfMemory;
            buf[0] = cmd.cla;
            buf[1] = cmd.ins;
            buf[2] = cmd.p1;
            buf[3] = cmd.p2;
            return buf;
        }

        if (!has_data and has_le) {
            // Case 2: CLA INS P1 P2 Le
            const le_val = cmd.le.?;
            const le_byte: u8 = if (le_val >= 256) 0x00 else @intCast(le_val);
            const buf = allocator.alloc(u8, 5) catch return PcscError.OutOfMemory;
            buf[0] = cmd.cla;
            buf[1] = cmd.ins;
            buf[2] = cmd.p1;
            buf[3] = cmd.p2;
            buf[4] = le_byte;
            return buf;
        }

        const data_slice = cmd.data.?;
        if (data_slice.len > 255) return PcscError.InvalidApdu; // T=0 doesn't support extended APDU natively

        if (has_data and !has_le) {
            // Case 3: CLA INS P1 P2 Lc Data
            const buf = allocator.alloc(u8, 5 + data_slice.len) catch return PcscError.OutOfMemory;
            buf[0] = cmd.cla;
            buf[1] = cmd.ins;
            buf[2] = cmd.p1;
            buf[3] = cmd.p2;
            buf[4] = @intCast(data_slice.len);
            @memcpy(buf[5..][0..data_slice.len], data_slice);
            return buf;
        }

        // Case 4: CLA INS P1 P2 Lc Data (Le sent separately via GET RESPONSE)
        const buf = allocator.alloc(u8, 5 + data_slice.len) catch return PcscError.OutOfMemory;
        buf[0] = cmd.cla;
        buf[1] = cmd.ins;
        buf[2] = cmd.p1;
        buf[3] = cmd.p2;
        buf[4] = @intCast(data_slice.len);
        @memcpy(buf[5..][0..data_slice.len], data_slice);
        return buf;
    }

    /// Build a GET RESPONSE command for retrieving data after SW=61xx.
    pub fn getResponseCommand(length: u8) ApduCommand {
        return openpgp_card.getResponse(length);
    }

    /// Determine the APDU case from a command.
    pub fn apduCase(cmd: ApduCommand) u8 {
        const has_data = cmd.data != null and cmd.data.?.len > 0;
        const has_le = cmd.le != null;

        if (!has_data and !has_le) return 1;
        if (!has_data and has_le) return 2;
        if (has_data and !has_le) return 3;
        return 4;
    }
};

// ---------------------------------------------------------------------------
// T=1 protocol framing
// ---------------------------------------------------------------------------

/// T=1 protocol block types.
pub const T1BlockType = enum(u2) {
    /// I-block: Information block (carries APDU data).
    i_block = 0,
    /// R-block: Receive-ready block (acknowledgment).
    r_block = 2,
    /// S-block: Supervisory block (protocol control).
    s_block = 3,
};

/// T=1 protocol APDU framing.
///
/// In T=1, data is transmitted in blocks with headers:
///   NAD PCB LEN INF... EDC
///
/// Where:
///   - NAD: Node Address (usually 0x00)
///   - PCB: Protocol Control Byte (identifies block type)
///   - LEN: Length of INF field
///   - INF: Information field (APDU data)
///   - EDC: Error Detection Code (LRC or CRC)
pub const T1Framing = struct {
    /// Maximum information field size per ISO 7816-3.
    pub const MAX_IFS: usize = 254;
    /// Default IFS.
    pub const DEFAULT_IFS: usize = 32;

    /// Current Information Field Size.
    ifs: usize,
    /// Send sequence number (0 or 1).
    send_seq: u1,
    /// Node address.
    nad: u8,
    /// Whether to use CRC (true) or LRC (false) for EDC.
    use_crc: bool,

    /// Create a T1 framing instance with default parameters.
    pub fn init() T1Framing {
        return .{
            .ifs = DEFAULT_IFS,
            .send_seq = 0,
            .nad = 0x00,
            .use_crc = false,
        };
    }

    /// Build a T=1 I-block containing APDU data.
    ///
    /// If the APDU data exceeds the IFS, it must be chained into
    /// multiple I-blocks. This function builds a single block.
    pub fn buildIBlock(self: *T1Framing, allocator: Allocator, data: []const u8, more: bool) PcscError![]u8 {
        const inf_len = @min(data.len, self.ifs);
        // NAD + PCB + LEN + INF + EDC(1 or 2)
        const edc_len: usize = if (self.use_crc) 2 else 1;
        const block_len = 3 + inf_len + edc_len;

        const block = allocator.alloc(u8, block_len) catch return PcscError.OutOfMemory;
        errdefer allocator.free(block);

        block[0] = self.nad; // NAD
        // PCB for I-block: bit 7 = 0, bit 6 = send_seq, bit 5 = more-data
        var pcb: u8 = 0;
        pcb |= @as(u8, self.send_seq) << 6;
        if (more) pcb |= 0x20;
        block[1] = pcb;
        block[2] = @intCast(inf_len);

        // INF
        @memcpy(block[3 .. 3 + inf_len], data[0..inf_len]);

        // EDC
        if (self.use_crc) {
            const crc = computeCrc16(block[0 .. 3 + inf_len]);
            block[3 + inf_len] = @intCast(crc >> 8);
            block[3 + inf_len + 1] = @intCast(crc & 0xFF);
        } else {
            block[3 + inf_len] = computeLrc(block[0 .. 3 + inf_len]);
        }

        // Toggle send sequence for next block
        self.send_seq ^= 1;

        return block;
    }

    /// Build a T=1 R-block (acknowledge receipt).
    pub fn buildRBlock(self: *const T1Framing, allocator: Allocator, expected_seq: u1, err_code: u2) PcscError![]u8 {
        const edc_len: usize = if (self.use_crc) 2 else 1;
        const block = allocator.alloc(u8, 3 + edc_len) catch return PcscError.OutOfMemory;
        errdefer allocator.free(block);

        block[0] = self.nad;
        // PCB for R-block: 10xx_xxxx, bit 4 = expected_seq, bits 0-1 = error
        var pcb: u8 = 0x80;
        pcb |= @as(u8, expected_seq) << 4;
        pcb |= @as(u8, err_code);
        block[1] = pcb;
        block[2] = 0; // No INF field

        if (self.use_crc) {
            const crc = computeCrc16(block[0..3]);
            block[3] = @intCast(crc >> 8);
            block[4] = @intCast(crc & 0xFF);
        } else {
            block[3] = computeLrc(block[0..3]);
        }

        return block;
    }

    /// Build a T=1 S-block (supervisory).
    pub fn buildSBlock(self: *const T1Framing, allocator: Allocator, request: bool, stype: SBlockType, data: ?[]const u8) PcscError![]u8 {
        const inf_len: usize = if (data) |d| d.len else 0;
        const edc_len: usize = if (self.use_crc) 2 else 1;
        const block = allocator.alloc(u8, 3 + inf_len + edc_len) catch return PcscError.OutOfMemory;
        errdefer allocator.free(block);

        block[0] = self.nad;
        // PCB for S-block: 11xx_xxxx
        var pcb: u8 = 0xC0;
        if (!request) pcb |= 0x20; // Response bit
        pcb |= @intFromEnum(stype);
        block[1] = pcb;
        block[2] = @intCast(inf_len);

        if (data) |d| {
            @memcpy(block[3 .. 3 + inf_len], d);
        }

        if (self.use_crc) {
            const crc = computeCrc16(block[0 .. 3 + inf_len]);
            block[3 + inf_len] = @intCast(crc >> 8);
            block[3 + inf_len + 1] = @intCast(crc & 0xFF);
        } else {
            block[3 + inf_len] = computeLrc(block[0 .. 3 + inf_len]);
        }

        return block;
    }

    /// Parse a received T=1 block.
    pub fn parseBlock(self: *const T1Framing, data: []const u8) PcscError!T1Block {
        const edc_len: usize = if (self.use_crc) 2 else 1;
        if (data.len < 3 + edc_len) return PcscError.InvalidResponse;

        const nad = data[0];
        const pcb = data[1];
        const inf_len = data[2];
        if (3 + @as(usize, inf_len) + edc_len != data.len) return PcscError.InvalidResponse;

        // Verify EDC
        if (self.use_crc) {
            const expected = computeCrc16(data[0 .. 3 + inf_len]);
            const received = (@as(u16, data[3 + inf_len]) << 8) | @as(u16, data[3 + inf_len + 1]);
            if (expected != received) return PcscError.TransmitFailed;
        } else {
            const expected = computeLrc(data[0 .. 3 + inf_len]);
            if (expected != data[3 + inf_len]) return PcscError.TransmitFailed;
        }

        const block_type: T1BlockType = @enumFromInt(@as(u2, @intCast((pcb >> 6) & 0x03)));
        const inf = if (inf_len > 0) data[3 .. 3 + inf_len] else data[3..3];

        return .{
            .nad = nad,
            .pcb = pcb,
            .block_type = block_type,
            .inf = inf,
            .more_data = switch (block_type) {
                .i_block => (pcb & 0x20) != 0,
                else => false,
            },
            .sequence = switch (block_type) {
                .i_block => @intCast((pcb >> 6) & 0x01),
                .r_block => @intCast((pcb >> 4) & 0x01),
                else => 0,
            },
        };
    }

    /// S-Block type codes.
    pub const SBlockType = enum(u4) {
        /// RESYNCH request/response
        resynch = 0x00,
        /// IFS request/response
        ifs = 0x01,
        /// ABORT request/response
        abort = 0x02,
        /// WTX (Waiting Time Extension) request/response
        wtx = 0x03,
    };
};

/// A parsed T=1 block.
pub const T1Block = struct {
    /// Node Address.
    nad: u8,
    /// Protocol Control Byte.
    pcb: u8,
    /// Block type.
    block_type: T1BlockType,
    /// Information field (APDU data for I-blocks).
    inf: []const u8,
    /// Whether more data follows (chaining indicator in I-blocks).
    more_data: bool,
    /// Sequence number.
    sequence: u1,
};

/// Compute LRC (Longitudinal Redundancy Check) for T=1.
pub fn computeLrc(data: []const u8) u8 {
    var lrc: u8 = 0;
    for (data) |b| {
        lrc ^= b;
    }
    return lrc;
}

/// Compute CRC-16/CCITT for T=1.
pub fn computeCrc16(data: []const u8) u16 {
    var crc: u16 = 0xFFFF;
    for (data) |b| {
        crc ^= @as(u16, b) << 8;
        for (0..8) |_| {
            if (crc & 0x8000 != 0) {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc = crc << 1;
            }
        }
    }
    return crc;
}

// ---------------------------------------------------------------------------
// PcscReader interface
// ---------------------------------------------------------------------------

/// Abstract interface for a PCSC card reader.
///
/// Implementations provide the actual communication with the reader
/// hardware. This abstraction allows platform-independent card operations
/// and mock implementations for testing.
pub const PcscReader = struct {
    /// Opaque implementation context.
    context: *anyopaque,
    /// V-table for reader operations.
    vtable: *const VTable,

    pub const VTable = struct {
        /// Connect to the card in the reader.
        connectFn: *const fn (ctx: *anyopaque, allocator: Allocator, mode: ShareMode, protocol: Protocol) PcscError!void,

        /// Disconnect from the card.
        disconnectFn: *const fn (ctx: *anyopaque, disposition: Disposition) PcscError!void,

        /// Transmit an APDU command and receive a response.
        transmitFn: *const fn (ctx: *anyopaque, allocator: Allocator, send: []const u8) PcscError![]u8,

        /// Get the ATR (Answer To Reset) from the card.
        getAtrFn: *const fn (ctx: *anyopaque, allocator: Allocator) PcscError![]u8,

        /// Get the current card state.
        getStateFn: *const fn (ctx: *anyopaque) CardState,

        /// Get the reader name.
        getNameFn: *const fn (ctx: *anyopaque) []const u8,

        /// Check if a card is present.
        isCardPresentFn: *const fn (ctx: *anyopaque) bool,
    };

    /// Connect to the card.
    pub fn connect(self: *const PcscReader, allocator: Allocator, mode: ShareMode, protocol: Protocol) PcscError!void {
        return self.vtable.connectFn(self.context, allocator, mode, protocol);
    }

    /// Disconnect from the card.
    pub fn disconnect(self: *const PcscReader, disposition: Disposition) PcscError!void {
        return self.vtable.disconnectFn(self.context, disposition);
    }

    /// Transmit an APDU and get the response.
    pub fn transmit(self: *const PcscReader, allocator: Allocator, data: []const u8) PcscError![]u8 {
        return self.vtable.transmitFn(self.context, allocator, data);
    }

    /// Get the card's ATR.
    pub fn getAtr(self: *const PcscReader, allocator: Allocator) PcscError![]u8 {
        return self.vtable.getAtrFn(self.context, allocator);
    }

    /// Get the current card state.
    pub fn getState(self: *const PcscReader) CardState {
        return self.vtable.getStateFn(self.context);
    }

    /// Get the reader name.
    pub fn getName(self: *const PcscReader) []const u8 {
        return self.vtable.getNameFn(self.context);
    }

    /// Check if a card is present.
    pub fn isCardPresent(self: *const PcscReader) bool {
        return self.vtable.isCardPresentFn(self.context);
    }

    /// Transmit an APDU command (high-level, using ApduCommand).
    pub fn transceive(self: *const PcscReader, allocator: Allocator, cmd: ApduCommand) PcscError!ApduResponse {
        const raw_cmd = cmd.serialize(allocator) catch return PcscError.OutOfMemory;
        defer allocator.free(raw_cmd);

        const raw_resp = try self.transmit(allocator, raw_cmd);
        defer allocator.free(raw_resp);

        return ApduResponse.parse(allocator, raw_resp) catch return PcscError.InvalidResponse;
    }
};

// ---------------------------------------------------------------------------
// PcscContext — manages reader connections
// ---------------------------------------------------------------------------

/// Represents a reader discovered during enumeration.
pub const ReaderInfo = struct {
    /// Reader name (null-terminated in PCSC, here a slice).
    name: []const u8,
    /// Whether a card is present in this reader.
    card_present: bool,
    /// Card state.
    state: CardState,
    /// ATR bytes (if card is present and powered).
    atr: ?[]const u8,
};

/// PCSC context for managing reader connections.
///
/// The context represents a connection to the PC/SC resource manager.
/// It is used to enumerate readers, detect cards, and establish
/// connections to specific readers.
pub const PcscContext = struct {
    /// List of discovered readers.
    readers: std.ArrayList(ReaderInfo),
    /// Whether the context is established.
    established: bool,

    /// Initialize a new PCSC context.
    pub fn init() PcscContext {
        return .{
            .readers = .empty,
            .established = false,
        };
    }

    /// Establish the context (connect to PCSC resource manager).
    pub fn establish(self: *PcscContext) PcscError!void {
        if (self.established) return;
        self.established = true;
    }

    /// Release the context.
    pub fn release(self: *PcscContext, allocator: Allocator) void {
        for (self.readers.items) |reader| {
            allocator.free(reader.name);
            if (reader.atr) |atr| allocator.free(atr);
        }
        self.readers.deinit(allocator);
        self.established = false;
    }

    /// Check if the context is established.
    pub fn isEstablished(self: *const PcscContext) bool {
        return self.established;
    }

    /// Add a reader to the context (for testing/mock purposes).
    pub fn addReader(self: *PcscContext, allocator: Allocator, info: ReaderInfo) PcscError!void {
        if (!self.established) return PcscError.InvalidContext;
        self.readers.append(allocator, info) catch return PcscError.OutOfMemory;
    }

    /// Get the number of readers.
    pub fn readerCount(self: *const PcscContext) usize {
        return self.readers.items.len;
    }

    /// Find a reader by name.
    pub fn findReader(self: *const PcscContext, reader_name: []const u8) ?*const ReaderInfo {
        for (self.readers.items) |*reader| {
            if (mem.eql(u8, reader.name, reader_name)) return reader;
        }
        return null;
    }

    /// Find readers with a card present.
    pub fn findReadersWithCards(self: *const PcscContext, allocator: Allocator) PcscError![]ReaderInfo {
        var result: std.ArrayList(ReaderInfo) = .empty;
        errdefer result.deinit(allocator);

        for (self.readers.items) |reader| {
            if (reader.card_present) {
                result.append(allocator, reader) catch return PcscError.OutOfMemory;
            }
        }

        return result.toOwnedSlice(allocator) catch return PcscError.OutOfMemory;
    }
};

// ---------------------------------------------------------------------------
// Mock PCSC reader (for testing)
// ---------------------------------------------------------------------------

/// Mock PCSC reader for testing card communication without hardware.
pub const MockPcscReader = struct {
    /// Reader name.
    reader_name: []const u8,
    /// Whether a card is present.
    card_present: bool,
    /// Whether connected.
    connected: bool,
    /// Current card state.
    state: CardState,
    /// ATR to return.
    atr_data: []const u8,
    /// Protocol in use.
    protocol: Protocol,
    /// Pre-configured responses: maps command bytes to response bytes.
    /// Uses a simple linear scan for matching.
    response_queue: std.ArrayList(MockResponse),
    /// Default response if no match found.
    default_response: [2]u8,

    pub const MockResponse = struct {
        /// Expected command prefix to match.
        command_prefix: []const u8,
        /// Response to return.
        response: []const u8,
    };

    /// Create a mock reader.
    pub fn init(reader_name: []const u8, atr: []const u8) MockPcscReader {
        return .{
            .reader_name = reader_name,
            .card_present = true,
            .connected = false,
            .state = .present,
            .atr_data = atr,
            .protocol = .t1,
            .response_queue = .empty,
            .default_response = .{ 0x90, 0x00 }, // Success
        };
    }

    /// Create a PcscReader interface backed by this mock.
    pub fn reader(self: *MockPcscReader) PcscReader {
        return .{
            .context = @ptrCast(self),
            .vtable = &mock_reader_vtable,
        };
    }

    /// Add a mock response.
    pub fn addResponse(self: *MockPcscReader, allocator: Allocator, prefix: []const u8, response: []const u8) !void {
        try self.response_queue.append(allocator, .{
            .command_prefix = prefix,
            .response = response,
        });
    }

    /// Free mock resources.
    pub fn deinit(self: *MockPcscReader, allocator: Allocator) void {
        self.response_queue.deinit(allocator);
    }

    fn mockConnect(ctx: *anyopaque, allocator: Allocator, mode: ShareMode, protocol: Protocol) PcscError!void {
        const self: *MockPcscReader = @ptrCast(@alignCast(ctx));
        _ = allocator;
        _ = mode;
        if (!self.card_present) return PcscError.ConnectionFailed;
        self.connected = true;
        self.protocol = protocol;
        self.state = .specific;
    }

    fn mockDisconnect(ctx: *anyopaque, disposition: Disposition) PcscError!void {
        const self: *MockPcscReader = @ptrCast(@alignCast(ctx));
        _ = disposition;
        if (!self.connected) return PcscError.ConnectionFailed;
        self.connected = false;
        self.state = .present;
    }

    fn mockTransmit(ctx: *anyopaque, allocator: Allocator, send: []const u8) PcscError![]u8 {
        const self: *MockPcscReader = @ptrCast(@alignCast(ctx));
        if (!self.connected) return PcscError.TransmitFailed;

        // Search for a matching response
        for (self.response_queue.items) |resp| {
            if (send.len >= resp.command_prefix.len and
                mem.eql(u8, send[0..resp.command_prefix.len], resp.command_prefix))
            {
                const result = allocator.dupe(u8, resp.response) catch return PcscError.OutOfMemory;
                return result;
            }
        }

        // Return default response
        const result = allocator.dupe(u8, &self.default_response) catch return PcscError.OutOfMemory;
        return result;
    }

    fn mockGetAtr(ctx: *anyopaque, allocator: Allocator) PcscError![]u8 {
        const self: *MockPcscReader = @ptrCast(@alignCast(ctx));
        if (!self.card_present) return PcscError.CardRemoved;
        return allocator.dupe(u8, self.atr_data) catch return PcscError.OutOfMemory;
    }

    fn mockGetState(ctx: *anyopaque) CardState {
        const self: *MockPcscReader = @ptrCast(@alignCast(ctx));
        return self.state;
    }

    fn mockGetName(ctx: *anyopaque) []const u8 {
        const self: *MockPcscReader = @ptrCast(@alignCast(ctx));
        return self.reader_name;
    }

    fn mockIsCardPresent(ctx: *anyopaque) bool {
        const self: *MockPcscReader = @ptrCast(@alignCast(ctx));
        return self.card_present;
    }

    const mock_reader_vtable: PcscReader.VTable = .{
        .connectFn = &mockConnect,
        .disconnectFn = &mockDisconnect,
        .transmitFn = &mockTransmit,
        .getAtrFn = &mockGetAtr,
        .getStateFn = &mockGetState,
        .getNameFn = &mockGetName,
        .isCardPresentFn = &mockIsCardPresent,
    };
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Protocol names" {
    try std.testing.expectEqualStrings("T=0", Protocol.t0.name());
    try std.testing.expectEqualStrings("T=1", Protocol.t1.name());
    try std.testing.expectEqualStrings("Raw", Protocol.raw.name());
}

test "CardState properties" {
    try std.testing.expect(!CardState.absent.isPresent());
    try std.testing.expect(CardState.present.isPresent());
    try std.testing.expect(CardState.powered.isPresent());

    try std.testing.expect(!CardState.absent.isReady());
    try std.testing.expect(!CardState.present.isReady());
    try std.testing.expect(CardState.powered.isReady());
    try std.testing.expect(CardState.specific.isReady());
}

test "ATR parse basic T=0 card" {
    // Simple ATR: TS=3B, T0=0x00 (no interface bytes, 0 historical bytes)
    const atr_data = [_]u8{ 0x3B, 0x00 };
    const atr = try Atr.parse(&atr_data);

    try std.testing.expect(atr.direct_convention);
    try std.testing.expectEqual(@as(u4, 0), atr.historical_len);
    try std.testing.expect(atr.supports_t0);
    try std.testing.expect(!atr.supports_t1);
    try std.testing.expectEqual(Protocol.t0, atr.preferredProtocol());
}

test "ATR parse with historical bytes" {
    // ATR with 2 historical bytes
    const atr_data = [_]u8{ 0x3B, 0x02, 'A', 'B' };
    const atr = try Atr.parse(&atr_data);

    try std.testing.expectEqual(@as(u4, 2), atr.historical_len);
    try std.testing.expectEqualSlices(u8, "AB", atr.historicalBytes());
}

test "ATR parse with TA1" {
    // ATR with TA1 present (T0 bit 4 set)
    // T0 = 0x10: TA1 present, 0 historical bytes
    // TA1 = 0x96: Fi=9, Di=6
    const atr_data = [_]u8{ 0x3B, 0x10, 0x96 };
    const atr = try Atr.parse(&atr_data);

    try std.testing.expect(atr.fi_di != null);
    try std.testing.expectEqual(@as(u4, 9), atr.fi_di.?.fi);
    try std.testing.expectEqual(@as(u4, 6), atr.fi_di.?.di);
}

test "ATR parse inverse convention" {
    const atr_data = [_]u8{ 0x3F, 0x00 };
    const atr = try Atr.parse(&atr_data);

    try std.testing.expect(!atr.direct_convention);
}

test "ATR parse invalid TS" {
    const atr_data = [_]u8{ 0x00, 0x00 };
    try std.testing.expectError(PcscError.InvalidAtr, Atr.parse(&atr_data));
}

test "ATR parse too short" {
    const atr_data = [_]u8{0x3B};
    try std.testing.expectError(PcscError.InvalidAtr, Atr.parse(&atr_data));
}

test "ATR with T=1 support" {
    // T0 = 0x80 (TD1 present, 0 historical bytes)
    // TD1 = 0x01 (T=1, no further interface bytes)
    // TCK = XOR of T0..TD1 = 0x80 ^ 0x01 = 0x81
    const atr_data = [_]u8{ 0x3B, 0x80, 0x01, 0x81 };
    const atr = try Atr.parse(&atr_data);

    try std.testing.expect(atr.supports_t1);
    try std.testing.expectEqual(Protocol.t1, atr.preferredProtocol());
}

test "computeLrc" {
    const data = [_]u8{ 0x00, 0x40, 0x05, 'H', 'e', 'l', 'l', 'o' };
    const lrc = computeLrc(&data);
    // XOR of all bytes
    var expected: u8 = 0;
    for (data) |b| expected ^= b;
    try std.testing.expectEqual(expected, lrc);
}

test "computeCrc16" {
    const data = [_]u8{ 0x01, 0x02, 0x03 };
    const crc = computeCrc16(&data);
    // CRC should be deterministic
    try std.testing.expectEqual(crc, computeCrc16(&data));
    // Different data should give different CRC
    const data2 = [_]u8{ 0x01, 0x02, 0x04 };
    try std.testing.expect(crc != computeCrc16(&data2));
}

test "T0Framing case detection" {
    // Case 1: no data, no Le
    const case1 = T0Framing.apduCase(.{ .cla = 0, .ins = 0, .p1 = 0, .p2 = 0, .data = null, .le = null });
    try std.testing.expectEqual(@as(u8, 1), case1);

    // Case 2: Le only
    const case2 = T0Framing.apduCase(.{ .cla = 0, .ins = 0, .p1 = 0, .p2 = 0, .data = null, .le = 256 });
    try std.testing.expectEqual(@as(u8, 2), case2);

    // Case 3: data only
    const case3 = T0Framing.apduCase(.{ .cla = 0, .ins = 0, .p1 = 0, .p2 = 0, .data = "test", .le = null });
    try std.testing.expectEqual(@as(u8, 3), case3);

    // Case 4: data + Le
    const case4 = T0Framing.apduCase(.{ .cla = 0, .ins = 0, .p1 = 0, .p2 = 0, .data = "test", .le = 256 });
    try std.testing.expectEqual(@as(u8, 4), case4);
}

test "T0Framing frameCommand Case 1" {
    const allocator = std.testing.allocator;

    const cmd: ApduCommand = .{ .cla = 0x00, .ins = 0xCA, .p1 = 0x00, .p2 = 0x6E, .data = null, .le = null };
    const framed = try T0Framing.frameCommand(allocator, cmd);
    defer allocator.free(framed);

    try std.testing.expectEqual(@as(usize, 4), framed.len);
    try std.testing.expectEqual(@as(u8, 0x00), framed[0]);
    try std.testing.expectEqual(@as(u8, 0xCA), framed[1]);
    try std.testing.expectEqual(@as(u8, 0x00), framed[2]);
    try std.testing.expectEqual(@as(u8, 0x6E), framed[3]);
}

test "T0Framing frameCommand Case 2" {
    const allocator = std.testing.allocator;

    const cmd: ApduCommand = .{ .cla = 0x00, .ins = 0xCA, .p1 = 0x00, .p2 = 0x6E, .data = null, .le = 256 };
    const framed = try T0Framing.frameCommand(allocator, cmd);
    defer allocator.free(framed);

    try std.testing.expectEqual(@as(usize, 5), framed.len);
    try std.testing.expectEqual(@as(u8, 0x00), framed[4]); // Le=256 -> 0x00
}

test "T0Framing frameCommand Case 3" {
    const allocator = std.testing.allocator;

    const data = [_]u8{ 0x01, 0x02, 0x03 };
    const cmd: ApduCommand = .{ .cla = 0x00, .ins = 0x20, .p1 = 0x00, .p2 = 0x81, .data = &data, .le = null };
    const framed = try T0Framing.frameCommand(allocator, cmd);
    defer allocator.free(framed);

    try std.testing.expectEqual(@as(usize, 8), framed.len);
    try std.testing.expectEqual(@as(u8, 3), framed[4]); // Lc
    try std.testing.expectEqual(@as(u8, 0x01), framed[5]);
    try std.testing.expectEqual(@as(u8, 0x02), framed[6]);
    try std.testing.expectEqual(@as(u8, 0x03), framed[7]);
}

test "T1Framing I-block build" {
    const allocator = std.testing.allocator;
    var framing = T1Framing.init();

    const data = "Hello";
    const block = try framing.buildIBlock(allocator, data, false);
    defer allocator.free(block);

    try std.testing.expectEqual(@as(u8, 0x00), block[0]); // NAD
    try std.testing.expectEqual(@as(u8, 5), block[2]); // LEN
    // INF should be "Hello"
    try std.testing.expectEqualStrings("Hello", block[3..8]);
    // Last byte is LRC
    try std.testing.expectEqual(computeLrc(block[0..8]), block[8]);
}

test "T1Framing I-block with chaining" {
    const allocator = std.testing.allocator;
    var framing = T1Framing.init();

    const block = try framing.buildIBlock(allocator, "test", true);
    defer allocator.free(block);

    // PCB should have more-data bit set (bit 5)
    try std.testing.expect((block[1] & 0x20) != 0);
}

test "T1Framing R-block build" {
    const allocator = std.testing.allocator;
    const framing = T1Framing.init();

    const block = try framing.buildRBlock(allocator, 0, 0);
    defer allocator.free(block);

    try std.testing.expectEqual(@as(u8, 0x00), block[0]); // NAD
    try std.testing.expect((block[1] & 0x80) != 0); // R-block marker
    try std.testing.expectEqual(@as(u8, 0), block[2]); // No INF
}

test "T1Framing S-block build" {
    const allocator = std.testing.allocator;
    const framing = T1Framing.init();

    const block = try framing.buildSBlock(allocator, true, .wtx, &.{0x01});
    defer allocator.free(block);

    try std.testing.expectEqual(@as(u8, 0x00), block[0]); // NAD
    try std.testing.expect((block[1] & 0xC0) == 0xC0); // S-block marker
    try std.testing.expectEqual(@as(u8, 1), block[2]); // LEN = 1
    try std.testing.expectEqual(@as(u8, 0x01), block[3]); // WTX value
}

test "T1Framing parse I-block roundtrip" {
    const allocator = std.testing.allocator;
    var framing = T1Framing.init();

    const block = try framing.buildIBlock(allocator, "test", false);
    defer allocator.free(block);

    // Reset send_seq for parsing
    const framing2 = T1Framing.init();
    const parsed = try framing2.parseBlock(block);

    try std.testing.expectEqual(T1BlockType.i_block, parsed.block_type);
    try std.testing.expectEqualStrings("test", parsed.inf);
    try std.testing.expect(!parsed.more_data);
}

test "T1Framing sequence number toggle" {
    const allocator = std.testing.allocator;
    var framing = T1Framing.init();

    try std.testing.expectEqual(@as(u1, 0), framing.send_seq);

    const block1 = try framing.buildIBlock(allocator, "a", false);
    defer allocator.free(block1);
    try std.testing.expectEqual(@as(u1, 1), framing.send_seq);

    const block2 = try framing.buildIBlock(allocator, "b", false);
    defer allocator.free(block2);
    try std.testing.expectEqual(@as(u1, 0), framing.send_seq);
}

test "PcscContext lifecycle" {
    const allocator = std.testing.allocator;

    var ctx = PcscContext.init();
    defer ctx.release(allocator);

    try std.testing.expect(!ctx.isEstablished());

    try ctx.establish();
    try std.testing.expect(ctx.isEstablished());

    // Adding reader before establish should work now
    const name = try allocator.dupe(u8, "Test Reader");
    try ctx.addReader(allocator, .{
        .name = name,
        .card_present = true,
        .state = .present,
        .atr = null,
    });

    try std.testing.expectEqual(@as(usize, 1), ctx.readerCount());

    const found = ctx.findReader("Test Reader");
    try std.testing.expect(found != null);
    try std.testing.expect(found.?.card_present);
}

test "PcscContext find readers with cards" {
    const allocator = std.testing.allocator;

    var ctx = PcscContext.init();
    defer ctx.release(allocator);
    try ctx.establish();

    const name1 = try allocator.dupe(u8, "Reader 1");
    try ctx.addReader(allocator, .{ .name = name1, .card_present = true, .state = .present, .atr = null });

    const name2 = try allocator.dupe(u8, "Reader 2");
    try ctx.addReader(allocator, .{ .name = name2, .card_present = false, .state = .absent, .atr = null });

    const name3 = try allocator.dupe(u8, "Reader 3");
    try ctx.addReader(allocator, .{ .name = name3, .card_present = true, .state = .specific, .atr = null });

    const with_cards = try ctx.findReadersWithCards(allocator);
    defer allocator.free(with_cards);

    try std.testing.expectEqual(@as(usize, 2), with_cards.len);
}

test "MockPcscReader connect and transmit" {
    const allocator = std.testing.allocator;

    // Simple T=0 ATR
    var mock = MockPcscReader.init("Test Reader", &.{ 0x3B, 0x00 });
    defer mock.deinit(allocator);
    var rdr = mock.reader();

    try std.testing.expectEqualStrings("Test Reader", rdr.getName());
    try std.testing.expect(rdr.isCardPresent());

    // Connect
    try rdr.connect(allocator, .shared, .t1);
    try std.testing.expectEqual(CardState.specific, rdr.getState());

    // Get ATR
    const atr_bytes = try rdr.getAtr(allocator);
    defer allocator.free(atr_bytes);
    try std.testing.expectEqualSlices(u8, &.{ 0x3B, 0x00 }, atr_bytes);

    // Transmit (default response)
    const resp = try rdr.transmit(allocator, &.{ 0x00, 0xCA, 0x00, 0x6E, 0x00 });
    defer allocator.free(resp);
    try std.testing.expectEqualSlices(u8, &.{ 0x90, 0x00 }, resp);

    // Disconnect
    try rdr.disconnect(.leave);
    try std.testing.expectEqual(CardState.present, rdr.getState());
}

test "MockPcscReader custom responses" {
    const allocator = std.testing.allocator;

    var mock = MockPcscReader.init("Test", &.{ 0x3B, 0x00 });
    defer mock.deinit(allocator);

    // Add custom response for SELECT
    try mock.addResponse(allocator, &.{ 0x00, 0xA4 }, &.{ 0x6F, 0x00, 0x90, 0x00 });

    var rdr = mock.reader();
    try rdr.connect(allocator, .shared, .t1);

    const resp = try rdr.transmit(allocator, &.{ 0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01 });
    defer allocator.free(resp);

    try std.testing.expectEqual(@as(usize, 4), resp.len);
    try std.testing.expectEqual(@as(u8, 0x6F), resp[0]);
}

test "MockPcscReader no card" {
    const allocator = std.testing.allocator;

    var mock = MockPcscReader.init("Empty Reader", &.{});
    defer mock.deinit(allocator);
    mock.card_present = false;

    var rdr = mock.reader();

    try std.testing.expect(!rdr.isCardPresent());
    try std.testing.expectError(PcscError.ConnectionFailed, rdr.connect(allocator, .shared, .t1));
}

test "ATR isOpenPgpCard" {
    // ATR with 0x80 category indicator in historical bytes
    const atr_data = [_]u8{ 0x3B, 0x01, 0x80 };
    const atr = try Atr.parse(&atr_data);
    try std.testing.expect(atr.isOpenPgpCard());

    // ATR without OpenPGP indicators
    const atr_data2 = [_]u8{ 0x3B, 0x02, 0x41, 0x42 };
    const atr2 = try Atr.parse(&atr_data2);
    try std.testing.expect(!atr2.isOpenPgpCard());
}
