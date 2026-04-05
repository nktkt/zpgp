// SPDX-License-Identifier: MIT
//! Inspection and analysis modules for OpenPGP data.
//!
//! Provides tools for examining the structure and security properties
//! of OpenPGP packets, keys, signatures, and messages without
//! performing cryptographic operations.

pub const packet_dump = @import("packet_dump.zig");
pub const key_analyzer = @import("key_analyzer.zig");
pub const message_analyzer = @import("message_analyzer.zig");

// Re-exports for convenience
pub const PacketInfo = packet_dump.PacketInfo;
pub const KeyInspection = packet_dump.KeyInspection;
pub const SignatureInspection = packet_dump.SignatureInspection;
pub const MessageInspection = packet_dump.MessageInspection;
pub const inspectPackets = packet_dump.inspectPackets;
pub const formatPacketDump = packet_dump.formatPacketDump;
pub const inspectKey = packet_dump.inspectKey;
pub const inspectSignature = packet_dump.inspectSignature;
pub const inspectMessage = packet_dump.inspectMessage;

pub const KeyAnalysis = key_analyzer.KeyAnalysis;
pub const analyzeKey = key_analyzer.analyzeKey;

pub const MessageAnalysis = message_analyzer.MessageAnalysis;
pub const analyzeMessage = message_analyzer.analyzeMessage;

test {
    const std = @import("std");
    std.testing.refAllDecls(@This());
}
