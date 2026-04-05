// SPDX-License-Identifier: MIT
//! OpenPGP protocol-level modules for message grammar validation,
//! transferable key validation, and keyserver protocol helpers.

pub const openpgp_message = @import("openpgp_message.zig");
pub const transferable_key = @import("transferable_key.zig");
pub const keyserver_protocol = @import("keyserver_protocol.zig");

// Re-exports for convenience
pub const MessageStructure = openpgp_message.MessageStructure;
pub const GrammarResult = openpgp_message.GrammarResult;
pub const analyzeMessageStructure = openpgp_message.analyzeMessageStructure;
pub const validateMessageGrammar = openpgp_message.validateMessageGrammar;

pub const TransferableKeyValidator = transferable_key.TransferableKeyValidator;
pub const KeyValidation = transferable_key.KeyValidation;

pub const KeyserverProtocol = keyserver_protocol.KeyserverProtocol;
pub const NormalizedKeyId = keyserver_protocol.NormalizedKeyId;
pub const detectProtocol = keyserver_protocol.detectProtocol;
pub const normalizeKeyId = keyserver_protocol.normalizeKeyId;

test {
    const std = @import("std");
    std.testing.refAllDecls(@This());
}
