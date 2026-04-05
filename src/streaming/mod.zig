// SPDX-License-Identifier: MIT
//! Streaming API for OpenPGP operations.
//!
//! This module provides incremental (streaming) interfaces for the four
//! core OpenPGP operations:
//!
//! - **Encryption** (`StreamEncryptor`): Feed plaintext in chunks, get
//!   SEIPD v1 (CFB-MDC) or v2 (AEAD) encrypted output.
//!
//! - **Decryption** (`StreamDecryptor`): Feed ciphertext in chunks, get
//!   plaintext output with integrity verification.
//!
//! - **Signing** (`StreamSigner`): Feed data in chunks, produce a V4
//!   signature packet.
//!
//! - **Verification** (`StreamVerifier`): Feed data in chunks, verify
//!   against a signature packet.
//!
//! All streaming types are designed for large message processing without
//! loading entire messages into memory. They maintain internal state
//! machines to enforce correct usage (header -> data -> finish).
//!
//! ## Security
//!
//! All sensitive key material is securely zeroed on `deinit` using the
//! zeroize module from `security/zeroize.zig`.

const std = @import("std");

// Sub-modules
pub const stream_encrypt = @import("stream_encrypt.zig");
pub const stream_decrypt = @import("stream_decrypt.zig");
pub const stream_sign = @import("stream_sign.zig");
pub const stream_verify = @import("stream_verify.zig");

// Re-exports for convenience
pub const StreamEncryptor = stream_encrypt.StreamEncryptor;
pub const StreamEncryptOptions = stream_encrypt.StreamEncryptOptions;
pub const StreamEncryptError = stream_encrypt.StreamEncryptError;
pub const PasswordEncryptSetup = stream_encrypt.PasswordEncryptSetup;
pub const initPasswordEncrypt = stream_encrypt.initPasswordEncrypt;

pub const StreamDecryptor = stream_decrypt.StreamDecryptor;
pub const StreamDecryptError = stream_decrypt.StreamDecryptError;
pub const HeaderResult = stream_decrypt.HeaderResult;

pub const StreamSigner = stream_sign.StreamSigner;
pub const StreamSignOptions = stream_sign.StreamSignOptions;
pub const StreamSignError = stream_sign.StreamSignError;

pub const StreamVerifier = stream_verify.StreamVerifier;
pub const StreamVerifyOptions = stream_verify.StreamVerifyOptions;
pub const StreamVerifyError = stream_verify.StreamVerifyError;
pub const VerifyResult = stream_verify.VerifyResult;
pub const verifyDetached = stream_verify.verifyDetached;
pub const DetachedVerifyOptions = stream_verify.DetachedVerifyOptions;

test {
    std.testing.refAllDecls(@This());
}
