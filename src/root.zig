//! zpgp — an OpenPGP (RFC 4880) library written in Zig.
const std = @import("std");

// ASCII Armor
pub const armor = @import("armor/armor.zig");
pub const crc24 = @import("armor/crc24.zig");

// Packet parsing
pub const packet = @import("packet/packet.zig");

// Core types
pub const enums = @import("types/enums.zig");
pub const mpi = @import("types/mpi.zig");
pub const key_id = @import("types/key_id.zig");
pub const time = @import("types/time.zig");

// Individual packet type parsers
pub const literal_data = @import("packets/literal_data.zig");
pub const user_id = @import("packets/user_id.zig");
pub const user_attribute = @import("packets/user_attribute.zig");
pub const trust = @import("packets/trust.zig");
pub const marker = @import("packets/marker.zig");
pub const one_pass_sig = @import("packets/one_pass_sig.zig");
pub const mod_detection = @import("packets/mod_detection.zig");
pub const public_key = @import("packets/public_key.zig");
pub const secret_key = @import("packets/secret_key.zig");
pub const signature = @import("packets/signature.zig");
pub const pkesk = @import("packets/pkesk.zig");
pub const skesk = @import("packets/skesk.zig");
pub const compressed_data = @import("packets/compressed_data.zig");
pub const sym_enc_data = @import("packets/sym_enc_data.zig");
pub const sym_enc_integrity = @import("packets/sym_enc_integrity.zig");

// Core types (S2K)
pub const s2k = @import("types/s2k.zig");

// Crypto foundations
pub const hash = @import("crypto/hash.zig");
pub const rsa = @import("crypto/rsa.zig");
pub const cfb = @import("crypto/cfb.zig");
pub const aes_keywrap = @import("crypto/aes_keywrap.zig");
pub const ecdh_mod = @import("crypto/ecdh.zig");
pub const session_key_mod = @import("crypto/session_key.zig");
pub const cast5_mod = @import("crypto/cast5.zig");
pub const twofish_mod = @import("crypto/twofish.zig");

// Signature modules
pub const subpackets = @import("signature/subpackets.zig");
pub const sig_types = @import("signature/types.zig");
pub const sig_creation = @import("signature/creation.zig");
pub const sig_verification = @import("signature/verification.zig");

// Key modules
pub const fingerprint_mod = @import("key/fingerprint.zig");
pub const key_mod = @import("key/key.zig");
pub const import_export = @import("key/import_export.zig");
pub const keyring = @import("key/keyring.zig");
pub const revocation = @import("key/revocation.zig");
pub const trust_model = @import("key/trust_model.zig");

// Keyserver modules
pub const hkp = @import("keyserver/hkp.zig");

// Message modules
pub const message = @import("message/message.zig");
pub const compose = @import("message/compose.zig");
pub const decompose = @import("message/decompose.zig");

// Re-exports for convenience.
pub const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
pub const SymmetricAlgorithm = enums.SymmetricAlgorithm;
pub const HashAlgorithm = enums.HashAlgorithm;
pub const CompressionAlgorithm = enums.CompressionAlgorithm;
pub const Mpi = mpi.Mpi;
pub const KeyId = key_id.KeyId;
pub const Fingerprint = key_id.Fingerprint;
pub const Timestamp = time.Timestamp;

test {
    // Pull in tests from all sub-modules.
    std.testing.refAllDecls(@This());
}
