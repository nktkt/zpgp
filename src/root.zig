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
pub const v3_signature = @import("packets/v3_signature.zig");
pub const v3_public_key = @import("packets/v3_public_key.zig");
pub const pkesk = @import("packets/pkesk.zig");
pub const skesk = @import("packets/skesk.zig");
pub const compressed_data = @import("packets/compressed_data.zig");
pub const sym_enc_data = @import("packets/sym_enc_data.zig");
pub const sym_enc_integrity = @import("packets/sym_enc_integrity.zig");
pub const v6_public_key = @import("packets/v6_public_key.zig");
pub const v6_signature = @import("packets/v6_signature.zig");
pub const padding = @import("packets/padding.zig");

// Core types (S2K)
pub const s2k = @import("types/s2k.zig");

// Crypto foundations
pub const hash = @import("crypto/hash.zig");
pub const rsa = @import("crypto/rsa.zig");
pub const rsa_keygen = @import("crypto/rsa_keygen.zig");
pub const dsa = @import("crypto/dsa.zig");
pub const cfb = @import("crypto/cfb.zig");
pub const aes_keywrap = @import("crypto/aes_keywrap.zig");
pub const ecdh_mod = @import("crypto/ecdh.zig");
pub const session_key_mod = @import("crypto/session_key.zig");
pub const cast5_mod = @import("crypto/cast5.zig");
pub const twofish_mod = @import("crypto/twofish.zig");
pub const triple_des_mod = @import("crypto/triple_des.zig");
pub const elgamal_mod = @import("crypto/elgamal.zig");
pub const seipd = @import("crypto/seipd.zig");
pub const seipd_v2 = @import("crypto/seipd_v2.zig");
pub const ed25519_ops = @import("crypto/ed25519_ops.zig");
pub const ed25519_native = @import("crypto/ed25519_native.zig");
pub const x25519_native = @import("crypto/x25519_native.zig");
pub const x448_mod = @import("crypto/x448.zig");
pub const ed448_mod = @import("crypto/ed448.zig");
pub const hkdf_mod = @import("crypto/hkdf.zig");
pub const argon2_mod = @import("crypto/argon2.zig");
pub const deprecation_mod = @import("crypto/deprecation.zig");

// AEAD modes (RFC 9580)
pub const aead = @import("crypto/aead/aead.zig");
pub const aead_eax = @import("crypto/aead/eax.zig");
pub const aead_ocb = @import("crypto/aead/ocb.zig");
pub const aead_gcm = @import("crypto/aead/gcm.zig");

// V6 crypto (RFC 9580)
pub const pkesk_v6 = @import("crypto/pkesk_v6.zig");
pub const skesk_v6 = @import("crypto/skesk_v6.zig");
pub const symmetric_dispatch = @import("crypto/symmetric_dispatch.zig");

// Signature modules
pub const subpackets = @import("signature/subpackets.zig");
pub const sig_types = @import("signature/types.zig");
pub const sig_creation = @import("signature/creation.zig");
pub const sig_verification = @import("signature/verification.zig");
pub const cleartext = @import("signature/cleartext.zig");
pub const detached = @import("signature/detached.zig");
pub const notation = @import("signature/notation.zig");
pub const v6_sig_creation = @import("signature/v6_creation.zig");
pub const v6_sig_verification = @import("signature/v6_verification.zig");

// Key modules
pub const fingerprint_mod = @import("key/fingerprint.zig");
pub const v6_fingerprint_mod = @import("key/v6_fingerprint.zig");
pub const key_mod = @import("key/key.zig");
pub const import_export = @import("key/import_export.zig");
pub const keyring = @import("key/keyring.zig");
pub const revocation = @import("key/revocation.zig");
pub const trust_model = @import("key/trust_model.zig");
pub const keygen = @import("key/generate.zig");
pub const v6_keygen = @import("key/v6_generate.zig");
pub const subkey = @import("key/subkey.zig");
pub const expiration = @import("key/expiration.zig");
pub const designated_revoker = @import("key/designated_revoker.zig");
pub const keyring_io = @import("key/keyring_io.zig");
pub const v6_key = @import("key/v6_key.zig");
pub const v6_import_export = @import("key/v6_import_export.zig");

// Keyserver modules
pub const hkp = @import("keyserver/hkp.zig");
pub const hkp_client = @import("keyserver/hkp_client.zig");

// Message modules
pub const message = @import("message/message.zig");
pub const compose = @import("message/compose.zig");
pub const decompose = @import("message/decompose.zig");
pub const v6_compose = @import("message/v6_compose.zig");
pub const v6_decompose = @import("message/v6_decompose.zig");

// WKD and Autocrypt
pub const wkd = @import("wkd.zig");
pub const autocrypt = @import("autocrypt.zig");

// Integration tests
pub const test_interop = @import("test_interop.zig");
pub const test_full = @import("test_full.zig");
pub const test_rfc9580 = @import("test_rfc9580.zig");
pub const test_v6_full = @import("test_v6_full.zig");
pub const test_algorithms = @import("test_algorithms.zig");
pub const test_crypto_vectors = @import("test_crypto_vectors.zig");
pub const test_packet_roundtrip = @import("test_packet_roundtrip.zig");
pub const test_key_lifecycle = @import("test_key_lifecycle.zig");
pub const test_message_roundtrip = @import("test_message_roundtrip.zig");
pub const test_subpacket_exhaustive = @import("test_subpacket_exhaustive.zig");

// Re-exports for convenience.
pub const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
pub const SymmetricAlgorithm = enums.SymmetricAlgorithm;
pub const HashAlgorithm = enums.HashAlgorithm;
pub const CompressionAlgorithm = enums.CompressionAlgorithm;
pub const AeadAlgorithm = enums.AeadAlgorithm;
pub const Mpi = mpi.Mpi;
pub const KeyId = key_id.KeyId;
pub const Fingerprint = key_id.Fingerprint;
pub const Timestamp = time.Timestamp;

test {
    // Pull in tests from all sub-modules.
    std.testing.refAllDecls(@This());
}
