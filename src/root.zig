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
pub const idea_mod = @import("crypto/idea.zig");
pub const blowfish_mod = @import("crypto/blowfish.zig");
pub const camellia_mod = @import("crypto/camellia.zig");
pub const key_stretching = @import("crypto/key_stretching.zig");
pub const cipher_registry = @import("crypto/cipher_registry.zig");

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

// Streaming API
pub const streaming = @import("streaming/mod.zig");

// Security utilities
pub const zeroize = @import("security/zeroize.zig");

// C ABI (FFI)
pub const cabi = @import("cabi/zpgp.zig");

// WKD and Autocrypt
pub const wkd = @import("wkd.zig");
pub const autocrypt = @import("autocrypt.zig");

// Inspection and analysis
pub const inspect = @import("inspect/mod.zig");

// Protocol validation
pub const protocol = @import("protocol/mod.zig");

// Utility modules
pub const utils = @import("utils/mod.zig");

// Policy modules
pub const algorithm_policy = @import("policy/algorithm_policy.zig");
pub const compliance = @import("policy/compliance.zig");

// Configuration modules
pub const preferences = @import("config/preferences.zig");
pub const gpg_config = @import("config/gpg_config.zig");

// Diagnostics modules
pub const error_report = @import("diag/error_report.zig");
pub const operation_log = @import("diag/operation_log.zig");

// Benchmark framework
pub const benchmark = @import("benchmark/bench.zig");

// Key migration utilities
pub const key_migrate = @import("migrate/key_migrate.zig");

// Compatibility layers
pub const gnupg_compat = @import("compat/gnupg.zig");
pub const sequoia_compat = @import("compat/sequoia.zig");

// Validation modules
pub const key_validator = @import("validation/key_validator.zig");
pub const message_validator = @import("validation/message_validator.zig");
pub const armor_validator = @import("validation/armor_validator.zig");

// Example modules
pub const example_encrypt_decrypt = @import("examples/encrypt_decrypt.zig");
pub const example_key_management = @import("examples/key_management.zig");
pub const example_signatures = @import("examples/signatures.zig");

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
pub const test_conformance = @import("test_conformance.zig");
pub const test_edge_cases = @import("test_edge_cases.zig");
pub const test_security = @import("test_security.zig");
pub const test_performance = @import("test_performance.zig");
pub const test_interop_v6 = @import("test_interop_v6.zig");
pub const test_utils = @import("test_utils.zig");
pub const test_policy = @import("test_policy.zig");
pub const test_examples = @import("test_examples.zig");
pub const test_inspect = @import("test_inspect.zig");
pub const test_protocol = @import("test_protocol.zig");
pub const test_ciphers_extended = @import("test_ciphers_extended.zig");
pub const test_config = @import("test_config.zig");
pub const test_diag = @import("test_diag.zig");
pub const test_benchmark = @import("test_benchmark.zig");
pub const test_migrate = @import("test_migrate.zig");
pub const test_compat = @import("test_compat.zig");
pub const test_validation = @import("test_validation.zig");
pub const test_sop_extended = @import("test_sop_extended.zig");

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

// Force C ABI symbol exports when built as a library.
// Referencing the cabi module at comptime ensures the `export fn`
// declarations within it are included in the compilation output.
comptime {
    _ = cabi;
}

test {
    // Pull in tests from all sub-modules.
    std.testing.refAllDecls(@This());
}
