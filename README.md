# zpgp

A comprehensive OpenPGP implementation written from scratch in Zig, covering both RFC 4880 (OpenPGP) and RFC 9580 (Crypto Refresh).

**93,000+ LOC | 180 source files | 2,834+ tests**

## Features

### Core Protocol
- **RFC 4880 (OpenPGP)** -- Full implementation of the classic OpenPGP standard
- **RFC 9580 (Crypto Refresh)** -- V6 keys, V6 signatures, SEIPDv2, AEAD, Argon2 S2K, padding packets
- **Packet Parsing** -- All OpenPGP packet types with streaming reader/writer and partial body length handling
- **ASCII Armor** -- Encode/decode armored PGP messages, keys, and signatures with CRC-24 validation
- **Cleartext Signature Framework** -- RFC 4880 Section 7 cleartext signed messages
- **Detached Signatures** -- Create and verify detached signature files

### Cryptographic Algorithms
- **Public Key** -- RSA (up to 4096-bit), Ed25519, X25519, DSA, ElGamal, ECDH, ECDSA
- **Symmetric Ciphers** -- AES-128, AES-192, AES-256, CAST5, Twofish, Blowfish, IDEA, Camellia-128, Camellia-192, Camellia-256, TripleDES
- **AEAD Modes** -- EAX, OCB3, GCM (RFC 9580 SEIPDv2)
- **Hash Functions** -- SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
- **S2K (String-to-Key)** -- Simple, Salted, Iterated+Salted, Argon2 (RFC 9580)
- **OpenPGP CFB Mode** -- Both resyncing (legacy SED) and non-resyncing (SEIPD) variants
- **AES Key Wrap** -- RFC 3394 implementation for ECDH session key wrapping

### Key Management
- **Key Generation** -- RSA, Ed25519, X25519, V4 and V6 key generation
- **Key Import/Export** -- Full key serialization including V6 keys
- **Keyring** -- Keyring management with GPG-compatible keyring I/O
- **Subkey Lifecycle** -- Create, bind, revoke, and select subkeys
- **Fingerprints** -- V4 (SHA-1) and V6 (SHA-256) fingerprint calculation
- **Web of Trust** -- Trust database with validity and trust path calculation
- **Key Revocation** -- Create and verify revocation signatures, designated revokers
- **Key Migration** -- V4 to V6 key migration
- **SSH Export** -- Export OpenPGP keys in SSH format

### Signatures
- **Creation and Verification** -- Document, certification, and subkey binding signatures
- **Subpacket Support** -- Full subpacket parsing including notation data
- **V6 Signatures** -- RFC 9580 V6 signature creation and verification

### Encryption and Compression
- **SEIPD** -- Symmetrically Encrypted Integrity Protected Data (V1)
- **SEIPDv2** -- AEAD-based encryption (RFC 9580)
- **Compression** -- Uncompressed, ZIP (raw DEFLATE), ZLIB

### Interoperability
- **GnuPG Compatibility** -- Cross-verification and format compatibility
- **Sequoia Compatibility** -- Interoperability with Sequoia PGP
- **Stateless OpenPGP (SOP)** -- Standard SOP interface
- **PGP/MIME** -- MIME integration for email
- **Autocrypt** -- Autocrypt header support
- **Web Key Directory (WKD)** -- Key discovery via WKD
- **HKP Client** -- Keyserver protocol for key lookup and submission

### Infrastructure
- **CLI Tool** -- Full-featured `zpgp` command-line interface
- **C ABI (libzpgp)** -- Shared/static library for FFI consumers
- **Streaming API** -- Streaming encrypt, decrypt, sign, and verify for large messages
- **SmartCard Support** -- OpenPGP Card protocol operations
- **Benchmarking Framework** -- Performance measurement and comparison
- **Algorithm Policy Engine** -- Configurable algorithm acceptance policies
- **Validation** -- Key, message, and armor validators
- **Diagnostics** -- Error reporting and operation logging

## Requirements

- Zig 0.15.2 or later

## Build

```sh
# Build the library and CLI
zig build

# Run all tests
zig build test

# Run the CLI
zig build run -- version
```

## CLI Usage

```
Usage: zpgp <command> [options]

Commands:
  keygen    Generate a new key pair (RSA, Ed25519, V6)
  sign      Sign a file or message
  verify    Verify a signature
  encrypt   Encrypt a file or message
  decrypt   Decrypt a file or message
  key       Key management (import, export, list, migrate)
  armor     ASCII-armor binary data
  dearmor   Remove ASCII armor
  inspect   Inspect packets, keys, and messages
  version   Show version information
  help      Show this help message
```

### Examples

```sh
# Generate a new Ed25519 key pair
zpgp keygen --algo ed25519 --uid "Alice <alice@example.com>"

# Sign a file
zpgp sign --key secret.asc document.txt

# Verify a signature
zpgp verify --key pubkey.asc document.txt.sig

# Encrypt to a recipient
zpgp encrypt --recipient pubkey.asc message.txt

# Decrypt a message
zpgp decrypt --key secret.asc message.txt.gpg

# ASCII-armor a file
zpgp armor message.bin

# Import a public key
zpgp key import pubkey.asc

# List keys in a keyring
zpgp key list keyring.gpg

# Inspect a packet dump
zpgp inspect message.gpg
```

## Library Usage

```zig
const zpgp = @import("zpgp");

// Decode ASCII armor
const result = try zpgp.armor.decode(allocator, armored_text);
defer result.deinit(allocator);

// Parse packet headers
var fbs = std.io.fixedBufferStream(result.data);
const header = try zpgp.packet.header.readHeader(fbs.reader());

// CRC-24 checksum
const crc = zpgp.crc24.compute(data);

// Hash with runtime algorithm selection
var ctx = try zpgp.hash.HashContext.init(.sha256);
ctx.update(data);
var digest: [32]u8 = undefined;
ctx.final(&digest);
```

## Project Structure

```
src/
  main.zig                CLI entry point
  root.zig                Library root (public API)
  autocrypt.zig           Autocrypt header support
  wkd.zig                 Web Key Directory client
  packet/                 Packet framing (headers, streaming I/O, tags)
  packets/                Individual packet type parsers (V3, V4, V6)
  types/                  Core types (enums, MPI, S2K, key IDs, timestamps)
  armor/                  ASCII Armor + CRC-24
  crypto/                 Cryptographic primitives
    rsa.zig / rsa_keygen.zig   RSA (PKCS#1 v1.5) + key generation
    cfb.zig               OpenPGP CFB mode
    cast5.zig             CAST-128 cipher
    twofish.zig           Twofish cipher
    blowfish.zig          Blowfish cipher
    idea.zig              IDEA cipher
    camellia.zig          Camellia-128/192/256 cipher
    triple_des.zig        TripleDES cipher
    ecdh.zig              ECDH key agreement
    ed25519_native.zig    Ed25519 native signatures
    x25519_native.zig     X25519 native key agreement
    dsa.zig               DSA sign/verify
    elgamal.zig           ElGamal encryption
    argon2.zig            Argon2 S2K (RFC 9580)
    aes_keywrap.zig       AES Key Wrap (RFC 3394)
    hash.zig              Runtime hash dispatch
    hkdf.zig              HKDF key derivation
    session_key.zig       Session key management
    seipd.zig / seipd_v2.zig  SEIPD V1 and V2 (AEAD)
    aead/                 AEAD modes (EAX, OCB3, GCM)
  signature/              Signature creation, verification, cleartext, detached
  key/                    Key structures, keyring, fingerprints, trust, V6 keys
  message/                High-level message compose/decompose (V4 and V6)
  streaming/              Streaming encrypt, decrypt, sign, verify
  keyserver/              HKP protocol client
  cabi/                   C ABI (libzpgp) for FFI consumers
  sop/                    Stateless OpenPGP (SOP) interface
  card/                   OpenPGP SmartCard protocol
  compat/                 GnuPG and Sequoia compatibility layers
  config/                 GPG configuration and algorithm preferences
  formats/                Cleartext signatures, PGP/MIME, SSH, keyring format
  inspect/                Packet dump, key and message analyzers
  migrate/                V4 to V6 key migration
  policy/                 Algorithm policy engine and compliance checks
  protocol/               High-level OpenPGP message and key protocols
  security/               Memory zeroization for secret material
  validation/             Key, message, and armor validators
  diag/                   Error reporting and operation logging
  utils/                  Base64, hex, PEM, email, time formatting
  benchmark/              Performance benchmarking framework
  examples/               Encrypt/decrypt, key management, signature examples
```

## Supported Algorithms

| Category | Algorithms |
|----------|-----------|
| Public Key | RSA (1,2,3), DSA (17), ECDH (18), ECDSA (19), EdDSA (22), Ed25519 (27), X25519 (25) |
| Symmetric | TripleDES (2), CAST5 (3), Blowfish (4), AES-128 (7), AES-192 (8), AES-256 (9), Twofish (10), Camellia-128 (11), Camellia-192 (12), Camellia-256 (13), IDEA (1) |
| AEAD | EAX (1), OCB (2), GCM (3) |
| Hash | SHA-1 (2), SHA-256 (8), SHA-384 (9), SHA-512 (10), SHA-224 (11) |
| S2K | Simple (0), Salted (1), Iterated+Salted (3), Argon2 (4, RFC 9580) |
| Compression | Uncompressed (0), ZIP (1), ZLIB (2) |

## Roadmap

### v0.1 -- Foundation (13k LOC) -- DONE

Core packet parsing, ASCII armor, RSA, Ed25519/ECDH, basic CLI, CAST5, Twofish, OpenPGP CFB, S2K, AES Key Wrap, Web of Trust, HKP client.

### v0.2 -- GnuPG Interoperability (20k LOC) -- DONE

RSA key generation, full keygen CLI, sign/verify/encrypt/decrypt commands, secret key passphrase handling, SEIPD integration, GnuPG cross-verification, DSA support.

### v0.3 -- RFC 4880 Full Compliance (30k LOC) -- DONE

V3 packet/signature support, Cleartext Signature Framework, detached signatures, full subkey lifecycle, designated revokers, key expiration, notation data, ElGamal encryption, TripleDES, keyring I/O, comprehensive error diagnostics, property-based and fuzz testing.

### v0.4 -- RFC 9580 Crypto Refresh (45k LOC) -- DONE

V6 key and signature packets, SEIPDv2 (AEAD), all AEAD modes (EAX, OCB, GCM), native X25519/Ed25519 key types, Argon2 S2K, V6 fingerprints (SHA-256), padding packets, deprecation warnings, RFC 9580 test vectors and interop testing.

### v1.0 -- Production Ready (93k+ LOC) -- CURRENT

| Task | Status |
|------|--------|
| Constant-time operations audit | Done |
| Memory zeroization for secret material | Done |
| Streaming API for large messages | Done |
| WKD (Web Key Directory) client | Done |
| Autocrypt header support | Done |
| C ABI (libzpgp) for FFI consumers | Done |
| Stateless OpenPGP (SOP) interface | Done |
| GnuPG/Sequoia compatibility layers | Done |
| SmartCard (OpenPGP Card) protocol | Done |
| Key migration (V4 to V6) | Done |
| SSH key export | Done |
| PGP/MIME support | Done |
| Algorithm policy engine | Done |
| Benchmarking framework | Done |
| API documentation and examples | Done |
| Conformance test suite (2,834+ tests) | Done |
| Blowfish, IDEA, Camellia ciphers | Done |
| Ed448 / X448 support | Awaiting Zig stdlib |
| BZip2 compression | Planned |
| Hardware token (PKCS#11) integration | Planned |

### Comparative Scale

```
LOC (thousands)
0    10    20    30    40    50    60    70    80    90   100  ...  350+
|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|------>|
[##############################]                                      Sequoia (44k)
[###################################]                                 OpenPGP.js (53k)
[##############################################]                      GopenPGP (50k)
[#############################################################]      zpgp v1.0 (93k)
[###########################################################################...] GnuPG (350k+)
```

## Standards

- [RFC 4880](https://datatracker.ietf.org/doc/html/rfc4880) -- OpenPGP Message Format
- [RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580) -- OpenPGP (Crypto Refresh)
- [RFC 2144](https://datatracker.ietf.org/doc/html/rfc2144) -- The CAST-128 Encryption Algorithm
- [RFC 3394](https://datatracker.ietf.org/doc/html/rfc3394) -- AES Key Wrap Algorithm
- [RFC 6637](https://datatracker.ietf.org/doc/html/rfc6637) -- Elliptic Curve Cryptography (ECC) in OpenPGP
- [RFC 3447](https://datatracker.ietf.org/doc/html/rfc3447) -- PKCS #1 v2.1 (RSA)
- [RFC 4880bis](https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis) -- OpenPGP (Draft Updates)

## License

MIT
