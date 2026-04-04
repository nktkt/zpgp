# zpgp

An OpenPGP (RFC 4880) implementation written from scratch in Zig.

## Features

- **Packet Parsing** -- Full support for all 15 OpenPGP packet types with streaming reader/writer and partial body length handling
- **ASCII Armor** -- Encode/decode armored PGP messages, keys, and signatures with CRC-24 validation
- **RSA** -- Up to 4096-bit key support built on `std.crypto.ff`, with PKCS#1 v1.5 signing, verification, encryption, and decryption
- **Ed25519 / ECDSA / ECDH** -- Curve25519 key agreement via `std.crypto.dh.X25519`
- **Symmetric Ciphers** -- AES-128, AES-256, CAST5 (RFC 2144), and Twofish
- **OpenPGP CFB Mode** -- Both resyncing (legacy SED) and non-resyncing (SEIPD) variants
- **String-to-Key (S2K)** -- Simple, Salted, and Iterated+Salted key derivation
- **AES Key Wrap** -- RFC 3394 implementation for ECDH session key wrapping
- **Signatures** -- Creation and verification of document, certification, and subkey binding signatures with full subpacket support
- **Key Management** -- Key import/export, keyring, V4 fingerprint calculation
- **Compression** -- ZIP (raw DEFLATE) and ZLIB decompression via `std.compress.flate`
- **Web of Trust** -- Basic trust database with validity calculation
- **Key Revocation** -- Create and verify revocation signatures
- **HKP Client** -- Keyserver protocol URL formatting and request building
- **CLI Tool** -- `zpgp` command-line interface for common operations

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
  keygen    Generate a new key pair
  sign      Sign a file
  verify    Verify a signature
  encrypt   Encrypt a file
  decrypt   Decrypt a file
  key       Key management (import, export, list)
  armor     ASCII-armor binary data
  dearmor   Remove ASCII armor
  version   Show version information
  help      Show this help message
```

### Examples

```sh
# ASCII-armor a file
zpgp armor message.bin

# Armor from stdin
echo "Hello, PGP!" | zpgp armor -

# Remove armor
zpgp dearmor message.asc

# Import a public key
zpgp key import pubkey.asc

# List keys in a keyring
zpgp key list keyring.gpg
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
  main.zig              CLI entry point
  root.zig              Library root (public API)
  packet/               Packet framing (headers, streaming I/O)
  packets/              Individual packet type parsers (15 types)
  types/                Core types (enums, MPI, S2K, timestamps)
  armor/                ASCII Armor + CRC-24
  crypto/               Cryptographic primitives
    rsa.zig             RSA (PKCS#1 v1.5)
    cfb.zig             OpenPGP CFB mode
    cast5.zig           CAST-128 cipher
    twofish.zig         Twofish cipher
    ecdh.zig            ECDH key agreement
    aes_keywrap.zig     AES Key Wrap (RFC 3394)
    hash.zig            Runtime hash dispatch
    session_key.zig     Session key management
  signature/            Signature creation, verification, subpackets
  key/                  Key structures, keyring, fingerprints, trust, revocation
  message/              High-level message compose/decompose
  keyserver/            HKP protocol client
```

## Supported Algorithms

| Category | Algorithms |
|----------|-----------|
| Public Key | RSA (1,2,3), DSA (17), ECDH (18), ECDSA (19), EdDSA (22) |
| Symmetric | AES-128 (7), AES-256 (9), CAST5 (3), Twofish (10), TripleDES (2) |
| Hash | SHA-1 (2), SHA-256 (8), SHA-384 (9), SHA-512 (10), SHA-224 (11) |
| Compression | Uncompressed (0), ZIP (1), ZLIB (2) |

## Standards

- [RFC 4880](https://datatracker.ietf.org/doc/html/rfc4880) -- OpenPGP Message Format
- [RFC 2144](https://datatracker.ietf.org/doc/html/rfc2144) -- The CAST-128 Encryption Algorithm
- [RFC 3394](https://datatracker.ietf.org/doc/html/rfc3394) -- AES Key Wrap Algorithm
- [RFC 6637](https://datatracker.ietf.org/doc/html/rfc6637) -- Elliptic Curve Cryptography (ECC) in OpenPGP
- [RFC 3447](https://datatracker.ietf.org/doc/html/rfc3447) -- PKCS #1 v2.1 (RSA)

## License

MIT
