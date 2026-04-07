// SPDX-License-Identifier: MIT
//! Tests for configuration modules (preferences, gpg_config).
//!
//! Exercises the preference negotiation system with comprehensive algorithm
//! combinations, multi-recipient scenarios, and the GnuPG configuration
//! parser with various real-world configuration patterns.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

const preferences_mod = @import("config/preferences.zig");
const Preferences = preferences_mod.Preferences;
const Features = preferences_mod.Features;
const NegotiatedAlgorithms = preferences_mod.NegotiatedAlgorithms;

const gpg_config_mod = @import("config/gpg_config.zig");
const GpgConfig = gpg_config_mod.GpgConfig;
const KeyserverOptions = gpg_config_mod.KeyserverOptions;

const enums = @import("types/enums.zig");
const SymmetricAlgorithm = enums.SymmetricAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;
const CompressionAlgorithm = enums.CompressionAlgorithm;
const AeadAlgorithm = enums.AeadAlgorithm;

// =========================================================================
// Preferences — negotiation between two parties
// =========================================================================

test "config: negotiate v4 sender with v4 recipient" {
    const sender = Preferences.default();
    const recipient = Preferences.default();
    const result = sender.negotiate(recipient);

    try testing.expect(result.symmetric == .aes256);
    try testing.expect(result.hash == .sha256);
    try testing.expect(result.compression == .zlib);
    try testing.expect(result.aead == null);
}

test "config: negotiate v6 sender with v6 recipient" {
    const sender = Preferences.defaultV6();
    const recipient = Preferences.defaultV6();
    const result = sender.negotiate(recipient);

    try testing.expect(result.symmetric == .aes256);
    try testing.expect(result.hash == .sha512);
    try testing.expect(result.aead != null);
    try testing.expect(result.aead.? == .ocb);
}

test "config: negotiate v4 sender with v6 recipient — AEAD disabled" {
    const sender = Preferences.default();
    const recipient = Preferences.defaultV6();
    const result = sender.negotiate(recipient);

    // V4 sender doesn't support AEAD
    try testing.expect(result.aead == null);
    // AES-256 is common to both
    try testing.expect(result.symmetric == .aes256);
}

test "config: negotiate v6 sender with v4 recipient — AEAD disabled" {
    const sender = Preferences.defaultV6();
    const recipient = Preferences.default();
    const result = sender.negotiate(recipient);

    try testing.expect(result.aead == null);
}

test "config: negotiate with no common symmetric — fallback to AES-128" {
    const allocator = testing.allocator;

    // Sender only supports Twofish
    var sender_sym = try allocator.alloc(SymmetricAlgorithm, 1);
    defer allocator.free(sender_sym);
    sender_sym[0] = .twofish;

    // Recipient only supports CAST5
    var recip_sym = try allocator.alloc(SymmetricAlgorithm, 1);
    defer allocator.free(recip_sym);
    recip_sym[0] = .cast5;

    const sender = Preferences{
        .symmetric = sender_sym,
        .hash = @constCast(&[_]HashAlgorithm{.sha256}),
        .compression = @constCast(&[_]CompressionAlgorithm{.uncompressed}),
        .aead = null,
        .features = .{},
    };
    const recipient = Preferences{
        .symmetric = recip_sym,
        .hash = @constCast(&[_]HashAlgorithm{.sha256}),
        .compression = @constCast(&[_]CompressionAlgorithm{.uncompressed}),
        .aead = null,
        .features = .{},
    };

    const result = sender.negotiate(recipient);
    // No common algorithm, should fall back to mandatory AES-128
    try testing.expect(result.symmetric == .aes128);
}

test "config: negotiate with no common hash — fallback to SHA-256" {
    const allocator = testing.allocator;

    var sender_hash = try allocator.alloc(HashAlgorithm, 1);
    defer allocator.free(sender_hash);
    sender_hash[0] = .sha512;

    var recip_hash = try allocator.alloc(HashAlgorithm, 1);
    defer allocator.free(recip_hash);
    recip_hash[0] = .sha1;

    const sender = Preferences{
        .symmetric = @constCast(&[_]SymmetricAlgorithm{.aes128}),
        .hash = sender_hash,
        .compression = @constCast(&[_]CompressionAlgorithm{.uncompressed}),
        .aead = null,
        .features = .{},
    };
    const recipient = Preferences{
        .symmetric = @constCast(&[_]SymmetricAlgorithm{.aes128}),
        .hash = recip_hash,
        .compression = @constCast(&[_]CompressionAlgorithm{.uncompressed}),
        .aead = null,
        .features = .{},
    };

    const result = sender.negotiate(recipient);
    try testing.expect(result.hash == .sha256);
}

// =========================================================================
// Preferences — multi-recipient negotiation
// =========================================================================

test "config: multi-recipient negotiation — two v4 recipients" {
    const allocator = testing.allocator;
    const prefs = [_]Preferences{ Preferences.default(), Preferences.default() };

    const result = try preferences_mod.negotiateForRecipients(allocator, &prefs);
    try testing.expect(result.symmetric == .aes256);
    try testing.expect(result.hash == .sha256);
    try testing.expect(result.aead == null);
}

test "config: multi-recipient negotiation — mixed v4 and v6" {
    const allocator = testing.allocator;
    const prefs = [_]Preferences{ Preferences.default(), Preferences.defaultV6() };

    const result = try preferences_mod.negotiateForRecipients(allocator, &prefs);
    try testing.expect(result.symmetric == .aes256);
    // AEAD: v4 recipient doesn't support, so null
    try testing.expect(result.aead == null);
}

test "config: multi-recipient negotiation — empty list" {
    const allocator = testing.allocator;
    const prefs = [_]Preferences{};

    const result = try preferences_mod.negotiateForRecipients(allocator, &prefs);
    // Should return safe defaults
    try testing.expect(result.symmetric == .aes128);
    try testing.expect(result.hash == .sha256);
    try testing.expect(result.compression == .uncompressed);
    try testing.expect(result.aead == null);
}

test "config: multi-recipient negotiation — single recipient" {
    const allocator = testing.allocator;
    const prefs = [_]Preferences{Preferences.defaultV6()};

    const result = try preferences_mod.negotiateForRecipients(allocator, &prefs);
    try testing.expect(result.symmetric == .aes256);
    try testing.expect(result.hash == .sha512);
    try testing.expect(result.aead != null);
}

// =========================================================================
// Preferences — algorithm scoring
// =========================================================================

test "config: symmetric algorithm scores" {
    // AES-256 should score highest
    try testing.expect(preferences_mod.symmetricScore(.aes256) > preferences_mod.symmetricScore(.aes128));
    try testing.expect(preferences_mod.symmetricScore(.aes128) > preferences_mod.symmetricScore(.cast5));
    try testing.expect(preferences_mod.symmetricScore(.cast5) > preferences_mod.symmetricScore(.idea));
    try testing.expect(preferences_mod.symmetricScore(.plaintext) == 0);
}

test "config: hash algorithm scores" {
    try testing.expect(preferences_mod.hashScore(.sha512) > preferences_mod.hashScore(.sha384));
    try testing.expect(preferences_mod.hashScore(.sha384) > preferences_mod.hashScore(.sha256));
    try testing.expect(preferences_mod.hashScore(.sha256) > preferences_mod.hashScore(.sha1));
    try testing.expect(preferences_mod.hashScore(.sha1) > preferences_mod.hashScore(.md5));
}

test "config: AEAD algorithm scores" {
    try testing.expect(preferences_mod.aeadScore(.ocb) > preferences_mod.aeadScore(.gcm));
    try testing.expect(preferences_mod.aeadScore(.gcm) > preferences_mod.aeadScore(.eax));
}

test "config: compression scores" {
    try testing.expect(preferences_mod.compressionScore(.zlib) > preferences_mod.compressionScore(.zip));
    try testing.expect(preferences_mod.compressionScore(.zip) > preferences_mod.compressionScore(.uncompressed));
}

// =========================================================================
// Features
// =========================================================================

test "config: features all" {
    const f = Features.all();
    try testing.expect(f.modification_detection);
    try testing.expect(f.aead);
    try testing.expect(!f.v5_keys);
}

test "config: features v4 default" {
    const f = Features.v4Default();
    try testing.expect(f.modification_detection);
    try testing.expect(!f.aead);
}

test "config: features v6 default" {
    const f = Features.v6Default();
    try testing.expect(f.modification_detection);
    try testing.expect(f.aead);
}

test "config: features describe" {
    const allocator = testing.allocator;

    const f1 = Features.v6Default();
    const desc1 = try f1.describe(allocator);
    defer allocator.free(desc1);
    try testing.expect(mem.indexOf(u8, desc1, "MDC") != null);
    try testing.expect(mem.indexOf(u8, desc1, "AEAD") != null);

    const f2 = Features{};
    const desc2 = try f2.describe(allocator);
    defer allocator.free(desc2);
    try testing.expectEqualStrings("none", desc2);
}

// =========================================================================
// Preferences — merge
// =========================================================================

test "config: merge preferences" {
    const allocator = testing.allocator;
    const v4 = Preferences.default();
    const v6 = Preferences.defaultV6();

    const merged = try v4.merge(v6, allocator);

    // Primary (v4) list should come first
    try testing.expect(merged.symmetric.len >= 4);
    try testing.expect(merged.symmetric[0] == .aes256);

    // Cleanup
    allocator.free(merged.symmetric);
    allocator.free(merged.hash);
    allocator.free(merged.compression);
    if (merged.aead) |aead_list| allocator.free(aead_list);
}

// =========================================================================
// Preferences — support checks
// =========================================================================

test "config: supports checks on v4 defaults" {
    const prefs = Preferences.default();
    try testing.expect(prefs.supportsSymmetric(.aes256));
    try testing.expect(prefs.supportsSymmetric(.cast5));
    try testing.expect(!prefs.supportsSymmetric(.twofish));
    try testing.expect(prefs.supportsHash(.sha256));
    try testing.expect(prefs.supportsHash(.sha1));
    try testing.expect(!prefs.supportsHash(.md5));
    try testing.expect(prefs.supportsCompression(.zlib));
    try testing.expect(!prefs.supportsAead(.ocb));
}

test "config: supports checks on v6 defaults" {
    const prefs = Preferences.defaultV6();
    try testing.expect(prefs.supportsAead(.ocb));
    try testing.expect(prefs.supportsAead(.gcm));
    try testing.expect(prefs.supportsAead(.eax));
}

// =========================================================================
// GpgConfig — typical configurations
// =========================================================================

test "config: gpg modern config" {
    const allocator = testing.allocator;
    const content =
        \\# Modern GnuPG configuration
        \\default-key 0x1234ABCD5678EF01
        \\keyserver hkps://keys.openpgp.org
        \\armor
        \\no-emit-version
        \\no-comments
        \\cipher-algo AES256
        \\digest-algo SHA512
        \\compress-algo ZLIB
        \\cert-digest-algo SHA512
        \\personal-cipher-preferences AES256 AES192 AES
        \\personal-digest-preferences SHA512 SHA384 SHA256
        \\personal-compress-preferences ZLIB BZIP2 ZIP
        \\s2k-cipher-algo AES256
        \\s2k-digest-algo SHA512
        \\s2k-mode 3
        \\s2k-count 65536
        \\use-agent
        \\
    ;

    var config = try GpgConfig.parse(allocator, content);
    defer config.deinit();

    try testing.expectEqualStrings("0x1234ABCD5678EF01", config.default_key.?);
    try testing.expectEqualStrings("hkps://keys.openpgp.org", config.keyserver.?);
    try testing.expect(config.armor);
    try testing.expect(config.no_emit_version);
    try testing.expect(config.no_comments);
    try testing.expect(config.cipher_algo.? == .aes256);
    try testing.expect(config.digest_algo.? == .sha512);
    try testing.expect(config.compress_algo.? == .zlib);
    try testing.expect(config.cert_digest_algo.? == .sha512);
    try testing.expect(config.s2k_cipher_algo.? == .aes256);
    try testing.expect(config.s2k_digest_algo.? == .sha512);
    try testing.expect(config.s2k_mode.? == 3);
    try testing.expect(config.s2k_count.? == 65536);
    try testing.expect(config.use_agent);

    try testing.expect(config.personal_cipher_preferences.len == 3);
    try testing.expect(config.personal_cipher_preferences[0] == .aes256);
    try testing.expect(config.personal_cipher_preferences[1] == .aes192);
    try testing.expect(config.personal_cipher_preferences[2] == .aes128);

    try testing.expect(config.personal_digest_preferences.len == 3);
    try testing.expect(config.personal_digest_preferences[0] == .sha512);
}

test "config: gpg minimal config" {
    const allocator = testing.allocator;
    const content =
        \\use-agent
        \\
    ;

    var config = try GpgConfig.parse(allocator, content);
    defer config.deinit();

    try testing.expect(config.use_agent);
    try testing.expect(config.default_key == null);
    try testing.expect(!config.armor);
}

test "config: gpg config with throw-keyids" {
    const allocator = testing.allocator;
    const content =
        \\throw-keyids
        \\default-recipient-self
        \\
    ;

    var config = try GpgConfig.parse(allocator, content);
    defer config.deinit();

    try testing.expect(config.throw_keyids);
    try testing.expect(config.default_recipient_self);
}

test "config: gpg config duplicate directives — last wins" {
    const allocator = testing.allocator;
    const content =
        \\cipher-algo AES128
        \\cipher-algo AES256
        \\
    ;

    var config = try GpgConfig.parse(allocator, content);
    defer config.deinit();

    try testing.expect(config.cipher_algo.? == .aes256);
}

test "config: gpg config serialize preserves settings" {
    const allocator = testing.allocator;
    const content =
        \\default-key ABCDEF01
        \\keyserver hkps://keys.example.com
        \\armor
        \\cipher-algo AES256
        \\digest-algo SHA256
        \\use-agent
        \\no-emit-version
        \\
    ;

    var config = try GpgConfig.parse(allocator, content);
    defer config.deinit();

    const serialized = try config.serialize(allocator);
    defer allocator.free(serialized);

    // Parse the serialized output
    var config2 = try GpgConfig.parse(allocator, serialized);
    defer config2.deinit();

    try testing.expectEqualStrings("ABCDEF01", config2.default_key.?);
    try testing.expectEqualStrings("hkps://keys.example.com", config2.keyserver.?);
    try testing.expect(config2.armor);
    try testing.expect(config2.cipher_algo.? == .aes256);
    try testing.expect(config2.digest_algo.? == .sha256);
    try testing.expect(config2.use_agent);
}

test "config: gpg config with windows line endings" {
    const allocator = testing.allocator;
    const content = "armor\r\nuse-agent\r\ndefault-key FFFF\r\n";

    var config = try GpgConfig.parse(allocator, content);
    defer config.deinit();

    try testing.expect(config.armor);
    try testing.expect(config.use_agent);
    try testing.expectEqualStrings("FFFF", config.default_key.?);
}

// =========================================================================
// GpgConfig — algorithm name parsing
// =========================================================================

test "config: parse symmetric algo names" {
    try testing.expect(gpg_config_mod.parseSymmetricAlgo("AES256").? == .aes256);
    try testing.expect(gpg_config_mod.parseSymmetricAlgo("aes256").? == .aes256);
    try testing.expect(gpg_config_mod.parseSymmetricAlgo("AES").? == .aes128);
    try testing.expect(gpg_config_mod.parseSymmetricAlgo("AES128").? == .aes128);
    try testing.expect(gpg_config_mod.parseSymmetricAlgo("3DES").? == .triple_des);
    try testing.expect(gpg_config_mod.parseSymmetricAlgo("CAST5").? == .cast5);
    try testing.expect(gpg_config_mod.parseSymmetricAlgo("TWOFISH").? == .twofish);
    try testing.expect(gpg_config_mod.parseSymmetricAlgo("BLOWFISH").? == .blowfish);
    try testing.expect(gpg_config_mod.parseSymmetricAlgo("IDEA").? == .idea);
    try testing.expect(gpg_config_mod.parseSymmetricAlgo("UNKNOWN") == null);
}

test "config: parse hash algo names" {
    try testing.expect(gpg_config_mod.parseHashAlgo("SHA256").? == .sha256);
    try testing.expect(gpg_config_mod.parseHashAlgo("SHA-256").? == .sha256);
    try testing.expect(gpg_config_mod.parseHashAlgo("SHA512").? == .sha512);
    try testing.expect(gpg_config_mod.parseHashAlgo("SHA1").? == .sha1);
    try testing.expect(gpg_config_mod.parseHashAlgo("MD5").? == .md5);
    try testing.expect(gpg_config_mod.parseHashAlgo("RIPEMD160").? == .ripemd160);
    try testing.expect(gpg_config_mod.parseHashAlgo("UNKNOWN") == null);
}

test "config: parse compression algo names" {
    try testing.expect(gpg_config_mod.parseCompressionAlgo("ZLIB").? == .zlib);
    try testing.expect(gpg_config_mod.parseCompressionAlgo("ZIP").? == .zip);
    try testing.expect(gpg_config_mod.parseCompressionAlgo("BZIP2").? == .bzip2);
    try testing.expect(gpg_config_mod.parseCompressionAlgo("NONE").? == .uncompressed);
    try testing.expect(gpg_config_mod.parseCompressionAlgo("UNCOMPRESSED").? == .uncompressed);
    try testing.expect(gpg_config_mod.parseCompressionAlgo("UNKNOWN") == null);
}

// =========================================================================
// GpgConfig — keyserver options
// =========================================================================

test "config: keyserver options defaults" {
    const opts = KeyserverOptions{};
    try testing.expect(!opts.auto_key_retrieve);
    try testing.expect(opts.honor_keyserver_url);
    try testing.expect(!opts.include_revoked);
}

test "config: keyserver options parse and serialize" {
    const allocator = testing.allocator;
    const opts = KeyserverOptions{
        .auto_key_retrieve = true,
        .honor_keyserver_url = false,
        .include_revoked = true,
        .include_subkeys = true,
    };

    const serialized = try opts.serialize(allocator);
    defer allocator.free(serialized);

    const parsed = KeyserverOptions.parse(serialized);
    try testing.expect(parsed.auto_key_retrieve);
    try testing.expect(!parsed.honor_keyserver_url);
    try testing.expect(parsed.include_revoked);
    try testing.expect(parsed.include_subkeys);
}

test "config: keyserver options parse comma separated" {
    const parsed = KeyserverOptions.parse("auto-key-retrieve,include-revoked,no-honor-keyserver-url");
    try testing.expect(parsed.auto_key_retrieve);
    try testing.expect(parsed.include_revoked);
    try testing.expect(!parsed.honor_keyserver_url);
}

// =========================================================================
// NegotiatedAlgorithms — describe
// =========================================================================

test "config: negotiated algorithms describe" {
    const allocator = testing.allocator;
    const neg = NegotiatedAlgorithms{
        .symmetric = .aes256,
        .hash = .sha512,
        .compression = .zlib,
        .aead = .ocb,
    };

    const desc = try neg.describe(allocator);
    defer allocator.free(desc);

    try testing.expect(mem.indexOf(u8, desc, "AES-256") != null);
    try testing.expect(mem.indexOf(u8, desc, "SHA512") != null);
    try testing.expect(mem.indexOf(u8, desc, "ZLIB") != null);
    try testing.expect(mem.indexOf(u8, desc, "OCB") != null);
}

test "config: negotiated algorithms describe without aead" {
    const allocator = testing.allocator;
    const neg = NegotiatedAlgorithms{
        .symmetric = .aes128,
        .hash = .sha256,
        .compression = .uncompressed,
        .aead = null,
    };

    const desc = try neg.describe(allocator);
    defer allocator.free(desc);

    try testing.expect(mem.indexOf(u8, desc, "AES-128") != null);
    try testing.expect(mem.indexOf(u8, desc, "none") != null);
}
