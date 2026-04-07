// SPDX-License-Identifier: MIT
//! Multiple keyring format support.
//!
//! Provides detection, import, and export of keys in various keyring
//! formats:
//!   - Binary OpenPGP packet format
//!   - ASCII-armored OpenPGP format
//!   - GnuPG keybox format (KBX) — detection only
//!   - SSH authorized_keys format
//!
//! This module acts as a format-agnostic front-end for key I/O,
//! automatically detecting the input format and routing to the
//! appropriate parser.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const armor = @import("../armor/armor.zig");

/// Supported keyring formats.
pub const KeyringFormat = enum {
    /// Raw binary OpenPGP packet sequence.
    binary,
    /// ASCII-armored OpenPGP data.
    armored,
    /// GnuPG keybox (KBX) format.
    keybox,
    /// SSH authorized_keys format (one key per line).
    ssh_authorized_keys,

    /// Return a human-readable label for the format.
    pub fn label(self: KeyringFormat) []const u8 {
        return switch (self) {
            .binary => "OpenPGP (binary)",
            .armored => "OpenPGP (armored)",
            .keybox => "GnuPG keybox (KBX)",
            .ssh_authorized_keys => "SSH authorized_keys",
        };
    }

    /// Return the conventional file extension for the format.
    pub fn extension(self: KeyringFormat) []const u8 {
        return switch (self) {
            .binary => ".gpg",
            .armored => ".asc",
            .keybox => ".kbx",
            .ssh_authorized_keys => "",
        };
    }
};

/// Errors specific to keyring format operations.
pub const KeyringFormatError = error{
    UnsupportedFormat,
    InvalidData,
    ConversionNotSupported,
    OutOfMemory,
    Overflow,
};

/// A single key extracted during import.
pub const KeyData = struct {
    /// Raw key data in binary OpenPGP format.
    data: []u8,
    /// Whether this key includes secret key material.
    is_secret: bool,

    pub fn deinit(self: KeyData, allocator: Allocator) void {
        allocator.free(self.data);
    }
};

/// Result of importing keys from any supported format.
pub const ImportedKeys = struct {
    /// The imported key data.
    keys: std.ArrayList(KeyData),
    /// The format that was detected in the input.
    format_detected: KeyringFormat,

    pub fn init(allocator: Allocator) ImportedKeys {
        _ = allocator;
        return .{
            .keys = .empty,
            .format_detected = .binary,
        };
    }

    pub fn deinit(self: *ImportedKeys, allocator: Allocator) void {
        for (self.keys.items) |k| k.deinit(allocator);
        self.keys.deinit(allocator);
    }

    /// Return the number of imported keys.
    pub fn count(self: *const ImportedKeys) usize {
        return self.keys.items.len;
    }

    /// Return the number of secret keys imported.
    pub fn secretKeyCount(self: *const ImportedKeys) usize {
        var n: usize = 0;
        for (self.keys.items) |k| {
            if (k.is_secret) n += 1;
        }
        return n;
    }

    /// Return the number of public keys imported.
    pub fn publicKeyCount(self: *const ImportedKeys) usize {
        return self.count() - self.secretKeyCount();
    }
};

/// Statistics about a keyring export operation.
pub const ExportStats = struct {
    keys_exported: usize,
    bytes_written: usize,
    format: KeyringFormat,
};

// ===========================================================================
// Format detection
// ===========================================================================

/// Detect the keyring format of the given data.
///
/// Heuristics:
///   - Starts with "-----BEGIN " -> armored
///   - Starts with KBX magic bytes (0x00 or specific header) -> keybox
///   - Starts with "ssh-" -> ssh_authorized_keys
///   - First byte has bit 7 set (OpenPGP packet tag) -> binary
///   - Otherwise -> binary (default)
pub fn detectFormat(data: []const u8) KeyringFormat {
    if (data.len == 0) return .binary;

    // ASCII-armored OpenPGP data
    if (data.len >= 11 and mem.startsWith(u8, data, "-----BEGIN ")) {
        return .armored;
    }

    // SSH authorized_keys format
    if (isSshAuthorizedKeys(data)) {
        return .ssh_authorized_keys;
    }

    // GnuPG keybox format (KBX)
    // KBX files start with a header blob: version byte, then "KBXf" magic
    if (data.len >= 8) {
        // Check for KBX header blob
        if (mem.indexOf(u8, data[0..@min(32, data.len)], "KBXf") != null) {
            return .keybox;
        }
        // Alternative: KBX starts with blob header (4 bytes length, 1 byte type = 1)
        if (data.len >= 5 and data[4] == 0x01) {
            const blob_len = std.mem.readInt(u32, data[0..4], .big);
            if (blob_len > 16 and blob_len < 1024) {
                // Plausible KBX header blob
                if (data.len >= blob_len and data.len > 32) {
                    // Look for KBX magic in the first blob
                    if (mem.indexOf(u8, data[0..@min(blob_len, data.len)], "KBXf") != null) {
                        return .keybox;
                    }
                }
            }
        }
    }

    // Binary OpenPGP packet (bit 7 must be set for a valid packet tag)
    if (data[0] & 0x80 != 0) {
        return .binary;
    }

    // Default to binary
    return .binary;
}

/// Check if data looks like SSH authorized_keys format.
fn isSshAuthorizedKeys(data: []const u8) bool {
    const trimmed = mem.trimLeft(u8, data, " \t");

    // Check for common SSH key type prefixes
    if (mem.startsWith(u8, trimmed, "ssh-rsa ")) return true;
    if (mem.startsWith(u8, trimmed, "ssh-ed25519 ")) return true;
    if (mem.startsWith(u8, trimmed, "ecdsa-sha2-")) return true;
    if (mem.startsWith(u8, trimmed, "ssh-dss ")) return true;

    return false;
}

// ===========================================================================
// Format conversion
// ===========================================================================

/// Convert keyring data from one format to another.
///
/// Supported conversions:
///   - binary <-> armored
///   - armored -> binary
///   - binary -> armored
///
/// Other conversions return ConversionNotSupported.
pub fn convertFormat(
    allocator: Allocator,
    data: []const u8,
    from: KeyringFormat,
    to: KeyringFormat,
) KeyringFormatError![]u8 {
    // Same format, just copy
    if (from == to) {
        return allocator.dupe(u8, data) catch return KeyringFormatError.OutOfMemory;
    }

    switch (from) {
        .binary => switch (to) {
            .armored => {
                // Detect the armor type from the first packet
                const armor_type = detectArmorType(data);
                return armor.encode(allocator, data, armor_type, null) catch
                    return KeyringFormatError.InvalidData;
            },
            else => return KeyringFormatError.ConversionNotSupported,
        },
        .armored => switch (to) {
            .binary => {
                var result = armor.decode(allocator, data) catch
                    return KeyringFormatError.InvalidData;
                const binary = allocator.dupe(u8, result.data) catch {
                    result.deinit();
                    return KeyringFormatError.OutOfMemory;
                };
                result.deinit();
                return binary;
            },
            else => return KeyringFormatError.ConversionNotSupported,
        },
        else => return KeyringFormatError.ConversionNotSupported,
    }
}

/// Detect the armor type from binary OpenPGP data.
fn detectArmorType(data: []const u8) armor.ArmorType {
    if (data.len == 0) return .public_key;

    const first = data[0];
    if (first & 0x80 == 0) return .public_key;

    const tag: u8 = if (first & 0x40 != 0)
        first & 0x3F
    else
        (first >> 2) & 0x0F;

    return switch (tag) {
        2 => .signature,
        5, 7 => .private_key,
        6, 14 => .public_key,
        else => .public_key,
    };
}

// ===========================================================================
// Import
// ===========================================================================

/// Import keys from any supported format.
///
/// Automatically detects the format and parses the keys accordingly.
pub fn importFromAnyFormat(allocator: Allocator, data: []const u8) KeyringFormatError!ImportedKeys {
    if (data.len == 0) return KeyringFormatError.InvalidData;

    const format = detectFormat(data);

    var result = ImportedKeys.init(allocator);
    errdefer result.deinit(allocator);
    result.format_detected = format;

    switch (format) {
        .armored => {
            // Decode armor and import as binary
            var decode_result = armor.decode(allocator, data) catch
                return KeyringFormatError.InvalidData;

            const is_secret = decode_result.armor_type == .private_key;
            const binary = allocator.dupe(u8, decode_result.data) catch {
                decode_result.deinit();
                return KeyringFormatError.OutOfMemory;
            };
            decode_result.deinit();

            result.keys.append(allocator, .{
                .data = binary,
                .is_secret = is_secret,
            }) catch {
                allocator.free(binary);
                return KeyringFormatError.OutOfMemory;
            };
        },
        .binary => {
            // Import binary data as-is
            const key_data = allocator.dupe(u8, data) catch return KeyringFormatError.OutOfMemory;

            // Check first packet tag to determine if secret key
            const is_secret = if (data.len > 0 and data[0] & 0x80 != 0) blk: {
                const tag: u8 = if (data[0] & 0x40 != 0)
                    data[0] & 0x3F
                else
                    (data[0] >> 2) & 0x0F;
                break :blk (tag == 5 or tag == 7); // Secret key or secret subkey
            } else false;

            result.keys.append(allocator, .{
                .data = key_data,
                .is_secret = is_secret,
            }) catch {
                allocator.free(key_data);
                return KeyringFormatError.OutOfMemory;
            };
        },
        .ssh_authorized_keys => {
            // Parse SSH authorized_keys format (one key per line)
            var line_iter = mem.splitSequence(u8, data, "\n");
            while (line_iter.next()) |line| {
                const trimmed = mem.trim(u8, line, " \t\r");
                if (trimmed.len == 0) continue;
                if (trimmed[0] == '#') continue; // Skip comments

                // Store the line as key data
                const line_copy = allocator.dupe(u8, trimmed) catch
                    return KeyringFormatError.OutOfMemory;

                result.keys.append(allocator, .{
                    .data = line_copy,
                    .is_secret = false,
                }) catch {
                    allocator.free(line_copy);
                    return KeyringFormatError.OutOfMemory;
                };
            }
        },
        .keybox => {
            // KBX format is detected but full parsing is not yet implemented.
            // Return the raw data as a single "key" for now.
            const key_data = allocator.dupe(u8, data) catch return KeyringFormatError.OutOfMemory;
            result.keys.append(allocator, .{
                .data = key_data,
                .is_secret = false,
            }) catch {
                allocator.free(key_data);
                return KeyringFormatError.OutOfMemory;
            };
        },
    }

    return result;
}

// ===========================================================================
// Export
// ===========================================================================

/// Export key data in the specified format.
///
/// Takes raw binary OpenPGP key data and converts it to the requested
/// output format.
pub fn exportInFormat(
    allocator: Allocator,
    key_data: []const u8,
    format: KeyringFormat,
    is_secret: bool,
) KeyringFormatError![]u8 {
    switch (format) {
        .binary => {
            return allocator.dupe(u8, key_data) catch return KeyringFormatError.OutOfMemory;
        },
        .armored => {
            const armor_type: armor.ArmorType = if (is_secret) .private_key else .public_key;
            return armor.encode(allocator, key_data, armor_type, null) catch
                return KeyringFormatError.InvalidData;
        },
        .keybox => return KeyringFormatError.ConversionNotSupported,
        .ssh_authorized_keys => return KeyringFormatError.ConversionNotSupported,
    }
}

/// Export multiple keys in the specified format, concatenating the results.
pub fn exportMultipleInFormat(
    allocator: Allocator,
    keys: []const KeyData,
    format: KeyringFormat,
) KeyringFormatError![]u8 {
    if (keys.len == 0) return allocator.alloc(u8, 0) catch return KeyringFormatError.OutOfMemory;

    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    for (keys) |key| {
        const exported = try exportInFormat(allocator, key.data, format, key.is_secret);
        defer allocator.free(exported);
        output.appendSlice(allocator, exported) catch return KeyringFormatError.OutOfMemory;

        // Add separator between armored keys
        if (format == .armored) {
            output.append(allocator, '\n') catch return KeyringFormatError.OutOfMemory;
        }
    }

    return output.toOwnedSlice(allocator) catch return KeyringFormatError.OutOfMemory;
}

// ===========================================================================
// Tests
// ===========================================================================

test "KeyringFormat label" {
    try std.testing.expectEqualStrings("OpenPGP (binary)", KeyringFormat.binary.label());
    try std.testing.expectEqualStrings("OpenPGP (armored)", KeyringFormat.armored.label());
    try std.testing.expectEqualStrings("GnuPG keybox (KBX)", KeyringFormat.keybox.label());
    try std.testing.expectEqualStrings("SSH authorized_keys", KeyringFormat.ssh_authorized_keys.label());
}

test "KeyringFormat extension" {
    try std.testing.expectEqualStrings(".gpg", KeyringFormat.binary.extension());
    try std.testing.expectEqualStrings(".asc", KeyringFormat.armored.extension());
    try std.testing.expectEqualStrings(".kbx", KeyringFormat.keybox.extension());
    try std.testing.expectEqualStrings("", KeyringFormat.ssh_authorized_keys.extension());
}

test "detectFormat armored" {
    const data = "-----BEGIN PGP PUBLIC KEY BLOCK-----\ndata\n-----END PGP PUBLIC KEY BLOCK-----";
    try std.testing.expectEqual(KeyringFormat.armored, detectFormat(data));
}

test "detectFormat binary" {
    // New-format public key packet (tag 6): 0xC6
    try std.testing.expectEqual(KeyringFormat.binary, detectFormat(&[_]u8{ 0xC6, 0x01, 0x04 }));
}

test "detectFormat ssh" {
    try std.testing.expectEqual(KeyringFormat.ssh_authorized_keys, detectFormat("ssh-rsa AAAA... user@host"));
    try std.testing.expectEqual(KeyringFormat.ssh_authorized_keys, detectFormat("ssh-ed25519 AAAA... user@host"));
    try std.testing.expectEqual(KeyringFormat.ssh_authorized_keys, detectFormat("ecdsa-sha2-nistp256 AAAA..."));
}

test "detectFormat empty" {
    try std.testing.expectEqual(KeyringFormat.binary, detectFormat(""));
}

test "convertFormat binary to armored" {
    const allocator = std.testing.allocator;
    // Minimal binary data that starts with a public key tag
    const binary = [_]u8{ 0xC6, 0x04, 0x04, 0x00, 0x00, 0x01 };
    const armored_data = try convertFormat(allocator, &binary, .binary, .armored);
    defer allocator.free(armored_data);

    try std.testing.expect(mem.startsWith(u8, armored_data, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));
}

test "convertFormat armored to binary" {
    const allocator = std.testing.allocator;
    // First create armored from binary
    const binary = [_]u8{ 0xC6, 0x04, 0x04, 0x00, 0x00, 0x01 };
    const armored_data = try convertFormat(allocator, &binary, .binary, .armored);
    defer allocator.free(armored_data);

    // Then convert back
    const round_trip = try convertFormat(allocator, armored_data, .armored, .binary);
    defer allocator.free(round_trip);

    try std.testing.expectEqualSlices(u8, &binary, round_trip);
}

test "convertFormat same format" {
    const allocator = std.testing.allocator;
    const data = "test data";
    const result = try convertFormat(allocator, data, .binary, .binary);
    defer allocator.free(result);
    try std.testing.expectEqualStrings(data, result);
}

test "convertFormat unsupported" {
    const allocator = std.testing.allocator;
    const result = convertFormat(allocator, "data", .keybox, .binary);
    try std.testing.expectError(KeyringFormatError.ConversionNotSupported, result);
}

test "importFromAnyFormat binary" {
    const allocator = std.testing.allocator;
    // Public key packet
    const data = [_]u8{ 0xC6, 0x04, 0x04, 0x00, 0x00, 0x01 };
    var result = try importFromAnyFormat(allocator, &data);
    defer result.deinit(allocator);

    try std.testing.expectEqual(KeyringFormat.binary, result.format_detected);
    try std.testing.expectEqual(@as(usize, 1), result.count());
    try std.testing.expect(!result.keys.items[0].is_secret);
}

test "importFromAnyFormat binary secret key" {
    const allocator = std.testing.allocator;
    // Secret key packet (tag 5): 0xC5
    const data = [_]u8{ 0xC5, 0x04, 0x04, 0x00, 0x00, 0x01 };
    var result = try importFromAnyFormat(allocator, &data);
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), result.count());
    try std.testing.expect(result.keys.items[0].is_secret);
    try std.testing.expectEqual(@as(usize, 1), result.secretKeyCount());
    try std.testing.expectEqual(@as(usize, 0), result.publicKeyCount());
}

test "importFromAnyFormat ssh" {
    const allocator = std.testing.allocator;
    const data = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest user@host\nssh-rsa AAAA... user2@host\n";
    var result = try importFromAnyFormat(allocator, data);
    defer result.deinit(allocator);

    try std.testing.expectEqual(KeyringFormat.ssh_authorized_keys, result.format_detected);
    try std.testing.expectEqual(@as(usize, 2), result.count());
}

test "importFromAnyFormat ssh with comments" {
    const allocator = std.testing.allocator;
    const data = "# This is a comment\nssh-ed25519 AAAA... user@host\n# Another comment\n\n";
    var result = try importFromAnyFormat(allocator, data);
    defer result.deinit(allocator);

    try std.testing.expectEqual(KeyringFormat.ssh_authorized_keys, result.format_detected);
    try std.testing.expectEqual(@as(usize, 1), result.count());
}

test "importFromAnyFormat empty" {
    const allocator = std.testing.allocator;
    const result = importFromAnyFormat(allocator, "");
    try std.testing.expectError(KeyringFormatError.InvalidData, result);
}

test "exportInFormat binary" {
    const allocator = std.testing.allocator;
    const data = [_]u8{ 0xC6, 0x04, 0x04, 0x00, 0x00, 0x01 };
    const result = try exportInFormat(allocator, &data, .binary, false);
    defer allocator.free(result);
    try std.testing.expectEqualSlices(u8, &data, result);
}

test "exportInFormat armored public" {
    const allocator = std.testing.allocator;
    const data = [_]u8{ 0xC6, 0x04, 0x04, 0x00, 0x00, 0x01 };
    const result = try exportInFormat(allocator, &data, .armored, false);
    defer allocator.free(result);
    try std.testing.expect(mem.indexOf(u8, result, "PUBLIC KEY") != null);
}

test "exportInFormat armored secret" {
    const allocator = std.testing.allocator;
    const data = [_]u8{ 0xC5, 0x04, 0x04, 0x00, 0x00, 0x01 };
    const result = try exportInFormat(allocator, &data, .armored, true);
    defer allocator.free(result);
    try std.testing.expect(mem.indexOf(u8, result, "PRIVATE KEY") != null);
}

test "exportInFormat keybox unsupported" {
    const allocator = std.testing.allocator;
    const result = exportInFormat(allocator, "data", .keybox, false);
    try std.testing.expectError(KeyringFormatError.ConversionNotSupported, result);
}

test "exportMultipleInFormat empty" {
    const allocator = std.testing.allocator;
    const result = try exportMultipleInFormat(allocator, &.{}, .binary);
    defer allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "ImportedKeys deinit" {
    const allocator = std.testing.allocator;
    var imported = ImportedKeys.init(allocator);
    const kd = try allocator.dupe(u8, "key-bytes");
    try imported.keys.append(allocator, .{ .data = kd, .is_secret = false });
    imported.deinit(allocator);
}

test "KeyData deinit" {
    const allocator = std.testing.allocator;
    const data = try allocator.dupe(u8, "key data");
    const kd = KeyData{ .data = data, .is_secret = false };
    kd.deinit(allocator);
}

test "isSshAuthorizedKeys" {
    try std.testing.expect(isSshAuthorizedKeys("ssh-rsa AAAA..."));
    try std.testing.expect(isSshAuthorizedKeys("ssh-ed25519 AAAA..."));
    try std.testing.expect(isSshAuthorizedKeys("ecdsa-sha2-nistp256 AAAA..."));
    try std.testing.expect(isSshAuthorizedKeys("ssh-dss AAAA..."));
    try std.testing.expect(!isSshAuthorizedKeys("not-ssh data"));
    try std.testing.expect(!isSshAuthorizedKeys(""));
}

test "detectArmorType" {
    try std.testing.expectEqual(armor.ArmorType.public_key, detectArmorType(&[_]u8{0xC6}));
    try std.testing.expectEqual(armor.ArmorType.private_key, detectArmorType(&[_]u8{0xC5}));
    try std.testing.expectEqual(armor.ArmorType.signature, detectArmorType(&[_]u8{0xC2}));
    try std.testing.expectEqual(armor.ArmorType.public_key, detectArmorType(&[_]u8{}));
}
