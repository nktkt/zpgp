// SPDX-License-Identifier: MIT
//! GPG-compatible keyring file I/O.
//!
//! Provides functions for:
//! - Loading keyrings from files (binary or armored)
//! - Saving keyrings to binary files
//! - Importing individual keys into keyrings
//! - Exporting individual keys from keyrings
//! - Merging keyrings together

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const fs = std.fs;

const Key = @import("key.zig").Key;
const Keyring = @import("keyring.zig").Keyring;
const import_export = @import("import_export.zig");
const fingerprint_mod = @import("fingerprint.zig");
const armor = @import("../armor/armor.zig");

/// Result of an import operation.
pub const ImportResult = struct {
    keys_imported: usize,
    keys_unchanged: usize,
    fingerprints: std.ArrayList([20]u8),

    pub fn init(allocator: Allocator) ImportResult {
        _ = allocator;
        return .{
            .keys_imported = 0,
            .keys_unchanged = 0,
            .fingerprints = .empty,
        };
    }

    pub fn deinit(self: *ImportResult, allocator: Allocator) void {
        self.fingerprints.deinit(allocator);
    }
};

/// Result of a merge operation.
pub const MergeResult = struct {
    new_keys: usize,
    updated_keys: usize,
    new_signatures: usize,
};

/// Load a keyring from a file path.
///
/// Supports both binary OpenPGP packet data and ASCII-armored input.
/// If the file starts with "-----BEGIN ", it is treated as armored.
pub fn loadKeyringFromFile(allocator: Allocator, path: []const u8) !Keyring {
    const data = try readFile(allocator, path);
    defer allocator.free(data);

    var kr = Keyring.init(allocator);
    errdefer kr.deinit();

    // Detect armor
    const binary_data = if (data.len > 10 and mem.startsWith(u8, data, "-----BEGIN ")) blk: {
        const result = try armor.decode(allocator, data);
        defer {
            for (result.headers) |hdr| {
                allocator.free(hdr.name);
                allocator.free(hdr.value);
            }
            allocator.free(result.headers);
        }
        // We need to load from the decoded data, but it'll be freed.
        // So we first load, then let it free.
        const loaded = try kr.loadFromBytes(result.data);
        _ = loaded;
        allocator.free(result.data);
        break :blk @as(?[]u8, null);
    } else blk: {
        const loaded = try kr.loadFromBytes(data);
        _ = loaded;
        break :blk @as(?[]u8, null);
    };
    _ = binary_data;

    return kr;
}

/// Save a keyring to a file in binary format.
pub fn saveKeyringToFile(keyring: *const Keyring, path: []const u8, allocator: Allocator) !void {
    const data = try keyring.saveToBytes(allocator);
    defer allocator.free(data);

    const file = try fs.cwd().createFile(path, .{});
    defer file.close();

    try file.writeAll(data);
}

/// Import key data (binary or armored) into an existing keyring.
///
/// Returns information about what was imported: number of new keys,
/// unchanged keys, and their fingerprints.
pub fn importKeyToKeyring(keyring: *Keyring, data: []const u8, allocator: Allocator) !ImportResult {
    var result = ImportResult.init(allocator);
    errdefer result.deinit(allocator);

    // Detect armor
    var binary_data: []const u8 = undefined;
    var decoded_data: ?[]u8 = null;
    var decoded_headers: ?[]armor.Header = null;
    defer {
        if (decoded_data) |d| allocator.free(d);
        if (decoded_headers) |hdrs| {
            for (hdrs) |hdr| {
                allocator.free(hdr.name);
                allocator.free(hdr.value);
            }
            allocator.free(hdrs);
        }
    }

    if (data.len > 10 and mem.startsWith(u8, data, "-----BEGIN ")) {
        const decode_result = try armor.decode(allocator, data);
        decoded_data = decode_result.data;
        decoded_headers = decode_result.headers;
        binary_data = decode_result.data;
    } else {
        binary_data = data;
    }

    // Try to import keys from the binary data
    var offset: usize = 0;
    while (offset < binary_data.len) {
        const remaining = binary_data[offset..];
        const key = import_export.importPublicKey(allocator, remaining) catch break;

        const fp = key.fingerprint();

        // Calculate bytes consumed by re-exporting BEFORE potentially deiniting
        const exported = import_export.exportPublicKey(allocator, &key) catch {
            var mutable_key = key;
            mutable_key.deinit(allocator);
            break;
        };
        const consumed = exported.len;
        allocator.free(exported);

        // Check if this key already exists
        if (keyring.findByFingerprint(fp) != null) {
            // Key already exists
            result.keys_unchanged += 1;
            var mutable_key = key;
            mutable_key.deinit(allocator);
        } else {
            // New key
            try result.fingerprints.append(allocator, fp);
            try keyring.addKey(key);
            result.keys_imported += 1;
        }

        offset += consumed;
    }

    return result;
}

/// Export a key from a keyring by its fingerprint.
///
/// Returns the key data as either ASCII-armored or binary format.
/// Returns null if the key is not found.
pub fn exportKeyFromKeyring(
    keyring: *const Keyring,
    fp: [20]u8,
    do_armor: bool,
    allocator: Allocator,
) !?[]u8 {
    const key = keyring.findByFingerprint(fp) orelse return null;

    if (do_armor) {
        const data = try import_export.exportPublicKeyArmored(allocator, key);
        return data;
    } else {
        const data = try import_export.exportPublicKey(allocator, key);
        return data;
    }
}

/// Merge two keyrings.
///
/// For each key in `src`:
/// - If the key does not exist in `dst`, it is added.
/// - If the key already exists in `dst`, new signatures are merged.
///   (Currently simplified: only adds entirely new keys.)
pub fn mergeKeyrings(dst: *Keyring, src: *const Keyring, allocator: Allocator) !MergeResult {
    var result = MergeResult{
        .new_keys = 0,
        .updated_keys = 0,
        .new_signatures = 0,
    };

    for (src.keys.items) |*src_key| {
        const src_fp = src_key.fingerprint();

        if (dst.findByFingerprint(src_fp) != null) {
            // Key already exists - in a full implementation we'd merge signatures.
            // For now, count as updated (but don't actually modify).
            result.updated_keys += 1;
        } else {
            // Export and re-import the key to create a copy
            const exported = try import_export.exportPublicKey(allocator, src_key);
            defer allocator.free(exported);

            const key_copy = try import_export.importPublicKey(allocator, exported);
            try dst.addKey(key_copy);
            result.new_keys += 1;
        }
    }

    return result;
}

/// Read an entire file into memory.
fn readFile(allocator: Allocator, path: []const u8) ![]u8 {
    return fs.cwd().readFileAlloc(allocator, path, 10 * 1024 * 1024); // 10 MB limit
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const PublicKeyPacket = @import("../packets/public_key.zig").PublicKeyPacket;
const UserIdPacket = @import("../packets/user_id.zig").UserIdPacket;

fn createTestKey(allocator: Allocator, email: []const u8, creation_time: u32) !Key {
    var body: [12]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], creation_time, .big);
    body[5] = 1; // RSA
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xFF;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;

    const pk = try PublicKeyPacket.parse(allocator, &body, false);
    errdefer pk.deinit(allocator);

    var key = Key.init(pk);
    errdefer key.deinit(allocator);

    const uid = try UserIdPacket.parse(allocator, email);
    try key.addUserId(allocator, .{
        .user_id = uid,
        .self_signature = null,
        .certifications = .empty,
    });

    return key;
}

test "ImportResult init and deinit" {
    const allocator = std.testing.allocator;

    var result = ImportResult.init(allocator);
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), result.keys_imported);
    try std.testing.expectEqual(@as(usize, 0), result.keys_unchanged);
}

test "MergeResult fields" {
    const result = MergeResult{
        .new_keys = 3,
        .updated_keys = 1,
        .new_signatures = 5,
    };
    try std.testing.expectEqual(@as(usize, 3), result.new_keys);
}

test "importKeyToKeyring adds new key" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    // Create and export a test key
    var key = try createTestKey(allocator, "Alice <alice@test.com>", 1000);
    defer key.deinit(allocator);

    const exported = try import_export.exportPublicKey(allocator, &key);
    defer allocator.free(exported);

    var result = try importKeyToKeyring(&kr, exported, allocator);
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), result.keys_imported);
    try std.testing.expectEqual(@as(usize, 0), result.keys_unchanged);
    try std.testing.expectEqual(@as(usize, 1), kr.count());
}

test "importKeyToKeyring detects duplicate" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    var key = try createTestKey(allocator, "Bob <bob@test.com>", 2000);
    defer key.deinit(allocator);

    const exported = try import_export.exportPublicKey(allocator, &key);
    defer allocator.free(exported);

    // Import once
    var result1 = try importKeyToKeyring(&kr, exported, allocator);
    defer result1.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), result1.keys_imported);

    // Import again (same key)
    var result2 = try importKeyToKeyring(&kr, exported, allocator);
    defer result2.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), result2.keys_imported);
    try std.testing.expectEqual(@as(usize, 1), result2.keys_unchanged);

    // Only one key in keyring
    try std.testing.expectEqual(@as(usize, 1), kr.count());
}

test "importKeyToKeyring armored input" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    var key = try createTestKey(allocator, "Carol <carol@test.com>", 3000);
    defer key.deinit(allocator);

    const armored = try import_export.exportPublicKeyArmored(allocator, &key);
    defer allocator.free(armored);

    var result = try importKeyToKeyring(&kr, armored, allocator);
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), result.keys_imported);
    try std.testing.expectEqual(@as(usize, 1), kr.count());
}

test "exportKeyFromKeyring found" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    const key = try createTestKey(allocator, "Dave <dave@test.com>", 4000);
    const fp = key.fingerprint();
    try kr.addKey(key);

    // Export as binary
    const data = try exportKeyFromKeyring(&kr, fp, false, allocator);
    try std.testing.expect(data != null);
    defer allocator.free(data.?);
    try std.testing.expect(data.?.len > 0);
}

test "exportKeyFromKeyring armored" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    const key = try createTestKey(allocator, "Eve <eve@test.com>", 5000);
    const fp = key.fingerprint();
    try kr.addKey(key);

    const data = try exportKeyFromKeyring(&kr, fp, true, allocator);
    try std.testing.expect(data != null);
    defer allocator.free(data.?);

    try std.testing.expect(mem.startsWith(u8, data.?, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));
}

test "exportKeyFromKeyring not found" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    const fake_fp = [_]u8{0xFF} ** 20;
    const data = try exportKeyFromKeyring(&kr, fake_fp, false, allocator);
    try std.testing.expect(data == null);
}

test "mergeKeyrings new keys" {
    const allocator = std.testing.allocator;

    var dst = Keyring.init(allocator);
    defer dst.deinit();

    var src = Keyring.init(allocator);
    defer src.deinit();

    const key1 = try createTestKey(allocator, "A <a@test.com>", 100);
    try dst.addKey(key1);

    const key2 = try createTestKey(allocator, "B <b@test.com>", 200);
    try src.addKey(key2);

    const result = try mergeKeyrings(&dst, &src, allocator);

    try std.testing.expectEqual(@as(usize, 1), result.new_keys);
    try std.testing.expectEqual(@as(usize, 0), result.updated_keys);
    try std.testing.expectEqual(@as(usize, 2), dst.count());
}

test "mergeKeyrings duplicate keys" {
    const allocator = std.testing.allocator;

    var dst = Keyring.init(allocator);
    defer dst.deinit();

    var src = Keyring.init(allocator);
    defer src.deinit();

    const key1 = try createTestKey(allocator, "Same <same@test.com>", 100);
    const fp1 = key1.fingerprint();
    try dst.addKey(key1);

    // Create same key for src
    const key2 = try createTestKey(allocator, "Same <same@test.com>", 100);
    const fp2 = key2.fingerprint();
    try src.addKey(key2);

    try std.testing.expectEqualSlices(u8, &fp1, &fp2);

    const result = try mergeKeyrings(&dst, &src, allocator);

    try std.testing.expectEqual(@as(usize, 0), result.new_keys);
    try std.testing.expectEqual(@as(usize, 1), result.updated_keys);
    try std.testing.expectEqual(@as(usize, 1), dst.count());
}

test "mergeKeyrings empty src" {
    const allocator = std.testing.allocator;

    var dst = Keyring.init(allocator);
    defer dst.deinit();

    var src = Keyring.init(allocator);
    defer src.deinit();

    const key = try createTestKey(allocator, "Only <only@test.com>", 100);
    try dst.addKey(key);

    const result = try mergeKeyrings(&dst, &src, allocator);

    try std.testing.expectEqual(@as(usize, 0), result.new_keys);
    try std.testing.expectEqual(@as(usize, 0), result.updated_keys);
    try std.testing.expectEqual(@as(usize, 1), dst.count());
}

test "mergeKeyrings empty dst" {
    const allocator = std.testing.allocator;

    var dst = Keyring.init(allocator);
    defer dst.deinit();

    var src = Keyring.init(allocator);
    defer src.deinit();

    const key = try createTestKey(allocator, "Src <src@test.com>", 100);
    try src.addKey(key);

    const result = try mergeKeyrings(&dst, &src, allocator);

    try std.testing.expectEqual(@as(usize, 1), result.new_keys);
    try std.testing.expectEqual(@as(usize, 1), dst.count());
}

test "ImportResult tracks fingerprints" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    var key = try createTestKey(allocator, "Track <track@test.com>", 7000);
    const expected_fp = key.fingerprint();
    defer key.deinit(allocator);

    const exported = try import_export.exportPublicKey(allocator, &key);
    defer allocator.free(exported);

    var result = try importKeyToKeyring(&kr, exported, allocator);
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), result.fingerprints.items.len);
    try std.testing.expectEqualSlices(u8, &expected_fp, &result.fingerprints.items[0]);
}
