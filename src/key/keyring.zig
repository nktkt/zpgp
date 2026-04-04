// SPDX-License-Identifier: MIT
//! Keyring management for OpenPGP keys.
//!
//! A Keyring holds a collection of Keys and provides lookup by
//! key ID, fingerprint, or email address.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const Key = @import("key.zig").Key;
const import_export = @import("import_export.zig");
const fingerprint_mod = @import("fingerprint.zig");

/// A collection of OpenPGP keys with lookup capabilities.
pub const Keyring = struct {
    allocator: Allocator,
    keys: std.ArrayList(Key),

    /// Initialize an empty keyring.
    pub fn init(allocator: Allocator) Keyring {
        return .{
            .allocator = allocator,
            .keys = .empty,
        };
    }

    /// Free all keys and memory associated with this keyring.
    pub fn deinit(self: *Keyring) void {
        for (self.keys.items) |*k| {
            k.deinit(self.allocator);
        }
        self.keys.deinit(self.allocator);
    }

    /// Add a key to the keyring. The keyring takes ownership.
    pub fn addKey(self: *Keyring, key: Key) !void {
        try self.keys.append(self.allocator, key);
    }

    /// Find a key by its 8-byte Key ID.
    ///
    /// Searches both primary keys and subkeys.
    pub fn findByKeyId(self: *const Keyring, kid: [8]u8) ?*const Key {
        for (self.keys.items) |*key| {
            // Check primary key
            const pk_kid = key.keyId();
            if (mem.eql(u8, &pk_kid, &kid)) return key;

            // Check subkeys
            for (key.subkeys.items) |*sub| {
                const sub_kid = fingerprint_mod.calculateV4KeyId(sub.key.raw_body);
                if (mem.eql(u8, &sub_kid, &kid)) return key;
            }
        }
        return null;
    }

    /// Find a key by its 20-byte fingerprint.
    ///
    /// Searches both primary keys and subkeys.
    pub fn findByFingerprint(self: *const Keyring, fp: [20]u8) ?*const Key {
        for (self.keys.items) |*key| {
            // Check primary key
            const pk_fp = key.fingerprint();
            if (mem.eql(u8, &pk_fp, &fp)) return key;

            // Check subkeys
            for (key.subkeys.items) |*sub| {
                const sub_fp = fingerprint_mod.calculateV4Fingerprint(sub.key.raw_body);
                if (mem.eql(u8, &sub_fp, &fp)) return key;
            }
        }
        return null;
    }

    /// Find all keys whose user IDs contain the given email address.
    ///
    /// Returns a slice of pointers to matching keys. The caller must free the
    /// returned slice (but not the Key pointers themselves).
    pub fn findByEmail(self: *const Keyring, email: []const u8, allocator: Allocator) ![]const *const Key {
        var matches: std.ArrayList(*const Key) = .empty;
        errdefer matches.deinit(allocator);

        for (self.keys.items) |*key| {
            for (key.user_ids.items) |uid_binding| {
                if (containsEmail(uid_binding.user_id.id, email)) {
                    try matches.append(allocator, key);
                    break; // Don't add the same key twice
                }
            }
        }

        return matches.toOwnedSlice(allocator);
    }

    /// Remove a key by its fingerprint. Returns true if a key was removed.
    pub fn removeByFingerprint(self: *Keyring, fp: [20]u8) bool {
        for (self.keys.items, 0..) |*key, i| {
            const pk_fp = key.fingerprint();
            if (mem.eql(u8, &pk_fp, &fp)) {
                key.deinit(self.allocator);
                _ = self.keys.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Return the number of keys in the keyring.
    pub fn count(self: *const Keyring) usize {
        return self.keys.items.len;
    }

    /// Load keys from binary packet data (may contain multiple transferable keys).
    ///
    /// Returns the number of keys successfully loaded.
    pub fn loadFromBytes(self: *Keyring, data: []const u8) !usize {
        var loaded: usize = 0;
        var offset: usize = 0;

        while (offset < data.len) {
            // Try to import a key starting at the current offset
            const remaining = data[offset..];
            const key = import_export.importPublicKey(self.allocator, remaining) catch {
                // If we can't parse more keys, stop
                break;
            };

            // Calculate how many bytes were consumed by re-exporting
            // and comparing. This is a simple approach; a more efficient
            // method would track the parser offset.
            const exported = import_export.exportPublicKey(self.allocator, &key) catch {
                var mutable_key = key;
                mutable_key.deinit(self.allocator);
                break;
            };
            defer self.allocator.free(exported);

            try self.addKey(key);
            loaded += 1;
            offset += exported.len;
        }

        return loaded;
    }

    /// Save all keys to binary packet data.
    pub fn saveToBytes(self: *const Keyring, allocator: Allocator) ![]u8 {
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(allocator);

        for (self.keys.items) |*key| {
            const key_data = try import_export.exportPublicKey(allocator, key);
            defer allocator.free(key_data);
            try output.appendSlice(allocator, key_data);
        }

        return try output.toOwnedSlice(allocator);
    }
};

/// Check if a user ID string contains an email address.
/// Handles the common format "Name <email@example.com>".
fn containsEmail(user_id: []const u8, email: []const u8) bool {
    // Check for <email> format
    if (mem.indexOf(u8, user_id, email)) |_| {
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const PublicKeyPacket = @import("../packets/public_key.zig").PublicKeyPacket;
const UserIdPacket = @import("../packets/user_id.zig").UserIdPacket;

fn buildTestKeyBody() [12]u8 {
    var body: [12]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], 1000, .big);
    body[5] = 1; // RSA
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xFF;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;
    return body;
}

fn createTestKey(allocator: Allocator, email: []const u8, creation_time: u32) !Key {
    var body: [12]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], creation_time, .big);
    body[5] = 1;
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

test "Keyring init and deinit" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    try std.testing.expectEqual(@as(usize, 0), kr.count());
}

test "Keyring addKey and count" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    const key = try createTestKey(allocator, "Alice <alice@example.com>", 1000);
    try kr.addKey(key);

    try std.testing.expectEqual(@as(usize, 1), kr.count());
}

test "Keyring findByKeyId" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    const key = try createTestKey(allocator, "Alice <alice@example.com>", 1000);
    const kid = key.keyId();
    try kr.addKey(key);

    const found = kr.findByKeyId(kid);
    try std.testing.expect(found != null);
    try std.testing.expectEqualStrings("Alice <alice@example.com>", found.?.primaryUserId().?);
}

test "Keyring findByKeyId not found" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    const key = try createTestKey(allocator, "Alice <alice@example.com>", 1000);
    try kr.addKey(key);

    const fake_kid = [_]u8{0} ** 8;
    const found = kr.findByKeyId(fake_kid);
    try std.testing.expect(found == null);
}

test "Keyring findByFingerprint" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    const key = try createTestKey(allocator, "Bob <bob@example.com>", 2000);
    const fp = key.fingerprint();
    try kr.addKey(key);

    const found = kr.findByFingerprint(fp);
    try std.testing.expect(found != null);
    try std.testing.expectEqualStrings("Bob <bob@example.com>", found.?.primaryUserId().?);
}

test "Keyring findByFingerprint not found" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    const key = try createTestKey(allocator, "Bob <bob@example.com>", 2000);
    try kr.addKey(key);

    const fake_fp = [_]u8{0} ** 20;
    const found = kr.findByFingerprint(fake_fp);
    try std.testing.expect(found == null);
}

test "Keyring findByEmail" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    const key1 = try createTestKey(allocator, "Alice <alice@example.com>", 1000);
    try kr.addKey(key1);

    const key2 = try createTestKey(allocator, "Bob <bob@example.com>", 2000);
    try kr.addKey(key2);

    const key3 = try createTestKey(allocator, "Alice (work) <alice@work.com>", 3000);
    try kr.addKey(key3);

    // Search for alice
    const alice_keys = try kr.findByEmail("alice@example.com", allocator);
    defer allocator.free(alice_keys);
    try std.testing.expectEqual(@as(usize, 1), alice_keys.len);

    // Search for bob
    const bob_keys = try kr.findByEmail("bob@example.com", allocator);
    defer allocator.free(bob_keys);
    try std.testing.expectEqual(@as(usize, 1), bob_keys.len);

    // Search for nonexistent
    const nobody_keys = try kr.findByEmail("nobody@example.com", allocator);
    defer allocator.free(nobody_keys);
    try std.testing.expectEqual(@as(usize, 0), nobody_keys.len);
}

test "Keyring removeByFingerprint" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    const key = try createTestKey(allocator, "Carol <carol@example.com>", 4000);
    const fp = key.fingerprint();
    try kr.addKey(key);

    try std.testing.expectEqual(@as(usize, 1), kr.count());

    const removed = kr.removeByFingerprint(fp);
    try std.testing.expect(removed);
    try std.testing.expectEqual(@as(usize, 0), kr.count());
}

test "Keyring removeByFingerprint not found" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    const key = try createTestKey(allocator, "Carol <carol@example.com>", 4000);
    try kr.addKey(key);

    const fake_fp = [_]u8{0xFF} ** 20;
    const removed = kr.removeByFingerprint(fake_fp);
    try std.testing.expect(!removed);
    try std.testing.expectEqual(@as(usize, 1), kr.count());
}

test "Keyring multiple keys" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    // Add several keys with different creation times (different fingerprints)
    const key1 = try createTestKey(allocator, "User1 <user1@test.com>", 100);
    const key2 = try createTestKey(allocator, "User2 <user2@test.com>", 200);
    const key3 = try createTestKey(allocator, "User3 <user3@test.com>", 300);

    try kr.addKey(key1);
    try kr.addKey(key2);
    try kr.addKey(key3);

    try std.testing.expectEqual(@as(usize, 3), kr.count());

    // Each can be found by its key ID
    for (kr.keys.items) |*key| {
        const kid = key.keyId();
        const found = kr.findByKeyId(kid);
        try std.testing.expect(found != null);
    }
}

test "Keyring saveToBytes and loadFromBytes round-trip" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    const key = try createTestKey(allocator, "Test <test@example.com>", 5000);
    try kr.addKey(key);

    // Save
    const saved = try kr.saveToBytes(allocator);
    defer allocator.free(saved);

    try std.testing.expect(saved.len > 0);

    // Load into new keyring
    var kr2 = Keyring.init(allocator);
    defer kr2.deinit();

    const loaded = try kr2.loadFromBytes(saved);
    try std.testing.expectEqual(@as(usize, 1), loaded);
    try std.testing.expectEqual(@as(usize, 1), kr2.count());
    try std.testing.expectEqualStrings("Test <test@example.com>", kr2.keys.items[0].primaryUserId().?);
}

test "containsEmail" {
    try std.testing.expect(containsEmail("Alice <alice@example.com>", "alice@example.com"));
    try std.testing.expect(containsEmail("alice@example.com", "alice@example.com"));
    try std.testing.expect(!containsEmail("Alice <alice@example.com>", "bob@example.com"));
    try std.testing.expect(containsEmail("Alice (comment) <alice@example.com>", "alice@example.com"));
}
