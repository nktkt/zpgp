// SPDX-License-Identifier: MIT
//! Trust path computation for the PGP Web of Trust.
//!
//! Implements graph traversal algorithms to find trust paths between keys
//! in the Web of Trust. This is the foundation for determining key validity
//! based on certification chains.
//!
//! The Web of Trust forms a directed graph where:
//!   - Nodes are OpenPGP keys (identified by fingerprint)
//!   - Edges are certification signatures (key A certifies key B)
//!   - Edge weights are the certifier's trust level
//!
//! Trust path computation follows RFC 4880 Section 5.2.1 and the PGP
//! trust model with configurable parameters for marginal and complete
//! trust requirements.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const trust_model = @import("trust_model.zig");
const TrustLevel = trust_model.TrustLevel;
const Validity = trust_model.Validity;
const TrustDB = trust_model.TrustDB;
const Keyring = @import("keyring.zig").Keyring;
const Key = @import("key.zig").Key;

// ---------------------------------------------------------------------------
// Trust Path types
// ---------------------------------------------------------------------------

/// A single node in a trust path.
pub const PathNode = struct {
    /// Fingerprint of the key at this node.
    key_fingerprint: [20]u8,
    /// The user ID that was certified (if applicable).
    user_id: ?[]const u8,
    /// The trust level of this key's owner.
    trust_level: TrustLevel,
    /// The type of signature connecting to the next node (0x10-0x13).
    signature_type: u8,
};

/// A complete trust path from a trusted root to a target key.
pub const TrustPath = struct {
    /// The nodes in the path, from root to target.
    path: std.ArrayList(PathNode),
    /// Whether this path is valid (all links verified).
    valid: bool,
    /// The effective trust amount for this path (0-120).
    /// 120 = full trust, 60 = marginal, 0 = no trust.
    trust_amount: u8,
    /// The depth of this path (number of intermediary certifiers).
    depth: u32,

    /// Initialize an empty trust path.
    pub fn init(allocator: Allocator) TrustPath {
        return .{
            .path = std.ArrayList(PathNode).init(allocator),
            .valid = false,
            .trust_amount = 0,
            .depth = 0,
        };
    }

    /// Free all memory associated with this trust path.
    pub fn deinit(self: *TrustPath) void {
        self.path.deinit();
    }

    /// Get the root (starting) node of the path.
    pub fn root(self: *const TrustPath) ?PathNode {
        if (self.path.items.len == 0) return null;
        return self.path.items[0];
    }

    /// Get the target (ending) node of the path.
    pub fn target(self: *const TrustPath) ?PathNode {
        if (self.path.items.len == 0) return null;
        return self.path.items[self.path.items.len - 1];
    }

    /// Get the number of nodes in the path.
    pub fn length(self: *const TrustPath) usize {
        return self.path.items.len;
    }

    /// Check if the path starts from an ultimately trusted key.
    pub fn startsFromUltimate(self: *const TrustPath) bool {
        if (self.root()) |r| {
            return r.trust_level == .ultimate;
        }
        return false;
    }

    /// Calculate the minimum trust level along the path.
    pub fn minimumTrust(self: *const TrustPath) TrustLevel {
        var min_trust = TrustLevel.ultimate;
        for (self.path.items) |node| {
            if (@intFromEnum(node.trust_level) < @intFromEnum(min_trust)) {
                min_trust = node.trust_level;
            }
        }
        return min_trust;
    }

    /// Add a node to the path.
    pub fn addNode(self: *TrustPath, node: PathNode) !void {
        try self.path.append(node);
        self.depth = if (self.path.items.len > 2)
            @intCast(self.path.items.len - 2)
        else
            0;
    }
};

// ---------------------------------------------------------------------------
// BFS-based trust path finder
// ---------------------------------------------------------------------------

/// Internal BFS queue entry.
const BfsEntry = struct {
    fingerprint: [20]u8,
    parent_index: ?usize, // Index into visited array
    trust_level: TrustLevel,
    sig_type: u8,
    depth: u32,
};

/// Find the shortest trust path between two keys.
///
/// Uses breadth-first search on the certification graph. The path goes
/// from `from_fp` (typically an ultimately trusted key) to `to_fp`.
///
/// Returns null if no path exists within the maximum depth.
pub fn findTrustPath(
    allocator: Allocator,
    from_fp: [20]u8,
    to_fp: [20]u8,
    keyring: *const Keyring,
    trust_db: *const TrustDB,
    max_depth: u32,
) !?TrustPath {
    // Quick check: same key
    if (mem.eql(u8, &from_fp, &to_fp)) {
        var path = TrustPath.init(allocator);
        errdefer path.deinit();

        const trust_level = trust_db.getOwnerTrust(from_fp);
        try path.addNode(.{
            .key_fingerprint = from_fp,
            .user_id = null,
            .trust_level = trust_level,
            .signature_type = 0x13, // Positive certification
        });
        path.valid = true;
        path.trust_amount = trustLevelToAmount(trust_level);
        return path;
    }

    // BFS
    var visited = std.ArrayList(BfsEntry).init(allocator);
    defer visited.deinit();

    var queue = std.ArrayList(usize).init(allocator);
    defer queue.deinit();

    // Start with the source key
    const from_trust = trust_db.getOwnerTrust(from_fp);
    try visited.append(.{
        .fingerprint = from_fp,
        .parent_index = null,
        .trust_level = from_trust,
        .sig_type = 0x13,
        .depth = 0,
    });
    try queue.append(0);

    // Track visited fingerprints to avoid cycles
    var seen = std.AutoHashMap([20]u8, void).init(allocator);
    defer seen.deinit();
    try seen.put(from_fp, {});

    var found_index: ?usize = null;

    while (queue.items.len > 0) {
        const current_idx = queue.orderedRemove(0);
        const current = visited.items[current_idx];

        if (current.depth >= max_depth) continue;

        // Find all keys certified by the current key
        const certified_keys = try findCertifiedKeys(allocator, current.fingerprint, keyring);
        defer allocator.free(certified_keys);

        for (certified_keys) |cert| {
            if (seen.contains(cert.target_fp)) continue;
            try seen.put(cert.target_fp, {});

            const target_trust = trust_db.getOwnerTrust(cert.target_fp);

            // Only follow paths through trusted keys
            // (unknown/never trust keys can be endpoints but not intermediaries)
            const can_extend = (target_trust == .marginal or
                target_trust == .full or
                target_trust == .ultimate);

            const new_idx = visited.items.len;
            try visited.append(.{
                .fingerprint = cert.target_fp,
                .parent_index = current_idx,
                .trust_level = target_trust,
                .sig_type = cert.sig_type,
                .depth = current.depth + 1,
            });

            // Check if we reached the target
            if (mem.eql(u8, &cert.target_fp, &to_fp)) {
                found_index = new_idx;
                break;
            }

            // Only enqueue if this key can certify others
            if (can_extend and current.depth + 1 < max_depth) {
                try queue.append(new_idx);
            }
        }

        if (found_index != null) break;
    }

    if (found_index == null) return null;

    // Reconstruct path
    var path = TrustPath.init(allocator);
    errdefer path.deinit();

    // Collect path indices in reverse
    var path_indices = std.ArrayList(usize).init(allocator);
    defer path_indices.deinit();

    var idx: ?usize = found_index;
    while (idx) |i| {
        try path_indices.append(i);
        idx = visited.items[i].parent_index;
    }

    // Reverse and build path
    var min_amount: u8 = 120;
    var i: usize = path_indices.items.len;
    while (i > 0) {
        i -= 1;
        const entry = visited.items[path_indices.items[i]];
        const amount = trustLevelToAmount(entry.trust_level);
        if (amount < min_amount) min_amount = amount;

        try path.addNode(.{
            .key_fingerprint = entry.fingerprint,
            .user_id = null,
            .trust_level = entry.trust_level,
            .signature_type = entry.sig_type,
        });
    }

    path.valid = true;
    path.trust_amount = min_amount;
    return path;
}

/// Compute all valid trust paths to a target key.
///
/// Finds all paths from any ultimately trusted key to the target,
/// up to the maximum depth. This is used to aggregate trust from
/// multiple independent certification paths.
pub fn computeAllPaths(
    allocator: Allocator,
    target_fp: [20]u8,
    keyring: *const Keyring,
    trust_db: *const TrustDB,
    max_depth: u32,
) ![]TrustPath {
    var paths = std.ArrayList(TrustPath).init(allocator);
    errdefer {
        for (paths.items) |*p| p.deinit();
        paths.deinit();
    }

    // Find all ultimately trusted keys as starting points
    const ultimate_keys = try findUltimateTrustKeys(allocator, keyring, trust_db);
    defer allocator.free(ultimate_keys);

    // Find paths from each ultimate key to the target
    for (ultimate_keys) |ult_fp| {
        if (findTrustPath(allocator, ult_fp, target_fp, keyring, trust_db, max_depth)) |maybe_path| {
            if (maybe_path) |p| {
                var path = p;
                if (path.valid) {
                    try paths.append(path);
                } else {
                    path.deinit();
                }
            }
        } else |_| {
            continue;
        }
    }

    return paths.toOwnedSlice();
}

/// Calculate effective validity from multiple trust paths.
///
/// Implements the classic PGP trust model:
///   - If any path provides full trust (from a fully trusted certifier),
///     the key is fully valid.
///   - If enough paths provide marginal trust (from marginally trusted
///     certifiers), the key is marginally valid.
///   - Otherwise, validity is unknown.
pub fn calculateEffectiveValidity(
    paths: []const TrustPath,
    marginals_needed: u32,
    completes_needed: u32,
) Validity {
    if (paths.len == 0) return .unknown;

    var complete_count: u32 = 0;
    var marginal_count: u32 = 0;

    for (paths) |path| {
        if (!path.valid) continue;

        // Check the trust amount of the path
        if (path.trust_amount >= 120) {
            complete_count += 1;
        } else if (path.trust_amount >= 60) {
            marginal_count += 1;
        }

        // Also check if path starts from ultimate trust
        if (path.startsFromUltimate()) {
            return .ultimate;
        }
    }

    if (complete_count >= completes_needed) return .full;
    if (marginal_count >= marginals_needed) return .marginal;

    return .unknown;
}

// ---------------------------------------------------------------------------
// Graph edge discovery
// ---------------------------------------------------------------------------

/// A certification edge in the trust graph.
const CertificationEdge = struct {
    target_fp: [20]u8,
    sig_type: u8,
};

/// Find all keys that have been certified by the given key.
///
/// Scans the keyring for certification signatures (0x10-0x13)
/// issued by the specified key.
fn findCertifiedKeys(
    allocator: Allocator,
    certifier_fp: [20]u8,
    keyring: *const Keyring,
) ![]CertificationEdge {
    var edges = std.ArrayList(CertificationEdge).init(allocator);
    errdefer edges.deinit();

    // Scan all keys in the keyring
    for (keyring.keys.items) |*key| {
        const key_fp = key.fingerprint();

        // Skip the certifier's own key
        if (mem.eql(u8, &key_fp, &certifier_fp)) continue;

        // Check each user ID for certifications from this certifier
        for (key.user_ids.items) |uid_binding| {
            for (uid_binding.certifications.items) |cert_sig| {
                // Check if this is a certification signature
                if (cert_sig.sig_type < 0x10 or cert_sig.sig_type > 0x13) continue;

                // Check if the certifier matches
                if (isCertifiedBy(&cert_sig, certifier_fp, keyring)) {
                    try edges.append(.{
                        .target_fp = key_fp,
                        .sig_type = cert_sig.sig_type,
                    });
                    break; // One edge per key is enough
                }
            }
        }
    }

    return edges.toOwnedSlice();
}

/// Check if a signature was made by a key with the given fingerprint.
fn isCertifiedBy(
    sig: *const @import("../packets/signature.zig").SignaturePacket,
    certifier_fp: [20]u8,
    keyring: *const Keyring,
) bool {
    // Try issuer fingerprint in hashed subpackets
    if (findIssuerFingerprintInSubpackets(sig.hashed_subpacket_data)) |fp| {
        if (mem.eql(u8, &fp, &certifier_fp)) return true;
    }

    // Try issuer fingerprint in unhashed subpackets
    if (findIssuerFingerprintInSubpackets(sig.unhashed_subpacket_data)) |fp| {
        if (mem.eql(u8, &fp, &certifier_fp)) return true;
    }

    // Try issuer key ID
    if (findIssuerKeyIdInSubpackets(sig.hashed_subpacket_data)) |kid| {
        if (keyring.findByKeyId(kid)) |key| {
            const key_fp = key.fingerprint();
            if (mem.eql(u8, &key_fp, &certifier_fp)) return true;
        }
    }

    if (findIssuerKeyIdInSubpackets(sig.unhashed_subpacket_data)) |kid| {
        if (keyring.findByKeyId(kid)) |key| {
            const key_fp = key.fingerprint();
            if (mem.eql(u8, &key_fp, &certifier_fp)) return true;
        }
    }

    return false;
}

/// Scan raw subpacket data for issuer fingerprint (tag 33).
fn findIssuerFingerprintInSubpackets(data: []const u8) ?[20]u8 {
    var offset: usize = 0;
    while (offset < data.len) {
        const first = data[offset];
        offset += 1;

        var body_len: usize = undefined;
        if (first < 192) {
            body_len = @as(usize, first);
        } else if (first <= 254) {
            if (offset >= data.len) return null;
            body_len = (@as(usize, first) - 192) * 256 + @as(usize, data[offset]) + 192;
            offset += 1;
        } else {
            if (offset + 4 > data.len) return null;
            body_len = mem.readInt(u32, data[offset..][0..4], .big);
            offset += 4;
        }

        if (body_len == 0 or offset + body_len > data.len) return null;

        const tag_val = data[offset] & 0x7F;
        if (tag_val == 33 and body_len >= 22) {
            return data[offset + 2 .. offset + 22][0..20].*;
        }

        offset += body_len;
    }
    return null;
}

/// Scan raw subpacket data for issuer key ID (tag 16).
fn findIssuerKeyIdInSubpackets(data: []const u8) ?[8]u8 {
    var offset: usize = 0;
    while (offset < data.len) {
        const first = data[offset];
        offset += 1;

        var body_len: usize = undefined;
        if (first < 192) {
            body_len = @as(usize, first);
        } else if (first <= 254) {
            if (offset >= data.len) return null;
            body_len = (@as(usize, first) - 192) * 256 + @as(usize, data[offset]) + 192;
            offset += 1;
        } else {
            if (offset + 4 > data.len) return null;
            body_len = mem.readInt(u32, data[offset..][0..4], .big);
            offset += 4;
        }

        if (body_len == 0 or offset + body_len > data.len) return null;

        const tag_val = data[offset] & 0x7F;
        if (tag_val == 16 and body_len == 9) {
            return data[offset + 1 .. offset + 9][0..8].*;
        }

        offset += body_len;
    }
    return null;
}

/// Find all keys with ultimate trust in the keyring.
fn findUltimateTrustKeys(
    allocator: Allocator,
    keyring: *const Keyring,
    trust_db: *const TrustDB,
) ![][20]u8 {
    var result = std.ArrayList([20]u8).init(allocator);
    errdefer result.deinit();

    for (keyring.keys.items) |*key| {
        const fp = key.fingerprint();
        if (trust_db.getOwnerTrust(fp) == .ultimate) {
            try result.append(fp);
        }
    }

    return result.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Trust level / amount conversion
// ---------------------------------------------------------------------------

/// Convert a trust level to a numeric trust amount (0-120).
///
/// These values follow the GnuPG convention:
///   - Unknown/Never: 0
///   - Marginal: 60
///   - Full: 120
///   - Ultimate: 120
pub fn trustLevelToAmount(level: TrustLevel) u8 {
    return switch (level) {
        .unknown => 0,
        .never => 0,
        .marginal => 60,
        .full => 120,
        .ultimate => 120,
    };
}

/// Convert a numeric trust amount to a trust level.
pub fn amountToTrustLevel(amount: u8) TrustLevel {
    if (amount >= 120) return .full;
    if (amount >= 60) return .marginal;
    return .unknown;
}

/// Default: 3 marginal certifications needed for marginal validity.
pub const DEFAULT_MARGINALS_NEEDED: u32 = 3;
/// Default: 1 complete certification needed for full validity.
pub const DEFAULT_COMPLETES_NEEDED: u32 = 1;
/// Default maximum certification chain depth.
pub const DEFAULT_MAX_DEPTH: u32 = 5;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const PublicKeyPacket = @import("../packets/public_key.zig").PublicKeyPacket;
const UserIdPacket = @import("../packets/user_id.zig").UserIdPacket;

fn buildTestKeyBody(creation_time: u32) [12]u8 {
    var body: [12]u8 = undefined;
    body[0] = 4;
    mem.writeInt(u32, body[1..5], creation_time, .big);
    body[5] = 1; // RSA
    mem.writeInt(u16, body[6..8], 8, .big);
    body[8] = 0xFF;
    mem.writeInt(u16, body[9..11], 8, .big);
    body[11] = 0x03;
    return body;
}

fn createTestKey(allocator: Allocator, email: []const u8, creation_time: u32) !Key {
    var body = buildTestKeyBody(creation_time);
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

test "TrustPath init and deinit" {
    const allocator = std.testing.allocator;

    var path = TrustPath.init(allocator);
    defer path.deinit();

    try std.testing.expect(!path.valid);
    try std.testing.expectEqual(@as(u8, 0), path.trust_amount);
    try std.testing.expectEqual(@as(u32, 0), path.depth);
    try std.testing.expectEqual(@as(usize, 0), path.length());
}

test "TrustPath addNode" {
    const allocator = std.testing.allocator;

    var path = TrustPath.init(allocator);
    defer path.deinit();

    try path.addNode(.{
        .key_fingerprint = [_]u8{0x01} ** 20,
        .user_id = null,
        .trust_level = .ultimate,
        .signature_type = 0x13,
    });

    try std.testing.expectEqual(@as(usize, 1), path.length());
    try std.testing.expect(path.root() != null);
    try std.testing.expect(path.target() != null);
    try std.testing.expectEqual(path.root().?.key_fingerprint, path.target().?.key_fingerprint);
}

test "TrustPath root and target" {
    const allocator = std.testing.allocator;

    var path = TrustPath.init(allocator);
    defer path.deinit();

    const fp1 = [_]u8{0x01} ** 20;
    const fp2 = [_]u8{0x02} ** 20;
    const fp3 = [_]u8{0x03} ** 20;

    try path.addNode(.{ .key_fingerprint = fp1, .user_id = null, .trust_level = .ultimate, .signature_type = 0x13 });
    try path.addNode(.{ .key_fingerprint = fp2, .user_id = null, .trust_level = .full, .signature_type = 0x13 });
    try path.addNode(.{ .key_fingerprint = fp3, .user_id = null, .trust_level = .marginal, .signature_type = 0x10 });

    try std.testing.expectEqual(fp1, path.root().?.key_fingerprint);
    try std.testing.expectEqual(fp3, path.target().?.key_fingerprint);
    try std.testing.expectEqual(@as(usize, 3), path.length());
}

test "TrustPath startsFromUltimate" {
    const allocator = std.testing.allocator;

    var path = TrustPath.init(allocator);
    defer path.deinit();

    try path.addNode(.{
        .key_fingerprint = [_]u8{0x01} ** 20,
        .user_id = null,
        .trust_level = .ultimate,
        .signature_type = 0x13,
    });

    try std.testing.expect(path.startsFromUltimate());

    var path2 = TrustPath.init(allocator);
    defer path2.deinit();

    try path2.addNode(.{
        .key_fingerprint = [_]u8{0x02} ** 20,
        .user_id = null,
        .trust_level = .full,
        .signature_type = 0x13,
    });

    try std.testing.expect(!path2.startsFromUltimate());
}

test "TrustPath minimumTrust" {
    const allocator = std.testing.allocator;

    var path = TrustPath.init(allocator);
    defer path.deinit();

    try path.addNode(.{ .key_fingerprint = [_]u8{0x01} ** 20, .user_id = null, .trust_level = .ultimate, .signature_type = 0x13 });
    try path.addNode(.{ .key_fingerprint = [_]u8{0x02} ** 20, .user_id = null, .trust_level = .marginal, .signature_type = 0x13 });
    try path.addNode(.{ .key_fingerprint = [_]u8{0x03} ** 20, .user_id = null, .trust_level = .full, .signature_type = 0x13 });

    try std.testing.expectEqual(TrustLevel.marginal, path.minimumTrust());
}

test "TrustPath empty root and target" {
    const allocator = std.testing.allocator;

    var path = TrustPath.init(allocator);
    defer path.deinit();

    try std.testing.expect(path.root() == null);
    try std.testing.expect(path.target() == null);
    try std.testing.expect(!path.startsFromUltimate());
}

test "trustLevelToAmount" {
    try std.testing.expectEqual(@as(u8, 0), trustLevelToAmount(.unknown));
    try std.testing.expectEqual(@as(u8, 0), trustLevelToAmount(.never));
    try std.testing.expectEqual(@as(u8, 60), trustLevelToAmount(.marginal));
    try std.testing.expectEqual(@as(u8, 120), trustLevelToAmount(.full));
    try std.testing.expectEqual(@as(u8, 120), trustLevelToAmount(.ultimate));
}

test "amountToTrustLevel" {
    try std.testing.expectEqual(TrustLevel.unknown, amountToTrustLevel(0));
    try std.testing.expectEqual(TrustLevel.unknown, amountToTrustLevel(30));
    try std.testing.expectEqual(TrustLevel.marginal, amountToTrustLevel(60));
    try std.testing.expectEqual(TrustLevel.marginal, amountToTrustLevel(90));
    try std.testing.expectEqual(TrustLevel.full, amountToTrustLevel(120));
}

test "calculateEffectiveValidity no paths" {
    const result = calculateEffectiveValidity(&.{}, DEFAULT_MARGINALS_NEEDED, DEFAULT_COMPLETES_NEEDED);
    try std.testing.expectEqual(Validity.unknown, result);
}

test "calculateEffectiveValidity one complete path" {
    const allocator = std.testing.allocator;

    var path = TrustPath.init(allocator);
    defer path.deinit();
    path.valid = true;
    path.trust_amount = 120;

    const paths = [_]TrustPath{path};
    const result = calculateEffectiveValidity(&paths, DEFAULT_MARGINALS_NEEDED, DEFAULT_COMPLETES_NEEDED);
    try std.testing.expectEqual(Validity.full, result);
}

test "calculateEffectiveValidity three marginal paths" {
    const allocator = std.testing.allocator;

    var path1 = TrustPath.init(allocator);
    defer path1.deinit();
    path1.valid = true;
    path1.trust_amount = 60;

    var path2 = TrustPath.init(allocator);
    defer path2.deinit();
    path2.valid = true;
    path2.trust_amount = 60;

    var path3 = TrustPath.init(allocator);
    defer path3.deinit();
    path3.valid = true;
    path3.trust_amount = 60;

    const paths = [_]TrustPath{ path1, path2, path3 };
    const result = calculateEffectiveValidity(&paths, DEFAULT_MARGINALS_NEEDED, DEFAULT_COMPLETES_NEEDED);
    try std.testing.expectEqual(Validity.marginal, result);
}

test "calculateEffectiveValidity insufficient marginals" {
    const allocator = std.testing.allocator;

    var path1 = TrustPath.init(allocator);
    defer path1.deinit();
    path1.valid = true;
    path1.trust_amount = 60;

    var path2 = TrustPath.init(allocator);
    defer path2.deinit();
    path2.valid = true;
    path2.trust_amount = 60;

    const paths = [_]TrustPath{ path1, path2 };
    const result = calculateEffectiveValidity(&paths, DEFAULT_MARGINALS_NEEDED, DEFAULT_COMPLETES_NEEDED);
    try std.testing.expectEqual(Validity.unknown, result);
}

test "calculateEffectiveValidity invalid paths ignored" {
    const allocator = std.testing.allocator;

    var path = TrustPath.init(allocator);
    defer path.deinit();
    path.valid = false;
    path.trust_amount = 120;

    const paths = [_]TrustPath{path};
    const result = calculateEffectiveValidity(&paths, DEFAULT_MARGINALS_NEEDED, DEFAULT_COMPLETES_NEEDED);
    try std.testing.expectEqual(Validity.unknown, result);
}

test "calculateEffectiveValidity from ultimate" {
    const allocator = std.testing.allocator;

    var path = TrustPath.init(allocator);
    defer path.deinit();
    path.valid = true;
    path.trust_amount = 120;

    try path.addNode(.{
        .key_fingerprint = [_]u8{0x01} ** 20,
        .user_id = null,
        .trust_level = .ultimate,
        .signature_type = 0x13,
    });

    const paths = [_]TrustPath{path};
    const result = calculateEffectiveValidity(&paths, DEFAULT_MARGINALS_NEEDED, DEFAULT_COMPLETES_NEEDED);
    try std.testing.expectEqual(Validity.ultimate, result);
}

test "findTrustPath same key" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    var db = TrustDB.init(allocator);
    defer db.deinit();

    var key = try createTestKey(allocator, "Alice <alice@example.com>", 1000);
    const fp = key.fingerprint();
    try kr.addKey(key);

    try db.setOwnerTrust(fp, .ultimate);

    var result = (try findTrustPath(allocator, fp, fp, &kr, &db, 5)).?;
    defer result.deinit();

    try std.testing.expect(result.valid);
    try std.testing.expectEqual(@as(usize, 1), result.length());
    try std.testing.expectEqual(TrustLevel.ultimate, result.root().?.trust_level);
}

test "findTrustPath no connection" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    var db = TrustDB.init(allocator);
    defer db.deinit();

    var key1 = try createTestKey(allocator, "Alice <alice@example.com>", 1000);
    const fp1 = key1.fingerprint();
    try kr.addKey(key1);

    var key2 = try createTestKey(allocator, "Bob <bob@example.com>", 2000);
    const fp2 = key2.fingerprint();
    try kr.addKey(key2);

    try db.setOwnerTrust(fp1, .ultimate);

    // No certifications exist between Alice and Bob
    const result = try findTrustPath(allocator, fp1, fp2, &kr, &db, 5);
    try std.testing.expect(result == null);
}

test "computeAllPaths no ultimate keys" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    var db = TrustDB.init(allocator);
    defer db.deinit();

    var key = try createTestKey(allocator, "Bob <bob@example.com>", 2000);
    const fp = key.fingerprint();
    try kr.addKey(key);

    const paths = try computeAllPaths(allocator, fp, &kr, &db, 5);
    defer {
        for (paths) |*p| {
            var mp = p.*;
            mp.deinit();
        }
        allocator.free(paths);
    }

    try std.testing.expectEqual(@as(usize, 0), paths.len);
}

test "findUltimateTrustKeys" {
    const allocator = std.testing.allocator;

    var kr = Keyring.init(allocator);
    defer kr.deinit();

    var db = TrustDB.init(allocator);
    defer db.deinit();

    var key1 = try createTestKey(allocator, "Alice <alice@example.com>", 1000);
    const fp1 = key1.fingerprint();
    try kr.addKey(key1);

    var key2 = try createTestKey(allocator, "Bob <bob@example.com>", 2000);
    const fp2 = key2.fingerprint();
    try kr.addKey(key2);

    try db.setOwnerTrust(fp1, .ultimate);
    try db.setOwnerTrust(fp2, .full);

    const ultimate = try findUltimateTrustKeys(allocator, &kr, &db);
    defer allocator.free(ultimate);

    try std.testing.expectEqual(@as(usize, 1), ultimate.len);
    try std.testing.expectEqual(fp1, ultimate[0]);
}

test "DEFAULT constants" {
    try std.testing.expectEqual(@as(u32, 3), DEFAULT_MARGINALS_NEEDED);
    try std.testing.expectEqual(@as(u32, 1), DEFAULT_COMPLETES_NEEDED);
    try std.testing.expectEqual(@as(u32, 5), DEFAULT_MAX_DEPTH);
}
