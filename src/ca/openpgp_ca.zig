// SPDX-License-Identifier: MIT
//! OpenPGP Certification Authority (CA) for organizational key management.
//!
//! Provides a lightweight CA that can:
//!   - Issue certifications (third-party signatures) on user keys
//!   - Revoke previously issued certifications
//!   - Enforce organizational key policies (algorithms, sizes, expiration)
//!   - Track all issued certifications in a simple database
//!   - Verify key ownership through challenge-response
//!
//! This implements the "CA" model described in the OpenPGP best practices:
//! an organizational key signs (certifies) employee keys, establishing a
//! trust path within the organization.
//!
//! The CA key itself is an Ed25519 or RSA key pair that only makes
//! certification signatures (0x10-0x13) on other keys' User IDs.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const enums = @import("../types/enums.zig");
const PublicKeyAlgorithm = enums.PublicKeyAlgorithm;
const HashAlgorithm = enums.HashAlgorithm;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during CA operations.
pub const CaError = error{
    /// The CA has not been initialized with a key pair.
    NotInitialized,
    /// The submitted key does not meet policy requirements.
    PolicyViolation,
    /// The key ownership verification failed.
    OwnershipVerificationFailed,
    /// The certification has already been revoked.
    AlreadyRevoked,
    /// The certification was not found in the database.
    CertificationNotFound,
    /// The user ID does not match the required domain.
    InvalidUserIdDomain,
    /// The key algorithm is not allowed by policy.
    AlgorithmNotAllowed,
    /// The key size is below the minimum requirement.
    KeyTooSmall,
    /// The key has no expiration or it exceeds the maximum.
    ExpirationPolicyViolation,
    /// The key has already been certified by this CA.
    AlreadyCertified,
    /// Database I/O error.
    DatabaseError,
    /// Out of memory.
    OutOfMemory,
    /// Invalid data format.
    InvalidFormat,
};

// ---------------------------------------------------------------------------
// Trust levels
// ---------------------------------------------------------------------------

/// Trust level for issued certifications.
///
/// Maps to OpenPGP certification signature types:
///   - 0x10: Generic certification
///   - 0x11: Persona certification
///   - 0x12: Casual certification
///   - 0x13: Positive certification
pub const CertificationLevel = enum(u8) {
    /// Generic certification — the CA does not vouch for identity.
    generic = 0x10,
    /// Persona certification — no identity verification performed.
    persona = 0x11,
    /// Casual certification — some identity checking was done.
    casual = 0x12,
    /// Positive certification — thorough identity verification.
    positive = 0x13,

    pub fn name(self: CertificationLevel) []const u8 {
        return switch (self) {
            .generic => "Generic",
            .persona => "Persona",
            .casual => "Casual",
            .positive => "Positive",
        };
    }

    /// The OpenPGP signature type byte.
    pub fn signatureType(self: CertificationLevel) u8 {
        return @intFromEnum(self);
    }
};

/// Trust depth for trust signatures.
///
/// Depth 0 means the certified key is trusted for its own signatures only.
/// Depth 1 means the certified key can itself certify other keys.
pub const TrustDepth = struct {
    /// Trust level (0-255, where 60 = partial, 120 = complete).
    level: u8,
    /// Depth of trust (0 = leaf, 1+ = can introduce).
    depth: u8,
    /// Optional regular expression for limiting trust scope.
    domain_regex: ?[]const u8,

    /// Default trust parameters for organizational use.
    pub fn orgDefault() TrustDepth {
        return .{
            .level = 120, // Complete trust
            .depth = 0, // Leaf (cannot certify others)
            .domain_regex = null,
        };
    }

    /// Trust that allows the certified key to also certify.
    pub fn introducer(domain: ?[]const u8) TrustDepth {
        return .{
            .level = 120,
            .depth = 1,
            .domain_regex = domain,
        };
    }
};

// ---------------------------------------------------------------------------
// CA Policy
// ---------------------------------------------------------------------------

/// Policy configuration for the Certification Authority.
///
/// Defines what keys the CA will accept for certification based on
/// algorithm, key size, expiration, and user ID format requirements.
pub const CaPolicy = struct {
    /// Minimum RSA key size in bits (0 to disable RSA requirement).
    min_rsa_bits: u16,
    /// Allowed public key algorithms.
    allowed_algorithms: AllowedAlgorithms,
    /// Maximum certification validity in seconds (0 = no limit).
    max_cert_validity_secs: u64,
    /// Default certification validity in seconds.
    default_cert_validity_secs: u64,
    /// Required email domain (null = any domain accepted).
    required_domain: ?[]const u8,
    /// Whether keys must have an expiration date.
    require_expiration: bool,
    /// Maximum key validity in seconds (0 = no limit).
    max_key_validity_secs: u64,
    /// Whether to perform challenge-response ownership verification.
    require_ownership_proof: bool,
    /// Default certification level for new certifications.
    default_cert_level: CertificationLevel,
    /// Default trust depth for new certifications.
    default_trust_depth: TrustDepth,
    /// Whether to auto-set certification expiration.
    auto_expiration: bool,

    pub const AllowedAlgorithms = struct {
        rsa: bool,
        ecdsa: bool,
        eddsa: bool,
        ed25519: bool,
        ed448: bool,
        x25519: bool,
        x448: bool,
    };

    /// Create a default (permissive) policy.
    pub fn default() CaPolicy {
        return .{
            .min_rsa_bits = 2048,
            .allowed_algorithms = .{
                .rsa = true,
                .ecdsa = true,
                .eddsa = true,
                .ed25519 = true,
                .ed448 = true,
                .x25519 = true,
                .x448 = true,
            },
            .max_cert_validity_secs = 365 * 24 * 3600, // 1 year
            .default_cert_validity_secs = 180 * 24 * 3600, // 180 days
            .required_domain = null,
            .require_expiration = false,
            .max_key_validity_secs = 0,
            .require_ownership_proof = false,
            .default_cert_level = .positive,
            .default_trust_depth = TrustDepth.orgDefault(),
            .auto_expiration = true,
        };
    }

    /// Create a strict organizational policy.
    pub fn strict(domain: []const u8) CaPolicy {
        return .{
            .min_rsa_bits = 3072,
            .allowed_algorithms = .{
                .rsa = true,
                .ecdsa = true,
                .eddsa = true,
                .ed25519 = true,
                .ed448 = true,
                .x25519 = true,
                .x448 = true,
            },
            .max_cert_validity_secs = 365 * 24 * 3600,
            .default_cert_validity_secs = 90 * 24 * 3600, // 90 days
            .required_domain = domain,
            .require_expiration = true,
            .max_key_validity_secs = 2 * 365 * 24 * 3600, // 2 years
            .require_ownership_proof = true,
            .default_cert_level = .positive,
            .default_trust_depth = TrustDepth.orgDefault(),
            .auto_expiration = true,
        };
    }

    /// Check if a public key algorithm is allowed.
    pub fn isAlgorithmAllowed(self: *const CaPolicy, algo: PublicKeyAlgorithm) bool {
        return switch (algo) {
            .rsa_encrypt_sign, .rsa_sign_only, .rsa_encrypt_only => self.allowed_algorithms.rsa,
            .ecdsa => self.allowed_algorithms.ecdsa,
            .eddsa => self.allowed_algorithms.eddsa,
            .ed25519 => self.allowed_algorithms.ed25519,
            .ed448 => self.allowed_algorithms.ed448,
            .x25519 => self.allowed_algorithms.x25519,
            .x448 => self.allowed_algorithms.x448,
            else => false,
        };
    }

    /// Validate a user ID against the domain policy.
    pub fn validateUserId(self: *const CaPolicy, user_id: []const u8) CaError!void {
        if (self.required_domain) |domain| {
            // Look for email address in angle brackets or bare
            if (extractEmailDomain(user_id)) |email_domain| {
                if (!asciiEqlIgnoreCase(email_domain, domain)) {
                    return CaError.InvalidUserIdDomain;
                }
            } else {
                return CaError.InvalidUserIdDomain;
            }
        }
    }

    /// Validate key parameters against policy.
    pub fn validateKeyParams(self: *const CaPolicy, params: KeyParams) CaError!void {
        // Check algorithm
        if (!self.isAlgorithmAllowed(params.algorithm)) {
            return CaError.AlgorithmNotAllowed;
        }

        // Check RSA key size
        switch (params.algorithm) {
            .rsa_encrypt_sign, .rsa_sign_only, .rsa_encrypt_only => {
                if (params.key_bits < self.min_rsa_bits) {
                    return CaError.KeyTooSmall;
                }
            },
            else => {},
        }

        // Check expiration
        if (self.require_expiration and !params.has_expiration) {
            return CaError.ExpirationPolicyViolation;
        }

        // Check max key validity
        if (self.max_key_validity_secs > 0 and params.has_expiration) {
            if (params.validity_secs > self.max_key_validity_secs) {
                return CaError.ExpirationPolicyViolation;
            }
        }
    }
};

/// Key parameters extracted from a public key for policy checking.
pub const KeyParams = struct {
    /// Public key algorithm.
    algorithm: PublicKeyAlgorithm,
    /// Key size in bits (for RSA/DSA; 0 for ECC).
    key_bits: u16,
    /// Whether the key has an expiration date.
    has_expiration: bool,
    /// Key validity period in seconds (from creation to expiration).
    validity_secs: u64,
    /// Key fingerprint (20 or 32 bytes).
    fingerprint: [32]u8,
    /// Length of the fingerprint.
    fingerprint_len: u8,
    /// Key creation timestamp.
    creation_time: u32,
};

// ---------------------------------------------------------------------------
// Certification record
// ---------------------------------------------------------------------------

/// A record of a certification issued by the CA.
pub const CertificationRecord = struct {
    /// Unique ID for this certification (sequential).
    id: u64,
    /// Fingerprint of the certified key (up to 32 bytes).
    key_fingerprint: [32]u8,
    /// Length of the fingerprint.
    fingerprint_len: u8,
    /// User ID that was certified.
    user_id: []const u8,
    /// Certification level used.
    cert_level: CertificationLevel,
    /// Trust depth assigned.
    trust_depth: TrustDepth,
    /// Timestamp when the certification was issued.
    issued_at: u64,
    /// Timestamp when the certification expires (0 = never).
    expires_at: u64,
    /// Whether this certification has been revoked.
    revoked: bool,
    /// Revocation timestamp (0 = not revoked).
    revoked_at: u64,
    /// Revocation reason (if revoked).
    revocation_reason: ?[]const u8,

    /// Check if the certification is currently valid.
    pub fn isValid(self: *const CertificationRecord, current_time: u64) bool {
        if (self.revoked) return false;
        if (self.expires_at > 0 and current_time >= self.expires_at) return false;
        return true;
    }

    /// Check if the certification has expired.
    pub fn isExpired(self: *const CertificationRecord, current_time: u64) bool {
        if (self.expires_at == 0) return false;
        return current_time >= self.expires_at;
    }

    /// Free allocated memory for this record.
    pub fn deinit(self: *const CertificationRecord, allocator: Allocator) void {
        if (self.user_id.len > 0) allocator.free(self.user_id);
        if (self.revocation_reason) |reason| allocator.free(reason);
        if (self.trust_depth.domain_regex) |regex| allocator.free(regex);
    }
};

// ---------------------------------------------------------------------------
// CA Database
// ---------------------------------------------------------------------------

/// Simple file-based database for tracking issued certifications.
///
/// Stores certifications as a flat list with sequential IDs.
/// Supports querying by fingerprint, user ID, and revocation status.
pub const CaDatabase = struct {
    /// All certification records.
    records: std.ArrayList(CertificationRecord),
    /// Next record ID.
    next_id: u64,
    /// Optional file path for persistence.
    file_path: ?[]const u8,

    /// Initialize an empty database.
    pub fn init() CaDatabase {
        return .{
            .records = .empty,
            .next_id = 1,
            .file_path = null,
        };
    }

    /// Initialize with a file path for persistence.
    pub fn initWithPath(path: []const u8) CaDatabase {
        return .{
            .records = .empty,
            .next_id = 1,
            .file_path = path,
        };
    }

    /// Free all resources.
    pub fn deinit(self: *CaDatabase, allocator: Allocator) void {
        for (self.records.items) |*record| {
            record.deinit(allocator);
        }
        self.records.deinit(allocator);
    }

    /// Add a certification record.
    pub fn addRecord(self: *CaDatabase, allocator: Allocator, record: CertificationRecord) CaError!u64 {
        var new_record = record;
        new_record.id = self.next_id;
        self.next_id += 1;

        self.records.append(allocator, new_record) catch return CaError.OutOfMemory;
        return new_record.id;
    }

    /// Find a certification by ID.
    pub fn findById(self: *const CaDatabase, id: u64) ?*const CertificationRecord {
        for (self.records.items) |*record| {
            if (record.id == id) return record;
        }
        return null;
    }

    /// Find certifications for a specific fingerprint.
    pub fn findByFingerprint(self: *const CaDatabase, fingerprint: []const u8) []const CertificationRecord {
        // Returns the full list; caller should filter.
        // For a proper implementation, we'd return a filtered slice.
        _ = fingerprint;
        return self.records.items;
    }

    /// Count total certifications.
    pub fn totalCount(self: *const CaDatabase) usize {
        return self.records.items.len;
    }

    /// Count active (non-revoked, non-expired) certifications.
    pub fn activeCount(self: *const CaDatabase, current_time: u64) usize {
        var count: usize = 0;
        for (self.records.items) |*record| {
            if (record.isValid(current_time)) count += 1;
        }
        return count;
    }

    /// Count revoked certifications.
    pub fn revokedCount(self: *const CaDatabase) usize {
        var count: usize = 0;
        for (self.records.items) |*record| {
            if (record.revoked) count += 1;
        }
        return count;
    }

    /// Revoke a certification by ID.
    pub fn revoke(self: *CaDatabase, id: u64, timestamp: u64, reason: ?[]const u8) CaError!void {
        for (self.records.items) |*record| {
            if (record.id == id) {
                if (record.revoked) return CaError.AlreadyRevoked;
                record.revoked = true;
                record.revoked_at = timestamp;
                record.revocation_reason = reason;
                return;
            }
        }
        return CaError.CertificationNotFound;
    }

    /// List all certified user IDs.
    pub fn listCertifiedUsers(self: *const CaDatabase, allocator: Allocator) CaError![][]const u8 {
        var users: std.ArrayList([]const u8) = .empty;
        errdefer users.deinit(allocator);

        for (self.records.items) |*record| {
            if (!record.revoked and record.user_id.len > 0) {
                const uid = allocator.dupe(u8, record.user_id) catch return CaError.OutOfMemory;
                users.append(allocator, uid) catch return CaError.OutOfMemory;
            }
        }

        return users.toOwnedSlice(allocator) catch return CaError.OutOfMemory;
    }

    /// Export the database as a serialized byte buffer.
    ///
    /// Format: header (8 bytes) + records.
    /// Each record: id(8) + fingerprint_len(1) + fingerprint(32) +
    ///              uid_len(2) + uid + cert_level(1) + trust_level(1) +
    ///              trust_depth(1) + issued_at(8) + expires_at(8) +
    ///              revoked(1) + revoked_at(8)
    pub fn exportToBytes(self: *const CaDatabase, allocator: Allocator) CaError![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);
        const w = buf.writer(allocator);

        // Header: "OPGPCA01"
        w.writeAll("OPGPCA01") catch return CaError.OutOfMemory;

        // Record count
        const count: u32 = @intCast(self.records.items.len);
        w.writeInt(u32, count, .big) catch return CaError.OutOfMemory;

        // Write each record
        for (self.records.items) |*record| {
            w.writeInt(u64, record.id, .big) catch return CaError.OutOfMemory;
            w.writeByte(record.fingerprint_len) catch return CaError.OutOfMemory;
            w.writeAll(&record.key_fingerprint) catch return CaError.OutOfMemory;

            const uid_len: u16 = @intCast(record.user_id.len);
            w.writeInt(u16, uid_len, .big) catch return CaError.OutOfMemory;
            if (record.user_id.len > 0) {
                w.writeAll(record.user_id) catch return CaError.OutOfMemory;
            }

            w.writeByte(@intFromEnum(record.cert_level)) catch return CaError.OutOfMemory;
            w.writeByte(record.trust_depth.level) catch return CaError.OutOfMemory;
            w.writeByte(record.trust_depth.depth) catch return CaError.OutOfMemory;
            w.writeInt(u64, record.issued_at, .big) catch return CaError.OutOfMemory;
            w.writeInt(u64, record.expires_at, .big) catch return CaError.OutOfMemory;
            w.writeByte(if (record.revoked) 1 else 0) catch return CaError.OutOfMemory;
            w.writeInt(u64, record.revoked_at, .big) catch return CaError.OutOfMemory;
        }

        return buf.toOwnedSlice(allocator) catch return CaError.OutOfMemory;
    }

    /// Import the database from serialized bytes.
    pub fn importFromBytes(allocator: Allocator, data: []const u8) CaError!CaDatabase {
        if (data.len < 12) return CaError.InvalidFormat;

        // Check header
        if (!mem.eql(u8, data[0..8], "OPGPCA01")) return CaError.InvalidFormat;

        const count = mem.readInt(u32, data[8..12], .big);
        var db = CaDatabase.init();
        errdefer db.deinit(allocator);

        var offset: usize = 12;

        for (0..count) |_| {
            if (offset + 8 + 1 + 32 + 2 > data.len) return CaError.InvalidFormat;

            const id = mem.readInt(u64, data[offset..][0..8], .big);
            offset += 8;

            const fp_len = data[offset];
            offset += 1;

            var fingerprint: [32]u8 = undefined;
            @memcpy(&fingerprint, data[offset..][0..32]);
            offset += 32;

            if (offset + 2 > data.len) return CaError.InvalidFormat;
            const uid_len = mem.readInt(u16, data[offset..][0..2], .big);
            offset += 2;

            if (offset + uid_len > data.len) return CaError.InvalidFormat;
            const user_id = if (uid_len > 0)
                allocator.dupe(u8, data[offset .. offset + uid_len]) catch return CaError.OutOfMemory
            else
                allocator.alloc(u8, 0) catch return CaError.OutOfMemory;
            offset += uid_len;

            if (offset + 3 + 8 + 8 + 1 + 8 > data.len) {
                allocator.free(user_id);
                return CaError.InvalidFormat;
            }

            const cert_level: CertificationLevel = @enumFromInt(data[offset]);
            offset += 1;
            const trust_level = data[offset];
            offset += 1;
            const trust_depth_val = data[offset];
            offset += 1;
            const issued_at = mem.readInt(u64, data[offset..][0..8], .big);
            offset += 8;
            const expires_at = mem.readInt(u64, data[offset..][0..8], .big);
            offset += 8;
            const revoked = data[offset] != 0;
            offset += 1;
            const revoked_at = mem.readInt(u64, data[offset..][0..8], .big);
            offset += 8;

            const record = CertificationRecord{
                .id = id,
                .key_fingerprint = fingerprint,
                .fingerprint_len = fp_len,
                .user_id = user_id,
                .cert_level = cert_level,
                .trust_depth = .{
                    .level = trust_level,
                    .depth = trust_depth_val,
                    .domain_regex = null,
                },
                .issued_at = issued_at,
                .expires_at = expires_at,
                .revoked = revoked,
                .revoked_at = revoked_at,
                .revocation_reason = null,
            };

            db.records.append(allocator, record) catch return CaError.OutOfMemory;
            if (id >= db.next_id) db.next_id = id + 1;
        }

        return db;
    }
};

// ---------------------------------------------------------------------------
// Key vetting result
// ---------------------------------------------------------------------------

/// Result of the key vetting process.
pub const VettingResult = struct {
    /// Whether the key passed all checks.
    approved: bool,
    /// List of issues found during vetting.
    issues: std.ArrayList(VettingIssue),

    pub const VettingIssue = struct {
        severity: Severity,
        description: []const u8,

        pub const Severity = enum {
            info,
            warning,
            rejection,

            pub fn name(self: Severity) []const u8 {
                return switch (self) {
                    .info => "INFO",
                    .warning => "WARNING",
                    .rejection => "REJECT",
                };
            }
        };

        pub fn deinit(self: *const VettingIssue, allocator: Allocator) void {
            allocator.free(self.description);
        }
    };

    /// Initialize an empty result (approved by default).
    pub fn init() VettingResult {
        return .{
            .approved = true,
            .issues = .empty,
        };
    }

    /// Free all resources.
    pub fn deinit(self: *VettingResult, allocator: Allocator) void {
        for (self.issues.items) |*issue| issue.deinit(allocator);
        self.issues.deinit(allocator);
    }

    /// Add an issue and mark as rejected if severity is rejection.
    pub fn addIssue(self: *VettingResult, allocator: Allocator, severity: VettingIssue.Severity, description: []const u8) CaError!void {
        const desc = allocator.dupe(u8, description) catch return CaError.OutOfMemory;
        self.issues.append(allocator, .{
            .severity = severity,
            .description = desc,
        }) catch return CaError.OutOfMemory;

        if (severity == .rejection) self.approved = false;
    }

    /// Format the result as a human-readable string.
    pub fn format(self: *const VettingResult, allocator: Allocator) CaError![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);
        const w = buf.writer(allocator);

        w.print("Key Vetting Result: {s}\n", .{if (self.approved) "APPROVED" else "REJECTED"}) catch return CaError.OutOfMemory;

        if (self.issues.items.len > 0) {
            w.print("Issues ({d}):\n", .{self.issues.items.len}) catch return CaError.OutOfMemory;
            for (self.issues.items, 0..) |issue, i| {
                w.print("  {d}. [{s}] {s}\n", .{ i + 1, issue.severity.name(), issue.description }) catch return CaError.OutOfMemory;
            }
        } else {
            w.writeAll("No issues found.\n") catch return CaError.OutOfMemory;
        }

        return buf.toOwnedSlice(allocator) catch return CaError.OutOfMemory;
    }
};

// ---------------------------------------------------------------------------
// Challenge-Response for ownership verification
// ---------------------------------------------------------------------------

/// A challenge for proving key ownership.
pub const OwnershipChallenge = struct {
    /// Random challenge nonce.
    nonce: [32]u8,
    /// Timestamp when the challenge was created.
    created_at: u64,
    /// Target key fingerprint.
    key_fingerprint: [32]u8,
    /// Length of the fingerprint.
    fingerprint_len: u8,
    /// Target user ID.
    user_id: []const u8,

    /// Check if the challenge has expired (default: 1 hour).
    pub fn isExpired(self: *const OwnershipChallenge, current_time: u64) bool {
        return current_time > self.created_at + 3600;
    }
};

// ---------------------------------------------------------------------------
// Certification Authority
// ---------------------------------------------------------------------------

/// OpenPGP Certification Authority.
///
/// Manages the CA key pair and issues/revokes certifications on user keys
/// according to the configured policy.
pub const CertificationAuthority = struct {
    /// Memory allocator.
    allocator: Allocator,
    /// CA policy.
    policy: CaPolicy,
    /// Certification database.
    database: CaDatabase,
    /// CA key fingerprint.
    ca_fingerprint: [32]u8,
    /// Length of the CA fingerprint.
    ca_fingerprint_len: u8,
    /// CA key algorithm.
    ca_algorithm: PublicKeyAlgorithm,
    /// Whether the CA has been initialized with a key.
    initialized: bool,
    /// CA display name / user ID.
    ca_name: []const u8,
    /// Outstanding ownership challenges.
    pending_challenges: std.ArrayList(OwnershipChallenge),

    /// Initialize a new CA with the given policy.
    pub fn init(allocator: Allocator, policy: CaPolicy) CertificationAuthority {
        return .{
            .allocator = allocator,
            .policy = policy,
            .database = CaDatabase.init(),
            .ca_fingerprint = std.mem.zeroes([32]u8),
            .ca_fingerprint_len = 0,
            .ca_algorithm = .ed25519,
            .initialized = false,
            .ca_name = "",
            .pending_challenges = .empty,
        };
    }

    /// Free all resources.
    pub fn deinit(self: *CertificationAuthority) void {
        self.database.deinit(self.allocator);
        self.pending_challenges.deinit(self.allocator);
        if (self.ca_name.len > 0) self.allocator.free(self.ca_name);
    }

    /// Initialize the CA with a key pair.
    ///
    /// The fingerprint identifies the CA key. The actual key material
    /// is managed externally (e.g., on a smart card or in a keyring).
    pub fn initializeWithKey(
        self: *CertificationAuthority,
        fingerprint: []const u8,
        algorithm: PublicKeyAlgorithm,
        ca_name: []const u8,
    ) CaError!void {
        if (fingerprint.len > 32) return CaError.InvalidFormat;

        @memset(&self.ca_fingerprint, 0);
        @memcpy(self.ca_fingerprint[0..fingerprint.len], fingerprint);
        self.ca_fingerprint_len = @intCast(fingerprint.len);
        self.ca_algorithm = algorithm;
        self.ca_name = self.allocator.dupe(u8, ca_name) catch return CaError.OutOfMemory;
        self.initialized = true;
    }

    /// Vet a key against the CA policy.
    ///
    /// Returns a detailed vetting result with any issues found.
    /// The key can only be certified if the result is approved.
    pub fn vetKey(self: *const CertificationAuthority, params: KeyParams, user_id: []const u8) CaError!VettingResult {
        var result = VettingResult.init();
        errdefer result.deinit(self.allocator);

        // Check algorithm
        if (!self.policy.isAlgorithmAllowed(params.algorithm)) {
            try result.addIssue(self.allocator, .rejection,
                "Key algorithm is not allowed by CA policy");
        }

        // Check RSA key size
        switch (params.algorithm) {
            .rsa_encrypt_sign, .rsa_sign_only, .rsa_encrypt_only => {
                if (params.key_bits < self.policy.min_rsa_bits) {
                    try result.addIssue(self.allocator, .rejection,
                        "RSA key size is below the minimum required by CA policy");
                }
            },
            else => {},
        }

        // Check expiration policy
        if (self.policy.require_expiration and !params.has_expiration) {
            try result.addIssue(self.allocator, .rejection,
                "Key must have an expiration date per CA policy");
        }

        if (self.policy.max_key_validity_secs > 0 and params.has_expiration) {
            if (params.validity_secs > self.policy.max_key_validity_secs) {
                try result.addIssue(self.allocator, .warning,
                    "Key validity period exceeds maximum recommended by CA policy");
            }
        }

        // Check user ID domain
        if (self.policy.required_domain != null) {
            self.policy.validateUserId(user_id) catch {
                try result.addIssue(self.allocator, .rejection,
                    "User ID email domain does not match required domain");
            };
        }

        // Check if already certified
        for (self.database.records.items) |*record| {
            if (record.fingerprint_len == params.fingerprint_len and
                mem.eql(u8, record.key_fingerprint[0..record.fingerprint_len],
                params.fingerprint[0..params.fingerprint_len]))
            {
                if (record.isValid(params.creation_time)) {
                    try result.addIssue(self.allocator, .info,
                        "Key is already certified by this CA");
                }
            }
        }

        // Note on key quality
        if (params.algorithm == .eddsa or params.algorithm == .ed25519) {
            try result.addIssue(self.allocator, .info,
                "Ed25519 key; recommended for modern OpenPGP usage");
        }

        return result;
    }

    /// Issue a certification for a user key.
    ///
    /// This creates a certification record in the database. The actual
    /// cryptographic signature must be created externally using the CA's
    /// private key (which may be on a smart card, HSM, etc.).
    ///
    /// Returns the certification record ID.
    pub fn issueCertification(
        self: *CertificationAuthority,
        params: KeyParams,
        user_id: []const u8,
        cert_level: ?CertificationLevel,
        trust_depth: ?TrustDepth,
        current_time: u64,
    ) CaError!u64 {
        if (!self.initialized) return CaError.NotInitialized;

        // Validate against policy
        try self.policy.validateKeyParams(params);
        try self.policy.validateUserId(user_id);

        // Calculate expiration
        const validity = self.policy.default_cert_validity_secs;
        const expires_at = if (self.policy.auto_expiration and validity > 0)
            current_time + validity
        else
            0;

        // Create record
        const uid_copy = self.allocator.dupe(u8, user_id) catch return CaError.OutOfMemory;
        errdefer self.allocator.free(uid_copy);

        const record = CertificationRecord{
            .id = 0, // Will be assigned by database
            .key_fingerprint = params.fingerprint,
            .fingerprint_len = params.fingerprint_len,
            .user_id = uid_copy,
            .cert_level = cert_level orelse self.policy.default_cert_level,
            .trust_depth = trust_depth orelse self.policy.default_trust_depth,
            .issued_at = current_time,
            .expires_at = expires_at,
            .revoked = false,
            .revoked_at = 0,
            .revocation_reason = null,
        };

        return self.database.addRecord(self.allocator, record);
    }

    /// Revoke a previously issued certification.
    pub fn revokeCertification(
        self: *CertificationAuthority,
        cert_id: u64,
        reason: ?[]const u8,
        current_time: u64,
    ) CaError!void {
        if (!self.initialized) return CaError.NotInitialized;

        const reason_copy = if (reason) |r|
            self.allocator.dupe(u8, r) catch return CaError.OutOfMemory
        else
            null;

        try self.database.revoke(cert_id, current_time, reason_copy);
    }

    /// Create an ownership challenge for a key.
    pub fn createChallenge(
        self: *CertificationAuthority,
        params: KeyParams,
        user_id: []const u8,
        current_time: u64,
    ) CaError!OwnershipChallenge {
        if (!self.initialized) return CaError.NotInitialized;

        // Generate a random nonce
        var nonce: [32]u8 = undefined;
        std.crypto.random.bytes(&nonce);

        const challenge = OwnershipChallenge{
            .nonce = nonce,
            .created_at = current_time,
            .key_fingerprint = params.fingerprint,
            .fingerprint_len = params.fingerprint_len,
            .user_id = user_id,
        };

        self.pending_challenges.append(self.allocator, challenge) catch
            return CaError.OutOfMemory;

        return challenge;
    }

    /// Verify an ownership challenge response.
    ///
    /// The response should be the challenge nonce signed by the key's
    /// private key. This function checks that the signature is valid
    /// (the actual signature verification is delegated to the caller).
    pub fn verifyChallenge(
        self: *CertificationAuthority,
        fingerprint: []const u8,
        nonce: [32]u8,
        current_time: u64,
    ) CaError!bool {
        // Find the matching challenge
        for (self.pending_challenges.items, 0..) |*challenge, idx| {
            if (challenge.fingerprint_len == fingerprint.len and
                mem.eql(u8, challenge.key_fingerprint[0..challenge.fingerprint_len], fingerprint) and
                mem.eql(u8, &challenge.nonce, &nonce))
            {
                if (challenge.isExpired(current_time)) {
                    // Remove expired challenge
                    _ = self.pending_challenges.orderedRemove(idx);
                    return CaError.OwnershipVerificationFailed;
                }

                // Challenge matches - remove it
                _ = self.pending_challenges.orderedRemove(idx);
                return true;
            }
        }

        return CaError.OwnershipVerificationFailed;
    }

    /// Get statistics about issued certifications.
    pub fn getStats(self: *const CertificationAuthority, current_time: u64) CaStats {
        return .{
            .total_certifications = self.database.totalCount(),
            .active_certifications = self.database.activeCount(current_time),
            .revoked_certifications = self.database.revokedCount(),
            .pending_challenges = self.pending_challenges.items.len,
        };
    }
};

/// CA statistics.
pub const CaStats = struct {
    total_certifications: usize,
    active_certifications: usize,
    revoked_certifications: usize,
    pending_challenges: usize,
};

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Extract the domain part from an email address in a user ID.
///
/// Handles formats like:
///   - "Alice <alice@example.com>"
///   - "alice@example.com"
///   - "<alice@example.com>"
fn extractEmailDomain(user_id: []const u8) ?[]const u8 {
    // Look for email in angle brackets first
    var email: ?[]const u8 = null;

    if (mem.indexOf(u8, user_id, "<")) |start| {
        if (mem.indexOf(u8, user_id[start..], ">")) |end_rel| {
            email = user_id[start + 1 .. start + end_rel];
        }
    }

    // If no angle brackets, treat the whole thing as potential email
    if (email == null) {
        email = mem.trim(u8, user_id, " \t");
    }

    // Find the @ sign
    if (email) |e| {
        if (mem.indexOf(u8, e, "@")) |at_pos| {
            if (at_pos + 1 < e.len) {
                return e[at_pos + 1 ..];
            }
        }
    }

    return null;
}

/// Case-insensitive ASCII string comparison.
fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ac, bc| {
        const al = if (ac >= 'A' and ac <= 'Z') ac + 32 else ac;
        const bl = if (bc >= 'A' and bc <= 'Z') bc + 32 else bc;
        if (al != bl) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "CaPolicy default" {
    const policy = CaPolicy.default();
    try std.testing.expect(policy.allowed_algorithms.rsa);
    try std.testing.expect(policy.allowed_algorithms.ed25519);
    try std.testing.expectEqual(@as(u16, 2048), policy.min_rsa_bits);
    try std.testing.expect(!policy.require_expiration);
}

test "CaPolicy strict" {
    const policy = CaPolicy.strict("example.com");
    try std.testing.expectEqual(@as(u16, 3072), policy.min_rsa_bits);
    try std.testing.expect(policy.require_expiration);
    try std.testing.expect(policy.require_ownership_proof);
    try std.testing.expectEqualStrings("example.com", policy.required_domain.?);
}

test "CaPolicy algorithm check" {
    const policy = CaPolicy.default();
    try std.testing.expect(policy.isAlgorithmAllowed(.rsa_encrypt_sign));
    try std.testing.expect(policy.isAlgorithmAllowed(.ed25519));
    try std.testing.expect(!policy.isAlgorithmAllowed(.dsa));
    try std.testing.expect(!policy.isAlgorithmAllowed(.elgamal));
}

test "CaPolicy validateUserId domain" {
    const policy = CaPolicy.strict("example.com");

    // Valid email
    try policy.validateUserId("Alice <alice@example.com>");

    // Wrong domain
    try std.testing.expectError(CaError.InvalidUserIdDomain,
        policy.validateUserId("Bob <bob@other.com>"));

    // No email at all
    try std.testing.expectError(CaError.InvalidUserIdDomain,
        policy.validateUserId("Charlie"));
}

test "CaPolicy validateKeyParams" {
    const policy = CaPolicy.strict("example.com");

    // Good Ed25519 key with expiration
    const good_params = KeyParams{
        .algorithm = .ed25519,
        .key_bits = 256,
        .has_expiration = true,
        .validity_secs = 365 * 24 * 3600,
        .fingerprint = std.mem.zeroes([32]u8),
        .fingerprint_len = 20,
        .creation_time = 1000000,
    };
    try policy.validateKeyParams(good_params);

    // RSA key too small
    var small_rsa = good_params;
    small_rsa.algorithm = .rsa_encrypt_sign;
    small_rsa.key_bits = 2048;
    try std.testing.expectError(CaError.KeyTooSmall, policy.validateKeyParams(small_rsa));

    // No expiration when required
    var no_exp = good_params;
    no_exp.has_expiration = false;
    try std.testing.expectError(CaError.ExpirationPolicyViolation,
        policy.validateKeyParams(no_exp));
}

test "CertificationLevel properties" {
    try std.testing.expectEqual(@as(u8, 0x13), CertificationLevel.positive.signatureType());
    try std.testing.expectEqualStrings("Positive", CertificationLevel.positive.name());
    try std.testing.expectEqualStrings("Generic", CertificationLevel.generic.name());
}

test "TrustDepth defaults" {
    const org = TrustDepth.orgDefault();
    try std.testing.expectEqual(@as(u8, 120), org.level);
    try std.testing.expectEqual(@as(u8, 0), org.depth);
    try std.testing.expect(org.domain_regex == null);

    const intro = TrustDepth.introducer("example.com");
    try std.testing.expectEqual(@as(u8, 1), intro.depth);
}

test "CertificationRecord validity" {
    const record = CertificationRecord{
        .id = 1,
        .key_fingerprint = std.mem.zeroes([32]u8),
        .fingerprint_len = 20,
        .user_id = "",
        .cert_level = .positive,
        .trust_depth = TrustDepth.orgDefault(),
        .issued_at = 1000,
        .expires_at = 2000,
        .revoked = false,
        .revoked_at = 0,
        .revocation_reason = null,
    };

    // Valid before expiration
    try std.testing.expect(record.isValid(1500));
    // Expired
    try std.testing.expect(!record.isValid(2500));
    try std.testing.expect(record.isExpired(2500));
    // Not yet expired
    try std.testing.expect(!record.isExpired(1500));
}

test "CertificationRecord revoked" {
    const record = CertificationRecord{
        .id = 1,
        .key_fingerprint = std.mem.zeroes([32]u8),
        .fingerprint_len = 20,
        .user_id = "",
        .cert_level = .positive,
        .trust_depth = TrustDepth.orgDefault(),
        .issued_at = 1000,
        .expires_at = 5000,
        .revoked = true,
        .revoked_at = 1500,
        .revocation_reason = null,
    };

    // Revoked record is never valid
    try std.testing.expect(!record.isValid(1200));
}

test "CaDatabase basic operations" {
    const allocator = std.testing.allocator;
    var db = CaDatabase.init();
    defer db.deinit(allocator);

    const uid = try allocator.dupe(u8, "alice@example.com");

    const id = try db.addRecord(allocator, .{
        .id = 0,
        .key_fingerprint = std.mem.zeroes([32]u8),
        .fingerprint_len = 20,
        .user_id = uid,
        .cert_level = .positive,
        .trust_depth = TrustDepth.orgDefault(),
        .issued_at = 1000,
        .expires_at = 5000,
        .revoked = false,
        .revoked_at = 0,
        .revocation_reason = null,
    });

    try std.testing.expectEqual(@as(u64, 1), id);
    try std.testing.expectEqual(@as(usize, 1), db.totalCount());
    try std.testing.expectEqual(@as(usize, 1), db.activeCount(2000));
    try std.testing.expectEqual(@as(usize, 0), db.revokedCount());
}

test "CaDatabase revoke" {
    const allocator = std.testing.allocator;
    var db = CaDatabase.init();
    defer db.deinit(allocator);

    const uid = try allocator.dupe(u8, "bob@example.com");

    const id = try db.addRecord(allocator, .{
        .id = 0,
        .key_fingerprint = std.mem.zeroes([32]u8),
        .fingerprint_len = 20,
        .user_id = uid,
        .cert_level = .positive,
        .trust_depth = TrustDepth.orgDefault(),
        .issued_at = 1000,
        .expires_at = 5000,
        .revoked = false,
        .revoked_at = 0,
        .revocation_reason = null,
    });

    try db.revoke(id, 2000, null);
    try std.testing.expectEqual(@as(usize, 1), db.revokedCount());
    try std.testing.expectEqual(@as(usize, 0), db.activeCount(2000));

    // Double revoke should fail
    try std.testing.expectError(CaError.AlreadyRevoked, db.revoke(id, 2500, null));
}

test "CaDatabase export/import roundtrip" {
    const allocator = std.testing.allocator;
    var db = CaDatabase.init();
    defer db.deinit(allocator);

    const uid1 = try allocator.dupe(u8, "alice@example.com");
    _ = try db.addRecord(allocator, .{
        .id = 0,
        .key_fingerprint = std.mem.zeroes([32]u8),
        .fingerprint_len = 20,
        .user_id = uid1,
        .cert_level = .positive,
        .trust_depth = TrustDepth.orgDefault(),
        .issued_at = 1000,
        .expires_at = 5000,
        .revoked = false,
        .revoked_at = 0,
        .revocation_reason = null,
    });

    const uid2 = try allocator.dupe(u8, "bob@example.com");
    _ = try db.addRecord(allocator, .{
        .id = 0,
        .key_fingerprint = std.mem.zeroes([32]u8),
        .fingerprint_len = 20,
        .user_id = uid2,
        .cert_level = .casual,
        .trust_depth = TrustDepth.orgDefault(),
        .issued_at = 2000,
        .expires_at = 6000,
        .revoked = false,
        .revoked_at = 0,
        .revocation_reason = null,
    });

    // Export
    const exported = try db.exportToBytes(allocator);
    defer allocator.free(exported);

    // Import
    var db2 = try CaDatabase.importFromBytes(allocator, exported);
    defer db2.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), db2.totalCount());
    try std.testing.expectEqual(@as(usize, 2), db2.activeCount(3000));
}

test "extractEmailDomain" {
    try std.testing.expectEqualStrings("example.com",
        extractEmailDomain("Alice <alice@example.com>").?);

    try std.testing.expectEqualStrings("test.org",
        extractEmailDomain("bob@test.org").?);

    try std.testing.expectEqualStrings("foo.bar",
        extractEmailDomain("<user@foo.bar>").?);

    try std.testing.expect(extractEmailDomain("no-email-here") == null);
}

test "asciiEqlIgnoreCase" {
    try std.testing.expect(asciiEqlIgnoreCase("example.com", "Example.Com"));
    try std.testing.expect(asciiEqlIgnoreCase("ABC", "abc"));
    try std.testing.expect(!asciiEqlIgnoreCase("abc", "abd"));
    try std.testing.expect(!asciiEqlIgnoreCase("abc", "ab"));
}

test "CertificationAuthority init and issue" {
    const allocator = std.testing.allocator;
    var ca = CertificationAuthority.init(allocator, CaPolicy.default());
    defer ca.deinit();

    // Initialize with key
    const fp: [20]u8 = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14 };
    try ca.initializeWithKey(&fp, .ed25519, "Test CA <ca@example.com>");

    try std.testing.expect(ca.initialized);

    // Issue certification
    const params = KeyParams{
        .algorithm = .ed25519,
        .key_bits = 256,
        .has_expiration = false,
        .validity_secs = 0,
        .fingerprint = std.mem.zeroes([32]u8),
        .fingerprint_len = 20,
        .creation_time = 1000000,
    };

    const cert_id = try ca.issueCertification(params, "Alice <alice@example.com>", null, null, 1000000);
    try std.testing.expectEqual(@as(u64, 1), cert_id);

    const stats = ca.getStats(1000000);
    try std.testing.expectEqual(@as(usize, 1), stats.total_certifications);
    try std.testing.expectEqual(@as(usize, 1), stats.active_certifications);
}

test "CertificationAuthority revoke" {
    const allocator = std.testing.allocator;
    var ca = CertificationAuthority.init(allocator, CaPolicy.default());
    defer ca.deinit();

    const fp: [20]u8 = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14 };
    try ca.initializeWithKey(&fp, .ed25519, "Test CA <ca@example.com>");

    const params = KeyParams{
        .algorithm = .ed25519,
        .key_bits = 256,
        .has_expiration = false,
        .validity_secs = 0,
        .fingerprint = std.mem.zeroes([32]u8),
        .fingerprint_len = 20,
        .creation_time = 1000000,
    };

    const cert_id = try ca.issueCertification(params, "Bob <bob@example.com>", null, null, 1000000);
    try ca.revokeCertification(cert_id, "Key compromised", 2000000);

    const stats = ca.getStats(2000000);
    try std.testing.expectEqual(@as(usize, 1), stats.revoked_certifications);
    try std.testing.expectEqual(@as(usize, 0), stats.active_certifications);
}

test "CertificationAuthority policy enforcement" {
    const allocator = std.testing.allocator;
    var ca = CertificationAuthority.init(allocator, CaPolicy.strict("example.com"));
    defer ca.deinit();

    const fp: [20]u8 = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14 };
    try ca.initializeWithKey(&fp, .ed25519, "Strict CA <ca@example.com>");

    // Key without expiration should be rejected
    const no_exp_params = KeyParams{
        .algorithm = .ed25519,
        .key_bits = 256,
        .has_expiration = false,
        .validity_secs = 0,
        .fingerprint = std.mem.zeroes([32]u8),
        .fingerprint_len = 20,
        .creation_time = 1000000,
    };
    try std.testing.expectError(CaError.ExpirationPolicyViolation,
        ca.issueCertification(no_exp_params, "Alice <alice@example.com>", null, null, 1000000));

    // Wrong domain should be rejected
    const good_params = KeyParams{
        .algorithm = .ed25519,
        .key_bits = 256,
        .has_expiration = true,
        .validity_secs = 365 * 24 * 3600,
        .fingerprint = std.mem.zeroes([32]u8),
        .fingerprint_len = 20,
        .creation_time = 1000000,
    };
    try std.testing.expectError(CaError.InvalidUserIdDomain,
        ca.issueCertification(good_params, "Bob <bob@other.org>", null, null, 1000000));
}

test "VettingResult" {
    const allocator = std.testing.allocator;
    var result = VettingResult.init();
    defer result.deinit(allocator);

    try std.testing.expect(result.approved);

    try result.addIssue(allocator, .info, "Test info");
    try std.testing.expect(result.approved);

    try result.addIssue(allocator, .rejection, "Test rejection");
    try std.testing.expect(!result.approved);

    try std.testing.expectEqual(@as(usize, 2), result.issues.items.len);

    // Test format
    const formatted = try result.format(allocator);
    defer allocator.free(formatted);
    try std.testing.expect(formatted.len > 0);
}
