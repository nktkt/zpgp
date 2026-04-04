// SPDX-License-Identifier: MIT
//! OpenPGP Signature Type classification per RFC 4880 Section 5.2.1.

const std = @import("std");

/// RFC 4880 Section 5.2.1 — Signature types.
pub const SignatureType = enum(u8) {
    /// Signature of a binary document (0x00).
    binary_document = 0x00,
    /// Signature of a canonical text document (0x01).
    canonical_text = 0x01,
    /// Standalone signature (0x02).
    standalone = 0x02,
    /// Generic certification of a User ID and Public-Key packet (0x10).
    generic_certification = 0x10,
    /// Persona certification (0x11).
    persona_certification = 0x11,
    /// Casual certification (0x12).
    casual_certification = 0x12,
    /// Positive certification (0x13).
    positive_certification = 0x13,
    /// Subkey binding signature (0x18).
    subkey_binding = 0x18,
    /// Primary key binding signature (0x19).
    primary_key_binding = 0x19,
    /// Signature directly on a key (0x1F).
    direct_key = 0x1F,
    /// Key revocation signature (0x20).
    key_revocation = 0x20,
    /// Subkey revocation signature (0x28).
    subkey_revocation = 0x28,
    /// Certification revocation signature (0x30).
    certification_revocation = 0x30,
    /// Timestamp signature (0x40).
    timestamp = 0x40,
    /// Third-Party Confirmation signature (0x50).
    third_party_confirmation = 0x50,
    _,

    /// Human-readable name for the signature type.
    pub fn name(self: SignatureType) []const u8 {
        return switch (self) {
            .binary_document => "Signature of a binary document",
            .canonical_text => "Signature of a canonical text document",
            .standalone => "Standalone signature",
            .generic_certification => "Generic certification",
            .persona_certification => "Persona certification",
            .casual_certification => "Casual certification",
            .positive_certification => "Positive certification",
            .subkey_binding => "Subkey binding signature",
            .primary_key_binding => "Primary key binding signature",
            .direct_key => "Signature directly on a key",
            .key_revocation => "Key revocation signature",
            .subkey_revocation => "Subkey revocation signature",
            .certification_revocation => "Certification revocation signature",
            .timestamp => "Timestamp signature",
            .third_party_confirmation => "Third-Party Confirmation signature",
            _ => "Unknown signature type",
        };
    }

    /// Whether this is a certification signature (0x10-0x13).
    pub fn isCertification(self: SignatureType) bool {
        const v = @intFromEnum(self);
        return v >= 0x10 and v <= 0x13;
    }

    /// Whether this is a revocation signature (0x20, 0x28, 0x30).
    pub fn isRevocation(self: SignatureType) bool {
        return switch (self) {
            .key_revocation, .subkey_revocation, .certification_revocation => true,
            else => false,
        };
    }

    /// Whether this is a document signature (binary or text).
    pub fn isDocumentSignature(self: SignatureType) bool {
        return switch (self) {
            .binary_document, .canonical_text => true,
            else => false,
        };
    }

    /// Whether this is a key binding signature (subkey or primary key binding).
    pub fn isKeyBinding(self: SignatureType) bool {
        return switch (self) {
            .subkey_binding, .primary_key_binding => true,
            else => false,
        };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "SignatureType name" {
    try std.testing.expectEqualStrings(
        "Signature of a binary document",
        SignatureType.binary_document.name(),
    );
    try std.testing.expectEqualStrings(
        "Positive certification",
        SignatureType.positive_certification.name(),
    );
    try std.testing.expectEqualStrings(
        "Key revocation signature",
        SignatureType.key_revocation.name(),
    );
}

test "SignatureType unknown" {
    const unknown: SignatureType = @enumFromInt(0xFF);
    try std.testing.expectEqualStrings("Unknown signature type", unknown.name());
    try std.testing.expect(!unknown.isCertification());
    try std.testing.expect(!unknown.isRevocation());
    try std.testing.expect(!unknown.isDocumentSignature());
}

test "SignatureType isCertification" {
    try std.testing.expect(SignatureType.generic_certification.isCertification());
    try std.testing.expect(SignatureType.persona_certification.isCertification());
    try std.testing.expect(SignatureType.casual_certification.isCertification());
    try std.testing.expect(SignatureType.positive_certification.isCertification());
    try std.testing.expect(!SignatureType.binary_document.isCertification());
    try std.testing.expect(!SignatureType.key_revocation.isCertification());
    try std.testing.expect(!SignatureType.subkey_binding.isCertification());
}

test "SignatureType isRevocation" {
    try std.testing.expect(SignatureType.key_revocation.isRevocation());
    try std.testing.expect(SignatureType.subkey_revocation.isRevocation());
    try std.testing.expect(SignatureType.certification_revocation.isRevocation());
    try std.testing.expect(!SignatureType.binary_document.isRevocation());
    try std.testing.expect(!SignatureType.positive_certification.isRevocation());
}

test "SignatureType isDocumentSignature" {
    try std.testing.expect(SignatureType.binary_document.isDocumentSignature());
    try std.testing.expect(SignatureType.canonical_text.isDocumentSignature());
    try std.testing.expect(!SignatureType.standalone.isDocumentSignature());
    try std.testing.expect(!SignatureType.positive_certification.isDocumentSignature());
}

test "SignatureType isKeyBinding" {
    try std.testing.expect(SignatureType.subkey_binding.isKeyBinding());
    try std.testing.expect(SignatureType.primary_key_binding.isKeyBinding());
    try std.testing.expect(!SignatureType.binary_document.isKeyBinding());
}

test "SignatureType integer values" {
    try std.testing.expectEqual(@as(u8, 0x00), @intFromEnum(SignatureType.binary_document));
    try std.testing.expectEqual(@as(u8, 0x13), @intFromEnum(SignatureType.positive_certification));
    try std.testing.expectEqual(@as(u8, 0x20), @intFromEnum(SignatureType.key_revocation));
    try std.testing.expectEqual(@as(u8, 0x50), @intFromEnum(SignatureType.third_party_confirmation));
}

test "SignatureType round-trip from u8" {
    const t: SignatureType = @enumFromInt(0x18);
    try std.testing.expectEqual(SignatureType.subkey_binding, t);
    try std.testing.expectEqualStrings("Subkey binding signature", t.name());
}
