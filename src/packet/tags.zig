const std = @import("std");

/// OpenPGP packet tag values as defined in RFC 4880 Section 4.3.
pub const PacketTag = enum(u8) {
    /// Public-Key Encrypted Session Key Packet (Tag 1)
    public_key_encrypted_session_key = 1,
    /// Signature Packet (Tag 2)
    signature = 2,
    /// Symmetric-Key Encrypted Session Key Packet (Tag 3)
    symmetric_key_encrypted_session_key = 3,
    /// One-Pass Signature Packet (Tag 4)
    one_pass_signature = 4,
    /// Secret-Key Packet (Tag 5)
    secret_key = 5,
    /// Public-Key Packet (Tag 6)
    public_key = 6,
    /// Secret-Subkey Packet (Tag 7)
    secret_subkey = 7,
    /// Compressed Data Packet (Tag 8)
    compressed_data = 8,
    /// Symmetrically Encrypted Data Packet (Tag 9)
    symmetrically_encrypted_data = 9,
    /// Marker Packet (Tag 10)
    marker = 10,
    /// Literal Data Packet (Tag 11)
    literal_data = 11,
    /// Trust Packet (Tag 12)
    trust = 12,
    /// User ID Packet (Tag 13)
    user_id = 13,
    /// Public-Subkey Packet (Tag 14)
    public_subkey = 14,
    /// User Attribute Packet (Tag 17)
    user_attribute = 17,
    /// Sym. Encrypted Integrity Protected Data Packet (Tag 18)
    sym_encrypted_integrity_protected_data = 18,
    /// Modification Detection Code Packet (Tag 19)
    modification_detection_code = 19,
    /// Catch-all for unknown/reserved tag values.
    _,

    /// Returns a human-readable name for this packet tag.
    pub fn name(self: PacketTag) []const u8 {
        return switch (self) {
            .public_key_encrypted_session_key => "Public-Key Encrypted Session Key",
            .signature => "Signature",
            .symmetric_key_encrypted_session_key => "Symmetric-Key Encrypted Session Key",
            .one_pass_signature => "One-Pass Signature",
            .secret_key => "Secret-Key",
            .public_key => "Public-Key",
            .secret_subkey => "Secret-Subkey",
            .compressed_data => "Compressed Data",
            .symmetrically_encrypted_data => "Symmetrically Encrypted Data",
            .marker => "Marker",
            .literal_data => "Literal Data",
            .trust => "Trust",
            .user_id => "User ID",
            .public_subkey => "Public-Subkey",
            .user_attribute => "User Attribute",
            .sym_encrypted_integrity_protected_data => "Sym. Encrypted Integrity Protected Data",
            .modification_detection_code => "Modification Detection Code",
            _ => "Unknown",
        };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "PacketTag known values" {
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(PacketTag.public_key_encrypted_session_key));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(PacketTag.signature));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(PacketTag.symmetric_key_encrypted_session_key));
    try std.testing.expectEqual(@as(u8, 4), @intFromEnum(PacketTag.one_pass_signature));
    try std.testing.expectEqual(@as(u8, 5), @intFromEnum(PacketTag.secret_key));
    try std.testing.expectEqual(@as(u8, 6), @intFromEnum(PacketTag.public_key));
    try std.testing.expectEqual(@as(u8, 7), @intFromEnum(PacketTag.secret_subkey));
    try std.testing.expectEqual(@as(u8, 8), @intFromEnum(PacketTag.compressed_data));
    try std.testing.expectEqual(@as(u8, 9), @intFromEnum(PacketTag.symmetrically_encrypted_data));
    try std.testing.expectEqual(@as(u8, 10), @intFromEnum(PacketTag.marker));
    try std.testing.expectEqual(@as(u8, 11), @intFromEnum(PacketTag.literal_data));
    try std.testing.expectEqual(@as(u8, 12), @intFromEnum(PacketTag.trust));
    try std.testing.expectEqual(@as(u8, 13), @intFromEnum(PacketTag.user_id));
    try std.testing.expectEqual(@as(u8, 14), @intFromEnum(PacketTag.public_subkey));
    try std.testing.expectEqual(@as(u8, 17), @intFromEnum(PacketTag.user_attribute));
    try std.testing.expectEqual(@as(u8, 18), @intFromEnum(PacketTag.sym_encrypted_integrity_protected_data));
    try std.testing.expectEqual(@as(u8, 19), @intFromEnum(PacketTag.modification_detection_code));
}

test "PacketTag.name returns correct strings" {
    try std.testing.expectEqualStrings("Signature", PacketTag.signature.name());
    try std.testing.expectEqualStrings("Public-Key", PacketTag.public_key.name());
    try std.testing.expectEqualStrings("Literal Data", PacketTag.literal_data.name());
    try std.testing.expectEqualStrings("User ID", PacketTag.user_id.name());
    try std.testing.expectEqualStrings(
        "Sym. Encrypted Integrity Protected Data",
        PacketTag.sym_encrypted_integrity_protected_data.name(),
    );
}

test "PacketTag unknown value" {
    const unknown: PacketTag = @enumFromInt(60);
    try std.testing.expectEqualStrings("Unknown", unknown.name());
}

test "PacketTag round-trip through integer" {
    const tag = PacketTag.literal_data;
    const int_val = @intFromEnum(tag);
    const back: PacketTag = @enumFromInt(int_val);
    try std.testing.expectEqual(tag, back);
}
