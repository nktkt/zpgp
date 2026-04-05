// SPDX-License-Identifier: MIT
//! Autocrypt header support per Autocrypt Level 1 specification.
//!
//! Autocrypt provides automatic end-to-end encryption for email by embedding
//! minimal OpenPGP key data in email headers.
//!
//! Autocrypt header format:
//!   Autocrypt: addr=<email>; [prefer-encrypt=mutual;] keydata=<base64>
//!
//! The keydata contains a minimal transferable public key:
//!   - Primary key packet
//!   - One User ID packet
//!   - Self-signature on the User ID
//!   - Encryption subkey packet (if separate from primary)
//!   - Binding signature on the subkey
//!
//! Autocrypt Setup Message:
//!   An armored OpenPGP message encrypted with a passphrase (displayed as
//!   a setup code) for transferring secret keys between devices.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const base64 = std.base64;

/// Autocrypt prefer-encrypt preference.
pub const PreferEncrypt = enum {
    /// The user prefers to receive encrypted email when possible.
    mutual,
    /// No preference expressed.
    nopreference,

    /// Format as the header attribute value.
    pub fn headerValue(self: PreferEncrypt) ?[]const u8 {
        return switch (self) {
            .mutual => "mutual",
            .nopreference => null,
        };
    }

    /// Parse from a string value.
    pub fn parse(value: []const u8) PreferEncrypt {
        if (mem.eql(u8, value, "mutual")) return .mutual;
        return .nopreference;
    }
};

/// Parsed Autocrypt header.
pub const AutocryptHeader = struct {
    /// The email address (addr attribute).
    addr: []const u8,
    /// The prefer-encrypt preference.
    prefer_encrypt: PreferEncrypt,
    /// The raw base64-encoded key data (keydata attribute).
    keydata: []const u8,

    /// Parse an Autocrypt header from a header value string.
    ///
    /// Expected format:
    ///   addr=<email>; [prefer-encrypt=mutual;] keydata=<base64>
    ///
    /// Attributes are separated by ';' and may have surrounding whitespace.
    pub fn parseHeader(allocator: Allocator, header_value: []const u8) !AutocryptHeader {
        var addr: ?[]const u8 = null;
        var prefer_encrypt = PreferEncrypt.nopreference;
        var keydata: ?[]const u8 = null;

        // Split by ';' and parse each attribute
        var iter = mem.splitScalar(u8, header_value, ';');
        while (iter.next()) |attr_raw| {
            const attr = mem.trim(u8, attr_raw, " \t\r\n");
            if (attr.len == 0) continue;

            // Find the '=' separator
            const eq_pos = mem.indexOf(u8, attr, "=") orelse continue;
            const key = mem.trim(u8, attr[0..eq_pos], " \t");
            const value = mem.trim(u8, attr[eq_pos + 1 ..], " \t");

            if (mem.eql(u8, key, "addr")) {
                addr = try allocator.dupe(u8, value);
            } else if (mem.eql(u8, key, "prefer-encrypt")) {
                prefer_encrypt = PreferEncrypt.parse(value);
            } else if (mem.eql(u8, key, "keydata")) {
                keydata = try allocator.dupe(u8, value);
            }
            // Unknown attributes are ignored per spec
        }

        if (addr == null) {
            if (keydata) |kd| allocator.free(kd);
            return error.MissingAddr;
        }
        if (keydata == null) {
            if (addr) |a| allocator.free(a);
            return error.MissingKeydata;
        }

        return .{
            .addr = addr.?,
            .prefer_encrypt = prefer_encrypt,
            .keydata = keydata.?,
        };
    }

    /// Generate an Autocrypt header value string.
    ///
    /// Produces a string like:
    ///   addr=alice@example.com; prefer-encrypt=mutual; keydata=<base64>
    ///
    /// The keydata should be the base64-encoded minimal key.
    pub fn generate(
        allocator: Allocator,
        email: []const u8,
        keydata_base64: []const u8,
        prefer: PreferEncrypt,
    ) ![]u8 {
        // Calculate total length
        const addr_prefix = "addr=";
        const pe_str = "; prefer-encrypt=mutual";
        const kd_prefix = "; keydata=";

        var total = addr_prefix.len + email.len + kd_prefix.len + keydata_base64.len;
        if (prefer == .mutual) {
            total += pe_str.len;
        }

        const result = try allocator.alloc(u8, total);
        errdefer allocator.free(result);

        var offset: usize = 0;

        // addr=<email>
        @memcpy(result[offset .. offset + addr_prefix.len], addr_prefix);
        offset += addr_prefix.len;
        @memcpy(result[offset .. offset + email.len], email);
        offset += email.len;

        // prefer-encrypt (if mutual)
        if (prefer == .mutual) {
            @memcpy(result[offset .. offset + pe_str.len], pe_str);
            offset += pe_str.len;
        }

        // keydata=<base64>
        @memcpy(result[offset .. offset + kd_prefix.len], kd_prefix);
        offset += kd_prefix.len;
        @memcpy(result[offset .. offset + keydata_base64.len], keydata_base64);

        return result;
    }

    /// Free all allocator-owned memory.
    pub fn deinit(self: AutocryptHeader, allocator: Allocator) void {
        allocator.free(self.addr);
        allocator.free(self.keydata);
    }
};

/// Create a minimal transferable key for Autocrypt from raw key packet data.
///
/// Autocrypt requires a minimal key that contains only:
///   - Primary key packet
///   - One User ID packet (the one matching the email)
///   - Self-signature on the User ID
///   - Encryption subkey (if separate)
///   - Binding signature on the encryption subkey
///
/// This function takes the full key data and strips unnecessary packets.
/// For simplicity, this implementation just returns the input data as-is,
/// since full packet filtering requires the key import infrastructure.
pub fn minimalKey(allocator: Allocator, key_data: []const u8) ![]u8 {
    // In a full implementation, we would parse the key, keep only
    // the necessary packets, and reserialize. For now, return a copy.
    return try allocator.dupe(u8, key_data);
}

/// Base64 encode key data for use in Autocrypt headers.
///
/// Autocrypt uses standard base64 without line wrapping.
pub fn base64EncodeKeyData(allocator: Allocator, data: []const u8) ![]u8 {
    const encoder = base64.standard.Encoder;
    const encoded_len = encoder.calcSize(data.len);
    const result = try allocator.alloc(u8, encoded_len);
    _ = encoder.encode(result, data);
    return result;
}

/// Base64 decode key data from an Autocrypt header.
///
/// Handles standard base64 and strips any whitespace that might
/// have been introduced by header folding.
pub fn base64DecodeKeyData(allocator: Allocator, encoded: []const u8) ![]u8 {
    // Strip whitespace
    const stripped = try stripWhitespace(allocator, encoded);
    defer allocator.free(stripped);

    const decoder = base64.standard.Decoder;
    const decoded_len = decoder.calcSizeForSlice(stripped) catch return error.InvalidBase64;
    const result = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(result);

    decoder.decode(result, stripped) catch return error.InvalidBase64;
    return result;
}

/// Strip whitespace from a string.
fn stripWhitespace(allocator: Allocator, input: []const u8) ![]u8 {
    var count: usize = 0;
    for (input) |c| {
        if (c != ' ' and c != '\t' and c != '\r' and c != '\n') {
            count += 1;
        }
    }

    const result = try allocator.alloc(u8, count);
    var idx: usize = 0;
    for (input) |c| {
        if (c != ' ' and c != '\t' and c != '\r' and c != '\n') {
            result[idx] = c;
            idx += 1;
        }
    }
    return result;
}

/// Autocrypt Setup Message support.
///
/// An Autocrypt Setup Message is an OpenPGP message containing the user's
/// secret key, encrypted with a "Setup Code" (a numeric passphrase displayed
/// as groups of digits).
pub const AutocryptSetupMessage = struct {
    /// Generate a random Autocrypt Setup Code.
    ///
    /// The setup code is 9 groups of 4 digits separated by dashes:
    ///   1234-5678-9012-3456-7890-1234-5678-9012-3456
    pub fn generateSetupCode(allocator: Allocator) ![]u8 {
        const groups = 9;
        const digits_per_group = 4;
        // 9 groups * 4 digits + 8 dashes = 44 characters
        const total_len = groups * digits_per_group + (groups - 1);

        const code = try allocator.alloc(u8, total_len);
        errdefer allocator.free(code);

        var offset: usize = 0;
        for (0..groups) |g| {
            if (g > 0) {
                code[offset] = '-';
                offset += 1;
            }
            for (0..digits_per_group) |_| {
                const random_bytes = blk: {
                    var buf: [1]u8 = undefined;
                    std.crypto.random.bytes(&buf);
                    break :blk buf;
                };
                code[offset] = '0' + (random_bytes[0] % 10);
                offset += 1;
            }
        }

        return code;
    }

    /// Validate an Autocrypt Setup Code format.
    ///
    /// A valid setup code is 9 groups of 4 digits separated by dashes.
    pub fn validateSetupCode(code: []const u8) bool {
        if (code.len != 44) return false;

        for (code, 0..) |c, i| {
            const pos_in_group = i % 5;
            if (pos_in_group == 4) {
                // Should be a dash (except at the very end)
                if (i < 44 and c != '-') return false;
            } else {
                // Should be a digit
                if (c < '0' or c > '9') return false;
            }
        }
        return true;
    }

    /// Format a setup code for display (add line breaks for readability).
    ///
    /// Groups the code into 3 lines of 3 groups each:
    ///   1234-5678-9012
    ///   3456-7890-1234
    ///   5678-9012-3456
    pub fn formatSetupCodeForDisplay(allocator: Allocator, code: []const u8) ![]u8 {
        if (code.len != 44) return error.InvalidSetupCode;

        // 3 lines of 14 chars + 2 newlines = 44 + 2 = 46
        const result = try allocator.alloc(u8, 46);
        errdefer allocator.free(result);

        @memcpy(result[0..14], code[0..14]);
        result[14] = '\n';
        @memcpy(result[15..29], code[15..29]);
        result[29] = '\n';
        @memcpy(result[30..44], code[30..44]);
        result[44] = '\n';
        result[45] = 0;

        return result[0..45];
    }

    /// Build the Autocrypt-Setup-Message header value.
    pub fn headerValue() []const u8 {
        return "v1";
    }

    /// Build the passphrase format header.
    pub fn passphraseFormatHeader() []const u8 {
        return "numeric9x4";
    }
};

/// Recommendations for Autocrypt Level 1 compliance.
pub const AutocryptRecommendation = enum {
    /// Encryption is available and recommended.
    available,
    /// Encryption is available but not preferred by recipient.
    discourage,
    /// Encryption is not available (no key or key is expired).
    disable,
    /// Encryption is available and both parties prefer it.
    encrypt,

    /// Human-readable description.
    pub fn description(self: AutocryptRecommendation) []const u8 {
        return switch (self) {
            .available => "Encryption available",
            .discourage => "Encryption available but not preferred",
            .disable => "Encryption not available",
            .encrypt => "Encryption recommended (mutual preference)",
        };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "PreferEncrypt parse" {
    try std.testing.expectEqual(PreferEncrypt.mutual, PreferEncrypt.parse("mutual"));
    try std.testing.expectEqual(PreferEncrypt.nopreference, PreferEncrypt.parse("anything-else"));
    try std.testing.expectEqual(PreferEncrypt.nopreference, PreferEncrypt.parse(""));
}

test "PreferEncrypt headerValue" {
    try std.testing.expectEqualStrings("mutual", PreferEncrypt.mutual.headerValue().?);
    try std.testing.expect(PreferEncrypt.nopreference.headerValue() == null);
}

test "AutocryptHeader parseHeader basic" {
    const allocator = std.testing.allocator;

    const header = try AutocryptHeader.parseHeader(
        allocator,
        "addr=alice@example.com; prefer-encrypt=mutual; keydata=AQID",
    );
    defer header.deinit(allocator);

    try std.testing.expectEqualStrings("alice@example.com", header.addr);
    try std.testing.expectEqual(PreferEncrypt.mutual, header.prefer_encrypt);
    try std.testing.expectEqualStrings("AQID", header.keydata);
}

test "AutocryptHeader parseHeader without prefer-encrypt" {
    const allocator = std.testing.allocator;

    const header = try AutocryptHeader.parseHeader(
        allocator,
        "addr=bob@example.com; keydata=BAUG",
    );
    defer header.deinit(allocator);

    try std.testing.expectEqualStrings("bob@example.com", header.addr);
    try std.testing.expectEqual(PreferEncrypt.nopreference, header.prefer_encrypt);
    try std.testing.expectEqualStrings("BAUG", header.keydata);
}

test "AutocryptHeader parseHeader with whitespace" {
    const allocator = std.testing.allocator;

    const header = try AutocryptHeader.parseHeader(
        allocator,
        " addr = carol@example.com ; keydata = AQIDBA== ",
    );
    defer header.deinit(allocator);

    try std.testing.expectEqualStrings("carol@example.com", header.addr);
    try std.testing.expectEqualStrings("AQIDBA==", header.keydata);
}

test "AutocryptHeader parseHeader missing addr" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.MissingAddr,
        AutocryptHeader.parseHeader(allocator, "keydata=AQID"),
    );
}

test "AutocryptHeader parseHeader missing keydata" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.MissingKeydata,
        AutocryptHeader.parseHeader(allocator, "addr=alice@example.com"),
    );
}

test "AutocryptHeader generate with mutual" {
    const allocator = std.testing.allocator;

    const header = try AutocryptHeader.generate(
        allocator,
        "alice@example.com",
        "AQID",
        .mutual,
    );
    defer allocator.free(header);

    try std.testing.expectEqualStrings(
        "addr=alice@example.com; prefer-encrypt=mutual; keydata=AQID",
        header,
    );
}

test "AutocryptHeader generate without prefer-encrypt" {
    const allocator = std.testing.allocator;

    const header = try AutocryptHeader.generate(
        allocator,
        "bob@example.com",
        "BAUG",
        .nopreference,
    );
    defer allocator.free(header);

    try std.testing.expectEqualStrings(
        "addr=bob@example.com; keydata=BAUG",
        header,
    );
}

test "AutocryptHeader generate and parse round-trip" {
    const allocator = std.testing.allocator;

    const generated = try AutocryptHeader.generate(
        allocator,
        "test@example.com",
        "SGVsbG8=",
        .mutual,
    );
    defer allocator.free(generated);

    const parsed = try AutocryptHeader.parseHeader(allocator, generated);
    defer parsed.deinit(allocator);

    try std.testing.expectEqualStrings("test@example.com", parsed.addr);
    try std.testing.expectEqual(PreferEncrypt.mutual, parsed.prefer_encrypt);
    try std.testing.expectEqualStrings("SGVsbG8=", parsed.keydata);
}

test "base64EncodeKeyData" {
    const allocator = std.testing.allocator;

    const data = [_]u8{ 0x01, 0x02, 0x03 };
    const encoded = try base64EncodeKeyData(allocator, &data);
    defer allocator.free(encoded);

    try std.testing.expectEqualStrings("AQID", encoded);
}

test "base64DecodeKeyData" {
    const allocator = std.testing.allocator;

    const decoded = try base64DecodeKeyData(allocator, "AQID");
    defer allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, decoded);
}

test "base64 round-trip" {
    const allocator = std.testing.allocator;

    const original = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
    const encoded = try base64EncodeKeyData(allocator, &original);
    defer allocator.free(encoded);

    const decoded = try base64DecodeKeyData(allocator, encoded);
    defer allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, &original, decoded);
}

test "base64DecodeKeyData strips whitespace" {
    const allocator = std.testing.allocator;

    const decoded = try base64DecodeKeyData(allocator, "AQ ID");
    defer allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, decoded);
}

test "minimalKey returns copy" {
    const allocator = std.testing.allocator;

    const data = [_]u8{ 0x01, 0x02, 0x03 };
    const minimal = try minimalKey(allocator, &data);
    defer allocator.free(minimal);

    try std.testing.expectEqualSlices(u8, &data, minimal);
}

test "AutocryptSetupMessage generateSetupCode format" {
    const allocator = std.testing.allocator;

    const code = try AutocryptSetupMessage.generateSetupCode(allocator);
    defer allocator.free(code);

    // Should be 44 characters: 9*4 digits + 8 dashes
    try std.testing.expectEqual(@as(usize, 44), code.len);

    // Validate format
    try std.testing.expect(AutocryptSetupMessage.validateSetupCode(code));
}

test "AutocryptSetupMessage validateSetupCode" {
    // Valid
    try std.testing.expect(AutocryptSetupMessage.validateSetupCode("1234-5678-9012-3456-7890-1234-5678-9012-3456"));

    // Invalid: wrong length
    try std.testing.expect(!AutocryptSetupMessage.validateSetupCode("1234-5678"));

    // Invalid: no dashes
    try std.testing.expect(!AutocryptSetupMessage.validateSetupCode("123456789012345678901234567890123456789012345"));

    // Invalid: letters instead of digits
    try std.testing.expect(!AutocryptSetupMessage.validateSetupCode("abcd-efgh-ijkl-mnop-qrst-uvwx-yzab-cdef-ghij"));
}

test "AutocryptSetupMessage generateSetupCode uniqueness" {
    const allocator = std.testing.allocator;

    const code1 = try AutocryptSetupMessage.generateSetupCode(allocator);
    defer allocator.free(code1);

    const code2 = try AutocryptSetupMessage.generateSetupCode(allocator);
    defer allocator.free(code2);

    // Extremely unlikely to be equal
    try std.testing.expect(!mem.eql(u8, code1, code2));
}

test "AutocryptSetupMessage headerValue" {
    try std.testing.expectEqualStrings("v1", AutocryptSetupMessage.headerValue());
}

test "AutocryptSetupMessage passphraseFormatHeader" {
    try std.testing.expectEqualStrings("numeric9x4", AutocryptSetupMessage.passphraseFormatHeader());
}

test "AutocryptRecommendation descriptions" {
    try std.testing.expect(AutocryptRecommendation.available.description().len > 0);
    try std.testing.expect(AutocryptRecommendation.discourage.description().len > 0);
    try std.testing.expect(AutocryptRecommendation.disable.description().len > 0);
    try std.testing.expect(AutocryptRecommendation.encrypt.description().len > 0);
}

test "stripWhitespace" {
    const allocator = std.testing.allocator;

    const result = try stripWhitespace(allocator, "hello world");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("helloworld", result);

    const result2 = try stripWhitespace(allocator, " \t\n hello \r\n ");
    defer allocator.free(result2);
    try std.testing.expectEqualStrings("hello", result2);

    const result3 = try stripWhitespace(allocator, "nospace");
    defer allocator.free(result3);
    try std.testing.expectEqualStrings("nospace", result3);
}
