// SPDX-License-Identifier: MIT
//! Real-world interoperability test suite.
//!
//! Tests the integration of:
//! - GnuPG test harness: fixture creation, key validation, armor round-trips
//! - HKP HTTP client: response parsing, URL construction, chunked encoding
//! - GPG agent protocol: Assuan protocol parsing, mock communication
//! - Fuzz harness: smoke tests with small deterministic inputs
//!
//! All tests are self-contained and do not require network access or
//! external programs.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

// Test harness modules
const gpg_harness = @import("test/gpg_harness.zig");
const fuzz_harness = @import("test/fuzz_harness.zig");

// HKP HTTP module
const hkp_http = @import("keyserver/hkp_http.zig");

// GPG agent connection module
const gpg_agent_conn = @import("formats/gpg_agent_conn.zig");

// Protocol parsing
const gpg_agent = @import("formats/gpg_agent.zig");
const AssuanResponse = gpg_agent.AssuanResponse;
const ResponseStatus = gpg_agent.ResponseStatus;

// Armor
const armor = @import("armor/armor.zig");

// ---------------------------------------------------------------------------
// GnuPG test harness tests
// ---------------------------------------------------------------------------

test "gpg_harness: armor roundtrip with various data sizes" {
    const allocator = testing.allocator;

    // Empty
    try testing.expect(try gpg_harness.armorRoundtrip(allocator, ""));

    // Small
    try testing.expect(try gpg_harness.armorRoundtrip(allocator, "hello"));

    // Medium
    var medium: [512]u8 = undefined;
    for (&medium, 0..) |*b, i| b.* = @intCast(i & 0xFF);
    try testing.expect(try gpg_harness.armorRoundtrip(allocator, &medium));

    // Large (4KB)
    var large: [4096]u8 = undefined;
    for (&large, 0..) |*b, i| b.* = @intCast((i * 7 + 3) & 0xFF);
    try testing.expect(try gpg_harness.armorRoundtrip(allocator, &large));
}

test "gpg_harness: armor type preservation" {
    const allocator = testing.allocator;
    const data = "test data for type preservation";

    try testing.expect(try gpg_harness.armorTypeRoundtrip(allocator, data, .public_key));
    try testing.expect(try gpg_harness.armorTypeRoundtrip(allocator, data, .private_key));
    try testing.expect(try gpg_harness.armorTypeRoundtrip(allocator, data, .message));
    try testing.expect(try gpg_harness.armorTypeRoundtrip(allocator, data, .signature));
}

test "gpg_harness: fingerprint determinism on synthetic key body" {
    // Construct a synthetic V4 public key packet body
    const body = [_]u8{
        4,                      // version
        0x65, 0x5E, 0xA0, 0x00, // creation_time = 2023-11-22T...
        1,                      // algorithm (RSA encrypt+sign)
        0x00, 0x10,             // MPI bit count = 16
        0xC0, 0x03,             // MPI data (n)
        0x00, 0x08,             // MPI bit count = 8
        0x03,                   // MPI data (e=3)
    };
    try testing.expect(gpg_harness.verifyFingerprintDeterminism(&body));
    try testing.expect(gpg_harness.verifyKeyIdExtraction(&body));
}

test "gpg_harness: packet structure validation" {
    // A valid packet sequence: tag 6 (public key) + tag 13 (user id)
    const data = [_]u8{
        0xC0 | 6, 3, 4, 0x00, 0x01, // tag 6, len 3, version 4, partial creation_time
        0xC0 | 13, 4, 'T', 'e', 's', 't', // tag 13, len 4, "Test"
    };
    const result = gpg_harness.validateBinaryPacketStructure(&data);
    try testing.expect(result.valid);
    try testing.expect(result.has_public_key);
    try testing.expect(result.has_user_id);
    try testing.expectEqual(@as(usize, 2), result.tag_count);
}

test "gpg_harness: MPI roundtrip small values" {
    const allocator = testing.allocator;
    try testing.expect(try gpg_harness.mpiRoundtrip(allocator, &[_]u8{0x01}));
    try testing.expect(try gpg_harness.mpiRoundtrip(allocator, &[_]u8{0x80}));
    try testing.expect(try gpg_harness.mpiRoundtrip(allocator, &[_]u8{ 0x01, 0x00, 0x01 }));
}

test "gpg_harness: format fingerprint and key ID" {
    const allocator = testing.allocator;

    var fp: [20]u8 = undefined;
    for (&fp, 0..) |*b, i| b.* = @intCast(i * 17 & 0xFF);

    const hex = try gpg_harness.formatFingerprint(allocator, fp);
    defer allocator.free(hex);
    try testing.expectEqual(@as(usize, 40), hex.len);

    var kid: [8]u8 = undefined;
    @memcpy(&kid, fp[12..20]);
    const kid_hex = try gpg_harness.formatKeyId(allocator, kid);
    defer allocator.free(kid_hex);
    try testing.expectEqual(@as(usize, 16), kid_hex.len);
}

test "gpg_harness: verify armor markers" {
    const valid_armor =
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" ++
        "Version: zpgp 0.1\n\n" ++
        "dGVzdA==\n" ++
        "=AAAA\n" ++
        "-----END PGP PUBLIC KEY BLOCK-----\n";
    try testing.expect(gpg_harness.verifyArmorMarkers(valid_armor));
    try testing.expect(!gpg_harness.verifyArmorMarkers("no markers here"));
}

// ---------------------------------------------------------------------------
// HKP HTTP client tests
// ---------------------------------------------------------------------------

test "hkp_http: URL parsing for keyserver URLs" {
    const url1 = try hkp_http.parseUrl("hkp://keys.openpgp.org");
    try testing.expectEqual(hkp_http.Scheme.hkp, url1.scheme);
    try testing.expectEqualStrings("keys.openpgp.org", url1.host);
    try testing.expectEqual(@as(u16, 11371), url1.port);

    const url2 = try hkp_http.parseUrl("hkps://keys.openpgp.org");
    try testing.expect(url2.scheme.requiresTls());

    const url3 = try hkp_http.parseUrl("http://localhost:8080/custom");
    try testing.expectEqual(@as(u16, 8080), url3.port);
    try testing.expectEqualStrings("/custom", url3.path);
}

test "hkp_http: HTTP response parsing with mock data" {
    const allocator = testing.allocator;

    // Simulate a keyserver returning an armored key
    const mock_response =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: application/pgp-keys\r\n" ++
        "Content-Length: 50\r\n" ++
        "\r\n" ++
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" ++
        "dGVzdA==\n-----END PGP PUBLIC KEY BLOCK-----";

    var resp = try hkp_http.parseHttpResponse(allocator, mock_response);
    defer resp.deinit(allocator);

    try testing.expectEqual(@as(u16, 200), resp.status_code);
    try testing.expect(resp.isSuccess());
    try testing.expect(mem.indexOf(u8, resp.body, "BEGIN PGP") != null);
}

test "hkp_http: HTTP response parsing 404" {
    const allocator = testing.allocator;

    const mock_response =
        "HTTP/1.1 404 Not Found\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "\r\n" ++
        "Key not found";

    var resp = try hkp_http.parseHttpResponse(allocator, mock_response);
    defer resp.deinit(allocator);

    try testing.expectEqual(@as(u16, 404), resp.status_code);
    try testing.expect(!resp.isSuccess());
}

test "hkp_http: chunked transfer encoding parsing" {
    const allocator = testing.allocator;

    const chunked_response =
        "HTTP/1.1 200 OK\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n" ++
        "1A\r\n" ++
        "-----BEGIN PGP PUBLIC KEY" ++
        "\r\n" ++
        "E\r\n" ++
        " BLOCK-----\r\n" ++
        "\r\n" ++
        "0\r\n" ++
        "\r\n";

    var resp = try hkp_http.parseHttpResponse(allocator, chunked_response);
    defer resp.deinit(allocator);

    try testing.expectEqual(@as(u16, 200), resp.status_code);
    try testing.expectEqualStrings("-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n", resp.body);
}

test "hkp_http: HKP transport client URL building" {
    const allocator = testing.allocator;

    const client = try hkp_http.HkpTransportClient.init(allocator, "hkp://keys.openpgp.org");

    const lookup_url = try client.buildLookupUrl(allocator, "0xDEADBEEF");
    defer allocator.free(lookup_url);
    try testing.expect(mem.indexOf(u8, lookup_url, "op=get") != null);
    try testing.expect(mem.indexOf(u8, lookup_url, "0xDEADBEEF") != null);
    try testing.expect(mem.indexOf(u8, lookup_url, "options=mr") != null);

    const search_url = try client.buildSearchUrl(allocator, "alice@example.com");
    defer allocator.free(search_url);
    try testing.expect(mem.indexOf(u8, search_url, "op=index") != null);
}

test "hkp_http: HKP transport client request building" {
    const allocator = testing.allocator;

    const client = try hkp_http.HkpTransportClient.init(allocator, "hkp://localhost:11371");

    const get_req = try client.buildKeyLookupRequest(allocator, "0xABCD1234");
    defer allocator.free(get_req);
    try testing.expect(mem.startsWith(u8, get_req, "GET "));
    try testing.expect(mem.indexOf(u8, get_req, "HTTP/1.1") != null);

    const post_req = try client.buildKeyUploadRequest(allocator, "armored key data");
    defer allocator.free(post_req);
    try testing.expect(mem.startsWith(u8, post_req, "POST "));
    try testing.expect(mem.indexOf(u8, post_req, "keytext=") != null);
}

test "hkp_http: extract armored key from response body" {
    const body =
        "Content before key\n" ++
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" ++
        "AABBCCDD\n" ++
        "-----END PGP PUBLIC KEY BLOCK-----\n" ++
        "Content after key\n";

    const key = hkp_http.HkpTransportClient.extractArmoredKey(body);
    try testing.expect(key != null);
    try testing.expect(mem.startsWith(u8, key.?, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));
}

// ---------------------------------------------------------------------------
// GPG agent protocol tests
// ---------------------------------------------------------------------------

test "gpg_agent_conn: readLine and readFullResponse" {
    const allocator = testing.allocator;

    // Simulate a gpg-agent session
    const agent_output = "D 2.4.3\nOK\n";
    var stream = std.io.fixedBufferStream(agent_output);
    const r = stream.reader();

    var resp = try gpg_agent_conn.readFullResponse(allocator, r);
    defer resp.deinit(allocator);

    try testing.expect(resp.isOk());
    try testing.expect(resp.data != null);
    try testing.expectEqualStrings("2.4.3", resp.data.?);
}

test "gpg_agent_conn: mock HAVEKEY command" {
    const allocator = testing.allocator;
    var mock = gpg_agent_conn.MockAgentConnection.init(allocator, "OK\n");
    defer mock.deinit(allocator);

    var r = mock.reader();
    var w = mock.writer(allocator);

    const result = try gpg_agent_conn.checkHaveKey(allocator, &w, &r, "AABBCCDDEE");
    try testing.expect(result);
    // Verify the command was sent
    try testing.expect(mem.indexOf(u8, mock.output.items, "HAVEKEY AABBCCDDEE") != null);
}

test "gpg_agent_conn: mock CLEAR_PASSPHRASE" {
    const allocator = testing.allocator;
    var mock = gpg_agent_conn.MockAgentConnection.init(allocator, "OK\n");
    defer mock.deinit(allocator);

    var r = mock.reader();
    var w = mock.writer(allocator);

    const result = try gpg_agent_conn.clearCachedPassphrase(allocator, &w, &r, "my-cache");
    try testing.expect(result);
    try testing.expect(mem.indexOf(u8, mock.output.items, "CLEAR_PASSPHRASE my-cache") != null);
}

test "gpg_agent_conn: mock agent version query" {
    const allocator = testing.allocator;
    var mock = gpg_agent_conn.MockAgentConnection.init(allocator, "D 2.2.40\nOK\n");
    defer mock.deinit(allocator);

    var r = mock.reader();
    var w = mock.writer(allocator);

    const version = try gpg_agent_conn.getAgentVersion(allocator, &w, &r);
    defer if (version) |v| allocator.free(v);

    try testing.expect(version != null);
    try testing.expectEqualStrings("2.2.40", version.?);
}

test "gpg_agent_conn: Assuan response parsing edge cases" {
    const allocator = testing.allocator;

    // ERR with no description
    var r1 = try AssuanResponse.parse(allocator, "ERR 67108922");
    defer r1.deinit(allocator);
    try testing.expectEqual(ResponseStatus.err, r1.status);
    try testing.expectEqual(@as(u32, 67108922), r1.error_code);
    try testing.expect(r1.data == null);

    // S with keyword only
    var r2 = try AssuanResponse.parse(allocator, "S KEYPAIRINFO");
    defer r2.deinit(allocator);
    try testing.expectEqual(ResponseStatus.status, r2.status);
    try testing.expectEqualStrings("KEYPAIRINFO", r2.keyword.?);

    // D with percent-encoded data
    var r3 = try AssuanResponse.parse(allocator, "D hello%0Aworld");
    defer r3.deinit(allocator);
    try testing.expectEqual(ResponseStatus.data_line, r3.status);
    try testing.expectEqualStrings("hello\nworld", r3.data.?);
}

test "gpg_agent_conn: socket path validation" {
    try testing.expect(gpg_agent_conn.isValidSocketPath("/home/user/.gnupg/S.gpg-agent"));
    try testing.expect(gpg_agent_conn.isValidSocketPath("/run/user/1000/gnupg/S.gpg-agent"));
    try testing.expect(!gpg_agent_conn.isValidSocketPath(""));
    try testing.expect(!gpg_agent_conn.isValidSocketPath("relative"));
    try testing.expect(!gpg_agent_conn.isValidSocketPath("/ends/with/"));
}

test "gpg_agent_conn: mock PKSIGN sequence" {
    const allocator = testing.allocator;

    // Simulate: SIGKEY -> OK, SETHASH -> OK, PKSIGN -> D <sig> + OK
    const responses = "OK\nOK\nD deadbeef\nOK\n";
    var mock = gpg_agent_conn.MockAgentConnection.init(allocator, responses);
    defer mock.deinit(allocator);

    var r = mock.reader();
    var w = mock.writer(allocator);

    const sig = try gpg_agent_conn.performSign(allocator, &w, &r, "KEYGRIP1234", 8, "AABBCCDD");
    defer if (sig) |s| allocator.free(s);

    try testing.expect(sig != null);
    try testing.expectEqualStrings("deadbeef", sig.?);

    // Verify commands were sent in order
    const sent = mock.output.items;
    const sigkey_pos = mem.indexOf(u8, sent, "SIGKEY KEYGRIP1234");
    const sethash_pos = mem.indexOf(u8, sent, "SETHASH 8 AABBCCDD");
    const pksign_pos = mem.indexOf(u8, sent, "PKSIGN");
    try testing.expect(sigkey_pos != null);
    try testing.expect(sethash_pos != null);
    try testing.expect(pksign_pos != null);
    try testing.expect(sigkey_pos.? < sethash_pos.?);
    try testing.expect(sethash_pos.? < pksign_pos.?);
}

// ---------------------------------------------------------------------------
// Fuzz harness smoke tests
// ---------------------------------------------------------------------------

test "fuzz: armor decoder smoke test" {
    const allocator = testing.allocator;
    try fuzz_harness.runFuzzBatch(allocator, fuzz_harness.fuzzArmorDecoder, void, 42, 20, 64);
}

test "fuzz: MPI reader smoke test" {
    const allocator = testing.allocator;
    try fuzz_harness.runFuzzBatch(allocator, fuzz_harness.fuzzMpiReader, void, 42, 20, 32);
}

test "fuzz: packet parser smoke test" {
    const allocator = testing.allocator;
    try fuzz_harness.runFuzzBatch(allocator, fuzz_harness.fuzzPacketParser, void, 42, 20, 128);
}

test "fuzz: CRC-24 smoke test" {
    const allocator = testing.allocator;
    try fuzz_harness.runFuzzBatch(allocator, fuzz_harness.fuzzCrc24, void, 42, 20, 256);
}

test "fuzz: property armor roundtrip" {
    const allocator = testing.allocator;

    const test_inputs = [_][]const u8{
        "", "a", "hello world",
        &([_]u8{0xFF} ** 16),
        &([_]u8{0x00} ** 32),
    };

    for (test_inputs) |input| {
        try testing.expect(try fuzz_harness.propertyArmorRoundtrip(allocator, input));
    }
}

test "fuzz: property MPI roundtrip" {
    const allocator = testing.allocator;

    const test_inputs = [_][]const u8{
        "",
        &[_]u8{0x01},
        &[_]u8{0xFF},
        &[_]u8{ 0x01, 0x00, 0x00, 0x00 },
        &([_]u8{0x7F} ** 64),
    };

    for (test_inputs) |input| {
        try testing.expect(try fuzz_harness.propertyMpiRoundtrip(allocator, input));
    }
}

test "fuzz: property CRC-24 determinism" {
    const test_inputs = [_][]const u8{
        "",
        "test",
        &([_]u8{0xAA} ** 1000),
    };

    for (test_inputs) |input| {
        try testing.expect(fuzz_harness.propertyCrc24Deterministic(input));
    }
}
