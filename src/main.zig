const std = @import("std");
const zpgp = @import("zpgp");

const armor = zpgp.armor;
const import_export = zpgp.import_export;
const keyring_mod = zpgp.keyring;

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printUsage();
        return;
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "keygen")) {
        cmdKeygen(args[2..]);
    } else if (std.mem.eql(u8, command, "sign")) {
        cmdSign(args[2..]);
    } else if (std.mem.eql(u8, command, "verify")) {
        cmdVerify(args[2..]);
    } else if (std.mem.eql(u8, command, "encrypt")) {
        cmdEncrypt(args[2..]);
    } else if (std.mem.eql(u8, command, "decrypt")) {
        cmdDecrypt(args[2..]);
    } else if (std.mem.eql(u8, command, "key")) {
        if (args.len < 3) {
            printKeyUsage();
            return;
        }
        const subcmd = args[2];
        if (std.mem.eql(u8, subcmd, "import")) {
            try cmdKeyImport(allocator, args[3..]);
        } else if (std.mem.eql(u8, subcmd, "export")) {
            cmdKeyExport(args[3..]);
        } else if (std.mem.eql(u8, subcmd, "list")) {
            try cmdKeyList(allocator, args[3..]);
        } else {
            printKeyUsage();
        }
    } else if (std.mem.eql(u8, command, "armor")) {
        try cmdArmor(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "dearmor")) {
        try cmdDearmor(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "version")) {
        printVersion();
    } else if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        printUsage();
    } else {
        const stderr = std.fs.File.stderr();
        const w = stderr.deprecatedWriter();
        w.print("Unknown command: {s}\n\n", .{command}) catch {};
        printUsage();
    }
}

fn printUsage() void {
    const stderr = std.fs.File.stderr();
    stderr.writeAll(
        \\Usage: zpgp <command> [options]
        \\
        \\Commands:
        \\  keygen    Generate a new key pair
        \\  sign      Sign a file
        \\  verify    Verify a signature
        \\  encrypt   Encrypt a file
        \\  decrypt   Decrypt a file
        \\  key       Key management (import, export, list)
        \\  armor     ASCII-armor binary data
        \\  dearmor   Remove ASCII armor
        \\  version   Show version information
        \\  help      Show this help message
        \\
    ) catch {};
}

fn printKeyUsage() void {
    const stderr = std.fs.File.stderr();
    stderr.writeAll(
        \\Usage: zpgp key <subcommand> [options]
        \\
        \\Subcommands:
        \\  import <file>    Import a key from a file
        \\  export <file>    Export a key to a file
        \\  list <file>      List keys in a keyring file
        \\
    ) catch {};
}

fn printVersion() void {
    const stdout = std.fs.File.stdout();
    stdout.writeAll("zpgp 0.1.0 - OpenPGP (RFC 4880) implementation in Zig\n") catch {};
}

// ---------------------------------------------------------------------------
// Key management commands
// ---------------------------------------------------------------------------

fn cmdKeyImport(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.fs.File.stdout();
    const w = stdout.deprecatedWriter();
    const stderr = std.fs.File.stderr();

    if (args.len < 1) {
        stderr.writeAll("Usage: zpgp key import <file>\n") catch {};
        return;
    }

    const file_path = args[0];
    const data = readInputFile(allocator, file_path) catch |err| {
        const ew = stderr.deprecatedWriter();
        ew.print("Error reading file '{s}': {}\n", .{ file_path, err }) catch {};
        return;
    };
    defer allocator.free(data);

    // Try to import the key
    var key = import_export.importPublicKeyAuto(allocator, data) catch |err| {
        const ew = stderr.deprecatedWriter();
        ew.print("Error importing key: {}\n", .{err}) catch {};
        return;
    };
    defer key.deinit(allocator);

    // Display key information
    try w.writeAll("Key imported successfully:\n");

    const fp = key.fingerprint();
    try w.writeAll("  Fingerprint: ");
    for (fp) |byte| {
        try w.print("{X:0>2}", .{byte});
    }
    try w.writeAll("\n");

    try w.print("  Algorithm:   {s}\n", .{key.primary_key.algorithm.name()});
    try w.print("  Created:     {d}\n", .{key.primary_key.creation_time});
    try w.print("  User IDs:    {d}\n", .{key.user_ids.items.len});

    for (key.user_ids.items, 0..) |uid, i| {
        try w.print("    [{d}] {s}\n", .{ i, uid.user_id.id });
    }

    try w.print("  Subkeys:     {d}\n", .{key.subkeys.items.len});
}

fn cmdKeyList(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.fs.File.stdout();
    const w = stdout.deprecatedWriter();
    const stderr = std.fs.File.stderr();

    if (args.len < 1) {
        stderr.writeAll("Usage: zpgp key list <file>\n") catch {};
        return;
    }

    const file_path = args[0];
    const data = readInputFile(allocator, file_path) catch |err| {
        const ew = stderr.deprecatedWriter();
        ew.print("Error reading file '{s}': {}\n", .{ file_path, err }) catch {};
        return;
    };
    defer allocator.free(data);

    // Detect if armored and decode
    const decoded = decodeIfArmored(allocator, data);
    const binary_data: []const u8 = decoded.binary;
    defer {
        if (decoded.owned_data) |d| allocator.free(d);
        if (decoded.owned_headers) |hdrs| {
            for (hdrs) |hdr| {
                allocator.free(hdr.name);
                allocator.free(hdr.value);
            }
            allocator.free(hdrs);
        }
    }

    // Load keys into a keyring
    var kr = keyring_mod.Keyring.init(allocator);
    defer kr.deinit();

    const loaded = kr.loadFromBytes(binary_data) catch |err| {
        const ew = stderr.deprecatedWriter();
        ew.print("Error loading keys: {}\n", .{err}) catch {};
        return;
    };

    try w.print("Found {d} key(s):\n\n", .{loaded});

    for (kr.keys.items, 0..) |*key, idx| {
        try w.print("Key #{d}:\n", .{idx + 1});

        const fp = key.fingerprint();
        try w.writeAll("  Fingerprint: ");
        for (fp) |byte| {
            try w.print("{X:0>2}", .{byte});
        }
        try w.writeAll("\n");

        const kid = key.keyId();
        try w.writeAll("  Key ID:      ");
        for (kid) |byte| {
            try w.print("{X:0>2}", .{byte});
        }
        try w.writeAll("\n");

        try w.print("  Algorithm:   {s}\n", .{key.primary_key.algorithm.name()});
        try w.print("  Created:     {d}\n", .{key.primary_key.creation_time});

        for (key.user_ids.items) |uid| {
            try w.print("  User ID:     {s}\n", .{uid.user_id.id});
        }

        try w.print("  Subkeys:     {d}\n", .{key.subkeys.items.len});
        try w.writeAll("\n");
    }
}

fn cmdKeyExport(args: []const []const u8) void {
    _ = args;
    const stderr = std.fs.File.stderr();
    stderr.writeAll("key export: not yet implemented\n") catch {};
}

// ---------------------------------------------------------------------------
// Armor/dearmor commands
// ---------------------------------------------------------------------------

fn cmdArmor(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.fs.File.stdout();
    const stderr = std.fs.File.stderr();

    // Determine armor type from --type flag, default to "message"
    var armor_type: armor.ArmorType = .message;
    var file_path: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--type") or std.mem.eql(u8, args[i], "-t")) {
            i += 1;
            if (i < args.len) {
                if (std.mem.eql(u8, args[i], "public-key")) {
                    armor_type = .public_key;
                } else if (std.mem.eql(u8, args[i], "private-key")) {
                    armor_type = .private_key;
                } else if (std.mem.eql(u8, args[i], "signature")) {
                    armor_type = .signature;
                } else if (std.mem.eql(u8, args[i], "message")) {
                    armor_type = .message;
                } else {
                    const ew = stderr.deprecatedWriter();
                    ew.print("Unknown armor type: {s}\n", .{args[i]}) catch {};
                    return;
                }
            }
        } else {
            file_path = args[i];
        }
    }

    const data = readInputFile(allocator, file_path orelse "-") catch |err| {
        const ew = stderr.deprecatedWriter();
        ew.print("Error reading input: {}\n", .{err}) catch {};
        return;
    };
    defer allocator.free(data);

    const headers = [_]armor.Header{
        .{ .name = "Version", .value = "zpgp 0.1" },
    };

    const armored = armor.encode(allocator, data, armor_type, &headers) catch |err| {
        const ew = stderr.deprecatedWriter();
        ew.print("Error encoding armor: {}\n", .{err}) catch {};
        return;
    };
    defer allocator.free(armored);

    try stdout.writeAll(armored);
}

fn cmdDearmor(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.fs.File.stdout();
    const stderr = std.fs.File.stderr();

    const file_path: []const u8 = if (args.len > 0) args[0] else "-";

    const data = readInputFile(allocator, file_path) catch |err| {
        const ew = stderr.deprecatedWriter();
        ew.print("Error reading input: {}\n", .{err}) catch {};
        return;
    };
    defer allocator.free(data);

    var result = armor.decode(allocator, data) catch |err| {
        const ew = stderr.deprecatedWriter();
        ew.print("Error decoding armor: {}\n", .{err}) catch {};
        return;
    };
    defer result.deinit();

    try stdout.writeAll(result.data);
}

// ---------------------------------------------------------------------------
// Stub commands
// ---------------------------------------------------------------------------

fn cmdKeygen(args: []const []const u8) void {
    _ = args;
    const stderr = std.fs.File.stderr();
    stderr.writeAll("keygen: not yet implemented\n") catch {};
}

fn cmdSign(args: []const []const u8) void {
    _ = args;
    const stderr = std.fs.File.stderr();
    stderr.writeAll("sign: not yet implemented\n") catch {};
}

fn cmdVerify(args: []const []const u8) void {
    _ = args;
    const stderr = std.fs.File.stderr();
    stderr.writeAll("verify: not yet implemented\n") catch {};
}

fn cmdEncrypt(args: []const []const u8) void {
    _ = args;
    const stderr = std.fs.File.stderr();
    stderr.writeAll("encrypt: not yet implemented\n") catch {};
}

fn cmdDecrypt(args: []const []const u8) void {
    _ = args;
    const stderr = std.fs.File.stderr();
    stderr.writeAll("decrypt: not yet implemented\n") catch {};
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DecodedInput = struct {
    binary: []const u8,
    owned_data: ?[]u8,
    owned_headers: ?[]armor.Header,
};

/// If the data looks armored, decode it. Otherwise return as-is.
fn decodeIfArmored(allocator: std.mem.Allocator, data: []const u8) DecodedInput {
    if (data.len > 10 and std.mem.startsWith(u8, data, "-----BEGIN ")) {
        const result = armor.decode(allocator, data) catch {
            return .{ .binary = data, .owned_data = null, .owned_headers = null };
        };
        return .{
            .binary = result.data,
            .owned_data = result.data,
            .owned_headers = result.headers,
        };
    }
    return .{ .binary = data, .owned_data = null, .owned_headers = null };
}

/// Read input data from a file path or stdin (if path is "-").
fn readInputFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    if (std.mem.eql(u8, path, "-")) {
        // Read from stdin
        const stdin = std.fs.File.stdin();
        return try stdin.readToEndAlloc(allocator, 10 * 1024 * 1024); // 10 MB limit
    } else {
        return try std.fs.cwd().readFileAlloc(allocator, path, 10 * 1024 * 1024);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "readInputFile reads a file" {
    // This test just verifies the function signature compiles.
    // Actual I/O tests would require test fixtures.
    const allocator = std.testing.allocator;
    const result = readInputFile(allocator, "/nonexistent/path/file.txt");
    try std.testing.expectError(error.FileNotFound, result);
}
