const std = @import("std");
const zpgp = @import("zpgp");

const armor = zpgp.armor;
const import_export = zpgp.import_export;
const keyring_mod = zpgp.keyring;
const compose = zpgp.compose;
const decompose_mod = zpgp.decompose;
const enums = zpgp.enums;
const keygen_mod = zpgp.keygen;
const PublicKeyAlgorithm = zpgp.PublicKeyAlgorithm;

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
        cmdKeygen(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "sign")) {
        cmdSign(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "verify")) {
        cmdVerify(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "encrypt")) {
        cmdEncrypt(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "decrypt")) {
        cmdDecrypt(allocator, args[2..]);
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

fn cmdKeygen(allocator: std.mem.Allocator, args: []const []const u8) void {
    const stdout = std.fs.File.stdout();
    const stderr = std.fs.File.stderr();
    const ew = stderr.deprecatedWriter();

    var name_str: ?[]const u8 = null;
    var email_str: ?[]const u8 = null;
    var algo_str: []const u8 = "rsa";
    var bits: u32 = 2048;
    var passphrase: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;
    var secret_output_path: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--name") or std.mem.eql(u8, args[i], "-n")) {
            i += 1;
            if (i < args.len) name_str = args[i];
        } else if (std.mem.eql(u8, args[i], "--email") or std.mem.eql(u8, args[i], "-e")) {
            i += 1;
            if (i < args.len) email_str = args[i];
        } else if (std.mem.eql(u8, args[i], "--algo") or std.mem.eql(u8, args[i], "-a")) {
            i += 1;
            if (i < args.len) algo_str = args[i];
        } else if (std.mem.eql(u8, args[i], "--bits") or std.mem.eql(u8, args[i], "-b")) {
            i += 1;
            if (i < args.len) {
                bits = std.fmt.parseInt(u32, args[i], 10) catch {
                    ew.print("Invalid bit count: {s}\n", .{args[i]}) catch {};
                    return;
                };
            }
        } else if (std.mem.eql(u8, args[i], "--passphrase") or std.mem.eql(u8, args[i], "-p")) {
            i += 1;
            if (i < args.len) passphrase = args[i];
        } else if (std.mem.eql(u8, args[i], "--output") or std.mem.eql(u8, args[i], "-o")) {
            i += 1;
            if (i < args.len) output_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--secret-output")) {
            i += 1;
            if (i < args.len) secret_output_path = args[i];
        }
    }

    if (name_str == null or email_str == null) {
        stderr.writeAll(
            \\Usage: zpgp keygen --name <name> --email <email> [options]
            \\
            \\Options:
            \\  --name, -n <name>          User name (required)
            \\  --email, -e <email>        Email address (required)
            \\  --algo, -a <algorithm>     Algorithm: rsa (default), ed25519
            \\  --bits, -b <bits>          Key size for RSA: 2048 (default), 3072, 4096
            \\  --passphrase, -p <pass>    Passphrase for secret key encryption
            \\  --output, -o <file>        Write public key to file (default: stdout)
            \\  --secret-output <file>     Write secret key to file
            \\
        ) catch {};
        return;
    }

    const user_id = std.fmt.allocPrint(allocator, "{s} <{s}>", .{ name_str.?, email_str.? }) catch {
        ew.print("Out of memory\n", .{}) catch {};
        return;
    };
    defer allocator.free(user_id);

    var algorithm: PublicKeyAlgorithm = .rsa_encrypt_sign;
    if (std.mem.eql(u8, algo_str, "rsa")) {
        algorithm = .rsa_encrypt_sign;
    } else if (std.mem.eql(u8, algo_str, "ed25519") or std.mem.eql(u8, algo_str, "eddsa")) {
        algorithm = .eddsa;
    } else {
        ew.print("Unknown algorithm: {s}. Use 'rsa' or 'ed25519'.\n", .{algo_str}) catch {};
        return;
    }

    ew.print("Generating {s} key", .{if (algorithm == .eddsa) "Ed25519" else "RSA"}) catch {};
    if (algorithm != .eddsa) {
        ew.print(" ({d} bits)", .{bits}) catch {};
    }
    ew.print(" for {s}...\n", .{user_id}) catch {};

    const result = keygen_mod.generateKey(allocator, .{
        .algorithm = algorithm,
        .bits = bits,
        .user_id = user_id,
        .passphrase = passphrase,
        .hash_algo = .sha256,
    }) catch |err| {
        ew.print("Error generating key: {}\n", .{err}) catch {};
        return;
    };
    defer result.deinit(allocator);

    ew.print("Key generated successfully.\n", .{}) catch {};
    ew.print("Fingerprint: ", .{}) catch {};
    for (result.fingerprint) |byte| {
        ew.print("{X:0>2}", .{byte}) catch {};
    }
    ew.print("\nKey ID: ", .{}) catch {};
    for (result.key_id) |byte| {
        ew.print("{X:0>2}", .{byte}) catch {};
    }
    ew.print("\n", .{}) catch {};

    writeOutputFile(output_path, result.public_key_armored) catch |err| {
        ew.print("Error writing public key: {}\n", .{err}) catch {};
        return;
    };

    if (secret_output_path) |sp| {
        writeOutputFile(sp, result.secret_key_armored) catch |err| {
            ew.print("Error writing secret key: {}\n", .{err}) catch {};
            return;
        };
        ew.print("Secret key written to: {s}\n", .{sp}) catch {};
    } else {
        if (output_path != null) {
            ew.print("Secret key not saved. Use --secret-output to save it.\n", .{}) catch {};
        } else {
            stdout.writeAll("\n") catch {};
            stderr.writeAll("--- Secret key follows ---\n") catch {};
            stdout.writeAll(result.secret_key_armored) catch {};
        }
    }
}

fn cmdSign(allocator: std.mem.Allocator, args: []const []const u8) void {
    const stderr = std.fs.File.stderr();
    const ew = stderr.deprecatedWriter();

    // Parse flags
    var key_path: ?[]const u8 = null;
    var passphrase: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;
    var do_armor = false;
    var input_path: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--key") or std.mem.eql(u8, args[i], "-k")) {
            i += 1;
            if (i < args.len) key_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--passphrase") or std.mem.eql(u8, args[i], "-p")) {
            i += 1;
            if (i < args.len) passphrase = args[i];
        } else if (std.mem.eql(u8, args[i], "--output") or std.mem.eql(u8, args[i], "-o")) {
            i += 1;
            if (i < args.len) output_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--armor") or std.mem.eql(u8, args[i], "-a")) {
            do_armor = true;
        } else {
            input_path = args[i];
        }
    }

    if (key_path == null or input_path == null) {
        stderr.writeAll("Usage: zpgp sign --key <secret-key-file> [--passphrase <pass>] [--armor] [--output <file>] <input-file>\n") catch {};
        return;
    }

    // Read secret key
    const key_data = readInputFile(allocator, key_path.?) catch |err| {
        ew.print("Error reading key file: {}\n", .{err}) catch {};
        return;
    };
    defer allocator.free(key_data);

    // Import the secret key
    var key = import_export.importPublicKeyAuto(allocator, key_data) catch |err| {
        ew.print("Error importing key: {}\n", .{err}) catch {};
        return;
    };
    defer key.deinit(allocator);

    // Read input file
    const input_data = readInputFile(allocator, input_path.?) catch |err| {
        ew.print("Error reading input: {}\n", .{err}) catch {};
        return;
    };
    defer allocator.free(input_data);

    // Create signed message
    const signed = compose.createSignedMessage(
        allocator,
        input_data,
        input_path.?,
        &key,
        passphrase,
        .sha256,
    ) catch |err| {
        ew.print("Error signing: {}\n", .{err}) catch {};
        return;
    };
    defer allocator.free(signed);

    // Optionally armor
    var output_data: []u8 = signed;
    var output_owned = false;
    if (do_armor) {
        const headers = [_]armor.Header{
            .{ .name = "Version", .value = "zpgp 0.1" },
        };
        output_data = armor.encode(allocator, signed, .message, &headers) catch |err| {
            ew.print("Error armoring: {}\n", .{err}) catch {};
            return;
        };
        output_owned = true;
    }
    defer if (output_owned) allocator.free(output_data);

    // Write output
    writeOutputFile(output_path, output_data) catch |err| {
        ew.print("Error writing output: {}\n", .{err}) catch {};
        return;
    };

    stderr.writeAll("Signature created successfully.\n") catch {};
}

fn cmdVerify(allocator: std.mem.Allocator, args: []const []const u8) void {
    const stderr = std.fs.File.stderr();
    const ew = stderr.deprecatedWriter();

    var key_path: ?[]const u8 = null;
    var input_path: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--key") or std.mem.eql(u8, args[i], "-k")) {
            i += 1;
            if (i < args.len) key_path = args[i];
        } else {
            input_path = args[i];
        }
    }

    if (key_path == null or input_path == null) {
        stderr.writeAll("Usage: zpgp verify --key <pubkey-file> <signed-file>\n") catch {};
        return;
    }

    // Read public key
    const key_data = readInputFile(allocator, key_path.?) catch |err| {
        ew.print("Error reading key file: {}\n", .{err}) catch {};
        return;
    };
    defer allocator.free(key_data);

    var key = import_export.importPublicKeyAuto(allocator, key_data) catch |err| {
        ew.print("Error importing key: {}\n", .{err}) catch {};
        return;
    };
    defer key.deinit(allocator);

    // Read signed message
    const input_data = readInputFile(allocator, input_path.?) catch |err| {
        ew.print("Error reading input: {}\n", .{err}) catch {};
        return;
    };
    defer allocator.free(input_data);

    // Parse the message
    var msg = decompose_mod.parseMessage(allocator, input_data) catch |err| {
        ew.print("Error parsing message: {}\n", .{err}) catch {};
        return;
    };
    defer msg.deinit(allocator);

    // Verify
    const plaintext = decompose_mod.verifySignedMessage(allocator, &msg, &key) catch |err| {
        ew.print("Signature verification FAILED: {}\n", .{err}) catch {};
        return;
    };
    defer allocator.free(plaintext);

    stderr.writeAll("Signature verified successfully.\n") catch {};
    const stdout = std.fs.File.stdout();
    stdout.writeAll(plaintext) catch {};
}

fn cmdEncrypt(allocator: std.mem.Allocator, args: []const []const u8) void {
    const stderr = std.fs.File.stderr();
    const ew = stderr.deprecatedWriter();

    var recipient_path: ?[]const u8 = null;
    var passphrase: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;
    var do_armor = false;
    var input_path: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--recipient") or std.mem.eql(u8, args[i], "-r")) {
            i += 1;
            if (i < args.len) recipient_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--passphrase") or std.mem.eql(u8, args[i], "-p")) {
            i += 1;
            if (i < args.len) passphrase = args[i];
        } else if (std.mem.eql(u8, args[i], "--output") or std.mem.eql(u8, args[i], "-o")) {
            i += 1;
            if (i < args.len) output_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--armor") or std.mem.eql(u8, args[i], "-a")) {
            do_armor = true;
        } else {
            input_path = args[i];
        }
    }

    if (input_path == null) {
        stderr.writeAll("Usage: zpgp encrypt [--recipient <pubkey-file>] [--passphrase <pass>] [--armor] [--output <file>] <input-file>\n") catch {};
        return;
    }

    // Read input
    const input_data = readInputFile(allocator, input_path.?) catch |err| {
        ew.print("Error reading input: {}\n", .{err}) catch {};
        return;
    };
    defer allocator.free(input_data);

    var encrypted: []u8 = undefined;

    if (passphrase) |pass| {
        // Symmetric encryption with passphrase
        encrypted = compose.encryptMessageSymmetric(
            allocator,
            input_data,
            input_path.?,
            pass,
            .aes256,
            null,
        ) catch |err| {
            ew.print("Error encrypting: {}\n", .{err}) catch {};
            return;
        };
    } else if (recipient_path) |rpath| {
        // Public key encryption
        const key_data = readInputFile(allocator, rpath) catch |err| {
            ew.print("Error reading recipient key: {}\n", .{err}) catch {};
            return;
        };
        defer allocator.free(key_data);

        var key = import_export.importPublicKeyAuto(allocator, key_data) catch |err| {
            ew.print("Error importing key: {}\n", .{err}) catch {};
            return;
        };
        defer key.deinit(allocator);

        const recipients = [_]*const @import("zpgp").key_mod.Key{&key};
        encrypted = compose.encryptMessage(
            allocator,
            input_data,
            input_path.?,
            &recipients,
            .aes256,
            null,
        ) catch |err| {
            ew.print("Error encrypting: {}\n", .{err}) catch {};
            return;
        };
    } else {
        stderr.writeAll("Error: must specify either --recipient or --passphrase\n") catch {};
        return;
    }
    defer allocator.free(encrypted);

    // Optionally armor
    var output_data: []u8 = encrypted;
    var output_owned = false;
    if (do_armor) {
        const headers = [_]armor.Header{
            .{ .name = "Version", .value = "zpgp 0.1" },
        };
        output_data = armor.encode(allocator, encrypted, .message, &headers) catch |err| {
            ew.print("Error armoring: {}\n", .{err}) catch {};
            return;
        };
        output_owned = true;
    }
    defer if (output_owned) allocator.free(output_data);

    writeOutputFile(output_path, output_data) catch |err| {
        ew.print("Error writing output: {}\n", .{err}) catch {};
        return;
    };

    stderr.writeAll("Encryption successful.\n") catch {};
}

fn cmdDecrypt(allocator: std.mem.Allocator, args: []const []const u8) void {
    const stderr = std.fs.File.stderr();
    const ew = stderr.deprecatedWriter();

    var key_path: ?[]const u8 = null;
    var passphrase: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;
    var input_path: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--key") or std.mem.eql(u8, args[i], "-k")) {
            i += 1;
            if (i < args.len) key_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--passphrase") or std.mem.eql(u8, args[i], "-p")) {
            i += 1;
            if (i < args.len) passphrase = args[i];
        } else if (std.mem.eql(u8, args[i], "--output") or std.mem.eql(u8, args[i], "-o")) {
            i += 1;
            if (i < args.len) output_path = args[i];
        } else {
            input_path = args[i];
        }
    }

    if (input_path == null) {
        stderr.writeAll("Usage: zpgp decrypt [--key <secret-key-file>] [--passphrase <pass>] [--output <file>] <input-file>\n") catch {};
        return;
    }

    // Read input
    const input_data = readInputFile(allocator, input_path.?) catch |err| {
        ew.print("Error reading input: {}\n", .{err}) catch {};
        return;
    };
    defer allocator.free(input_data);

    // Parse the message
    var msg = decompose_mod.parseMessage(allocator, input_data) catch |err| {
        ew.print("Error parsing message: {}\n", .{err}) catch {};
        return;
    };
    defer msg.deinit(allocator);

    if (!msg.isEncrypted()) {
        stderr.writeAll("Error: message is not encrypted\n") catch {};
        return;
    }

    var plaintext: []u8 = undefined;

    if (passphrase) |pass| {
        // Passphrase decryption
        plaintext = decompose_mod.decryptWithPassphrase(allocator, &msg, pass) catch |err| {
            ew.print("Error decrypting: {}\n", .{err}) catch {};
            return;
        };
    } else if (key_path) |kpath| {
        // Secret key decryption
        const key_data = readInputFile(allocator, kpath) catch |err| {
            ew.print("Error reading key file: {}\n", .{err}) catch {};
            return;
        };
        defer allocator.free(key_data);

        var key = import_export.importPublicKeyAuto(allocator, key_data) catch |err| {
            ew.print("Error importing key: {}\n", .{err}) catch {};
            return;
        };
        defer key.deinit(allocator);

        plaintext = decompose_mod.decryptWithKey(allocator, &msg, &key, null) catch |err| {
            ew.print("Error decrypting: {}\n", .{err}) catch {};
            return;
        };
    } else {
        stderr.writeAll("Error: must specify either --key or --passphrase\n") catch {};
        return;
    }
    defer allocator.free(plaintext);

    // Write output
    writeOutputFile(output_path, plaintext) catch |err| {
        ew.print("Error writing output: {}\n", .{err}) catch {};
        return;
    };

    stderr.writeAll("Decryption successful.\n") catch {};
}

/// Write output data to a file or stdout.
fn writeOutputFile(path: ?[]const u8, data: []const u8) !void {
    if (path) |p| {
        if (std.mem.eql(u8, p, "-")) {
            try std.fs.File.stdout().writeAll(data);
        } else {
            try std.fs.cwd().writeFile(.{ .sub_path = p, .data = data });
        }
    } else {
        try std.fs.File.stdout().writeAll(data);
    }
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
