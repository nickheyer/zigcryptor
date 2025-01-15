const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Aes256 = std.crypto.core.aes.Aes256;
const Sha256Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

const PAD_SIZE: usize = 16;
const BUFFER_SIZE: usize = 4096;
const SALT_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const PBKDF2_ITERATIONS: usize = 100000;

const CryptoError = error{
    InvalidBlockSize,
    InvalidPadding,
    InvalidIV,
    InvalidMode,
};

// OP MODE
const CryptoMode = enum {
    Encrypt,
    Decrypt,

    pub fn fromString(str: []const u8) !CryptoMode {
        if (std.mem.eql(u8, str, "encrypt")) return .Encrypt;
        if (std.mem.eql(u8, str, "decrypt")) return .Decrypt;
        return error.InvalidMode;
    }

    pub fn fileExtension(self: CryptoMode) []const u8 {
        return switch (self) {
            .Encrypt => "enc",
            .Decrypt => "dec",
        };
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // PARSE ARGS
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 4) {
        try printUsage(args[0]);
        std.process.exit(1);
    }

    // SETUP CRYPTO
    const mode = CryptoMode.fromString(args[1]) catch {
        try printUsage(args[0]);
        std.process.exit(1);
    };

    try processFile(mode, args[2], args[3], allocator);
}

fn printUsage(prog_name: []const u8) !void {
    try std.io.getStdErr().writer().print("Usage: {s} <encrypt|decrypt> <input_file> <password>\n", .{prog_name});
}

fn deriveKey(password: []const u8) ![KEY_SIZE]u8 {
    var key: [KEY_SIZE]u8 = undefined;
    var salt: [SALT_SIZE]u8 = .{0} ** SALT_SIZE;

    try std.crypto.pwhash.pbkdf2(&key, password, &salt, PBKDF2_ITERATIONS, Sha256Hmac);

    return key;
}

fn processFile(mode: CryptoMode, input_path: []const u8, password: []const u8, allocator: std.mem.Allocator) !void {
    // DERIVE KEY
    const key = try deriveKey(password);

    // SETUP FILES
    const input_file = try std.fs.cwd().openFile(input_path, .{});
    defer input_file.close();

    const output_path = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ input_path, mode.fileExtension() });
    defer allocator.free(output_path);

    const output_file = try std.fs.cwd().createFile(output_path, .{});
    defer output_file.close();

    switch (mode) {
        .Encrypt => try encryptFile(&input_file, &output_file, key),
        .Decrypt => try decryptFile(&input_file, &output_file, key),
    }
}

fn encryptFile(input: *const std.fs.File, output: *const std.fs.File, key: [KEY_SIZE]u8) !void {
    // SETUP IV
    var iv: [PAD_SIZE]u8 = undefined;
    std.crypto.random.bytes(&iv);
    try output.writeAll(&iv);

    const aes = Aes256.initEnc(key);
    var buffer: [BUFFER_SIZE]u8 = undefined;
    var pending: [PAD_SIZE]u8 = undefined;
    var pending_size: usize = 0;

    while (true) {
        const bytes_read = try input.read(buffer[0..]);
        if (bytes_read == 0) break;

        var pos: usize = 0;
        while (pos < bytes_read) {
            const available = bytes_read - pos;
            const can_take = @min(available, PAD_SIZE - pending_size);

            @memcpy(pending[pending_size .. pending_size + can_take], buffer[pos .. pos + can_take]);
            pending_size += can_take;
            pos += can_take;

            if (pending_size == PAD_SIZE) {
                var block: [PAD_SIZE]u8 = undefined;
                @memcpy(block[0..PAD_SIZE], pending[0..PAD_SIZE]);
                aes.encrypt(&block, &block);
                try output.writeAll(&block);
                pending_size = 0;
            }
        }
    }

    // HANDLE FINAL BLOCK WITH PADDING
    if (pending_size < PAD_SIZE) {
        const pad_val: u8 = @intCast(PAD_SIZE - pending_size);
        @memset(pending[pending_size..], pad_val);
    }

    var final_block: [PAD_SIZE]u8 = undefined;
    @memcpy(final_block[0..PAD_SIZE], pending[0..PAD_SIZE]);
    aes.encrypt(&final_block, &final_block);
    try output.writeAll(&final_block);
}

fn decryptFile(input: *const std.fs.File, output: *const std.fs.File, key: [KEY_SIZE]u8) !void {
    // READ IV
    var iv: [PAD_SIZE]u8 = undefined;
    const iv_read = try input.read(&iv);
    if (iv_read != PAD_SIZE) return CryptoError.InvalidIV;

    const aes = Aes256.initDec(key);
    var buffer: [BUFFER_SIZE]u8 = undefined;
    var last_block: [PAD_SIZE]u8 = undefined;
    var has_last_block = false;

    while (true) {
        const bytes_read = try input.read(buffer[0..]);
        if (bytes_read == 0) break;

        var pos: usize = 0;
        while (pos + PAD_SIZE <= bytes_read) {
            if (has_last_block) {
                try output.writeAll(&last_block);
            }

            var block: [PAD_SIZE]u8 = undefined;
            @memcpy(block[0..PAD_SIZE], buffer[pos .. pos + PAD_SIZE]);
            aes.decrypt(&block, &block);
            @memcpy(last_block[0..PAD_SIZE], block[0..PAD_SIZE]);
            has_last_block = true;
            pos += PAD_SIZE;
        }
    }

    if (!has_last_block) return CryptoError.InvalidBlockSize;

    // HANDLE PADDING IN LAST BLOCK
    const pad_val = last_block[PAD_SIZE - 1];
    if (pad_val == 0 or pad_val > PAD_SIZE) return CryptoError.InvalidPadding;

    // VERIFY PADDING
    for (last_block[PAD_SIZE - pad_val .. PAD_SIZE]) |b| {
        if (b != pad_val) return CryptoError.InvalidPadding;
    }

    // WRITE FINAL BLOCK WITHOUT PADDING
    try output.writeAll(last_block[0 .. PAD_SIZE - pad_val]);
}

test "encryption and decryption" {
    const test_allocator = std.testing.allocator;
    const test_file_path = "test.txt";
    const test_content = "Hello, World!";
    const test_password = "test123";

    // MAKE TEST TXT
    {
        const test_file = try std.fs.cwd().createFile(test_file_path, .{});
        defer test_file.close();
        try test_file.writeAll(test_content);
    }

    try processFile(.Encrypt, test_file_path, test_password, test_allocator);
    try processFile(.Decrypt, "test.txt.enc", test_password, test_allocator);

    // VERIFY
    const decrypted_file = try std.fs.cwd().openFile("test.txt.enc.dec", .{});
    defer decrypted_file.close();

    var buf: [100]u8 = undefined;
    const bytes_read = try decrypted_file.readAll(&buf);
    const decrypted_content = buf[0..bytes_read];

    try std.testing.expectEqualStrings(test_content, decrypted_content);

    // CLEANUP
    try std.fs.cwd().deleteFile(test_file_path);
    try std.fs.cwd().deleteFile("test.txt.enc");
    try std.fs.cwd().deleteFile("test.txt.enc.dec");
}
