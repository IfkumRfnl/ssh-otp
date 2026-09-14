const std = @import("std");
const core = @import("core.zig");

const Passwd = extern struct {
    pw_name: ?[*:0]u8,
    pw_passwd: ?[*:0]u8,
    pw_uid: u32,
    pw_gid: u32,
    pw_gecos: ?[*:0]u8,
    pw_dir: ?[*:0]u8,
    pw_shell: ?[*:0]u8,
};
const Handler = *const fn (c_int) callconv(.c) void;
extern "c" fn getpwnam(name: [*:0]const u8) ?*const Passwd;
extern "c" fn getuid() u32;
extern "c" fn geteuid() u32;
extern "c" fn isatty(fd: c_int) c_int;
extern "c" fn ssh_otp_disable_core_dumps() c_int;
extern "c" fn signal(number: c_int, handler: ?Handler) ?Handler;
extern "c" fn write(fd: c_int, buffer: [*]const u8, count: usize) isize;
extern "c" fn ssh_otp_sleep(milliseconds: u32) c_int;
extern "c" fn __errno_location() *c_int;

var caught_signal: c_int = 0;

fn onSignal(number: c_int) callconv(.c) void {
    const flag: *volatile c_int = &caught_signal;
    flag.* = number;
}

fn interruption() c_int {
    const flag: *volatile c_int = &caught_signal;
    return flag.*;
}

fn installSignals() !void {
    // Also catch a lost terminal's SIGPIPE so output errors can revoke the ticket.
    for ([_]c_int{ 1, 2, 15, 13 }) |number| {
        if (signal(number, onSignal)) |previous| {
            if (@intFromPtr(previous) == std.math.maxInt(usize)) return error.SignalSetupFailed;
        }
    }
}

fn writeAll(fd: c_int, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const written = write(fd, bytes[offset..].ptr, bytes.len - offset);
        if (written < 0) {
            if (__errno_location().* == 4 and interruption() == 0) continue;
            return error.OutputFailed;
        }
        if (written == 0) return error.OutputFailed;
        offset += @intCast(written);
    }
}

const usage =
    "Usage: ssh-otp USERNAME DURATION\n" ++
    "       ssh-otp --help\n\n" ++
    "Issue a one-use SSH passphrase for an existing user. DURATION is a positive\n" ++
    "integer followed by s, m, or h, from 1 second through 1 hour (for example 10m).\n" ++
    "Non-root callers may issue only for their own real UID; root may target any\n" ++
    "existing user. Requires a root-owned setuid installation and terminal stdout.\n\n" ++
    "The passphrase is shown once. Leave this process running while signing in.\n" ++
    "It ends when the passphrase is used, expires, or is replaced. Ctrl-C revokes\n" ++
    "any still-active passphrase. Existing SSH sessions are never disconnected.\n";

fn parseDuration(text: []const u8) !u32 {
    if (text.len < 2) return error.InvalidDuration;
    const multiplier: u32 = switch (text[text.len - 1]) {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        else => return error.InvalidDuration,
    };
    var value: u32 = 0;
    for (text[0 .. text.len - 1]) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidDuration;
        value = value * 10 + (byte - '0');
        if (value > 3600) return error.InvalidDuration;
    }
    if (value == 0 or value > 3600 / multiplier) return error.InvalidDuration;
    return value * multiplier;
}

const Outcome = union(enum) {
    consumed,
    expired,
    replaced,
    interrupted: c_int,
};

fn monitor(uid: u32, ticket: *core.Ticket) !Outcome {
    if (interruption() != 0) return .{ .interrupted = interruption() };
    try writeAll(1, "One-use SSH passphrase:\n");
    try writeAll(1, ticket.phrase[0..ticket.phrase_len]);
    std.crypto.secureZero(u8, &ticket.phrase);
    try writeAll(1, "\nWaiting for use or expiry; Ctrl-C revokes it.\n");

    while (true) {
        if (interruption() != 0) return .{ .interrupted = interruption() };
        switch (try core.status(uid, ticket.token)) {
            .active => {},
            .consumed => return .consumed,
            .expired => return .expired,
            .replaced => return .replaced,
        }
        if (ssh_otp_sleep(200) != 0 and __errno_location().* != 4) return error.SleepFailed;
    }
}

fn run(argc: c_int, argv: [*][*:0]u8) !c_int {
    if (argc == 2 and std.mem.eql(u8, std.mem.span(argv[1]), "--help")) {
        try writeAll(1, usage);
        return 0;
    }
    if (argc != 3) return error.InvalidArguments;
    const duration = try parseDuration(std.mem.span(argv[2]));
    if (std.mem.span(argv[1]).len == 0) return error.UnknownUser;

    if (ssh_otp_disable_core_dumps() != 0) return error.CoreDumpSetupFailed;
    const real_uid = getuid();
    // Copy the UID immediately: getpwnam returns libc-owned static storage.
    const target_uid = (getpwnam(argv[1]) orelse return error.UnknownUser).pw_uid;
    if (real_uid != 0 and target_uid != real_uid) return error.WrongUser;
    if (geteuid() != 0) return error.InstallationRequired;
    if (isatty(1) != 1) return error.TerminalRequired;
    try installSignals();
    if (interruption() != 0) return 128 + interruption();

    var ticket = try core.issue(target_uid, duration);
    defer std.crypto.secureZero(u8, &ticket.phrase);
    const outcome = monitor(target_uid, &ticket) catch |err| {
        core.revoke(target_uid, ticket.token) catch |cleanup_error| {
            report(cleanup_error);
            writeAll(2, "ssh-otp: revocation failed; the credential may remain active until its expiry.\n") catch {};
        };
        return err;
    };
    // Token-conditional revocation must not remove a newer replacement ticket.
    try core.revoke(target_uid, ticket.token);
    switch (outcome) {
        .consumed => try writeAll(1, "Passphrase consumed or invalidated; it is no longer usable. Existing SSH sessions are unaffected.\n"),
        .expired => try writeAll(1, "Passphrase expired and was invalidated. Existing SSH sessions are unaffected.\n"),
        .replaced => try writeAll(1, "Passphrase replaced by a newer issuance. Existing SSH sessions are unaffected.\n"),
        .interrupted => |number| {
            try writeAll(1, "Stopped; any still-active passphrase was revoked. Existing SSH sessions are unaffected.\n");
            return 128 + number;
        },
    }
    return 0;
}

fn report(err: anyerror) void {
    const message: []const u8 = switch (err) {
        error.InvalidArguments => "expected USERNAME DURATION; use --help for usage",
        error.InvalidDuration => "duration must be an integer with s/m/h suffix, between 1s and 1h",
        error.UnknownUser => "the requested user does not exist",
        error.WrongUser => "only root may issue a passphrase for another UID",
        error.InstallationRequired => "effective UID must be root; ask an administrator to install the CLI root-owned with mode 4755",
        error.TerminalRequired => "stdout must be an interactive terminal; refusing to pipe or redirect a secret",
        error.CoreDumpSetupFailed => "could not disable core dumps; refusing to issue a secret",
        error.SignalSetupFailed => "could not install interruption handlers",
        error.OutputFailed => "could not write output",
        error.SleepFailed => "could not wait for credential status",
        else => @errorName(err),
    };
    writeAll(2, "ssh-otp: ") catch return;
    writeAll(2, message) catch return;
    writeAll(2, "\n") catch {};
}

pub export fn main(argc: c_int, argv: [*][*:0]u8) c_int {
    return run(argc, argv) catch |err| {
        report(err);
        return 1;
    };
}
