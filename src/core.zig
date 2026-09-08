const std = @import("std");
const c = @cImport({
    // glibc's fortified variadic wrappers cannot be translated by translate-c.
    @cUndef("_FORTIFY_SOURCE");
    @cDefine("_FORTIFY_SOURCE", "0");
    @cInclude("stdlib.h");
    @cInclude("sys/stat.h");
    @cInclude("sys/file.h");
    @cInclude("sys/random.h");
    @cInclude("fcntl.h");
    @cInclude("unistd.h");
    @cInclude("time.h");
    @cInclude("errno.h");
});

pub const Ticket = struct { token: [16]u8, phrase: [160]u8, phrase_len: usize };
pub const State = enum { active, consumed, expired, replaced };
const Record = [64]u8;
const words = blk: {
    @setEvalBranchQuota(300000);
    var result: [7776][]const u8 = undefined;
    var lines = std.mem.tokenizeScalar(u8, @embedFile("words.txt"), '\n');
    for (&result) |*word| word.* = lines.next() orelse @compileError("wordlist too short");
    if (lines.next() != null) @compileError("wordlist too long");
    break :blk result;
};
const store_path: [:0]const u8 = "/run/ssh-otp";

fn random(bytes: []u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const n = c.getrandom(bytes.ptr + offset, bytes.len - offset, 0);
        if (n < 0 and c.__errno_location().* == c.EINTR) continue;
        if (n <= 0) return error.RandomUnavailable;
        offset += @intCast(n);
    }
}

fn now() !u64 {
    var ts: c.struct_timespec = undefined;
    // Includes time spent suspended; /run records disappear on reboot.
    if (c.clock_gettime(c.CLOCK_BOOTTIME, &ts) != 0 or ts.tv_sec < 0) return error.ClockUnavailable;
    return @intCast(ts.tv_sec);
}

fn verifier(token: [16]u8, phrase: []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("ssh-otp-v1\x00");
    hash.update(&token);
    hash.update(phrase);
    return hash.finalResult();
}

const Store = struct {
    dir: c_int,
    lock: c_int,

    fn open(path: [:0]const u8) !Store {
        if (!@import("builtin").is_test and c.geteuid() != 0) return error.RootRequired;
        if (c.mkdir(path, 0o700) != 0 and c.__errno_location().* != c.EEXIST) return error.StoreUnavailable;
        const dir = c.open(path, c.O_RDONLY | c.O_DIRECTORY | c.O_NOFOLLOW | c.O_CLOEXEC);
        if (dir < 0) return error.UnsafeStore;
        errdefer _ = c.close(dir);
        var st: c.struct_stat = undefined;
        if (c.fstat(dir, &st) != 0 or st.st_uid != c.geteuid() or st.st_mode & 0o7777 != 0o700) return error.UnsafeStore;
        const lock = c.openat(dir, ".lock", c.O_RDWR | c.O_CREAT | c.O_NOFOLLOW | c.O_CLOEXEC | c.O_NONBLOCK, @as(c_uint, 0o600));
        if (lock < 0) return error.UnsafeStore;
        errdefer _ = c.close(lock);
        try safeFile(lock);
        while (c.flock(lock, c.LOCK_EX) != 0) {
            if (c.__errno_location().* != c.EINTR) return error.LockFailed;
        }
        return .{ .dir = dir, .lock = lock };
    }

    fn close(self: Store) void {
        _ = c.close(self.lock);
        _ = c.close(self.dir);
    }

    fn name(uid: u32, buf: *[16]u8) ![:0]u8 {
        return std.fmt.bufPrintZ(buf, "{d}", .{uid});
    }

    fn load(self: Store, uid: u32) !?Record {
        var buf: [16]u8 = undefined;
        const fd = c.openat(self.dir, try name(uid, &buf), c.O_RDONLY | c.O_NOFOLLOW | c.O_CLOEXEC | c.O_NONBLOCK);
        if (fd < 0) {
            if (c.__errno_location().* == c.ENOENT) return null;
            return error.RecordUnavailable;
        }
        defer _ = c.close(fd);
        try safeFile(fd);
        var st: c.struct_stat = undefined;
        if (c.fstat(fd, &st) != 0 or st.st_size != 64) return error.CorruptRecord;
        var record: Record = undefined;
        var offset: usize = 0;
        while (offset < record.len) {
            const n = c.read(fd, record[offset..].ptr, record.len - offset);
            if (n < 0 and c.__errno_location().* == c.EINTR) continue;
            if (n <= 0) return error.RecordUnavailable;
            offset += @intCast(n);
        }
        if (!std.mem.eql(u8, record[0..4], "OTP1")) return error.CorruptRecord;
        return record;
    }

    fn save(self: Store, uid: u32, record: Record) !void {
        var buf: [16]u8 = undefined;
        const filename = try name(uid, &buf);
        const fd = c.openat(self.dir, filename, c.O_WRONLY | c.O_CREAT | c.O_NOFOLLOW | c.O_CLOEXEC | c.O_NONBLOCK, @as(c_uint, 0o600));
        if (fd < 0) return error.RecordUnavailable;
        defer _ = c.close(fd);
        try safeFile(fd);
        // Under the global lock, interrupted writes are either absent or malformed:
        // readers never accept a partial record. No rename can change the lock inode.
        errdefer _ = c.unlinkat(self.dir, filename, 0);
        if (c.ftruncate(fd, 0) != 0) return error.RecordUnavailable;
        var offset: usize = 0;
        while (offset < record.len) {
            const n = c.write(fd, record[offset..].ptr, record.len - offset);
            if (n < 0 and c.__errno_location().* == c.EINTR) continue;
            if (n <= 0) return error.RecordUnavailable;
            offset += @intCast(n);
        }
    }

    fn remove(self: Store, uid: u32) !void {
        var buf: [16]u8 = undefined;
        if (c.unlinkat(self.dir, try name(uid, &buf), 0) != 0 and c.__errno_location().* != c.ENOENT) return error.RecordUnavailable;
    }
};

fn safeFile(fd: c_int) !void {
    var st: c.struct_stat = undefined;
    if (c.fstat(fd, &st) != 0 or st.st_uid != c.geteuid() or st.st_mode & c.S_IFMT != c.S_IFREG or st.st_mode & 0o7777 != 0o600 or st.st_nlink != 1) return error.UnsafeStore;
}

fn issueAt(path: [:0]const u8, uid: u32, seconds: u32) !Ticket {
    if (seconds == 0 or seconds > 3600) return error.InvalidDuration;
    var ticket: Ticket = .{ .token = undefined, .phrase = @splat(0), .phrase_len = 0 };
    errdefer std.crypto.secureZero(u8, &ticket.phrase);
    try random(&ticket.token);
    for (0..4) |index| {
        var value: u16 = undefined;
        // Rejection sampling keeps all 7,776 words equally likely.
        while (true) {
            try random(std.mem.asBytes(&value));
            if (value < 62208) break;
        }
        const word = words[value % 7776];
        if (index != 0) {
            ticket.phrase[ticket.phrase_len] = '=';
            ticket.phrase_len += 1;
        }
        @memcpy(ticket.phrase[ticket.phrase_len..][0..word.len], word);
        ticket.phrase_len += word.len;
    }
    const store = try Store.open(path);
    defer store.close();
    var record: Record = @splat(0);
    @memcpy(record[0..4], "OTP1");
    @memcpy(record[4..20], &ticket.token);
    std.mem.writeInt(u64, record[20..28], (try now()) + seconds, .little);
    @memcpy(record[28..60], &verifier(ticket.token, ticket.phrase[0..ticket.phrase_len]));
    try store.save(uid, record);
    return ticket;
}

pub fn issue(uid: u32, seconds: u32) !Ticket {
    return issueAt(store_path, uid, seconds);
}

fn statusAt(path: [:0]const u8, uid: u32, token: [16]u8) !State {
    const store = try Store.open(path);
    defer store.close();
    const record = (try store.load(uid)) orelse return .consumed;
    if (!std.mem.eql(u8, record[4..20], &token)) return .replaced;
    if (try now() >= std.mem.readInt(u64, record[20..28], .little)) {
        try store.remove(uid);
        return .expired;
    }
    return .active;
}

pub fn status(uid: u32, token: [16]u8) !State {
    return statusAt(store_path, uid, token);
}

fn revokeAt(path: [:0]const u8, uid: u32, token: [16]u8) !void {
    const store = try Store.open(path);
    defer store.close();
    const record = (try store.load(uid)) orelse return;
    if (std.mem.eql(u8, record[4..20], &token)) try store.remove(uid);
}

pub fn revoke(uid: u32, token: [16]u8) !void {
    return revokeAt(store_path, uid, token);
}

fn authenticateAt(path: [:0]const u8, uid: u32, phrase: []const u8) !bool {
    const store = try Store.open(path);
    defer store.close();
    var record = (try store.load(uid)) orelse return false;
    if (try now() >= std.mem.readInt(u64, record[20..28], .little) or record[60] >= 5) {
        try store.remove(uid);
        return false;
    }
    const token: [16]u8 = record[4..20].*;
    const expected: [32]u8 = record[28..60].*;
    const actual = verifier(token, phrase);
    if (std.crypto.timing_safe.eql([32]u8, expected, actual)) {
        // Consume before reporting authentication success, even if the client drops.
        try store.remove(uid);
        return true;
    }
    record[60] += 1;
    if (record[60] >= 5) try store.remove(uid) else try store.save(uid, record);
    return false;
}

pub fn authenticate(uid: u32, phrase: []const u8) !bool {
    if (phrase.len > 160) return false;
    return authenticateAt(store_path, uid, phrase);
}

const TestStore = struct {
    path: [64]u8,
    fn init() !TestStore {
        var self: TestStore = .{ .path = @splat(0) };
        const template = "/tmp/ssh-otp-test-XXXXXX";
        @memcpy(self.path[0..template.len], template);
        if (c.mkdtemp(@ptrCast(&self.path)) == null) return error.TempFailed;
        return self;
    }
    fn slice(self: *const TestStore) [:0]const u8 {
        return self.path[0..std.mem.indexOfScalar(u8, &self.path, 0).? :0];
    }
    fn deinit(self: *const TestStore) void {
        const dir = c.open(self.slice(), c.O_RDONLY | c.O_DIRECTORY);
        if (dir >= 0) {
            _ = c.unlinkat(dir, "1000", 0);
            _ = c.unlinkat(dir, ".lock", 0);
            _ = c.close(dir);
        }
        _ = c.rmdir(self.slice());
    }
};

test "single use, replacement, stale revocation and wrong attempts" {
    var tmp = try TestStore.init();
    defer tmp.deinit();
    const a = try issueAt(tmp.slice(), 1000, 60);
    try std.testing.expect(!(try authenticateAt(tmp.slice(), 1000, "wrong")));
    const b = try issueAt(tmp.slice(), 1000, 60);
    try std.testing.expectEqual(State.replaced, try statusAt(tmp.slice(), 1000, a.token));
    try revokeAt(tmp.slice(), 1000, a.token);
    try std.testing.expect(!(try authenticateAt(tmp.slice(), 1000, a.phrase[0..a.phrase_len])));
    try std.testing.expect(try authenticateAt(tmp.slice(), 1000, b.phrase[0..b.phrase_len]));
    try std.testing.expect(!(try authenticateAt(tmp.slice(), 1000, b.phrase[0..b.phrase_len])));
    const d = try issueAt(tmp.slice(), 1000, 60);
    for (0..5) |_| try std.testing.expect(!(try authenticateAt(tmp.slice(), 1000, "wrong")));
    try std.testing.expect(!(try authenticateAt(tmp.slice(), 1000, d.phrase[0..d.phrase_len])));
}

test "expiry is enforced by authentication without issuer" {
    var tmp = try TestStore.init();
    defer tmp.deinit();
    const ticket = try issueAt(tmp.slice(), 1000, 1);
    var delay: c.struct_timespec = .{ .tv_sec = 1, .tv_nsec = 10000000 };
    _ = c.nanosleep(&delay, null);
    try std.testing.expect(!(try authenticateAt(tmp.slice(), 1000, ticket.phrase[0..ticket.phrase_len])));
}

test "unsafe store permissions and record symlinks fail closed" {
    var tmp = try TestStore.init();
    defer tmp.deinit();
    _ = c.chmod(tmp.slice(), 0o755);
    try std.testing.expectError(error.UnsafeStore, issueAt(tmp.slice(), 1000, 60));
    _ = c.chmod(tmp.slice(), 0o700);
    const dir = c.open(tmp.slice(), c.O_RDONLY | c.O_DIRECTORY);
    defer _ = c.close(dir);
    try std.testing.expectEqual(@as(c_int, 0), c.symlinkat("/dev/null", dir, "1000"));
    try std.testing.expectError(error.RecordUnavailable, issueAt(tmp.slice(), 1000, 60));
}
