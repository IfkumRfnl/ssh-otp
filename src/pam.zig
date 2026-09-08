const core = @import("core.zig");
const options = @import("build_options");

const PamHandle = opaque {};
const PamMessage = extern struct {
    msg_style: c_int,
    msg: ?[*:0]const u8,
};
const PamResponse = extern struct {
    resp: ?[*:0]u8,
    resp_retcode: c_int,
};
const PamConversation = extern struct {
    conv: ?*const fn (c_int, [*]const ?*const PamMessage, *?[*]PamResponse, ?*anyopaque) callconv(.c) c_int,
    appdata_ptr: ?*anyopaque,
};
const Passwd = extern struct {
    pw_name: ?[*:0]u8,
    pw_passwd: ?[*:0]u8,
    pw_uid: u32,
    pw_gid: u32,
    pw_gecos: ?[*:0]u8,
    pw_dir: ?[*:0]u8,
    pw_shell: ?[*:0]u8,
};

extern "c" fn pam_get_user(*PamHandle, *?[*:0]const u8, ?[*:0]const u8) c_int;
extern "c" fn pam_get_item(*const PamHandle, c_int, *?*const anyopaque) c_int;
extern "c" fn geteuid() u32;
extern "c" fn getpwnam([*:0]const u8) ?*Passwd;
extern "c" fn strnlen([*:0]const u8, usize) usize;
extern "c" fn strlen([*:0]const u8) usize;
extern "c" fn explicit_bzero(*anyopaque, usize) void;
extern "c" fn free(?*anyopaque) void;

const PAM_SUCCESS = 0;
const PAM_AUTH_ERR = 7;
const PAM_CONV = 5;
const PAM_PROMPT_ECHO_OFF = 1;
const PAM_SILENT: c_int = 0x8000;
const PAM_DISALLOW_NULL_AUTHTOK: c_int = 0x0001;

// PAM conversation responses belong to the caller and must be malloc-compatible.
// Wipe the entire response even if it is too long to be an accepted credential.
fn releaseResponse(responses: [*]PamResponse) void {
    if (responses[0].resp) |secret| {
        explicit_bzero(@ptrCast(secret), strlen(secret));
        free(@ptrCast(secret));
    }
    free(@ptrCast(responses));
}

export fn pam_sm_authenticate(handle: ?*PamHandle, flags: c_int, argc: c_int, argv: ?[*]const ?[*:0]const u8) callconv(.c) c_int {
    _ = argv;
    // This module has no runtime options, especially no password fallback or
    // alternate credential-store path. Reject misspelled configuration options.
    if (argc != 0 or (flags & ~(PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK)) != 0) return PAM_AUTH_ERR;
    if (!options.testing and geteuid() != 0) return PAM_AUTH_ERR;
    const pamh = handle orelse return PAM_AUTH_ERR;

    var username: ?[*:0]const u8 = null;
    if (pam_get_user(pamh, &username, null) != PAM_SUCCESS) return PAM_AUTH_ERR;
    const name = username orelse return PAM_AUTH_ERR;
    if (name[0] == 0) return PAM_AUTH_ERR;
    const account = getpwnam(name) orelse return PAM_AUTH_ERR;
    // getpwnam uses static storage; capture the UID before calling application code.
    const uid = account.pw_uid;

    var item: ?*const anyopaque = null;
    if (pam_get_item(pamh, PAM_CONV, &item) != PAM_SUCCESS) return PAM_AUTH_ERR;
    const raw_conversation = item orelse return PAM_AUTH_ERR;
    if (@intFromPtr(raw_conversation) % @alignOf(PamConversation) != 0) return PAM_AUTH_ERR;
    const conversation: *const PamConversation = @ptrCast(@alignCast(raw_conversation));
    const converse = conversation.conv orelse return PAM_AUTH_ERR;
    const prompt = PamMessage{ .msg_style = PAM_PROMPT_ECHO_OFF, .msg = "Burner password: " };
    const messages = [_]?*const PamMessage{&prompt};
    var responses: ?[*]PamResponse = null;
    const result = converse(1, &messages, &responses, conversation.appdata_ptr);
    // A conversation may return an allocated response even on an error.
    const response = responses orelse return PAM_AUTH_ERR;
    defer releaseResponse(response);
    if (result != PAM_SUCCESS or response[0].resp_retcode != 0) return PAM_AUTH_ERR;
    const secret = response[0].resp orelse return PAM_AUTH_ERR;
    const length = strnlen(secret, 161);
    if (length == 0 or length > 160) return PAM_AUTH_ERR;
    const accepted = core.authenticate(uid, secret[0..length]) catch return PAM_AUTH_ERR;
    return if (accepted) PAM_SUCCESS else PAM_AUTH_ERR;
}

export fn pam_sm_setcred(handle: ?*PamHandle, flags: c_int, argc: c_int, argv: ?[*]const ?[*:0]const u8) callconv(.c) c_int {
    _ = handle;
    _ = flags;
    _ = argc;
    _ = argv;
    return PAM_SUCCESS;
}
