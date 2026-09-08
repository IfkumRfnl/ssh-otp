const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const options = b.addOptions();
    options.addOption(bool, "testing", false);
    options.addOption([]const u8, "store_path", "/run/ssh-otp");
    const cli = b.addExecutable(.{
        .name = "ssh-otp",
        .root_module = b.createModule(.{ .root_source_file = b.path("src/main.zig"), .target = target, .optimize = optimize, .link_libc = true }),
    });
    cli.root_module.addOptions("build_options", options);
    b.installArtifact(cli);
    const pam = b.addLibrary(.{
        .name = "pam_ssh_otp",
        .linkage = .dynamic,
        .root_module = b.createModule(.{ .root_source_file = b.path("src/pam.zig"), .target = target, .optimize = optimize, .link_libc = true }),
    });
    pam.root_module.addOptions("build_options", options);
    pam.linker_allow_shlib_undefined = true;
    b.installArtifact(pam);
    const test_options = b.addOptions();
    test_options.addOption(bool, "testing", true);
    test_options.addOption([]const u8, "store_path", "/tmp/ssh-otp-tests-unused");
    const tests = b.addTest(.{ .root_module = b.createModule(.{ .root_source_file = b.path("src/core.zig"), .target = target, .optimize = optimize, .link_libc = true }) });
    tests.root_module.addOptions("build_options", test_options);
    const run_tests = b.addRunArtifact(tests);
    b.step("test", "Run credential lifecycle and filesystem safety regression tests").dependOn(&run_tests.step);
}
