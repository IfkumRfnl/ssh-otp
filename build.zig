const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const cli = b.addExecutable(.{
        .name = "ssh-otp",
        .root_module = b.createModule(.{ .root_source_file = b.path("src/main.zig"), .target = target, .optimize = optimize, .link_libc = true }),
    });
    b.installArtifact(cli);
    const pam = b.addLibrary(.{
        .name = "pam_ssh_otp",
        .linkage = .dynamic,
        .root_module = b.createModule(.{ .root_source_file = b.path("src/pam.zig"), .target = target, .optimize = optimize, .link_libc = true }),
    });
    pam.linker_allow_shlib_undefined = true;
    b.installArtifact(pam);
    const tests = b.addTest(.{ .root_module = b.createModule(.{ .root_source_file = b.path("src/core.zig"), .target = target, .optimize = optimize, .link_libc = true }) });
    const run_tests = b.addRunArtifact(tests);
    b.step("test", "Run credential lifecycle and filesystem safety regression tests").dependOn(&run_tests.step);
}
