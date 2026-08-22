const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    addTool(b, .{
        .name = "collect-result",
        .source = "src/collect_result.zig",
        .description = "Collect one target's bounded fuzzing result",
        .target = target,
        .optimize = optimize,
    });
    addTool(b, .{
        .name = "merge-results",
        .source = "src/merge_results.zig",
        .description = "Validate and merge one complete target matrix",
        .target = target,
        .optimize = optimize,
    });
    addTool(b, .{
        .name = "generate-website",
        .source = "src/generate_website.zig",
        .description = "Generate the static results website",
        .target = target,
        .optimize = optimize,
    });
}

const ToolOptions = struct {
    name: []const u8,
    source: []const u8,
    description: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
};

fn addTool(b: *std.Build, options: ToolOptions) void {
    const executable = b.addExecutable(.{
        .name = options.name,
        .root_module = b.createModule(.{
            .root_source_file = b.path(options.source),
            .target = options.target,
            .optimize = options.optimize,
        }),
    });
    b.installArtifact(executable);

    const run = b.addRunArtifact(executable);
    if (b.args) |args| run.addArgs(args);

    const step = b.step(options.name, options.description);
    step.dependOn(&run.step);
}
