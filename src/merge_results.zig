const std = @import("std");
const FuzzResult = @import("FuzzResult.zig");

const result_limit: u8 = 20;
const target_count_max: u8 = 128;

pub fn main(init: std.process.Init) !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 5) return error.ExpectedFourArguments;

    const expected_sha = args[1];
    const targets_path = args[2];
    const results_path = args[3];
    const database_path = args[4];
    try validateSHA(expected_sha);

    const manifest_content = try std.Io.Dir.cwd().readFileAlloc(
        init.io,
        targets_path,
        arena,
        .limited(1024 * 1024),
    );
    const manifest = try std.json.parseFromSliceLeaky(
        Manifest,
        arena,
        manifest_content,
        .{ .ignore_unknown_fields = false },
    );
    try validateManifest(manifest);

    const found = try arena.alloc(bool, manifest.include.len);
    @memset(found, false);

    var new_results: std.ArrayList(FuzzResult) = .empty;
    defer new_results.deinit(gpa);
    try loadMatrixResults(
        arena,
        init.io,
        expected_sha,
        manifest,
        found,
        results_path,
        &new_results,
        gpa,
    );

    for (found) |target_found| {
        if (!target_found) return error.MissingTargetResult;
    }

    const database_content = try std.Io.Dir.cwd().readFileAlloc(
        init.io,
        database_path,
        arena,
        .limited(32 * 1024 * 1024),
    );
    const old_results = try std.json.parseFromSliceLeaky(
        []FuzzResult,
        arena,
        database_content,
        .{ .ignore_unknown_fields = false },
    );
    if (old_results.len > result_limit) return error.DatabaseExceedsResultLimit;

    try new_results.appendSlice(gpa, old_results);
    std.mem.sort(FuzzResult, new_results.items, {}, FuzzResult.lessThan);

    const output_len = @min(new_results.items.len, result_limit);
    try writeJSON(init.io, database_path, new_results.items[0..output_len]);
}

fn loadMatrixResults(
    arena: std.mem.Allocator,
    io: std.Io,
    expected_sha: []const u8,
    manifest: Manifest,
    found: []bool,
    results_path: []const u8,
    new_results: *std.ArrayList(FuzzResult),
    gpa: std.mem.Allocator,
) !void {
    var results_directory = try std.Io.Dir.cwd().openDir(
        io,
        results_path,
        .{ .iterate = true },
    );
    defer results_directory.close(io);

    const artifact_prefix = try std.fmt.allocPrint(arena, "result-{s}-", .{expected_sha});
    var artifact_count: u16 = 0;
    var iterator = results_directory.iterate();
    while (try iterator.next(io)) |entry| {
        artifact_count += 1;
        if (artifact_count > target_count_max) return error.TooManyResultArtifacts;
        if (entry.kind != .directory) return error.InvalidResultArtifact;
        if (!std.mem.startsWith(u8, entry.name, artifact_prefix)) {
            return error.UnexpectedResultArtifact;
        }

        const target_name = entry.name[artifact_prefix.len..];
        const target_index = findTarget(manifest.include, target_name) orelse {
            return error.UnexpectedTargetResult;
        };
        if (found[target_index]) return error.DuplicateTargetResult;

        var artifact_directory = try results_directory.openDir(
            io,
            entry.name,
            .{ .iterate = true },
        );
        defer artifact_directory.close(io);
        try validateArtifactDirectory(io, artifact_directory);

        const content = try artifact_directory.readFileAlloc(
            io,
            "result.json",
            arena,
            .limited(4 * 1024 * 1024),
        );
        const results = try std.json.parseFromSliceLeaky(
            []FuzzResult,
            arena,
            content,
            .{ .ignore_unknown_fields = false },
        );
        try validateTargetResults(
            arena,
            expected_sha,
            manifest.include[target_index],
            results,
        );

        try new_results.appendSlice(gpa, results);
        found[target_index] = true;
    }

    if (artifact_count != manifest.include.len) return error.ResultArtifactCountMismatch;
}

fn validateArtifactDirectory(io: std.Io, directory: std.Io.Dir) !void {
    var entry_count: u8 = 0;
    var found_result = false;
    var iterator = directory.iterate();
    while (try iterator.next(io)) |entry| {
        entry_count += 1;
        if (entry_count > 1) return error.UnexpectedResultArtifactFile;
        if (entry.kind != .file) return error.UnexpectedResultArtifactFile;
        if (!std.mem.eql(u8, entry.name, "result.json")) {
            return error.UnexpectedResultArtifactFile;
        }
        found_result = true;
    }
    if (!found_result) return error.MissingResultJSON;
}

fn validateTargetResults(
    arena: std.mem.Allocator,
    expected_sha: []const u8,
    target: Target,
    results: []const FuzzResult,
) !void {
    if (results.len == 0) return error.EmptyTargetResult;
    if (results.len > 2) return error.TooManyTargetResults;

    var found_success = false;
    var found_crash = false;
    var found_hang = false;
    for (results) |result| {
        if (!std.mem.eql(u8, result.commit_sha, expected_sha)) {
            return error.CommitSHAMismatch;
        }
        if (!std.mem.eql(u8, result.target, target.target)) {
            return error.TargetMismatch;
        }
        try validateResult(arena, result, target.max_input_len);

        switch (result.kind) {
            .success => {
                if (found_success) return error.DuplicateResultKind;
                found_success = true;
            },
            .crash => {
                if (found_crash) return error.DuplicateResultKind;
                found_crash = true;
            },
            .hang => {
                if (found_hang) return error.DuplicateResultKind;
                found_hang = true;
            },
        }
    }

    if (found_success and results.len != 1) return error.SuccessWithFailure;
    if (results.len == 2 and !FuzzResult.sameRun(results[0], results[1])) {
        return error.InconsistentTargetResults;
    }
}

fn validateResult(
    arena: std.mem.Allocator,
    result: FuzzResult,
    max_input_len: u32,
) !void {
    try validateSHA(result.commit_sha);
    if (result.branch.len == 0) return error.EmptyBranch;
    if (result.branch.len > 256) return error.BranchTooLong;
    if (result.commit_timestamp == 0) return error.InvalidCommitTimestamp;
    if (result.start_timestamp == 0) return error.InvalidStartTimestamp;
    if (result.total_execs == 0) return error.NoExecutions;
    if (result.edges_found > result.total_edges) return error.InvalidEdgeCounts;

    if (result.kind == .success) {
        if (result.encoded_failure.len != 0) return error.SuccessHasFailure;
        return;
    }

    const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(
        result.encoded_failure,
    );
    if (decoded_len > max_input_len) return error.FailureTooLong;
    const decoded = try arena.alloc(u8, decoded_len);
    try std.base64.standard.Decoder.decode(decoded, result.encoded_failure);
}

fn validateManifest(manifest: Manifest) !void {
    if (manifest.include.len == 0) return error.EmptyTargetMatrix;
    if (manifest.include.len > target_count_max) return error.TooManyTargets;

    for (manifest.include, 0..) |target, target_index| {
        if (target.target.len == 0) return error.EmptyTargetName;
        if (target.target.len > 128) return error.TargetNameTooLong;
        if (target.max_input_len == 0) return error.InvalidInputLimit;
        for (target.target) |byte| {
            const allowed = std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '_';
            if (!allowed) return error.InvalidTargetName;
        }
        for (manifest.include[0..target_index]) |previous| {
            if (std.mem.eql(u8, previous.target, target.target)) {
                return error.DuplicateTarget;
            }
        }
    }
}

fn findTarget(targets: []const Target, name: []const u8) ?usize {
    for (targets, 0..) |target, index| {
        if (std.mem.eql(u8, target.target, name)) return index;
    }
    return null;
}

fn validateSHA(commit_sha: []const u8) !void {
    if (commit_sha.len != 40) return error.InvalidCommitSHA;
    for (commit_sha) |byte| {
        if (!std.ascii.isHex(byte)) return error.InvalidCommitSHA;
    }
}

fn writeJSON(io: std.Io, path: []const u8, results: []const FuzzResult) !void {
    std.debug.assert(results.len <= result_limit);

    var atomic_file = try std.Io.Dir.cwd().createFileAtomic(io, path, .{
        .replace = true,
    });
    defer atomic_file.deinit(io);

    var buffer: [4096]u8 = undefined;
    var writer = atomic_file.file.writer(io, &buffer);
    try writer.interface.print("{f}\n", .{
        std.json.fmt(results, .{ .whitespace = .indent_2 }),
    });
    try writer.interface.flush();
    try atomic_file.replace(io);
}

const Manifest = struct {
    include: []const Target,
};

const Target = struct {
    target: []const u8,
    max_input_len: u32,
};
