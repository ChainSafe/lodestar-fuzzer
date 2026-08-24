const std = @import("std");
const Database = @import("Database.zig");

const failure_entry_count_max: u32 = 256;
const stats_line_count_max: u32 = 1_024;

pub fn main(init: std.process.Init) !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 11) return error.ExpectedTenArguments;

    const campaign_id = try std.fmt.parseInt(u64, args[1], 10);
    const requested_ref = args[2];
    const commit_sha = args[3];
    const commit_timestamp = try std.fmt.parseInt(u64, args[4], 10);
    const target = args[5];
    const max_input_len = try std.fmt.parseInt(u32, args[6], 10);
    const fuzz_output_path = args[7];
    const crash_path = args[8];
    const hang_path = args[9];
    const output_path = args[10];

    if (campaign_id == 0) return error.InvalidCampaignID;
    try Database.validateRef(requested_ref);
    try Database.validateSHA(commit_sha);
    try Database.validateTargetName(target);
    if (commit_timestamp == 0) return error.InvalidCommitTimestamp;
    if (max_input_len == 0) return error.InvalidInputLimit;

    const stats_path = try std.fs.path.join(
        arena,
        &.{ fuzz_output_path, "default", "fuzzer_stats" },
    );
    const stats = try loadStats(arena, init.io, stats_path);

    const hang_failure = try loadShortestFailure(arena, init.io, hang_path, max_input_len);
    const crash_failure = try loadShortestFailure(arena, init.io, crash_path, max_input_len);

    const artifact: Database.TargetArtifact = .{
        .campaign_id = campaign_id,
        .ref = requested_ref,
        .commit_sha = commit_sha,
        .commit_timestamp = commit_timestamp,
        .result = .{
            .target = target,
            .start_timestamp = stats.start_timestamp,
            .run_time_seconds = stats.run_time_seconds,
            .edges_found = stats.edges_found,
            .total_edges = stats.total_edges,
            .corpus_count = stats.corpus_count,
            .corpus_found = stats.corpus_found,
            .unique_crashes = stats.unique_crashes,
            .unique_hangs = stats.unique_hangs,
            .total_execs = stats.total_execs,
            .encoded_crash = crash_failure,
            .encoded_hang = hang_failure,
        },
    };
    try Database.validateTargetResult(arena, artifact.result, max_input_len);
    try writeJSON(gpa, init.io, output_path, artifact);
}

fn loadStats(arena: std.mem.Allocator, io: std.Io, path: []const u8) !FuzzerStats {
    const content = try std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        arena,
        .limited(1024 * 1024),
    );

    var stats: FuzzerStats = .{};
    var seen: SeenStats = .{};
    var line_count: u32 = 0;
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        line_count += 1;
        if (line_count > stats_line_count_max) return error.TooManyStatsLines;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const key = std.mem.trim(u8, line[0..colon], &std.ascii.whitespace);
        const value = std.mem.trim(u8, line[colon + 1 ..], &std.ascii.whitespace);

        if (std.mem.eql(u8, key, "start_time")) {
            if (seen.start_timestamp) return error.DuplicateStatsField;
            seen.start_timestamp = true;
            stats.start_timestamp = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, key, "run_time")) {
            if (seen.run_time_seconds) return error.DuplicateStatsField;
            seen.run_time_seconds = true;
            stats.run_time_seconds = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, key, "execs_done")) {
            if (seen.total_execs) return error.DuplicateStatsField;
            seen.total_execs = true;
            stats.total_execs = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, key, "edges_found")) {
            if (seen.edges_found) return error.DuplicateStatsField;
            seen.edges_found = true;
            stats.edges_found = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, key, "total_edges")) {
            if (seen.total_edges) return error.DuplicateStatsField;
            seen.total_edges = true;
            stats.total_edges = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, key, "corpus_count")) {
            if (seen.corpus_count) return error.DuplicateStatsField;
            seen.corpus_count = true;
            stats.corpus_count = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, key, "corpus_found")) {
            if (seen.corpus_found) return error.DuplicateStatsField;
            seen.corpus_found = true;
            stats.corpus_found = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, key, "saved_crashes")) {
            if (seen.unique_crashes) return error.DuplicateStatsField;
            seen.unique_crashes = true;
            stats.unique_crashes = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, key, "saved_hangs")) {
            if (seen.unique_hangs) return error.DuplicateStatsField;
            seen.unique_hangs = true;
            stats.unique_hangs = try std.fmt.parseInt(u64, value, 10);
        }
    }

    if (!seen.all()) return error.MissingStatsField;
    return stats;
}

fn loadShortestFailure(
    arena: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    max_input_len: u32,
) !?[]const u8 {
    var directory = try std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
    defer directory.close(io);

    var selected_name: ?[]const u8 = null;
    var selected_size: u64 = 0;
    var entry_count: u32 = 0;
    var iterator = directory.iterate();
    while (try iterator.next(io)) |entry| {
        entry_count += 1;
        if (entry_count > failure_entry_count_max) return error.TooManyFailureEntries;
        if (entry.kind != .file) return error.InvalidFailureEntry;

        const stat = try directory.statFile(io, entry.name, .{});
        if (stat.size > max_input_len) return error.FailureTooLong;
        if (selected_name == null or stat.size < selected_size) {
            selected_name = try arena.dupe(u8, entry.name);
            selected_size = stat.size;
        } else if (stat.size == selected_size) {
            if (std.mem.lessThan(u8, entry.name, selected_name.?)) {
                selected_name = try arena.dupe(u8, entry.name);
            }
        }
    }

    const name = selected_name orelse return null;
    const content = try directory.readFileAlloc(
        io,
        name,
        arena,
        .limited(@as(usize, max_input_len) + 1),
    );
    if (content.len > max_input_len) return error.FailureTooLong;

    const encoded_len = std.base64.standard.Encoder.calcSize(content.len);
    const encoded = try arena.alloc(u8, encoded_len);
    return std.base64.standard.Encoder.encode(encoded, content);
}

fn writeJSON(
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    artifact: Database.TargetArtifact,
) !void {
    const output = try gpa.alloc(u8, Database.artifact_size_max);
    defer gpa.free(output);

    var output_writer = std.Io.Writer.fixed(output);
    output_writer.print("{f}\n", .{
        std.json.fmt(artifact, .{ .whitespace = .indent_2 }),
    }) catch return error.ResultArtifactTooLarge;

    var atomic_file = try std.Io.Dir.cwd().createFileAtomic(io, path, .{
        .replace = true,
    });
    defer atomic_file.deinit(io);

    var buffer: [4096]u8 = undefined;
    var writer = atomic_file.file.writer(io, &buffer);
    try writer.interface.writeAll(output_writer.buffered());
    try writer.interface.flush();
    try atomic_file.replace(io);
}

const FuzzerStats = struct {
    start_timestamp: u64 = 0,
    run_time_seconds: u64 = 0,
    edges_found: u64 = 0,
    total_edges: u64 = 0,
    corpus_count: u64 = 0,
    corpus_found: u64 = 0,
    unique_crashes: u64 = 0,
    unique_hangs: u64 = 0,
    total_execs: u64 = 0,
};

const SeenStats = struct {
    start_timestamp: bool = false,
    run_time_seconds: bool = false,
    edges_found: bool = false,
    total_edges: bool = false,
    corpus_count: bool = false,
    corpus_found: bool = false,
    unique_crashes: bool = false,
    unique_hangs: bool = false,
    total_execs: bool = false,

    fn all(self: @This()) bool {
        return self.start_timestamp and self.run_time_seconds and
            self.edges_found and self.total_edges and self.corpus_count and self.corpus_found and
            self.unique_crashes and self.unique_hangs and self.total_execs;
    }
};
