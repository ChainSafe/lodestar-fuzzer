const std = @import("std");
const FuzzResult = @import("FuzzResult.zig");

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
    if (args.len != 10) return error.ExpectedNineArguments;

    const branch = args[1];
    const commit_sha = args[2];
    const commit_timestamp = try std.fmt.parseInt(u64, args[3], 10);
    const target = args[4];
    const max_input_len = try std.fmt.parseInt(u32, args[5], 10);
    const fuzz_output_path = args[6];
    const crash_path = args[7];
    const hang_path = args[8];
    const output_path = args[9];

    try validateRef(branch);
    try validateSHA(commit_sha);
    try validateName(target, 128);
    if (commit_timestamp == 0) return error.InvalidCommitTimestamp;
    if (max_input_len == 0) return error.InvalidInputLimit;

    const stats_path = try std.fs.path.join(
        arena,
        &.{ fuzz_output_path, "default", "fuzzer_stats" },
    );
    const stats = try loadStats(arena, init.io, stats_path);

    var results: std.ArrayList(FuzzResult) = .empty;
    defer results.deinit(gpa);

    const hang_failure = try loadShortestFailure(arena, init.io, hang_path, max_input_len);
    const crash_failure = try loadShortestFailure(arena, init.io, crash_path, max_input_len);
    if ((stats.unique_hangs > 0) != (hang_failure != null)) return error.FailureCountMismatch;
    if ((stats.unique_crashes > 0) != (crash_failure != null)) return error.FailureCountMismatch;

    if (hang_failure) |failure| {
        try results.append(gpa, makeResult(.{
            .branch = branch,
            .commit_sha = commit_sha,
            .commit_timestamp = commit_timestamp,
            .target = target,
            .stats = stats,
            .kind = .hang,
            .encoded_failure = failure,
        }));
    }
    if (crash_failure) |failure| {
        try results.append(gpa, makeResult(.{
            .branch = branch,
            .commit_sha = commit_sha,
            .commit_timestamp = commit_timestamp,
            .target = target,
            .stats = stats,
            .kind = .crash,
            .encoded_failure = failure,
        }));
    }
    if (results.items.len == 0) {
        try results.append(gpa, makeResult(.{
            .branch = branch,
            .commit_sha = commit_sha,
            .commit_timestamp = commit_timestamp,
            .target = target,
            .stats = stats,
            .kind = .success,
            .encoded_failure = "",
        }));
    }

    std.debug.assert(results.items.len > 0);
    std.debug.assert(results.items.len <= 2);
    std.mem.sort(FuzzResult, results.items, {}, FuzzResult.lessThan);
    try writeJSON(init.io, output_path, results.items);
}

const MakeResultOptions = struct {
    branch: []const u8,
    commit_sha: []const u8,
    commit_timestamp: u64,
    target: []const u8,
    stats: FuzzerStats,
    kind: FuzzResult.Kind,
    encoded_failure: []const u8,
};

fn makeResult(options: MakeResultOptions) FuzzResult {
    return .{
        .branch = options.branch,
        .commit_sha = options.commit_sha,
        .commit_timestamp = options.commit_timestamp,
        .start_timestamp = options.stats.start_timestamp,
        .target = options.target,
        .edges_found = options.stats.edges_found,
        .total_edges = options.stats.total_edges,
        .unique_crashes = options.stats.unique_crashes,
        .unique_hangs = options.stats.unique_hangs,
        .total_execs = options.stats.total_execs,
        .kind = options.kind,
        .encoded_failure = options.encoded_failure,
    };
}

fn validateRef(value: []const u8) !void {
    if (value.len == 0) return error.EmptyRef;
    if (value.len > 256) return error.RefTooLong;
    for (value) |byte| {
        if (std.ascii.isControl(byte)) return error.InvalidRef;
    }
}

fn validateName(value: []const u8, len_max: u16) !void {
    if (value.len == 0) return error.EmptyName;
    if (value.len > len_max) return error.NameTooLong;
    for (value) |byte| {
        const allowed = std.ascii.isAlphanumeric(byte) or
            byte == '-' or byte == '_' or byte == '/' or byte == '.';
        if (!allowed) return error.InvalidName;
    }
}

fn validateSHA(commit_sha: []const u8) !void {
    if (commit_sha.len != 40) return error.InvalidCommitSHA;
    for (commit_sha) |byte| {
        if (!std.ascii.isHex(byte)) return error.InvalidCommitSHA;
    }
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
    if (stats.start_timestamp == 0) return error.InvalidStartTimestamp;
    if (stats.total_execs == 0) return error.NoExecutions;
    if (stats.edges_found > stats.total_edges) return error.InvalidEdgeCounts;
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

fn writeJSON(io: std.Io, path: []const u8, results: []const FuzzResult) !void {
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

const FuzzerStats = struct {
    start_timestamp: u64 = 0,
    edges_found: u64 = 0,
    total_edges: u64 = 0,
    unique_crashes: u64 = 0,
    unique_hangs: u64 = 0,
    total_execs: u64 = 0,
};

const SeenStats = struct {
    start_timestamp: bool = false,
    edges_found: bool = false,
    total_edges: bool = false,
    unique_crashes: bool = false,
    unique_hangs: bool = false,
    total_execs: bool = false,

    fn all(self: @This()) bool {
        return self.start_timestamp and self.edges_found and self.total_edges and
            self.unique_crashes and self.unique_hangs and self.total_execs;
    }
};
