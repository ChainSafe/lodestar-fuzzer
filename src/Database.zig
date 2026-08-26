const std = @import("std");
const Database = @This();

pub const schema_version_current: u16 = 2;
pub const schema_version_previous: u16 = 1;
pub const campaign_limit: u8 = 3;
pub const target_count_max: u8 = 128;
pub const crash_count_max: u32 = 25_600;
pub const hang_count_max: u32 = 512;
pub const artifact_size_max: usize = 4 * 1024 * 1024;
pub const database_size_max: usize = 32 * 1024 * 1024;

schema_version: u16,
campaigns: []const Campaign,

pub const Campaign = struct {
    project_id: []const u8 = "lodestar-z",
    repository: []const u8 = "ChainSafe/lodestar-z",
    campaign_id: u64,
    ref: []const u8,
    commit_sha: []const u8,
    commit_timestamp: u64,
    start_timestamp: u64,
    results: []const TargetResult,
};

pub const TargetResult = struct {
    target: []const u8,
    corpus_version: u32 = 1,
    start_timestamp: u64,
    run_time_seconds: u64,
    edges_found: u64,
    total_edges: u64,
    corpus_count: u64,
    corpus_found: u64,
    unique_crashes: u64,
    unique_hangs: u64,
    total_execs: u64,
    encoded_crash: ?[]const u8,
    encoded_hang: ?[]const u8,
};

pub const TargetArtifact = struct {
    project_id: []const u8,
    repository: []const u8,
    campaign_id: u64,
    ref: []const u8,
    commit_sha: []const u8,
    commit_timestamp: u64,
    result: TargetResult,
};

pub const Parsed = union(enum) {
    current: Database,
    legacy: []const LegacyResult,
};

pub fn parse(arena: std.mem.Allocator, content: []const u8) !Parsed {
    const trimmed = std.mem.trim(u8, content, &std.ascii.whitespace);
    if (trimmed.len == 0) return error.EmptyDatabase;

    return switch (trimmed[0]) {
        '{' => .{ .current = try std.json.parseFromSliceLeaky(
            Database,
            arena,
            trimmed,
            .{ .ignore_unknown_fields = false },
        ) },
        '[' => .{ .legacy = try std.json.parseFromSliceLeaky(
            []const LegacyResult,
            arena,
            trimmed,
            .{ .ignore_unknown_fields = false },
        ) },
        else => error.InvalidDatabaseJSON,
    };
}

pub fn validate(database: Database, arena: std.mem.Allocator) !void {
    if (database.schema_version != schema_version_current and
        database.schema_version != schema_version_previous)
    {
        return error.UnsupportedDatabaseSchema;
    }
    if (database.campaigns.len > campaign_limit) return error.DatabaseExceedsCampaignLimit;

    for (database.campaigns, 0..) |campaign, campaign_index| {
        if (campaign.campaign_id == 0) return error.InvalidCampaignID;
        try validateProjectID(campaign.project_id);
        try validateRepository(campaign.repository);
        try validateRef(campaign.ref);
        try validateSHA(campaign.commit_sha);
        if (campaign.commit_timestamp == 0) return error.InvalidCommitTimestamp;
        if (campaign.start_timestamp == 0) return error.InvalidStartTimestamp;
        if (campaign.results.len == 0) return error.EmptyCampaign;
        if (campaign.results.len > target_count_max) return error.TooManyTargetResults;
        if (campaign.start_timestamp != campaignStartTimestamp(campaign.results)) {
            return error.CampaignStartTimestampMismatch;
        }

        if (campaign_index > 0) {
            const previous = database.campaigns[campaign_index - 1];
            if (!campaignLessThan({}, previous, campaign)) return error.InvalidCampaignOrder;
        }
        for (database.campaigns[0..campaign_index]) |previous| {
            if (previous.campaign_id == campaign.campaign_id) return error.DuplicateCampaign;
        }
        for (campaign.results, 0..) |result, result_index| {
            try validateTargetName(result.target);
            try validateTargetResult(arena, result, null);
            for (campaign.results[0..result_index]) |previous| {
                if (std.mem.eql(u8, previous.target, result.target)) {
                    return error.DuplicateTargetResult;
                }
            }
        }
    }
}

pub fn validateTargetResult(
    arena: std.mem.Allocator,
    result: TargetResult,
    max_input_len: ?u32,
) !void {
    if (result.start_timestamp == 0) return error.InvalidStartTimestamp;
    if (result.corpus_version == 0) return error.InvalidCorpusVersion;
    if (result.run_time_seconds == 0) return error.InvalidRunTime;
    if (result.total_edges == 0) return error.EmptyInstrumentationMap;
    if (result.edges_found > result.total_edges) return error.InvalidEdgeCounts;
    if (result.corpus_count == 0) return error.EmptyCorpus;
    if (result.corpus_found > result.corpus_count) return error.InvalidCorpusCounts;
    if (result.total_execs == 0) return error.NoExecutions;
    if (result.unique_crashes > crash_count_max) return error.TooManyCrashes;
    if (result.unique_hangs > hang_count_max) return error.TooManyHangs;
    if ((result.unique_crashes > 0) != (result.encoded_crash != null)) {
        return error.FailureCountMismatch;
    }
    if ((result.unique_hangs > 0) != (result.encoded_hang != null)) {
        return error.FailureCountMismatch;
    }
    try validateFailure(arena, result.encoded_crash, max_input_len);
    try validateFailure(arena, result.encoded_hang, max_input_len);
}

pub fn validateRef(value: []const u8) !void {
    if (value.len == 0) return error.EmptyRef;
    if (value.len > 256) return error.RefTooLong;
    for (value) |byte| {
        if (std.ascii.isControl(byte)) return error.InvalidRef;
    }
}

pub fn validateProjectID(value: []const u8) !void {
    if (value.len == 0) return error.EmptyProjectID;
    if (value.len > 128) return error.ProjectIDTooLong;
    for (value) |byte| {
        const allowed = std.ascii.isLower(byte) or std.ascii.isDigit(byte) or byte == '-';
        if (!allowed) return error.InvalidProjectID;
    }
}

pub fn validateRepository(value: []const u8) !void {
    if (value.len == 0) return error.EmptyRepository;
    if (value.len > 256) return error.RepositoryTooLong;

    var slash_count: u16 = 0;
    for (value) |byte| {
        if (byte == '/') {
            slash_count += 1;
            continue;
        }
        const allowed = std.ascii.isAlphanumeric(byte) or byte == '_' or byte == '-' or byte == '.';
        if (!allowed) return error.InvalidRepository;
    }
    if (slash_count != 1) return error.InvalidRepository;
    if (value[0] == '/' or value[value.len - 1] == '/') return error.InvalidRepository;
}

pub fn validateSHA(commit_sha: []const u8) !void {
    if (commit_sha.len != 40) return error.InvalidCommitSHA;
    for (commit_sha) |byte| {
        if (!std.ascii.isHex(byte)) return error.InvalidCommitSHA;
    }
}

pub fn validateTargetName(value: []const u8) !void {
    if (value.len == 0) return error.EmptyTargetName;
    if (value.len > 128) return error.TargetNameTooLong;
    for (value) |byte| {
        const allowed = std.ascii.isLower(byte) or std.ascii.isDigit(byte) or byte == '_';
        if (!allowed) return error.InvalidTargetName;
    }
}

pub fn campaignLessThan(_: void, lhs: Campaign, rhs: Campaign) bool {
    if (lhs.start_timestamp != rhs.start_timestamp) {
        return lhs.start_timestamp > rhs.start_timestamp;
    }
    return lhs.campaign_id > rhs.campaign_id;
}

pub fn campaignStartTimestamp(results: []const TargetResult) u64 {
    std.debug.assert(results.len > 0);
    var start_timestamp = results[0].start_timestamp;
    for (results[1..]) |result| {
        start_timestamp = @min(start_timestamp, result.start_timestamp);
    }
    return start_timestamp;
}

pub fn writeAtomic(
    database: Database,
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) !void {
    std.debug.assert(database.campaigns.len <= campaign_limit);

    const output = try gpa.alloc(u8, database_size_max);
    defer gpa.free(output);
    var output_writer = std.Io.Writer.fixed(output);
    output_writer.print("{f}\n", .{
        std.json.fmt(database, .{ .whitespace = .indent_2 }),
    }) catch return error.DatabaseTooLarge;

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

fn validateFailure(
    arena: std.mem.Allocator,
    encoded: ?[]const u8,
    max_input_len: ?u32,
) !void {
    const content = encoded orelse return;
    const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(content);
    if (max_input_len) |limit| {
        if (decoded_len > limit) return error.FailureTooLong;
    }
    const decoded = try arena.alloc(u8, decoded_len);
    try std.base64.standard.Decoder.decode(decoded, content);
}

const LegacyResult = struct {
    branch: []const u8,
    commit_sha: []const u8,
    commit_timestamp: u64,
    start_timestamp: u64,
    target: []const u8,
    edges_found: u64,
    total_edges: u64,
    unique_crashes: u64,
    unique_hangs: u64,
    total_execs: u64,
    kind: enum { success, crash, hang },
    encoded_failure: []const u8,
};
