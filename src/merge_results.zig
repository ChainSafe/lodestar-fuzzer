const std = @import("std");
const Database = @import("Database.zig");

const legacy_result_limit: u8 = 20;

pub fn main(init: std.process.Init) !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 8) return error.ExpectedSevenArguments;

    const campaign_id = try std.fmt.parseInt(u64, args[1], 10);
    const expected_ref = args[2];
    const expected_sha = args[3];
    const expected_commit_timestamp = try std.fmt.parseInt(u64, args[4], 10);
    const targets_path = args[5];
    const results_path = args[6];
    const database_path = args[7];
    if (campaign_id == 0) return error.InvalidCampaignID;
    try Database.validateRef(expected_ref);
    try Database.validateSHA(expected_sha);
    if (expected_commit_timestamp == 0) return error.InvalidCommitTimestamp;

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

    const new_results = try loadMatrixResults(arena, init.io, .{
        .campaign_id = campaign_id,
        .expected_ref = expected_ref,
        .expected_sha = expected_sha,
        .expected_commit_timestamp = expected_commit_timestamp,
        .manifest = manifest,
        .results_path = results_path,
    });
    const new_campaign: Database.Campaign = .{
        .campaign_id = campaign_id,
        .ref = expected_ref,
        .commit_sha = expected_sha,
        .commit_timestamp = expected_commit_timestamp,
        .start_timestamp = Database.campaignStartTimestamp(new_results),
        .results = new_results,
    };

    const database_content = try std.Io.Dir.cwd().readFileAlloc(
        init.io,
        database_path,
        arena,
        .limited(Database.database_size_max + 1),
    );
    if (database_content.len > Database.database_size_max) return error.DatabaseTooLarge;
    const parsed_database = try Database.parse(arena, database_content);

    var campaigns: std.ArrayList(Database.Campaign) = .empty;
    defer campaigns.deinit(gpa);
    try campaigns.append(gpa, new_campaign);
    switch (parsed_database) {
        .legacy => |legacy| {
            if (legacy.len > legacy_result_limit) return error.LegacyDatabaseExceedsResultLimit;
        },
        .current => |database| {
            try database.validate(arena);
            for (database.campaigns) |campaign| {
                if (campaign.campaign_id != campaign_id) {
                    try campaigns.append(gpa, campaign);
                }
            }
        },
    }

    std.mem.sort(Database.Campaign, campaigns.items, {}, Database.campaignLessThan);
    if (campaigns.items.len > Database.campaign_limit) {
        campaigns.shrinkRetainingCapacity(Database.campaign_limit);
    }

    try Database.writeAtomic(.{
        .schema_version = Database.schema_version_current,
        .campaigns = campaigns.items,
    }, gpa, init.io, database_path);
}

const LoadMatrixOptions = struct {
    campaign_id: u64,
    expected_ref: []const u8,
    expected_sha: []const u8,
    expected_commit_timestamp: u64,
    manifest: Manifest,
    results_path: []const u8,
};

fn loadMatrixResults(
    arena: std.mem.Allocator,
    io: std.Io,
    options: LoadMatrixOptions,
) ![]const Database.TargetResult {
    var results_directory = try std.Io.Dir.cwd().openDir(
        io,
        options.results_path,
        .{ .iterate = true },
    );
    defer results_directory.close(io);

    const found = try arena.alloc(bool, options.manifest.include.len);
    @memset(found, false);
    const results = try arena.alloc(Database.TargetResult, options.manifest.include.len);

    const artifact_prefix = try std.fmt.allocPrint(
        arena,
        "result-{s}-",
        .{options.expected_sha},
    );
    var artifact_count: u16 = 0;
    var iterator = results_directory.iterate();
    while (try iterator.next(io)) |entry| {
        artifact_count += 1;
        if (artifact_count > Database.target_count_max) return error.TooManyResultArtifacts;
        if (entry.kind != .directory) return error.InvalidResultArtifact;
        if (!std.mem.startsWith(u8, entry.name, artifact_prefix)) {
            return error.UnexpectedResultArtifact;
        }

        const target_name = entry.name[artifact_prefix.len..];
        const target_index = findTarget(options.manifest.include, target_name) orelse {
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
            .limited(Database.artifact_size_max + 1),
        );
        if (content.len > Database.artifact_size_max) return error.ResultArtifactTooLarge;
        const artifact = try std.json.parseFromSliceLeaky(
            Database.TargetArtifact,
            arena,
            content,
            .{ .ignore_unknown_fields = false },
        );
        try validateTargetArtifact(
            arena,
            options,
            options.manifest.include[target_index],
            artifact,
        );

        results[target_index] = artifact.result;
        found[target_index] = true;
    }

    if (artifact_count != options.manifest.include.len) {
        return error.ResultArtifactCountMismatch;
    }
    for (found) |target_found| {
        if (!target_found) return error.MissingTargetResult;
    }
    return results;
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

fn validateTargetArtifact(
    arena: std.mem.Allocator,
    options: LoadMatrixOptions,
    target: Target,
    artifact: Database.TargetArtifact,
) !void {
    if (artifact.campaign_id != options.campaign_id) return error.CampaignIDMismatch;
    if (!std.mem.eql(u8, artifact.ref, options.expected_ref)) return error.RefMismatch;
    if (!std.mem.eql(u8, artifact.commit_sha, options.expected_sha)) {
        return error.CommitSHAMismatch;
    }
    if (artifact.commit_timestamp != options.expected_commit_timestamp) {
        return error.CommitTimestampMismatch;
    }
    if (!std.mem.eql(u8, artifact.result.target, target.target)) return error.TargetMismatch;
    try Database.validateTargetResult(arena, artifact.result, target.max_input_len);
}

fn validateManifest(manifest: Manifest) !void {
    if (manifest.include.len == 0) return error.EmptyTargetMatrix;
    if (manifest.include.len > Database.target_count_max) return error.TooManyTargets;

    for (manifest.include, 0..) |target, target_index| {
        try Database.validateTargetName(target.target);
        if (target.max_input_len == 0) return error.InvalidInputLimit;
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

const Manifest = struct {
    include: []const Target,
};

const Target = struct {
    target: []const u8,
    max_input_len: u32,
};
