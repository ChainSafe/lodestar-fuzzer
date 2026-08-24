const std = @import("std");
const FuzzResult = @import("FuzzResult.zig");

const result_limit: u8 = 20;

pub fn main(init: std.process.Init) !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 1) return error.UnexpectedArguments;

    const content = try std.Io.Dir.cwd().readFileAlloc(
        init.io,
        "data.json",
        arena,
        .limited(32 * 1024 * 1024),
    );
    const results = try std.json.parseFromSliceLeaky(
        []FuzzResult,
        arena,
        content,
        .{ .ignore_unknown_fields = false },
    );
    if (results.len > result_limit) return error.DatabaseExceedsResultLimit;

    std.Io.Dir.cwd().createDir(init.io, "www", .default_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };
    var output_directory = try std.Io.Dir.cwd().openDir(init.io, "www", .{});
    defer output_directory.close(init.io);

    var atomic_file = try output_directory.createFileAtomic(
        init.io,
        "index.html",
        .{ .replace = true },
    );
    defer atomic_file.deinit(init.io);

    var buffer: [16 * 1024]u8 = undefined;
    var file_writer = atomic_file.file.writer(init.io, &buffer);
    const writer = &file_writer.interface;
    try writeHeader(writer);
    try writeResults(writer, results);
    try writer.writeAll(
        \\    </tbody>
        \\  </table>
        \\  <p class="foot">The database retains the 20 highest-priority recent results.</p>
        \\</main>
        \\</body>
        \\</html>
        \\
    );
    try writer.flush();
    try atomic_file.replace(init.io);
}

fn writeHeader(writer: *std.Io.Writer) !void {
    try writer.writeAll(
        \\<!doctype html>
        \\<html lang="en">
        \\<head>
        \\  <meta charset="utf-8">
        \\  <meta name="viewport" content="width=device-width, initial-scale=1">
        \\  <title>Lodestar-Z fuzz results</title>
        \\  <style>
        \\    :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
        \\    body { margin: 0; }
        \\    main { margin: 0 auto; max-width: 110rem; padding: 2rem; }
        \\    h1 { margin-top: 0; }
        \\    table { border-collapse: collapse; width: 100%; }
        \\    th, td { border-bottom: 1px solid #8888; padding: .65rem; text-align: left; }
        \\    th { position: sticky; top: 0; background: Canvas; }
        \\    code { overflow-wrap: anywhere; }
        \\    .success { color: #167a35; font-weight: 700; }
        \\    .crash, .hang { color: #b3261e; font-weight: 700; }
        \\    .foot { color: GrayText; }
        \\    @media (max-width: 60rem) { main { padding: 1rem; } table { display: block; overflow: auto; } }
        \\  </style>
        \\</head>
        \\<body>
        \\<main>
        \\  <h1>Lodestar-Z fuzz results</h1>
        \\  <p><a href="https://github.com/ChainSafe/lodestar-fuzzer/blob/main/data.json">Raw data</a></p>
        \\  <p class="foot">
        \\    <a href="https://aflplus.plus/docs/afl-fuzz_approach/">AFL map edges</a>
        \\    are coverage-map slots reached in each instrumented target binary,
        \\    not source line or function coverage. Compare them only between runs of the same
        \\    target and instrumentation.
        \\  </p>
        \\  <table>
        \\    <thead>
        \\      <tr>
        \\        <th>Commit</th><th>Ref</th><th>Target</th><th>Result</th>
        \\        <th>Run start</th><th>AFL map edges</th><th>Executions</th>
        \\        <th>Failure input</th>
        \\      </tr>
        \\    </thead>
        \\    <tbody>
        \\
    );
}

fn writeResults(writer: *std.Io.Writer, results: []const FuzzResult) !void {
    for (results) |result| {
        try writer.writeAll("      <tr><td><a href=\"");
        try writer.writeAll("https://github.com/ChainSafe/lodestar-z/commit/");
        try writeEscaped(writer, result.commit_sha);
        try writer.writeAll("\"><code>");
        try writeEscaped(writer, result.commit_sha[0..12]);
        try writer.writeAll("</code></a><br><small>");
        try writer.print("{d}", .{result.commit_timestamp});
        try writer.writeAll("</small></td><td>");
        try writeEscaped(writer, result.branch);
        try writer.writeAll("</td><td><code>");
        try writeEscaped(writer, result.target);
        try writer.writeAll("</code></td><td class=\"");
        try writer.writeAll(@tagName(result.kind));
        try writer.writeAll("\">");
        try writer.writeAll(@tagName(result.kind));
        try writer.print("<br><small>{d} crashes, {d} hangs</small>", .{
            result.unique_crashes,
            result.unique_hangs,
        });
        try writer.print(
            "</td><td>{d}</td><td>{d} found<br>" ++
                "<small>{d} instrumented</small></td><td>{d}</td><td>",
            .{
                result.start_timestamp,
                result.edges_found,
                result.total_edges,
                result.total_execs,
            },
        );
        if (result.kind == .success) {
            try writer.writeAll("None");
        } else {
            try writer.writeAll("<details><summary>base64</summary><code>");
            try writeEscaped(writer, result.encoded_failure);
            try writer.writeAll("</code></details>");
        }
        try writer.writeAll("</td></tr>\n");
    }
}

fn writeEscaped(writer: *std.Io.Writer, value: []const u8) !void {
    for (value) |byte| {
        switch (byte) {
            '&' => try writer.writeAll("&amp;"),
            '<' => try writer.writeAll("&lt;"),
            '>' => try writer.writeAll("&gt;"),
            '"' => try writer.writeAll("&quot;"),
            '\'' => try writer.writeAll("&#39;"),
            else => try writer.writeByte(byte),
        }
    }
}
