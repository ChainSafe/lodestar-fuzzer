const std = @import("std");
const Database = @import("Database.zig");

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
        .limited(Database.database_size_max + 1),
    );
    if (content.len > Database.database_size_max) return error.DatabaseTooLarge;
    const parsed_database = try Database.parse(arena, content);

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
    switch (parsed_database) {
        .legacy => try writeLegacyNotice(writer),
        .current => |database| try writeDatabase(writer, database, arena),
    }
    try writer.writeAll(
        \\  <p class="foot">
        \\    The database retains the latest three complete campaigns per project. Re-running
        \\    the same GitHub Actions run replaces that campaign.
        \\  </p>
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
        \\  <title>Consensus fuzz results</title>
        \\  <style>
        \\    :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
        \\    body { margin: 0; }
        \\    main { margin: 0 auto; max-width: 110rem; padding: 2rem; }
        \\    h1 { margin-top: 0; }
        \\    section { margin: 2rem 0 3rem; }
        \\    table { border-collapse: collapse; width: 100%; }
        \\    th, td { border-bottom: 1px solid #8888; padding: .65rem; text-align: left; }
        \\    th { position: sticky; top: 0; z-index: 1; background: Canvas; }
        \\    code { overflow-wrap: anywhere; }
        \\    .failure { color: #b3261e; font-weight: 700; }
        \\    .foot, .summary { color: GrayText; }
        \\    .metric {
        \\      position: relative;
        \\      padding: 0;
        \\      border: 0;
        \\      border-bottom: 1px dotted currentColor;
        \\      background: none;
        \\      color: inherit;
        \\      cursor: help;
        \\      font: inherit;
        \\      outline-offset: .2rem;
        \\    }
        \\    .metric::before {
        \\      content: "?";
        \\      display: inline-grid;
        \\      place-items: center;
        \\      width: 1rem;
        \\      height: 1rem;
        \\      margin-right: .3rem;
        \\      border: 1px solid currentColor;
        \\      border-radius: 50%;
        \\      font-size: .7rem;
        \\      line-height: 1;
        \\    }
        \\    .metric::after {
        \\      content: attr(data-tooltip);
        \\      position: absolute;
        \\      top: calc(100% + .7rem);
        \\      left: 50%;
        \\      z-index: 2;
        \\      width: min(22rem, 75vw);
        \\      padding: .65rem .75rem;
        \\      border: 1px solid #8888;
        \\      border-radius: .4rem;
        \\      background: Canvas;
        \\      color: CanvasText;
        \\      box-shadow: 0 .3rem 1rem #0004;
        \\      font-size: .85rem;
        \\      font-weight: 400;
        \\      line-height: 1.35;
        \\      opacity: 0;
        \\      pointer-events: none;
        \\      transform: translateX(-50%);
        \\      transition: opacity .12s ease;
        \\      visibility: hidden;
        \\      white-space: normal;
        \\    }
        \\    .metric:hover::after, .metric:focus::after {
        \\      opacity: 1;
        \\      visibility: visible;
        \\    }
        \\    th:first-child .metric::after { left: 0; transform: none; }
        \\    th:last-child .metric::after { right: 0; left: auto; transform: none; }
        \\    @media (max-width: 60rem) {
        \\      main { padding: 1rem; }
        \\      table { display: block; overflow: auto; }
        \\    }
        \\  </style>
        \\</head>
        \\<body>
        \\<main>
        \\  <h1>Consensus fuzz results</h1>
        \\  <p><a href="https://github.com/ChainSafe/lodestar-fuzzer/blob/main/data.json">
        \\    Raw data
        \\  </a></p>
        \\  <p class="foot">
        \\    Hover over or focus a ? column heading to see its definition.
        \\    <a href="https://aflplus.plus/docs/afl-fuzz_approach/">AFL map edges</a>
        \\    are coverage-map slots reached in each instrumented target binary, not source line
        \\    or function coverage. Queue entries are inputs that produced interesting coverage.
        \\  </p>
        \\
    );
}

fn writeLegacyNotice(writer: *std.Io.Writer) !void {
    try writer.writeAll(
        \\  <section>
        \\    <h2>Legacy results</h2>
        \\    <p>The existing rows predate campaign IDs and cannot be grouped reliably. The next
        \\      completed campaign will migrate the database to campaign-aware history.</p>
        \\  </section>
        \\
    );
}

fn writeDatabase(
    writer: *std.Io.Writer,
    database: Database,
    arena: std.mem.Allocator,
) !void {
    try database.validate(arena);

    if (database.campaigns.len == 0) {
        try writer.writeAll("  <p>No campaigns recorded.</p>\n");
        return;
    }

    for (database.campaigns) |campaign| {
        try writeCampaign(writer, campaign);
    }
}

fn writeCampaign(writer: *std.Io.Writer, campaign: Database.Campaign) !void {
    var total_execs: u64 = 0;
    var total_runtime_seconds: u64 = 0;
    var total_corpus_found: u64 = 0;
    var total_crashes: u64 = 0;
    var total_hangs: u64 = 0;
    for (campaign.results) |result| {
        total_execs = std.math.add(u64, total_execs, result.total_execs) catch {
            return error.MetricOverflow;
        };
        total_runtime_seconds = std.math.add(
            u64,
            total_runtime_seconds,
            result.run_time_seconds,
        ) catch return error.MetricOverflow;
        total_corpus_found = std.math.add(u64, total_corpus_found, result.corpus_found) catch {
            return error.MetricOverflow;
        };
        total_crashes = std.math.add(u64, total_crashes, result.unique_crashes) catch {
            return error.MetricOverflow;
        };
        total_hangs = std.math.add(u64, total_hangs, result.unique_hangs) catch {
            return error.MetricOverflow;
        };
    }

    try writer.writeAll("  <section>\n    <h2>");
    try writeEscaped(writer, campaign.project_id);
    try writer.writeAll(" campaign <a href=\"");
    try writer.writeAll("https://github.com/ChainSafe/lodestar-fuzzer/actions/runs/");
    try writer.print("{d}\">#{d}</a></h2>\n    <p><code>", .{
        campaign.campaign_id,
        campaign.campaign_id,
    });
    try writeEscaped(writer, campaign.ref);
    try writer.writeAll("</code> · <a href=\"");
    try writer.writeAll("https://github.com/");
    try writeEscaped(writer, campaign.repository);
    try writer.writeAll("/commit/");
    try writeEscaped(writer, campaign.commit_sha);
    try writer.writeAll("\"><code>");
    try writeEscaped(writer, campaign.commit_sha[0..12]);
    try writer.writeAll("</code></a></p>\n");
    try writer.print(
        "    <p class=\"summary\">{d} targets · {d} new queue entries · " ++
            "{d} executions · {d}h {d}m target time · {d} crashes · {d} hangs</p>\n",
        .{
            campaign.results.len,
            total_corpus_found,
            total_execs,
            total_runtime_seconds / 3600,
            total_runtime_seconds % 3600 / 60,
            total_crashes,
            total_hangs,
        },
    );
    try writer.writeAll(
        \\    <table>
        \\      <thead>
        \\        <tr>
        \\          <th><button class="metric" type="button"
        \\            aria-label="Target. Fuzz harness name and corpus-format version."
        \\            data-tooltip="Fuzz harness name. corpus vN is the target's corpus-format
        \\              namespace, not a campaign number.">Target</button></th>
        \\          <th><button class="metric" type="button"
        \\            aria-label="Failures. Unique AFL++ crashes and hangs saved in this run."
        \\            data-tooltip="Unique crashes and hangs AFL++ saved in this run. Expand a
        \\              base64 sample here; download the run artifact for every raw input."
        \\            >Failures</button></th>
        \\          <th><button class="metric" type="button"
        \\            aria-label="Queue. New entries and total entries when the worker stopped."
        \\            data-tooltip="new is AFL++ corpus_found for this run. at exit is corpus_count,
        \\              the total queue size when the worker stopped.">Queue</button></th>
        \\          <th><button class="metric" type="button"
        \\            aria-label="AFL map edges. Coverage-map slots reached by the exit queue."
        \\            data-tooltip="AFL++ edges_found: coverage-map slots reached by the exit queue.
        \\              This is not source-line or function coverage and is not comparable across
        \\              different binaries.">AFL map edges</button></th>
        \\          <th><button class="metric" type="button"
        \\            aria-label="Work. Executions, average throughput, and target runtime."
        \\            data-tooltip="Total executions, average executions per second, and target
        \\              runtime. Target jobs run in parallel.">Work</button></th>
        \\        </tr>
        \\      </thead>
        \\      <tbody>
        \\
    );
    for (campaign.results) |result| try writeResult(writer, result);
    try writer.writeAll("      </tbody>\n    </table>\n  </section>\n");
}

fn writeResult(writer: *std.Io.Writer, result: Database.TargetResult) !void {
    const failed = result.unique_crashes > 0 or result.unique_hangs > 0;
    try writer.writeAll("        <tr><td><code>");
    try writeEscaped(writer, result.target);
    try writer.print("</code><br><small>corpus v{d}</small></td><td class=\"", .{
        result.corpus_version,
    });
    if (failed) try writer.writeAll("failure");
    try writer.writeAll("\">");
    if (failed) {
        try writer.print("{d} crashes<br><small>{d} hangs</small>", .{
            result.unique_crashes,
            result.unique_hangs,
        });
        try writeFailure(writer, "crash", result.encoded_crash);
        try writeFailure(writer, "hang", result.encoded_hang);
    } else {
        try writer.writeAll("None");
    }
    try writer.print(
        "</td><td>{d} new<br><small>{d} at exit</small></td><td>{d}</td>" ++
            "<td>{d} executions<br><small>{d}/s · {d}s</small></td>",
        .{
            result.corpus_found,
            result.corpus_count,
            result.edges_found,
            result.total_execs,
            result.total_execs / result.run_time_seconds,
            result.run_time_seconds,
        },
    );
    try writer.writeAll("</tr>\n");
}

fn writeFailure(writer: *std.Io.Writer, kind: []const u8, encoded: ?[]const u8) !void {
    const content = encoded orelse return;
    try writer.writeAll("<details><summary>");
    try writer.writeAll(kind);
    try writer.writeAll(" base64</summary><code>");
    try writeEscaped(writer, content);
    try writer.writeAll("</code></details>");
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
