# Lodestar Fuzzer

This repository runs finite AFL++ campaigns against every fuzz target published by
[Lodestar-Z](https://github.com/ChainSafe/lodestar-z). Lodestar-Z owns target behavior, committed
seeds, executable construction, and corpus replay. This repository owns the schedule, runner-local
campaign corpus, result database, and GitHub Pages report.

The workflow structure is inspired by
[`roc-lang/roc-compiler-fuzz`](https://github.com/roc-lang/roc-compiler-fuzz). The controller is an
independent Zig and GitHub Actions adaptation for Lodestar-Z's target metadata and a single AFL++
worker per target.

## Workflow

Scheduled runs use Lodestar-Z `main` for 7,200 seconds. A manual run accepts a Lodestar-Z branch,
tag, or commit and a per-target duration. The hosted discovery job checks out that ref once, runs:

```sh
cd lodestar-z/test/fuzz
zig build fuzz-metadata
```

It validates the compact `zig-out/share/lodestar-z-fuzz/targets.json`, resolves the checkout to an
exact 40-character commit SHA, and creates the target matrix. Every campaign job checks out that
exact SHA and runs only:

```sh
zig build -Doptimize=ReleaseSafe -Dfuzz-target="$TARGET"
zig build replay-corpus -Doptimize=ReleaseSafe -Dfuzz-target="$TARGET"
```

Each matrix item starts one finite `afl-fuzz` process in explore mode. The target's published
`max_input_len` is passed through `-G`; AFL++ writes the single-worker state under `default/`.
Campaign jobs upload results but never modify Git.

The final hosted aggregation job requires exactly one artifact for every discovered target. The Zig
merger rejects missing, duplicate, unexpected, or campaign-mismatched results, retains the latest
three complete campaigns in `data.json`, generates `www/index.html`, and performs at most one commit
and push. Re-running the same GitHub Actions run replaces that campaign. A separate hosted job
publishes the generated site through GitHub Pages.

## Runner contract

Campaign jobs require these labels:

```text
self-hosted, linux, x64, lodestar-fuzz
```

The host must already provide Zig 0.16.0, LLVM 18, and AFL++ 5.02c. Set the repository variable
`AFL_BIN_DIR` if AFL++ is not installed at `/opt/afl++/5.02c/bin`. The workflow checks versions and
reads `/proc/sys/kernel/core_pattern`; it does not install packages, run `sudo`, or provision the
runner. A piped `core_pattern` fails the preflight.

Set the repository variable `STATE_ROOT` to relocate persistent state from
`/var/lib/lodestar-fuzzer`. Each target owns:

```text
$STATE_ROOT/
├── corpus/<target>/
│   ├── current -> versions/<generation>
│   └── versions/<generation>/
└── staging/<target>/<run-id>/
```

The job overlays current inputs with `corpus/<target>-cmin`, runs AFL++, and minimizes the new
`default/queue` with `afl-cmin`. If cmin fails, the unminimized queue is the only fallback. Before
publication, every candidate must be a nonempty flat directory of regular inputs within the target
limit and must pass `zig-out/bin/repro-<target>` as a directory replay.

Publication renames the candidate to a new immutable version, creates a `current.next` symlink, and
atomically renames the symlink over `current`. The live version is never changed in place. Cleanup
retains the new current version and its immediate predecessor and only removes resolved paths below
that target's private version and staging directories.

## Zig tools

Zig 0.16.0 builds all tools:

```sh
zig build
zig build collect-result -- <campaign-id> <ref> <sha> <commit-time> <target> <max-input> \
  <afl-output> <crashes> <hangs> <result.json>
zig build merge-results -- <campaign-id> <ref> <sha> <commit-time> <targets.json> \
  <artifact-directory> <data.json>
zig build generate-website
```

The versioned result database groups every target from one GitHub Actions run under its campaign ID.
Each target records run time, execution count, exit queue size, locally discovered queue entries,
AFL map edges, crash and hang counts, and at most one minimized sample of each failure kind. The
per-target artifact is limited to 4 MiB. The database is limited to 32 MiB and updates atomically,
so an oversized result fails without replacing the previous database.

The merger accepts the original flat result array only as a one-time legacy input. The first
campaign-aware update replaces those rows because their campaign membership cannot be recovered
reliably.

[AFL map edges](https://aflplus.plus/docs/afl-fuzz_approach/) are instrumentation slots, not source
line or function coverage. The Pages report emphasizes newly discovered queue entries, corpus size,
execution throughput, duration, failures, and the absolute map-edge count for each target.
