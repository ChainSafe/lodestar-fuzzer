# Lodestar Fuzzer

Periodic AFL++ campaigns for [lodestar-z](https://github.com/ChainSafe/lodestar-z), modeled after
[`roc-lang/roc-compiler-fuzz`](https://github.com/roc-lang/roc-compiler-fuzz).

The repository owns scheduling and mutable campaign state. Lodestar-Z owns target semantics,
instrumented binaries, repro binaries, committed seed corpora, and the generated target manifest.
One scheduled GitHub Actions job checks out both repositories, builds the current project revision,
replays its committed corpus, and runs every selected target for a finite duration.

## Runner contract

The workflow uses a dedicated runner with these labels:

```text
self-hosted, linux, x64, fuzz
```

The host must provide Python 3, Git, Zig 0.16.0, LLVM 18, and AFL++ 5.02c built from commit
`011cd189801830253c66ecd3cd6919ec01b46c34`. The controller checks the Zig and AFL++ versions before
building. Tool installation and runner registration remain host-administration tasks and do not run
inside each campaign.

The workflow prepends `/opt/afl++/5.02c/bin` to `PATH`. Set the repository variable
`LODESTAR_FUZZ_AFL_BIN_DIR` if the pinned installation lives elsewhere.

Provision the dedicated host with `/opt/afl++/5.02c/bin/afl-system-config` before enabling the
workflow and after each reboot. This configures Linux crash handling and CPU settings required by
AFL++. The workflow does not use `sudo` or mutate host configuration; the controller fails its
read-only preflight if `core_pattern` still delegates crashes to an external utility. Do not attach
this workflow to a shared host.

The authoritative mutable state defaults to:

```text
~/.local/state/lodestar-fuzzer/lodestar-z
```

Set the repository variable `LODESTAR_FUZZ_STATE_ROOT` to use another persistent path. Back up that
directory as host data. GitHub artifacts contain reports and newly discovered inputs, but are not
the corpus backup.

## Schedule and manual runs

The workflow runs every four hours. Its defaults are:

| Setting | Default | Repository variable |
| --- | ---: | --- |
| Campaign duration per target | 7,200 seconds | `LODESTAR_FUZZ_DURATION_SECONDS` |
| Concurrent targets | 13 | `LODESTAR_FUZZ_JOBS` |
| Per-execution timeout | 1,000 ms | `LODESTAR_FUZZ_TIMEOUT_MS` |
| Per-worker memory limit | 1,024 MiB | `LODESTAR_FUZZ_MEMORY_MB` |

`workflow_dispatch` can override the duration, Lodestar-Z ref, and comma-separated target or group
selectors. Scheduled runs fuzz `main` and select every manifest target. Concurrency prevents two
campaigns from mutating the persistent state at the same time. AFL++ CPU affinity is disabled so
the host scheduler can run the 13 target processes on the 12-core runner.

## Project contract

The controller expects the checked-out project to provide:

```text
test/fuzz/
├── build.zig
├── corpus/<target>-cmin/
└── zig-out/
    ├── bin/fuzz-<target>
    ├── bin/repro-<target>
    └── share/lodestar-z-fuzz/targets.tsv
```

It runs these commands from `test/fuzz`:

```sh
zig build -Doptimize=ReleaseSafe
zig build replay-corpus -Doptimize=ReleaseSafe
```

`targets.tsv` schema 2 supplies each target's group, executable, committed corpus, and maximum input
length. The controller passes that target-specific limit to AFL++ with `-G`; it does not impose
Roc's uniform 16 KiB limit.

Each finite run starts from the persistent minimized corpus plus newly committed seeds. After a
run, the controller merges the new queue and invokes AFL++ 5.02c `afl-cmin` through stdin, without
`@@`, `afl-cmin.bash`, or `AFL_NO_FORKSRV`. The minimized result atomically replaces that target's
persistent corpus.

Crash and hang inputs are minimized with `afl-tmin` when possible and otherwise retained unchanged,
matching Roc's lossless fallback. Inputs are stored by SHA-256 under `failures/`; identical bytes are
not stored twice. This is artifact deduplication, not proof that two different inputs represent
different bugs. Stored failures are replayed against each newly built revision and reported as
active, changed, or no longer reproduced. Promotion into a Lodestar-Z regression test remains a
reviewed source change.

## Local invocation

The controller operates only on a clean project checkout:

```sh
python3 controller.py \
  --project-root /path/to/lodestar-z \
  --duration-seconds 7200 \
  --jobs 13 \
  --timeout-ms 1000 \
  --memory-mb 1024
```

Use `--selectors ssz_basic,bls` to run an explicit target and a manifest group. The default state
path may be overridden with `--state-root`. Reports are written below `reports/` unless
`--report-dir` is supplied.

The controller never pushes to Lodestar-Z, updates committed corpora, creates issues, or changes the
runner configuration.
