# Consensus Fuzzer

This repository runs finite AFL++ campaigns against fuzz targets published by independent projects.
Each target project owns target behavior, committed seeds, executable construction, and corpus
replay. This repository owns reusable campaign orchestration, project-specific schedules,
runner-local campaign corpora, the result database, and the GitHub Pages report.

The workflow structure is inspired by
[`roc-lang/roc-compiler-fuzz`](https://github.com/roc-lang/roc-compiler-fuzz). The controller is an
independent Zig and GitHub Actions adaptation for project-owned target metadata and a single AFL++
worker per target.

## Workflow

`.github/workflows/fuzz.yml` is the reusable single-project campaign. Small caller workflows provide
the project identity, repository, canonical ref, metadata path, and schedule. The current
`fuzz-lodestar-z.yml` caller starts every six hours and uses Lodestar-Z `main` for 7,200 seconds. Its
manual entry accepts a Lodestar-Z branch, tag, or commit and a per-target duration.

The hosted discovery job checks out the selected project revision once and runs the shared project
contract:

```sh
cd target-project/test/fuzz
zig build fuzz-metadata
```

It validates the configured compact target metadata file, resolves the checkout to an exact
40-character commit SHA, and creates the target matrix. Every campaign job checks out that exact SHA
and runs only:

```sh
zig build -Doptimize=ReleaseSafe -Dfuzz-target="$TARGET"
zig build replay-corpus -Doptimize=ReleaseSafe -Dfuzz-target="$TARGET"
```

Each matrix item starts one finite `afl-fuzz` process in explore mode. The target's published
`max_input_len` is passed through `-G`; AFL++ writes the single-worker state under `default/`.
Campaign jobs upload results but never modify Git.

The final hosted aggregation job requires exactly one artifact for every discovered target. Each
artifact contains `result.json` and every crash or hang retained by AFL++. The Zig merger rejects
missing, duplicate, unexpected, or campaign-mismatched results, retains the latest three complete
campaigns per project in `data.json`, generates `www/index.html`, and performs at most one commit and
push.
Re-running the same GitHub Actions run replaces that campaign. A separate hosted job publishes the
generated site through GitHub Pages.

Aggregation runs only after discovery and every target job complete successfully. A target job may
still preserve and upload failure evidence after corpus post-processing fails, but an incomplete
matrix never updates `data.json` or Pages.

## Runner contract

Campaign jobs require these labels:

```text
self-hosted, linux, x64, lodestar-fuzz
```

The host must already provide Zig 0.16.0, LLVM 18, and AFL++ 5.02c. Set the repository variable
`AFL_BIN_DIR` if AFL++ is not installed at `/opt/afl++/5.02c/bin`. The workflow checks versions and
reads `/proc/sys/kernel/core_pattern`; it does not install packages, run `sudo`, or provision the
runner. A piped `core_pattern` fails the preflight.

All agents with the `lodestar-fuzz` label must run on the same physical host and share one
`STATE_ROOT`. Registering that label on another host would split the persistent corpus. Multiple
physical hosts require shared storage or distinct labels that bind each project to one host.

Set the repository variable `STATE_ROOT` to relocate persistent state from
`/var/lib/lodestar-fuzzer`. Each target owns:

```text
$STATE_ROOT/
└── projects/<project>/
    ├── corpus/<target>/v<corpus-version>/
    │   ├── current -> versions/<generation>
    │   └── versions/<generation>/
    ├── failures/<target>/v<corpus-version>/<generation>/
    │   ├── result.json
    │   ├── crashes/
    │   └── hangs/
    └── staging/<target>/v<corpus-version>/<generation>/
```

The project, target, and target-published corpus version form the persistent corpus identity. Only a
controller `main` campaign for that project's canonical ref may update `current`. Other runs may use
`current` as input but cannot publish over it. The job overlays current inputs with
`corpus/<target>-cmin` under SHA-256 content names, so equal inputs deduplicate and unrelated inputs
cannot overwrite each other by basename. It then runs AFL++ and minimizes the new `default/queue`
with `afl-cmin`. A cmin failure stops publication and propagates its original error, leaving the
previous `current` corpus unchanged.
Before publication, every candidate must be a nonempty flat directory of regular inputs within the
target limit and must pass `zig-out/bin/repro-<target>` as a directory replay.

Publication renames the candidate to a new immutable version, creates a `current.next` symlink, and
atomically renames the symlink over `current`. The live version is never changed in place. Cleanup
retains the new current version and its immediate predecessor and only removes resolved paths below
that target's private version and staging directories.

Every AFL crash and hang is copied unchanged. A campaign with failures moves those inputs into the
runner's persistent `failures` directory before result validation, then uploads that directory as the
target artifact. GitHub retains the downloadable artifact for 30 days; the runner copy is the durable
source until failure storage moves to S3. Campaigns without failures leave no persistent failure
directory. The collector enforces AFL++ 5.02c's limits of 25,600 unique crashes and 512 unique hangs
per target run.

Before deploying this workflow, copy or move each existing `$STATE_ROOT/corpus/<target>` directory to
`$STATE_ROOT/projects/lodestar-z/corpus/<target>/v1`. Both layouts may coexist only when the new
target has a `current` symlink, which permits branch validation while the default workflow still uses
the old layout. Remove the old layout after this workflow reaches `main`.

## Adding a project

A project must expose the same bounded contract under `test/fuzz`:

- `zig build fuzz-metadata` writes a validated target matrix.
- `zig build -Dfuzz-target=<name>` builds one `fuzz-<name>` binary.
- `zig build replay-corpus -Dfuzz-target=<name>` replays committed inputs.
- `corpus/<name>-cmin` contains the committed bootstrap corpus.
- `zig-out/bin/repro-<name>` replays a file or flat corpus directory.

Add one small caller workflow that invokes `.github/workflows/fuzz.yml` with a unique `project_id`,
the repository, canonical ref, metadata path, and whether the project needs legacy corpus migration.
Campaigns remain globally serialized on the shared runner, while corpus, failures, artifacts, and
database rows stay isolated by project identity.

The database currently accepts two project identities, matching the planned Lodestar-Z and Zapi
campaigns. Extending that bound requires an explicit configuration change.

Lodestar-Z satisfies this contract through its pending fuzz PR. Zapi does not expose it yet, so its
caller should be added only after Zapi publishes concrete targets and reproducers.

## Zig tools

Zig 0.16.0 builds all tools:

```sh
zig build
zig build collect-result -- <project> <repository> <campaign-id> <ref> <sha> <commit-time> \
  <target> <corpus-version> <max-input> <afl-output> <crashes> <hangs> <result.json>
zig build merge-results -- <project> <repository> <campaign-id> <ref> <sha> <commit-time> \
  <targets.json> <artifact-directory> <data.json>
zig build generate-website
```

The versioned result database identifies each campaign by project, repository, and GitHub Actions run.
Each target records its corpus version, run time, execution count, exit queue size, locally discovered
queue entries, AFL map edges, crash and hang counts, and at most one raw sample of each failure kind.
Each `result.json` is limited to 4 MiB. The database is limited to 32 MiB and updates atomically, so
an oversized result fails without replacing the previous database.

The merger accepts the original flat result array only as a one-time legacy input. The first
campaign-aware update replaces those rows because their campaign membership cannot be recovered
reliably.

[AFL map edges](https://aflplus.plus/docs/afl-fuzz_approach/) are instrumentation slots, not source
line or function coverage. The Pages report emphasizes newly discovered queue entries, corpus size,
execution throughput, duration, failures, and the absolute map-edge count for each target.
