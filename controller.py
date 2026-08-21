#!/usr/bin/env python3

import argparse
import concurrent.futures
import csv
import dataclasses
import datetime
import fcntl
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

MANIFEST_HEADER = ["schema", "group", "target", "executable", "cmin", "max_input_len"]
TARGET_PATTERN = re.compile(r"^[a-z0-9_]+$")
MAX_TARGETS = 64
MAX_INPUTS = 100_000
MAX_FAILURES_PER_KIND = 1_024
MAX_ARCHIVED_FAILURES = 4_096
EXPECTED_ZIG_VERSION = "0.16.0"
EXPECTED_AFL_VERSION = "5.02c"


class ControllerError(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class Target:
    group: str
    name: str
    executable: Path
    committed_corpus: Path
    max_input_len: int


@dataclasses.dataclass
class Campaign:
    target: Target
    output: Path
    returncode: int
    timed_out: bool


class Processes:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.active: set[subprocess.Popen[bytes]] = set()

    def run(
        self,
        argv: list[str],
        cwd: Path,
        env: dict[str, str],
        log: Path,
        timeout: int,
    ) -> tuple[int, bool]:
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("wb") as output:
            process = subprocess.Popen(
                argv,
                cwd=cwd,
                env=env,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            with self.lock:
                self.active.add(process)
            try:
                return process.wait(timeout=timeout), False
            except subprocess.TimeoutExpired:
                self.stop(process)
                return process.wait(), True
            finally:
                with self.lock:
                    self.active.discard(process)

    def stop(self, process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)

    def stop_all(self) -> None:
        with self.lock:
            active = list(self.active)
        for process in active:
            self.stop(process)


PROCESSES = Processes()


def positive(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def run_output(argv: list[str], cwd: Path) -> str:
    result = subprocess.run(argv, cwd=cwd, check=True, capture_output=True, text=True)
    return (result.stdout + result.stderr).strip()


def require_clean_checkout(project_root: Path) -> None:
    status = run_output(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        project_root,
    )
    if status:
        raise ControllerError("project checkout must be clean")


def require_tool(name: str) -> Path:
    found = shutil.which(name)
    if found is None:
        raise ControllerError(f"required tool {name!r} was not found")
    return Path(found).resolve(strict=True)


def check_toolchain(project_root: Path) -> dict[str, str]:
    zig = require_tool("zig")
    afl_fuzz = require_tool("afl-fuzz")
    require_tool("afl-cmin")
    require_tool("afl-tmin")
    require_tool("afl-cc")
    llvm_config = require_tool("llvm-config-18")
    zig_version = run_output([str(zig), "version"], project_root)
    afl_version = run_output([str(afl_fuzz), "--version"], project_root)
    llvm_version = run_output([str(llvm_config), "--version"], project_root)
    if zig_version != EXPECTED_ZIG_VERSION:
        raise ControllerError(f"expected Zig {EXPECTED_ZIG_VERSION}, found {zig_version}")
    if EXPECTED_AFL_VERSION not in afl_version:
        raise ControllerError(f"expected AFL++ {EXPECTED_AFL_VERSION}, found {afl_version}")
    if not llvm_version.startswith("18."):
        raise ControllerError(f"expected LLVM 18, found {llvm_version}")
    return {"zig": zig_version, "afl": afl_version, "llvm": llvm_version}


def resolve_project_path(fuzz_root: Path, raw: str, kind: str) -> Path:
    path = Path(raw)
    if path.is_absolute():
        raise ControllerError(f"{kind} path must be relative")
    resolved = (fuzz_root / path).resolve(strict=True)
    if not resolved.is_relative_to(fuzz_root):
        raise ControllerError(f"{kind} path escapes test/fuzz")
    return resolved


def load_targets(manifest: Path, fuzz_root: Path) -> list[Target]:
    fuzz_root = fuzz_root.resolve(strict=True)
    with manifest.open(newline="", encoding="utf-8") as source:
        rows = list(csv.reader(source, delimiter="\t", strict=True))
    if not rows or rows[0] != MANIFEST_HEADER:
        raise ControllerError("invalid targets.tsv header")
    if not 1 <= len(rows) - 1 <= MAX_TARGETS:
        raise ControllerError("targets.tsv target count is outside the supported bound")
    targets: list[Target] = []
    names: set[str] = set()
    for row_number, row in enumerate(rows[1:], 2):
        if len(row) != len(MANIFEST_HEADER):
            raise ControllerError(f"targets.tsv row {row_number} must have six fields")
        schema, group, name, executable_raw, corpus_raw, max_raw = row
        if schema != "2" or not TARGET_PATTERN.fullmatch(group) or not TARGET_PATTERN.fullmatch(name):
            raise ControllerError(f"invalid targets.tsv row {row_number}")
        if name in names:
            raise ControllerError(f"duplicate target {name!r}")
        names.add(name)
        try:
            max_input_len = int(max_raw)
        except ValueError as error:
            raise ControllerError(f"invalid maximum for target {name!r}") from error
        if str(max_input_len) != max_raw or max_input_len <= 0:
            raise ControllerError(f"invalid maximum for target {name!r}")
        executable = resolve_project_path(fuzz_root, executable_raw, "executable")
        corpus = resolve_project_path(fuzz_root, corpus_raw, "corpus")
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ControllerError(f"target executable is not executable: {executable}")
        if not corpus.is_dir():
            raise ControllerError(f"target corpus is not a directory: {corpus}")
        targets.append(Target(group, name, executable, corpus, max_input_len))
    return targets


def select_targets(targets: list[Target], selectors_raw: str) -> list[Target]:
    selectors = [item.strip() for item in selectors_raw.split(",") if item.strip()]
    if not selectors:
        return targets
    selected: list[Target] = []
    selected_names: set[str] = set()
    for selector in selectors:
        matches = [target for target in targets if target.name == selector or target.group == selector]
        if not matches:
            raise ControllerError(f"unknown target or group {selector!r}")
        for target in matches:
            if target.name not in selected_names:
                selected.append(target)
                selected_names.add(target.name)
    return selected


def input_files(directory: Path, max_input_len: int, strict: bool) -> list[Path]:
    files: list[Path] = []
    for entry in sorted(directory.iterdir()):
        if entry.is_symlink() or not entry.is_file():
            if strict:
                raise ControllerError(f"corpus contains a non-regular entry: {entry}")
            continue
        if entry.stat().st_size > max_input_len:
            raise ControllerError(f"input exceeds the target maximum: {entry}")
        files.append(entry)
        if len(files) > MAX_INPUTS:
            raise ControllerError(f"input count exceeds {MAX_INPUTS}: {directory}")
    return files


def copy_by_hash(sources: list[Path], destination: Path) -> int:
    destination.mkdir(parents=True, exist_ok=True)
    for source in sources:
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        target = destination / digest
        if not target.exists():
            shutil.copyfile(source, target)
    return len(input_files(destination, 2**63 - 1, True))


def initialize_corpus(target: Target, state_root: Path) -> Path:
    destination = state_root / "corpus" / target.name
    committed = input_files(target.committed_corpus, target.max_input_len, True)
    if not committed:
        raise ControllerError(f"committed corpus is empty for {target.name}")
    copy_by_hash(committed, destination)
    return destination


def afl_environment(target: Target) -> dict[str, str]:
    env = os.environ.copy()
    env["AFL_INPUT_LEN_MAX"] = str(target.max_input_len)
    env["AFL_NO_AFFINITY"] = "1"
    env["AFL_NO_CRASH_README"] = "1"
    env["AFL_NO_UI"] = "1"
    return env


def run_campaign(
    target: Target,
    corpus: Path,
    run_root: Path,
    duration_seconds: int,
    timeout_ms: int,
    memory_mb: int,
) -> Campaign:
    output = run_root / target.name
    argv = [
        str(require_tool("afl-fuzz")),
        "-i",
        str(corpus),
        "-o",
        str(output),
        "-V",
        str(duration_seconds),
        "-M",
        "main",
        "-t",
        f"{timeout_ms}+",
        "-m",
        str(memory_mb),
        "-G",
        str(target.max_input_len),
        "--",
        str(target.executable),
    ]
    returncode, timed_out = PROCESSES.run(
        argv,
        target.executable.parent,
        afl_environment(target),
        output.with_suffix(".log"),
        duration_seconds + 300,
    )
    return Campaign(target, output, returncode, timed_out)


def minimize_corpus(
    campaign: Campaign,
    persistent: Path,
    state_root: Path,
    timeout_ms: int,
    memory_mb: int,
) -> int:
    queue = campaign.output / "main" / "queue"
    if not queue.is_dir():
        raise ControllerError(f"missing AFL++ queue for {campaign.target.name}")
    staging_root = state_root / ".staging"
    staging_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=staging_root) as temporary:
        staging = Path(temporary)
        merged = staging / "merged"
        minimized = staging / "minimized"
        sources = input_files(campaign.target.committed_corpus, campaign.target.max_input_len, True)
        sources += input_files(persistent, campaign.target.max_input_len, True)
        sources += input_files(queue, campaign.target.max_input_len, False)
        copy_by_hash(sources, merged)
        argv = [
            str(require_tool("afl-cmin")),
            "-i",
            str(merged),
            "-o",
            str(minimized),
            "-t",
            f"{timeout_ms}+",
            "-m",
            str(memory_mb),
            "--",
            str(campaign.target.executable),
        ]
        returncode, timed_out = PROCESSES.run(
            argv,
            campaign.target.executable.parent,
            afl_environment(campaign.target),
            campaign.output / "cmin.log",
            7_200,
        )
        if returncode != 0 or timed_out:
            raise ControllerError(f"afl-cmin failed for {campaign.target.name}")
        normalized = staging / "normalized"
        minimized_files = input_files(minimized, campaign.target.max_input_len, True)
        if not minimized_files:
            raise ControllerError(f"afl-cmin produced an empty corpus for {campaign.target.name}")
        count = copy_by_hash(minimized_files, normalized)
        previous = persistent.with_name(f".{persistent.name}.previous")
        if previous.exists():
            raise ControllerError(f"stale corpus replacement exists: {previous}")
        persistent.rename(previous)
        normalized.rename(persistent)
        shutil.rmtree(previous)
        return count


def minimize_failure(
    target: Target,
    source: Path,
    kind: str,
    staging: Path,
    timeout_ms: int,
    memory_mb: int,
) -> tuple[Path, bool]:
    output = staging / "minimized"
    argv = [
        str(require_tool("afl-tmin")),
        "-i",
        str(source),
        "-o",
        str(output),
        "-t",
        f"{timeout_ms}+",
        "-m",
        str(memory_mb),
    ]
    if kind == "hangs":
        argv.append("-H")
    argv.extend(["--", str(target.executable)])
    returncode, timed_out = PROCESSES.run(
        argv,
        target.executable.parent,
        afl_environment(target),
        staging / "tmin.log",
        300,
    )
    if returncode == 0 and not timed_out and output.is_file() and output.stat().st_size <= target.max_input_len:
        return output, True
    return source, False


def archive_failures(
    campaign: Campaign,
    state_root: Path,
    report_dir: Path,
    commit: str,
    timeout_ms: int,
    memory_mb: int,
) -> list[dict[str, object]]:
    archived: list[dict[str, object]] = []
    staging_root = state_root / ".staging"
    staging_root.mkdir(parents=True, exist_ok=True)
    for kind in ("crashes", "hangs"):
        source_dir = campaign.output / "main" / kind
        if not source_dir.is_dir():
            continue
        sources = input_files(source_dir, campaign.target.max_input_len, False)
        if len(sources) > MAX_FAILURES_PER_KIND:
            raise ControllerError(f"too many {kind} to archive for {campaign.target.name}")
        for source in sources:
            with tempfile.TemporaryDirectory(dir=staging_root) as temporary:
                chosen, minimized = minimize_failure(
                    campaign.target,
                    source,
                    kind,
                    Path(temporary),
                    timeout_ms,
                    memory_mb,
                )
                data = chosen.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            destination_dir = state_root / "failures" / campaign.target.name / kind
            destination_dir.mkdir(parents=True, exist_ok=True)
            destination = destination_dir / f"{digest}.input"
            is_new = not destination.exists()
            if is_new:
                destination.write_bytes(data)
                metadata = {
                    "commit": commit,
                    "kind": kind,
                    "minimized": minimized,
                    "sha256": digest,
                    "target": campaign.target.name,
                }
                destination.with_suffix(".json").write_text(
                    json.dumps(metadata, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                artifact_dir = report_dir / "new-findings" / campaign.target.name / kind
                artifact_dir.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(destination, artifact_dir / destination.name)
                shutil.copyfile(destination.with_suffix(".json"), artifact_dir / f"{digest}.json")
            archived.append({"kind": kind, "sha256": digest, "new": is_new, "minimized": minimized})
    return archived


def replay_failures(
    target: Target,
    state_root: Path,
    report_dir: Path,
    timeout_ms: int,
) -> dict[str, int]:
    result = {"active": 0, "changed": 0, "not_reproduced": 0}
    count = 0
    for kind in ("crashes", "hangs"):
        directory = state_root / "failures" / target.name / kind
        if not directory.is_dir():
            continue
        for source in sorted(directory.glob("*.input")):
            count += 1
            if count > MAX_ARCHIVED_FAILURES:
                raise ControllerError(f"archived failure count exceeds {MAX_ARCHIVED_FAILURES} for {target.name}")
            returncode, timed_out = PROCESSES.run(
                [str(target.executable), str(source)],
                target.executable.parent,
                os.environ.copy(),
                report_dir / f"replay-{target.name}.log",
                max(1, (timeout_ms + 999) // 1000),
            )
            expected = (kind == "crashes" and returncode != 0 and not timed_out) or (
                kind == "hangs" and timed_out
            )
            if expected:
                result["active"] += 1
            elif returncode == 0 and not timed_out:
                result["not_reproduced"] += 1
            else:
                result["changed"] += 1
    return result


def read_stats(campaign: Campaign) -> dict[str, str]:
    path = campaign.output / "main" / "fuzzer_stats"
    if not path.is_file():
        return {}
    stats: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        key, separator, value = line.partition(":")
        if separator:
            stats[key.strip()] = value.strip()
    return stats


def write_report(report_dir: Path, report: dict[str, object]) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    lines = ["# Lodestar-Z fuzz campaign", "", f"Commit: `{report['commit']}`", "", "| Target | Execs | Corpus | New findings | Status |", "| --- | ---: | ---: | ---: | --- |"]
    for target in report["targets"]:
        status = (
            "ok"
            if target["returncode"] == 0 and not target["timed_out"] and not target["error"]
            else "failed"
        )
        lines.append(
            f"| `{target['name']}` | {target['execs']} | {target['corpus']} | {target['new_findings']} | {status} |"
        )
    (report_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def postprocess_campaign(
    campaign: Campaign,
    persistent: Path,
    state_root: Path,
    report_dir: Path,
    commit: str,
    timeout_ms: int,
    memory_mb: int,
) -> dict[str, object]:
    stats = read_stats(campaign)
    findings: list[dict[str, object]] = []
    error = ""
    corpus_count = len(input_files(persistent, campaign.target.max_input_len, True))
    if campaign.returncode == 0 and not campaign.timed_out:
        try:
            findings = archive_failures(
                campaign,
                state_root,
                report_dir,
                commit,
                timeout_ms,
                memory_mb,
            )
            corpus_count = minimize_corpus(
                campaign,
                persistent,
                state_root,
                timeout_ms,
                memory_mb,
            )
        except (ControllerError, OSError) as caught:
            error = str(caught)
    return {
        "name": campaign.target.name,
        "returncode": campaign.returncode,
        "timed_out": campaign.timed_out,
        "error": error,
        "execs": stats.get("execs_done", "unknown"),
        "corpus": corpus_count,
        "new_findings": sum(1 for finding in findings if finding["new"]),
        "findings": findings,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--state-root", default="")
    parser.add_argument("--report-dir", type=Path, default=Path("reports"))
    parser.add_argument("--duration-seconds", type=positive, required=True)
    parser.add_argument("--jobs", type=positive, required=True)
    parser.add_argument("--timeout-ms", type=positive, required=True)
    parser.add_argument("--memory-mb", type=positive, required=True)
    parser.add_argument("--selectors", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if sys.platform != "linux":
        raise ControllerError("the campaign controller requires Linux")
    project_root = args.project_root.resolve(strict=True)
    fuzz_root = (project_root / "test" / "fuzz").resolve(strict=True)
    state_root = (
        Path(args.state_root).expanduser().resolve()
        if args.state_root
        else (Path.home() / ".local" / "state" / "lodestar-fuzzer" / "lodestar-z").resolve()
    )
    report_dir = args.report_dir.resolve()
    state_root.mkdir(parents=True, exist_ok=True)
    lock_path = state_root / ".lock"
    with lock_path.open("a+b") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ControllerError("another campaign owns the state directory") from error
        require_clean_checkout(project_root)
        toolchain = check_toolchain(project_root)
        build_log = report_dir / "build.log"
        returncode, timed_out = PROCESSES.run(
            [str(require_tool("zig")), "build", "-Doptimize=ReleaseSafe"],
            fuzz_root,
            os.environ.copy(),
            build_log,
            3_600,
        )
        if returncode != 0 or timed_out:
            raise ControllerError("fuzz build failed")
        require_clean_checkout(project_root)
        targets = load_targets(fuzz_root / "zig-out" / "share" / "lodestar-z-fuzz" / "targets.tsv", fuzz_root)
        targets = select_targets(targets, args.selectors)
        returncode, timed_out = PROCESSES.run(
            [str(require_tool("zig")), "build", "replay-corpus", "-Doptimize=ReleaseSafe"],
            fuzz_root,
            os.environ.copy(),
            report_dir / "seed-replay.log",
            3_600,
        )
        if returncode != 0 or timed_out:
            raise ControllerError("committed corpus replay failed")
        commit = run_output(["git", "rev-parse", "--verify", "HEAD^{commit}"], project_root)
        run_id = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + commit[:12]
        run_root = state_root / "runs" / run_id
        run_root.mkdir(parents=True)
        corpora = {target.name: initialize_corpus(target, state_root) for target in targets}
        replays = {
            target.name: replay_failures(target, state_root, report_dir, args.timeout_ms)
            for target in targets
        }
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.jobs, len(targets))) as executor:
            futures = [
                executor.submit(
                    run_campaign,
                    target,
                    corpora[target.name],
                    run_root,
                    args.duration_seconds,
                    args.timeout_ms,
                    args.memory_mb,
                )
                for target in targets
            ]
            campaigns = [future.result() for future in futures]
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.jobs, len(targets))) as executor:
            futures = [
                executor.submit(
                    postprocess_campaign,
                    campaign,
                    corpora[campaign.target.name],
                    state_root,
                    report_dir,
                    commit,
                    args.timeout_ms,
                    args.memory_mb,
                )
                for campaign in campaigns
            ]
            target_reports = [future.result() for future in futures]
        for target_report in target_reports:
            target_report["replayed_failures"] = replays[str(target_report["name"])]
        failed = any(
            target_report["returncode"] != 0
            or target_report["timed_out"]
            or target_report["error"]
            for target_report in target_reports
        )
        report = {
            "commit": commit,
            "finished_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "run_id": run_id,
            "toolchain": toolchain,
            "targets": target_reports,
        }
        write_report(report_dir, report)
        write_report(state_root / "reports" / run_id, report)
        if not failed:
            shutil.rmtree(run_root)
        return 1 if failed else 0


def handle_signal(signum: int, _frame: object) -> None:
    PROCESSES.stop_all()
    raise SystemExit(128 + signum)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    try:
        raise SystemExit(main())
    except (ControllerError, OSError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
