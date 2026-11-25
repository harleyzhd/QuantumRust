#!/usr/bin/env python3
"""Tool comparison on the mutation benchmark: QuantumRust against other scanners.

Usage:
    python3 docs/scripts/compare_tools.py benchmark/mutants [--jobs N] [--json out.json]
        [--from-json out.json] [--modes M6,M7] [--tools codeql,...]

`cargo xtask compare` runs it on `benchmark/mutants`. The other tools are
PostQuant, CryptoScan, crypto-scanner and CodeQL. A tool that is not installed
is skipped.

Every tool runs over the same mutants. Beside the totals, the report shows
recall by NIST tier and by failure mode, false positives by negative bucket,
and the positives that QuantumRust alone finds or alone misses.

How the comparison is kept fair:

* One scorer. Every tool, QuantumRust included, is scored by
  `score_benchmark.score`.
* Same source. The other tools scan a copy of each mutant without `target/`
  and `qr-out/`, which hold build output full of crypto symbol names.
  `examples/` is kept, since `N3` puts its crypto there. QuantumRust runs on
  the original, because it compiles.
* Fixed configurations. Each tool runs in its default configuration and, where
  it has one, its most inclusive one. Both are reported.
* The headline is "all findings". The other tools grade classical and quantum
  risk on one scale, so their findings cannot be mapped onto QuantumRust's
  quantum-vulnerable status. The vulnerable-only row is QuantumRust's alone.
* Recall by tier uses the label's NIST tier. "All findings" recall also counts
  quantum-resistant sites (AES-256, SHA-256, ML-KEM), which some scanners hide
  by default, so recall over the Tier 1 and Tier 1+2 positives is shown too.
* Line-exact, with file level beside it. Some scanners report a crate's `use`
  line instead of the call. The file-level column counts a positive as found
  when any finding lands in the labelled file. Each mutant file holds one
  crypto family, so this measures detection without location.
* Exit codes are not errors. PostQuant exits 1 when its grade is C or worse,
  so output is read either way. Only a missing or unparseable report fails a
  run, and a failed run raises instead of scoring as empty.
"""

from __future__ import annotations

import argparse
import atexit
import json
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
import score_benchmark as bench  # noqa: E402

Finding = dict
Runner = Callable[[Path, list[str]], list[Finding]]


class Tool:
    """A detector in the comparison: how to version it and how to run it."""

    def __init__(
        self,
        name: str,
        version: Callable[[], str | None],
        configs: list[tuple[str, list[str]]],
        run: Runner,
        scans_copy: bool = True,
    ) -> None:
        self.name = name
        self.version = version
        self.configs = configs
        self.run = run
        self.scans_copy = scans_copy


def _version_of(*cmd: str) -> Callable[[], str | None]:
    def version() -> str | None:
        if shutil.which(cmd[0]) is None:
            return None
        proc = subprocess.run(list(cmd), capture_output=True, text=True, check=False)
        text = re.sub(r"\x1b\[[0-9;]*m", "", proc.stdout or proc.stderr)
        out = [line.strip() for line in text.strip().splitlines() if line.strip()]
        return " ".join(out[:2]) if out else "unknown"

    return version


# ---- QuantumRust ------------------------------------------------------------

def _quantumrust(repo: Path) -> Runner:
    def run(mutant: Path, args: list[str]) -> list[Finding]:
        return bench.analyse(repo, mutant, args)

    return run


# ---- PostQuant --------------------------------------------------------------

def _postquant(src: Path, args: list[str]) -> list[Finding]:
    proc = subprocess.run(
        ["postquant", "analyze", str(src), "--format", "json", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        # An empty result would score as a miss; see `score_benchmark.analyse`.
        raise RuntimeError(f"postquant {src.name}: unparseable output ({proc.returncode})") from e
    return [
        {
            "file": f.get("file"),
            "line": f.get("line"),
            "status": None,  # no faithful mapping; see the module docs
            "name": f"{f.get('algorithm')} ({f.get('risk')})",
        }
        for f in doc.get("findings", [])
    ]


# ---- CryptoScan (CSNP / QRAMM) ---------------------------------------------

def _cryptoscan(src: Path, args: list[str]) -> list[Finding]:
    proc = subprocess.run(
        ["cryptoscan", "scan", str(src), "--format", "json", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"cryptoscan {src.name}: unparseable output ({proc.returncode})") from e
    # Paths come back absolute; the scorer matches on suffix, so they score as
    # they stand.
    return [
        {
            "file": f.get("file"),
            "line": f.get("line"),
            "status": None,
            "name": f"{f.get('algorithm')} ({f.get('migrationStatus')})",
        }
        for f in doc.get("findings") or []
    ]


# ---- crypto-scanner (mbennett-labs) -----------------------------------------

def _crypto_scanner(src: Path, args: list[str]) -> list[Finding]:
    # Its stdout goes through a terminal renderer that wraps long lines at the
    # window width, splitting strings mid-token: not valid JSON. `-o` writes
    # the report to a file instead.
    with tempfile.TemporaryDirectory(prefix="qr-cs-") as tmp:
        out = Path(tmp) / "report.json"
        proc = subprocess.run(
            ["crypto-scanner", "scan", str(src), "-o", str(out), *args],
            capture_output=True,
            text=True,
            check=False,
        )
        try:
            doc = json.loads(out.read_text())
        except (OSError, json.JSONDecodeError) as e:
            raise RuntimeError(f"crypto-scanner {src.name}: no report ({proc.returncode})") from e
    return [
        {
            "file": f.get("file_path"),
            "line": f.get("line_number"),
            "status": None,
            "name": f"{f.get('algorithm')} ({f.get('risk_level')})",
        }
        for f in doc.get("findings") or []
    ]


# ---- CodeQL (GitHub) ----------------------------------------------------------

# One CodeQL database for the whole staged benchmark, not one per mutant.
# Extraction loads every dependency's source, about two minutes per mutant, so
# it is paid once here, and dependencies resolve through the benchmark's
# Cargo.lock as they do for QuantumRust. Mutants share no code, so a file's
# results do not depend on the other crates in the database. Results are split
# back out by mutant directory.
_CODEQL_LOCK = threading.Lock()
_CODEQL_DB: dict[Path, Path] = {}
_CODEQL_RESULTS: dict[tuple[Path, tuple[str, ...]], dict[str, list[Finding]]] = {}


def _codeql_run(cmd: list[str], what: str) -> None:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        tail = "\n".join(proc.stderr.strip().splitlines()[-5:])
        raise RuntimeError(f"codeql {what}: exit {proc.returncode}\n{tail}")


def _codeql_suite(root: Path, args: list[str]) -> dict[str, list[Finding]]:
    key = (root, tuple(args))
    with _CODEQL_LOCK:
        if key in _CODEQL_RESULTS:
            return _CODEQL_RESULTS[key]
        if root not in _CODEQL_DB:
            work = Path(tempfile.mkdtemp(prefix="qr-codeql-"))
            atexit.register(shutil.rmtree, work, True)
            _codeql_run(
                ["codeql", "database", "create", str(work / "db"), "--language=rust",
                 f"--source-root={root}", "--overwrite", "--threads=0", "--ram=4096"],
                "database create",
            )
            _CODEQL_DB[root] = work / "db"
        db = _CODEQL_DB[root]
        sarif = db.parent / f"{len(_CODEQL_RESULTS)}.sarif"
        _codeql_run(
            ["codeql", "database", "analyze", str(db), *args, "--format=sarif-latest",
             f"--output={sarif}", "--threads=0", "--ram=4096"],
            f"analyze {' '.join(args)}",
        )
        by_mutant: dict[str, list[Finding]] = {}
        for run in json.loads(sarif.read_text()).get("runs", []):
            for result in run.get("results", []):
                for loc in result.get("locations", []):
                    phys = loc.get("physicalLocation", {})
                    uri = phys.get("artifactLocation", {}).get("uri", "")
                    by_mutant.setdefault(uri.split("/", 1)[0], []).append(
                        {
                            "file": uri,
                            "line": phys.get("region", {}).get("startLine"),
                            "status": None,
                            "name": result.get("ruleId"),
                        }
                    )
        _CODEQL_RESULTS[key] = by_mutant
        return by_mutant


def _codeql(src: Path, args: list[str]) -> list[Finding]:
    return _codeql_suite(src.parent, args).get(src.name, [])


def tools(repo: Path) -> list[Tool]:
    return [
        Tool(
            "quantumrust",
            lambda: "workspace HEAD",
            [("default", []), ("--cfg-union", ["--cfg-union"])],
            _quantumrust(repo),
            scans_copy=False,
        ),
        Tool(
            "postquant",
            _version_of("postquant", "--version"),
            [("default", []), ("--show-all", ["--show-all"])],
            _postquant,
        ),
        Tool(
            "cryptoscan",
            _version_of("cryptoscan", "version"),
            # Withholds quantum-safe findings (AES, SHA-2) unless asked.
            [("default", []), ("--include-quantum-safe", ["--include-quantum-safe"])],
            _cryptoscan,
        ),
        Tool(
            "codeql",
            _version_of("codeql", "version", "--format=terse"),
            # The default Rust suite, and security-extended as the inclusive one.
            [
                ("rust-code-scanning", ["codeql/rust-queries:codeql-suites/rust-code-scanning.qls"]),
                ("security-extended", ["codeql/rust-queries:codeql-suites/rust-security-extended.qls"]),
            ],
            _codeql,
        ),
        Tool(
            "crypto-scanner",
            _version_of("crypto-scanner", "--version"),
            # No inclusive mode to offer: one configuration.
            [("default", [])],
            _crypto_scanner,
        ),
    ]


# ---- harness ----------------------------------------------------------------

def stage(suite: Path, labels: list[dict], into: Path) -> None:
    """Copy each mutant into `into`, without the build output.

    Keeps what a user would point a scanner at: `src/`, `Cargo.toml` and
    `examples/`, where `N3` puts its crypto. Drops `target/` and `qr-out/`,
    which are full of crypto symbol names.
    """
    skip = shutil.ignore_patterns("target", "qr-out")
    for mutant in labels:
        shutil.copytree(suite / mutant["id"], into / mutant["id"], ignore=skip)
    # The workspace manifest and lock, beside the mutants: a tool that builds
    # one database for the benchmark resolves the same dependency versions
    # QuantumRust analysed.
    for name in ("Cargo.toml", "Cargo.lock"):
        if (suite / name).exists():
            shutil.copy2(suite / name, into / name)
    # The mutants' path dependencies, beside them as in the benchmark. Without
    # them the staged workspace does not resolve, and CodeQL, which loads it
    # through cargo, extracts nothing while still exiting 0. They sit outside
    # every mutant, so no per-mutant scan reads them, and CodeQL results under
    # `_deps/` belong to no mutant.
    if (suite / "_deps").exists():
        shutil.copytree(suite / "_deps", into / "_deps", ignore=skip)


TIERS = [
    ("Tier 1, quantum-vulnerable", {"1"}),
    ("Tier 1+2, needs migration", {"1", "2"}),
    ("Tier 3, resistant", {"3"}),
]


def tier_recall(
    labels: list[dict], results: list[list[Finding]], tiers: set[str]
) -> tuple[int, int]:
    """Line-exact hits over the positives whose label is in `tiers`."""
    chosen = [
        (m, r)
        for m, r in zip(labels, results)
        if m["polarity"] == "positive" and str(m["nist_tier"]) in tiers
    ]
    hits = sum(any(bench.matches(e, f) for e in m["expected"] for f in r) for m, r in chosen)
    return hits, len(chosen)


def file_level(labels: list[dict], results: list[list[Finding]]) -> int:
    """Positives with any finding in the labelled file, at any line."""
    return sum(
        any(
            (f.get("file") or "").endswith(e["file"])
            for e in mutant["expected"]
            for f in findings
        )
        for mutant, findings in zip(labels, results)
        if mutant["polarity"] == "positive"
    )


def score_all(labels: list[dict], results: list[list[Finding]]) -> dict:
    """`score_benchmark.score`, plus the file-level, per-tier and per-mode views."""
    scored = bench.score(labels, results)
    scored["file_hits"] = file_level(labels, results)
    scored["tiers"] = {name: tier_recall(labels, results, tiers) for name, tiers in TIERS}
    scored["file_by_mode"] = {
        mode: file_level(
            [m for m in labels if m["failure_mode"] == mode],
            [r for m, r in zip(labels, results) if m["failure_mode"] == mode],
        )
        for mode in scored["by_mode"]
    }
    return scored


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("suite", type=Path)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--json", type=Path, help="write every finding and score here")
    ap.add_argument(
        "--from-json",
        type=Path,
        help="re-score the findings a previous --json run saved, without running any tool",
    )
    ap.add_argument(
        "--modes",
        help="score only the positives of these failure modes, e.g. M6,M7 (recall only)",
    )
    ap.add_argument(
        "--tools",
        help="run only these tools, e.g. codeql (comma-separated; default: all)",
    )
    args = ap.parse_args()

    repo = Path(__file__).resolve().parents[2]
    wanted = set(args.tools.split(",")) if args.tools else None
    if wanted and (unknown := wanted - {t.name for t in tools(repo)}):
        ap.error(f"unknown tool(s): {', '.join(sorted(unknown))}")
    suite = args.suite.resolve()
    labels = json.loads((suite / "labels.json").read_text())
    if args.modes:
        # A positive-only slice: precision is not defined on it, and the report
        # says so rather than printing 100%.
        keep = set(args.modes.split(","))
        labels = [m for m in labels if m["failure_mode"] in keep]

    if args.from_json:
        saved = json.loads(args.from_json.read_text())
        columns = [
            (key, score_all(labels, [rec["findings"].get(m["id"], []) for m in labels]))
            for key, rec in saved.items()
        ]
        report(columns)
        return 0

    columns: list[tuple[str, dict]] = []
    record: dict[str, dict] = {}
    with tempfile.TemporaryDirectory(prefix="qr-src-") as tmp:
        copy = Path(tmp)
        stage(suite, labels, copy)
        for tool in tools(repo):
            if wanted and tool.name not in wanted:
                continue
            version = tool.version()
            if version is None:
                print(f"  -- {tool.name}: not installed, skipped", file=sys.stderr)
                continue
            root = copy if tool.scans_copy else suite
            for config, flags in tool.configs:
                with ThreadPoolExecutor(max_workers=args.jobs) as pool:
                    results = list(
                        pool.map(lambda m: tool.run(root / m["id"], flags), labels)
                    )
                key = f"{tool.name} {config}"
                scored = score_all(labels, results)
                columns.append((key, scored))
                record[key] = {
                    "tool": tool.name,
                    "version": version,
                    "flags": flags,
                    "findings": {m["id"]: r for m, r in zip(labels, results)},
                    "score": {k: v for k, v in scored.items() if k != "negatives_hit"},
                }
                print(f"  ran {key} ({version})", file=sys.stderr)

    report(columns)
    if args.json:
        args.json.write_text(json.dumps(record, indent=2, default=list))
    return 0


def report(columns: list[tuple[str, dict]]) -> None:
    if not columns:
        print("no tools ran")
        return
    width = max(len(k) for k, _ in columns)
    first = columns[0][1]
    print(f"\nTool comparison: {first['n_pos']} positive, {first['n_neg']} negative mutants\n")

    print(f"  {'all findings':<{width}}  precision   recall      F1    TP  FP  FN"
          f"   recall, file-level (secondary)")
    for key, s in columns:
        t, f, missed = s["all"]
        p, r, f1 = bench.prf(t, f, missed)
        prec = f"{p:8.1%}" if s["n_neg"] else "     n/a"
        f1s = f"{f1:7.1%}" if s["n_neg"] else "    n/a"
        print(f"  {key:<{width}}  {prec} {r:8.1%} {f1s}  {t:4d}{f:4d}{missed:4d}"
              f"   {s['file_hits'] / s['n_pos']:6.1%} ({s['file_hits']}/{s['n_pos']})")

    qr = [(k, s) for k, s in columns if k.startswith("quantumrust")]
    for key, s in qr:
        t, f, missed = s["vulnerable"]
        p, r, f1 = bench.prf(t, f, missed)
        prec = f"{p:8.1%}" if s["n_neg"] else "     n/a"
        f1s = f"{f1:7.1%}" if s["n_neg"] else "    n/a"
        print(f"  {key + ' (vulnerable-only; QuantumRust only)':<{width}}  "
              f"{prec} {r:8.1%} {f1s}  {t:4d}{f:4d}{missed:4d}")

    # One row per tool configuration, one column per category: the configs'
    # names are long, the categories short.
    def table(title: str, cols: list[str], cell: Callable[[dict, str], str]) -> None:
        cells = {(key, c): cell(s, c) for key, s in columns for c in cols}
        widths = [max(len(c), *(len(cells[key, c]) for key, _ in columns)) + 2 for c in cols]
        print(f"\n  {title}")
        print(f"    {'':<{width}}" + "".join(f"{c:>{w}}" for c, w in zip(cols, widths)))
        for key, _ in columns:
            print(f"    {key:<{width}}" + "".join(f"{cells[key, c]:>{w}}" for c, w in zip(cols, widths)))

    def tier(s: dict, name: str) -> str:
        hit, n = s["tiers"][name]
        return f"{hit}/{n} {hit / n if n else 0:.0%}"

    table("recall by the labels' NIST tier (line-exact)", [n for n, _ in TIERS], tier)
    modes = sorted(first["by_mode"])
    table("recall by failure mode (line-exact, then file-level)", modes,
          lambda s, m: "{}/{} f{}".format(*s["by_mode"].get(m, [0, 0]), s["file_by_mode"].get(m, 0)))
    buckets = sorted({b for _, s in columns for b in s["by_negative"]})
    table("false positives by negative bucket", buckets,
          lambda s, b: str(s["by_negative"].get(b, 0)))

    # Both directions: what QuantumRust finds that every other tool misses, and
    # what every other tool finds that QuantumRust misses.
    others = [s for k, s in columns if not k.startswith("quantumrust")]
    if qr and others:
        for key, s in qr:
            ids = sorted(s["hits"])
            only_qr = [i for i in ids if s["hits"][i] and not any(o["hits"][i] for o in others)]
            only_them = [i for i in ids if not s["hits"][i] and all(o["hits"][i] for o in others)]
            print(f"\n  {key}: found, and missed by every comparator config: {len(only_qr)}")
            for i in only_qr:
                print(f"    {i}")
            print(f"  {key}: missed, and found by every comparator config: {len(only_them)}")
            for i in only_them:
                print(f"    {i}")


if __name__ == "__main__":
    sys.exit(main())
