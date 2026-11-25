#!/usr/bin/env python3
"""Scalability: runtime and peak memory per pipeline stage.

Usage:
    python3 docs/scripts/measure_scale.py run OUT_DIR [--corpus NAME=PATH ...]
        [--profile release|debug] [--warmup] [--cold] [--descend] [--suffix S]
    python3 docs/scripts/measure_scale.py report OUT_DIR [--md FILE]

`cargo xtask scale` passes its arguments here.

`run` analyses each corpus once with `quantumrust analyze --timings`, calling
the built binary directly so cargo's start-up is not timed, and writes one
JSON per corpus into OUT_DIR. `report` builds tables from whatever JSON is
there, so a long corpus (sequoia, about 20 minutes) can run on its own and
join later. The target is under one hour per 100k lines of code on a 16-core,
32 GB machine. Corpora fall in three tiers: small < 10k, medium 10k-100k,
large > 100k lines.

* Lines of code are counted two ways over `src/**/*.rs`: physical lines, and
  code lines without blanks or comments. The tier can differ between them:
  sequoia has 131k physical lines and about 76k code lines.
* Peak memory is `getrusage`'s high-water mark at the end of each stage, for
  the CLI process and for the largest single child (one `rustc` extraction
  driver). Children's memory is never summed.
* Cache state is recorded. Extraction keeps dependencies compiled under
  `target/qr-extract`, and a first run on a crate also compiles every
  dependency. `--warmup` runs once untimed first.
* The machine is recorded with each result.
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# Name -> crate root, relative to the repository. Tiers are assigned from the
# measured LOC, not declared here.
CORPORA = {
    "demo-crate": "fixtures/demo-crate",
    "multi-unit": "fixtures/multi-unit",
    "flow-sensitivity": "fixtures/flow-sensitivity",
    "jsonwebtoken": "../analysed-crates/jsonwebtoken-11.1.0",
    "age": "../analysed-crates/age-0.12.1",
    "sequoia": "../analysed-crates/sequoia-openpgp-2.4.1",
}
STAGES = ["extract-mir", "extract-llvm", "fuse", "rule-matching", "taint",
          "call-graph", "risk-scoring", "report"]
TARGET_MINUTES_PER_100K = 60.0
# Where the MIR and LLVM extractors keep compiled dependencies, per crate.
CACHE_DIRS = ["qr-extract", "qr-extract-llvm"]
# With `--descend`, MIR extraction builds into a cache of its own.
DESCEND_CACHE_DIRS = ["qr-extract-descend", "qr-extract-llvm"]
# A per-100k rate is reported only from here up; below it the run is start-up.
MIN_LOC_FOR_RATE = 1_000


def count_loc(root: Path) -> dict:
    """Physical and code lines over every `src/**/*.rs` outside `target/`."""
    physical = code = files = 0
    for path in sorted(root.rglob("*.rs")):
        parts = path.relative_to(root).parts
        if "target" in parts or "src" not in parts:
            continue
        files += 1
        in_block = False
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            physical += 1
            line = raw.strip()
            if in_block:
                if "*/" in line:
                    in_block = False
                continue
            if not line or line.startswith("//"):
                continue
            if line.startswith("/*"):
                in_block = "*/" not in line
                continue
            code += 1
    return {"files": files, "physical": physical, "code": code}


def tier(loc: int) -> str:
    return "small" if loc < 10_000 else "medium" if loc <= 100_000 else "large"


def machine() -> dict:
    def sysctl(key: str) -> str:
        try:
            return subprocess.run(["sysctl", "-n", key], capture_output=True, text=True,
                                  check=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            return ""
    rustc = subprocess.run(["rustc", "--version"], cwd=REPO, capture_output=True,
                           text=True, check=False).stdout.strip()
    mem = sysctl("hw.memsize")
    return {
        "cpu": sysctl("machdep.cpu.brand_string") or platform.processor(),
        "logical_cpus": sysctl("hw.ncpu"),
        "physical_cpus": sysctl("hw.physicalcpu"),
        "memory_gb": round(int(mem) / 2**30, 1) if mem else None,
        "os": f"{platform.system()} {platform.release()}",
        "rustc": rustc,
    }


def build(profile: str) -> Path:
    """Build the CLI and both extraction drivers; return the CLI binary.

    The drivers must be rebuilt with the CLI: it refuses a driver older than
    its sources, and a release CLI looks for release drivers beside itself.
    """
    flags = ["--release"] if profile == "release" else []
    for pkg in (["-p", "quantumrust-cli"], ["-p", "mir-extract", "--bin", "mir-extract-driver"],
                ["-p", "llvm-extract", "--bins"]):
        subprocess.run(["cargo", "build", "-q", *flags, *pkg], cwd=REPO, check=True)
    return REPO / "target" / profile / "quantumrust"


def runtime_env() -> dict:
    """The binary links `rustc_driver`, which `cargo run` would put on the
    loader path. Calling the binary directly has to do the same."""
    import os
    sysroot = subprocess.run(["rustc", "--print", "sysroot"], cwd=REPO, capture_output=True,
                             text=True, check=True).stdout.strip()
    var = "DYLD_FALLBACK_LIBRARY_PATH" if platform.system() == "Darwin" else "LD_LIBRARY_PATH"
    env = dict(os.environ)
    env[var] = f"{sysroot}/lib" + (f":{env[var]}" if env.get(var) else "")
    return env


def run(args: argparse.Namespace) -> int:
    out = args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    corpora = dict(spec.split("=", 1) for spec in args.corpus) if args.corpus else CORPORA
    binary = build(args.profile)
    env = runtime_env()
    host = machine()
    for name, rel in corpora.items():
        root = (REPO / rel).resolve()
        if not (root / "Cargo.toml").is_file():
            print(f"  {name}: no crate at {root}, skipped", file=sys.stderr)
            continue
        # Each extractor keeps its own compiled dependencies.
        caches = [root / "target" / d for d in (DESCEND_CACHE_DIRS if args.descend else CACHE_DIRS)]
        cached = all(c.is_dir() for c in caches)
        timings = out / f"{name}.timings.json"

        def once() -> tuple[subprocess.CompletedProcess, float]:
            start = time.monotonic()
            flags = ["--descend"] if args.descend else []
            proc = subprocess.run([str(binary), "analyze", str(root), *flags, "--timings", str(timings)],
                                  cwd=REPO, env=env, capture_output=True, text=True, check=False)
            return proc, time.monotonic() - start

        moved = []
        if args.cold:
            # Moved aside, never deleted: it is the user's build cache, and it
            # goes back when the run is done.
            for c in caches:
                if c.is_dir():
                    c.rename(c.with_name(c.name + ".qr-saved"))
                    moved.append(c)
        try:
            if args.warmup and not args.cold:
                once()
            proc, wall = once()
        finally:
            for c in moved:
                # What this run compiled is ours to remove; the saved cache
                # is restored in its place.
                shutil.rmtree(c, ignore_errors=True)
                c.with_name(c.name + ".qr-saved").rename(c)
        if proc.returncode != 0:
            raise RuntimeError(f"{name}: exit {proc.returncode}\n{proc.stderr[-1500:]}")
        record = {
            "name": name, "root": str(root), "profile": args.profile,
            "warmup": args.warmup and not args.cold, "cold": args.cold, "descend": args.descend,
            "extraction_cache_existed": cached and not args.cold,
            "loc": count_loc(root), "machine": host,
            "wall_including_startup_s": wall,
            "findings": proc.stdout.count(" blast="),
            "timings": json.loads(timings.read_text()),
        }
        (out / f"{name}{args.suffix}.json").write_text(json.dumps(record, indent=2))
        timings.unlink()
        t = record["timings"]
        print(f"  {name}: {record['loc']['physical']} physical / {record['loc']['code']} code LOC, "
              f"{t['total_wall_s']:.1f} s, peak {t['peak_self_mb']:.0f} MB self / "
              f"{t['peak_children_mb']:.0f} MB children")
    return 0


def report(args: argparse.Namespace) -> int:
    records = [json.loads(p.read_text()) for p in sorted(args.out_dir.glob("*.json"))]
    if not records:
        print(f"no results in {args.out_dir}", file=sys.stderr)
        return 1
    records.sort(key=lambda r: (r["loc"]["physical"], bool(r.get("descend")), bool(r.get("cold"))))
    for r in records:
        r["label"] = (r["name"] + (" --descend" if r.get("descend") else "")
                      + (" (cold)" if r.get("cold") else ""))
    lines = []
    host = records[0]["machine"]
    lines.append(f"Machine: {host['cpu']}, {host['physical_cpus']} cores / "
                 f"{host['logical_cpus']} threads, {host['memory_gb']} GB, {host['os']}; "
                 f"{host['rustc']}. The target machine is 16 cores / 32 GB.\n")
    lines.append("| corpus | LOC physical / code | tier (physical / code) | findings | total s "
                 "| min per 100k LOC (physical / code) | peak MB self / largest child | profile, cache |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for r in records:
        loc, t = r["loc"], r["timings"]
        per = lambda n: (t["total_wall_s"] / 60.0) / (n / 100_000)  # noqa: E731
        # Below a thousand lines the fixed start-up cost is the whole run, and
        # a per-100k rate extrapolates nothing but that.
        rate = (f"{per(loc['physical']):.1f} / {per(loc['code']):.1f}"
                if loc["physical"] >= MIN_LOC_FOR_RATE else "—")
        lines.append(
            f"| {r['label']} | {loc['physical']:,} / {loc['code']:,} | "
            f"{tier(loc['physical'])} / {tier(loc['code'])} | {r['findings']} | "
            f"{t['total_wall_s']:.1f} | {rate} | "
            f"{t['peak_self_mb']:.0f} / {t['peak_children_mb']:.0f} | "
            f"{r['profile']}, {'cold' if r.get('cold') else 'warm' if r['extraction_cache_existed'] or r['warmup'] else 'first run'} |")
    lines.append("")
    lines.append("Per stage, wall seconds (share of total):\n")
    lines.append("| corpus | " + " | ".join(STAGES) + " |")
    lines.append("|---|" + "---|" * len(STAGES))
    for r in records:
        t = r["timings"]
        by = {s["stage"]: s for s in t["stages"]}
        cells = []
        for stage in STAGES:
            s = by.get(stage)
            cells.append(f"{s['wall_s']:.2f} ({100 * s['wall_s'] / t['total_wall_s']:.0f}%)"
                         if s else "—")
        lines.append(f"| {r.get('label', r['name'])} | " + " | ".join(cells) + " |")
    lines.append("")
    lines.append("Per stage, peak memory reached by the end of the stage, MB (self / largest child):\n")
    lines.append("| corpus | " + " | ".join(STAGES) + " |")
    lines.append("|---|" + "---|" * len(STAGES))
    for r in records:
        by = {s["stage"]: s for s in r["timings"]["stages"]}
        cells = [f"{by[s]['peak_self_mb']:.0f} / {by[s]['peak_children_mb']:.0f}" if s in by else "—"
                 for s in STAGES]
        lines.append(f"| {r.get('label', r['name'])} | " + " | ".join(cells) + " |")
    lines.append("")
    extraction = {r["label"]: sum(s["wall_s"] for s in r["timings"]["stages"]
                                 if s["stage"].startswith("extract"))
                  / r["timings"]["total_wall_s"] for r in records}
    lines.append("Extraction's share of wall time: " + ", ".join(
        f"{name} {100 * share:.0f}%" for name, share in extraction.items()))
    large = [r for r in records if tier(r["loc"]["physical"]) == "large"]
    for r in large:
        t, loc = r["timings"], r["loc"]
        per = (t["total_wall_s"] / 60.0) / (loc["physical"] / 100_000)
        per_code = (t["total_wall_s"] / 60.0) / (loc["code"] / 100_000)
        lines.append(f"\nTarget check on {r['label']}: {per:.1f} min per 100k physical LOC "
                     f"({per_code:.1f} per 100k code LOC) against {TARGET_MINUTES_PER_100K:.0f}; "
                     f"peak {max(t['peak_self_mb'], t['peak_children_mb']):.0f} MB against 32 GB.")
    text = "\n".join(lines)
    print(text)
    if args.md:
        args.md.write_text(text + "\n")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("out_dir", type=Path)
    r.add_argument("--corpus", action="append", default=[], metavar="NAME=PATH",
                   help="crate root relative to the repository; default: the shipped corpus")
    r.add_argument("--profile", choices=["release", "debug"], default="release")
    r.add_argument("--warmup", action="store_true", help="run each corpus once, untimed, first")
    r.add_argument("--cold", action="store_true",
                   help="move the extraction cache aside for the run, so every dependency "
                        "is compiled too; the cache is restored afterwards")
    r.add_argument("--descend", action="store_true",
                   help="analyse with --descend; --cold then clears the descent cache too")
    r.add_argument("--suffix", default="", help="appended to each result's file name, e.g. -cold")
    p = sub.add_parser("report")
    p.add_argument("out_dir", type=Path)
    p.add_argument("--md", type=Path, help="also write the tables to this Markdown file")
    args = ap.parse_args()
    return run(args) if args.cmd == "run" else report(args)


if __name__ == "__main__":
    sys.exit(main())
