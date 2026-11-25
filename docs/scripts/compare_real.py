#!/usr/bin/env python3
"""Agreement with the other scanners on the real crates.

Usage:
    python3 docs/scripts/compare_real.py OUT_DIR --stage STAGE_DIR [--tools scanners|codeql|all|none]

Needs the corpus from `benchmark/real-crates/prepare.sh` and a release build
of `quantumrust`.

The real crates have no ground truth, so this measures agreement, not
precision or recall: for each tool configuration, which call sites it shares
with QuantumRust and which each side reports alone.

* Same runners as the tool comparison. Each tool is run and parsed by
  `compare_tools.py`'s functions, in its default and its most inclusive
  configuration.
* Same source. The other tools scan a copy of each crate without `target/`,
  whose build output is full of crypto symbol names. QuantumRust runs on the
  original, because it compiles.
* Every finding is bucketed by where it lands, because the tools do not read
  the same files. QuantumRust analyses the library it compiles; the scanners
  read everything:
    - `src`: a file under `src/` that QuantumRust's build compiled, read from
      rustc's dep-info for the library (the newest `.d` in
      `target/qr-extract`). Only here is agreement meaningful;
    - `uncompiled`: a `src/` file the build did not compile, such as an
      optional feature's module (`age`'s `ssh`) or a crypto backend that is
      not selected (`jsonwebtoken`'s `aws_lc`). This is real crypto in code
      that is not built, like the benchmark's feature-gated `M4`. Items behind
      `#[cfg]` inside a compiled file are not separated out;
    - `dev`: `tests/`, `benches/`, `examples/`, `build.rs`. The benchmark
      counts crypto here as a false positive (`N2`, `N3`);
    - `other`: manifests, lockfiles, READMEs, changelogs, assets.
* A site is a (file, line) pair; several findings on one line are one site.
  Agreement is reported line-exact and per file, since the scanners often
  report a crate's `use` line instead of its call.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import compare_tools as tools  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
CRATES = REPO.parent / "analysed-crates"
CORPUS = ["age-0.12.1", "jsonwebtoken-11.1.0", "sequoia-openpgp-2.4.1"]
TOOLCHAIN = "nightly-2026-06-01"

# CryptoScan 1.4.0 panics on these files ("slice bounds out of range" in
# analyzer.IsURLOrPath), and the panic aborts the whole scan. All are binary
# OpenPGP test keys under tests/data/keys/, in the `dev` bucket. They are
# excluded by basename, since `--exclude` does not match paths; each name
# matches exactly one file in the crate.
CRYPTOSCAN_CRASHES = {
    "sequoia-openpgp-2.4.1": [
        "SHA384-private.pgp", "SHA512.pgp", "SHA512-private.pgp", "SHA1.pgp",
        "SHA1-private.pgp", "MD5.pgp", "MD5-private.pgp", "SHA256.pgp", "marven.pgp",
    ],
}


def _cryptoscan(src: Path, args: list[str]) -> list[dict]:
    crashes = CRYPTOSCAN_CRASHES.get(src.name)
    return tools._cryptoscan(src, [*args, "--exclude", ",".join(crashes)] if crashes else args)


QUANTUMRUST = [("default", []), ("--descend", ["--descend"])]
SCANNERS = [
    ("postquant", "default", [], tools._postquant),
    ("postquant", "--show-all", ["--show-all"], tools._postquant),
    ("cryptoscan", "default", [], _cryptoscan),
    ("cryptoscan", "--include-quantum-safe", ["--include-quantum-safe"], _cryptoscan),
    ("crypto-scanner", "default", [], tools._crypto_scanner),
]
CODEQL_SUITES = [
    ("rust-code-scanning", "codeql/rust-queries:codeql-suites/rust-code-scanning.qls"),
    ("security-extended", "codeql/rust-queries:codeql-suites/rust-security-extended.qls"),
]


def env() -> dict[str, str]:
    """The toolchain pinned, and the sysroot the release binary links against."""
    e = dict(os.environ, RUSTUP_TOOLCHAIN=TOOLCHAIN)
    sysroot = subprocess.run(
        ["rustc", "--print", "sysroot"], capture_output=True, text=True, check=True, env=e
    ).stdout.strip()
    e["DYLD_FALLBACK_LIBRARY_PATH"] = f"{sysroot}/lib"
    return e


def relative(path: str | None, root: Path) -> str:
    p = (path or "").replace("\\", "/")
    for prefix in (str(root.resolve()) + "/", str(root) + "/"):
        if p.startswith(prefix):
            return p[len(prefix):]
    return p.lstrip("./")


def compiled(crate: str) -> set[str]:
    """The library's source files, from the newest dep-info QuantumRust's build wrote."""
    lib = crate.rsplit("-", 1)[0].replace("-", "_")
    deps = sorted((CRATES / crate / "target/qr-extract/debug/deps").glob(f"{lib}-*.d"),
                  key=lambda p: p.stat().st_mtime)
    if not deps:
        raise RuntimeError(f"{crate}: no dep-info; run QuantumRust on it first")
    first = deps[-1].read_text().splitlines()[0]
    return {f for f in first.split(":", 1)[1].split() if f.endswith(".rs")}


def bucket(rel: str, built: set[str]) -> str:
    if rel.startswith(("tests/", "benches/", "examples/")) or rel == "build.rs":
        return "dev"
    if not (rel.startswith("src/") and rel.endswith(".rs")):
        return "other"
    return "src" if rel in built else "uncompiled"


def quantumrust(crate: str, args: list[str], out: Path, e: dict[str, str]) -> list[dict]:
    """Every occurrence in the CBOM, read as `score_benchmark` reads it."""
    proc = subprocess.run(
        [str(REPO / "target/release/quantumrust"), "analyze", str(CRATES / crate),
         *args, "--out", str(out)],
        capture_output=True, text=True, check=False, env=e, cwd=REPO,
    )
    (out / "terminal.txt").write_text(proc.stdout + proc.stderr)
    cbom = out / "cbom.json"
    if proc.returncode != 0 or not cbom.exists():
        raise RuntimeError(f"quantumrust {crate} {args}: exit {proc.returncode}")
    found = []
    for comp in json.loads(cbom.read_text()).get("components", []):
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        for occ in comp.get("evidence", {}).get("occurrences") or []:
            found.append({
                "file": occ.get("location"), "line": occ.get("line"),
                "name": comp.get("name"), "rule": props.get("quantumrust:rule"),
            })
    return found


def stage(crate: str, into: Path) -> Path:
    dest = into / crate
    if not dest.exists():
        shutil.copytree(CRATES / crate, dest, ignore=shutil.ignore_patterns("target", "qr-out"))
    return dest


def codeql(src: Path, suite: str, work: Path, e: dict[str, str]) -> list[dict]:
    db = work / "db"
    if not db.exists():
        tools._codeql_run(
            ["codeql", "database", "create", str(db), "--language=rust",
             f"--source-root={src}", "--overwrite", "--threads=0", "--ram=4096"],
            "database create",
        )
    sarif = work / f"{suite.rsplit('/', 1)[-1]}.sarif"
    tools._codeql_run(
        ["codeql", "database", "analyze", str(db), suite, "--format=sarif-latest",
         f"--output={sarif}", "--threads=0", "--ram=4096"],
        "analyze",
    )
    found = []
    for run in json.loads(sarif.read_text()).get("runs", []):
        for result in run.get("results", []):
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                found.append({
                    "file": phys.get("artifactLocation", {}).get("uri"),
                    "line": phys.get("region", {}).get("startLine"),
                    "name": result.get("ruleId"),
                })
    return found


def sites(findings: list[dict], root: Path, built: set[str]) -> dict[str, set]:
    by: dict[str, set] = {}
    for f in findings:
        rel = relative(f.get("file"), root)
        by.setdefault(bucket(rel, built), set()).add((rel, f.get("line")))
    return by


def summarise(results: dict) -> str:
    lines = []
    for crate, runs in results.items():
        lines.append(f"\n== {crate}")
        lines.append(f"  {'configuration':38} {'findings':>8} {'src':>5} {'uncomp':>6} {'dev':>5} "
                     f"{'other':>5} | vs QR default, src: {'both':>4} {'QR':>4} {'tool':>4} "
                     f"| files: {'both':>4} {'QR':>4} {'tool':>4}")
        qr = {tuple(s) for s in runs["quantumrust default"]["sites"].get("src", [])}
        qr_files = {f for f, _ in qr}
        for name, run in runs.items():
            b = {k: {tuple(s) for s in v} for k, v in run["sites"].items()}
            src = b.get("src", set())
            files = {f for f, _ in src}
            lines.append(
                f"  {name:38} {run['n']:>8} {len(src):>5} {len(b.get('uncompiled', ())):>6} "
                f"{len(b.get('dev', ())):>5} {len(b.get('other', ())):>5} | "
                f"{'':19}{len(src & qr):>4} {len(qr - src):>4} {len(src - qr):>4} | "
                f"{'':7}{len(files & qr_files):>4} {len(qr_files - files):>4} {len(files - qr_files):>4}"
            )
    lines.append("\nColumns after `findings` count distinct (file, line) sites by bucket "
                 "(see the module docstring).")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("out", type=Path)
    ap.add_argument("--tools", choices=["scanners", "codeql", "all", "none"], default="scanners",
                    help="`none` re-buckets and re-summarises the saved findings only")
    ap.add_argument("--stage", type=Path, required=True,
                    help="where the comparators' copies of the crates go (outside the repo)")
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    a.stage.mkdir(parents=True, exist_ok=True)
    # The copies sit outside analysed-crates/, so its toolchain file does not
    # reach them; a build script run by CodeQL would otherwise get `stable`.
    shutil.copy2(CRATES / "rust-toolchain.toml", a.stage / "rust-toolchain.toml")
    e = env()
    results_path = a.out / "results.json"
    results = json.loads(results_path.read_text()) if results_path.exists() else {}

    for crate in CORPUS:
        runs = results.setdefault(crate, {})
        src = stage(crate, a.stage)
        if a.tools in ("scanners", "all"):
            for cfg, args in QUANTUMRUST:
                out = a.out / crate / f"quantumrust-{cfg.lstrip('-')}"
                out.mkdir(parents=True, exist_ok=True)
                f = quantumrust(crate, args, out, e)
                runs[f"quantumrust {cfg}"] = {"n": len(f), "findings": f}
                print(f"  {crate}: quantumrust {cfg}: {len(f)}", flush=True)
            for tool, cfg, args, run in SCANNERS:
                f = run(src, args)
                runs[f"{tool} {cfg}"] = {"n": len(f), "findings": f}
                print(f"  {crate}: {tool} {cfg}: {len(f)}", flush=True)
        if a.tools in ("codeql", "all"):
            work = a.stage / f"codeql-{crate}"
            work.mkdir(exist_ok=True)
            for cfg, suite in CODEQL_SUITES:
                f = codeql(src, suite, work, e)
                runs[f"codeql {cfg}"] = {"n": len(f), "findings": f}
                print(f"  {crate}: codeql {cfg}: {len(f)}", flush=True)
        built = compiled(crate)
        for name, run in runs.items():
            root = CRATES / crate if name.startswith("quantumrust") else src
            run["sites"] = {k: sorted(v, key=str) for k, v in sites(run["findings"], root, built).items()}
        results_path.write_text(json.dumps(results, indent=1, default=list))

    text = summarise(results)
    (a.out / "summary.txt").write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
