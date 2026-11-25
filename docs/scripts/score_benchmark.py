#!/usr/bin/env python3
"""Score QuantumRust on the mutation benchmark.

Usage:
    python3 docs/scripts/score_benchmark.py benchmark/mutants [--fold A|B] [--jobs N]
        [--cfg-union] [--descend] [--labels FILE]

Generate the benchmark first with `cargo xtask bench`. The script runs
`quantumrust analyze` on every mutant and scores the findings against
`labels.json`.

* A positive mutant is found if a finding lands on its labelled file and line.
  Labels are crate-relative (`src/lib.rs`) and the tool reports
  workspace-relative paths, so the path is matched as a suffix.
* Every finding on a negative mutant is a false positive.
* Precision and recall are reported twice: over all findings, and over
  quantum-vulnerable and deprecated findings only. `N0` and `N1` are real
  SHA-256 calls with no security role, so an inventory may list them and a
  risk report should not.

`--cfg-union` also extracts under the features each mutant leaves off. It
measures `M4`, whose crypto is behind a disabled feature.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

VULNERABLE = {"quantum-vulnerable", "deprecated"}

# One mutant takes seconds. A run past this is stuck, not slow.
TIMEOUT_S = 300


def matches(expected: dict, finding: dict) -> bool:
    """Whether a finding lands on an expected call site: path by suffix, line exactly."""
    got = finding.get("file") or ""
    return finding.get("line") == expected["line"] and got.endswith(expected["file"])


def analyse(repo: Path, mutant: Path, extra: list[str]) -> list[dict]:
    """Findings for one mutant.

    Raises if the run fails: an empty result would score as a miss on a
    positive and a pass on a negative.
    """
    out = mutant / "qr-out"
    cmd = [
        "cargo", "run", "-q", "-p", "quantumrust-cli", "--",
        "analyze", str(mutant), "--out", str(out), *extra,
    ]
    for attempt in (1, 2):
        # Clear the last run's output, so a failed run is not scored on it.
        shutil.rmtree(out, ignore_errors=True)
        try:
            proc = subprocess.run(
                cmd, cwd=repo, capture_output=True, text=True, check=False,
                timeout=TIMEOUT_S,
            )
        except subprocess.TimeoutExpired:
            print(f"  !! {mutant.name}: timed out (attempt {attempt})", file=sys.stderr)
            continue
        break
    else:
        raise RuntimeError(f"{mutant.name}: timed out twice")
    cbom = out / "cbom.json"
    if proc.returncode != 0 or not cbom.exists():
        tail = "\n".join(proc.stderr.strip().splitlines()[-5:])
        raise RuntimeError(f"{mutant.name}: exit {proc.returncode}, no CBOM\n{tail}")
    doc = json.loads(cbom.read_text())
    findings = []
    for comp in doc.get("components", []):
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        occ = (comp.get("evidence", {}).get("occurrences") or [{}])[0]
        findings.append(
            {
                "file": occ.get("location"),
                "line": occ.get("line"),
                "status": props.get("quantumrust:quantum-status"),
                "name": comp.get("name"),
                "rule": props.get("quantumrust:rule"),
            }
        )
    return findings


def score(labels: list[dict], results: list[list[dict]]) -> dict:
    """Score one tool's findings against the labels.

    `compare_tools.py` scores every tool with this function, so all tools are
    counted the same way.
    """
    tp = fn = 0
    fp_all = fp_vuln = 0
    tp_vuln = fn_vuln = 0
    by_mode: dict[str, list[int]] = {}
    by_negative: dict[str, int] = {}
    negatives_hit: list[tuple[str, str]] = []
    hits: dict[str, bool] = {}

    for mutant, findings in zip(labels, results):
        mode = mutant["failure_mode"]
        if mutant["polarity"] == "positive":
            hit = any(matches(e, f) for e in mutant["expected"] for f in findings)
            hits[mutant["id"]] = hit
            tp += hit
            fn += not hit
            hit_v = any(
                matches(e, f)
                for e in mutant["expected"]
                for f in findings
                if f["status"] in VULNERABLE
            )
            tp_vuln += hit_v
            fn_vuln += not hit_v
            slot = by_mode.setdefault(mode, [0, 0])
            slot[0] += hit
            slot[1] += 1
        else:
            # The bucket (N0..N6) is only in the id; the label says "N".
            bucket = mutant["id"].split("-")[0]
            by_negative[bucket] = by_negative.get(bucket, 0) + len(findings)
            fp_all += len(findings)
            vuln = [f for f in findings if f["status"] in VULNERABLE]
            fp_vuln += len(vuln)
            for f in findings:
                negatives_hit.append((mutant["id"], f"{f['name']} [{f['status']}]"))

    return {
        "n_pos": sum(1 for m in labels if m["polarity"] == "positive"),
        "n_neg": sum(1 for m in labels if m["polarity"] != "positive"),
        "all": (tp, fp_all, fn),
        "vulnerable": (tp_vuln, fp_vuln, fn_vuln),
        "by_mode": by_mode,
        "by_negative": by_negative,
        "negatives_hit": negatives_hit,
        "hits": hits,
    }


def prf(t: int, f: int, missed: int) -> tuple[float, float, float]:
    p = t / (t + f) if t + f else 0.0
    r = t / (t + missed) if t + missed else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f1


def render(scored: dict, title: str) -> None:
    """Print one tool's score."""
    print(f"\n{title}: {scored['n_pos']} positive, {scored['n_neg']} negative mutants\n")

    for label, (t, f, missed) in (
        ("all findings", scored["all"]),
        ("vulnerable-only", scored["vulnerable"]),
    ):
        p, r, f1 = prf(t, f, missed)
        print(
            f"  {label:16s}  precision {p:6.1%}   recall {r:6.1%}   F1 {f1:6.1%}"
            f"   (TP {t}, FP {f}, FN {missed})"
        )

    print("\n  recall by failure mode")
    for mode in sorted(scored["by_mode"]):
        hit, total = scored["by_mode"][mode]
        print(f"    {mode}  {hit}/{total}")

    if scored["negatives_hit"]:
        print(f"\n  findings on negative mutants ({len(scored['negatives_hit'])}):")
        for mid, what in scored["negatives_hit"]:
            print(f"    {mid:16s} {what[:70]}")
    else:
        print("\n  no findings on any negative mutant")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("suite", type=Path)
    ap.add_argument("--fold", choices=["A", "B"], help="score one fold only")
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument(
        "--cfg-union",
        action="store_true",
        help="also extract under each mutant's disabled features",
    )
    ap.add_argument(
        "--descend",
        action="store_true",
        help="follow calls into dependency code, depth 3",
    )
    ap.add_argument(
        "--labels",
        type=Path,
        help="score these labels instead of SUITE/labels.json (a subset of the suite)",
    )
    args = ap.parse_args()
    extra = ["--cfg-union"] if args.cfg_union else []
    if args.descend:
        extra.append("--descend")

    repo = Path(__file__).resolve().parents[2]
    suite = args.suite.resolve()
    labels = json.loads((args.labels or suite / "labels.json").read_text())
    if args.fold:
        labels = [m for m in labels if m["fold"] == args.fold]

    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(lambda m: analyse(repo, suite / m["id"], extra), labels))

    scored = score(labels, results)
    fold = f" (fold {args.fold})" if args.fold else ""
    union = " with --cfg-union" if args.cfg_union else ""
    descend = " with --descend" if args.descend else ""
    render(scored, f"Benchmark score{fold}{union}{descend}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
