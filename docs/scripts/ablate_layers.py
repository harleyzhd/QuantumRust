#!/usr/bin/env python3
"""Layer ablation on the mutation benchmark: both IR layers, MIR only, LLVM only.

Usage:
    python3 docs/scripts/ablate_layers.py benchmark/mutants [--jobs N] [--json out.json] [--descend]
    python3 docs/scripts/ablate_layers.py benchmark/mutants --from-json out.json

`cargo xtask ablate` runs the first form.

The question is whether the dual-layer CPG beats both single-layer runs on F1,
at precision no lower. Only detection is scored: blast radius comes from MIR,
so a risk-scored comparison would measure that instead of the layers.

* Line-exact, and within a window. The LLVM layer takes a call's line from its
  debug location, which can be a line or two from the line MIR reports. Exact
  matching alone would count that as a miss for LLVM only. Recall within
  +-WINDOW lines is shown beside the line-exact figures.
* Resolution, not row counts. Dual can report fewer rows than the two layers
  together, because fusion lets a named rule replace a fallback at the same
  site. So among the labels each configuration finds, the script counts how
  many came from a named rule (not a `-999` fallback) and how many were
  classified.
* One scorer. Precision, recall, F1 and recall by failure mode come from
  `score_benchmark.score`.

Each layer runs twice: with default features and with `--cfg-union`. Without
`--cfg-union`, `M4` is invisible to every layer.
"""

from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import score_benchmark as bench  # noqa: E402

LAYERS = ["dual", "mir-only", "llvm-only"]
FEATURES = [("default", []), ("cfg-union", ["--cfg-union"])]
WINDOW = 2


def within(expected: dict, finding: dict, window: int) -> bool:
    """`score_benchmark.matches`, with the line allowed to differ by `window`."""
    line = finding.get("line")
    return (
        line is not None
        and abs(line - expected["line"]) <= window
        and (finding.get("file") or "").endswith(expected["file"])
    )


def resolution(labels: list[dict], results: list[list[dict]]) -> dict:
    """Among positives found line-exact: how many through a named rule, and classified."""
    found = named = classified = windowed = 0
    for mutant, findings in zip(labels, results):
        if mutant["polarity"] != "positive":
            continue
        windowed += any(within(e, f, WINDOW) for e in mutant["expected"] for f in findings)
        hits = [f for e in mutant["expected"] for f in findings if bench.matches(e, f)]
        if not hits:
            continue
        found += 1
        named += any(not (f.get("rule") or "").endswith("-999") for f in hits)
        classified += any(f.get("status") not in (None, "unknown") for f in hits)
    return {"found": found, "named": named, "classified": classified, "windowed": windowed}


def by_mode_window(labels: list[dict], results: list[list[dict]]) -> dict:
    out: dict[str, list[int]] = {}
    for mutant, findings in zip(labels, results):
        if mutant["polarity"] != "positive":
            continue
        slot = out.setdefault(mutant["failure_mode"], [0, 0])
        slot[0] += any(within(e, f, WINDOW) for e in mutant["expected"] for f in findings)
        slot[1] += 1
    return out


def score_all(labels: list[dict], results: list[list[dict]]) -> dict:
    scored = bench.score(labels, results)
    scored["resolution"] = resolution(labels, results)
    scored["by_mode_window"] = by_mode_window(labels, results)
    tier1 = [(m, r) for m, r in zip(labels, results) if m["nist_tier"] == 1]
    scored["tier1"] = (sum(scored["hits"][m["id"]] for m, _ in tier1), len(tier1))
    return scored


def report(columns: list[tuple[str, dict]]) -> None:
    width = max(len(k) for k, _ in columns)
    first = columns[0][1]
    print(f"\nLayer ablation: {first['n_pos']} positive, {first['n_neg']} negative mutants; window +-{WINDOW} lines\n")
    print(f"  {'configuration':<{width}}  precision   recall      F1  TP  FP  FN"
          f"   recall +-{WINDOW}   Tier 1   named   classified")
    for key, s in columns:
        tp, fp, fn = s["all"]
        p, r, f1 = bench.prf(tp, fp, fn)
        res = s["resolution"]
        print(f"  {key:<{width}}  {p:8.1%} {r:8.1%} {f1:7.1%} {tp:3d} {fp:3d} {fn:3d}"
              f"   {res['windowed'] / s['n_pos']:8.1%}   {s['tier1'][0]:2d}/{s['tier1'][1]:<3d}"
              f"  {res['named']:3d}/{res['found']:<3d} {res['classified']:3d}/{res['found']:<3d}")

    modes = sorted(first["by_mode"])
    cells = {
        (key, m): "{}/{} w{}".format(*s["by_mode"].get(m, [0, 0]), s["by_mode_window"].get(m, [0, 0])[0])
        for key, s in columns
        for m in modes
    }
    widths = [max(len(m), *(len(cells[k, m]) for k, _ in columns)) + 2 for m in modes]
    print(f"\n  recall by failure mode (line-exact, then w = within +-{WINDOW} lines)")
    print(f"    {'':<{width}}" + "".join(f"{m:>{w}}" for m, w in zip(modes, widths)))
    for key, _ in columns:
        print(f"    {key:<{width}}" + "".join(f"{cells[key, m]:>{w}}" for m, w in zip(modes, widths)))

    print("\n  Per feature policy: does dual beat both ablations on F1, at precision no lower?")
    for policy, _ in FEATURES:
        # Keys are "<layer> <policy>", plus " descend" under --descend, so the
        # policy is the second word.
        cols = {k.split(" ")[0]: s for k, s in columns if k.split(" ")[1] == policy}
        if set(cols) != set(LAYERS):
            print(f"    {policy}: no verdict, ran {sorted(cols) or 'no layer'} of {LAYERS}")
            continue
        f1 = {k: bench.prf(*cols[k]["all"])[2] for k in LAYERS}
        prec = {k: bench.prf(*cols[k]["all"])[0] for k in LAYERS}
        verdicts = []
        for other in ("mir-only", "llvm-only"):
            beats = f1["dual"] > f1[other] and prec["dual"] >= prec[other]
            verdicts.append(f"vs {other}: F1 {f1['dual']:.1%} vs {f1[other]:.1%}, "
                            f"precision {prec['dual']:.1%} vs {prec[other]:.1%} -> {'beats' if beats else 'does not beat'}")
        print(f"    {policy}: " + "; ".join(verdicts))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("suite", type=Path)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--json", type=Path, help="write every finding and score here")
    ap.add_argument("--from-json", type=Path, help="re-score a previous --json run")
    ap.add_argument("--descend", action="store_true",
                    help="every configuration follows calls into dependency code")
    args = ap.parse_args()

    repo = Path(__file__).resolve().parents[2]
    suite = args.suite.resolve()
    labels = json.loads((suite / "labels.json").read_text())

    if args.from_json:
        saved = json.loads(args.from_json.read_text())
        report([(k, score_all(labels, [r["findings"].get(m["id"], []) for m in labels]))
                for k, r in saved.items()])
        return 0

    columns: list[tuple[str, dict]] = []
    record: dict[str, dict] = {}
    for policy, flags in FEATURES:
        for layer in LAYERS:
            extra = ["--ablation", layer, *flags, *(["--descend"] if args.descend else [])]
            with ThreadPoolExecutor(max_workers=args.jobs) as pool:
                results = list(pool.map(lambda m: bench.analyse(repo, suite / m["id"], extra), labels))
            key = f"{layer} {policy}" + (" descend" if args.descend else "")
            columns.append((key, score_all(labels, results)))
            record[key] = {"flags": extra, "findings": {m["id"]: r for m, r in zip(labels, results)}}
            print(f"  ran {key}", file=sys.stderr)

    report(columns)
    if args.json:
        args.json.write_text(json.dumps(record, indent=2, default=list))
    return 0


if __name__ == "__main__":
    sys.exit(main())
