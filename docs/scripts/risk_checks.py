#!/usr/bin/env python3
"""Ranking checks: formal properties of the risk ranking.

Usage:
    python3 docs/scripts/risk_checks.py benchmark/mutants [--jobs N] [--json out.json]
        [--real NAME=analyze-output.txt|findings.json ...] [--bracket NAME=CPG,LOW.json,HIGH.json[,dyn] ...]
        [--figures DIR]
    python3 docs/scripts/risk_checks.py benchmark/mutants --from-json out.json [...]

`cargo xtask risk-checks` runs the first form. The checks use fold B of the
mutation benchmark.

The ranking is tier first: the tool's NIST tier, then `f(b) x Criticality`
within the tier. A finding's priority is the pair `(tier, score)`, and every
check compares pairs. The rank tests (Kruskal-Wallis, Cliff's delta) use each
pair's position in that order.

* Monotonicity. Over every pair of findings, one at least as severe, at least
  as far-reaching and equally critical must rank at least as high. Also checks
  `f(0) = 1` and that Tier 3 scores exactly zero.
* Stability across call graphs. The ranking is computed at both ends of the
  range every sound call graph falls in: `--call-graph fallback`, where
  unresolved dispatch reaches nothing, and `--call-graph cha`, where it reaches
  every local body that could answer it. Each pair of findings is reported as
  agreeing (same order at both ends) and as guaranteed (same order for every
  call graph in between). A pair is guaranteed when its score intervals do not
  overlap or, given the CPG (`--bracket NAME=CPG,LOW,HIGH`, findings from
  `analyze --findings-json`), when reachability settles it for every graph.
  The bracket also covers calls through function pointers. `cha_bracket`
  recomputes both ends on its own, and the script raises if its blast radii
  differ from the CLI's.
* Differentiation. The rank of the finding at each positive's labelled line,
  grouped by the label's NIST tier: Kruskal-Wallis across the three groups and
  Cliff's delta for each pair, with and without findings mapped conservatively
  (status `Unknown`, scored at their class's ceiling). The benchmark has five
  near-identical mutants per (family, parameter) cell, which are not
  independent samples, so the test is repeated on one value per cell.
* Partial-order agreement. Every pair of positives whose labels NIST IR 8547
  orders strictly (Tier 1 above Tier 2 above Tier 3) must be ranked in that
  order. Ties and inversions are counted, and every inversion is listed. With
  tier-first ranking, an inversion can only come from the tool assigning a
  different tier than the label.
* Ratio sweep. Agreement under a multiplicative score,
  `{T1: ratio, T2: 1, T3: 0} x f(b) x Criticality`, beside the tier-first
  figure. It shows how often blast radius would overturn tier if tiers were
  weighted instead of compared.

`--real` adds a real crate's `analyze` output, printed or from
`--findings-json`. It has no labels, so its tiers are the tool's own and its
agreement is 100% by construction.
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import score_benchmark as bench  # noqa: E402
from cha_bracket import Bracket  # noqa: E402
from severity_sensitivity import LINE, tier_on  # noqa: E402

RATIOS = [1.0, 1.1, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0, 4.0, 6.0, 8.0]


def blast_factor(blast: int) -> float:
    return 1.0 + math.log2(blast + 1)


def key(f: dict) -> tuple[int, float]:
    """A finding's priority, larger = more urgent: tier first, then score."""
    return (3 - f["tier"], f["score"])


def parse(text: str) -> list[dict]:
    """The scored findings in an `analyze` run's output.

    Raises on output without `tier=`, whose `risk=` would include the severity
    weight and so measure something else. The tier is the one the tool
    printed; nothing here recomputes it.
    """
    out = []
    for m in LINE.finditer(text):
        tier = tier_on(m)
        score, blast = float(m["risk"]), int(m["blast"])
        out.append({
            "rule": m["rule"], "cls": m["cls"], "status": m["status"],
            "file": m["file"], "line": int(m["line"]), "blast": blast, "score": score,
            "tier": tier,
            "conservative": m["status"] == "Unknown",
            # Criticality is the remaining factor; with no map it is the
            # neutral band. Recovered from the score, and only where the score
            # is non-zero.
            "criticality": score / blast_factor(blast) if tier != 3 else None,
        })
    return out


def load_findings(path: Path) -> list[dict]:
    """`analyze --findings-json` output, in the shape `parse` produces."""
    out = []
    for f in json.loads(Path(path).read_text()):
        out.append({
            "node_id": f["node_id"], "rule": f["rule"], "cls": f["class"], "status": f["status"],
            "file": f["file"], "line": f["line"], "blast": f["blast"], "score": f["score"],
            "tier": f["tier"], "conservative": f["conservative"],
            "criticality": f["score"] / blast_factor(f["blast"]) if f["tier"] != 3 else None,
        })
    return out


def run_mutant(repo: Path, mutant: Path, call_graph: str = "fallback") -> list[dict]:
    """One mutant through the CLI, as scored findings. Raises on failure.

    A run killed by a signal is retried once. The tool is deterministic, so a
    retry can change whether a result exists but never what it is.
    """
    out = mutant / "qr-out"
    for attempt in (1, 2):
        shutil.rmtree(out, ignore_errors=True)
        proc = subprocess.run(
            ["cargo", "run", "-q", "-p", "quantumrust-cli", "--", "analyze", str(mutant),
             "--out", str(out), "--call-graph", call_graph],
            cwd=repo, capture_output=True, text=True, check=False, timeout=bench.TIMEOUT_S,
        )
        if proc.returncode >= 0 or attempt == 2:
            break
        print(f"  {mutant.name}: killed by signal {-proc.returncode}, retrying", file=sys.stderr)
    if proc.returncode != 0:
        raise RuntimeError(f"{mutant.name}: exit {proc.returncode}\n{proc.stderr[-800:]}")
    return parse(proc.stdout)


# ---- monotonicity -----------------------------------------------------------

def monotonicity(findings: list[dict]) -> dict:
    """One finding at least as severe, as far-reaching and as critical as
    another must rank at least as high; plus the two anchors."""
    violations = []
    for a, b in itertools.permutations(findings, 2):
        if a["criticality"] is not None and b["criticality"] is not None \
                and abs(a["criticality"] - b["criticality"]) > 1e-6:
            continue
        if a["tier"] <= b["tier"] and a["blast"] >= b["blast"] \
                and (key(a)[0], key(a)[1] + 1e-9) < key(b):
            violations.append((a, b))
    tier3_nonzero = [f for f in findings if f["tier"] == 3 and f["score"] != 0.0]
    # f(0) = 1: with no criticality map every finding is Medium (1.0), so a
    # Tier 1/2 finding with no reach scores exactly 1.
    f0 = [f for f in findings if f["blast"] == 0 and f["tier"] != 3
          and abs(f["score"] - 1.0) > 0.01]
    return {"pairs_violating": len(violations), "tier3_nonzero": len(tier3_nonzero),
            "f0_violations": len(f0), "findings": len(findings)}


# ---- stability across call graphs -------------------------------------------

def bracket(low: list[dict], high: list[dict], graph: Bracket | None = None) -> dict:
    """Ranking stability between the two ends of the call-graph bracket.

    `low` and `high` are the same findings, in the same order, ranked with the
    fallback and the CHA call graph. Every sound provider's blast radius for a
    finding lies in `[low, high]`, so its score lies in the matching interval.
    With `graph`, reachability between the findings' nodes is used as well.
    """
    if [(f["rule"], f["file"], f["line"]) for f in low] != \
            [(f["rule"], f["file"], f["line"]) for f in high]:
        raise ValueError("the two runs did not produce the same findings")
    shrank = [(a, b) for a, b in zip(low, high) if b["blast"] < a["blast"]]
    if shrank:
        raise ValueError(f"{len(shrank)} findings lost reach under the upper bound")
    if graph is not None:
        for a, b in zip(low, high):
            mine = (graph.blast("low", a["node_id"]), graph.blast("high", a["node_id"]))
            if mine != (a["blast"], b["blast"]):
                raise ValueError(f"{a['file']}:{a['line']}: independent reach {mine} != "
                                 f"the CLI's {(a['blast'], b['blast'])}")
    moved = sum(a["blast"] != b["blast"] for a, b in zip(low, high))

    def sign(x, y):
        return (x > y) - (x < y)

    def settled_by_reach(x: int, y: int) -> bool:
        """Every graph in the bracket orders `x`, `y` the same way."""
        if x == y:
            return True
        x_in_y, y_in_x = x in graph.reach("low", y), y in graph.reach("low", x)
        if x_in_y and y_in_x:
            return True  # mutually reachable at the low end: tied everywhere
        if x_in_y and y not in graph.reach("high", x):
            return True  # y's reach contains x's, plus x, in every graph
        return y_in_x and x not in graph.reach("high", y)

    # pairs, agree, guaranteed by intervals, guaranteed with reachability
    counts = {"all": [0, 0, 0, 0], "same tier, scored": [0, 0, 0, 0]}
    unstable = []
    for (a_lo, a_hi), (b_lo, b_hi) in itertools.combinations(list(zip(low, high)), 2):
        agree = sign(key(a_lo), key(b_lo)) == sign(key(a_hi), key(b_hi))
        if a_lo["tier"] != b_lo["tier"] or a_lo["tier"] == 3:
            by_interval = True  # tier decides, or both score a true zero
        elif a_lo["blast"] == a_hi["blast"] and b_lo["blast"] == b_hi["blast"]:
            by_interval = True  # neither moves
        else:
            by_interval = a_hi["score"] < b_lo["score"] or b_hi["score"] < a_lo["score"]
        by_reach = by_interval or (graph is not None and agree
                                   and settled_by_reach(a_lo["node_id"], b_lo["node_id"]))
        groups = ["all"] + (["same tier, scored"] if a_lo["tier"] == b_lo["tier"] != 3 else [])
        for g in groups:
            c = counts[g]
            c[0] += 1
            c[1] += agree
            c[2] += by_interval
            c[3] += by_reach
        if not agree:
            unstable.append((a_lo, a_hi, b_lo, b_hi))

    def rate(k, n):
        return k / n if n else float("nan")

    return {"findings": len(low), "moved": moved, "with_reach": graph is not None,
            "_pairs": [(a["blast"], b["blast"], a["tier"]) for a, b in zip(low, high)]
            if graph is not None else [],
            "extra_edges": len(graph.extra) if graph is not None else None,
            **{g: {"pairs": n, "agree": a, "by_interval": i, "guaranteed": r,
                   "agree_rate": rate(a, n), "interval_rate": rate(i, n), "guaranteed_rate": rate(r, n)}
               for g, (n, a, i, r) in counts.items()},
            "flips": unstable}


# ---- differentiation --------------------------------------------------------

def cliffs_delta(xs: list[float], ys: list[float]) -> float:
    gt = sum(1 for x in xs for y in ys if x > y)
    lt = sum(1 for x in xs for y in ys if x < y)
    return (gt - lt) / (len(xs) * len(ys)) if xs and ys else float("nan")


def magnitude(delta: float) -> str:
    # Romano et al. (2006) thresholds.
    d = abs(delta)
    return "negligible" if d < 0.147 else "small" if d < 0.33 else "medium" if d < 0.474 else "large"


def exact_kruskal(groups: dict[int, list[float]]) -> float | None:
    """Kruskal-Wallis p by exhaustive permutation, when that is small enough.

    The chi-square approximation is unreliable for groups this small; with a
    dozen values every relabelling can simply be enumerated.
    """
    from scipy.stats import kruskal

    sizes = [len(v) for v in groups.values() if v]
    values = [x for v in groups.values() if v for x in v]
    if len(sizes) < 2 or math.factorial(len(values)) // math.prod(math.factorial(k) for k in sizes) > 200_000:
        return None
    observed = kruskal(*[v for v in groups.values() if v]).statistic
    hits = total = 0
    for perm in _partitions(list(range(len(values))), sizes):
        try:
            h = kruskal(*[[values[i] for i in part] for part in perm]).statistic
        except ValueError:  # every value identical in this relabelling
            h = 0.0
        total += 1
        hits += h >= observed - 1e-12
    return hits / total


def _partitions(items: list[int], sizes: list[int]):
    if not sizes:
        yield []
        return
    for first in itertools.combinations(items, sizes[0]):
        rest = [i for i in items if i not in first]
        for tail in _partitions(rest, sizes[1:]):
            yield [list(first), *tail]


def differentiation(groups: dict[int, list[float]]) -> dict:
    from scipy.stats import kruskal

    present = {t: v for t, v in groups.items() if v}
    out: dict = {"n": {t: len(v) for t, v in groups.items()}}
    values = [v for v in present.values()]
    if len(values) >= 2 and len({x for v in values for x in v}) > 1:
        h, p = kruskal(*values)
        out["kruskal"] = {"H": h, "p": p, "p_exact": exact_kruskal(present)}
    out["cliffs"] = {
        f"T{a}>T{b}": (cliffs_delta(groups[a], groups[b]), magnitude(cliffs_delta(groups[a], groups[b])))
        for a, b in ((1, 2), (1, 3), (2, 3)) if groups.get(a) and groups.get(b)
    }
    return out


# ---- partial-order agreement ------------------------------------------------

def rescored(f: dict, ratio: float) -> float:
    """`f` under the multiplicative score: Tier1 weighted `ratio` times Tier2
    (Tier2 = 1, Tier3 = 0)."""
    return {1: ratio, 2: 1.0, 3: 0.0}[f["tier"]] * f["score"]


def agreement(items: list[tuple[int, dict]], ratio: float | None = None) -> dict:
    """Pairs ordered strictly by tier: agree, tie, or invert.

    `items` pairs a tier (the label's on the benchmark, the tool's on a real
    crate) with the finding ranked for it. With `ratio`, the multiplicative
    score is used instead of the tier-first priority.
    """
    agree = tie = 0
    inversions = []
    for (ta, fa), (tb, fb) in itertools.combinations(items, 2):
        if ta == tb:
            continue
        (hi_t, hi), (lo_t, lo) = sorted(((ta, fa), (tb, fb)), key=lambda x: x[0])
        r_hi = key(hi) if ratio is None else rescored(hi, ratio)
        r_lo = key(lo) if ratio is None else rescored(lo, ratio)
        if r_hi > r_lo:
            agree += 1
        elif r_hi == r_lo:
            tie += 1
        else:
            inversions.append(((hi_t, hi), (lo_t, lo)))
    total = agree + tie + len(inversions)
    return {"pairs": total, "agree": agree, "tie": tie, "invert": len(inversions),
            "rate": agree / total if total else float("nan"), "inversions": inversions}


# ---- assembling -------------------------------------------------------------

def labelled(labels: list[dict], results: dict[str, list[dict]]) -> tuple[list, int]:
    """(label tier, the finding scored at its labelled line, cell) per found positive."""
    out, missing = [], 0
    for m in labels:
        if m["polarity"] != "positive":
            continue
        e = m["expected"][0]
        hits = [f for f in results.get(m["id"], [])
                if f["line"] == e["line"] and f["file"].endswith(e["file"])]
        if not hits:
            missing += 1
            continue
        # Several findings can land on one call; the one ranked highest is
        # what a reader triaging by risk sees first.
        best = max(hits, key=key)
        out.append((int(m["nist_tier"]), best, f"{m['family']} {m['parameter']}"))
    return out, missing


def analyse(labels: list[dict], results: dict[str, list[dict]], real: dict[str, list[dict]],
            brackets: dict[str, tuple[list[dict], list[dict], Bracket]] | None = None,
            results_high: dict[str, list[dict]] | None = None) -> dict:
    fold_b = [m for m in labels if m["fold"] == "B"]
    items, missing = labelled(fold_b, results)
    report: dict = {"fold_b_positives": sum(m["polarity"] == "positive" for m in fold_b),
                    "found": len(items), "missing": missing}

    report["stability"] = {}
    if results_high is not None:
        low = [f for m in fold_b for f in results.get(m["id"], [])]
        high = [f for m in fold_b for f in results_high.get(m["id"], [])]
        report["stability"]["benchmark fold B, pooled"] = bracket(low, high)
    for name, (low, high, graph) in (brackets or {}).items():
        report["stability"][name] = bracket(low, high, graph)

    report["monotonicity"] = {"all fold-B findings": monotonicity(
        [f for m in fold_b for f in results.get(m["id"], [])])}
    for name, fs in real.items():
        report["monotonicity"][name] = monotonicity(fs)

    # Each found positive's position in the tier-first order: all a rank test
    # reads from a value.
    position = {k: i for i, k in enumerate(sorted({key(f) for _, f, _ in items}))}

    def groups(subset):
        g: dict[int, list[float]] = {1: [], 2: [], 3: []}
        for t, f, _ in subset:
            g[t].append(position[key(f)])
        return g

    def per_cell(subset):
        cells: dict[tuple[int, str], list[float]] = {}
        for t, f, cell in subset:
            cells.setdefault((t, cell), []).append(position[key(f)])
        g: dict[int, list[float]] = {1: [], 2: [], 3: []}
        for (t, _), v in cells.items():
            g[t].append(sum(v) / len(v))
        return g

    exact = [x for x in items if not x[1]["conservative"]]
    report["differentiation"] = {
        "per mutant, all": differentiation(groups(items)),
        "per mutant, without conservative": differentiation(groups(exact)),
        "per cell, all": differentiation(per_cell(items)),
        "per cell, without conservative": differentiation(per_cell(exact)),
        "conservative": [(t, f["file"], f["line"], f["rule"], f["status"], f["tier"], f["score"])
                         for t, f, _ in items if f["conservative"]],
    }
    pairs = [(t, f) for t, f, _ in items]
    report["agreement"] = {
        "benchmark fold B, label tiers": agreement(pairs),
        "benchmark fold B, label tiers, without conservative": agreement([(t, f) for t, f, _ in exact]),
    }
    for name, fs in real.items():
        report["agreement"][f"{name}, tool tiers"] = agreement([(f["tier"], f) for f in fs])
    report["sweep"] = {
        "benchmark fold B": [(r, agreement(pairs, r)["rate"]) for r in RATIOS],
        **{name: [(r, agreement([(f["tier"], f) for f in fs], r)["rate"]) for r in RATIOS]
           for name, fs in real.items()},
    }
    report["tier_first"] = {
        "benchmark fold B": report["agreement"]["benchmark fold B, label tiers"]["rate"],
        **{name: report["agreement"][f"{name}, tool tiers"]["rate"] for name in real},
    }
    n = max(len(position) - 1, 1)
    report["_items"] = [(t, 100.0 * position[key(f)] / n, cell, f["conservative"], f["tier"])
                        for t, f, cell in items]
    return report


def print_report(r: dict) -> None:
    print(f"\nRanking checks on benchmark fold B: {r['fold_b_positives']} positives, "
          f"{r['found']} found ({r['missing']} not found, no score to check)\n")
    print("monotonicity")
    for name, m in r["monotonicity"].items():
        print(f"  {name:<28} findings {m['findings']:>4}  violating pairs {m['pairs_violating']}"
              f"  tier-3 non-zero {m['tier3_nonzero']}  f(0)!=1 {m['f0_violations']}")
    print("\nstability, bracketed: fallback (no edge for unresolved dispatch) vs CHA "
          "(every local candidate). Rupta itself cannot build any corpus here.")
    if not r["stability"]:
        print("  not run — pass --bracket, or run live")
    for name, b in r["stability"].items():
        extra = f", {b['extra_edges']} edges added" if b["extra_edges"] is not None else ""
        print(f"  {name:<24} findings {b['findings']:>4}, blast moved for {b['moved']}{extra}"
              + ("" if b["with_reach"] else "  (no CPG: intervals only)"))
        for g in ("all", "same tier, scored"):
            x = b[g]
            print(f"      {g:<18} pairs {x['pairs']:>6}  same order at both ends {x['agree_rate']:.2%}"
                  f"  guaranteed for every provider between: by intervals {x['interval_rate']:.2%},"
                  f" with reachability {x['guaranteed_rate']:.2%}")
        for a_lo, a_hi, b_lo, b_hi in b["flips"][:5]:
            print(f"      flips: {a_lo['file']}:{a_lo['line']} blast {a_lo['blast']}->{a_hi['blast']}"
                  f"  vs  {b_lo['file']}:{b_lo['line']} blast {b_lo['blast']}->{b_hi['blast']}")
        if len(b["flips"]) > 5:
            print(f"      ... {len(b['flips']) - 5} more")
    print("\ndifferentiation across the labels' NIST tiers")
    for key in ("per mutant, all", "per mutant, without conservative", "per cell, all",
                "per cell, without conservative"):
        d = r["differentiation"][key]
        kw = d.get("kruskal")
        exact = kw and kw.get("p_exact")
        kw_s = (f"H={kw['H']:.2f} p={kw['p']:.2e}" + (f" (exact permutation p={exact:.4f})" if exact is not None else "")
                if kw else "not computable")
        cl = "  ".join(f"{k} {v[0]:+.3f} ({v[1]})" for k, v in d["cliffs"].items())
        print(f"  {key:<34} n={d['n']}  Kruskal-Wallis {kw_s}\n      Cliff's delta: {cl}")
    print(f"  conservatively mapped among found positives: {len(r['differentiation']['conservative'])}")
    for c in r["differentiation"]["conservative"]:
        print(f"    label T{c[0]}  {c[1]}:{c[2]}  {c[3]} {c[4]} -> ranked as T{c[5]}, score {c[6]:.2f}")
    print("\nagreement with the IR 8547 partial order")
    for name, a in r["agreement"].items():
        print(f"  {name:<51} {a['agree']}/{a['pairs']} = {a['rate']:.2%}  ties {a['tie']}  inversions {a['invert']}")
        for (ht, hi), (lt, lo) in a["inversions"][:10]:
            print(f"      T{ht} (ranked T{hi['tier']}) {hi['file']}:{hi['line']} score {hi['score']:.2f} blast {hi['blast']}"
                  f"  <  T{lt} (ranked T{lo['tier']}) {lo['file']}:{lo['line']} score {lo['score']:.2f} blast {lo['blast']}")
        if a["invert"] > 10:
            print(f"      ... {a['invert'] - 10} more")
    print("\nMultiplicative score: agreement by Tier1:Tier2 ratio, against tier-first")
    for name, sweep in r["sweep"].items():
        print(f"  {name:<16} " + "  ".join(f"{ratio:g}:{rate:.2%}" for ratio, rate in sweep)
              + f"  | tier-first:{r['tier_first'][name]:.2%}")


def figures(r: dict, out: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    out.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.size": 9, "axes.spines.top": False, "axes.spines.right": False})

    # Figure 1: rank position by the label's tier, over bands of the tool's tier.
    fig, ax = plt.subplots(figsize=(4.2, 3.0))
    colours = {1: "#b2182b", 2: "#ef8a62", 3: "#4d4d4d"}
    for t in (1, 2, 3):
        band = [pos for _, pos, _, _, tool in r["_items"] if tool == t]
        if band:
            ax.axhspan(min(band) - 0.8, max(band) + 0.8, color=colours[t], alpha=0.08, linewidth=0)
            ax.text(3.45, (min(band) + max(band)) / 2, f"ranked\nTier {t}", fontsize=6,
                    va="center", color=colours[t])
    for t in (1, 2, 3):
        pts = [(pos, cons) for tier, pos, _, cons, _ in r["_items"] if tier == t]
        for i, (pos, cons) in enumerate(pts):
            x = t + (i % 9 - 4) * 0.035
            ax.scatter(x, pos, s=16, facecolor="none" if cons else colours[t], edgecolor=colours[t], linewidth=0.8)
    from matplotlib.lines import Line2D
    ax.legend(handles=[
        Line2D([], [], marker="o", linestyle="", color="#4d4d4d", label="classified"),
        Line2D([], [], marker="o", linestyle="", markerfacecolor="none", color="#4d4d4d",
               label="conservatively mapped"),
    ], frameon=False, fontsize=7, loc="lower left")
    ax.set_xticks([1, 2, 3], ["Tier 1\nmust migrate", "Tier 2\nshould migrate", "Tier 3\nresistant"])
    ax.set_xlim(0.6, 3.75)
    ax.set_ylabel("rank position (100 = most urgent)")
    ax.set_title("Tier-first rank by labelled NIST tier, benchmark fold B", fontsize=9)
    fig.tight_layout()
    fig.savefig(out / "figure-01-risk-by-tier.pdf")
    fig.savefig(out / "figure-01-risk-by-tier.png", dpi=200)
    plt.close(fig)

    # Figure 2: partial-order agreement against the Tier1:Tier2 ratio.
    fig, ax = plt.subplots(figsize=(4.2, 3.0))
    for i, (name, sweep) in enumerate(r["sweep"].items()):
        line, = ax.plot([s[0] for s in sweep], [s[1] * 100 for s in sweep], marker="o", markersize=3, label=name)
        # Every corpus sits at 100% here, so the markers are spread to stay visible.
        ax.plot([sweep[-1][0] * 1.6 * (1 + 0.07 * (i - 1))], [r["tier_first"][name] * 100], marker="D",
                markersize=4, color=line.get_color(), linestyle="")
    ax.axhline(99, color="grey", linestyle="--", linewidth=0.8)
    ax.axvline(2.0, color="grey", linestyle=":", linewidth=0.8)
    ax.set_xscale("log", base=2)
    ticks = [1, 2, 4, 8]
    ax.set_xticks(ticks + [RATIOS[-1] * 1.6], [str(t) for t in ticks] + ["tier\nfirst"])
    ax.set_xlabel("Tier1 : Tier2 ratio in a multiplicative score")
    ax.set_ylabel("pairs in IR 8547 order (%)")
    ax.legend(frameon=False, fontsize=8)
    ax.set_title("Partial-order agreement: ratio sweep vs. tier-first", fontsize=9)
    fig.tight_layout()
    fig.savefig(out / "figure-02-ratio-sweep.pdf")
    fig.savefig(out / "figure-02-ratio-sweep.png", dpi=200)
    plt.close(fig)

    # Figure 3: each finding's blast radius at both ends of the call-graph bracket.
    shown = {n: b for n, b in r["stability"].items() if b.get("_pairs")}
    if shown:
        fig, ax = plt.subplots(figsize=(4.2, 3.2))
        # Marker shape is the bracket and colour the tier, each with its own
        # legend, so the legends stay small.
        markers = ["o", "^", "s", "D", "v", "P"]
        tiers_shown = set()
        for i, (name, b) in enumerate(shown.items()):
            for t in (1, 2, 3):
                pts = [(lo + 1, hi + 1) for lo, hi, tier in b["_pairs"] if tier == t]
                if pts:
                    tiers_shown.add(t)
                    ax.scatter([p[0] for p in pts], [p[1] for p in pts], s=12, marker=markers[i % len(markers)],
                               facecolor="none", edgecolor=colours[t], linewidth=0.7)
        lim = max(hi for b in shown.values() for _, hi, _ in b["_pairs"]) + 2
        ax.plot([1, lim], [1, lim], color="grey", linewidth=0.6, linestyle=":")
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel("blast + 1, fallback (lower bound)")
        ax.set_ylabel("blast + 1, CHA (upper bound)")
        ax.add_artist(ax.legend(handles=[
            Line2D([], [], marker=markers[i % len(markers)], linestyle="", markerfacecolor="none",
                   color="#4d4d4d", markersize=4, label=name)
            for i, name in enumerate(shown)
        ], frameon=False, fontsize=6, loc="upper left"))
        # The upper bound is never below the lower one, so this corner is empty.
        ax.legend(handles=[
            Line2D([], [], color=colours[t], linewidth=1.5, label=f"Tier {t}") for t in sorted(tiers_shown)
        ], frameon=False, fontsize=6, loc="lower right")
        ax.set_title("Blast radius across the call-graph bracket", fontsize=9)
        fig.tight_layout()
        fig.savefig(out / "figure-03-bracket.pdf")
        fig.savefig(out / "figure-03-bracket.png", dpi=200)
        plt.close(fig)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("suite", type=Path)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--json", type=Path, help="write the scored findings here")
    ap.add_argument("--from-json", type=Path, help="re-analyse a previous --json run")
    ap.add_argument("--real", action="append", default=[], metavar="NAME=FILE",
                    help="a real crate's analyze output (.txt) or --findings-json file "
                         "(.json), as an at-scale supplement")
    ap.add_argument("--bracket", action="append", default=[], metavar="NAME=CPG,LOW,HIGH[,dyn]",
                    help="a real crate's dumped CPG and `--findings-json` output under "
                         "--call-graph fallback and cha (or cha-dyn, with `dyn`)")
    ap.add_argument("--figures", type=Path, help="write the figures into this directory")
    args = ap.parse_args()

    repo = Path(__file__).resolve().parents[2]
    suite = args.suite.resolve()
    labels = json.loads((suite / "labels.json").read_text())
    fold_b = [m for m in labels if m["fold"] == "B"]

    results_high = None
    if args.from_json:
        data = json.loads(args.from_json.read_text())
        # A --json run holds both ends of the bracket; a file of one run holds
        # the fallback results only.
        if "fallback" in data:
            results, results_high = data["fallback"], data["cha"]
        else:
            results = data
    else:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            found = list(pool.map(lambda m: run_mutant(repo, suite / m["id"]), fold_b))
            high = list(pool.map(lambda m: run_mutant(repo, suite / m["id"], "cha"), fold_b))
        results = {m["id"]: f for m, f in zip(fold_b, found)}
        results_high = {m["id"]: f for m, f in zip(fold_b, high)}
        if args.json:
            args.json.write_text(json.dumps({"fallback": results, "cha": results_high}, indent=2))

    real = {}
    for spec in args.real:
        name, _, path = spec.partition("=")
        real[name] = load_findings(Path(path)) if path.endswith(".json") else parse(
            Path(path).read_text()
        )

    brackets = {}
    for spec in args.bracket:
        name, _, paths = spec.partition("=")
        cpg, low, high, *scope = paths.split(",")
        brackets[name] = (load_findings(Path(low)), load_findings(Path(high)),
                          Bracket(Path(cpg), dyn_only=scope == ["dyn"]))

    r = analyse(labels, results, real, brackets, results_high)
    print_report(r)
    if args.figures:
        figures(r, args.figures)
    return 0


if __name__ == "__main__":
    sys.exit(main())
