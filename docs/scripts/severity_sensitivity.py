#!/usr/bin/env python3
"""Rank sensitivity to the severity table.

Usage:
    python3 docs/scripts/severity_sensitivity.py <analyze-output.txt | findings.json>

The tool ranks tier first, so the severity ranks in
`data/nist_ir_8547_tiers.toml` are compared, never multiplied. This script
re-scores a real `analyze` run under a multiplicative score,
`severity x f(blast radius)`, with several severity tables, and reports how
many pairwise orderings move against the 2:1 table. It shows two things:

* Rescaling changes nothing: multiplying every rank by one factor moves no pair.
* Re-weighting does: the Tier1:Tier2 ratio decides how much blast radius a
  Tier2 finding needs to overtake a Tier1 one.

It reads the CLI's output instead of re-running the analysis. The score
depends only on tier, blast radius and criticality, which are all on each
line, so one run covers every table.
"""

from __future__ import annotations

import itertools
import json
import math
import re
import sys
from collections import Counter

# `  [RULE] signature (Class, Status)  file:line  blast=N tier=T risk=X.XX`
#
# The tier is read from `tier=`, never recomputed, so it is always the tool's
# own. Output without it is rejected.
LINE = re.compile(
    r"\[(?P<rule>\S+)\] .*?\((?P<cls>\w+), (?P<status>\w+)\)"
    r"\s+(?P<file>\S+):(?P<line>\d+)\s+blast=(?P<blast>\d+)"
    r"(?: tier=(?P<tier>\d))? risk=(?P<risk>[0-9.]+)"
)


def tier_on(m: re.Match) -> int:
    """The tier the tool printed on one matched line."""
    if m["tier"] is None:
        raise ValueError(f"no tier= on line {m.group(0)!r}; re-run analyze with this tool version")
    return int(m["tier"])

# Severity tables to compare. The first is the one the tool ships.
TABLES: dict[str, tuple[float, float, float]] = {
    "shipped ordinal ranks 2:1": (2.0, 1.0, 0.0),
    "placeholder ranks 4:2": (4.0, 2.0, 0.0),
    "CVSS band floors 7:4": (7.0, 4.0, 0.0),
    "CVSS band midpoints 8:5.5": (8.0, 5.5, 0.0),
    "flat — severity carries nothing": (1.0, 1.0, 0.0),
}


class Finding(tuple):
    """`(rule, file, line, tier, blast)`: the score's inputs from one line."""

    __slots__ = ()

    @property
    def tier(self) -> int:
        return self[3]

    @property
    def blast(self) -> int:
        return self[4]


def parse(path: str) -> list[Finding]:
    """The findings in an `analyze --findings-json` file (`.json`) or in
    `analyze`'s printed output, with the tier the tool assigned."""
    if path.endswith(".json"):
        with open(path, encoding="utf-8") as fh:
            return [
                Finding((f["rule"], f["file"], f["line"], f["tier"], f["blast"]))
                for f in json.load(fh)
            ]
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            m = LINE.search(raw)
            if m:
                out.append(Finding((m["rule"], m["file"], int(m["line"]), tier_on(m), int(m["blast"]))))
    return out


def score(f: Finding, table: tuple[float, float, float]) -> float:
    """`Severity x f(BlastRadius) x Criticality`, with Criticality neutral.

    These runs use no criticality map, so every finding is Medium and weighs
    1.0, and the score reduces to the two terms that vary.
    """
    return table[f.tier - 1] * (1.0 + math.log2(f.blast + 1))


def disagreements(findings: list[Finding], a, b) -> tuple[int, int, list]:
    """Pairs whose relative order differs between two tables."""
    moved, total, examples = 0, 0, []
    for x, y in itertools.combinations(findings, 2):
        total += 1
        ord_a = (score(x, a) > score(y, a)) - (score(x, a) < score(y, a))
        ord_b = (score(x, b) > score(y, b)) - (score(x, b) < score(y, b))
        if ord_a != ord_b:
            moved += 1
            if len(examples) < 3:
                examples.append((x, y))
    return moved, total, examples


def crossover(ratio: float, tier1_blast: int) -> int:
    """Blast radius a Tier2 finding needs to overtake that Tier1 one.

    Solves `1 + log2(b + 1) = ratio * (1 + log2(tier1_blast + 1))`.
    """
    target = ratio * (1.0 + math.log2(tier1_blast + 1))
    return math.ceil(2.0 ** (target - 1.0)) - 1


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2

    findings = parse(sys.argv[1])
    if not findings:
        print(f"no findings parsed from {sys.argv[1]}", file=sys.stderr)
        return 1

    tiers = Counter(f.tier for f in findings)
    print(f"{len(findings)} findings from {sys.argv[1]}")
    print(
        f"  tier mix: Tier1={tiers[1]}  Tier2={tiers[2]}  Tier3={tiers[3]}"
        f"  ({tiers[3]} score 0 under every table)"
    )
    if not (tiers[1] and tiers[2]):
        print(
            "  NOTE: a corpus without both Tier1 and Tier2 cannot exercise the\n"
            "        ratio at all — every table below will agree trivially."
        )

    shipped = TABLES["shipped ordinal ranks 2:1"]
    print(f"\npairwise orderings that move, against the shipped 2:1 table:")
    for name, table in TABLES.items():
        if table == shipped:
            continue
        moved, total, examples = disagreements(findings, shipped, table)
        pct = 100.0 * (total - moved) / total if total else 100.0
        print(f"  {name:<34} {total - moved}/{total} preserved ({pct:.2f}%)")
        for x, y in examples:
            print(
                f"      flips: T{x.tier} {x[1]}:{x[2]} blast={x.blast}"
                f"  vs  T{y.tier} {y[1]}:{y[2]} blast={y.blast}"
            )

    print("\nwhere a Tier2 finding overtakes a Tier1 one (blast radius needed):")
    header = "  Tier1 blast  " + "".join(f"{n.split()[-1]:>12}" for n in TABLES)
    print(header)
    for b1 in (1, 10, 100, 1000):
        row = f"  {b1:>11}  "
        for table in TABLES.values():
            row += f"{crossover(table[0] / table[1], b1):>12}"
        print(row)

    return 0


if __name__ == "__main__":
    sys.exit(main())
