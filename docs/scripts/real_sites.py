#!/usr/bin/env python3
"""Classify the source line at each `src` site that compare_real.py found.

Usage:
    python3 docs/scripts/real_sites.py OUT_DIR --stage STAGE_DIR

Agreement counts alone cannot say whether a site one tool reports and the other
does not is a miss or noise. This reads the source line at every `src` site and
sorts it:

* `comment`: a `//`, `///` or `//!` line, or inside a `/* */` block;
* `use`: an import (`use ...;`, `extern crate`);
* `string`: the crypto name appears only inside a string literal;
* `code`: anything else, such as a call, a type, an identifier or a match arm.

`code` is an upper bound on sites that could be crypto operations; the other
three cannot be. Writes `sites.txt` and `sites.json` into OUT_DIR.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

CRATES = Path(__file__).resolve().parents[3] / "analysed-crates"


def kind(lines: list[str], n: int) -> str:
    text = lines[n - 1].strip() if 0 < n <= len(lines) else ""
    if text.startswith(("//", "*", "/*")):
        return "comment"
    if re.match(r"(pub(\([^)]*\))?\s+)?use\s|extern\s+crate\s", text):
        return "use"
    code = re.sub(r'"(?:\\.|[^"\\])*"', '""', text)
    code = re.sub(r"//.*", "", code)
    if code.strip(' ,;"()[]{}') == "" or not re.search(r"[A-Za-z]", code.replace('""', "")):
        return "string"
    return "code"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("out", type=Path)
    ap.add_argument("--stage", type=Path, required=True)
    a = ap.parse_args()
    results = json.loads((a.out / "results.json").read_text())
    rows = ["configuration                          crate      sites in src: total  comment   use  string  code"]
    detail = {}
    for crate, runs in results.items():
        cache: dict[str, list[str]] = {}

        def source(rel: str) -> list[str]:
            if rel not in cache:
                p = CRATES / crate / rel
                cache[rel] = p.read_text(errors="replace").splitlines() if p.exists() else []
            return cache[rel]

        qr = {tuple(s) for s in runs["quantumrust default"]["sites"].get("src", [])}
        for name, run in runs.items():
            src = [tuple(s) for s in run["sites"].get("src", [])]
            only = [s for s in src if s not in qr] if not name.startswith("quantumrust") else src
            c = Counter(kind(source(f), ln) for f, ln in only if isinstance(ln, int))
            label = "QR's own sites" if name.startswith("quantumrust") else "tool-only"
            rows.append(f"{name:38} {crate.split('-')[0]:10} {label:>13}: {len(only):>5}"
                        f" {c['comment']:>8} {c['use']:>5} {c['string']:>7} {c['code']:>5}")
            detail[f"{crate} {name}"] = [
                {"file": f, "line": ln, "kind": kind(source(f), ln),
                 "text": source(f)[ln - 1].strip()[:160] if 0 < ln <= len(source(f)) else ""}
                for f, ln in only if isinstance(ln, int)
            ]
    (a.out / "sites.json").write_text(json.dumps(detail, indent=1))
    text = "\n".join(rows)
    (a.out / "sites.txt").write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
