#!/usr/bin/env python3
"""Time each classical scheme and its post-quantum replacement.

Usage:
    python3 docs/scripts/pqc_speed.py [--out data/pqc_speed.json] [--runs N]

Builds `benchmark/pqc-speed` in release, runs it `--runs` times (default 3),
and writes each operation's median across the runs, with the machine, the
compiler, the exact crate versions (from the benchmark's lockfile) and the
date. Run it on an idle machine.

Several runs are used because background load comes in bursts and slows
whatever is being timed. A slow operation (SLH-DSA signing, RSA keygen) gets
too few samples in one run to outvote a burst; across runs, the median drops
it. Each run's median is kept beside the combined one.

The tool does not time anything itself. `qr-report::migration` reads the file
this writes, as it reads the FIPS sizes in `data/pqc_replacements.toml`.
"""

from __future__ import annotations

import argparse
import datetime
import json
import platform
import re
import statistics
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BENCH = REPO / "benchmark" / "pqc-speed"
CRATES = ["ml-kem", "ml-dsa", "slh-dsa", "rsa", "sha2", "p256", "p384", "p521",
          "k256", "dsa", "ed25519-dalek", "x25519-dalek", "cx448"]


def sysctl(key: str) -> str:
    try:
        return subprocess.run(["sysctl", "-n", key], capture_output=True, text=True,
                              check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def crate_versions() -> dict:
    lock = (BENCH / "Cargo.lock").read_text()
    found = {}
    for name, version in re.findall(r'name = "([^"]+)"\nversion = "([^"]+)"', lock):
        if name in CRATES:
            found.setdefault(name, version)
    return found


def combine(runs: list[dict]) -> dict:
    """Each operation's median across runs; each run's median kept beside it."""
    out: dict = {}
    for scheme in runs[0]:
        for op in runs[0][scheme]:
            cells = [run[scheme][op] for run in runs]
            out.setdefault(scheme, {})[op] = {
                "median_us": statistics.median(c["median_us"] for c in cells),
                "mean_us": statistics.median(c["mean_us"] for c in cells),
                "min_us": min(c["min_us"] for c in cells),
                "iterations": sum(c["iterations"] for c in cells),
                "run_medians_us": [c["median_us"] for c in cells],
            }
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=REPO / "data" / "pqc_speed.json")
    ap.add_argument("--runs", type=int, default=3)
    args = ap.parse_args()

    subprocess.run(["cargo", "build", "--release", "-q"], cwd=BENCH, check=True)
    started = datetime.datetime.now(datetime.timezone.utc)
    runs = []
    for i in range(args.runs):
        print(f"run {i + 1} of {args.runs}", file=sys.stderr)
        run = subprocess.run([str(BENCH / "target" / "release" / "pqc-speed")], cwd=BENCH,
                             capture_output=True, text=True, check=True)
        runs.append(json.loads(run.stdout)["schemes"])
    mem = sysctl("hw.memsize")
    record = {
        "note": "Timings of each scheme in pqc_replacements.toml, measured in one "
                "sitting by benchmark/pqc-speed with the crates below (the versions sequoia-openpgp "
                "2.4.1 locks; k256, which sequoia does not use, is the newest 0.13), "
                "release build. median_us is what the report uses: the median, across "
                "the runs, of each run's median (run_medians_us). These are "
                "this machine's numbers for these Rust implementations, not a property of "
                "the algorithms: optimised C or assembly can be several times faster, and "
                "the post-quantum crates are pre-1.0.",
        "date": started.date().isoformat(),
        "machine": {
            "cpu": sysctl("machdep.cpu.brand_string") or platform.processor(),
            "logical_cpus": sysctl("hw.ncpu"),
            "physical_cpus": sysctl("hw.physicalcpu"),
            "memory_gb": round(int(mem) / 2**30, 1) if mem else None,
            "os": f"{platform.system()} {platform.release()}",
        },
        "rustc": subprocess.run(["rustc", "--version"], cwd=BENCH, capture_output=True,
                                text=True, check=True).stdout.strip(),
        "crates": crate_versions(),
        "runs": args.runs,
        "schemes": combine(runs),
    }
    args.out.write_text(json.dumps(record, indent=2) + "\n")
    for name, ops in record["schemes"].items():
        cells = "  ".join(f"{op} {v['median_us']:,.1f} us" for op, v in ops.items())
        print(f"  {name:<18} {cells}")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
