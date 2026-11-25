# Benchmarks

**Mutation benchmark.** Generated test crates. Each positive mutant makes one
known crypto call, either directly (failure mode `M0`) or hidden in a way a
text search can miss: a wrapper, trait object, macro, `cfg` feature, FFI,
alias, generic or dependency. Each negative mutant is a decoy, such as a
checksum, that should give no finding. The generated `labels.json` lists each
mutant's failure mode and the expected file, line and API. From the
repository root:

```bash
cargo xtask bench          # writes benchmark/mutants, pinned by mutants.Cargo.lock
cargo build --workspace
python3 docs/scripts/score_benchmark.py benchmark/mutants --jobs 2
```

The scorer prints precision, recall and F1. Options: `--fold A|B` (half the
suite), `--cfg-union`, `--descend`, `--labels FILE` (a subset).

**pqc-speed.** Times each scheme in `data/pqc_replacements.toml` and writes
`data/pqc_speed.json`, the CPU column of the report's migration plan. That
file is compiled into the tool, so rebuild or reinstall the tool to use a new
one.

```bash
python3 docs/scripts/pqc_speed.py    # --runs N (default 3), --out FILE
```

**Real crates.** See [real-crates/README.md](real-crates/README.md).
