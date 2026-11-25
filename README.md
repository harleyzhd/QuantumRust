# QuantumRust

QuantumRust finds quantum-vulnerable cryptography in a Rust crate and writes a CycloneDX 1.7 CBOM and an HTML report with a migration plan. This is version 1.0.

## Requirements

macOS or Linux, [rustup](https://rustup.rs), and the toolchain QuantumRust is built against:

```bash
rustup toolchain install nightly-2026-06-01 --component rustc-dev,llvm-tools-preview,rust-src
```

`cargo test --workspace` and the evaluation scripts need Python 3.11 or newer with these packages:

```bash
python3 -m pip install jsonschema lxml scipy matplotlib
```

Run the commands below from the repository root.

## Install and check

```bash
cargo xtask install      # add --offline to use only the local cargo registry
quantumrust doctor       # checks the toolchain and both drivers, and prints the fix for any that fail
```

This installs `quantumrust`, `mir-extract-driver` and `llvm-extract-driver` into `~/.cargo/bin`, or into `DIR/bin` with `--root DIR`. Keep the three in one directory.

## Run

```bash
quantumrust analyze path/to/crate --out qr-out
```

This prints the findings, ranked, and a migration plan, and writes `qr-out/cbom.json` and `qr-out/report.html`. Extraction always uses the pinned toolchain, whatever the crate's own `rust-toolchain.toml` says, so the crate must build on it. The first run compiles the crate's dependencies and is the slow one.

Each finding shows the rule, the call, its algorithm and quantum status, the call site, its blast radius (how many of the crate's nodes it reaches), its NIST IR 8547 tier (1 vulnerable, 2 deprecated or under 256 bits, 3 resistant) and a risk score that orders findings within a tier.

| Option | What it does |
|---|---|
| `--out DIR` | write the CBOM and `report.html` into DIR |
| `--format json\|xml\|both` | CBOM format: `cbom.json`, `cbom.xml` or both (default `json`) |
| `--profile ID\|FILE` | mark each finding pass, fail or review against `cnsa-2.0`, `nist-ir-8547`, `fips-pqc` (see `profiles/`) or your own profile file |
| `--criticality FILE` | TOML of `[[module]]` entries, each a `pattern` matched against file paths and a `criticality` of `High`, `Medium` or `Low` (default `Medium`) |
| `--descend[=DEPTH]` | follow calls into dependencies (default depth 3) and report crypto found there at your call site |
| `--cfg-union` | also analyse code behind Cargo features that are off by default |
| `--cfg-union-max N` | with `--cfg-union`, the most per-feature passes when `--all-features` does not build (default 3) |
| `--call-graph MODE` | how unresolved trait calls are linked: `fallback` (not linked), `cha-dyn` (`dyn` calls to every local impl), `cha` (all trait calls), `auto` (default) |
| `--manifest-assets` | also list crypto crates in the manifest that no call reached |
| `--refactor-scope` | also count the call sites a migration of each finding would touch |
| `--findings-json FILE` | write every scored finding as JSON |
| `--dump-cpg FILE`, `--cpg FILE` | save the code property graph, or analyse a saved one without extraction |
| `--timings FILE` | write wall clock, CPU and peak memory per stage as JSON |
| `--ablation dual\|mir-only\|llvm-only` | build the graph from one IR layer only |
| `--score-tables DIR` | read `nist_ir_8547_tiers.toml` and `cvss_v31_environmental.toml` from DIR instead of the copies built into the tool |

`--call-graph auto` uses Rupta when `QR_CARGO_PTA` points at its `cargo-pta` binary and Rupta builds the crate, and `fallback` otherwise. Build Rupta from commit `878f728` of github.com/rustanlys/rupta with `patches/0001-rupta-def-path-labels.patch` applied; it runs on `nightly-2024-02-03`.

## Rules

Each rule is a TOML file in `rules/`, embedded in the binary; `rules/R-RSA-001.toml` shows the format. To add one, add its file and list it in `SHIPPED` in `crates/rules/src/lib.rs`, then add a call it should match to a crate in `fixtures/rule-coverage/`, ending the line with `// expect: <rule id>`. `cargo test --workspace` checks that every rule fires where expected.

## Evaluation

```bash
cargo build --workspace            # the scripts run the tool with cargo run, which needs both drivers in target/debug
cargo xtask bench                  # generate the mutation benchmark in benchmark/mutants
benchmark/real-crates/prepare.sh   # unpack the real crates into ../analysed-crates
```

| Command | Measures | Archived output |
|---|---|---|
| `python3 docs/scripts/score_benchmark.py benchmark/mutants` | precision, recall and F1 on the benchmark | `docs/benchmark-scores/` |
| `cargo xtask compare` | the same for CryptoScan, PostQuant, crypto-scanner and CodeQL (any not installed is skipped) | `docs/tool-comparison/` |
| `cargo xtask ablate` | both IR layers against MIR only and LLVM only | `docs/layer-ablation/` |
| `cargo xtask risk-checks` | checks of the ranking | `docs/ranking/` |
| `cargo xtask scale run OUT && cargo xtask scale report OUT` | runtime and memory per stage | `docs/scalability/` |
| `python3 docs/scripts/compare_real.py OUT --stage DIR`, then `docs/scripts/real_sites.py` with the same arguments | agreement with the other scanners on the real crates | `docs/real-crates/` |

Extra arguments are passed to the script, such as `cargo xtask ablate --descend`; each script's `--help` lists them. `scale run OUT` builds the tool in release (`--profile debug` for a debug build), analyses the fixtures and the real crates, and writes one JSON per crate into the output directory OUT. `scale report OUT` prints the tables from those files. `compare_real.py` runs `target/release/quantumrust`, so run `cargo build --release --workspace` first; `--stage DIR` is a directory outside the repository for the other scanners' copies of the crates.

Archived results are in `docs/`: the folders above, and `unseen-crate/`, the findings on `vodozemac` 0.11.2, a crate the tool was not developed on. The scripts are in `docs/scripts/`.

## License

MIT OR Apache-2.0.
