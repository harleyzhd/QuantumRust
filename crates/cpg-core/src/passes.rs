use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;

use crate::features::{self, Pass, Plan};
use crate::{Cpg, CpgNode, NodeIndex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FeaturePolicy {
    #[default]
    DefaultOnly,
    CfgUnion {
        max_fallback: usize,
    },
}

impl FeaturePolicy {
    #[must_use]
    pub fn plan(self, crate_root: &Path) -> Plan {
        match self {
            Self::DefaultOnly => Plan::default_only(),
            Self::CfgUnion { .. } => features::plan(crate_root),
        }
    }

    fn max_fallback(self) -> usize {
        match self {
            Self::DefaultOnly => 0,
            Self::CfgUnion { max_fallback } => max_fallback,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PassReport {
    pub ran: Vec<String>,
    pub all_features: Option<Result<(), String>>,
    pub failed: Vec<(String, String)>,
    pub skipped: Vec<String>,
}

impl PassReport {
    #[must_use]
    pub fn is_multi_pass(&self) -> bool {
        self.ran.len() > 1
    }

    #[must_use]
    pub fn gap(&self) -> Option<String> {
        if self.failed.is_empty() && self.skipped.is_empty() {
            return None;
        }
        let mut parts = Vec::new();
        if !self.failed.is_empty() {
            let failed: Vec<String> = self
                .failed
                .iter()
                .map(|(label, why)| format!("{label} ({why})"))
                .collect();
            parts.push(format!("did not build: {}", failed.join(", ")));
        }
        if !self.skipped.is_empty() {
            parts.push(format!(
                "not attempted, beyond the fallback cap: {}",
                self.skipped.join(", ")
            ));
        }
        Some(format!(
            "feature configurations not analysed, so crypto behind them is invisible — {}",
            parts.join("; ")
        ))
    }
}

pub fn extract_with<E: fmt::Display>(
    crate_root: &Path,
    policy: FeaturePolicy,
    run: impl FnMut(&Pass) -> Result<Cpg, E>,
) -> Result<(Cpg, PassReport), E> {
    run_plan(&policy.plan(crate_root), policy, run)
}

pub fn run_plan<E: fmt::Display>(
    plan: &Plan,
    policy: FeaturePolicy,
    mut run: impl FnMut(&Pass) -> Result<Cpg, E>,
) -> Result<(Cpg, PassReport), E> {
    let mut report = PassReport::default();
    let mut graphs = vec![run(&plan.default_pass)?];
    report.ran.push(plan.default_pass.label.clone());

    let extra = matches!(policy, FeaturePolicy::CfgUnion { .. });
    if let Some(all) = plan.all_pass.as_ref().filter(|_| extra) {
        match run(all) {
            Ok(graph) => {
                graphs.push(graph);
                report.ran.push(all.label.clone());
                report.all_features = Some(Ok(()));
            }
            Err(error) => {
                report.all_features = Some(Err(summarise(&error.to_string())));
                for (attempt, pass) in plan.individual.iter().enumerate() {
                    if attempt >= policy.max_fallback() {
                        report.skipped.push(pass.label.clone());
                        continue;
                    }
                    match run(pass) {
                        Ok(graph) => {
                            graphs.push(graph);
                            report.ran.push(pass.label.clone());
                        }
                        Err(error) => report
                            .failed
                            .push((pass.label.clone(), summarise(&error.to_string()))),
                    }
                }
            }
        }
    }

    let merged = union(graphs).expect("the default pass always contributes a graph");
    Ok((merged, report))
}

fn summarise(message: &str) -> String {
    let lines: Vec<&str> = message
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let Some(at) = lines.iter().position(|l| l.starts_with("error")) else {
        return lines.first().copied().unwrap_or_default().to_string();
    };
    match build_script_crate(lines[at]) {
        Some(krate) => match build_script_reason(&lines[at..]) {
            Some(reason) => format!("build script of `{krate}` failed: {reason}"),
            None => format!("build script of `{krate}` failed"),
        },
        None => lines[at].to_string(),
    }
}

fn build_script_crate(line: &str) -> Option<&str> {
    let spec = line
        .strip_prefix("error: failed to run custom build command for `")?
        .split('`')
        .next()?;
    Some(spec.split(" (").next().unwrap_or(spec))
}

fn build_script_reason<'a>(lines: &[&'a str]) -> Option<&'a str> {
    let start = lines.iter().position(|l| *l == "--- stderr")? + 1;
    let mut stderr = lines[start..].iter().copied();
    let first = stderr.next()?;
    if first.starts_with("thread ") && first.contains(" panicked at ") {
        stderr.next()
    } else {
        Some(first)
    }
}

#[must_use]
pub fn union(passes: Vec<Cpg>) -> Option<Cpg> {
    let mut passes = passes.into_iter();
    let first = passes.next()?;
    let rest: Vec<Cpg> = passes.collect();
    if rest.is_empty() {
        return Some(first);
    }

    let mut merged = Cpg::new(first.mode());
    if let Some(source) = first.source() {
        merged.set_source(source.to_string());
    }

    let mut nodes: HashMap<Slot, NodeIndex> = HashMap::new();
    let mut edges: HashSet<(Slot, Slot, String)> = HashSet::new();

    for pass in std::iter::once(&first).chain(rest.iter()) {
        let mut placed: HashMap<u32, (Slot, NodeIndex)> = HashMap::new();
        let mut occurrences: HashMap<String, usize> = HashMap::new();

        for node in pass.nodes() {
            let key = identity(node);
            let seen = occurrences.entry(key.clone()).or_insert(0);
            let slot = (key, *seen);
            *seen += 1;
            let index = match nodes.get(&slot) {
                Some(&existing) => existing,
                None => {
                    let fresh = merged.copy_node(node);
                    nodes.insert(slot.clone(), fresh);
                    fresh
                }
            };
            placed.insert(node.id, (slot, index));
        }

        for (from, to, edge) in pass.edges_full() {
            let (Some((x, a)), Some((y, b))) = (placed.get(&from), placed.get(&to)) else {
                continue;
            };
            if edges.insert((
                x.clone(),
                y.clone(),
                format!("{:?}{:?}", edge.kind, edge.args),
            )) {
                merged.add_edge_full(*a, *b, edge);
            }
        }
    }

    Some(merged)
}

type Slot = (String, usize);

fn identity(node: &CpgNode) -> String {
    let location = node.location.as_ref().map_or_else(String::new, |l| {
        format!("{}:{}", stable_path(&l.file), l.line)
    });
    format!(
        "{:?}\u{1f}{:?}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{:?}\u{1f}{:?}\u{1f}{:?}",
        node.layer,
        node.kind,
        node.symbol,
        node.canonical.as_deref().unwrap_or(""),
        location,
        node.const_args,
        node.type_args,
        node.static_args,
    )
}

fn stable_path(file: &str) -> String {
    let segments: Vec<&str> = file.split(['/', '\\']).collect();
    let mut out = Vec::with_capacity(segments.len());
    for (i, segment) in segments.iter().enumerate() {
        let generated = i > 0 && segments[i - 1] == "build" && segments.get(i + 1) == Some(&"out");
        match segment.rsplit_once('-') {
            Some((package, hash)) if generated && is_build_hash(hash) => out.push(package),
            _ => out.push(segment),
        }
    }
    out.join("/")
}

fn is_build_hash(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AblationMode, EdgeKind, IrLayer, NodeKind, SourceLoc};

    fn call(cpg: &mut Cpg, symbol: &str, line: u32) -> NodeIndex {
        cpg.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            symbol,
            Some(SourceLoc::new("src/lib.rs", line)),
        )
    }

    fn pass_with(symbols: &[(&str, u32)]) -> Cpg {
        let mut cpg = Cpg::new(AblationMode::Dual);
        for (symbol, line) in symbols {
            call(&mut cpg, symbol, *line);
        }
        cpg
    }

    #[test]
    fn no_passes_is_nothing_to_union() {
        assert!(union(Vec::new()).is_none());
    }

    #[test]
    fn a_single_pass_is_returned_untouched() {
        let one = pass_with(&[("rsa::RsaPrivateKey::new", 21), ("app::run", 5)]);
        let before: Vec<(u32, String)> = one.nodes().map(|n| (n.id, n.symbol.clone())).collect();
        let merged = union(vec![one]).unwrap();
        let after: Vec<(u32, String)> = merged.nodes().map(|n| (n.id, n.symbol.clone())).collect();
        assert_eq!(before, after, "ids and order are kept, not rebuilt");
    }

    #[test]
    fn a_call_site_both_passes_saw_appears_once() {
        let shared = &[("rsa::RsaPrivateKey::new", 21)][..];
        let merged = union(vec![pass_with(shared), pass_with(shared)]).unwrap();
        assert_eq!(merged.node_count(), 1);
    }

    #[test]
    fn a_call_site_only_the_gated_pass_saw_is_kept() {
        let default = pass_with(&[("app::run", 5)]);
        let gated = pass_with(&[("app::run", 5), ("rsa::RsaPrivateKey::new", 21)]);
        let merged = union(vec![default, gated]).unwrap();
        assert_eq!(merged.node_count(), 2);
        let symbols: Vec<&str> = merged.nodes().map(|n| n.symbol.as_str()).collect();
        assert!(symbols.contains(&"rsa::RsaPrivateKey::new"));
    }

    #[test]
    fn the_same_callee_at_two_lines_stays_two_nodes() {
        let cpg = pass_with(&[
            ("rsa::RsaPrivateKey::new", 21),
            ("rsa::RsaPrivateKey::new", 44),
        ]);
        let merged = union(vec![cpg.clone(), cpg]).unwrap();
        assert_eq!(merged.node_count(), 2);
    }

    #[test]
    fn an_edge_both_passes_carried_is_added_once() {
        let build = || {
            let mut cpg = Cpg::new(AblationMode::Dual);
            let a = call(&mut cpg, "app::sign", 10);
            let b = call(&mut cpg, "rsa::sign", 11);
            cpg.add_edge(a, b, EdgeKind::DataDep);
            cpg
        };
        let merged = union(vec![build(), build()]).unwrap();
        assert_eq!(merged.node_count(), 2);
        assert_eq!(merged.edge_count(), 1, "the shared edge is not doubled");
    }

    #[test]
    fn reachability_does_not_double_across_passes() {
        let build = || {
            let mut cpg = Cpg::new(AblationMode::Dual);
            let a = call(&mut cpg, "app::keygen", 3);
            let b = call(&mut cpg, "app::sign", 4);
            let c = call(&mut cpg, "app::send", 5);
            cpg.add_edge(a, b, EdgeKind::DataDep);
            cpg.add_edge(b, c, EdgeKind::DataDep);
            cpg
        };
        let merged = union(vec![build(), build()]).unwrap();
        assert_eq!(merged.node_count(), 3);
        assert_eq!(merged.edge_count(), 2);
    }

    #[test]
    fn different_edge_kinds_between_one_pair_both_survive() {
        let mut cpg = Cpg::new(AblationMode::Dual);
        let a = call(&mut cpg, "app::sign", 10);
        let b = call(&mut cpg, "rsa::sign", 11);
        cpg.add_edge(a, b, EdgeKind::DataDep);
        cpg.add_edge(a, b, EdgeKind::Call);
        let merged = union(vec![cpg.clone(), cpg]).unwrap();
        assert_eq!(merged.edge_count(), 2);
    }

    #[test]
    fn nodes_without_a_canonical_are_kept_apart() {
        let cpg = pass_with(&[
            ("core::ops::Try::branch", 9),
            ("core::clone::Clone::clone", 9),
        ]);
        let merged = union(vec![cpg.clone(), cpg]).unwrap();
        assert_eq!(merged.node_count(), 2);
    }

    #[test]
    fn the_merged_graph_keeps_the_first_passs_mode_and_source() {
        let mut one = Cpg::new(AblationMode::MirOnly);
        one.set_source("age-0.12.1");
        call(&mut one, "app::run", 1);
        let two = pass_with(&[("app::run", 1)]);
        let merged = union(vec![one, two]).unwrap();
        assert_eq!(merged.mode(), AblationMode::MirOnly);
        assert_eq!(merged.source(), Some("age-0.12.1"));
    }

    #[test]
    fn same_line_call_sites_in_one_pass_stay_distinct() {
        let cpg = pass_with(&[
            ("core::clone::Clone::clone", 12),
            ("core::clone::Clone::clone", 12),
        ]);
        let merged = union(vec![cpg.clone(), cpg]).unwrap();
        assert_eq!(merged.node_count(), 2);
    }

    #[test]
    fn a_pass_with_more_occurrences_contributes_the_extra_one() {
        let two = pass_with(&[("app::log", 7), ("app::log", 7)]);
        let three = pass_with(&[("app::log", 7), ("app::log", 7), ("app::log", 7)]);
        assert_eq!(
            union(vec![two.clone(), three.clone()])
                .unwrap()
                .node_count(),
            3
        );
        assert_eq!(
            union(vec![three, two]).unwrap().node_count(),
            3,
            "order does not matter"
        );
    }

    #[test]
    fn a_union_is_never_smaller_than_its_largest_pass() {
        let small = pass_with(&[("app::run", 1)]);
        let large = pass_with(&[
            ("app::run", 1),
            ("f", 2),
            ("f", 2),
            ("g", 3),
            ("g", 3),
            ("g", 3),
        ]);
        let largest = large.node_count();
        assert!(union(vec![small, large]).unwrap().node_count() >= largest);
    }

    #[test]
    fn same_line_twins_keep_separate_edges() {
        let build = || {
            let mut cpg = Cpg::new(AblationMode::Dual);
            let first = call(&mut cpg, "Clone::clone", 5);
            let second = call(&mut cpg, "Clone::clone", 5);
            let sink = call(&mut cpg, "rsa::sign", 6);
            cpg.add_edge(first, sink, EdgeKind::DataDep);
            cpg.add_edge(second, sink, EdgeKind::DataDep);
            cpg
        };
        let merged = union(vec![build(), build()]).unwrap();
        assert_eq!(merged.node_count(), 3);
        assert_eq!(merged.edge_count(), 2);
    }

    #[test]
    fn generated_code_in_a_rehashed_build_dir_is_one_node() {
        let at = |dir: &str| {
            let mut cpg = Cpg::new(AblationMode::Dual);
            cpg.add_node(
                IrLayer::Mir,
                NodeKind::CallSite,
                "lalrpop_util::state_machine::Parser::drive",
                Some(SourceLoc::new(
                    format!("/t/qr-extract/debug/build/{dir}/out/message/grammar.rs"),
                    276,
                )),
            );
            cpg
        };
        let merged = union(vec![
            at("sequoia-openpgp-3b40288800695afb"),
            at("sequoia-openpgp-91c0de55aa01b2f7"),
        ])
        .unwrap();
        assert_eq!(merged.node_count(), 1);
        let kept = merged.nodes().next().unwrap().location.clone().unwrap();
        assert!(
            kept.file.contains("3b40288800695afb"),
            "the first pass's real path is kept"
        );
    }

    #[test]
    fn only_a_cargo_build_hash_is_stripped() {
        assert_eq!(
            stable_path("/t/debug/build/pkg-0123456789abcdef/out/g.rs"),
            "/t/debug/build/pkg/out/g.rs"
        );
        for untouched in [
            "/t/debug/build/foo-cafe/out/g.rs",
            "/t/src/pkg-0123456789abcdef/g.rs",
            "/t/debug/build/pkg-0123456789abcdef/src/g.rs",
            "/t/debug/build/pkg-0123456789ABCDEF/out/g.rs",
            "src/native/x25519.rs",
        ] {
            assert_eq!(stable_path(untouched), untouched);
        }
    }

    fn three_features() -> Plan {
        features::plan_from_manifest("[features]\na = []\nb = []\nc = []\n")
    }

    const UNION: FeaturePolicy = FeaturePolicy::CfgUnion { max_fallback: 3 };

    fn run_with(
        plan: &Plan,
        policy: FeaturePolicy,
        broken: &[&str],
    ) -> (Vec<String>, Result<(Cpg, PassReport), String>) {
        let mut attempted = Vec::new();
        let result = run_plan(plan, policy, |pass| {
            attempted.push(pass.label.clone());
            if broken.contains(&pass.label.as_str()) {
                return Err(format!(
                    "cargo check failed under the extraction wrapper:\n\
                     warning: unused\nerror: `{}` does not build",
                    pass.label
                ));
            }
            Ok(pass_with(&[("app::run", 1), (pass.label.as_str(), 2)]))
        });
        (attempted, result)
    }

    #[test]
    fn the_default_policy_runs_exactly_one_pass() {
        let plan = FeaturePolicy::DefaultOnly.plan(Path::new("/nonexistent"));
        let (attempted, result) = run_with(&plan, FeaturePolicy::DefaultOnly, &[]);
        assert_eq!(attempted, ["default"]);
        assert!(!result.unwrap().1.is_multi_pass());
    }

    #[test]
    fn the_default_policy_overrides_a_multi_pass_plan() {
        let (attempted, result) = run_with(&three_features(), FeaturePolicy::DefaultOnly, &[]);
        assert_eq!(attempted, ["default"]);
        assert!(result.unwrap().1.gap().is_none());
    }

    #[test]
    fn a_failing_default_pass_fails_the_extraction() {
        let (attempted, result) = run_with(&three_features(), UNION, &["default"]);
        assert!(result.is_err());
        assert_eq!(attempted, ["default"]);
    }

    #[test]
    fn when_all_features_builds_no_fallback_is_attempted() {
        let (attempted, result) = run_with(&three_features(), UNION, &[]);
        let (merged, report) = result.unwrap();
        assert_eq!(attempted, ["default", "all-features"]);
        assert_eq!(report.all_features, Some(Ok(())));
        assert!(report.gap().is_none());
        assert_eq!(
            merged.node_count(),
            3,
            "shared call site once, plus one per pass"
        );
    }

    #[test]
    fn when_all_features_fails_each_feature_is_tried_in_turn() {
        let (attempted, result) = run_with(&three_features(), UNION, &["all-features"]);
        let (merged, report) = result.unwrap();
        assert_eq!(attempted, ["default", "all-features", "a", "b", "c"]);
        assert_eq!(report.ran, ["default", "a", "b", "c"]);
        assert!(matches!(report.all_features, Some(Err(_))));
        assert_eq!(merged.node_count(), 5);
    }

    #[test]
    fn an_all_features_failure_alone_is_not_a_gap() {
        let (_, result) = run_with(&three_features(), UNION, &["all-features"]);
        assert!(result.unwrap().1.gap().is_none());
    }

    #[test]
    fn a_feature_that_does_not_build_is_a_declared_gap() {
        let (_, result) = run_with(&three_features(), UNION, &["all-features", "b"]);
        let (_, report) = result.unwrap();
        assert_eq!(report.ran, ["default", "a", "c"]);
        let gap = report.gap().expect("b was not analysed");
        assert!(gap.contains("b (error: `b` does not build)"), "{gap}");
    }

    #[test]
    fn the_fallback_cap_counts_attempts_not_successes() {
        let capped = FeaturePolicy::CfgUnion { max_fallback: 2 };
        let (attempted, result) = run_with(&three_features(), capped, &["all-features", "a"]);
        let (_, report) = result.unwrap();
        assert_eq!(attempted, ["default", "all-features", "a", "b"]);
        assert_eq!(report.skipped, ["c"]);
        let gap = report.gap().unwrap();
        assert!(gap.contains("beyond the fallback cap: c"), "{gap}");
    }

    #[test]
    fn a_zero_cap_attempts_all_features_and_nothing_after() {
        let none = FeaturePolicy::CfgUnion { max_fallback: 0 };
        let (attempted, result) = run_with(&three_features(), none, &["all-features"]);
        assert_eq!(attempted, ["default", "all-features"]);
        assert_eq!(result.unwrap().1.skipped, ["a", "b", "c"]);
    }

    const BUILD_SCRIPT_EXIT: &str = "cargo check failed under the extraction wrapper:
error: failed to run custom build command for `bsfail v0.1.0 (/tmp/bsfail)`

Caused by:
  process didn't exit successfully: `/tmp/bsfail/target/debug/build/bsfail-6a2649a917011bc6/build-script-build` (exit status: 1)
  --- stdout
  cargo:warning=probing backends

  --- stderr
  Multiple cryptographic backends selected.

  Sequoia requires exactly one cryptographic backend.
";

    const BUILD_SCRIPT_PANIC: &str = "error: failed to run custom build command for `nettle-sys v2.3.2`

Caused by:
  process didn't exit successfully: `/t/build/nettle-sys-0123456789abcdef/build-script-build` (exit status: 101)
  --- stderr

  thread 'main' (1777668) panicked at build.rs:3:9:
  Could not find nettle via pkg-config: package 'nettle' not found
  note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
";

    #[test]
    fn a_build_script_failure_reports_what_the_script_said() {
        assert_eq!(
            summarise(BUILD_SCRIPT_EXIT),
            "build script of `bsfail v0.1.0` failed: Multiple cryptographic backends selected."
        );
    }

    #[test]
    fn a_panicking_build_script_reports_the_panic_message() {
        assert_eq!(
            summarise(BUILD_SCRIPT_PANIC),
            "build script of `nettle-sys v2.3.2` failed: \
             Could not find nettle via pkg-config: package 'nettle' not found"
        );
    }

    #[test]
    fn a_build_script_that_wrote_nothing_still_names_the_crate() {
        let silent = "error: failed to run custom build command for `quiet v1.0.0`\n\
                      Caused by:\n  process didn't exit successfully: `x` (exit status: 1)";
        assert_eq!(summarise(silent), "build script of `quiet v1.0.0` failed");
    }

    #[test]
    fn a_failure_is_summarised_to_its_first_error_line() {
        let raw = "cargo check failed under the extraction wrapper:\n\
                   warning: unused import\n   Compiling x\nerror: linking with `cc` failed\nnote: …";
        assert_eq!(summarise(raw), "error: linking with `cc` failed");
        assert_eq!(
            summarise("no error lines here\nat all"),
            "no error lines here"
        );
        assert_eq!(summarise(""), "");
    }
}
