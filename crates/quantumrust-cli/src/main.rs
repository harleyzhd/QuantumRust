#![feature(rustc_private)]

extern crate rustc_driver;

mod doctor;
mod timings;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use callgraph::{FallbackCallGraphProvider, Reachability};
use clap::{Parser, Subcommand};
use cpg_core::{CallGraphProvider, Cpg, FeaturePolicy, Finding};
use qr_risk::{score_with, tier_for, NistTier, TierAssignment};
use qr_rules::RuleSet;

#[derive(Parser)]
#[command(
    name = "quantumrust",
    version,
    about = "Quantum-vulnerable crypto detection for Rust"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Copy, Clone, PartialEq, Eq, clap::ValueEnum)]
enum CbomFormat {
    Json,
    Xml,
    Both,
}

#[derive(Copy, Clone, PartialEq, Eq, clap::ValueEnum)]
enum Ablation {
    Dual,
    MirOnly,
    LlvmOnly,
}

impl From<Ablation> for cpg_core::AblationMode {
    fn from(a: Ablation) -> Self {
        match a {
            Ablation::Dual => Self::Dual,
            Ablation::MirOnly => Self::MirOnly,
            Ablation::LlvmOnly => Self::LlvmOnly,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, clap::ValueEnum)]
enum CallGraphChoice {
    #[value(help = "Rupta when `QR_CARGO_PTA` is set and builds, else the fallback")]
    Auto,
    #[value(
        help = "The graph's own call edges, where an unresolved call reaches nothing. The lower \
                end of the call-graph range"
    )]
    Fallback,
    #[value(
        help = "The fallback plus every `dyn` call linked to every local impl that could answer it"
    )]
    ChaDyn,
    #[value(
        help = "The fallback plus every unresolved trait call, `dyn` or generic, linked that way. \
                The upper end of the call-graph range"
    )]
    Cha,
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Command {
    #[command(
        about = "Analyse a Rust crate (live MIR extraction) or a serialized CPG \
                 (`--cpg <file.json>`)"
    )]
    Analyze {
        #[arg(help = "Path to a crate root (a directory containing Cargo.toml)")]
        path: Option<PathBuf>,
        #[arg(
            long,
            help = "Analyse a serialized CPG instead of extracting from source"
        )]
        cpg: Option<PathBuf>,
        #[arg(long, help = "Write the CBOM and the HTML report into this directory")]
        out: Option<PathBuf>,
        #[arg(
            long,
            help = "Write the fused CPG to a JSON file, for inspecting cross-layer linking and \
                    edge fan-out"
        )]
        dump_cpg: Option<PathBuf>,
        #[arg(
            long,
            default_value = "json",
            help = "The CBOM format or formats to write"
        )]
        format: CbomFormat,
        #[arg(
            long,
            help = "Path to a criticality map, a file that says which parts of this codebase \
                    matter more. CVSS Environmental bands are the deploying organisation's input, \
                    so without a map every finding gets a neutral `Medium`"
        )]
        criticality: Option<PathBuf>,
        #[arg(
            long,
            help = "Report findings against a compliance profile, given as a shipped id \
                    (`cnsa-2.0`, `nist-ir-8547`, `fips-pqc`) or as a path to a profile file. This \
                    reports against the policy and never certifies compliance"
        )]
        profile: Option<String>,
        #[arg(
            long,
            default_value = "dual",
            help = "Which IR layers to build the CPG from. `dual` (default) uses both layers. \
                    `mir-only` and `llvm-only` use one layer each, to show what that layer finds \
                    on its own"
        )]
        ablation: Ablation,
        #[arg(
            long,
            help = "Directory holding the score's constant tables (`nist_ir_8547_tiers.toml`, \
                    `cvss_v31_environmental.toml`), used in place of the shipped copies in \
                    `/data`. A revised standard then needs a re-run and no rebuild"
        )]
        score_tables: Option<PathBuf>,
        #[arg(
            long,
            help = "Also estimate each finding's refactor scope, the call sites a migration would \
                    touch. It counts the sites that key material reaches and not everything the \
                    call graph reaches, so an imprecise call graph can inflate the ranking but \
                    not the cost",
            long_help = "Also estimate each finding's refactor scope, the call sites a migration \
                         would touch. It counts the sites that key material reaches and not \
                         everything the call graph reaches, so an imprecise call graph can \
                         inflate the ranking but not the cost.\n\nOff by default, because it walks \
                         the graph once per finding, which takes a few seconds on a large crate."
        )]
        refactor_scope: bool,
        #[arg(
            long,
            help = "Also list crypto crates that the manifest declares and no call site reached, \
                    as declared unknowns. The analysis looks at one crate, so crypto used only \
                    inside a dependency is otherwise missed silently. Off by default, because \
                    these are not detections"
        )]
        manifest_assets: bool,
        #[arg(
            long,
            help = "Also extract under the Cargo features that the default set leaves off, so \
                    crypto behind a disabled `#[cfg(feature = \"…\")]` is analysed as well. Off \
                    by default, because each extra feature configuration is another full compile \
                    per IR layer"
        )]
        cfg_union: bool,
        #[arg(
            long,
            default_value_t = 3,
            requires = "cfg_union",
            help = "With `--cfg-union`, the most per-feature passes to attempt when \
                    `--all-features` does not build, as happens when features are mutually \
                    exclusive. Features beyond the cap are reported as unanalysed"
        )]
        cfg_union_max: usize,
        #[arg(long, value_name = "DEPTH", num_args = 0..=1, default_missing_value = "3",
              value_parser = clap::value_parser!(u8).range(1..=8),
              help = "Follow calls into dependency code, up to DEPTH dependency bodies along a \
                      call path (default 3), and report crypto found there at the local call \
                      site that reaches it. Only crates that can reach a crypto crate are \
                      entered, and crypto crates themselves never are. Off by default, because \
                      it is a separate build that starts cold")]
        descend: Option<u8>,
        #[arg(
            long,
            value_enum,
            default_value = "auto",
            help = "Which call graph the blast radius is computed over. `auto` (default) uses \
                    Rupta when it is available, else the fallback. `fallback` and `cha` are the \
                    lower and upper ends of the range that any sound call graph falls in"
        )]
        call_graph: CallGraphChoice,
        #[arg(
            long,
            help = "Also write every scored finding as JSON, with the CPG node it sits on, so \
                    scripts can tell two findings on one line apart"
        )]
        findings_json: Option<PathBuf>,
        #[arg(
            long,
            help = "Also write per-stage wall clock, CPU time and peak memory as JSON. \
                    `cargo xtask scale` reads this file"
        )]
        timings: Option<PathBuf>,
    },
    #[command(about = "Write the built-in demo CPG to a JSON file (regenerates the fixture)")]
    DumpDemoCpg { path: PathBuf },
    #[command(
        about = "Check that the toolchain and both extraction drivers are in place, and say how \
                 to fix whatever is not"
    )]
    Doctor,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Analyze {
            path,
            cpg,
            out,
            dump_cpg,
            format,
            profile,
            criticality,
            ablation,
            manifest_assets,
            score_tables,
            refactor_scope,
            cfg_union,
            cfg_union_max,
            descend,
            call_graph,
            findings_json,
            timings,
        } => analyze(&AnalyzeArgs {
            path: path.as_deref(),
            cpg_path: cpg.as_deref(),
            out: out.as_deref(),
            dump_cpg: dump_cpg.as_deref(),
            format,
            profile: profile.as_deref(),
            criticality: criticality.as_deref(),
            ablation,
            manifest_assets,
            score_tables: score_tables.as_deref(),
            refactor_scope,
            features: if cfg_union {
                FeaturePolicy::CfgUnion {
                    max_fallback: cfg_union_max,
                }
            } else {
                FeaturePolicy::DefaultOnly
            },
            descend,
            call_graph,
            findings_json: findings_json.as_deref(),
            timings: timings.as_deref(),
        }),
        Command::DumpDemoCpg { path } => {
            Cpg::demo().save_json(&path).context("writing demo CPG")?;
            println!("wrote demo CPG to {}", path.display());
            Ok(())
        }
        Command::Doctor => {
            if doctor::run() {
                Ok(())
            } else {
                std::process::exit(1)
            }
        }
    }
}

fn print_against_profile(judged: &qr_report::Judged, findings: &[cpg_core::Finding]) {
    println!(
        "\nAgainst profile: {} ({})",
        judged.profile_name, judged.profile_id
    );
    for (finding, verdict) in findings.iter().zip(&judged.verdicts) {
        if *verdict != qr_report::Verdict::Pass {
            println!(
                "  [{}] {} — {}:{}",
                verdict.label(),
                qr_report::display_symbol(&finding.contextual_signature),
                finding.location.file,
                finding.location.line
            );
        }
    }
    println!("  {} ({})", judged.tally(), qr_report::NOT_A_CERTIFICATE);
}

struct AnalyzeArgs<'a> {
    path: Option<&'a Path>,
    cpg_path: Option<&'a Path>,
    out: Option<&'a Path>,
    dump_cpg: Option<&'a Path>,
    format: CbomFormat,
    profile: Option<&'a str>,
    criticality: Option<&'a Path>,
    ablation: Ablation,
    manifest_assets: bool,
    score_tables: Option<&'a Path>,
    refactor_scope: bool,
    features: FeaturePolicy,
    descend: Option<u8>,
    call_graph: CallGraphChoice,
    findings_json: Option<&'a Path>,
    timings: Option<&'a Path>,
}

fn analyze(args: &AnalyzeArgs<'_>) -> Result<()> {
    let AnalyzeArgs {
        path,
        cpg_path,
        out,
        dump_cpg,
        format,
        profile,
        criticality,
        ablation,
        manifest_assets,
        score_tables,
        refactor_scope,
        features,
        descend,
        call_graph: call_graph_choice,
        findings_json,
        timings: timings_path,
    } = *args;
    let mut timer = timings::Timings::start();
    let mut cpg = load_cpg(path, cpg_path, ablation, features, descend, &mut timer)?;
    if cpg.source().is_none() {
        if let Some(p) = path {
            cpg.set_source(analysed_target(Some(p), None));
        }
    }
    if let Some(target) = dump_cpg {
        cpg.save_json(target).context("dumping fused CPG")?;
        tracing::info!(path = %target.display(), "wrote fused CPG");
    }
    tracing::info!(
        nodes = cpg.node_count(),
        edges = cpg.edge_count(),
        "loaded CPG"
    );

    let rules = RuleSet::builtin();
    let findings = rules.match_cpg(&cpg);
    let findings = qr_rules::rehome(&cpg, &rules, findings);
    timer.mark("rule-matching");
    let findings = qr_taint::annotate(&cpg, &rules, findings);
    timer.mark("taint");
    let tainted = findings
        .iter()
        .filter(|f| !f.taint_chain.is_empty())
        .count();
    tracing::info!(
        findings = findings.len(),
        with_taint_chain = tainted,
        "matched rules"
    );

    let bracket = |scope| -> Result<cpg_core::CallGraph> {
        let provider = callgraph::ChaCallGraphProvider { scope };
        let cg = provider.build(&cpg)?;
        tracing::info!(
            provider = provider.name(),
            edges = cg.edges.len(),
            "call graph"
        );
        Ok(cg)
    };
    let call_graph = match (
        call_graph_choice,
        callgraph::rupta::cargo_pta_from_env(),
        path,
    ) {
        (CallGraphChoice::Fallback, _, _) => {
            let cg = FallbackCallGraphProvider.build(&cpg)?;
            tracing::info!(provider = "fallback", edges = cg.edges.len(), "call graph");
            cg
        }
        (CallGraphChoice::ChaDyn, _, _) => bracket(callgraph::DispatchScope::Dyn)?,
        (CallGraphChoice::Cha, _, _) => bracket(callgraph::DispatchScope::AllUnresolved)?,
        (CallGraphChoice::Auto, Some(_), Some(root)) => {
            let rupta = callgraph::RuptaCallGraphProvider {
                crate_root: root.to_path_buf(),
                cargo_pta: None,
            };
            match rupta.build(&cpg) {
                Ok(cg) => {
                    tracing::info!(
                        provider = rupta.name(),
                        edges = cg.edges.len(),
                        "call graph"
                    );
                    cg
                }
                Err(e) => {
                    tracing::warn!("rupta unavailable ({e}); using fallback call graph");
                    FallbackCallGraphProvider.build(&cpg)?
                }
            }
        }
        _ => FallbackCallGraphProvider.build(&cpg)?,
    };

    timer.mark("call-graph");

    let instances = std::cell::RefCell::new(std::collections::HashMap::new());
    let same_call = |a: &cpg_core::CpgNode, b: &cpg_core::CpgNode| {
        let mut cache = instances.borrow_mut();
        let mine = cache
            .entry(a.id)
            .or_insert_with(|| rules.instance_of(a))
            .clone();
        let theirs = cache.entry(b.id).or_insert_with(|| rules.instance_of(b));
        mine.compatible(theirs)
    };
    let reach = Reachability::new_with(&cpg, &call_graph, &same_call);
    let criticality = match criticality {
        Some(path) => qr_risk::CriticalityMap::load(path).context("loading criticality map")?,
        None => qr_risk::CriticalityMap::default(),
    };
    let tables = match score_tables {
        Some(dir) => {
            let t = qr_risk::ScoreTables::load_dir(dir).context("loading score tables")?;
            tracing::info!(dir = %dir.display(), "score tables");
            t
        }
        None => qr_risk::ScoreTables::builtin(),
    };
    if criticality.is_empty() {
        tracing::info!("no criticality map: every finding scores the neutral Medium band");
    }

    let symbol_of: std::collections::HashMap<u32, &str> =
        cpg.nodes().map(|n| (n.id, n.symbol.as_str())).collect();
    let type_args_of: std::collections::HashMap<u32, &[String]> = cpg
        .nodes()
        .map(|n| (n.id, n.type_args.as_slice()))
        .collect();
    let resolved_to: std::collections::HashMap<u32, String> = cpg
        .edges()
        .into_iter()
        .filter(|(_, _, kind)| *kind == cpg_core::EdgeKind::TraitResolve)
        .filter_map(|(from, to, _)| Some((from, symbol_of.get(&to)?.to_string())))
        .collect();
    let flow = refactor_scope.then(|| qr_taint::data_dep_adjacency(&cpg));
    let target = profile
        .map(qr_report::load_profile)
        .transpose()
        .context("loading compliance profile")?;
    for name in target.iter().flat_map(|p| p.unknown_verdict_names(&rules)) {
        tracing::warn!(
            "the profile gives a verdict for {name:?}, which this tool never reports \
             or recommends; check the name against the report"
        );
    }
    let judged = target
        .as_ref()
        .map(|p| qr_report::Judged::new(p, &findings, &rules));
    let scored: Vec<qr_report::ScoredFinding<'_>> = findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let blast = reach.blast_radius(f.node_id) as u64;
            let risk = score_with(
                &tables,
                tier_of(f),
                blast,
                criticality.for_path(&f.location.file),
            );
            qr_report::ScoredFinding {
                finding: f,
                tier: tier_number(risk.tier),
                risk: risk.value,
                severity: risk.severity,
                blast_factor: risk.blast_factor,
                criticality: risk.criticality,
                blast_radius: blast,
                conservative: risk.conservatively_mapped,
                resolves_to: resolved_to.get(&f.node_id).cloned(),
                call_symbol: symbol_of.get(&f.node_id).map(|s| s.to_string()),
                refactor_scope: flow
                    .as_ref()
                    .map(|flow| qr_taint::refactor_scope_in(flow, f)),
                chain_absence: if !f.taint_chain.is_empty() {
                    None
                } else if f.qv_status != cpg_core::QvStatus::Vulnerable {
                    Some("chains are traced for quantum-vulnerable findings")
                } else if rules.is_sink(&f.contextual_signature) {
                    Some("this call is itself a sink, so there is nothing downstream")
                } else {
                    Some("no data-flow path from here to a sink was found")
                },
                algorithm: qr_report::algorithm_name(f, &rules),
                advice: {
                    let name = qr_report::algorithm_name(f, &rules);
                    let types = type_args_of.get(&f.node_id).copied().unwrap_or(&[]);
                    qr_report::migration::recommend_at(f, types, &rules, &name, target.as_ref())
                },
                verdict: judged.as_ref().and_then(|j| j.verdicts.get(i).copied()),
                parts: qr_report::parts_text(&f.with, &rules),
            }
        })
        .collect();
    timer.mark("risk-scoring");

    println!("\nFindings ({}):", findings.len());
    for r in qr_report::ranked(&scored) {
        let f = r.finding;
        println!(
            "  [{}] {} ({:?}, {:?})  {}:{}  blast={} tier={} risk={:.2}{}",
            f.rule_id,
            qr_report::display_symbol(&f.contextual_signature),
            f.algorithm_class,
            f.qv_status,
            f.location.file,
            f.location.line,
            r.blast_radius,
            r.tier,
            r.risk,
            if r.conservative {
                " (conservative: upper bound)"
            } else {
                ""
            },
        );
        if !f.taint_chain.is_empty() {
            let chain: Vec<String> = f
                .taint_chain
                .iter()
                .map(|l| format!("{}:{}", l.file, l.line))
                .collect();
            println!("        taint: {}", chain.join(" -> "));
        }
        if !f.via.is_empty() {
            println!("        via: {}", qr_report::via_text(&f.via));
        }
        if !f.with.is_empty() {
            println!("        with: {}", qr_report::parts_text(&f.with, &rules));
        }
    }
    if let Some(path) = findings_json {
        let rows: Vec<serde_json::Value> = scored
            .iter()
            .map(|r| {
                let f = r.finding;
                serde_json::json!({
                    "node_id": f.node_id,
                    "rule": f.rule_id,
                    "signature": f.contextual_signature,
                    "class": format!("{:?}", f.algorithm_class),
                    "status": format!("{:?}", f.qv_status),
                    "file": f.location.file,
                    "line": f.location.line,
                    "blast": r.blast_radius,
                    "tier": r.tier,
                    "score": r.risk,
                    "conservative": r.conservative,
                    "parameter_set": f.parameter_set,
                    "with": f.with.iter().map(|p| serde_json::json!({
                        "rule": p.rule_id,
                        "signature": p.signature,
                        "status": format!("{:?}", p.qv_status),
                        "parameter_set": p.parameter_set,
                    })).collect::<Vec<_>>(),
                    "via": f.via.iter().map(|v| serde_json::json!({
                        "symbol": v.symbol,
                        "file": v.location.as_ref().map(|l| l.file.clone()),
                        "line": v.location.as_ref().map(|l| l.line),
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        std::fs::write(path, serde_json::to_string_pretty(&rows)?)
            .context("writing findings JSON")?;
    }
    if !scored.is_empty() {
        print!(
            "\n{}",
            qr_report::headline::render_text(&qr_report::headline(&scored))
        );
        let plan = qr_report::migration::plan(&scored);
        let unplanned = qr_report::migration::unplanned(&scored);
        if !plan.is_empty() || !unplanned.is_empty() {
            print!("\n{}", qr_report::migration::render_text(&plan, &unplanned));
        }
    }

    if let Some(judged) = &judged {
        print_against_profile(judged, &findings);
    }

    let declared = if manifest_assets {
        let root = path.unwrap_or_else(|| Path::new("."));
        let all = qr_report::declared_crypto(root, &rules);
        let symbols: Vec<&str> = cpg.nodes().map(|n| n.symbol.as_str()).collect();
        let gap = qr_report::unreached(&all, symbols);
        if !gap.is_empty() {
            println!(
                "\nDeclared but not reached ({} crate{}) — crypto inside a dependency \
                 is invisible to a crate-local analysis:",
                gap.len(),
                if gap.len() == 1 { "" } else { "s" }
            );
            for dep in &gap {
                let version = dep.version.as_deref().unwrap_or("*");
                println!("  {} {version}", dep.name);
            }
        }
        gap
    } else {
        Vec::new()
    };

    if let Some(dir) = out {
        std::fs::create_dir_all(dir).context("creating output directory")?;
        let mut written: Vec<&str> = Vec::new();
        let subject = path.and_then(qr_report::subject_of);
        let extras = qr_report::CbomExtras {
            declared: &declared,
            judged: judged.as_ref(),
            subject: subject.as_ref(),
        };
        if format != CbomFormat::Xml {
            let cbom = qr_report::emit_cbom_report(&findings, &rules, extras);
            std::fs::write(dir.join("cbom.json"), serde_json::to_string_pretty(&cbom)?)?;
            written.push("cbom.json");
        }
        if format != CbomFormat::Json {
            std::fs::write(
                dir.join("cbom.xml"),
                qr_report::emit_cbom_xml_report(&findings, &rules, extras),
            )?;
            written.push("cbom.xml");
        }
        std::fs::write(
            dir.join("report.html"),
            qr_report::render_dashboard_with(
                &scored,
                cpg.source()
                    .map(str::to_string)
                    .unwrap_or_else(|| analysed_target(path, cpg_path))
                    .as_str(),
                judged.as_ref(),
            ),
        )?;
        written.push("report.html");
        println!("\nwrote {} to {}", written.join(", "), dir.display());
    }
    timer.mark("report");
    if let Some(path) = timings_path {
        std::fs::write(path, serde_json::to_string_pretty(&timer.to_json())?)
            .context("writing timings")?;
    }

    Ok(())
}

fn analysed_target(path: Option<&Path>, cpg_path: Option<&Path>) -> String {
    if let Some(p) = path {
        return p
            .canonicalize()
            .ok()
            .as_deref()
            .and_then(Path::file_name)
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| p.display().to_string());
    }
    match cpg_path {
        Some(p) => format!(
            "serialized CPG: {}",
            p.file_name().unwrap_or(p.as_os_str()).to_string_lossy()
        ),
        None => "built-in demo CPG".to_string(),
    }
}

fn warn_if_cpg_predates_extractors(cpg_path: &Path) {
    let Ok(dumped) = cpg_path.metadata().and_then(|m| m.modified()) else {
        return;
    };
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    for extractor in ["mir-extract", "llvm-extract"] {
        let src = crates.join(extractor).join("src");
        let Some((newest, at)) = cpg_core::driver_freshness::newest_source(&src) else {
            continue;
        };
        if at > dumped {
            tracing::warn!(
                cpg = %cpg_path.display(),
                newer = %newest.display(),
                "the serialized CPG predates the extractor that would build it — \
                 re-dump with `--dump-cpg` or the analysis describes a graph this \
                 code no longer produces"
            );
            return;
        }
    }
}

fn load_cpg(
    path: Option<&Path>,
    cpg_path: Option<&Path>,
    ablation: Ablation,
    features: FeaturePolicy,
    descend: Option<u8>,
    timer: &mut timings::Timings,
) -> Result<Cpg> {
    if let Some(p) = cpg_path {
        if descend.is_some() {
            tracing::warn!(
                "--descend has no effect with --cpg: there is no extraction to descend in"
            );
        }
        warn_if_cpg_predates_extractors(p);
        let cpg = Cpg::load_json(p).with_context(|| format!("loading CPG from {}", p.display()))?;
        timer.mark("load-cpg");
        return Ok(cpg);
    }
    if let Some(p) = path {
        use cpg_core::{AblationMode, LlvmProvider, MirProvider};
        let mode: AblationMode = ablation.into();
        tracing::info!("extracting dual-level CPG from {}", p.display());
        let descent = match descend {
            Some(depth) => {
                let known = qr_rules::crypto::crypto_crates(&RuleSet::builtin());
                let plan = cpg_core::descent::plan(p, depth, &|name: &str| {
                    qr_rules::crypto::is_crypto_crate(name, &known)
                })
                .context("planning dependency descent")?;
                tracing::info!(depth, crates = ?plan.crates, "dependency descent");
                if plan.crates.is_empty() {
                    tracing::info!(
                        "dependency descent: no dependency reaches a crypto crate, \
                         so extracting as without --descend"
                    );
                    None
                } else {
                    Some(plan)
                }
            }
            None => None,
        };
        let mir = mir_extract::RustcMirProvider {
            features,
            descent: descent.clone(),
            ..Default::default()
        }
        .extract(p)
        .with_context(|| format!("extracting MIR layer from {}", p.display()))?;
        timer.mark("extract-mir");
        let llvm = llvm_extract::LlvmIrProvider {
            features,
            descent,
            ..Default::default()
        }
        .extract(p)
        .with_context(|| format!("extracting LLVM layer from {}", p.display()))?;
        timer.mark("extract-llvm");
        let mut fused = cpg_fusion::fuse(&mir, &llvm, mode);
        let linked = cpg_fusion::infer_cross_layer_refs(&mut fused);
        timer.mark("fuse");
        tracing::info!(
            mir_nodes = mir.node_count(),
            llvm_nodes = llvm.node_count(),
            cross_layer_edges = linked,
            "fused dual-level CPG"
        );
        return Ok(fused);
    }
    tracing::info!("no path given; analysing the built-in demo CPG");
    let cpg = Cpg::demo();
    timer.mark("load-cpg");
    Ok(cpg)
}

fn tier_of(f: &Finding) -> TierAssignment {
    tier_for(f.qv_status, f.algorithm_class)
}

fn tier_number(tier: NistTier) -> u8 {
    match tier {
        NistTier::Tier1 => 1,
        NistTier::Tier2 => 2,
        NistTier::Tier3 => 3,
    }
}
