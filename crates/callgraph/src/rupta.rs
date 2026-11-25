use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use cpg_core::{CallGraph, Cpg, CpgError, EdgeKind, IrLayer, NodeKind};

use crate::cha::{call_key, impl_key, segments, suffix_match};

pub const RUPTA_TOOLCHAIN: &str = "nightly-2024-02-03";
pub const CARGO_PTA_ENV: &str = "QR_CARGO_PTA";

pub fn run_cargo_pta(cargo_pta: &Path, crate_root: &Path) -> Result<String, CpgError> {
    let cargo_pta = cargo_pta.canonicalize().map_err(|e| {
        CpgError::Extraction(format!(
            "cargo-pta not found at {} ({e}); {CARGO_PTA_ENV} must point at the built binary",
            cargo_pta.display()
        ))
    })?;
    let crate_root = crate_root.canonicalize()?;
    let toolchain =
        std::env::var("QR_RUPTA_TOOLCHAIN").unwrap_or_else(|_| RUPTA_TOOLCHAIN.to_string());
    let out_dir = crate_root.join("target").join("qr-rupta");
    std::fs::create_dir_all(&out_dir)?;
    let dot_path = out_dir.join("callgraph.dot");
    let _ = std::fs::remove_file(&dot_path);

    let now = std::time::SystemTime::now();
    for name in ["src/main.rs", "src/lib.rs"] {
        let path = crate_root.join(name);
        if path.is_file() {
            let file = std::fs::File::options().append(true).open(&path)?;
            let _ = file.set_times(std::fs::FileTimes::new().set_modified(now));
        }
    }

    let sysroot = Command::new("rustup")
        .args(["run", &toolchain, "rustc", "--print", "sysroot"])
        .output()?;
    if !sysroot.status.success() {
        return Err(CpgError::Extraction(format!(
            "rustup run {toolchain} rustc --print sysroot failed — is Rupta's toolchain installed?"
        )));
    }
    let sysroot = String::from_utf8_lossy(&sysroot.stdout).trim().to_string();
    let dylib_var = if cfg!(target_os = "macos") {
        "DYLD_FALLBACK_LIBRARY_PATH"
    } else {
        "LD_LIBRARY_PATH"
    };

    let output = Command::new(&cargo_pta)
        .arg("pta")
        .arg("--")
        .arg("--dump-call-graph")
        .arg(&dot_path)
        .current_dir(&crate_root)
        .env_remove("CARGO")
        .env_remove("RUSTC")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_TARGET_DIR")
        .env("RUSTUP_TOOLCHAIN", &toolchain)
        .env(dylib_var, format!("{sysroot}/lib"))
        .output()?;
    if !output.status.success() {
        return Err(CpgError::Extraction(format!(
            "cargo-pta failed on {}:\n{}",
            crate_root.display(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(std::fs::read_to_string(&dot_path)?)
}

pub fn cargo_pta_from_env() -> Option<PathBuf> {
    std::env::var_os(CARGO_PTA_ENV).map(PathBuf::from)
}

pub fn refine_with_dot(dot: &str, cpg: &Cpg) -> CallGraph {
    let mut labels: HashMap<usize, String> = HashMap::new();
    let mut succ: HashMap<usize, Vec<usize>> = HashMap::new();
    for line in dot.lines() {
        let t = line.trim();
        if let Some((a, b)) = parse_edge(t) {
            succ.entry(a).or_default().push(b);
        } else if let Some((idx, label)) = parse_node(t) {
            labels.insert(idx, label.trim().to_string());
        }
    }

    let mut exact: HashMap<String, Vec<u32>> = HashMap::new();
    let mut loose: HashMap<String, Vec<u32>> = HashMap::new();
    for n in cpg
        .nodes()
        .filter(|n| n.layer == IrLayer::Mir && n.kind == NodeKind::Function && n.location.is_some())
    {
        let bare = n.symbol.split_once("::").map(|(_, rest)| rest);
        for key in std::iter::once(n.symbol.as_str()).chain(bare) {
            exact.entry(key.to_string()).or_default().push(n.id);
            loose.entry(strip_generics(key)).or_default().push(n.id);
        }
    }
    let bodies_of = |label: &str| -> Vec<u32> {
        let mut ids = exact
            .get(label)
            .or_else(|| loose.get(&strip_generics(label)))
            .cloned()
            .unwrap_or_default();
        ids.sort_unstable();
        ids.dedup();
        ids
    };

    let mut resolved: HashSet<u32> = HashSet::new();
    let mut contains: Vec<(u32, u32)> = Vec::new();
    for (from, to, kind) in cpg.edges() {
        match kind {
            EdgeKind::TraitResolve => {
                resolved.insert(from);
            }
            EdgeKind::Contains => contains.push((from, to)),
            _ => {}
        }
    }
    let unresolved: HashMap<u32, &cpg_core::CpgNode> = cpg
        .nodes()
        .filter(|n| {
            n.layer == IrLayer::Mir && n.kind == NodeKind::TraitMethod && !resolved.contains(&n.id)
        })
        .map(|n| (n.id, n))
        .collect();
    let mut calls_in: HashMap<u32, Vec<&cpg_core::CpgNode>> = HashMap::new();
    for (body, child) in contains {
        if let Some(call) = unresolved.get(&child) {
            calls_in.entry(body).or_default().push(call);
        }
    }

    let mut edges: Vec<(u32, u32)> = cpg
        .edges()
        .into_iter()
        .filter(|(_, _, kind)| *kind == EdgeKind::Call)
        .map(|(from, to, _)| (from, to))
        .collect();
    for (&caller_idx, callees) in &succ {
        let Some(caller_label) = labels.get(&caller_idx) else {
            continue;
        };
        let calls: Vec<&cpg_core::CpgNode> = bodies_of(caller_label)
            .iter()
            .filter_map(|body| calls_in.get(body))
            .flatten()
            .copied()
            .collect();
        if calls.is_empty() {
            continue;
        }
        for &callee_idx in callees {
            let Some(callee_label) = labels.get(&callee_idx) else {
                continue;
            };
            let answering: Vec<u32> = calls
                .iter()
                .filter(|call| answers(&call.symbol, callee_label))
                .map(|call| call.id)
                .collect();
            if answering.is_empty() {
                continue;
            }
            let targets = analysed_targets(callee_idx, &labels, &succ, &bodies_of);
            for &call in &answering {
                edges.extend(targets.iter().map(|&body| (call, body)));
            }
        }
    }
    edges.retain(|(a, b)| a != b);
    edges.sort_unstable();
    edges.dedup();
    CallGraph { edges }
}

fn answers(call_symbol: &str, callee_label: &str) -> bool {
    let Some((trait_path, method)) = call_key(call_symbol) else {
        return false;
    };
    let fn_family = matches!(
        (trait_path.last().map(String::as_str), method.as_str()),
        (Some("Fn"), "call") | (Some("FnMut"), "call_mut") | (Some("FnOnce"), "call_once")
    );
    if fn_family && callee_label.ends_with('}') && callee_label.contains("{closure") {
        return true;
    }
    if let Some(key) = impl_key(callee_label) {
        return key.method == method && suffix_match(&key.trait_path, &trait_path);
    }
    let mut segs = segments(callee_label);
    segs.pop().is_some_and(|m| m == method) && suffix_match(&segs, &trait_path)
}

fn analysed_targets(
    start: usize,
    labels: &HashMap<usize, String>,
    succ: &HashMap<usize, Vec<usize>>,
    bodies_of: &dyn Fn(&str) -> Vec<u32>,
) -> Vec<u32> {
    let mut out = Vec::new();
    let mut seen: HashSet<usize> = HashSet::from([start]);
    let mut stack = vec![start];
    while let Some(idx) = stack.pop() {
        let bodies = labels.get(&idx).map(|l| bodies_of(l)).unwrap_or_default();
        if !bodies.is_empty() {
            out.extend(bodies);
            continue;
        }
        for &next in succ.get(&idx).into_iter().flatten() {
            if seen.insert(next) {
                stack.push(next);
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn strip_generics(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut depth = 0i32;
    for c in path.chars() {
        match c {
            '<' if out.ends_with(|p: char| p.is_alphanumeric() || p == ':' || p == '_') => {
                depth += 1
            }
            '<' if depth > 0 => depth += 1,
            '>' if depth > 0 => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out.replace("::::", "::")
}

fn parse_edge(line: &str) -> Option<(usize, usize)> {
    let (lhs, rest) = line.split_once("->")?;
    let a: usize = lhs.trim().parse().ok()?;
    let rhs = rest.trim();
    let end = rhs.find(|c: char| !c.is_ascii_digit()).unwrap_or(rhs.len());
    let b: usize = rhs[..end].parse().ok()?;
    Some((a, b))
}

fn parse_node(line: &str) -> Option<(usize, String)> {
    let bracket = line.find('[')?;
    let idx: usize = line[..bracket].trim().parse().ok()?;
    let label_pos = line.find("label")?;
    let open = line[label_pos..].find('"')? + label_pos;
    let close = line[open + 1..].find('"')? + open + 1;
    Some((idx, line[open + 1..close].to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cha::{dispatch_edges, DispatchScope};
    use cpg_core::{AblationMode, SourceLoc};

    fn body(c: &mut Cpg, symbol: &str) -> u32 {
        let n = c.add_node(
            IrLayer::Mir,
            NodeKind::Function,
            symbol,
            Some(SourceLoc::new("src/main.rs", 1)),
        );
        c.node(n).id
    }

    fn dyn_call(c: &mut Cpg, owner: u32, symbol: &str) -> u32 {
        let n = c.add_node(
            IrLayer::Mir,
            NodeKind::TraitMethod,
            symbol,
            Some(SourceLoc::new("src/main.rs", 9)),
        );
        let id = c.node(n).id;
        c.add_edge_by_id(owner, id, EdgeKind::Contains);
        c.add_edge_by_id(owner, id, EdgeKind::Call);
        id
    }

    fn fallback(c: &Cpg) -> Vec<(u32, u32)> {
        let mut e: Vec<(u32, u32)> = c
            .edges()
            .into_iter()
            .filter(|(_, _, k)| *k == EdgeKind::Call)
            .map(|(a, b, _)| (a, b))
            .collect();
        e.sort_unstable();
        e
    }

    fn added(c: &Cpg, dot: &str) -> Vec<(u32, u32)> {
        let base = fallback(c);
        let refined = refine_with_dot(dot, c).edges;
        assert!(
            base.iter().all(|e| refined.contains(e)),
            "a fallback edge was dropped"
        );
        let extra: Vec<(u32, u32)> = refined.into_iter().filter(|e| !base.contains(e)).collect();
        let cha = dispatch_edges(c, DispatchScope::AllUnresolved);
        assert!(
            extra.iter().all(|e| cha.contains(e)),
            "Rupta added an edge outside the class-hierarchy bound: {extra:?} vs {cha:?}"
        );
        extra
    }

    #[test]
    fn static_calls_keep_the_fallback_and_add_nothing() {
        let mut c = Cpg::new(AblationMode::MirOnly);
        let main = body(&mut c, "demo_crate::main");
        let swr = body(&mut c, "demo_crate::sign_with_rsa");
        c.add_edge_by_id(main, swr, EdgeKind::Call);
        let dot = r#"digraph {
    0 [ label = "main" ]
    1 [ label = "sign_with_rsa" ]
    2 [ label = "rsa::RsaPrivateKey::new" ]
    0 -> 1 [ label = "bb3[0]" ]
    1 -> 2 [ label = "bb1[0]" ]
}"#;
        assert_eq!(refine_with_dot(dot, &c).edges, fallback(&c));
    }

    #[test]
    fn a_dyn_call_reaches_the_impl_rupta_names_and_no_other() {
        let mut c = Cpg::new(AblationMode::MirOnly);
        let main = body(&mut c, "demo_crate::main");
        let call = dyn_call(&mut c, main, "<dyn Signer>::sign");
        let _a = body(&mut c, "demo_crate::<A as Signer>::sign");
        let b = body(&mut c, "demo_crate::<B as Signer>::sign");
        let dot = r#"digraph {
    0 [ label = "main" ]
    1 [ label = "<B as Signer>::sign" ]
    0 -> 1 [ label = "bb2[0]" ]
}"#;
        assert_eq!(added(&c, dot), [(call, b)]);
    }

    #[test]
    fn an_edge_is_anchored_in_its_own_caller() {
        let mut c = Cpg::new(AblationMode::MirOnly);
        let f = body(&mut c, "demo_crate::f");
        let g = body(&mut c, "demo_crate::g");
        let in_f = dyn_call(&mut c, f, "<dyn Signer>::sign");
        let in_g = dyn_call(&mut c, g, "<dyn Signer>::sign");
        let b = body(&mut c, "demo_crate::<B as Signer>::sign");
        let dot = r#"digraph {
    0 [ label = "g" ]
    1 [ label = "<B as Signer>::sign" ]
    0 -> 1 [ label = "bb0[0]" ]
}"#;
        let extra = added(&c, dot);
        assert_eq!(extra, [(in_g, b)]);
        assert!(!extra.iter().any(|&(call, _)| call == in_f));
    }

    #[test]
    fn a_callback_through_a_dependency_reaches_the_local_body() {
        let mut c = Cpg::new(AblationMode::MirOnly);
        let main = body(&mut c, "demo_crate::main");
        let call = dyn_call(&mut c, main, "<dyn std::io::Write>::write_all");
        let write = body(&mut c, "demo_crate::<Sink<W> as std::io::Write>::write");
        let dot = r#"digraph {
    0 [ label = "main" ]
    1 [ label = "std::io::Write::write_all" ]
    2 [ label = "<Sink<std::vec::Vec<u8>> as std::io::Write>::write" ]
    3 [ label = "std::io::Error::new" ]
    0 -> 1 [ label = "bb5[0]" ]
    1 -> 2 [ label = "bb2[0]" ]
    1 -> 3 [ label = "bb4[0]" ]
}"#;
        assert_eq!(added(&c, dot), [(call, write)]);
    }

    #[test]
    fn a_callee_of_another_trait_does_not_answer_the_call() {
        let mut c = Cpg::new(AblationMode::MirOnly);
        let main = body(&mut c, "demo_crate::main");
        dyn_call(&mut c, main, "<dyn Signer>::sign");
        body(&mut c, "demo_crate::<B as Other>::sign");
        let dot = r#"digraph {
    0 [ label = "main" ]
    1 [ label = "<B as Other>::sign" ]
    0 -> 1 [ ]
}"#;
        assert!(added(&c, dot).is_empty());
    }

    #[test]
    fn an_unknown_label_maps_nothing_rather_than_guessing() {
        let mut c = Cpg::new(AblationMode::MirOnly);
        let main = body(&mut c, "demo_crate::main");
        dyn_call(&mut c, main, "<dyn Signer>::sign");
        let dot = r#"digraph {
    0 [ label = "main" ]
    1 [ label = "some::crate::not_in_the_cpg" ]
    0 -> 1 [ ]
}"#;
        assert!(added(&c, dot).is_empty());
    }

    #[test]
    fn generic_arguments_are_dropped_only_where_they_are_arguments() {
        assert_eq!(
            strip_generics("<Sink<std::vec::Vec<u8>> as std::io::Write>::write"),
            "<Sink as std::io::Write>::write"
        );
        assert_eq!(
            strip_generics("std::fmt::Arguments::<'a>::new_const"),
            "std::fmt::Arguments::new_const"
        );
    }
}
