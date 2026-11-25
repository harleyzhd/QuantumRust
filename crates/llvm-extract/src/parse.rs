use cpg_core::{AblationMode, Cpg, EdgeKind, IrLayer, NodeKind, SafetyCtx};
use rustc_demangle::try_demangle;

use crate::dataflow::{load_pointer, memcpy_operands, split_assignment, sret_slot, Origins};
use crate::debug::{dbg_ref, DebugInfo};

pub fn parse_ll(text: &str, local_crate: &str) -> Cpg {
    parse_ll_with(text, local_crate, &|_| false)
}

pub fn parse_ll_with(text: &str, local_crate: &str, lift: &dyn Fn(&str) -> bool) -> Cpg {
    let mut cpg = Cpg::new(AblationMode::LlvmOnly);
    let mut current_fn: Option<cpg_core::NodeIndex> = None;
    let mut in_foreign_fn = false;
    let mut functions: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let mut pending: Vec<(u32, String)> = Vec::new();
    let mut origins = Origins::default();
    let debug = DebugInfo::parse(text);
    let lines: Vec<&str> = text.lines().collect();
    let locate = |at: usize| dbg_ref(&lines, at).and_then(|id| debug.location(id));

    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();

        if trimmed.starts_with("define ") {
            if let Some(symbol) = defined_symbol(trimmed) {
                let demangled = demangle(&symbol);
                if crate_root(&demangled) != local_crate && !lift(&demangled) {
                    in_foreign_fn = true;
                    continue;
                }
                in_foreign_fn = false;
                let node = cpg.add_node_full(
                    IrLayer::Llvm,
                    NodeKind::Function,
                    demangled.clone(),
                    Some(demangled.clone()),
                    locate(index),
                    SafetyCtx::Safe,
                );
                functions.entry(demangled).or_insert(cpg.node(node).id);
                origins.clear();
                current_fn = Some(node);
            }
            continue;
        }
        if trimmed == "}" {
            current_fn = None;
            in_foreign_fn = false;
            continue;
        }
        if in_foreign_fn {
            continue;
        }
        let Some(fn_node) = current_fn else {
            continue;
        };
        let (dst, rhs) = split_assignment(trimmed);

        let made = match callee_of(trimmed) {
            Some(Callee::Direct(symbol)) if !is_noise(&symbol) => {
                let demangled = demangle(&symbol);
                let (kind, safety) = if demangled == symbol {
                    (NodeKind::FfiBoundary, SafetyCtx::Ffi)
                } else {
                    (NodeKind::CallSite, SafetyCtx::Safe)
                };
                let is_call = kind == NodeKind::CallSite;
                let node = cpg.add_node_full(
                    IrLayer::Llvm,
                    kind,
                    demangled.clone(),
                    Some(demangled.clone()),
                    locate(index),
                    safety,
                );
                if is_call {
                    cpg.set_type_args(node, crate::symbol_types::type_args(&demangled));
                }
                cpg.add_edge(fn_node, node, EdgeKind::Contains);
                cpg.add_edge(fn_node, node, EdgeKind::Call);
                pending.push((cpg.node(node).id, demangled));
                Some(cpg.node(node).id)
            }
            Some(Callee::Indirect(reg)) => {
                let node = cpg.add_node(
                    IrLayer::Llvm,
                    NodeKind::Vtable,
                    format!("<indirect {reg}>"),
                    locate(index),
                );
                cpg.add_edge(fn_node, node, EdgeKind::Contains);
                cpg.add_edge(fn_node, node, EdgeKind::Call);
                Some(cpg.node(node).id)
            }
            _ => None,
        };

        let sources = origins.behind(rhs);
        match made {
            Some(node) => {
                for source in sources {
                    if source != node {
                        cpg.add_edge_by_id(source, node, EdgeKind::DataDep);
                    }
                }
                if let Some(dst) = dst {
                    origins.produced_by(dst, node);
                }
                if let Some(slot) = sret_slot(rhs) {
                    origins.produced_by(slot, node);
                }
            }
            None => {
                if let Some((dst_slot, src_slot)) = memcpy_operands(rhs) {
                    let carried = origins.of(src_slot).to_vec();
                    if !carried.is_empty() {
                        origins.derived_from(dst_slot, carried);
                    }
                } else if let Some(dst) = dst {
                    if let Some(slot) = load_pointer(rhs) {
                        origins.derived_from(dst, origins.of(slot).to_vec());
                    } else {
                        origins.derived_from(dst, sources);
                    }
                }
            }
        }
    }

    link_callees(&mut cpg, &functions, &pending);
    cpg
}

pub fn descend_ll(text: &str, local_crate: &str, plan: &cpg_core::DescentPlan) -> Cpg {
    let allowed = |s: &str| plan.crates.contains(crate_root(s));
    let wide = parse_ll_with(text, local_crate, &allowed);
    let depths = reachable_depths(&wide, local_crate, plan.depth);
    let mut cpg = parse_ll_with(text, local_crate, &|s: &str| depths.contains_key(s));
    let contains: Vec<(u32, u32)> = cpg
        .edges()
        .into_iter()
        .filter(|(_, _, k)| *k == EdgeKind::Contains)
        .map(|(a, b, _)| (a, b))
        .collect();
    let marks: Vec<(u32, u8)> = cpg
        .nodes()
        .filter(|n| n.kind == NodeKind::Function)
        .filter_map(|n| Some((n.id, *depths.get(n.symbol.as_str())?)))
        .collect();
    for (function, depth) in marks {
        let inside = contains
            .iter()
            .filter(|(a, _)| *a == function)
            .map(|(_, b)| *b);
        for id in std::iter::once(function).chain(inside) {
            if let Some(index) = cpg.index_of_id(id) {
                cpg.set_dep_depth(index, depth);
            }
        }
    }
    cpg
}

fn reachable_depths(
    cpg: &Cpg,
    local_crate: &str,
    cap: u8,
) -> std::collections::HashMap<String, u8> {
    use std::collections::{HashMap, HashSet, VecDeque};
    let symbol: HashMap<u32, &str> = cpg.nodes().map(|n| (n.id, n.symbol.as_str())).collect();
    let is_fn: HashSet<u32> = cpg
        .nodes()
        .filter(|n| n.kind == NodeKind::Function)
        .map(|n| n.id)
        .collect();
    let mut calls: HashMap<u32, Vec<u32>> = HashMap::new();
    for (a, b, k) in cpg.edges() {
        if k == EdgeKind::Call {
            calls.entry(a).or_default().push(b);
        }
    }
    let mut queue: VecDeque<(u32, u8)> = cpg
        .nodes()
        .filter(|n| n.kind == NodeKind::Function && crate_root(&n.symbol) == local_crate)
        .map(|n| (n.id, 0))
        .collect();
    let mut seen: HashSet<u32> = queue.iter().map(|(id, _)| *id).collect();
    let mut depth: HashMap<String, u8> = HashMap::new();
    while let Some((node, d)) = queue.pop_front() {
        for &next in calls.get(&node).into_iter().flatten() {
            let nd = if is_fn.contains(&next) { d + 1 } else { d };
            if nd > cap || !seen.insert(next) {
                continue;
            }
            if is_fn.contains(&next) {
                depth.insert(symbol[&next].to_string(), nd);
            }
            queue.push_back((next, nd));
        }
    }
    depth
}

fn link_callees(
    cpg: &mut Cpg,
    functions: &std::collections::HashMap<String, u32>,
    pending: &[(u32, String)],
) {
    for (call, symbol) in pending {
        let Some(&callee) = functions.get(symbol) else {
            continue;
        };
        if callee != *call {
            cpg.add_edge_by_id(*call, callee, EdgeKind::Call);
        }
    }
}

enum Callee {
    Direct(String),
    Indirect(String),
}

fn defined_symbol(line: &str) -> Option<String> {
    let at = line.find('@')?;
    read_symbol(&line[at..])
}

fn callee_of(line: &str) -> Option<Callee> {
    let pos = find_call_keyword(line)?;
    let rest = &line[pos..];
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '@' || c == '%' {
            if let Some(symbol) = read_symbol(&rest[i..]) {
                let end = i + 1 + raw_len(&rest[i + 1..], &symbol);
                if bytes.get(end) == Some(&b'(') {
                    return Some(if c == '@' {
                        Callee::Direct(symbol)
                    } else {
                        Callee::Indirect(format!("%{symbol}"))
                    });
                }
            }
        }
        i += 1;
    }
    None
}

fn find_call_keyword(line: &str) -> Option<usize> {
    for keyword in ["invoke ", "call "] {
        let mut from = 0;
        while let Some(rel) = line[from..].find(keyword) {
            let pos = from + rel;
            let boundary =
                pos == 0 || line.as_bytes()[pos - 1] == b' ' || line.as_bytes()[pos - 1] == b'\t';
            if boundary {
                return Some(pos + keyword.len());
            }
            from = pos + keyword.len();
        }
    }
    None
}

fn read_symbol(s: &str) -> Option<String> {
    let rest = &s[1..];
    if let Some(quoted) = rest.strip_prefix('"') {
        let end = quoted.find('"')?;
        return Some(quoted[..end].to_string());
    }
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '$')))
        .unwrap_or(rest.len());
    (end > 0).then(|| rest[..end].to_string())
}

fn raw_len(raw: &str, symbol: &str) -> usize {
    if raw.starts_with('"') {
        symbol.len() + 2
    } else {
        symbol.len()
    }
}

fn is_noise(symbol: &str) -> bool {
    symbol.starts_with("llvm.")
        || symbol.starts_with("__rust")
        || symbol.starts_with("rust_")
        || symbol.starts_with("_Unwind")
}

fn demangle(symbol: &str) -> String {
    match try_demangle(symbol) {
        Ok(d) => format!("{d:#}"),
        Err(_) => symbol.to_string(),
    }
}

fn crate_root(demangled: &str) -> &str {
    let start = demangled.trim_start_matches('<');
    start.split("::").next().unwrap_or(start)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESCENT: &str = r#"
define void @_ZN3app6target17h0000000000000001E() {
  call void @_ZN5vault11digest_with17h0000000000000002E()
  ret void
}
define void @_ZN5vault11digest_with17h0000000000000002E() {
  call void @_ZN4sha26digest17h0000000000000003E()
  call void @_ZN5vault5inner17h0000000000000005E()
  ret void
}
define void @_ZN5vault5inner17h0000000000000005E() {
  ret void
}
define void @_ZN5vault6orphan17h0000000000000004E() {
  call void @_ZN4sha26digest17h0000000000000003E()
  ret void
}
define void @_ZN4sha26digest17h0000000000000003E() {
  ret void
}
"#;

    #[test]
    fn descent_lifts_reachable_dependency_functions_only() {
        let plan = cpg_core::DescentPlan {
            depth: 3,
            crates: ["vault".to_string()].into(),
        };
        let cpg = descend_ll(DESCENT, "app", &plan);
        let depth = |name: &str| {
            cpg.nodes()
                .find(|n| n.kind == NodeKind::Function && n.symbol.ends_with(name))
                .map(|n| n.dep_depth)
        };
        assert_eq!(depth("target"), Some(None));
        assert_eq!(depth("digest_with"), Some(Some(1)));
        assert_eq!(depth("inner"), Some(Some(2)));
        assert_eq!(depth("orphan"), None, "never called from local code");
        assert_eq!(
            depth("sha2::digest"),
            None,
            "a crypto crate is never lifted"
        );
        assert!(cpg
            .nodes()
            .any(|n| n.kind == NodeKind::CallSite && n.symbol.ends_with("sha2::digest")));

        let shallow = descend_ll(DESCENT, "app", &cpg_core::DescentPlan { depth: 1, ..plan });
        assert!(!shallow
            .nodes()
            .any(|n| n.kind == NodeKind::Function && n.symbol.ends_with("inner")));
    }

    #[test]
    fn without_descent_parsing_is_unchanged() {
        let a = parse_ll(SAMPLE, "demo_crate");
        let b = parse_ll_with(SAMPLE, "demo_crate", &|_| false);
        let symbols = |c: &Cpg| {
            c.nodes()
                .map(|n| (n.symbol.clone(), n.dep_depth))
                .collect::<Vec<_>>()
        };
        assert_eq!(symbols(&a), symbols(&b));
        assert_eq!(a.edges(), b.edges());
    }

    const SAMPLE: &str = r#"
define internal void @_ZN10demo_crate13sign_with_rsa17h0123456789abcdefE(ptr %msg) unnamed_addr #1 {
start:
  %0 = call i32 @RSA_sign(i32 672, ptr %m, i32 %len, ptr %sig, ptr %sl, ptr null)
  %1 = call void @llvm.dbg.value(metadata i32 %0)
  call void (ptr, ...) @printf(ptr @fmt)
  ret void
}

define void @_ZN10demo_crate10use_signer17hfedcba9876543210E(ptr %self) {
start:
  %vtable = load ptr, ptr %self
  %fnptr = load ptr, ptr %vtable
  %2 = call ptr %fnptr(ptr %self, ptr %msg)
  ret void
}

define void @_ZN3rsa8internal17h1111111111111111E() {
start:
  %0 = call i32 @foreign_helper(i32 1)
  ret void
}
"#;

    const LOCAL_CALL: &str = r#"
define void @_ZN10demo_crate6caller17h0000000000000001E() {
start:
  %0 = call i32 @_ZN10demo_crate6callee17h0000000000000002E()
  %1 = call i32 @RSA_sign(i32 672)
  ret void
}

define i32 @_ZN10demo_crate6callee17h0000000000000002E() {
start:
  %0 = call i32 @_ZN10demo_crate6callee17h0000000000000002E()
  ret i32 0
}
"#;

    fn call_edges(cpg: &Cpg) -> Vec<String> {
        let name = |id: u32| {
            cpg.nodes()
                .find(|n| n.id == id)
                .map(|n| n.symbol.clone())
                .unwrap_or_default()
        };
        cpg.edges()
            .into_iter()
            .filter(|(_, _, k)| *k == EdgeKind::Call)
            .map(|(s, t, _)| format!("{} -> {}", name(s), name(t)))
            .collect()
    }

    const FLOWS: &str = r#"
define void @_ZN10demo_crate4main17h0000000000000001E() {
start:
  %key = call ptr @_ZN3rsa13RsaPrivateKey3new17h0000000000000002E(i32 2048)
  %ptr = getelementptr inbounds i8, ptr %key, i64 0
  %cast = bitcast ptr %ptr to ptr
  %sig = call i32 @RSA_sign(i32 672, ptr %cast)
  ret void
}
"#;

    const SRET_CHAIN: &str = r#"
define void @_ZN10demo_crate4main17h0000000000000003E() {
start:
  %_4 = alloca [344 x i8], align 8
  %key = alloca [344 x i8], align 8
  invoke void @_ZN3rsa13RsaPrivateKey3new17h0000000000000002E(ptr sret([344 x i8]) align 8 %_4, i64 2048)
          to label %bb2 unwind label %cleanup
bb2:
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %key, ptr align 8 %_4, i64 344, i1 false)
  %loaded = load ptr, ptr %key, align 8
  %sig = call i32 @RSA_sign(i32 672, ptr %loaded)
  ret void
}
"#;

    const THROUGH_MEMORY: &str = r#"
define void @_ZN10demo_crate4main17h0000000000000004E() {
start:
  %slot = alloca ptr, align 8
  %key = call ptr @_ZN3rsa13RsaPrivateKey3new17h0000000000000002E(i32 2048)
  store ptr %key, ptr %slot, align 8
  %other = load ptr, ptr %slot, align 8
  %sig = call i32 @RSA_sign(i32 672, ptr %other)
  ret void
}
"#;

    fn dep_edges(cpg: &Cpg) -> Vec<String> {
        let name = |id: u32| {
            cpg.nodes()
                .find(|n| n.id == id)
                .map(|n| n.symbol.clone())
                .unwrap_or_default()
        };
        cpg.edges()
            .into_iter()
            .filter(|(_, _, k)| *k == EdgeKind::DataDep)
            .map(|(s, t, _)| format!("{} -> {}", name(s), name(t)))
            .collect()
    }

    const KEY_TO_SINK: &str = "rsa::RsaPrivateKey::new -> RSA_sign";

    #[test]
    fn a_value_flows_from_the_call_that_made_it_to_the_call_that_uses_it() {
        let edges = dep_edges(&parse_ll(FLOWS, "demo_crate"));
        assert!(
            edges.contains(&KEY_TO_SINK.to_string()),
            "key material should reach the FFI sink through getelementptr and \
             bitcast, but the edges were {edges:#?}"
        );
    }

    #[test]
    fn an_sret_return_reaches_its_sink_through_memcpy_and_load() {
        let edges = dep_edges(&parse_ll(SRET_CHAIN, "demo_crate"));
        assert!(
            edges.contains(&KEY_TO_SINK.to_string()),
            "the sret slot chain should reach the sink, but the edges were {edges:#?}"
        );
    }

    #[test]
    fn a_pointer_stored_into_memory_is_not_tracked_back_out() {
        let edges = dep_edges(&parse_ll(THROUGH_MEMORY, "demo_crate"));
        assert!(
            !edges.contains(&KEY_TO_SINK.to_string()),
            "a store/load round trip needs a memory model: {edges:#?}"
        );
    }

    #[test]
    fn registers_do_not_leak_between_function_bodies() {
        let two = r#"
define void @_ZN10demo_crate1a17h0000000000000001E() {
start:
  %0 = call ptr @_ZN3rsa13RsaPrivateKey3new17h0000000000000002E(i32 2048)
  ret void
}

define void @_ZN10demo_crate1b17h0000000000000003E() {
start:
  %1 = call i32 @RSA_sign(i32 672, ptr %0)
  ret void
}
"#;
        let edges = dep_edges(&parse_ll(two, "demo_crate"));
        assert!(
            edges.is_empty(),
            "%0 in the second body is a different register: {edges:#?}"
        );
    }

    #[test]
    fn a_call_site_links_to_the_body_it_targets() {
        let edges = call_edges(&parse_ll(LOCAL_CALL, "demo_crate"));
        assert!(
            edges.contains(&"demo_crate::callee -> demo_crate::callee".to_string()),
            "call site to callee body missing from {edges:#?}"
        );
        assert!(
            edges.contains(&"demo_crate::caller -> demo_crate::callee".to_string()),
            "fn to call-site edge lost from {edges:#?}"
        );
    }

    #[test]
    fn a_call_with_no_local_body_links_to_nothing() {
        let cpg = parse_ll(LOCAL_CALL, "demo_crate");
        let ffi = cpg
            .nodes()
            .find(|n| n.symbol == "RSA_sign")
            .expect("FFI node");
        assert!(
            !cpg.edges()
                .iter()
                .any(|(s, _, k)| *s == ffi.id && *k == EdgeKind::Call),
            "an unresolvable callee must not acquire an outgoing Call edge"
        );
    }

    #[test]
    fn a_recursive_call_does_not_self_loop() {
        let cpg = parse_ll(LOCAL_CALL, "demo_crate");
        let body = cpg
            .nodes()
            .find(|n| n.symbol == "demo_crate::callee" && n.kind == NodeKind::Function)
            .expect("callee body");
        assert!(
            !cpg.edges()
                .iter()
                .any(|(s, t, _)| *s == body.id && *t == body.id),
            "self-loop on the recursive body"
        );
    }

    #[test]
    fn parses_functions_and_calls() {
        let cpg = parse_ll(SAMPLE, "demo_crate");
        assert!(cpg.nodes().all(|n| n.layer == IrLayer::Llvm));
        assert!(cpg
            .nodes()
            .any(|n| n.kind == NodeKind::Function && n.symbol == "demo_crate::sign_with_rsa"));
        assert!(cpg
            .nodes()
            .any(|n| n.kind == NodeKind::Function && n.symbol == "demo_crate::use_signer"));
    }

    #[test]
    fn ffi_call_kept_with_ffi_ctx() {
        let cpg = parse_ll(SAMPLE, "demo_crate");
        let ffi = cpg.nodes().find(|n| n.symbol == "RSA_sign").unwrap();
        assert_eq!(ffi.kind, NodeKind::FfiBoundary);
        assert_eq!(ffi.safety_ctx, SafetyCtx::Ffi);
    }

    #[test]
    fn indirect_call_becomes_vtable_node() {
        let cpg = parse_ll(SAMPLE, "demo_crate");
        assert!(cpg
            .nodes()
            .any(|n| n.kind == NodeKind::Vtable && n.symbol.contains("%fnptr")));
    }

    #[test]
    fn intrinsics_are_skipped_varargs_are_not() {
        let cpg = parse_ll(SAMPLE, "demo_crate");
        assert!(!cpg.nodes().any(|n| n.symbol.contains("llvm.dbg")));
        assert!(cpg.nodes().any(|n| n.symbol == "printf"));
    }

    #[test]
    fn foreign_crate_monomorphisations_are_skipped() {
        let cpg = parse_ll(SAMPLE, "demo_crate");
        assert!(!cpg.nodes().any(|n| n.symbol.contains("rsa::internal")));
        assert!(!cpg.nodes().any(|n| n.symbol.contains("foreign_helper")));
    }
}
