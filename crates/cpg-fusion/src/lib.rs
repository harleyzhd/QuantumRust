use std::collections::HashMap;

use cpg_core::{AblationMode, Cpg, EdgeKind, IrLayer, NodeKind};

pub fn fuse(mir: &Cpg, llvm: &Cpg, mode: AblationMode) -> Cpg {
    let mut out = Cpg::new(mode);

    if mode.keeps(IrLayer::Mir) {
        copy_layer(mir, IrLayer::Mir, &mut out);
    }
    if mode.keeps(IrLayer::Llvm) {
        copy_layer(llvm, IrLayer::Llvm, &mut out);
    }
    out
}

pub fn infer_cross_layer_refs(cpg: &mut Cpg) -> usize {
    let mut mir_fns: HashMap<String, Vec<u32>> = HashMap::new();
    let mut llvm_fns: HashMap<String, Vec<u32>> = HashMap::new();
    let mut kind_of: HashMap<u32, (IrLayer, NodeKind)> = HashMap::new();
    for n in cpg.nodes() {
        kind_of.insert(n.id, (n.layer, n.kind.clone()));
        if n.kind == NodeKind::Function {
            match n.layer {
                IrLayer::Mir => mir_fns.entry(n.symbol.clone()).or_default().push(n.id),
                IrLayer::Llvm => llvm_fns.entry(n.symbol.clone()).or_default().push(n.id),
            }
        }
    }
    let mut contains: HashMap<u32, Vec<u32>> = HashMap::new();
    for (s, t, k) in cpg.edges() {
        if k == EdgeKind::Contains {
            contains.entry(s).or_default().push(t);
        }
    }

    let children_of_kind = |contains: &HashMap<u32, Vec<u32>>, id: &u32, want: NodeKind| {
        contains
            .get(id)
            .into_iter()
            .flatten()
            .filter(|c| kind_of.get(c).is_some_and(|(_, k)| *k == want))
            .copied()
            .collect::<Vec<u32>>()
    };

    let mut identity: HashMap<u32, CallIdentity> = HashMap::new();
    for node in cpg.nodes().filter(|n| is_call_shaped(&n.kind)) {
        identity.insert(
            node.id,
            CallIdentity {
                segments: segments(&node.symbol),
                canonical: node.canonical.clone(),
            },
        );
    }

    let mut added = 0;
    let pairs = mir_fns.iter().flat_map(|(symbol, mir_ids)| {
        let llvm_ids = llvm_fns.get(symbol).map(Vec::as_slice).unwrap_or(&[]);
        mir_ids
            .iter()
            .flat_map(move |m| llvm_ids.iter().map(move |l| (m, l)))
    });
    for (mir_id, llvm_id) in pairs {
        if cpg.add_edge_by_id(*mir_id, *llvm_id, EdgeKind::CrossLayerRef) {
            added += 1;
        }
        let trait_methods = children_of_kind(&contains, mir_id, NodeKind::TraitMethod);
        let vtables = children_of_kind(&contains, llvm_id, NodeKind::Vtable);
        for tm in &trait_methods {
            for vt in &vtables {
                if cpg.add_edge_by_id(*tm, *vt, EdgeKind::CrossLayerRef) {
                    added += 1;
                }
            }
        }

        added += link_call_sites(cpg, &contains, &kind_of, &identity, *mir_id, *llvm_id);
    }
    added
}

struct CallIdentity {
    segments: Vec<String>,
    canonical: Option<String>,
}

fn is_call_shaped(kind: &NodeKind) -> bool {
    matches!(
        kind,
        NodeKind::CallSite | NodeKind::TraitMethod | NodeKind::FfiBoundary
    )
}

fn link_call_sites(
    cpg: &mut Cpg,
    contains: &HashMap<u32, Vec<u32>>,
    kind_of: &HashMap<u32, (IrLayer, NodeKind)>,
    identity: &HashMap<u32, CallIdentity>,
    mir_fn: u32,
    llvm_fn: u32,
) -> usize {
    let children = |id: u32| -> Vec<u32> {
        contains
            .get(&id)
            .into_iter()
            .flatten()
            .filter(|c| kind_of.get(c).is_some_and(|(_, k)| is_call_shaped(k)))
            .copied()
            .collect()
    };
    let llvm_calls = children(llvm_fn);
    let mut added = 0;
    for mir_call in children(mir_fn) {
        for &llvm_call in &llvm_calls {
            let paired = match (
                identity.get(&mir_call).and_then(|i| i.canonical.as_deref()),
                identity
                    .get(&llvm_call)
                    .and_then(|i| i.canonical.as_deref()),
            ) {
                (Some(mir), Some(llvm)) => mir == llvm,
                _ => match (identity.get(&mir_call), identity.get(&llvm_call)) {
                    (Some(a), Some(b)) => same_api(&a.segments, &b.segments),
                    _ => false,
                },
            };
            if paired && cpg.add_edge_by_id(mir_call, llvm_call, EdgeKind::CrossLayerRef) {
                added += 1;
            }
        }
    }
    added
}

fn same_api(a: &[String], b: &[String]) -> bool {
    let (Some(a_method), Some(b_method)) = (a.last(), b.last()) else {
        return false;
    };
    if a_method != b_method {
        return false;
    }
    let owner = |segments: &[String]| segments.len().checked_sub(2).map(|i| segments[i].clone());
    match (owner(a), owner(b)) {
        (None, _) | (_, None) => true,
        (Some(x), Some(y)) => b.contains(&x) || a.contains(&y),
    }
}

fn segments(symbol: &str) -> Vec<String> {
    let symbol = symbol.trim();
    let unwrapped = match symbol.strip_prefix('<') {
        Some(rest) => match matching_gt(rest) {
            Some(end) => format!("{}::{}", &rest[..end], &rest[end + 1..]),
            None => symbol.to_string(),
        },
        None => symbol.to_string(),
    };

    let mut flat = String::with_capacity(unwrapped.len());
    let mut depth = 0usize;
    for c in unwrapped.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => flat.push(c),
            _ => {}
        }
    }

    flat.replace(" as ", "::")
        .split("::")
        .map(|s| {
            s.trim_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .to_ascii_lowercase()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

fn matching_gt(s: &str) -> Option<usize> {
    let mut depth = 1usize;
    for (i, c) in s.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

fn copy_layer(src: &Cpg, layer: IrLayer, out: &mut Cpg) {
    let mut id_map: HashMap<u32, _> = HashMap::new();
    for node in src.nodes().filter(|n| n.layer == layer) {
        let idx = out.copy_node(node);
        id_map.insert(node.id, idx);
    }
    for (s, t, edge) in src.edges_full() {
        if let (Some(&a), Some(&b)) = (id_map.get(&s), id_map.get(&t)) {
            out.add_edge_full(a, b, edge);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpg_core::{NodeKind, SourceLoc};

    fn mir_only() -> Cpg {
        let mut c = Cpg::new(AblationMode::Dual);
        let f = c.add_node(
            IrLayer::Mir,
            NodeKind::Function,
            "a::f",
            Some(SourceLoc::new("a.rs", 1)),
        );
        let g = c.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            "a::g",
            Some(SourceLoc::new("a.rs", 2)),
        );
        c.add_edge(f, g, cpg_core::EdgeKind::Call);
        c
    }

    fn llvm_only() -> Cpg {
        let mut c = Cpg::new(AblationMode::Dual);
        c.add_node_with_ctx(
            IrLayer::Llvm,
            NodeKind::FfiBoundary,
            "sys::ffi_sink",
            None,
            cpg_core::SafetyCtx::Ffi,
        );
        c
    }

    #[test]
    fn fusion_preserves_safety_ctx() {
        let fused = fuse(&mir_only(), &llvm_only(), AblationMode::Dual);
        let ffi = fused.nodes().find(|n| n.symbol == "sys::ffi_sink").unwrap();
        assert_eq!(ffi.safety_ctx, cpg_core::SafetyCtx::Ffi);
    }

    #[test]
    fn infers_cross_layer_refs() {
        let mut mir = Cpg::new(AblationMode::Dual);
        let f = mir.add_node(IrLayer::Mir, NodeKind::Function, "a::f", None);
        let tm = mir.add_node(
            IrLayer::Mir,
            NodeKind::TraitMethod,
            "<dyn a::Signer>::sign",
            None,
        );
        mir.add_edge(f, tm, cpg_core::EdgeKind::Contains);

        let mut llvm = Cpg::new(AblationMode::Dual);
        let f2 = llvm.add_node(IrLayer::Llvm, NodeKind::Function, "a::f", None);
        let vt = llvm.add_node(IrLayer::Llvm, NodeKind::Vtable, "<indirect %3>", None);
        llvm.add_edge(f2, vt, cpg_core::EdgeKind::Contains);

        let mut fused = fuse(&mir, &llvm, AblationMode::Dual);
        let added = infer_cross_layer_refs(&mut fused);
        assert_eq!(added, 2, "fn<->fn and trait-method->vtable");
        let cross: Vec<_> = fused
            .edges()
            .into_iter()
            .filter(|(_, _, k)| *k == cpg_core::EdgeKind::CrossLayerRef)
            .collect();
        assert_eq!(cross.len(), 2);
    }

    #[test]
    fn fusion_preserves_canonical() {
        let mut mir = Cpg::new(AblationMode::Dual);
        mir.add_node_full(
            IrLayer::Mir,
            NodeKind::CallSite,
            "rsa::RsaPrivateKey::new",
            Some("<rsa::key::RsaPrivateKey>::new".to_string()),
            None,
            cpg_core::SafetyCtx::Safe,
        );
        let fused = fuse(&mir, &Cpg::new(AblationMode::Dual), AblationMode::Dual);
        assert_eq!(
            fused.nodes().next().unwrap().canonical.as_deref(),
            Some("<rsa::key::RsaPrivateKey>::new")
        );
    }

    fn cross_layer_pair(mir_key: &str, llvm_key: &str) -> usize {
        let mut mir = Cpg::new(AblationMode::Dual);
        let f = mir.add_node(IrLayer::Mir, NodeKind::Function, "a::f", None);
        let call = mir.add_node_full(
            IrLayer::Mir,
            NodeKind::CallSite,
            "a::Type::new",
            Some(mir_key.to_string()),
            None,
            cpg_core::SafetyCtx::Safe,
        );
        mir.add_edge(f, call, cpg_core::EdgeKind::Contains);

        let mut llvm = Cpg::new(AblationMode::Dual);
        let f2 = llvm.add_node(IrLayer::Llvm, NodeKind::Function, "a::f", None);
        let call2 = llvm.add_node_full(
            IrLayer::Llvm,
            NodeKind::CallSite,
            "a::Type::new",
            Some(llvm_key.to_string()),
            None,
            cpg_core::SafetyCtx::Safe,
        );
        llvm.add_edge(f2, call2, cpg_core::EdgeKind::Contains);

        let mut fused = fuse(&mir, &llvm, AblationMode::Dual);
        infer_cross_layer_refs(&mut fused);
        fused
            .edges()
            .into_iter()
            .filter(|(_, _, k)| *k == cpg_core::EdgeKind::CrossLayerRef)
            .count()
    }

    #[test]
    fn identical_canonical_keys_pair() {
        assert_eq!(
            cross_layer_pair("a::one::Type::new", "a::one::Type::new"),
            2
        );
    }

    #[test]
    fn differing_canonical_keys_do_not_pair_however_alike_they_read() {
        assert_eq!(
            cross_layer_pair("a::one::Type::new", "a::other::Type::new"),
            1,
            "only fn<->fn; these are different APIs"
        );
    }

    #[test]
    fn segments_bridge_the_two_renderings() {
        assert!(same_api(
            &segments("rsa::RsaPrivateKey::new"),
            &segments("<rsa::key::RsaPrivateKey>::new::<rand::rngs::thread::ThreadRng>")
        ));
        assert!(same_api(
            &segments("rsa::signature::RandomizedSigner::sign_with_rng"),
            &segments(
                "<rsa::pkcs1v15::signing_key::SigningKey<sha2::Sha256> as \
                 signature::signer::RandomizedSigner<rsa::pkcs1v15::signature::Signature>>\
                 ::sign_with_rng::<rand::rngs::thread::ThreadRng>"
            )
        ));
        assert!(same_api(
            &segments("openssl_sys::RSA_sign"),
            &segments("RSA_sign")
        ));
    }

    #[test]
    fn two_new_calls_in_one_body_do_not_pair_with_each_other() {
        let rsa_key = segments("rsa::RsaPrivateKey::new");
        let signing_key = segments("rsa::pkcs1v15::SigningKey::<D>::new");
        let llvm_rsa_key = segments("<rsa::key::RsaPrivateKey>::new::<R>");
        let llvm_signing_key = segments("<rsa::pkcs1v15::signing_key::SigningKey<D>>::new");

        assert!(same_api(&rsa_key, &llvm_rsa_key));
        assert!(same_api(&signing_key, &llvm_signing_key));
        assert!(!same_api(&rsa_key, &llvm_signing_key));
        assert!(!same_api(&signing_key, &llvm_rsa_key));
    }

    #[test]
    fn different_methods_never_pair() {
        assert!(!same_api(
            &segments("rsa::RsaPrivateKey::new"),
            &segments("<rsa::key::RsaPrivateKey>::sign")
        ));
    }

    #[test]
    fn links_the_same_call_across_layers() {
        let mut mir = Cpg::new(AblationMode::Dual);
        let f = mir.add_node(IrLayer::Mir, NodeKind::Function, "a::f", None);
        let call = mir.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            "rsa::RsaPrivateKey::new",
            Some(SourceLoc::new("a.rs", 3)),
        );
        mir.add_edge(f, call, cpg_core::EdgeKind::Contains);

        let mut llvm = Cpg::new(AblationMode::Dual);
        let f2 = llvm.add_node(IrLayer::Llvm, NodeKind::Function, "a::f", None);
        let call2 = llvm.add_node(
            IrLayer::Llvm,
            NodeKind::CallSite,
            "<rsa::key::RsaPrivateKey>::new::<R>",
            None,
        );
        llvm.add_edge(f2, call2, cpg_core::EdgeKind::Contains);

        let mut fused = fuse(&mir, &llvm, AblationMode::Dual);
        infer_cross_layer_refs(&mut fused);
        let cross: Vec<_> = fused
            .edges()
            .into_iter()
            .filter(|(_, _, k)| *k == cpg_core::EdgeKind::CrossLayerRef)
            .collect();
        assert_eq!(cross.len(), 2, "got: {cross:?}");
    }

    #[test]
    fn dual_unions_both_layers() {
        let fused = fuse(&mir_only(), &llvm_only(), AblationMode::Dual);
        assert_eq!(fused.node_count(), 3);
        assert_eq!(fused.edge_count(), 1);
    }

    #[test]
    fn mir_only_drops_llvm() {
        let fused = fuse(&mir_only(), &llvm_only(), AblationMode::MirOnly);
        assert_eq!(fused.node_count(), 2);
        assert!(fused.nodes().all(|n| n.layer == IrLayer::Mir));
    }

    #[test]
    fn llvm_only_drops_mir() {
        let fused = fuse(&mir_only(), &llvm_only(), AblationMode::LlvmOnly);
        assert_eq!(fused.node_count(), 1);
        assert_eq!(fused.edge_count(), 0);
    }

    #[test]
    fn every_mir_function_of_a_symbol_is_paired() {
        let mut mir = Cpg::new(AblationMode::Dual);
        let body = mir.add_node(IrLayer::Mir, NodeKind::Function, "a::f::{closure#0}", None);
        let stub = mir.add_node(IrLayer::Mir, NodeKind::Function, "a::f::{closure#0}", None);
        let mut llvm = Cpg::new(AblationMode::Dual);
        llvm.add_node(IrLayer::Llvm, NodeKind::Function, "a::f::{closure#0}", None);
        let mut fused = fuse(&mir, &llvm, AblationMode::Dual);
        infer_cross_layer_refs(&mut fused);
        let (body, stub) = (mir.node(body).id, mir.node(stub).id);
        let paired: Vec<u32> = fused
            .edges()
            .into_iter()
            .filter(|(_, _, k)| *k == cpg_core::EdgeKind::CrossLayerRef)
            .map(|(from, _, _)| from)
            .collect();
        assert!(
            paired.contains(&body) && paired.contains(&stub),
            "{paired:?}"
        );
    }
}
