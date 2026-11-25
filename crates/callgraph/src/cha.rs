use std::collections::HashMap;

use cpg_core::{CallGraph, CallGraphProvider, Cpg, CpgError, EdgeKind, IrLayer, NodeKind};

use crate::FallbackCallGraphProvider;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchScope {
    Dyn,
    AllUnresolved,
}

#[derive(Debug, Clone, Copy)]
pub struct ChaCallGraphProvider {
    pub scope: DispatchScope,
}

impl CallGraphProvider for ChaCallGraphProvider {
    fn build(&self, cpg: &Cpg) -> Result<CallGraph, CpgError> {
        let mut graph = FallbackCallGraphProvider.build(cpg)?;
        graph.edges.extend(dispatch_edges(cpg, self.scope));
        graph.edges.sort_unstable();
        graph.edges.dedup();
        Ok(graph)
    }

    fn name(&self) -> &'static str {
        match self.scope {
            DispatchScope::Dyn => "cha-dyn",
            DispatchScope::AllUnresolved => "cha",
        }
    }
}

pub type TraitMethodName = (&'static str, &'static str);

pub const FORWARDS: [(TraitMethodName, TraitMethodName); 5] = [
    (("Into", "into"), ("From", "from")),
    (("TryInto", "try_into"), ("TryFrom", "try_from")),
    (("ToString", "to_string"), ("Display", "fmt")),
    (("ToOwned", "to_owned"), ("Clone", "clone")),
    (("FromResidual", "from_residual"), ("From", "from")),
];

const FN_TRAITS: [TraitMethodName; 3] = [
    ("Fn", "call"),
    ("FnMut", "call_mut"),
    ("FnOnce", "call_once"),
];

#[derive(Default)]
struct ImplBlock {
    trait_path: Vec<String>,
    methods: HashMap<String, u32>,
}

type BlocksOf = HashMap<(String, Vec<String>), ImplBlock>;

pub fn dispatch_edges(cpg: &Cpg, scope: DispatchScope) -> Vec<(u32, u32)> {
    let resolved: std::collections::HashSet<u32> = cpg
        .edges()
        .into_iter()
        .filter(|(_, _, kind)| *kind == EdgeKind::TraitResolve)
        .map(|(from, _, _)| from)
        .collect();

    let bodies = || {
        cpg.nodes().filter(|n| {
            n.layer == IrLayer::Mir && n.kind == NodeKind::Function && n.location.is_some()
        })
    };
    let mut blocks: HashMap<String, BlocksOf> = HashMap::new();
    for n in bodies() {
        let Some(key) = impl_key(&n.symbol) else {
            continue;
        };
        let name = key.trait_path.last().cloned().unwrap_or_default();
        let block = blocks
            .entry(name)
            .or_default()
            .entry((key.self_type, key.trait_path.clone()))
            .or_default();
        block.trait_path = key.trait_path;
        block.methods.insert(key.method, n.id);
    }
    let closures: Vec<u32> = bodies()
        .filter(|n| n.symbol.contains("{closure"))
        .map(|n| n.id)
        .collect();

    let mut refs_by_sig: HashMap<&str, Vec<u32>> = HashMap::new();
    let mut item_refs: Vec<u32> = Vec::new();
    for r in cpg
        .nodes()
        .filter(|n| n.layer == IrLayer::Mir && n.kind == NodeKind::FnRef)
    {
        if let Some(sig) = r.fn_sig.as_deref() {
            refs_by_sig.entry(sig).or_default().push(r.id);
        }
        if !r.symbol.contains("{closure") {
            item_refs.push(r.id);
        }
    }
    let calls_out: std::collections::HashSet<u32> = cpg
        .edges()
        .into_iter()
        .filter(|(_, _, kind)| *kind == EdgeKind::Call)
        .map(|(from, _, _)| from)
        .collect();

    let mut out = Vec::new();
    for call in cpg
        .nodes()
        .filter(|n| n.layer == IrLayer::Mir && n.kind == NodeKind::IndirectCall)
    {
        if calls_out.contains(&call.id) {
            continue;
        }
        let candidates = call.fn_sig.as_deref().and_then(|sig| refs_by_sig.get(sig));
        out.extend(candidates.into_iter().flatten().map(|&r| (call.id, r)));
    }
    for call in cpg.nodes() {
        if call.layer != IrLayer::Mir
            || call.kind != NodeKind::TraitMethod
            || resolved.contains(&call.id)
        {
            continue;
        }
        let is_dyn = call.symbol.starts_with("<dyn ");
        if scope == DispatchScope::Dyn && !is_dyn {
            continue;
        }
        let Some((trait_path, method)) = call_key(&call.symbol) else {
            continue;
        };
        let Some(name) = trait_path.last() else {
            continue;
        };
        if FN_TRAITS.contains(&(name.as_str(), method.as_str())) {
            out.extend(closures.iter().map(|&c| (call.id, c)));
            out.extend(item_refs.iter().map(|&r| (call.id, r)));
            continue;
        }
        let forwarded = FORWARDS
            .iter()
            .find(|((t, m), _)| t == name && *m == method)
            .map(|(_, to)| *to);
        let (target_name, target_method) = match forwarded {
            Some((t, m)) => (t.to_string(), m.to_string()),
            None => (name.clone(), method.clone()),
        };
        let is_std = trait_path.first().is_some_and(|s| s == "core");
        for block in blocks
            .get(&target_name)
            .into_iter()
            .flatten()
            .map(|(_, b)| b)
        {
            let matches = match forwarded {
                Some(_) => block.trait_path.first().is_some_and(|s| s == "core") == is_std,
                None => suffix_match(&block.trait_path, &trait_path),
            };
            if !matches {
                continue;
            }
            match block.methods.get(&target_method) {
                Some(&body) => out.push((call.id, body)),
                None => out.extend(block.methods.values().map(|&body| (call.id, body))),
            }
        }
    }
    out.retain(|(call, body)| call != body);
    out.sort_unstable();
    out.dedup();
    out
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ImplKey {
    pub(crate) trait_path: Vec<String>,
    pub(crate) method: String,
    pub(crate) self_type: String,
}

pub(crate) fn impl_key(symbol: &str) -> Option<ImplKey> {
    let close = symbol.rfind(">::")?;
    let method = &symbol[close + 3..];
    if method.contains("::") || method.contains('{') || method.is_empty() {
        return None;
    }
    let bytes = symbol.as_bytes();
    let mut depth = 0i32;
    let mut open = None;
    for i in (0..=close).rev() {
        match bytes[i] {
            b'>' => depth += 1,
            b'<' => {
                depth -= 1;
                if depth == 0 {
                    open = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let inner = &symbol[open? + 1..close];
    let mut depth = 0i32;
    for (i, c) in inner.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            ' ' if depth == 0 && inner[i..].starts_with(" as ") => {
                return Some(ImplKey {
                    trait_path: segments(&inner[i + 4..]),
                    method: method.to_string(),
                    self_type: inner[..i].to_string(),
                });
            }
            _ => {}
        }
    }
    None
}

pub(crate) fn call_key(symbol: &str) -> Option<(Vec<String>, String)> {
    if let Some(rest) = symbol.strip_prefix("<dyn ") {
        let close = rest.rfind(">::")?;
        let trait_part = rest[..close].split(" + ").next()?;
        return Some((segments(trait_part), rest[close + 3..].to_string()));
    }
    let mut segs = segments(symbol);
    let method = segs.pop()?;
    (!segs.is_empty()).then_some((segs, method))
}

pub(crate) fn segments(path: &str) -> Vec<String> {
    let mut flat = String::with_capacity(path.len());
    let mut depth = 0i32;
    for c in path.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            _ if depth == 0 => flat.push(c),
            _ => {}
        }
    }
    let mut segs: Vec<String> = flat
        .split("::")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if let Some(first) = segs.first_mut() {
        if matches!(first.as_str(), "std" | "alloc") {
            *first = "core".to_string();
        }
    }
    segs
}

pub(crate) fn suffix_match(a: &[String], b: &[String]) -> bool {
    let n = a.len().min(b.len());
    n > 0 && a[a.len() - n..] == b[b.len() - n..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Reachability;
    use cpg_core::{AblationMode, SourceLoc};

    fn body(cpg: &mut Cpg, symbol: &str) -> u32 {
        let n = cpg.add_node(
            IrLayer::Mir,
            NodeKind::Function,
            symbol,
            Some(SourceLoc::new("src/lib.rs", 1)),
        );
        cpg.node(n).id
    }

    fn trait_call(cpg: &mut Cpg, symbol: &str) -> u32 {
        let n = cpg.add_node(
            IrLayer::Mir,
            NodeKind::TraitMethod,
            symbol,
            Some(SourceLoc::new("src/lib.rs", 9)),
        );
        cpg.node(n).id
    }

    fn typed(cpg: &mut Cpg, kind: NodeKind, symbol: &str, sig: &str) -> u32 {
        let n = cpg.add_node(
            IrLayer::Mir,
            kind,
            symbol,
            Some(SourceLoc::new("src/lib.rs", 5)),
        );
        cpg.set_fn_sig(n, sig.to_string());
        cpg.node(n).id
    }

    #[test]
    fn a_pointer_call_reaches_every_reference_of_its_type() {
        let mut cpg = Cpg::new(AblationMode::MirOnly);
        let call = typed(
            &mut cpg,
            NodeKind::IndirectCall,
            "<indirect fn(u64) -> u64>",
            "fn(u64) -> u64",
        );
        let sign = typed(&mut cpg, NodeKind::FnRef, "k::sign", "fn(u64) -> u64");
        let verify = typed(&mut cpg, NodeKind::FnRef, "k::verify", "fn(u64) -> u64");
        let digest = typed(&mut cpg, NodeKind::FnRef, "k::digest", "fn(&[u8]) -> u64");
        for scope in [DispatchScope::Dyn, DispatchScope::AllUnresolved] {
            let edges = dispatch_edges(&cpg, scope);
            assert_eq!(edges, [(call, sign), (call, verify)], "{scope:?}");
            assert!(!edges.contains(&(call, digest)));
        }
    }

    #[test]
    fn a_settled_pointer_call_is_not_linked_again() {
        let mut cpg = Cpg::new(AblationMode::MirOnly);
        let call = typed(
            &mut cpg,
            NodeKind::IndirectCall,
            "<indirect fn(u64)>",
            "fn(u64)",
        );
        let sign = typed(&mut cpg, NodeKind::FnRef, "k::sign", "fn(u64)");
        typed(&mut cpg, NodeKind::FnRef, "k::verify", "fn(u64)");
        cpg.add_edge_by_id(call, sign, EdgeKind::Call);
        assert!(dispatch_edges(&cpg, DispatchScope::AllUnresolved).is_empty());
    }

    #[test]
    fn an_fn_call_reaches_the_functions_used_as_values() {
        let mut cpg = Cpg::new(AblationMode::MirOnly);
        let call = trait_call(&mut cpg, "std::ops::Fn::call");
        let item = typed(&mut cpg, NodeKind::FnRef, "k::sign", "fn(u64)");
        let closure = body(&mut cpg, "k::f::{closure#0}");
        let closure_ref = typed(&mut cpg, NodeKind::FnRef, "k::f::{closure#0}", "fn(u64)");
        let edges = dispatch_edges(&cpg, DispatchScope::AllUnresolved);
        assert!(edges.contains(&(call, item)) && edges.contains(&(call, closure)));
        assert!(!edges.contains(&(call, closure_ref)), "{edges:?}");
    }

    #[test]
    fn impl_symbols_parse_with_generics_and_lifetimes() {
        let key = impl_key(
            "sequoia_openpgp::<armor::Reader<'_> as buffered_reader::BufferedReader<parse::Cookie>>::data",
        )
        .expect("an impl method");
        assert_eq!(key.trait_path, ["buffered_reader", "BufferedReader"]);
        assert_eq!(key.method, "data");
        assert_eq!(key.self_type, "armor::Reader<'_>");
        assert_eq!(
            impl_key("age::<error::E as std::fmt::Debug>::fmt").map(|k| k.trait_path),
            Some(vec!["core".into(), "fmt".into(), "Debug".into()])
        );
        assert!(impl_key("age::format::read_header").is_none());
        assert!(impl_key("age::<X as T>::f::{closure#0}").is_none());
    }

    #[test]
    fn a_dyn_call_reaches_every_impl_of_its_method() {
        let mut cpg = Cpg::new(AblationMode::MirOnly);
        let call = trait_call(&mut cpg, "<dyn crypto::Signer>::sign");
        let rsa = body(&mut cpg, "k::<backend::Rsa as crypto::Signer>::sign");
        let ecdsa = body(&mut cpg, "k::<backend::Ecdsa as crypto::Signer>::sign");
        let other = body(&mut cpg, "k::<backend::Rsa as other::Signer2>::sign");
        let edges = dispatch_edges(&cpg, DispatchScope::Dyn);
        assert!(edges.contains(&(call, rsa)) && edges.contains(&(call, ecdsa)));
        assert!(!edges.contains(&(call, other)), "{edges:?}");
    }

    #[test]
    fn a_provided_method_reaches_the_methods_of_impls_that_do_not_override_it() {
        let mut cpg = Cpg::new(AblationMode::MirOnly);
        let call = trait_call(&mut cpg, "<dyn std::io::Write>::write_all");
        let write = body(&mut cpg, "k::<Sink as std::io::Write>::write");
        let flush = body(&mut cpg, "k::<Sink as std::io::Write>::flush");
        let edges = dispatch_edges(&cpg, DispatchScope::Dyn);
        assert_eq!(edges, [(call, write), (call, flush)]);
    }

    #[test]
    fn scope_and_resolution_decide_which_calls_are_linked() {
        let mut cpg = Cpg::new(AblationMode::MirOnly);
        let generic = trait_call(&mut cpg, "crypto::Signer::sign");
        let resolved = trait_call(&mut cpg, "crypto::Signer::sign");
        let imp = body(&mut cpg, "k::<backend::Rsa as crypto::Signer>::sign");
        cpg.add_edge_by_id(resolved, imp, EdgeKind::TraitResolve);
        assert!(dispatch_edges(&cpg, DispatchScope::Dyn).is_empty());
        assert_eq!(
            dispatch_edges(&cpg, DispatchScope::AllUnresolved),
            [(generic, imp)]
        );
    }

    #[test]
    fn into_reaches_from_and_fn_calls_reach_closures() {
        let mut cpg = Cpg::new(AblationMode::MirOnly);
        let into = trait_call(&mut cpg, "std::convert::Into::into");
        let from = body(&mut cpg, "k::<Key as std::convert::From<Bytes>>::from");
        let call = trait_call(&mut cpg, "std::ops::Fn::call");
        let closure = body(&mut cpg, "k::run::{closure#0}");
        let edges = dispatch_edges(&cpg, DispatchScope::AllUnresolved);
        assert!(edges.contains(&(into, from)), "{edges:?}");
        assert!(edges.contains(&(call, closure)), "{edges:?}");
    }

    #[test]
    fn reach_under_the_upper_bound_never_falls_below_the_fallback() {
        let mut cpg = Cpg::new(AblationMode::MirOnly);
        let caller = body(&mut cpg, "k::run");
        let call = trait_call(&mut cpg, "<dyn crypto::Signer>::sign");
        let imp = body(&mut cpg, "k::<backend::Rsa as crypto::Signer>::sign");
        let inner = trait_call(&mut cpg, "rsa::sign");
        for (a, b) in [(caller, call), (imp, inner)] {
            cpg.add_edge_by_id(a, b, EdgeKind::Call);
        }
        let low = Reachability::new(&cpg, &FallbackCallGraphProvider.build(&cpg).unwrap());
        let high = Reachability::new(
            &cpg,
            &ChaCallGraphProvider {
                scope: DispatchScope::Dyn,
            }
            .build(&cpg)
            .unwrap(),
        );
        for n in cpg.nodes() {
            assert!(low.blast_radius(n.id) <= high.blast_radius(n.id));
        }
        assert_eq!(low.blast_radius(caller), 1);
        assert_eq!(
            high.blast_radius(caller),
            3,
            "the call now reaches the impl and its body"
        );
    }
}
