use std::collections::{HashMap, HashSet};

use cpg_core::{ArgMap, Cpg, CpgEdge, EdgeKind, NodeKind};

pub fn link_across_units(cpg: &mut Cpg) -> usize {
    let functions: HashMap<String, u32> = cpg
        .nodes()
        .filter(|n| n.kind == NodeKind::Function)
        .filter(|n| n.location.is_some())
        .filter_map(|n| n.canonical.clone().map(|key| (key, n.id)))
        .collect();
    if functions.is_empty() {
        return 0;
    }

    let mut already_linked: HashSet<u32> = HashSet::new();
    let mut params_of: HashMap<u32, Vec<(u32, ArgMap)>> = HashMap::new();
    let mut returns_of: HashMap<u32, Vec<u32>> = HashMap::new();
    let is_function: HashSet<u32> = functions.values().copied().collect();

    for (src, dst, edge) in cpg.edges_full() {
        match edge.kind {
            EdgeKind::Call if is_function.contains(&dst) => {
                already_linked.insert(src);
            }
            EdgeKind::ArgFlow if is_function.contains(&src) => {
                params_of.entry(src).or_default().push((dst, edge.args));
            }
            EdgeKind::ReturnFlow if is_function.contains(&dst) => {
                returns_of.entry(dst).or_default().push(src);
            }
            _ => {}
        }
    }

    let call_shaped = [
        NodeKind::CallSite,
        NodeKind::TraitMethod,
        NodeKind::FfiBoundary,
        NodeKind::FnRef,
    ];
    let references: HashSet<u32> = cpg
        .nodes()
        .filter(|n| n.kind == NodeKind::FnRef)
        .map(|n| n.id)
        .collect();
    let mut pending: Vec<(u32, u32)> = cpg
        .nodes()
        .filter(|n| call_shaped.contains(&n.kind) && !already_linked.contains(&n.id))
        .filter_map(|n| {
            let callee = functions.get(n.canonical.as_deref()?)?;
            (*callee != n.id).then_some((n.id, *callee))
        })
        .collect();
    pending.sort_unstable();

    let mut linked = 0;
    for (call, callee) in pending {
        if !cpg.add_edge_by_id(call, callee, EdgeKind::Call) {
            continue;
        }
        linked += 1;
        if references.contains(&call) {
            continue;
        }
        for (inner, args) in params_of.get(&callee).into_iter().flatten() {
            cpg.add_edge_full_by_id(
                call,
                *inner,
                CpgEdge {
                    kind: EdgeKind::ArgFlow,
                    args: args.clone(),
                },
            );
        }
        for inner in returns_of.get(&callee).into_iter().flatten() {
            cpg.add_edge_by_id(*inner, call, EdgeKind::ReturnFlow);
        }
    }
    linked
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpg_core::{AblationMode, IrLayer, SafetyCtx, SourceLoc};

    fn merged_units() -> Cpg {
        let mut cpg = Cpg::new(AblationMode::MirOnly);

        let build = cpg.add_node_full(
            IrLayer::Mir,
            NodeKind::Function,
            "lib::build",
            Some("lib::build".to_string()),
            Some(SourceLoc::new("src/lib.rs", 1)),
            SafetyCtx::Safe,
        );
        let inner = cpg.add_node_full(
            IrLayer::Mir,
            NodeKind::CallSite,
            "lib::inner",
            Some("lib::inner".to_string()),
            Some(SourceLoc::new("src/lib.rs", 2)),
            SafetyCtx::Safe,
        );
        cpg.add_edge(build, inner, EdgeKind::Contains);
        cpg.add_edge(build, inner, EdgeKind::ArgFlow);
        cpg.add_edge(inner, build, EdgeKind::ReturnFlow);

        let main = cpg.add_node_full(
            IrLayer::Mir,
            NodeKind::Function,
            "bin::main",
            Some("bin::main".to_string()),
            Some(SourceLoc::new("src/main.rs", 1)),
            SafetyCtx::Safe,
        );
        let call = cpg.add_node_full(
            IrLayer::Mir,
            NodeKind::CallSite,
            "lib::build",
            Some("lib::build".to_string()),
            Some(SourceLoc::new("src/main.rs", 2)),
            SafetyCtx::Safe,
        );
        cpg.add_edge(main, call, EdgeKind::Contains);
        cpg
    }

    fn edges_of(cpg: &Cpg, want: EdgeKind) -> Vec<(u32, u32)> {
        cpg.edges()
            .into_iter()
            .filter(|(_, _, k)| *k == want)
            .map(|(s, t, _)| (s, t))
            .collect()
    }

    #[test]
    fn links_a_call_to_a_body_in_another_unit() {
        let mut cpg = merged_units();
        assert_eq!(link_across_units(&mut cpg), 1);
        assert!(edges_of(&cpg, EdgeKind::Call).contains(&(3, 0)));
    }

    #[test]
    fn splices_the_callees_interface_onto_the_call_site() {
        let mut cpg = merged_units();
        link_across_units(&mut cpg);
        assert!(edges_of(&cpg, EdgeKind::ArgFlow).contains(&(3, 1)));
        assert!(edges_of(&cpg, EdgeKind::ReturnFlow).contains(&(1, 3)));
    }

    #[test]
    fn links_a_reference_to_its_body_without_data_flow() {
        let mut cpg = merged_units();
        let reference = cpg.add_node_full(
            IrLayer::Mir,
            NodeKind::FnRef,
            "lib::build",
            Some("lib::build".to_string()),
            Some(SourceLoc::new("src/main.rs", 3)),
            SafetyCtx::Safe,
        );
        let id = cpg.node(reference).id;
        assert_eq!(link_across_units(&mut cpg), 2);
        assert!(edges_of(&cpg, EdgeKind::Call).contains(&(id, 0)));
        assert!(!edges_of(&cpg, EdgeKind::ArgFlow)
            .iter()
            .any(|(s, _)| *s == id));
        assert!(!edges_of(&cpg, EdgeKind::ReturnFlow)
            .iter()
            .any(|(_, t)| *t == id));
    }

    #[test]
    fn is_idempotent() {
        let mut cpg = merged_units();
        assert_eq!(link_across_units(&mut cpg), 1);
        assert_eq!(
            link_across_units(&mut cpg),
            0,
            "second run must add nothing"
        );
    }

    #[test]
    fn leaves_a_call_the_per_unit_pass_already_wired() {
        let mut cpg = merged_units();
        cpg.add_edge_by_id(3, 0, EdgeKind::Call);
        assert_eq!(link_across_units(&mut cpg), 0);
    }

    #[test]
    fn a_body_less_stub_does_not_become_a_call_target() {
        let mut cpg = Cpg::new(AblationMode::MirOnly);
        let stub = cpg.add_node_full(
            IrLayer::Mir,
            NodeKind::Function,
            "<Key as Signer>::sign",
            Some("<Key as Signer>::sign".into()),
            None,
            SafetyCtx::Safe,
        );
        let caller = cpg.add_node_full(
            IrLayer::Mir,
            NodeKind::Function,
            "demo::main",
            Some("demo::main".into()),
            Some(SourceLoc::new("src/main.rs", 1)),
            SafetyCtx::Safe,
        );
        let call = cpg.add_node_full(
            IrLayer::Mir,
            NodeKind::TraitMethod,
            "Signer::sign",
            Some("<Key as Signer>::sign".into()),
            Some(SourceLoc::new("src/main.rs", 2)),
            SafetyCtx::Safe,
        );
        cpg.add_edge(caller, call, EdgeKind::Contains);

        link_across_units(&mut cpg);

        let stub_id = cpg.node(stub).id;
        let call_id = cpg.node(call).id;
        assert!(
            !cpg.edges()
                .iter()
                .any(|(s, t, k)| *s == call_id && *t == stub_id && *k == EdgeKind::Call),
            "a resolution target must not enter the call graph as a reachable body"
        );
    }

    #[test]
    fn a_call_with_no_matching_body_is_left_alone() {
        let mut cpg = Cpg::new(AblationMode::MirOnly);
        cpg.add_node_full(
            IrLayer::Mir,
            NodeKind::CallSite,
            "rsa::RsaPrivateKey::new",
            Some("rsa::key::RsaPrivateKey::new".to_string()),
            None,
            SafetyCtx::Safe,
        );
        assert_eq!(link_across_units(&mut cpg), 0);
    }
}
