use std::collections::{HashMap, HashSet, VecDeque};

use cpg_core::{Cpg, CpgNode, EdgeKind, Finding, NodeKind, ViaFrame};

use crate::{Instance, RuleSet};

pub fn rehome(cpg: &Cpg, rules: &RuleSet, findings: Vec<Finding>) -> Vec<Finding> {
    let nodes: HashMap<u32, &CpgNode> = cpg.nodes().map(|n| (n.id, n)).collect();
    let in_dependency = |id: &u32| nodes.get(id).is_some_and(|n| n.dep_depth.is_some());
    if !findings.iter().any(|f| in_dependency(&f.node_id)) {
        return findings;
    }
    let mut container: HashMap<u32, u32> = HashMap::new();
    let mut callers: HashMap<u32, Vec<u32>> = HashMap::new();
    for (from, to, kind) in cpg.edges() {
        match kind {
            EdgeKind::Contains => {
                container.insert(to, from);
            }
            EdgeKind::Call if nodes.get(&to).is_some_and(|n| n.kind == NodeKind::Function) => {
                callers.entry(to).or_default().push(from);
            }
            _ => {}
        }
    }
    let frame = |id: u32| ViaFrame {
        symbol: nodes[&id].symbol.clone(),
        location: nodes[&id]
            .location
            .as_ref()
            .map(cpg_core::paths::display_loc),
    };

    let instance = |id: u32| rules.instance_of(nodes[&id]);
    let mut out: Vec<Finding> = Vec::new();
    let mut held: HashMap<(String, String, u32), Vec<Instance>> = HashMap::new();
    let mut rehomed: Vec<(Finding, Instance)> = Vec::new();
    for f in findings {
        if !in_dependency(&f.node_id) {
            held.entry((f.rule_id.clone(), f.location.file.clone(), f.location.line))
                .or_default()
                .push(instance(f.node_id));
            out.push(f);
            continue;
        }
        let reached = instance(f.node_id);
        let Some(&start) = container.get(&f.node_id) else {
            continue;
        };
        let mut queue = VecDeque::from([(start, vec![start])]);
        let mut visited = HashSet::from([start]);
        while let Some((function, path)) = queue.pop_front() {
            for &call in callers.get(&function).into_iter().flatten() {
                let call_node = nodes[&call];
                if call_node.dep_depth.is_none() {
                    let mut moved = f.clone();
                    moved.node_id = call;
                    if let Some(loc) = &call_node.location {
                        moved.location = loc.clone();
                    }
                    moved.via = path.iter().rev().map(|&id| frame(id)).collect();
                    moved.via.push(frame(f.node_id));
                    rehomed.push((moved, reached.clone()));
                } else if let Some(&outer) = container.get(&call) {
                    if visited.insert(outer) {
                        let mut longer = path.clone();
                        longer.push(outer);
                        queue.push_back((outer, longer));
                    }
                }
            }
        }
    }
    rehomed.sort_by_key(|(f, _)| f.via.len());
    for (f, reached) in rehomed {
        let at = held
            .entry((f.rule_id.clone(), f.location.file.clone(), f.location.line))
            .or_default();
        if !at.iter().any(|i| i.compatible(&reached)) {
            at.push(reached);
            out.push(f);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuleSet;
    use cpg_core::{
        AblationMode, AlgorithmClass, EdgeKind, IrLayer, NodeKind, QvStatus, SafetyCtx, SourceLoc,
    };

    struct G {
        cpg: Cpg,
    }
    impl G {
        fn node(
            &mut self,
            kind: NodeKind,
            symbol: &str,
            file: &str,
            line: u32,
            depth: Option<u8>,
        ) -> u32 {
            let n = self.cpg.add_node_full(
                IrLayer::Mir,
                kind,
                symbol,
                None,
                Some(SourceLoc::new(file, line)),
                SafetyCtx::Safe,
            );
            if let Some(d) = depth {
                self.cpg.set_dep_depth(n, d);
            }
            self.cpg.node(n).id
        }
        fn edge(&mut self, a: u32, b: u32, k: EdgeKind) {
            self.cpg.add_edge_by_id(a, b, k);
        }
    }

    fn finding(node: u32, line: u32) -> Finding {
        Finding {
            rule_id: "R-SHA2-001".into(),
            node_id: node,
            algorithm_class: AlgorithmClass::Hash,
            qv_status: QvStatus::Resistant,
            location: SourceLoc::new("vault/src/lib.rs", line),
            contextual_signature: "sha2::Sha256::digest".into(),
            taint_chain: Vec::new(),
            taint_nodes: Vec::new(),
            key_size: None,
            via: Vec::new(),
            parameter_set: None,
            with: Vec::new(),
        }
    }

    fn graph() -> (G, [u32; 6]) {
        let mut g = G {
            cpg: Cpg::new(AblationMode::MirOnly),
        };
        let m8 = g.node(NodeKind::Function, "app::m8", "src/lib.rs", 5, None);
        let c8 = g.node(NodeKind::CallSite, "vault::seal", "src/lib.rs", 6, None);
        let c8b = g.node(NodeKind::CallSite, "vault::seal", "src/lib.rs", 9, None);
        let seal = g.node(
            NodeKind::Function,
            "vault::seal",
            "vault/src/lib.rs",
            3,
            Some(1),
        );
        let dig = g.node(
            NodeKind::CallSite,
            "sha2::Sha256::digest",
            "vault/src/lib.rs",
            4,
            Some(1),
        );
        let c10 = g.node(NodeKind::CallSite, "relay::forward", "src/lib.rs", 12, None);
        let fwd = g.node(
            NodeKind::Function,
            "relay::forward",
            "relay/src/lib.rs",
            1,
            Some(1),
        );
        let cst = g.node(
            NodeKind::CallSite,
            "vault::seal_twice",
            "relay/src/lib.rs",
            2,
            Some(1),
        );
        let st = g.node(
            NodeKind::Function,
            "vault::seal_twice",
            "vault/src/lib.rs",
            8,
            Some(2),
        );
        let dig2 = g.node(
            NodeKind::CallSite,
            "sha2::Sha224::digest",
            "vault/src/lib.rs",
            9,
            Some(2),
        );
        g.edge(m8, c8, EdgeKind::Contains);
        g.edge(m8, c8b, EdgeKind::Contains);
        g.edge(c8, seal, EdgeKind::Call);
        g.edge(c8b, seal, EdgeKind::Call);
        g.edge(seal, dig, EdgeKind::Contains);
        g.edge(c10, fwd, EdgeKind::Call);
        g.edge(fwd, cst, EdgeKind::Contains);
        g.edge(cst, st, EdgeKind::Call);
        g.edge(st, dig2, EdgeKind::Contains);
        (g, [c8, c8b, dig, c10, dig2, seal])
    }

    #[test]
    fn a_dependency_finding_moves_to_every_local_call_that_reaches_it() {
        let (g, [c8, c8b, dig, ..]) = graph();
        let out = rehome(&g.cpg, &RuleSet::builtin(), vec![finding(dig, 4)]);
        let mut at: Vec<(u32, u32)> = out.iter().map(|f| (f.node_id, f.location.line)).collect();
        at.sort_unstable();
        assert_eq!(at, [(c8, 6), (c8b, 9)]);
        let via: Vec<&str> = out[0].via.iter().map(|v| v.symbol.as_str()).collect();
        assert_eq!(via, ["vault::seal", "sha2::Sha256::digest"]);
        assert!(out.iter().all(|f| f.location.file == "src/lib.rs"));
    }

    #[test]
    fn two_hops_record_both_frames() {
        let (g, [.., c10, dig2, _]) = graph();
        let out = rehome(&g.cpg, &RuleSet::builtin(), vec![finding(dig2, 9)]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].node_id, c10);
        let via: Vec<&str> = out[0].via.iter().map(|v| v.symbol.as_str()).collect();
        assert_eq!(
            via,
            [
                "relay::forward",
                "vault::seal_twice",
                "sha2::Sha224::digest"
            ]
        );
    }

    #[test]
    fn a_local_finding_is_untouched_and_duplicates_collapse() {
        let (g, [c8, _, dig, ..]) = graph();
        let mut local = finding(c8, 6);
        local.location = SourceLoc::new("src/lib.rs", 6);
        let out = rehome(
            &g.cpg,
            &RuleSet::builtin(),
            vec![local.clone(), finding(dig, 4), finding(dig, 4)],
        );
        assert_eq!(out.iter().filter(|f| f.location.line == 6).count(), 1);
        assert_eq!(out.iter().filter(|f| f.location.line == 9).count(), 1);
        assert!(out.contains(&local));
    }

    #[test]
    fn re_homed_rows_of_two_instances_stay_two() {
        let (mut g, [c8, _, dig, _, _, seal]) = graph();
        let other = g.node(
            NodeKind::CallSite,
            "sha2::Sha256::digest",
            "vault/src/lib.rs",
            5,
            Some(1),
        );
        g.edge(seal, other, EdgeKind::Contains);
        let idx = |g: &G, id: u32| g.cpg.index_of_id(id).expect("node");
        let (a, b) = (idx(&g, dig), idx(&g, other));
        g.cpg.set_type_args(a, vec!["p256::NistP256".into()]);
        g.cpg.set_type_args(b, vec!["p384::NistP384".into()]);
        let out = rehome(
            &g.cpg,
            &RuleSet::builtin(),
            vec![finding(dig, 4), finding(other, 5)],
        );
        assert_eq!(
            out.iter().filter(|f| f.node_id == c8).count(),
            2,
            "{out:#?}"
        );
    }
}
