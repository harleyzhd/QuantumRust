pub mod cha;
pub mod rupta;

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;

pub use cha::{ChaCallGraphProvider, DispatchScope};
use cpg_core::{CallGraph, CallGraphProvider, Cpg, CpgError, CpgNode, EdgeKind, IrLayer, NodeKind};

#[derive(Debug, Default)]
pub struct RuptaCallGraphProvider {
    pub crate_root: PathBuf,
    pub cargo_pta: Option<PathBuf>,
}

impl CallGraphProvider for RuptaCallGraphProvider {
    fn build(&self, cpg: &Cpg) -> Result<CallGraph, CpgError> {
        let cargo_pta = self
            .cargo_pta
            .clone()
            .or_else(rupta::cargo_pta_from_env)
            .ok_or_else(|| {
                CpgError::Extraction(format!(
                    "cargo-pta not configured; set {} or RuptaCallGraphProvider::cargo_pta",
                    rupta::CARGO_PTA_ENV
                ))
            })?;
        let dot = rupta::run_cargo_pta(&cargo_pta, &self.crate_root)?;
        Ok(rupta::refine_with_dot(&dot, cpg))
    }

    fn name(&self) -> &'static str {
        "rupta"
    }
}

#[derive(Debug, Default)]
pub struct FallbackCallGraphProvider;

impl CallGraphProvider for FallbackCallGraphProvider {
    fn build(&self, cpg: &Cpg) -> Result<CallGraph, CpgError> {
        let edges = cpg
            .edges()
            .into_iter()
            .filter(|(_, _, kind)| *kind == EdgeKind::Call)
            .map(|(s, t, _)| (s, t))
            .collect();
        Ok(CallGraph { edges })
    }

    fn name(&self) -> &'static str {
        "fallback"
    }
}

pub struct Reachability {
    adjacency: HashMap<u32, Vec<u32>>,
    uncounted: HashSet<u32>,
}

impl Reachability {
    pub fn new(cpg: &Cpg, graph: &CallGraph) -> Self {
        Self::new_with(cpg, graph, &|_, _| true)
    }

    pub fn new_with(
        cpg: &Cpg,
        graph: &CallGraph,
        same_call: &dyn Fn(&CpgNode, &CpgNode) -> bool,
    ) -> Self {
        let mut this = Self::over_call_graph(graph);
        this.uncounted = cpg
            .nodes()
            .filter(|n| n.dep_depth.is_some())
            .map(|n| n.id)
            .collect();
        for (from, to, kind) in cpg.edges() {
            if matches!(
                kind,
                EdgeKind::DataDep | EdgeKind::ArgFlow | EdgeKind::ReturnFlow
            ) {
                this.adjacency.entry(from).or_default().push(to);
            }
        }
        let is_call = |kind: &NodeKind| {
            matches!(
                kind,
                NodeKind::CallSite | NodeKind::TraitMethod | NodeKind::IndirectCall
            )
        };
        let mut mir_calls: HashMap<(&str, u32), Vec<&CpgNode>> = HashMap::new();
        for n in cpg.nodes() {
            if let (IrLayer::Mir, true, Some(loc)) = (&n.layer, is_call(&n.kind), &n.location) {
                mir_calls
                    .entry((loc.file.as_str(), loc.line))
                    .or_default()
                    .push(n);
            }
        }
        for n in cpg.nodes() {
            if let (IrLayer::Llvm, true, Some(loc)) = (&n.layer, is_call(&n.kind), &n.location) {
                if let Some(twins) = mir_calls.get(&(loc.file.as_str(), loc.line)) {
                    let same: Vec<u32> = if twins.len() > 1 {
                        twins
                            .iter()
                            .filter(|t| same_call(n, t))
                            .map(|t| t.id)
                            .collect()
                    } else {
                        Vec::new()
                    };
                    let targets = if same.is_empty() {
                        twins.iter().map(|t| t.id).collect()
                    } else {
                        same
                    };
                    this.adjacency.entry(n.id).or_default().extend(targets);
                }
            }
        }
        this.tidy();
        this
    }

    pub fn over_call_graph(graph: &CallGraph) -> Self {
        let mut adjacency: HashMap<u32, Vec<u32>> = HashMap::new();
        for (from, to) in &graph.edges {
            adjacency.entry(*from).or_default().push(*to);
        }
        let mut this = Self {
            adjacency,
            uncounted: HashSet::new(),
        };
        this.tidy();
        this
    }

    fn tidy(&mut self) {
        for targets in self.adjacency.values_mut() {
            targets.sort_unstable();
            targets.dedup();
        }
    }

    pub fn reachable(&self, start: u32) -> HashSet<u32> {
        let mut seen: HashSet<u32> = HashSet::from([start]);
        let mut queue: VecDeque<u32> = VecDeque::from([start]);
        while let Some(node) = queue.pop_front() {
            for next in self.adjacency.get(&node).into_iter().flatten() {
                if seen.insert(*next) {
                    queue.push_back(*next);
                }
            }
        }
        seen.remove(&start);
        seen
    }

    pub fn blast_radius(&self, start: u32) -> usize {
        self.reachable(start)
            .into_iter()
            .filter(|n| !self.uncounted.contains(n))
            .count()
    }
}

pub fn forward_reachable(graph: &CallGraph, start: u32) -> usize {
    Reachability::over_call_graph(graph).blast_radius(start)
}

#[cfg(test)]
mod tests {
    #[test]
    fn an_llvm_call_reaches_what_its_mir_twin_reaches() {
        let (cpg, llvm, _) = twin_graph(7);
        let graph = FallbackCallGraphProvider.build(&cpg).unwrap();
        let reach = Reachability::new(&cpg, &graph);
        assert_eq!(reach.blast_radius(cpg.node(llvm).id), 4);
    }

    #[test]
    fn an_llvm_call_on_another_line_is_not_bridged() {
        let (cpg, llvm, _) = twin_graph(70);
        let graph = FallbackCallGraphProvider.build(&cpg).unwrap();
        let reach = Reachability::new(&cpg, &graph);
        assert_eq!(reach.blast_radius(cpg.node(llvm).id), 0);
    }

    #[test]
    fn the_bridge_is_not_a_cpg_edge() {
        let (cpg, _, edges) = twin_graph(7);
        let graph = FallbackCallGraphProvider.build(&cpg).unwrap();
        let _ = Reachability::new(&cpg, &graph);
        assert_eq!(cpg.edges().len(), edges);
    }

    fn twin_graph(llvm_line: u32) -> (cpg_core::Cpg, cpg_core::NodeIndex, usize) {
        use cpg_core::{AblationMode, Cpg, EdgeKind, IrLayer, NodeKind, SourceLoc};
        let mut cpg = Cpg::new(AblationMode::Dual);
        let at = |line| Some(SourceLoc::new("src/lib.rs", line));
        let m = cpg.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            "rsa::RsaPrivateKey::new",
            at(7),
        );
        let a = cpg.add_node(IrLayer::Mir, NodeKind::CallSite, "a", at(8));
        let b = cpg.add_node(IrLayer::Mir, NodeKind::CallSite, "b", at(9));
        let c = cpg.add_node(IrLayer::Mir, NodeKind::CallSite, "c", at(10));
        cpg.add_edge(m, a, EdgeKind::DataDep);
        cpg.add_edge(a, b, EdgeKind::DataDep);
        cpg.add_edge(b, c, EdgeKind::DataDep);
        let llvm = cpg.add_node(
            IrLayer::Llvm,
            NodeKind::CallSite,
            "<rsa::key::RsaPrivateKey>::new",
            at(llvm_line),
        );
        let edges = cpg.edges().len();
        (cpg, llvm, edges)
    }

    #[test]
    fn blast_radius_counts_only_the_analysed_crates_nodes() {
        use cpg_core::{AblationMode, Cpg, EdgeKind, IrLayer, NodeKind};
        let mut cpg = Cpg::new(AblationMode::MirOnly);
        let a = cpg.add_node(IrLayer::Mir, NodeKind::CallSite, "a", None);
        let d = cpg.add_node(IrLayer::Mir, NodeKind::CallSite, "dep", None);
        let b = cpg.add_node(IrLayer::Mir, NodeKind::CallSite, "b", None);
        cpg.set_dep_depth(d, 1);
        cpg.add_edge(a, d, EdgeKind::DataDep);
        cpg.add_edge(d, b, EdgeKind::DataDep);
        let graph = FallbackCallGraphProvider.build(&cpg).unwrap();
        let reach = Reachability::new(&cpg, &graph);
        let id = |n| cpg.node(n).id;
        assert_eq!(reach.reachable(id(a)).len(), 2);
        assert_eq!(
            reach.blast_radius(id(a)),
            1,
            "b counts; the dependency node does not"
        );
    }

    #[test]
    fn the_indexed_and_walking_reachability_agree_on_a_call_only_graph() {
        use cpg_core::{AblationMode, IrLayer, NodeKind};
        let mut cpg = Cpg::new(AblationMode::MirOnly);
        let a = cpg.add_node(IrLayer::Mir, NodeKind::Function, "a", None);
        let b = cpg.add_node(IrLayer::Mir, NodeKind::CallSite, "b", None);
        let c = cpg.add_node(IrLayer::Mir, NodeKind::Function, "c", None);
        let d = cpg.add_node(IrLayer::Mir, NodeKind::CallSite, "d", None);
        cpg.add_edge(a, b, EdgeKind::Call);
        cpg.add_edge(b, c, EdgeKind::Call);
        cpg.add_edge(c, d, EdgeKind::Call);
        cpg.add_edge(a, d, EdgeKind::Contains);

        let graph = FallbackCallGraphProvider.build(&cpg).expect("call graph");
        let indexed = Reachability::new(&cpg, &graph);
        for node in cpg.nodes() {
            assert_eq!(
                forward_reachable(&graph, node.id),
                indexed.blast_radius(node.id),
                "the two reachability paths disagree at node {}",
                node.symbol
            );
        }
    }

    #[test]
    fn the_bridge_prefers_the_same_instance() {
        use cpg_core::{AblationMode, IrLayer, NodeKind, SafetyCtx, SourceLoc};
        let mut cpg = Cpg::new(AblationMode::Dual);
        let at = || Some(SourceLoc::new("src/ecdsa.rs", 60));
        let call = |cpg: &mut Cpg, layer, symbol: &str, loc| {
            let n = cpg.add_node_full(
                layer,
                NodeKind::CallSite,
                symbol,
                None,
                loc,
                SafetyCtx::Safe,
            );
            cpg.node(n).id
        };
        let mir256 = call(&mut cpg, IrLayer::Mir, "verify::<P256>", at());
        let mir384 = call(&mut cpg, IrLayer::Mir, "verify::<P384>", at());
        let llvm384 = call(&mut cpg, IrLayer::Llvm, "verify::<P384>", at());
        let after256 = call(&mut cpg, IrLayer::Mir, "use256", None);
        let after384 = call(&mut cpg, IrLayer::Mir, "use384", None);
        cpg.add_edge_by_id(mir256, after256, EdgeKind::DataDep);
        cpg.add_edge_by_id(mir384, after384, EdgeKind::DataDep);
        let graph = FallbackCallGraphProvider.build(&cpg).unwrap();
        let same = |a: &cpg_core::CpgNode, b: &cpg_core::CpgNode| a.symbol == b.symbol;
        let reach = Reachability::new_with(&cpg, &graph, &same).reachable(llvm384);
        assert!(
            reach.contains(&after384) && !reach.contains(&after256),
            "{reach:?}"
        );
        let none = |_: &cpg_core::CpgNode, _: &cpg_core::CpgNode| false;
        let reach = Reachability::new_with(&cpg, &graph, &none).reachable(llvm384);
        assert!(
            reach.contains(&after384) && reach.contains(&after256),
            "{reach:?}"
        );
    }

    use super::*;

    #[test]
    fn a_call_graph_leaf_still_has_reach_through_data_flow() {
        let cpg = Cpg::demo();
        let graph = FallbackCallGraphProvider.build(&cpg).unwrap();
        let sign = cpg
            .nodes()
            .find(|n| n.symbol == "rsa::RsaPrivateKey::sign")
            .unwrap()
            .id;

        assert_eq!(forward_reachable(&graph, sign), 0);
        assert_eq!(Reachability::new(&cpg, &graph).blast_radius(sign), 1);
    }

    #[test]
    fn reach_does_not_follow_cross_layer_or_trait_edges() {
        let cpg = Cpg::demo();
        let graph = FallbackCallGraphProvider.build(&cpg).unwrap();
        let trait_sign = cpg
            .nodes()
            .find(|n| n.symbol.contains("dyn signature::Signer"))
            .unwrap()
            .id;

        assert_eq!(Reachability::new(&cpg, &graph).blast_radius(trait_sign), 0);
    }

    #[test]
    fn reach_excludes_the_start_node() {
        let cpg = Cpg::demo();
        let graph = FallbackCallGraphProvider.build(&cpg).unwrap();
        let vtable = cpg
            .nodes()
            .find(|n| n.symbol.contains("vtable"))
            .unwrap()
            .id;
        assert_eq!(Reachability::new(&cpg, &graph).blast_radius(vtable), 0);
    }

    #[test]
    fn fallback_extracts_call_edges() {
        let cpg = Cpg::demo();
        let cg = FallbackCallGraphProvider.build(&cpg).unwrap();
        assert_eq!(cg.edges.len(), 2);
    }

    #[test]
    fn reachability_counts_downstream() {
        let cg = CallGraph {
            edges: vec![(0, 1), (1, 2), (0, 3)],
        };
        assert_eq!(forward_reachable(&cg, 0), 3);
        assert_eq!(forward_reachable(&cg, 1), 1);
        assert_eq!(forward_reachable(&cg, 2), 0);
    }
}
