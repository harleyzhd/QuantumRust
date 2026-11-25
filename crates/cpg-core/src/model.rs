use std::path::Path;

use petgraph::stable_graph::{NodeIndex, StableDiGraph};
use petgraph::visit::{EdgeRef, IntoEdgeReferences};
use serde::{Deserialize, Serialize};

use crate::error::CpgError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IrLayer {
    Mir,
    Llvm,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeKind {
    Function,
    CallSite,
    TraitMethod,
    Vtable,
    FfiBoundary,
    Predicate,
    IndirectCall,
    FnRef,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafetyCtx {
    #[default]
    Safe,
    Unsafe,
    Ffi,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLoc {
    pub file: String,
    pub line: u32,
}

impl SourceLoc {
    pub fn new(file: impl Into<String>, line: u32) -> Self {
        Self {
            file: file.into(),
            line,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpgNode {
    pub id: u32,
    pub layer: IrLayer,
    pub kind: NodeKind,
    pub symbol: String,
    #[serde(default)]
    pub canonical: Option<String>,
    pub location: Option<SourceLoc>,
    #[serde(default)]
    pub safety_ctx: SafetyCtx,
    #[serde(default)]
    pub const_args: Vec<ConstArg>,
    #[serde(default)]
    pub type_args: Vec<String>,
    #[serde(default)]
    pub static_args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fn_sig: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dep_depth: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstArg {
    pub index: u32,
    pub value: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeKind {
    Call,
    DataDep,
    TraitResolve,
    CrossLayerRef,
    ControlFlow,
    ControlDep,
    Contains,
    ArgFlow,
    ReturnFlow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpgEdge {
    pub kind: EdgeKind,
    #[serde(default, skip_serializing_if = "ArgMap::is_empty")]
    pub args: ArgMap,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgMap(pub Vec<(u8, u64)>);

impl ArgMap {
    pub const RESULT: u8 = u8::MAX;

    pub const ALL: u64 = u64::MAX;

    pub fn bit(index: usize) -> u64 {
        1 << index.min(63)
    }

    pub fn key(index: usize) -> u8 {
        index.min(63) as u8
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn from_result(mask: u64) -> Self {
        Self(vec![(Self::RESULT, mask)])
    }

    pub fn reach(&self, held: u64) -> u64 {
        if self.is_empty() {
            return Self::ALL;
        }
        self.0
            .iter()
            .filter(|(from, _)| *from == Self::RESULT || held & Self::bit(*from as usize) != 0)
            .fold(0, |acc, (_, to)| acc | to)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AblationMode {
    Dual,
    MirOnly,
    LlvmOnly,
}

impl AblationMode {
    pub fn keeps(self, layer: IrLayer) -> bool {
        match self {
            AblationMode::Dual => true,
            AblationMode::MirOnly => layer == IrLayer::Mir,
            AblationMode::LlvmOnly => layer == IrLayer::Llvm,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cpg {
    graph: StableDiGraph<CpgNode, CpgEdge>,
    mode: AblationMode,
    next_id: u32,
    #[serde(default)]
    source: Option<String>,
}

impl Cpg {
    pub fn new(mode: AblationMode) -> Self {
        Self {
            graph: StableDiGraph::new(),
            mode,
            next_id: 0,
            source: None,
        }
    }

    pub fn mode(&self) -> AblationMode {
        self.mode
    }

    pub fn add_node(
        &mut self,
        layer: IrLayer,
        kind: NodeKind,
        symbol: impl Into<String>,
        location: Option<SourceLoc>,
    ) -> NodeIndex {
        self.add_node_with_ctx(layer, kind, symbol, location, SafetyCtx::Safe)
    }

    pub fn add_node_with_ctx(
        &mut self,
        layer: IrLayer,
        kind: NodeKind,
        symbol: impl Into<String>,
        location: Option<SourceLoc>,
        safety_ctx: SafetyCtx,
    ) -> NodeIndex {
        self.add_node_full(layer, kind, symbol, None, location, safety_ctx)
    }

    pub fn copy_node(&mut self, node: &CpgNode) -> NodeIndex {
        let id = self.next_id;
        self.next_id += 1;
        self.graph.add_node(CpgNode { id, ..node.clone() })
    }

    pub fn set_const_args(&mut self, node: NodeIndex, const_args: Vec<ConstArg>) {
        if let Some(n) = self.graph.node_weight_mut(node) {
            n.const_args = const_args;
        }
    }

    pub fn set_type_args(&mut self, node: NodeIndex, type_args: Vec<String>) {
        if let Some(n) = self.graph.node_weight_mut(node) {
            n.type_args = type_args;
        }
    }

    pub fn set_static_args(&mut self, node: NodeIndex, static_args: Vec<String>) {
        if let Some(n) = self.graph.node_weight_mut(node) {
            n.static_args = static_args;
        }
    }

    pub fn set_fn_sig(&mut self, node: NodeIndex, fn_sig: String) {
        if let Some(n) = self.graph.node_weight_mut(node) {
            n.fn_sig = Some(fn_sig);
        }
    }

    pub fn next_id(&self) -> u32 {
        self.next_id
    }

    pub fn mark_dep_depth_from(&mut self, first_id: u32, depth: u8) {
        for n in self.graph.node_weights_mut() {
            if n.id >= first_id {
                n.dep_depth = Some(depth);
            }
        }
    }

    pub fn set_dep_depth(&mut self, node: NodeIndex, depth: u8) {
        if let Some(n) = self.graph.node_weight_mut(node) {
            n.dep_depth = Some(depth);
        }
    }

    pub fn add_node_full(
        &mut self,
        layer: IrLayer,
        kind: NodeKind,
        symbol: impl Into<String>,
        canonical: Option<String>,
        location: Option<SourceLoc>,
        safety_ctx: SafetyCtx,
    ) -> NodeIndex {
        let id = self.next_id;
        self.next_id += 1;
        self.graph.add_node(CpgNode {
            id,
            layer,
            kind,
            symbol: symbol.into(),
            canonical,
            location,
            safety_ctx,
            const_args: Vec::new(),
            type_args: Vec::new(),
            static_args: Vec::new(),
            fn_sig: None,
            dep_depth: None,
        })
    }

    pub fn add_edge(&mut self, from: NodeIndex, to: NodeIndex, kind: EdgeKind) {
        self.add_edge_full(
            from,
            to,
            CpgEdge {
                kind,
                args: ArgMap::default(),
            },
        );
    }

    pub fn add_edge_full(&mut self, from: NodeIndex, to: NodeIndex, edge: CpgEdge) {
        self.graph.add_edge(from, to, edge);
    }

    pub fn index_of_id(&self, id: u32) -> Option<NodeIndex> {
        let guess = NodeIndex::new(id as usize);
        if self.graph.node_weight(guess).is_some_and(|n| n.id == id) {
            return Some(guess);
        }
        self.graph.node_indices().find(|&i| self.graph[i].id == id)
    }

    pub fn add_edge_by_id(&mut self, from: u32, to: u32, kind: EdgeKind) -> bool {
        self.add_edge_full_by_id(
            from,
            to,
            CpgEdge {
                kind,
                args: ArgMap::default(),
            },
        )
    }

    pub fn add_edge_full_by_id(&mut self, from: u32, to: u32, edge: CpgEdge) -> bool {
        match (self.index_of_id(from), self.index_of_id(to)) {
            (Some(a), Some(b)) => {
                self.add_edge_full(a, b, edge);
                true
            }
            _ => false,
        }
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    pub fn node(&self, index: NodeIndex) -> &CpgNode {
        &self.graph[index]
    }

    pub fn nodes(&self) -> impl Iterator<Item = &CpgNode> + '_ {
        self.graph.node_indices().map(move |i| &self.graph[i])
    }

    pub fn nodes_of_kind<'a>(
        &'a self,
        kind: &'a NodeKind,
    ) -> impl Iterator<Item = &'a CpgNode> + 'a {
        self.nodes().filter(move |n| &n.kind == kind)
    }

    pub fn edges(&self) -> Vec<(u32, u32, EdgeKind)> {
        self.graph
            .edge_references()
            .map(|e| {
                let s = self.graph[e.source()].id;
                let t = self.graph[e.target()].id;
                (s, t, e.weight().kind)
            })
            .collect()
    }

    pub fn edges_full(&self) -> Vec<(u32, u32, CpgEdge)> {
        self.graph
            .edge_references()
            .map(|e| {
                let s = self.graph[e.source()].id;
                let t = self.graph[e.target()].id;
                (s, t, e.weight().clone())
            })
            .collect()
    }

    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    pub fn set_source(&mut self, source: impl Into<String>) {
        self.source = Some(source.into());
    }

    pub fn save_json(&self, path: impl AsRef<Path>) -> Result<(), CpgError> {
        let text = serde_json::to_string_pretty(self)?;
        std::fs::write(path, text)?;
        Ok(())
    }

    pub fn load_json(path: impl AsRef<Path>) -> Result<Self, CpgError> {
        let text = std::fs::read_to_string(path)?;
        let cpg = serde_json::from_str(&text)?;
        Ok(cpg)
    }

    pub fn demo() -> Self {
        let mut cpg = Cpg::new(AblationMode::Dual);

        let main = cpg.add_node(
            IrLayer::Mir,
            NodeKind::Function,
            "demo_crate::main",
            Some(SourceLoc::new("src/main.rs", 10)),
        );
        let sign = cpg.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            "rsa::RsaPrivateKey::sign",
            Some(SourceLoc::new("src/main.rs", 15)),
        );
        let trait_sign = cpg.add_node(
            IrLayer::Mir,
            NodeKind::TraitMethod,
            "<dyn signature::Signer>::sign",
            Some(SourceLoc::new("src/main.rs", 15)),
        );
        let vtable = cpg.add_node(
            IrLayer::Llvm,
            NodeKind::Vtable,
            "vtable::signature::Signer::sign",
            None,
        );
        let ffi = cpg.add_node_with_ctx(
            IrLayer::Llvm,
            NodeKind::FfiBoundary,
            "openssl_sys::RSA_sign",
            Some(SourceLoc::new("src/ffi.rs", 5)),
            SafetyCtx::Ffi,
        );
        let pred = cpg.add_node(
            IrLayer::Mir,
            NodeKind::Predicate,
            "demo_crate::main::{config.use_rsa}",
            Some(SourceLoc::new("src/main.rs", 14)),
        );

        cpg.add_edge(main, sign, EdgeKind::Call);
        cpg.add_edge(main, trait_sign, EdgeKind::Call);
        cpg.add_edge(trait_sign, sign, EdgeKind::TraitResolve);
        cpg.add_edge(trait_sign, vtable, EdgeKind::CrossLayerRef);
        cpg.add_edge(sign, ffi, EdgeKind::DataDep);
        cpg.add_edge(main, pred, EdgeKind::Contains);
        cpg.add_edge(main, sign, EdgeKind::Contains);
        cpg.add_edge(main, trait_sign, EdgeKind::Contains);
        cpg.add_edge(pred, sign, EdgeKind::ControlDep);
        cpg.add_edge(pred, trait_sign, EdgeKind::ControlFlow);

        cpg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dep_depth_is_absent_from_json_unless_set_and_marks_a_range() {
        let mut cpg = Cpg::new(AblationMode::MirOnly);
        cpg.add_node(IrLayer::Mir, NodeKind::Function, "local", None);
        let first = cpg.next_id();
        cpg.add_node(IrLayer::Mir, NodeKind::Function, "dep", None);
        cpg.mark_dep_depth_from(first, 2);
        let json = serde_json::to_string(&cpg).unwrap();
        assert_eq!(json.matches("dep_depth").count(), 1, "{json}");
        let depths: Vec<Option<u8>> = cpg.nodes().map(|n| n.dep_depth).collect();
        assert_eq!(depths, [None, Some(2)]);
    }

    #[test]
    fn demo_is_dual_level() {
        let cpg = Cpg::demo();
        assert!(cpg.nodes().any(|n| n.layer == IrLayer::Mir));
        assert!(cpg.nodes().any(|n| n.layer == IrLayer::Llvm));
        assert!(cpg.nodes().any(|n| n.symbol.contains("Signer")));
        assert!(cpg.nodes().any(|n| n.symbol.contains("RSA_sign")));
    }

    #[test]
    fn json_round_trip() {
        let dir = std::env::temp_dir();
        let path = dir.join("quantumrust_demo_cpg_roundtrip.json");
        let cpg = Cpg::demo();
        cpg.save_json(&path).unwrap();
        let loaded = Cpg::load_json(&path).unwrap();
        assert_eq!(cpg.node_count(), loaded.node_count());
        assert_eq!(cpg.edge_count(), loaded.edge_count());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn index_of_id_finds_every_node() {
        let demo = Cpg::demo();
        let reloaded: Cpg = serde_json::from_str(&serde_json::to_string(&demo).unwrap()).unwrap();
        for cpg in [&demo, &reloaded] {
            for n in cpg.nodes() {
                let i = cpg.index_of_id(n.id).expect("every id resolves");
                assert_eq!(cpg.node(i).id, n.id);
            }
            assert!(cpg.index_of_id(u32::MAX).is_none());
        }
    }

    #[test]
    fn ablation_keeps() {
        assert!(AblationMode::MirOnly.keeps(IrLayer::Mir));
        assert!(!AblationMode::MirOnly.keeps(IrLayer::Llvm));
        assert!(AblationMode::LlvmOnly.keeps(IrLayer::Llvm));
        assert!(AblationMode::Dual.keeps(IrLayer::Mir));
    }

    #[test]
    fn demo_carries_control_and_safety_context() {
        let cpg = Cpg::demo();
        let ffi = cpg.nodes().find(|n| n.symbol.contains("RSA_sign")).unwrap();
        assert_eq!(ffi.safety_ctx, SafetyCtx::Ffi);
        let kinds: Vec<EdgeKind> = cpg.edges().iter().map(|(_, _, k)| *k).collect();
        assert!(kinds.contains(&EdgeKind::ControlDep));
        assert!(kinds.contains(&EdgeKind::ControlFlow));
        assert!(kinds.contains(&EdgeKind::Contains));
    }

    #[test]
    fn missing_safety_ctx_deserializes_as_safe() {
        let json = r#"{
            "id": 0, "layer": "Mir", "kind": "Function",
            "symbol": "a::f", "location": null
        }"#;
        let node: CpgNode = serde_json::from_str(json).unwrap();
        assert_eq!(node.safety_ctx, SafetyCtx::Safe);
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    #[test]
    fn demo_cpg_snapshot() {
        insta::assert_json_snapshot!(Cpg::demo());
    }
}
