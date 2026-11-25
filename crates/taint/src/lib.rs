use std::collections::{HashMap, HashSet, VecDeque};

use cpg_core::{AlgorithmClass, ArgMap, Cpg, CpgNode, EdgeKind, Finding, QvStatus, SourceLoc};
use qr_rules::RuleSet;

pub type FlowGraph = HashMap<u32, Vec<FlowEdge>>;

#[derive(Debug, Clone)]
pub struct FlowEdge {
    pub to: u32,
    pub kind: EdgeKind,
    pub args: ArgMap,
}

pub fn data_dep_adjacency(cpg: &Cpg) -> FlowGraph {
    let error_path: HashSet<u32> = cpg
        .nodes()
        .filter(|node| is_error_path(&node.symbol))
        .map(|node| node.id)
        .collect();
    let mut flow: FlowGraph = HashMap::new();
    for (src, dst, edge) in cpg.edges_full() {
        if error_path.contains(&dst) {
            continue;
        }
        if matches!(
            edge.kind,
            EdgeKind::DataDep | EdgeKind::ArgFlow | EdgeKind::ReturnFlow
        ) {
            flow.entry(src).or_default().push(FlowEdge {
                to: dst,
                kind: edge.kind,
                args: edge.args,
            });
        }
    }
    for targets in flow.values_mut() {
        targets.sort_unstable_by_key(|edge| edge.to);
    }
    flow
}

pub fn is_error_path(symbol: &str) -> bool {
    let last = symbol
        .rsplit("::")
        .find(|segment| !segment.starts_with('<'));
    symbol.contains("FromResidual") && last == Some("from_residual")
}

pub const CONTEXT_DEPTH: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Context {
    sites: [u32; CONTEXT_DEPTH],
    len: usize,
}

impl Context {
    const EMPTY: Context = Context {
        sites: [0; CONTEXT_DEPTH],
        len: 0,
    };

    fn push(self, site: u32) -> Context {
        if CONTEXT_DEPTH == 0 {
            return self;
        }
        let mut next = self;
        if next.len == CONTEXT_DEPTH {
            next.sites.copy_within(1.., 0);
            next.len -= 1;
        }
        next.sites[next.len] = site;
        next.len += 1;
        next
    }

    fn top(self) -> Option<u32> {
        self.len.checked_sub(1).map(|i| self.sites[i])
    }

    fn pop(self) -> Context {
        let mut next = self;
        if let Some(i) = next.len.checked_sub(1) {
            next.sites[i] = 0;
            next.len = i;
        }
        next
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Step {
    node: u32,
    args: u64,
    context: Context,
}

impl Step {
    fn start(node: u32) -> Step {
        Step {
            node,
            args: ArgMap::ALL,
            context: Context::EMPTY,
        }
    }

    fn follow(self, edge: &FlowEdge) -> Option<Step> {
        let (args, context) = match edge.kind {
            EdgeKind::ArgFlow => {
                if self.args == 0 {
                    return None;
                }
                let entered = edge.args.reach(self.args);
                if entered == 0 {
                    return None;
                }
                (entered, self.context.push(self.node))
            }
            EdgeKind::ReturnFlow => {
                let context = match self.context.top() {
                    None => self.context,
                    Some(site) if site == edge.to => self.context.pop(),
                    Some(_) => return None,
                };
                (0, context)
            }
            _ => (edge.args.reach(ArgMap::ALL), self.context),
        };
        Some(Step {
            node: edge.to,
            args,
            context,
        })
    }
}

pub fn annotate(cpg: &Cpg, rules: &RuleSet, mut findings: Vec<Finding>) -> Vec<Finding> {
    let flow = data_dep_adjacency(cpg);
    let nodes: HashMap<u32, &CpgNode> = cpg.nodes().map(|node| (node.id, node)).collect();
    let sinks: HashSet<u32> = nodes
        .values()
        .filter(|node| rules.is_sink(&node.symbol))
        .map(|node| node.id)
        .collect();

    for finding in &mut findings {
        if finding.qv_status != QvStatus::Vulnerable {
            continue;
        }
        if let Some(path) = path_to_nearest_sink(finding.node_id, &flow, &sinks) {
            finding.taint_chain = path.iter().map(|id| location_of(&nodes, *id)).collect();
            finding.taint_nodes = path.clone();
        }
    }
    propagate_key_sizes(cpg, &mut findings);
    findings
}

pub fn refactor_scope(cpg: &Cpg, finding: &Finding) -> usize {
    refactor_scope_in(&data_dep_adjacency(cpg), finding)
}

pub fn refactor_scope_in(flow: &FlowGraph, finding: &Finding) -> usize {
    taint_reachable(finding.node_id, flow).len()
}

fn taint_reachable(start: u32, flow: &FlowGraph) -> HashSet<u32> {
    let start = Step::start(start);
    let mut visited: HashSet<Step> = HashSet::from([start]);
    let mut reached: HashSet<u32> = HashSet::new();
    let mut queue = VecDeque::from([start]);

    while let Some(current) = queue.pop_front() {
        for edge in flow.get(&current.node).into_iter().flatten() {
            let Some(step) = current.follow(edge) else {
                continue;
            };
            if visited.insert(step) {
                reached.insert(step.node);
                queue.push_back(step);
            }
        }
    }
    reached
}

pub fn propagate_key_sizes(cpg: &Cpg, findings: &mut [Finding]) {
    let flow = data_dep_adjacency(cpg);

    let mut reaching: HashMap<(u32, AlgorithmClass), u32> = HashMap::new();
    for finding in findings.iter() {
        let Some(size) = finding.key_size else {
            continue;
        };
        for node in taint_reachable(finding.node_id, &flow) {
            reaching
                .entry((node, finding.algorithm_class))
                .and_modify(|best| *best = (*best).min(size))
                .or_insert(size);
        }
    }

    for finding in findings.iter_mut() {
        if finding.key_size.is_some() {
            continue;
        }
        finding.key_size = reaching
            .get(&(finding.node_id, finding.algorithm_class))
            .copied();
    }
}

fn path_to_nearest_sink(start: u32, flow: &FlowGraph, sinks: &HashSet<u32>) -> Option<Vec<u32>> {
    let start = Step::start(start);
    let mut parent: HashMap<Step, Step> = HashMap::new();
    let mut visited: HashSet<Step> = HashSet::from([start]);
    let mut queue = VecDeque::from([start]);

    while let Some(current) = queue.pop_front() {
        for edge in flow.get(&current.node).into_iter().flatten() {
            let Some(step) = current.follow(edge) else {
                continue;
            };
            if !visited.insert(step) {
                continue;
            }
            parent.insert(step, current);
            if sinks.contains(&step.node) {
                return Some(walk_back(start, step, &parent));
            }
            queue.push_back(step);
        }
    }
    None
}

fn walk_back(start: Step, end: Step, parent: &HashMap<Step, Step>) -> Vec<u32> {
    let mut path = vec![end.node];
    let mut current = end;
    while current != start {
        match parent.get(&current) {
            Some(&previous) => {
                path.push(previous.node);
                current = previous;
            }
            None => break,
        }
    }
    path.reverse();
    path
}

fn location_of(nodes: &HashMap<u32, &CpgNode>, id: u32) -> SourceLoc {
    nodes
        .get(&id)
        .and_then(|node| node.location.as_ref())
        .map(cpg_core::paths::display_loc)
        .unwrap_or_else(|| SourceLoc::new("<unknown>", 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpg_core::AlgorithmClass;

    fn keygen_to_sign(sizes: &[u32]) -> (Cpg, Vec<Finding>) {
        use cpg_core::{AblationMode, IrLayer, NodeKind, SourceLoc};

        let mut cpg = Cpg::new(AblationMode::Dual);
        let sign = cpg.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            "rsa::pkcs1v15::SigningKey::sign",
            Some(SourceLoc::new("src/main.rs", 30)),
        );
        for i in 0..sizes.len() {
            let keygen = cpg.add_node(
                IrLayer::Mir,
                NodeKind::CallSite,
                "rsa::RsaPrivateKey::new",
                Some(SourceLoc::new("src/main.rs", 10 + i as u32)),
            );
            cpg.add_edge(keygen, sign, EdgeKind::DataDep);
        }

        let findings = cpg
            .nodes()
            .map(|node| Finding {
                rule_id: "R-RSA-001".into(),
                node_id: node.id,
                algorithm_class: AlgorithmClass::Rsa,
                qv_status: QvStatus::Vulnerable,
                location: node.location.clone().unwrap(),
                contextual_signature: node.symbol.clone(),
                taint_chain: Vec::new(),
                taint_nodes: Vec::new(),
                via: Vec::new(),
                key_size: node
                    .location
                    .as_ref()
                    .and_then(|loc| loc.line.checked_sub(10))
                    .and_then(|i| sizes.get(i as usize))
                    .copied(),
                parameter_set: None,
                with: Vec::new(),
            })
            .collect();
        (cpg, findings)
    }

    #[test]
    fn a_key_size_reaches_the_operation_that_uses_the_key() {
        let (cpg, mut findings) = keygen_to_sign(&[2048]);
        propagate_key_sizes(&cpg, &mut findings);
        let sign = findings.iter().find(|f| f.location.line == 30).unwrap();
        assert_eq!(sign.key_size, Some(2048));
    }

    #[test]
    fn the_smallest_key_reaching_a_sink_wins() {
        let (cpg, mut findings) = keygen_to_sign(&[4096, 1024, 2048]);
        propagate_key_sizes(&cpg, &mut findings);
        let sign = findings.iter().find(|f| f.location.line == 30).unwrap();
        assert_eq!(sign.key_size, Some(1024));
    }

    #[test]
    fn a_read_size_outranks_a_propagated_one() {
        let (cpg, mut findings) = keygen_to_sign(&[1024]);
        for finding in findings.iter_mut().filter(|f| f.location.line == 30) {
            finding.key_size = Some(4096);
        }
        propagate_key_sizes(&cpg, &mut findings);
        let sign = findings.iter().find(|f| f.location.line == 30).unwrap();
        assert_eq!(sign.key_size, Some(4096));
    }

    #[test]
    fn a_key_size_does_not_cross_algorithm_classes() {
        let (cpg, mut findings) = keygen_to_sign(&[2048]);
        for finding in findings.iter_mut().filter(|f| f.location.line == 30) {
            finding.algorithm_class = AlgorithmClass::Ecdsa;
        }
        propagate_key_sizes(&cpg, &mut findings);
        let sign = findings.iter().find(|f| f.location.line == 30).unwrap();
        assert_eq!(sign.key_size, None);
    }

    fn demo_findings() -> (Cpg, RuleSet, Vec<Finding>) {
        let cpg = Cpg::demo();
        let rules = RuleSet::builtin();
        let findings = rules.match_cpg(&cpg);
        (cpg, rules, findings)
    }

    #[test]
    fn key_material_reaching_an_ffi_sink_gets_a_chain() {
        let (cpg, rules, findings) = demo_findings();
        let annotated = annotate(&cpg, &rules, findings);

        let signing = annotated
            .iter()
            .find(|f| f.contextual_signature.contains("RsaPrivateKey"))
            .expect("the rsa signing finding");
        assert_eq!(
            signing
                .taint_chain
                .iter()
                .map(|l| format!("{}:{}", l.file, l.line))
                .collect::<Vec<_>>(),
            vec!["src/main.rs:15", "src/ffi.rs:5"],
        );
    }

    #[test]
    fn a_source_with_no_outgoing_flow_gets_no_chain() {
        let (cpg, rules, findings) = demo_findings();
        let annotated = annotate(&cpg, &rules, findings);

        let ffi = annotated
            .iter()
            .find(|f| f.contextual_signature.contains("RSA_sign"))
            .expect("the ffi finding");
        assert!(ffi.taint_chain.is_empty());
    }

    #[test]
    fn non_vulnerable_findings_are_left_alone() {
        let cpg = Cpg::demo();
        let rules = RuleSet::builtin();
        let resistant = Finding {
            rule_id: "R-MLKEM-001".into(),
            node_id: 1,
            algorithm_class: AlgorithmClass::Kem,
            qv_status: QvStatus::Resistant,
            location: SourceLoc::new("src/main.rs", 15),
            contextual_signature: "pqcrypto_mlkem::encapsulate".into(),
            taint_chain: Vec::new(),
            taint_nodes: Vec::new(),
            via: Vec::new(),
            key_size: None,
            parameter_set: None,
            with: Vec::new(),
        };
        let annotated = annotate(&cpg, &rules, vec![resistant]);
        assert!(annotated[0].taint_chain.is_empty());
    }

    #[test]
    fn refactor_scope_counts_taint_reachable_nodes() {
        let (cpg, _, findings) = demo_findings();
        let signing = findings
            .iter()
            .find(|f| f.contextual_signature.contains("RsaPrivateKey"))
            .expect("the rsa signing finding");
        assert_eq!(refactor_scope(&cpg, signing), 1);
    }

    fn round_trip_cpg() -> Cpg {
        use cpg_core::{AblationMode, IrLayer, NodeKind};

        let mut cpg = Cpg::new(AblationMode::MirOnly);
        let call_site = cpg.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            "demo_crate::f",
            Some(SourceLoc::new("src/main.rs", 100)),
        );
        let producer = cpg.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            "rsa::signature::SignatureEncoding::to_vec",
            Some(SourceLoc::new("src/main.rs", 20)),
        );
        let sink = cpg.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            "rsa::signature::RandomizedSigner::sign_with_rng",
            Some(SourceLoc::new("src/main.rs", 21)),
        );
        cpg.add_edge(producer, call_site, EdgeKind::ReturnFlow);
        cpg.add_edge(call_site, sink, EdgeKind::ArgFlow);
        cpg
    }

    fn node_id(cpg: &Cpg, needle: &str) -> u32 {
        cpg.nodes()
            .find(|n| n.symbol.contains(needle))
            .unwrap_or_else(|| panic!("no node matching {needle}"))
            .id
    }

    fn finding_at(cpg: &Cpg, needle: &str) -> Finding {
        let node = cpg.nodes().find(|n| n.symbol.contains(needle)).unwrap();
        Finding {
            rule_id: "R-RSA-001".into(),
            node_id: node.id,
            algorithm_class: AlgorithmClass::Rsa,
            qv_status: QvStatus::Vulnerable,
            location: node.location.clone().unwrap(),
            contextual_signature: node.symbol.clone(),
            taint_chain: Vec::new(),
            taint_nodes: Vec::new(),
            via: Vec::new(),
            key_size: None,
            parameter_set: None,
            with: Vec::new(),
        }
    }

    #[test]
    fn a_return_value_does_not_flow_into_its_own_calls_arguments() {
        let cpg = round_trip_cpg();
        let rules = RuleSet::builtin();
        let annotated = annotate(&cpg, &rules, vec![finding_at(&cpg, "to_vec")]);
        assert!(
            annotated[0].taint_chain.is_empty(),
            "unbalanced call/return path was taken: {:?}",
            annotated[0].taint_chain
        );
    }

    #[test]
    fn argument_flow_still_works_when_not_arrived_by_return() {
        let mut cpg = round_trip_cpg();
        use cpg_core::{IrLayer, NodeKind};
        let source = cpg.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            "rsa::RsaPrivateKey::new",
            Some(SourceLoc::new("src/main.rs", 99)),
        );
        let call_site = cpg.index_of_id(node_id(&cpg, "demo_crate::f")).unwrap();
        cpg.add_edge(source, call_site, EdgeKind::DataDep);

        let rules = RuleSet::builtin();
        let annotated = annotate(&cpg, &rules, vec![finding_at(&cpg, "RsaPrivateKey")]);
        assert_eq!(
            annotated[0]
                .taint_chain
                .iter()
                .map(|l| l.line)
                .collect::<Vec<_>>(),
            vec![99, 100, 21],
            "a source reaching the call site normally must still enter the callee"
        );
    }

    fn two_callers(sizes: [u32; 2]) -> (Cpg, Vec<Finding>) {
        use cpg_core::{AblationMode, IrLayer, NodeKind};

        let mut cpg = Cpg::new(AblationMode::MirOnly);
        let inner = cpg.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            "demo_crate::inner",
            Some(SourceLoc::new("src/f.rs", 2)),
        );
        for (i, caller) in ["a", "b"].iter().enumerate() {
            let line = 10 * (i as u32 + 1);
            let keygen = cpg.add_node(
                IrLayer::Mir,
                NodeKind::CallSite,
                "rsa::RsaPrivateKey::new",
                Some(SourceLoc::new(format!("src/{caller}.rs"), line)),
            );
            let site = cpg.add_node(
                IrLayer::Mir,
                NodeKind::CallSite,
                "demo_crate::f",
                Some(SourceLoc::new(format!("src/{caller}.rs"), line + 1)),
            );
            let sign = cpg.add_node(
                IrLayer::Mir,
                NodeKind::CallSite,
                "rsa::pkcs1v15::SigningKey::sign",
                Some(SourceLoc::new(format!("src/{caller}.rs"), line + 2)),
            );
            cpg.add_edge(keygen, site, EdgeKind::DataDep);
            cpg.add_edge(site, inner, EdgeKind::ArgFlow);
            cpg.add_edge(inner, site, EdgeKind::ReturnFlow);
            cpg.add_edge(site, sign, EdgeKind::DataDep);
        }
        let findings = cpg
            .nodes()
            .filter(|n| n.symbol.starts_with("rsa::"))
            .map(|n| {
                let mut f = finding_at(&cpg, &n.symbol);
                f.node_id = n.id;
                f.location = n.location.clone().unwrap();
                f.key_size = match (n.symbol.ends_with("::new"), f.location.line) {
                    (true, 10) => Some(sizes[0]),
                    (true, 20) => Some(sizes[1]),
                    _ => None,
                };
                f
            })
            .collect();
        (cpg, findings)
    }

    fn reached_lines(cpg: &Cpg, start: u32) -> Vec<String> {
        let mut lines: Vec<String> = taint_reachable(start, &data_dep_adjacency(cpg))
            .into_iter()
            .filter_map(|id| cpg.nodes().find(|n| n.id == id)?.location.clone())
            .map(|l| format!("{}:{}", l.file, l.line))
            .collect();
        lines.sort();
        lines
    }

    #[test]
    fn a_value_returns_only_to_the_call_site_it_entered_through() {
        let (cpg, _) = two_callers([2048, 4096]);
        let keygen_a = cpg
            .nodes()
            .find(|n| {
                n.location
                    .as_ref()
                    .is_some_and(|l| l.file == "src/a.rs" && l.line == 10)
            })
            .unwrap()
            .id;
        let reached = reached_lines(&cpg, keygen_a);
        assert!(reached.contains(&"src/a.rs:12".to_string()), "{reached:?}");
        assert!(
            !reached.iter().any(|l| l.starts_with("src/b.rs")),
            "caller A's key left through caller B: {reached:?}"
        );
    }

    #[test]
    fn each_caller_keeps_its_own_key_size_through_a_shared_helper() {
        let (cpg, mut findings) = two_callers([2048, 4096]);
        propagate_key_sizes(&cpg, &mut findings);
        let size_at = |file: &str| {
            findings
                .iter()
                .find(|f| f.location.file == file && f.location.line % 10 == 2)
                .and_then(|f| f.key_size)
        };
        assert_eq!(size_at("src/a.rs"), Some(2048));
        assert_eq!(size_at("src/b.rs"), Some(4096));
    }

    #[test]
    fn a_value_produced_inside_a_callee_reaches_every_caller() {
        let (cpg, _) = two_callers([2048, 4096]);
        let reached = reached_lines(&cpg, node_id(&cpg, "demo_crate::inner"));
        assert!(reached.contains(&"src/a.rs:12".to_string()), "{reached:?}");
        assert!(reached.contains(&"src/b.rs:22".to_string()), "{reached:?}");
    }

    #[test]
    fn a_call_nested_deeper_than_the_context_still_returns() {
        use cpg_core::{AblationMode, IrLayer, NodeKind};

        let mut cpg = Cpg::new(AblationMode::MirOnly);
        let mut node = |symbol: &str, line: u32| {
            cpg.add_node(
                IrLayer::Mir,
                NodeKind::CallSite,
                symbol,
                Some(SourceLoc::new("src/main.rs", line)),
            )
        };
        let keygen = node("rsa::RsaPrivateKey::new", 1);
        let sign = node("rsa::pkcs1v15::SigningKey::sign", 2);
        let sites: Vec<_> = (0..=CONTEXT_DEPTH + 1)
            .map(|j| node(&format!("demo_crate::w{}", j + 1), 10 + j as u32))
            .collect();
        cpg.add_edge(keygen, sites[0], EdgeKind::DataDep);
        cpg.add_edge(sites[0], sign, EdgeKind::DataDep);
        for pair in sites.windows(2) {
            cpg.add_edge(pair[0], pair[1], EdgeKind::ArgFlow);
            cpg.add_edge(pair[1], pair[0], EdgeKind::ReturnFlow);
        }

        let reached = reached_lines(
            &cpg,
            cpg.nodes()
                .find(|n| n.symbol.ends_with("::new"))
                .unwrap()
                .id,
        );
        assert!(
            reached.contains(&"src/main.rs:2".to_string()),
            "{reached:?}"
        );
    }

    #[test]
    fn recursion_terminates() {
        use cpg_core::{AblationMode, IrLayer, NodeKind};

        let mut cpg = Cpg::new(AblationMode::MirOnly);
        let keygen = cpg.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            "rsa::RsaPrivateKey::new",
            Some(SourceLoc::new("src/main.rs", 1)),
        );
        let recursive = cpg.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            "demo_crate::walk",
            Some(SourceLoc::new("src/main.rs", 2)),
        );
        let sign = cpg.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            "rsa::pkcs1v15::SigningKey::sign",
            Some(SourceLoc::new("src/main.rs", 3)),
        );
        cpg.add_edge(keygen, recursive, EdgeKind::DataDep);
        cpg.add_edge(recursive, recursive, EdgeKind::ArgFlow);
        cpg.add_edge(recursive, recursive, EdgeKind::ReturnFlow);
        cpg.add_edge(recursive, sign, EdgeKind::DataDep);

        let reached = reached_lines(&cpg, node_id(&cpg, "RsaPrivateKey::new"));
        assert!(
            reached.contains(&"src/main.rs:3".to_string()),
            "{reached:?}"
        );
    }

    fn two_params(positions: bool) -> Cpg {
        use cpg_core::{AblationMode, CpgEdge, IrLayer, NodeKind};

        let mut cpg = Cpg::new(AblationMode::MirOnly);
        let mut node = |symbol: &str, line: u32| {
            cpg.add_node(
                IrLayer::Mir,
                NodeKind::CallSite,
                symbol,
                Some(SourceLoc::new("src/main.rs", line)),
            )
        };
        let keygen = node("rsa::RsaPrivateKey::new", 1);
        let label = node("demo_crate::label", 2);
        let site = node("demo_crate::f", 3);
        let use_key = node("demo_crate::use_key", 10);
        let use_label = node("demo_crate::use_label", 11);
        let sign_key = node("rsa::pkcs1v15::SigningKey::sign", 12);
        let sign_label = node("rsa::pkcs1v15::SigningKey::sign", 13);
        let args = |entries: Vec<(u8, u64)>| {
            if positions {
                ArgMap(entries)
            } else {
                ArgMap::default()
            }
        };
        let mut edge = |from, to, kind, entries| {
            cpg.add_edge_full(
                from,
                to,
                CpgEdge {
                    kind,
                    args: args(entries),
                },
            );
        };
        edge(
            keygen,
            site,
            EdgeKind::DataDep,
            vec![(ArgMap::RESULT, ArgMap::bit(0))],
        );
        edge(
            label,
            site,
            EdgeKind::DataDep,
            vec![(ArgMap::RESULT, ArgMap::bit(1))],
        );
        edge(site, use_key, EdgeKind::ArgFlow, vec![(0, ArgMap::bit(0))]);
        edge(
            site,
            use_label,
            EdgeKind::ArgFlow,
            vec![(1, ArgMap::bit(0))],
        );
        edge(
            use_key,
            sign_key,
            EdgeKind::DataDep,
            vec![(ArgMap::RESULT, ArgMap::bit(0))],
        );
        edge(
            use_label,
            sign_label,
            EdgeKind::DataDep,
            vec![(ArgMap::RESULT, ArgMap::bit(0))],
        );
        cpg
    }

    #[test]
    fn a_value_enters_a_callee_only_through_the_parameter_it_is_passed_as() {
        let cpg = two_params(true);
        let reached = reached_lines(&cpg, node_id(&cpg, "RsaPrivateKey::new"));
        assert!(
            reached.contains(&"src/main.rs:12".to_string()),
            "{reached:?}"
        );
        assert!(
            !reached.contains(&"src/main.rs:11".to_string())
                && !reached.contains(&"src/main.rs:13".to_string()),
            "the key reached the label's parameter: {reached:?}"
        );
    }

    #[test]
    fn an_edge_without_positions_is_every_argument() {
        let cpg = two_params(false);
        let reached = reached_lines(&cpg, node_id(&cpg, "RsaPrivateKey::new"));
        assert!(
            reached.contains(&"src/main.rs:12".to_string()),
            "{reached:?}"
        );
        assert!(
            reached.contains(&"src/main.rs:13".to_string()),
            "{reached:?}"
        );
    }

    #[test]
    fn the_error_path_is_recognised_in_both_layers_and_nothing_else() {
        assert!(is_error_path("std::ops::FromResidual::from_residual"));
        assert!(is_error_path(
            "<core::result::Result<(), anyhow::Error> as core::ops::try_trait::FromResidual<core::result::Result<core::convert::Infallible, std::io::Error>>>::from_residual"
        ));
        assert!(!is_error_path("std::ops::Try::branch"));
        assert!(!is_error_path("demo_crate::from_residual"));
        assert!(!is_error_path("std::ops::FromResidual::other"));
    }

    fn question_mark() -> Cpg {
        use cpg_core::{AblationMode, IrLayer, NodeKind};

        let mut cpg = Cpg::new(AblationMode::MirOnly);
        let mut node = |kind, symbol: &str, line: u32| {
            cpg.add_node(
                IrLayer::Mir,
                kind,
                symbol,
                Some(SourceLoc::new("src/main.rs", line)),
            )
        };
        let keygen = node(NodeKind::CallSite, "rsa::RsaPrivateKey::new", 1);
        let write = node(NodeKind::CallSite, "demo_crate::write", 2);
        let branch = node(NodeKind::TraitMethod, "std::ops::Try::branch", 2);
        let residual = node(
            NodeKind::TraitMethod,
            "std::ops::FromResidual::from_residual",
            2,
        );
        let use_n = node(NodeKind::CallSite, "rsa::pkcs1v15::SigningKey::sign", 3);
        let caller_site = node(NodeKind::CallSite, "demo_crate::f", 10);
        let caller_sink = node(NodeKind::CallSite, "rsa::pkcs1v15::SigningKey::sign", 11);
        cpg.add_edge(keygen, write, EdgeKind::DataDep);
        cpg.add_edge(write, branch, EdgeKind::DataDep);
        cpg.add_edge(branch, use_n, EdgeKind::DataDep);
        cpg.add_edge(branch, residual, EdgeKind::DataDep);
        cpg.add_edge(residual, caller_site, EdgeKind::ReturnFlow);
        cpg.add_edge(caller_site, caller_sink, EdgeKind::DataDep);
        cpg
    }

    #[test]
    fn a_value_does_not_travel_up_the_error_path_of_a_question_mark() {
        let cpg = question_mark();
        let reached = reached_lines(&cpg, node_id(&cpg, "RsaPrivateKey::new"));
        assert!(
            reached.contains(&"src/main.rs:3".to_string()),
            "success arm: {reached:?}"
        );
        assert!(
            !reached
                .iter()
                .any(|l| l.ends_with(":10") || l.ends_with(":11")),
            "error arm: {reached:?}"
        );
    }

    #[test]
    fn adjacency_only_follows_data_dep() {
        let cpg = Cpg::demo();
        let flow = data_dep_adjacency(&cpg);
        assert_eq!(flow.values().map(|v| v.len()).sum::<usize>(), 1);
    }
}
