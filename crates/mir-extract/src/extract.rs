use std::collections::{BTreeMap, HashMap, HashSet};

use rustc_driver::{Callbacks, Compilation};
use rustc_interface::interface::Compiler;
use rustc_middle::mir::{Body, TerminatorKind};
use rustc_middle::ty::{self, TyCtxt, TypeVisitableExt};
use rustc_span::def_id::{DefId, LOCAL_CRATE};
use rustc_span::Span;

use cpg_core::{
    AblationMode, ArgMap, Cpg, CpgEdge, EdgeKind, IrLayer, NodeIndex, NodeKind, SafetyCtx,
    SourceLoc,
};

use crate::dataflow::{const_args, BodyFlow, StaticRefs};
use crate::fnptr;

#[derive(Default)]
pub struct ExtractCallbacks {
    pub cpg: Option<Cpg>,
}

impl Callbacks for ExtractCallbacks {
    fn after_analysis(&mut self, _compiler: &Compiler, tcx: TyCtxt<'_>) -> Compilation {
        self.cpg = Some(build_cpg(tcx));
        Compilation::Continue
    }
}

pub(crate) struct FnInterface {
    pub(crate) fn_node: NodeIndex,
    pub(crate) param_calls: Vec<(NodeIndex, ArgMap)>,
    pub(crate) return_calls: Vec<NodeIndex>,
}

#[derive(Default)]
pub(crate) struct WalkCtx<'tcx> {
    pub(crate) instance: Option<ty::Instance<'tcx>>,
}

pub(crate) struct Walked<'tcx> {
    pub(crate) interface: FnInterface,
    pub(crate) local_calls: Vec<(NodeIndex, DefId)>,
    pub(crate) foreign_calls: Vec<(NodeIndex, DefId, ty::GenericArgsRef<'tcx>)>,
}

pub fn build_cpg(tcx: TyCtxt<'_>) -> Cpg {
    let mut cpg = Cpg::new(AblationMode::MirOnly);
    let crate_name = tcx.crate_name(LOCAL_CRATE);
    let descent = cpg_core::DescentPlan::from_env();
    let mut interfaces: HashMap<DefId, FnInterface> = HashMap::new();
    let mut local_calls: Vec<(NodeIndex, DefId)> = Vec::new();
    let mut resolved_traits: Vec<TraitResolution> = Vec::new();
    let mut local_refs: Vec<(NodeIndex, DefId)> = Vec::new();
    let mut seeds = Vec::new();

    for local_def in tcx.hir_body_owners() {
        let def_id = local_def.to_def_id();
        if is_initialiser(tcx, def_id) {
            let refs = fnptr::references(tcx, &mut cpg, tcx.mir_for_ctfe(def_id), None);
            local_refs.extend(refs.local());
            continue;
        }
        if !tcx.def_kind(def_id).is_fn_like() || !tcx.is_mir_available(def_id) {
            continue;
        }
        let fn_symbol = format!("{crate_name}::{}", tcx.def_path_str(def_id));
        let fn_node = cpg.add_node_full(
            IrLayer::Mir,
            NodeKind::Function,
            fn_symbol.clone(),
            canonical_definition(tcx, def_id),
            source_loc(tcx, tcx.def_span(def_id)),
            fn_safety(tcx, def_id),
        );

        let body = tcx.optimized_mir(def_id);
        let walked = walk_body(
            tcx,
            &mut cpg,
            fn_node,
            &fn_symbol,
            body,
            &WalkCtx::default(),
            &mut resolved_traits,
            &mut local_refs,
        );
        interfaces.insert(def_id, walked.interface);
        local_calls.extend(walked.local_calls);
        seeds.extend(walked.foreign_calls);
        for promoted in tcx.promoted_mir(def_id).iter() {
            let refs = fnptr::references(tcx, &mut cpg, promoted, Some(fn_node));
            local_refs.extend(refs.local());
        }
    }

    link_local_calls(&mut cpg, &interfaces, &local_calls);
    if let Some(plan) = &descent {
        let back = crate::descent::descend(
            tcx,
            &mut cpg,
            plan,
            seeds,
            &mut resolved_traits,
            &mut local_refs,
        );
        link_local_calls(&mut cpg, &interfaces, &back);
    }
    link_local_refs(&mut cpg, &interfaces, &local_refs);
    link_trait_resolutions(&mut cpg, &resolved_traits);
    cpg
}

fn is_initialiser(tcx: TyCtxt<'_>, def_id: DefId) -> bool {
    use rustc_hir::def::DefKind;
    matches!(
        tcx.def_kind(def_id),
        DefKind::Static { .. }
            | DefKind::Const { .. }
            | DefKind::AssocConst { .. }
            | DefKind::InlineConst
    )
}

fn link_local_refs(
    cpg: &mut Cpg,
    interfaces: &HashMap<DefId, FnInterface>,
    local_refs: &[(NodeIndex, DefId)],
) {
    for (reference, function) in local_refs {
        if let Some(interface) = interfaces.get(function) {
            cpg.add_edge(*reference, interface.fn_node, EdgeKind::Call);
        }
    }
}

fn link_local_calls(
    cpg: &mut Cpg,
    interfaces: &HashMap<DefId, FnInterface>,
    local_calls: &[(NodeIndex, DefId)],
) {
    for (call_node, callee) in local_calls {
        if let Some(interface) = interfaces.get(callee) {
            link_call(cpg, *call_node, interface);
        }
    }
}

pub(crate) fn link_call(cpg: &mut Cpg, call: NodeIndex, interface: &FnInterface) {
    cpg.add_edge(call, interface.fn_node, EdgeKind::Call);
    for (inner, args) in &interface.param_calls {
        cpg.add_edge_full(
            call,
            *inner,
            CpgEdge {
                kind: EdgeKind::ArgFlow,
                args: args.clone(),
            },
        );
    }
    for inner in &interface.return_calls {
        cpg.add_edge(*inner, call, EdgeKind::ReturnFlow);
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn walk_body<'tcx>(
    tcx: TyCtxt<'tcx>,
    cpg: &mut Cpg,
    fn_node: NodeIndex,
    fn_symbol: &str,
    body: &Body<'tcx>,
    ctx: &WalkCtx<'tcx>,
    resolved_traits: &mut Vec<TraitResolution>,
    local_refs: &mut Vec<(NodeIndex, DefId)>,
) -> Walked<'tcx> {
    let mut call_nodes: BTreeMap<usize, NodeIndex> = BTreeMap::new();
    let mut pred_nodes: Vec<(NodeIndex, Vec<usize>)> = Vec::new();
    let mut local_calls: Vec<(NodeIndex, DefId)> = Vec::new();
    let mut foreign_calls: Vec<(NodeIndex, DefId, ty::GenericArgsRef<'tcx>)> = Vec::new();
    let body_flow = BodyFlow::of(body);
    let static_refs = StaticRefs::of(tcx, body, &body_flow);
    let fn_refs = fnptr::references(tcx, cpg, body, Some(fn_node));
    local_refs.extend(fn_refs.local());

    for (bb, data) in body.basic_blocks.iter_enumerated() {
        let Some(terminator) = &data.terminator else {
            continue;
        };
        match &terminator.kind {
            TerminatorKind::Call { func, fn_span, .. } => {
                let span = call_span(tcx, terminator.source_info.span, *fn_span);
                let direct =
                    func.const_fn_def()
                        .or_else(|| match func.ty(&body.local_decls, tcx).kind() {
                            ty::FnDef(def, args) => Some((*def, *args)),
                            _ => None,
                        });
                let Some((callee, generic_args)) = direct else {
                    let node = fnptr::indirect_call(tcx, cpg, body, func, span);
                    cpg.add_edge(fn_node, node, EdgeKind::Contains);
                    cpg.add_edge(fn_node, node, EdgeKind::Call);
                    call_nodes.insert(bb.as_usize(), node);
                    for site in fnptr::resolve(body, func, &fn_refs)
                        .into_iter()
                        .flatten()
                        .map(|i| &fn_refs.sites[i])
                    {
                        if site.target.is_local() {
                            local_calls.push((node, site.target));
                        } else {
                            cpg.add_edge(node, site.node, EdgeKind::Call);
                        }
                    }
                    continue;
                };
                let generic_args = match ctx.instance {
                    Some(instance) => instance.instantiate_mir_and_normalize_erasing_regions(
                        tcx,
                        ty::TypingEnv::fully_monomorphized(),
                        ty::EarlyBinder::bind(generic_args),
                    ),
                    None => generic_args,
                };
                let (kind, symbol) = callee_kind_and_symbol(tcx, callee, generic_args);
                let safety = if tcx.is_foreign_item(callee) {
                    SafetyCtx::Ffi
                } else {
                    SafetyCtx::Safe
                };
                let resolved = resolution(tcx, callee, generic_args);
                let is_trait_method = kind == NodeKind::TraitMethod;
                let node = cpg.add_node_full(
                    IrLayer::Mir,
                    kind,
                    symbol,
                    resolved.as_ref().map(|r| r.canonical.clone()),
                    source_loc(tcx, span),
                    safety,
                );
                if is_trait_method {
                    if let Some(r) = resolved.filter(|r| !r.canonical.starts_with("<dyn ")) {
                        resolved_traits.push(TraitResolution {
                            call: node,
                            impl_path: r.canonical.clone(),
                            impl_canonical: r.canonical,
                        });
                    }
                }
                cpg.set_const_args(node, const_args(&terminator.kind));
                cpg.set_type_args(node, type_args(tcx, generic_args));
                cpg.set_static_args(node, static_refs.at_call(&body_flow, bb.as_usize()));
                cpg.add_edge(fn_node, node, EdgeKind::Contains);
                cpg.add_edge(fn_node, node, EdgeKind::Call);
                call_nodes.insert(bb.as_usize(), node);
                if callee.is_local() {
                    local_calls.push((node, callee));
                } else {
                    foreign_calls.push((node, callee, generic_args));
                }
            }
            TerminatorKind::SwitchInt { targets, .. } => {
                let node = cpg.add_node(
                    IrLayer::Mir,
                    NodeKind::Predicate,
                    format!("{fn_symbol}::{{bb{}}}", bb.as_usize()),
                    source_loc(tcx, terminator.source_info.span),
                );
                cpg.add_edge(fn_node, node, EdgeKind::Contains);
                let succs = targets.all_targets().iter().map(|t| t.as_usize()).collect();
                pred_nodes.push((node, succs));
            }
            _ => {}
        }
    }

    for (pred, succs) in &pred_nodes {
        for succ in succs {
            if let Some(call) = call_nodes.get(succ) {
                cpg.add_edge(*pred, *call, EdgeKind::ControlDep);
                cpg.add_edge(*pred, *call, EdgeKind::ControlFlow);
            }
        }
    }

    let barriers: HashSet<usize> = call_nodes
        .keys()
        .flat_map(|&bb| body_flow.call_outputs(bb))
        .collect();
    for (&src_bb, src_node) in &call_nodes {
        let outputs = body_flow.call_outputs(src_bb);
        if outputs.is_empty() {
            continue;
        }
        let reachable = body_flow.reach_from(&outputs, &barriers);
        for (&dst_bb, dst_node) in &call_nodes {
            if src_bb == dst_bb {
                continue;
            }
            let mask = body_flow.call_arg_mask(dst_bb, &reachable);
            if mask != 0 {
                cpg.add_edge_full(
                    *src_node,
                    *dst_node,
                    CpgEdge {
                        kind: EdgeKind::DataDep,
                        args: ArgMap::from_result(mask),
                    },
                );
            }
        }
    }

    let interface = FnInterface {
        fn_node,
        param_calls: param_consuming_calls(&body_flow, &barriers, &call_nodes),
        return_calls: return_producing_calls(&body_flow, &barriers, &call_nodes),
    };
    for (call, args) in &interface.param_calls {
        cpg.add_edge_full(
            fn_node,
            *call,
            CpgEdge {
                kind: EdgeKind::ArgFlow,
                args: args.clone(),
            },
        );
    }
    for call in &interface.return_calls {
        cpg.add_edge(*call, fn_node, EdgeKind::ReturnFlow);
    }
    Walked {
        interface,
        local_calls,
        foreign_calls,
    }
}

fn param_consuming_calls(
    body_flow: &BodyFlow,
    barriers: &HashSet<usize>,
    call_nodes: &BTreeMap<usize, NodeIndex>,
) -> Vec<(NodeIndex, ArgMap)> {
    let reach: Vec<(usize, HashSet<usize>)> = body_flow
        .param_defs_by_position()
        .into_iter()
        .map(|(position, def)| (position, body_flow.reach_until_redefined(def, barriers)))
        .collect();
    call_nodes
        .iter()
        .filter_map(|(&bb, node)| {
            let entries: Vec<(u8, u64)> = reach
                .iter()
                .map(|(position, defs)| (ArgMap::key(*position), body_flow.call_arg_mask(bb, defs)))
                .filter(|(_, mask)| *mask != 0)
                .collect();
            (!entries.is_empty()).then_some((*node, ArgMap(entries)))
        })
        .collect()
}

fn return_producing_calls(
    body_flow: &BodyFlow,
    barriers: &HashSet<usize>,
    call_nodes: &BTreeMap<usize, NodeIndex>,
) -> Vec<NodeIndex> {
    call_nodes
        .iter()
        .filter(|(&bb, _)| {
            body_flow
                .reach_from(&body_flow.call_outputs(bb), barriers)
                .into_iter()
                .any(|reached| body_flow.is_return(reached))
        })
        .map(|(_, node)| *node)
        .collect()
}

pub(crate) fn callee_kind_and_symbol(
    tcx: TyCtxt<'_>,
    callee: DefId,
    generic_args: ty::GenericArgsRef<'_>,
) -> (NodeKind, String) {
    if let Some(trait_did) = tcx.trait_of_assoc(callee) {
        let is_dyn = generic_args
            .types()
            .next()
            .is_some_and(|self_ty| matches!(self_ty.kind(), ty::Dynamic(..)));
        if is_dyn {
            return (
                NodeKind::TraitMethod,
                format!(
                    "<dyn {}>::{}",
                    tcx.def_path_str(trait_did),
                    tcx.item_name(callee)
                ),
            );
        }
        return (NodeKind::TraitMethod, tcx.def_path_str(callee));
    }
    (NodeKind::CallSite, tcx.def_path_str(callee))
}

pub(crate) fn type_args<'tcx>(
    tcx: TyCtxt<'tcx>,
    generic_args: ty::GenericArgsRef<'tcx>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for arg in generic_args.iter() {
        for inner in arg.walk() {
            let Some(ty) = inner.as_type() else {
                continue;
            };
            if let ty::Adt(def, _) = ty.kind() {
                let path = tcx.def_path_str(def.did());
                if !out.contains(&path) {
                    out.push(path);
                }
            }
        }
    }
    out
}

pub struct TraitResolution {
    call: NodeIndex,
    impl_path: String,
    impl_canonical: String,
}

fn link_trait_resolutions(cpg: &mut Cpg, resolved: &[TraitResolution]) -> usize {
    let mut by_canonical: HashMap<&str, NodeIndex> = HashMap::new();
    for node in cpg.nodes() {
        if node.kind == NodeKind::Function {
            if let Some(key) = node.canonical.as_deref() {
                by_canonical
                    .entry(key)
                    .or_insert_with(|| NodeIndex::from(node.id));
            }
        }
    }
    let existing: HashMap<String, NodeIndex> = by_canonical
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

    let mut stubs: HashMap<String, NodeIndex> = HashMap::new();
    let mut added = 0;
    for r in resolved {
        let target = existing
            .get(&r.impl_canonical)
            .copied()
            .or_else(|| stubs.get(&r.impl_canonical).copied())
            .unwrap_or_else(|| {
                let node = cpg.add_node_full(
                    IrLayer::Mir,
                    NodeKind::Function,
                    r.impl_path.clone(),
                    Some(r.impl_canonical.clone()),
                    None,
                    SafetyCtx::Safe,
                );
                stubs.insert(r.impl_canonical.clone(), node);
                node
            });
        cpg.add_edge(r.call, target, EdgeKind::TraitResolve);
        added += 1;
    }
    added
}

pub(crate) struct Resolution {
    pub(crate) canonical: String,
}

pub(crate) fn resolution<'tcx>(
    tcx: TyCtxt<'tcx>,
    callee: DefId,
    generic_args: ty::GenericArgsRef<'tcx>,
) -> Option<Resolution> {
    if generic_args.has_non_region_param() {
        return None;
    }
    let instance = ty::Instance::try_resolve(
        tcx,
        ty::TypingEnv::fully_monomorphized(),
        callee,
        generic_args,
    )
    .ok()
    .flatten()?;
    let mangled = tcx.symbol_name(instance).name.to_string();
    Some(Resolution {
        canonical: demangle_like_llvm(&mangled),
    })
}

fn canonical_definition(tcx: TyCtxt<'_>, def_id: DefId) -> Option<String> {
    if tcx.generics_of(def_id).count() > 0 {
        return None;
    }
    let mangled = tcx
        .symbol_name(ty::Instance::mono(tcx, def_id))
        .name
        .to_string();
    Some(demangle_like_llvm(&mangled))
}

pub(crate) fn demangle_like_llvm(mangled: &str) -> String {
    match rustc_demangle::try_demangle(mangled) {
        Ok(demangled) => format!("{demangled:#}"),
        Err(_) => mangled.to_string(),
    }
}

pub(crate) fn fn_safety(tcx: TyCtxt<'_>, def_id: DefId) -> SafetyCtx {
    use rustc_hir::def::DefKind;
    if !matches!(tcx.def_kind(def_id), DefKind::Fn | DefKind::AssocFn) {
        return SafetyCtx::Safe;
    }
    match tcx.fn_sig(def_id).skip_binder().safety() {
        rustc_hir::Safety::Unsafe => SafetyCtx::Unsafe,
        rustc_hir::Safety::Safe => SafetyCtx::Safe,
    }
}

fn call_span(tcx: TyCtxt<'_>, span: Span, fn_span: Span) -> Span {
    let sm = tcx.sess.source_map();
    if span.is_dummy()
        || fn_span.is_dummy()
        || sm.lookup_source_file_idx(fn_span.lo()) != sm.lookup_source_file_idx(span.lo())
    {
        return span;
    }
    fn_span
}

pub(crate) fn source_loc(tcx: TyCtxt<'_>, span: Span) -> Option<SourceLoc> {
    if span.is_dummy() {
        return None;
    }
    let sm = tcx.sess.source_map();
    let loc = sm.lookup_char_pos(span.lo());
    let file = loc
        .file
        .name
        .clone()
        .into_local_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| {
            loc.file
                .name
                .display(rustc_span::RemapPathScopeComponents::DIAGNOSTICS)
                .to_string()
        });
    Some(SourceLoc::new(file, loc.line as u32))
}
