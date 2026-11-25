use std::collections::{HashMap, VecDeque};

use rustc_middle::ty::{self, TyCtxt, TypeVisitableExt};
use rustc_span::def_id::DefId;

use cpg_core::{Cpg, DescentPlan, IrLayer, NodeIndex, NodeKind};

use crate::extract::{
    demangle_like_llvm, fn_safety, link_call, source_loc, walk_body, FnInterface, TraitResolution,
    WalkCtx,
};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Target<'tcx> {
    Mono(ty::Instance<'tcx>),
    Poly(DefId),
}

impl Target<'_> {
    fn def_id(self) -> DefId {
        match self {
            Self::Mono(i) => i.def_id(),
            Self::Poly(d) => d,
        }
    }
}

fn target_of<'tcx>(
    tcx: TyCtxt<'tcx>,
    def: DefId,
    args: ty::GenericArgsRef<'tcx>,
) -> Option<Target<'tcx>> {
    if args.has_non_region_param() {
        return Some(Target::Poly(def));
    }
    let instance = ty::Instance::try_resolve(tcx, ty::TypingEnv::fully_monomorphized(), def, args)
        .ok()
        .flatten()?;
    matches!(instance.def, ty::InstanceKind::Item(_)).then_some(Target::Mono(instance))
}

pub(crate) fn descend<'tcx>(
    tcx: TyCtxt<'tcx>,
    cpg: &mut Cpg,
    plan: &DescentPlan,
    seeds: Vec<(NodeIndex, DefId, ty::GenericArgsRef<'tcx>)>,
    resolved_traits: &mut Vec<TraitResolution>,
    local_refs: &mut Vec<(NodeIndex, DefId)>,
) -> Vec<(NodeIndex, DefId)> {
    let descendable = |def: DefId| plan.crates.contains(tcx.crate_name(def.krate).as_str());
    let mut walked: HashMap<Target<'tcx>, FnInterface> = HashMap::new();
    let mut queue: VecDeque<(NodeIndex, Target<'tcx>, u8)> = VecDeque::new();
    let mut back_into_local = Vec::new();
    for (call, def, args) in seeds {
        if let Some(t) = target_of(tcx, def, args).filter(|t| descendable(t.def_id())) {
            queue.push_back((call, t, 1));
        }
    }
    while let Some((call, target, depth)) = queue.pop_front() {
        if let Some(interface) = walked.get(&target) {
            link_call(cpg, call, interface);
            continue;
        }
        let def = target.def_id();
        if !tcx.is_mir_available(def) {
            tracing::debug!(callee = %tcx.def_path_str(def), "no MIR to descend into");
            continue;
        }
        let (body, ctx, symbol) = match target {
            Target::Mono(instance) => (
                tcx.instance_mir(instance.def),
                WalkCtx {
                    instance: Some(instance),
                },
                demangle_like_llvm(tcx.symbol_name(instance).name),
            ),
            Target::Poly(def) => {
                tracing::info!(callee = %tcx.def_path_str(def), "descending polymorphically");
                (
                    tcx.optimized_mir(def),
                    WalkCtx::default(),
                    tcx.def_path_str(def),
                )
            }
        };
        let first = cpg.next_id();
        let fn_node = cpg.add_node_full(
            IrLayer::Mir,
            NodeKind::Function,
            symbol.clone(),
            Some(symbol.clone()),
            source_loc(tcx, tcx.def_span(def)),
            fn_safety(tcx, def),
        );
        let w = walk_body(
            tcx,
            cpg,
            fn_node,
            &symbol,
            body,
            &ctx,
            resolved_traits,
            local_refs,
        );
        cpg.mark_dep_depth_from(first, depth);
        link_call(cpg, call, &w.interface);
        walked.insert(target, w.interface);
        back_into_local.extend(w.local_calls);
        if depth < plan.depth {
            for (inner, def, args) in w.foreign_calls {
                if let Some(t) = target_of(tcx, def, args).filter(|t| descendable(t.def_id())) {
                    queue.push_back((inner, t, depth + 1));
                }
            }
        }
    }
    back_into_local
}
