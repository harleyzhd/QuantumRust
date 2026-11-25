use std::collections::{BTreeSet, HashMap, HashSet};

use rustc_middle::mir::visit::{MutatingUseContext, PlaceContext, Visitor};
use rustc_middle::mir::{
    Body, CastKind, Local, Location, Operand, Place, Rvalue, StatementKind, TerminatorKind,
};
use rustc_middle::ty::adjustment::PointerCoercion;
use rustc_middle::ty::print::with_no_trimmed_paths;
use rustc_middle::ty::{self, Ty, TyCtxt};
use rustc_span::def_id::DefId;
use rustc_span::Span;

use cpg_core::{Cpg, EdgeKind, IrLayer, NodeIndex, NodeKind, SafetyCtx};

use crate::extract::{callee_kind_and_symbol, resolution, source_loc, type_args};

pub struct FnRefSite {
    pub node: NodeIndex,
    pub target: DefId,
}

#[derive(Default)]
pub struct BodyRefs {
    pub sites: Vec<FnRefSite>,
    by_statement: HashMap<(usize, usize), usize>,
}

pub fn references<'tcx>(
    tcx: TyCtxt<'tcx>,
    cpg: &mut Cpg,
    body: &Body<'tcx>,
    container: Option<NodeIndex>,
) -> BodyRefs {
    let mut refs = BodyRefs::default();
    for (bb, data) in body.basic_blocks.iter_enumerated() {
        for (index, statement) in data.statements.iter().enumerate() {
            let StatementKind::Assign(assign) = &statement.kind else {
                continue;
            };
            let rvalue = &assign.1;
            let span = statement.source_info.span;
            match rvalue {
                Rvalue::Cast(
                    CastKind::PointerCoercion(
                        PointerCoercion::ReifyFnPointer(_) | PointerCoercion::ClosureFnPointer(_),
                        _,
                    ),
                    operand,
                    pointer,
                ) => {
                    let Some(target) = function_of(operand.ty(&body.local_decls, tcx)) else {
                        continue;
                    };
                    let sig = pointer.fn_sig(tcx);
                    let node = add_ref(tcx, cpg, target, sig, span, container);
                    refs.by_statement
                        .insert((bb.as_usize(), index), refs.sites.len());
                    refs.sites.push(FnRefSite {
                        node,
                        target: target.0,
                    });
                }
                Rvalue::Use(operand, ..) => {
                    refs.items(tcx, cpg, body, [operand], span, container);
                }
                Rvalue::Aggregate(_, operands) => {
                    refs.items(tcx, cpg, body, operands.iter(), span, container);
                }
                _ => {}
            }
        }
        if let Some(terminator) = &data.terminator {
            if let TerminatorKind::Call { args, .. } = &terminator.kind {
                let span = terminator.source_info.span;
                refs.items(
                    tcx,
                    cpg,
                    body,
                    args.iter().map(|a| &a.node),
                    span,
                    container,
                );
            }
        }
    }
    refs
}

impl BodyRefs {
    fn items<'a, 'tcx: 'a>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        cpg: &mut Cpg,
        body: &Body<'tcx>,
        operands: impl IntoIterator<Item = &'a Operand<'tcx>>,
        span: Span,
        container: Option<NodeIndex>,
    ) {
        for operand in operands {
            let Operand::Constant(_) = operand else {
                continue;
            };
            let ty = operand.ty(&body.local_decls, tcx);
            if !matches!(ty.kind(), ty::FnDef(..)) {
                continue;
            }
            let Some(target) = function_of(ty) else {
                continue;
            };
            let node = add_ref(tcx, cpg, target, ty.fn_sig(tcx), span, container);
            self.sites.push(FnRefSite {
                node,
                target: target.0,
            });
        }
    }

    pub fn local(&self) -> impl Iterator<Item = (NodeIndex, DefId)> + '_ {
        self.sites
            .iter()
            .filter(|site| site.target.is_local())
            .map(|site| (site.node, site.target))
    }
}

fn function_of(ty: Ty<'_>) -> Option<(DefId, ty::GenericArgsRef<'_>, bool)> {
    match ty.kind() {
        ty::FnDef(def, args) => Some((*def, args, false)),
        ty::Closure(def, args) => Some((*def, args, true)),
        _ => None,
    }
}

fn add_ref<'tcx>(
    tcx: TyCtxt<'tcx>,
    cpg: &mut Cpg,
    (def, args, is_closure): (DefId, ty::GenericArgsRef<'tcx>, bool),
    sig: ty::PolyFnSig<'tcx>,
    span: Span,
    container: Option<NodeIndex>,
) -> NodeIndex {
    let (symbol, canonical) = if is_closure {
        (tcx.def_path_str(def), None)
    } else {
        (
            callee_kind_and_symbol(tcx, def, args).1,
            resolution(tcx, def, args).map(|r| r.canonical),
        )
    };
    let safety = if tcx.is_foreign_item(def) {
        SafetyCtx::Ffi
    } else {
        SafetyCtx::Safe
    };
    let node = cpg.add_node_full(
        IrLayer::Mir,
        NodeKind::FnRef,
        symbol,
        canonical,
        source_loc(tcx, span),
        safety,
    );
    if !is_closure {
        cpg.set_type_args(node, type_args(tcx, args));
    }
    cpg.set_fn_sig(node, render_fn_sig(tcx, sig));
    if let Some(container) = container {
        cpg.add_edge(container, node, EdgeKind::Contains);
    }
    node
}

pub fn render_fn_sig<'tcx>(tcx: TyCtxt<'tcx>, sig: ty::PolyFnSig<'tcx>) -> String {
    let sig = tcx.instantiate_bound_regions_with_erased(sig);
    let sig = tcx.erase_and_anonymize_regions(sig);
    with_no_trimmed_paths!(Ty::new_fn_ptr(tcx, ty::Binder::dummy(sig)).to_string())
}

pub fn indirect_call<'tcx>(
    tcx: TyCtxt<'tcx>,
    cpg: &mut Cpg,
    body: &Body<'tcx>,
    func: &Operand<'tcx>,
    span: Span,
) -> NodeIndex {
    let ty = func.ty(&body.local_decls, tcx);
    let sig = matches!(ty.kind(), ty::FnPtr(..)).then(|| render_fn_sig(tcx, ty.fn_sig(tcx)));
    let node = cpg.add_node_full(
        IrLayer::Mir,
        NodeKind::IndirectCall,
        format!("<indirect {}>", sig.as_deref().unwrap_or("fn")),
        None,
        source_loc(tcx, span),
        SafetyCtx::Safe,
    );
    if let Some(sig) = sig {
        cpg.set_fn_sig(node, sig);
    }
    node
}

pub fn resolve(body: &Body<'_>, func: &Operand<'_>, refs: &BodyRefs) -> Option<Vec<usize>> {
    let place = func.place()?;
    if !place.projection.is_empty() {
        return None;
    }
    let writes = Writes::of(body);
    let params: HashSet<Local> = body.args_iter().collect();
    let mut found: BTreeSet<usize> = BTreeSet::new();
    let mut seen: HashSet<Local> = HashSet::new();
    let mut pending = vec![place.local];
    while let Some(local) = pending.pop() {
        if !seen.insert(local) {
            continue;
        }
        if params.contains(&local) || writes.untracked.contains(&local) {
            return None;
        }
        for &(at, rvalue) in writes.assigned.get(&local)? {
            match rvalue {
                Rvalue::Cast(..) => found.insert(*refs.by_statement.get(&at)?),
                Rvalue::Use(Operand::Copy(from) | Operand::Move(from), ..)
                    if from.projection.is_empty() =>
                {
                    pending.push(from.local);
                    true
                }
                _ => return None,
            };
        }
    }
    (!found.is_empty()).then(|| found.into_iter().collect())
}

type Assignment<'a, 'tcx> = ((usize, usize), &'a Rvalue<'tcx>);

struct Writes<'a, 'tcx> {
    assigned: HashMap<Local, Vec<Assignment<'a, 'tcx>>>,
    untracked: HashSet<Local>,
}

impl<'a, 'tcx> Writes<'a, 'tcx> {
    fn of(body: &'a Body<'tcx>) -> Self {
        let mut this = Self {
            assigned: HashMap::new(),
            untracked: HashSet::new(),
        };
        for (bb, data) in body.basic_blocks.iter_enumerated() {
            for (index, statement) in data.statements.iter().enumerate() {
                if let StatementKind::Assign(assign) = &statement.kind {
                    let (place, rvalue) = &**assign;
                    if place.projection.is_empty() {
                        this.assigned
                            .entry(place.local)
                            .or_default()
                            .push(((bb.as_usize(), index), rvalue));
                    }
                }
            }
        }
        let mut untracked = Untracked::default();
        untracked.visit_body(body);
        this.untracked = untracked.locals;
        this
    }
}

#[derive(Default)]
struct Untracked {
    locals: HashSet<Local>,
}

impl<'tcx> Visitor<'tcx> for Untracked {
    fn visit_local(&mut self, local: Local, context: PlaceContext, _location: Location) {
        match context {
            PlaceContext::MutatingUse(MutatingUseContext::Store) => {}
            PlaceContext::MutatingUse(_) => {
                self.locals.insert(local);
            }
            _ => {}
        }
    }

    fn visit_place(&mut self, place: &Place<'tcx>, context: PlaceContext, location: Location) {
        if !place.projection.is_empty() && context.is_mutating_use() {
            self.locals.insert(place.local);
        }
        self.super_place(place, context, location);
    }
}
