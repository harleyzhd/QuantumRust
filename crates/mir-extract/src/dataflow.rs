use std::collections::{HashMap, HashSet, VecDeque};

use rustc_middle::mir::interpret::GlobalAlloc;
use rustc_middle::mir::visit::{PlaceContext, Visitor};
use rustc_middle::mir::{
    Body, BorrowKind, ConstOperand, Local, Location, Operand, Rvalue, StatementKind,
    TerminatorKind, UnwindAction, RETURN_PLACE,
};
use rustc_middle::ty::TyCtxt;

use cpg_core::{ArgMap, ConstArg};

use crate::reaching::{self, Block, Reaching, Step};

pub struct BodyFlow {
    reaching: Reaching,
    terminator_at: Vec<usize>,
    call_positions: HashMap<usize, Vec<usize>>,
    params: Vec<usize>,
}

pub struct CallFlow {
    pub def: Local,
    pub uses: Vec<Local>,
    pub positions: Vec<usize>,
}

impl BodyFlow {
    pub fn of(body: &Body<'_>) -> Self {
        let lent = mutable_loans(body);
        let blocks: Vec<Block> = body
            .basic_blocks
            .iter()
            .map(|data| {
                let mut steps: Vec<Step> = data
                    .statements
                    .iter()
                    .map(|statement| match &statement.kind {
                        StatementKind::Assign(assign) => {
                            let (place, rvalue) = &**assign;
                            let mut reads = LocalReads::default();
                            reads.visit_rvalue(rvalue, Location::START);
                            Step {
                                reads: reads.locals.iter().map(|l| l.as_usize()).collect(),
                                write: Some(place.local.as_usize()),
                                overwrites: place.projection.is_empty(),
                                also_writes: Vec::new(),
                            }
                        }
                        _ => Step::default(),
                    })
                    .collect();
                let (terminator_step, succs) = match &data.terminator {
                    Some(terminator) => terminator_step(&terminator.kind, &lent),
                    None => (Step::default(), Vec::new()),
                };
                steps.push(terminator_step);
                Block { steps, succs }
            })
            .collect();
        let params: Vec<usize> = body.args_iter().map(Local::as_usize).collect();
        let call_positions = body
            .basic_blocks
            .iter_enumerated()
            .filter_map(|(bb, data)| {
                let call = call_flow(&data.terminator.as_ref()?.kind)?;
                Some((bb.as_usize(), call.positions))
            })
            .collect();
        Self {
            reaching: reaching::analyse(&blocks, &params),
            terminator_at: body
                .basic_blocks
                .iter()
                .map(|d| d.statements.len())
                .collect(),
            call_positions,
            params,
        }
    }

    pub fn call_outputs(&self, bb: usize) -> Vec<usize> {
        let at = (bb, self.terminator_at[bb]);
        self.reaching
            .def_at
            .get(&at)
            .into_iter()
            .chain(self.reaching.side_defs.get(&at).into_iter().flatten())
            .copied()
            .collect()
    }

    pub fn call_inputs(&self, bb: usize) -> &[usize] {
        self.reaching
            .inputs
            .get(&(bb, self.terminator_at[bb]))
            .map_or(&[], Vec::as_slice)
    }

    pub fn call_arg_mask(&self, bb: usize, defs: &HashSet<usize>) -> u64 {
        let (Some(per_read), Some(positions)) = (
            self.reaching.read_inputs.get(&(bb, self.terminator_at[bb])),
            self.call_positions.get(&bb),
        ) else {
            return 0;
        };
        per_read
            .iter()
            .zip(positions)
            .filter(|(seen, _)| seen.iter().any(|def| defs.contains(def)))
            .fold(0, |mask, (_, &position)| mask | ArgMap::bit(position))
    }

    pub fn param_defs_by_position(&self) -> Vec<(usize, usize)> {
        self.params
            .iter()
            .enumerate()
            .filter_map(|(position, local)| Some((position, *self.reaching.entry.get(local)?)))
            .collect()
    }

    pub fn statement_def(&self, bb: usize, step: usize) -> Option<usize> {
        self.reaching.def_at.get(&(bb, step)).copied()
    }

    pub fn is_return(&self, def: usize) -> bool {
        self.reaching.defs[def].local == RETURN_PLACE.as_usize()
    }

    pub fn reach_until_redefined(&self, start: usize, barriers: &HashSet<usize>) -> HashSet<usize> {
        self.reach_from(&[start], barriers)
    }

    pub fn reach_from(&self, starts: &[usize], barriers: &HashSet<usize>) -> HashSet<usize> {
        let mut seen: HashSet<usize> = starts.iter().copied().collect();
        let mut queue: VecDeque<usize> = starts.iter().copied().collect();
        while let Some(def) = queue.pop_front() {
            for &next in &self.reaching.flow[def] {
                if !starts.contains(&next) && barriers.contains(&next) {
                    continue;
                }
                if seen.insert(next) {
                    queue.push_back(next);
                }
            }
        }
        seen
    }
}

fn terminator_step(
    kind: &TerminatorKind<'_>,
    lent: &HashMap<Local, Vec<Local>>,
) -> (Step, Vec<(usize, bool)>) {
    if let TerminatorKind::Call {
        destination,
        target,
        unwind,
        ..
    } = kind
    {
        let call = call_flow(kind).expect("a call terminator has a call flow");
        let mut also_writes: Vec<usize> = Vec::new();
        for local in call
            .uses
            .iter()
            .flat_map(|arg| lent.get(arg).into_iter().flatten())
        {
            if !also_writes.contains(&local.as_usize()) {
                also_writes.push(local.as_usize());
            }
        }
        let step = Step {
            reads: call.uses.iter().map(|l| l.as_usize()).collect(),
            write: Some(call.def.as_usize()),
            overwrites: destination.projection.is_empty(),
            also_writes,
        };
        let mut succs: Vec<(usize, bool)> = target.iter().map(|t| (t.as_usize(), true)).collect();
        if let UnwindAction::Cleanup(cleanup) = unwind {
            succs.push((cleanup.as_usize(), false));
        }
        return (step, succs);
    }
    let succs = kind.successors().map(|s| (s.as_usize(), true)).collect();
    (Step::default(), succs)
}

fn mutable_loans(body: &Body<'_>) -> HashMap<Local, Vec<Local>> {
    let mut lent: HashMap<Local, Vec<Local>> = HashMap::new();
    loop {
        let mut changed = false;
        for data in body.basic_blocks.iter() {
            for statement in &data.statements {
                let StatementKind::Assign(assign) = &statement.kind else {
                    continue;
                };
                let (place, rvalue) = &**assign;
                if !place.projection.is_empty() {
                    continue;
                }
                let sources: Vec<Local> = match rvalue {
                    Rvalue::Ref(_, BorrowKind::Mut { .. }, borrowed) => {
                        match lent.get(&borrowed.local) {
                            Some(inner) if !borrowed.projection.is_empty() => inner.clone(),
                            _ => vec![borrowed.local],
                        }
                    }
                    Rvalue::Use(Operand::Copy(from) | Operand::Move(from), _)
                        if from.projection.is_empty() =>
                    {
                        lent.get(&from.local).cloned().unwrap_or_default()
                    }
                    _ => continue,
                };
                let entry = lent.entry(place.local).or_default();
                for source in sources {
                    if !entry.contains(&source) {
                        entry.push(source);
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            return lent;
        }
    }
}

pub fn const_args(kind: &TerminatorKind<'_>) -> Vec<ConstArg> {
    let TerminatorKind::Call { args, .. } = kind else {
        return Vec::new();
    };
    args.iter()
        .enumerate()
        .filter_map(|(index, arg)| {
            let Operand::Constant(operand) = &arg.node else {
                return None;
            };
            let scalar = operand.const_.try_to_scalar_int()?;
            Some(ConstArg {
                index: index as u32,
                value: scalar.to_uint(scalar.size()),
            })
        })
        .collect()
}

pub struct StaticRefs {
    by_def: HashMap<usize, Vec<String>>,
}

impl StaticRefs {
    pub fn of<'tcx>(tcx: TyCtxt<'tcx>, body: &Body<'tcx>, flow: &BodyFlow) -> Self {
        let mut by_def: HashMap<usize, Vec<String>> = HashMap::new();
        for (bb, data) in body.basic_blocks.iter_enumerated() {
            for (step, statement) in data.statements.iter().enumerate() {
                let StatementKind::Assign(assign) = &statement.kind else {
                    continue;
                };
                let paths = static_paths(tcx, &assign.1);
                let Some(def) = flow.statement_def(bb.as_usize(), step) else {
                    continue;
                };
                for path in paths {
                    push_static(by_def.entry(def).or_default(), path);
                }
            }
        }

        for (seed, paths) in by_def.clone() {
            for reached in flow.reach_until_redefined(seed, &HashSet::new()) {
                for path in &paths {
                    push_static(by_def.entry(reached).or_default(), path.clone());
                }
            }
        }
        Self { by_def }
    }

    pub fn at_call(&self, flow: &BodyFlow, bb: usize) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for def in flow.call_inputs(bb) {
            for path in self.by_def.get(def).into_iter().flatten() {
                push_static(&mut out, path.clone());
            }
        }
        out
    }
}

fn push_static(out: &mut Vec<String>, path: String) {
    if !out.contains(&path) {
        out.push(path);
    }
}

fn static_paths<'tcx>(tcx: TyCtxt<'tcx>, rvalue: &Rvalue<'tcx>) -> Vec<String> {
    let mut constants: Vec<&ConstOperand<'tcx>> = Vec::new();
    match rvalue {
        Rvalue::Use(Operand::Constant(c), _) | Rvalue::Cast(_, Operand::Constant(c), _) => {
            constants.push(c)
        }
        Rvalue::Aggregate(_, operands) => constants.extend(
            operands
                .iter()
                .filter_map(|op| match op {
                    Operand::Constant(c) => Some(&**c),
                    _ => None,
                })
                .map(|c| c as &ConstOperand<'tcx>),
        ),
        _ => {}
    }

    constants
        .into_iter()
        .filter_map(|constant| {
            let scalar = constant.const_.try_to_scalar()?;
            let pointer = scalar.to_pointer(&tcx).discard_err()?;
            let provenance = pointer.provenance?;
            match tcx.global_alloc(provenance.alloc_id()) {
                GlobalAlloc::Static(def_id) => Some(tcx.def_path_str(def_id)),
                _ => None,
            }
        })
        .collect()
}

pub fn call_flow(kind: &TerminatorKind<'_>) -> Option<CallFlow> {
    let TerminatorKind::Call {
        args, destination, ..
    } = kind
    else {
        return None;
    };
    let (positions, uses) = args
        .iter()
        .enumerate()
        .filter_map(|(position, arg)| match &arg.node {
            Operand::Copy(place) | Operand::Move(place) => Some((position, place.local)),
            Operand::Constant(_) | Operand::RuntimeChecks(_) => None,
        })
        .unzip();
    Some(CallFlow {
        def: destination.local,
        uses,
        positions,
    })
}

#[derive(Default)]
struct LocalReads {
    locals: Vec<Local>,
}

impl<'tcx> Visitor<'tcx> for LocalReads {
    fn visit_local(&mut self, local: Local, _context: PlaceContext, _location: Location) {
        self.locals.push(local);
    }
}
