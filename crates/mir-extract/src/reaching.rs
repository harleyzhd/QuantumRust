use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct Step {
    pub reads: Vec<usize>,
    pub write: Option<usize>,
    pub overwrites: bool,
    pub also_writes: Vec<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct Block {
    pub steps: Vec<Step>,
    pub succs: Vec<(usize, bool)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Site {
    Entry,
    Step { block: usize, step: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Def {
    pub local: usize,
    pub site: Site,
}

#[derive(Debug, Default)]
pub struct Reaching {
    pub defs: Vec<Def>,
    pub flow: Vec<Vec<usize>>,
    pub inputs: HashMap<(usize, usize), Vec<usize>>,
    pub read_inputs: HashMap<(usize, usize), Vec<Vec<usize>>>,
    pub def_at: HashMap<(usize, usize), usize>,
    pub side_defs: HashMap<(usize, usize), Vec<usize>>,
    pub entry: HashMap<usize, usize>,
}

#[must_use]
pub fn analyse(blocks: &[Block], params: &[usize]) -> Reaching {
    let mut out = Reaching::default();
    for &param in params {
        out.entry.insert(param, out.defs.len());
        out.defs.push(Def {
            local: param,
            site: Site::Entry,
        });
    }
    for (b, block) in blocks.iter().enumerate() {
        for (s, step) in block.steps.iter().enumerate() {
            if let Some(local) = step.write {
                out.def_at.insert((b, s), out.defs.len());
                out.defs.push(Def {
                    local,
                    site: Site::Step { block: b, step: s },
                });
            }
            for &local in &step.also_writes {
                out.side_defs
                    .entry((b, s))
                    .or_default()
                    .push(out.defs.len());
                out.defs.push(Def {
                    local,
                    site: Site::Step { block: b, step: s },
                });
            }
        }
    }
    out.flow = vec![Vec::new(); out.defs.len()];

    let mut by_local: HashMap<usize, Vec<usize>> = HashMap::new();
    for (index, def) in out.defs.iter().enumerate() {
        by_local.entry(def.local).or_default().push(index);
    }

    let side_defs = out.side_defs.clone();
    let weak = |state: &mut Bits, b: usize, s: usize| {
        for &def in side_defs.get(&(b, s)).into_iter().flatten() {
            state.insert(def);
        }
    };
    let apply = |state: &mut Bits, b: usize, s: usize, step: &Step| {
        weak(state, b, s);
        let Some(local) = step.write else {
            return;
        };
        if step.overwrites {
            for &killed in by_local.get(&local).into_iter().flatten() {
                state.remove(killed);
            }
        }
        state.insert(out.def_at[&(b, s)]);
    };

    let mut ins = vec![Bits::new(out.defs.len()); blocks.len()];
    if let Some(first) = ins.first_mut() {
        for &def in out.entry.values() {
            first.insert(def);
        }
    }
    loop {
        let mut changed = false;
        for (b, block) in blocks.iter().enumerate() {
            let mut state = ins[b].clone();
            let last = block.steps.len().saturating_sub(1);
            let mut before_last = state.clone();
            for (s, step) in block.steps.iter().enumerate() {
                if s == last {
                    before_last = state.clone();
                    weak(&mut before_last, b, s);
                }
                apply(&mut state, b, s, step);
            }
            for &(succ, sees_last) in &block.succs {
                let leaving = if sees_last { &state } else { &before_last };
                changed |= ins[succ].union_with(leaving);
            }
        }
        if !changed {
            break;
        }
    }

    for (b, block) in blocks.iter().enumerate() {
        let mut state = ins[b].clone();
        for (s, step) in block.steps.iter().enumerate() {
            let mut seen: Vec<usize> = Vec::new();
            let mut per_read: Vec<Vec<usize>> = Vec::with_capacity(step.reads.len());
            for local in &step.reads {
                let visible: Vec<usize> = by_local
                    .get(local)
                    .into_iter()
                    .flatten()
                    .copied()
                    .filter(|&def| state.contains(def))
                    .collect();
                for &def in &visible {
                    if !seen.contains(&def) {
                        seen.push(def);
                    }
                }
                per_read.push(visible);
            }
            if per_read.iter().any(|defs| !defs.is_empty()) {
                out.read_inputs.insert((b, s), per_read);
            }
            let written: Vec<usize> = out
                .def_at
                .get(&(b, s))
                .into_iter()
                .chain(out.side_defs.get(&(b, s)).into_iter().flatten())
                .copied()
                .collect();
            for &w in &written {
                for &def in &seen {
                    if def != w && !out.flow[def].contains(&w) {
                        out.flow[def].push(w);
                    }
                }
            }
            if !seen.is_empty() {
                out.inputs.insert((b, s), seen);
            }
            apply(&mut state, b, s, step);
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Bits(Vec<u64>);

impl Bits {
    fn new(len: usize) -> Self {
        Self(vec![0; len.div_ceil(64)])
    }

    fn insert(&mut self, i: usize) {
        self.0[i / 64] |= 1u64 << (i % 64);
    }

    fn remove(&mut self, i: usize) {
        self.0[i / 64] &= !(1u64 << (i % 64));
    }

    fn contains(&self, i: usize) -> bool {
        self.0[i / 64] & (1u64 << (i % 64)) != 0
    }

    fn union_with(&mut self, other: &Self) -> bool {
        let mut changed = false;
        for (mine, theirs) in self.0.iter_mut().zip(&other.0) {
            let next = *mine | theirs;
            changed |= next != *mine;
            *mine = next;
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(local: usize, reads: &[usize]) -> Step {
        Step {
            reads: reads.to_vec(),
            write: Some(local),
            overwrites: true,
            also_writes: Vec::new(),
        }
    }

    fn read(locals: &[usize]) -> Step {
        Step {
            reads: locals.to_vec(),
            ..Step::default()
        }
    }

    fn block(steps: Vec<Step>, succs: &[usize]) -> Block {
        Block {
            steps,
            succs: succs.iter().map(|&s| (s, true)).collect(),
        }
    }

    fn seen_at(r: &Reaching, at: (usize, usize), local: usize) -> Vec<Site> {
        r.inputs
            .get(&at)
            .into_iter()
            .flatten()
            .filter(|&&d| r.defs[d].local == local)
            .map(|&d| r.defs[d].site)
            .collect()
    }

    fn site(block: usize, step: usize) -> Site {
        Site::Step { block, step }
    }

    fn reaches(r: &Reaching, from: (usize, usize), to: (usize, usize)) -> bool {
        let (start, goal) = (r.def_at[&from], r.def_at[&to]);
        let mut stack = vec![start];
        let mut seen = vec![false; r.defs.len()];
        while let Some(d) = stack.pop() {
            if d == goal {
                return true;
            }
            if !std::mem::replace(&mut seen[d], true) {
                stack.extend(&r.flow[d]);
            }
        }
        false
    }

    fn reassigned() -> Vec<Block> {
        vec![
            block(vec![write(1, &[])], &[1]),
            block(vec![write(3, &[1]), write(2, &[3])], &[2]),
            block(vec![write(4, &[])], &[3]),
            block(vec![write(1, &[4]), write(6, &[1]), write(5, &[6])], &[]),
        ]
    }

    #[test]
    fn an_overwrite_hides_the_old_value_from_later_reads() {
        let r = analyse(&reassigned(), &[]);
        assert_eq!(
            seen_at(&r, (1, 0), 1),
            [site(0, 0)],
            "first borrow sees the 2048 key"
        );
        assert_eq!(
            seen_at(&r, (3, 1), 1),
            [site(3, 0)],
            "second borrow sees only the move"
        );
    }

    #[test]
    fn a_value_moved_into_a_reused_local_flows_on() {
        let r = analyse(&reassigned(), &[]);
        assert!(
            reaches(&r, (2, 0), (3, 2)),
            "4096 key -> move -> borrow -> sign"
        );
        assert!(
            !reaches(&r, (0, 0), (3, 2)),
            "2048 key was overwritten first"
        );
        assert!(reaches(&r, (0, 0), (1, 1)));
    }

    #[test]
    fn both_arms_of_a_join_reach_the_use() {
        let blocks = vec![
            block(vec![], &[1, 2]),
            block(vec![write(1, &[])], &[3]),
            block(vec![write(1, &[])], &[3]),
            block(vec![read(&[1])], &[]),
        ];
        let r = analyse(&blocks, &[]);
        assert_eq!(seen_at(&r, (3, 0), 1), [site(1, 0), site(2, 0)]);
    }

    #[test]
    fn a_loop_carries_a_late_write_round_the_back_edge() {
        let blocks = vec![
            block(vec![write(1, &[])], &[1]),
            block(vec![read(&[1])], &[2]),
            block(vec![write(1, &[])], &[1, 3]),
            block(vec![], &[]),
        ];
        let r = analyse(&blocks, &[]);
        assert_eq!(seen_at(&r, (1, 0), 1), [site(0, 0), site(2, 0)]);
    }

    #[test]
    fn an_unwind_edge_does_not_see_the_calls_write() {
        let blocks = vec![
            block(vec![write(1, &[])], &[1]),
            Block {
                steps: vec![write(1, &[])],
                succs: vec![(2, true), (3, false)],
            },
            block(vec![read(&[1])], &[]),
            block(vec![read(&[1])], &[]),
        ];
        let r = analyse(&blocks, &[]);
        assert_eq!(seen_at(&r, (2, 0), 1), [site(1, 0)], "normal return");
        assert_eq!(
            seen_at(&r, (3, 0), 1),
            [site(0, 0)],
            "unwind: the old value"
        );
    }

    #[test]
    fn a_partial_write_adds_without_killing() {
        let partial = Step {
            reads: vec![2],
            write: Some(1),
            overwrites: false,
            also_writes: Vec::new(),
        };
        let blocks = vec![block(vec![write(1, &[]), partial, read(&[1])], &[])];
        let r = analyse(&blocks, &[]);
        assert_eq!(seen_at(&r, (0, 2), 1), [site(0, 0), site(0, 1)]);
    }

    #[test]
    fn a_parameter_is_defined_on_entry() {
        let blocks = vec![block(vec![write(2, &[1])], &[])];
        let r = analyse(&blocks, &[1]);
        assert_eq!(seen_at(&r, (0, 0), 1), [Site::Entry]);
        assert_eq!(r.flow[r.entry[&1]], [r.def_at[&(0, 0)]]);
    }

    #[test]
    fn each_read_sees_only_its_own_definitions() {
        let blocks = vec![Block {
            steps: vec![write(1, &[]), write(2, &[]), write(3, &[1, 2])],
            succs: Vec::new(),
        }];
        let r = analyse(&blocks, &[]);
        let def_of = |step: usize| r.def_at[&(0, step)];
        assert_eq!(
            r.read_inputs[&(0, 2)],
            vec![vec![def_of(0)], vec![def_of(1)]]
        );
    }

    #[test]
    fn a_write_through_a_borrow_adds_a_definition_and_kills_nothing() {
        let call = Step {
            reads: vec![3],
            write: Some(4),
            overwrites: true,
            also_writes: vec![1],
        };
        let blocks = vec![block(
            vec![write(1, &[]), write(3, &[]), call, read(&[1])],
            &[],
        )];
        let r = analyse(&blocks, &[]);
        let side = r.side_defs[&(0, 2)][0];
        assert_eq!(seen_at(&r, (0, 3), 1), [site(0, 0), site(0, 2)]);
        assert!(r.flow[r.def_at[&(0, 1)]].contains(&side), "x flows into h");
    }

    #[test]
    fn a_step_reading_its_own_earlier_value_gets_no_self_edge() {
        let blocks = vec![
            block(vec![write(1, &[])], &[1]),
            block(vec![write(1, &[1])], &[1, 2]),
            block(vec![], &[]),
        ];
        let r = analyse(&blocks, &[]);
        let me = r.def_at[&(1, 0)];
        assert!(!r.flow[me].contains(&me));
        assert!(r.flow[r.def_at[&(0, 0)]].contains(&me));
    }

    #[test]
    fn bits_survive_a_word_boundary() {
        let mut bits = Bits::new(130);
        for i in [0, 63, 64, 129] {
            bits.insert(i);
        }
        assert!([0, 63, 64, 129].iter().all(|&i| bits.contains(i)));
        bits.remove(64);
        assert!(!bits.contains(64) && bits.contains(63));
        let mut other = Bits::new(130);
        assert!(other.union_with(&bits));
        assert!(!other.union_with(&bits), "a second union changes nothing");
    }
}
