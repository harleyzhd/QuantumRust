"""Blast radius at both ends of the call-graph bracket, from a dumped CPG.

The bracket is the range any sound call graph lies in: the lower end is
`--call-graph fallback`, the upper end `--call-graph cha`. This module
rebuilds both ends in Python, with no code shared with the Rust tool, so the
risk checks can cross-check every blast radius the CLI prints and test
whether one finding's reach contains another's.

The upper end follows `callgraph::cha`. An unresolved MIR trait call reaches
the method of every analysed impl of that trait, or every method of an impl
that does not define it. It also goes through the std blanket impls in
`FORWARDS`, and for `Fn`, `FnMut` and `FnOnce` reaches every closure and
every function used as a value. An unresolved call through a function
pointer reaches every function reference with the same signature.
"""

from __future__ import annotations

import collections
import functools
import json
from pathlib import Path

from call_instances import compatible, instance, load_rules

STD = {"std", "core", "alloc"}
FN_TRAITS = {("Fn", "call"), ("FnMut", "call_mut"), ("FnOnce", "call_once")}
FORWARDS = {
    ("Into", "into"): ("From", "from"),
    ("TryInto", "try_into"): ("TryFrom", "try_from"),
    ("ToString", "to_string"): ("Display", "fmt"),
    ("ToOwned", "to_owned"): ("Clone", "clone"),
    ("FromResidual", "from_residual"): ("From", "from"),
}
# Edges the blast radius walks besides calls, as `callgraph::Reachability`.
FLOW = {"DataDep", "ArgFlow", "ReturnFlow"}


def _strip_generics(path: str) -> str:
    out, depth = [], 0
    for c in path:
        if c == "<":
            depth += 1
        elif c == ">":
            depth -= 1
        elif depth == 0:
            out.append(c)
    return "".join(out)


def _segments(path: str) -> list[str]:
    segs = [s.strip() for s in _strip_generics(path).split("::") if s.strip()]
    if segs and segs[0] in STD:
        segs[0] = "core"
    return segs


def impl_key(symbol: str) -> tuple[list[str], str, str] | None:
    """`(trait path, method, self type)` for `..<Type as Trait>::method`."""
    close = symbol.rfind(">::")
    if close < 0:
        return None
    method = symbol[close + 3:]
    if not method or "::" in method or "{" in method:
        return None
    depth, i = 0, close
    while i >= 0:
        if symbol[i] == ">":
            depth += 1
        elif symbol[i] == "<":
            depth -= 1
            if depth == 0:
                break
        i -= 1
    inner = symbol[i + 1:close]
    depth = 0
    for j, c in enumerate(inner):
        if c == "<":
            depth += 1
        elif c == ">":
            depth -= 1
        elif depth == 0 and inner.startswith(" as ", j):
            return _segments(inner[j + 4:]), method, inner[:j]
    return None


def call_key(symbol: str) -> tuple[list[str], str] | None:
    """`(trait path, method)` that an unresolved trait call names."""
    if symbol.startswith("<dyn "):
        close = symbol.rfind(">::")
        if close < 0:
            return None
        return _segments(symbol[5:close].split(" + ")[0]), symbol[close + 3:]
    segs = _segments(symbol)
    return (segs[:-1], segs[-1]) if len(segs) >= 2 else None


def _suffix_match(a: list[str], b: list[str]) -> bool:
    n = min(len(a), len(b))
    return n > 0 and a[-n:] == b[-n:]


def dispatch_edges(nodes: list[dict], edges: list, dyn_only: bool) -> set[tuple[int, int]]:
    """Unresolved call -> candidate body, as `callgraph::cha` defines it."""
    resolved = {s for s, _, p in edges if p["kind"] == "TraitResolve"}
    bodies = [n for n in nodes
              if n["layer"] == "Mir" and n["kind"] == "Function" and n["location"]]
    blocks: dict[str, dict] = collections.defaultdict(lambda: collections.defaultdict(dict))
    for n in bodies:
        key = impl_key(n["symbol"])
        if key:
            trait, method, self_ty = key
            blocks[trait[-1]][(self_ty, tuple(trait))][method] = n["id"]
    closures = [n["id"] for n in bodies if "{closure" in n["symbol"]]
    refs = [n for n in nodes if n["layer"] == "Mir" and n["kind"] == "FnRef"]
    by_sig: dict[str, list[int]] = collections.defaultdict(list)
    for r in refs:
        if r.get("fn_sig"):
            by_sig[r["fn_sig"]].append(r["id"])
    items = [r["id"] for r in refs if "{closure" not in r["symbol"]]
    has_callee = {s for s, _, p in edges if p["kind"] == "Call"}

    out: set[tuple[int, int]] = set()
    for n in nodes:
        if n["layer"] == "Mir" and n["kind"] == "IndirectCall" and n["id"] not in has_callee:
            out.update((n["id"], r) for r in by_sig.get(n.get("fn_sig") or "", ()))
    for n in nodes:
        if n["layer"] != "Mir" or n["kind"] != "TraitMethod" or n["id"] in resolved:
            continue
        if dyn_only and not n["symbol"].startswith("<dyn "):
            continue
        called = call_key(n["symbol"])
        if not called or not called[0]:
            continue
        trait, method = called
        if (trait[-1], method) in FN_TRAITS:
            out.update((n["id"], c) for c in closures + items)
            continue
        forwarded = FORWARDS.get((trait[-1], method))
        name, target = forwarded if forwarded else (trait[-1], method)
        is_std = trait[0] == "core"
        for (_, tsegs), methods in blocks.get(name, {}).items():
            if forwarded:
                ok = (tsegs[0] == "core") == is_std
            else:
                ok = _suffix_match(list(tsegs), trait)
            if not ok:
                continue
            targets = [methods[target]] if target in methods else list(methods.values())
            out.update((n["id"], t) for t in targets)
    return {(a, b) for a, b in out if a != b}


CALLS = {"CallSite", "TraitMethod", "IndirectCall"}


@functools.cache
def _rules():
    return load_rules()


def bridges(nodes: list[dict]) -> set[tuple[int, int]]:
    """LLVM call -> MIR call on the same file and line. When several MIR calls
    share the line, only those with a compatible instance, if any are."""
    by_loc: dict[tuple, list[dict]] = collections.defaultdict(list)
    for n in nodes:
        if n and n["layer"] == "Mir" and n["kind"] in CALLS and n.get("location"):
            by_loc[(n["location"]["file"], n["location"]["line"])].append(n)
    rules = _rules()
    cache: dict[int, tuple] = {}

    def instance_of(n: dict) -> tuple:
        if n["id"] not in cache:
            cache[n["id"]] = instance(n, rules)
        return cache[n["id"]]

    out: set[tuple[int, int]] = set()
    for n in nodes:
        if not (n and n["layer"] == "Llvm" and n["kind"] in CALLS and n.get("location")):
            continue
        twins = by_loc.get((n["location"]["file"], n["location"]["line"]), [])
        same = ([t for t in twins if compatible(instance_of(n), instance_of(t))]
                if len(twins) > 1 else [])
        out.update((n["id"], t["id"]) for t in (same or twins))
    return out


class Bracket:
    """Reach at both ends of the bracket over one dumped CPG."""

    def __init__(self, cpg_path: Path, dyn_only: bool = False) -> None:
        graph = json.loads(Path(cpg_path).read_text())["graph"]
        low: dict[int, set[int]] = collections.defaultdict(set)
        for s, t, p in graph["edges"]:
            if p["kind"] == "Call" or p["kind"] in FLOW:
                low[s].add(t)
        high = collections.defaultdict(set, {k: set(v) for k, v in low.items()})
        self.extra = dispatch_edges(graph["nodes"], graph["edges"], dyn_only)
        for s, t in self.extra:
            high[s].add(t)
        for s, t in bridges(graph["nodes"]):
            low[s].add(t)
            high[s].add(t)
        self._adj = {"low": low, "high": high}
        self._cache: dict[tuple[str, int], set[int]] = {}
        self._dep = {n["id"] for n in graph["nodes"] if n and n.get("dep_depth") is not None}

    def reach(self, end: str, start: int) -> set[int]:
        """Nodes reachable from `start` at one end, `start` excluded."""
        if (end, start) not in self._cache:
            adj, seen, stack = self._adj[end], {start}, [start]
            while stack:
                for nxt in adj.get(stack.pop(), ()):
                    if nxt not in seen:
                        seen.add(nxt)
                        stack.append(nxt)
            seen.discard(start)
            self._cache[(end, start)] = seen
        return self._cache[(end, start)]

    def blast(self, end: str, start: int) -> int:
        """`reach` counted like the CLI's blast radius: dependency nodes are
        walked through but not counted."""
        return len(self.reach(end, start) - self._dep)
