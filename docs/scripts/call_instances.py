"""The instance of a call: what the call is about.

An instance is the parameter sets (a curve, a key size) and the type-name
rules (a digest, a cipher) that a call's type and static arguments match.
Two calls on one source line are the same call only if their instances are
compatible. This mirrors `crates/rules/src/instance.rs`.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"

Segments = list[str]
Instance = tuple[frozenset[str], frozenset[str]]


@dataclass(frozen=True)
class Rules:
    """Type names from the rule files, as `(name, type names)` pairs."""

    by_rule: tuple[tuple[str, tuple[Segments, ...]], ...]
    by_set: tuple[tuple[str, tuple[Segments, ...]], ...]


def load_rules() -> Rules:
    """Read the type names of every rule and parameter set in `rules/`."""
    docs = [tomllib.loads(p.read_text()) for p in sorted(RULES_DIR.glob("*.toml"))]
    return Rules(
        by_rule=tuple(
            (d["id"], tuple(split_signature(t) for t in d.get("match", {}).get("type_names", [])))
            for d in docs
        ),
        by_set=tuple(
            (s["identifier"], tuple(split_signature(t) for t in s.get("type_names", [])))
            for d in docs
            for s in d.get("parameter_sets", [])
        ),
    )


def instance(node: dict, rules: Rules) -> Instance:
    """The parameter sets and rule ids that the node's arguments match."""
    args = [prepared(a) for a in node.get("type_args", []) + node.get("static_args", [])]

    def named(types: tuple[Segments, ...]) -> bool:
        return any(segments_match(a, t) for a in args for t in types)

    params = frozenset(name for name, types in rules.by_set if named(types))
    hits = frozenset(name for name, types in rules.by_rule if named(types))
    return params, hits


def compatible(a: Instance, b: Instance) -> bool:
    """Parameter sets agree (or one side has none), and one side's rule hits
    contain the other's."""
    (pa, ha), (pb, hb) = a, b
    return (pa == pb or not pa or not pb) and (ha <= hb or hb <= ha)


def split_signature(s: str) -> Segments:
    """A rule's path, lowercased and split on `::`."""
    return [p for p in s.lower().split("::") if p]


def prepared(symbol: str) -> Segments:
    """A printed path as the rules compare it: generics dropped, lowercased,
    split into segments."""
    return _path_segments(_normalize_generics(symbol).lower())


def segments_match(symbol: Segments, wanted: Segments) -> bool:
    """`wanted` is a suffix of `symbol`, or ends on the same segment with the
    rest of `wanted` appearing in order before it."""
    n, w = len(symbol), len(wanted)
    if w == 0 or w > n:
        return False
    if symbol[n - w:] == wanted:
        return True
    if symbol[-1] != wanted[-1]:
        return False
    rest = list(wanted[:-1])
    for seg in symbol[:-1]:
        if rest and seg == rest[0]:
            rest.pop(0)
    return not rest


def _matching_gt(s: str) -> int | None:
    depth = 1
    for i, c in enumerate(s):
        if c == "<":
            depth += 1
        elif c == ">":
            depth -= 1
            if depth == 0:
                return i
    return None


def _normalize_generics(symbol: str) -> str:
    s = symbol.strip()
    if s.startswith("<") and (p := _matching_gt(s[1:])) is not None:
        s = s[1:][:p] + s[1:][p + 1:]
    out, depth = [], 0
    for c in s:
        if c == "<":
            depth += 1
        elif c == ">":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(c)
    return "".join(out)


def _trim(seg: str) -> str:
    def keep(c: str) -> bool:
        return c.isascii() and (c.isalnum() or c == "_")

    i, j = 0, len(seg)
    while i < j and not keep(seg[i]):
        i += 1
    while j > i and not keep(seg[j - 1]):
        j -= 1
    return seg[i:j]


def _path_segments(normalized: str) -> Segments:
    out = []
    for seg in normalized.split("::"):
        seg = _trim(seg)
        for kw in ("dyn ", "impl "):
            if seg.startswith(kw):
                seg = seg[len(kw):].lstrip()
                break
        if " as " in seg:
            seg = seg[: seg.index(" as ")].rstrip()
        if seg:
            out.append(seg)
    return out
