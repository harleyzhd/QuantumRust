#!/usr/bin/env python3
"""Validate a CBOM against the vendored CycloneDX 1.7 schemas.

Usage:
    python3 schemas/validate_cbom.py out/cbom.json out/cbom.xml
    python3 schemas/validate_cbom.py --self-test

Needs `jsonschema` and `lxml`. Exits non-zero if any document fails, and
prints its violations.

This checks conformance to the published schema, not whether the inventory
makes sense as a crypto bill of materials. The XSD also checks element order,
which the JSON schema cannot.

`--self-test` mutates a valid document six ways and checks that every mutation
is rejected. A validator that resolves no `$ref`s passes everything, so run it
whenever the schemas are refreshed.

The schemas come from https://cyclonedx.org/schema/ and are vendored so the
check works offline. `bom-1.7.xsd` has one edit: its `xs:import` of the SPDX
namespace names the sibling `spdx.xsd`, because the original URL resolves to
no document.
"""

from __future__ import annotations

import copy
import json
import pathlib
import sys
import warnings

warnings.filterwarnings("ignore", message=".*RefResolver.*")

SCHEMAS = pathlib.Path(__file__).parent


def _json_validator():
    from jsonschema import Draft202012Validator, RefResolver

    schema = json.loads((SCHEMAS / "bom-1.7.schema.json").read_text())
    store = {
        "http://cyclonedx.org/schema/spdx.schema.json": json.loads(
            (SCHEMAS / "spdx.schema.json").read_text()
        ),
        "http://cyclonedx.org/schema/jsf-0.82.schema.json": json.loads(
            (SCHEMAS / "jsf-0.82.schema.json").read_text()
        ),
        schema.get("$id", ""): schema,
    }

    def validate(document) -> list[str]:
        resolver = RefResolver(
            base_uri=schema.get("$id", ""), referrer=schema, store=store
        )
        errors = Draft202012Validator(schema, resolver=resolver).iter_errors(document)
        return [
            f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}"
            for e in sorted(errors, key=lambda e: list(e.path))
        ]

    return validate


def _xml_validator():
    from lxml import etree

    schema = etree.XMLSchema(etree.parse(str(SCHEMAS / "bom-1.7.xsd")))

    def validate(path: pathlib.Path) -> list[str]:
        document = etree.parse(str(path))
        if schema.validate(document):
            return []
        return [f"line {e.line}: {e.message}" for e in schema.error_log]

    return validate


def self_test() -> int:
    """Mutate a valid document six ways; every mutation must be rejected."""
    validate = _json_validator()
    good = json.loads((SCHEMAS / "selftest-cbom.json").read_text())
    if validate(good):
        print("FAIL: the self-test fixture does not validate", file=sys.stderr)
        for violation in validate(good):
            print("   ", violation, file=sys.stderr)
        return 1

    def mutate(fn):
        document = copy.deepcopy(good)
        fn(document)
        return document

    cases = {
        "bad bomFormat": mutate(lambda d: d.update(bomFormat="NotCycloneDX")),
        "missing specVersion": mutate(lambda d: d.pop("specVersion")),
        "bad component type": mutate(
            lambda d: d["components"][0].update(type="banana")
        ),
        "bad assetType": mutate(
            lambda d: d["components"][0]["cryptoProperties"].update(assetType="nope")
        ),
        "bad primitive": mutate(
            lambda d: d["components"][0]["cryptoProperties"][
                "algorithmProperties"
            ].update(primitive="wat")
        ),
        "level out of range": mutate(
            lambda d: d["components"][0]["cryptoProperties"][
                "algorithmProperties"
            ].update(nistQuantumSecurityLevel=99)
        ),
    }

    failures = 0
    for name, document in cases.items():
        violations = validate(document)
        status = "rejected" if violations else "NOT REJECTED"
        print(f"  {name:22} {status}")
        if not violations:
            failures += 1
    if failures:
        print(
            f"\n{failures} negative control(s) passed validation — the validator "
            "is not resolving the schema and its results mean nothing.",
            file=sys.stderr,
        )
        return 1
    print("\nself-test OK: every negative control was rejected")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    if not argv:
        print(__doc__)
        return 2

    json_validate = _json_validator()
    xml_validate = _xml_validator()
    failed = 0

    for name in argv:
        path = pathlib.Path(name)
        if not path.is_file():
            print(f"{path}: not found", file=sys.stderr)
            failed += 1
            continue
        if path.suffix == ".json":
            violations = json_validate(json.loads(path.read_text()))
        elif path.suffix == ".xml":
            violations = xml_validate(path)
        else:
            print(f"{path}: expected .json or .xml", file=sys.stderr)
            failed += 1
            continue

        if violations:
            failed += 1
            print(f"{path}: FAILS CycloneDX 1.7 ({len(violations)} violations)")
            for violation in violations[:20]:
                print("   ", violation)
        else:
            print(f"{path}: validates against CycloneDX 1.7")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
