"""The identity bake-off, and the materiality policy it motivates."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evalseal.bakeoff import CASES, IDENTITY_FNS, MAX_SAFE, run_bakeoff
from evalseal.materiality import (
    DEFAULT_POLICY,
    EXCLUDE,
    MaterialityPolicy,
    Rule,
    apply_policy,
    policy_address_of,
)


def _fn(name: str):
    return next(f for f in IDENTITY_FNS if f.name == name)


def _case(name: str):
    return next(c for c in CASES if c.name == name)


# --- the case set itself must be non-trivial ------------------------------

def test_key_reordering_is_not_among_the_cases():
    """Deliberate: everyone handles key order, so it proves nothing."""
    assert not any("key_reorder" == c.name for c in CASES)


def test_cases_include_both_directions():
    assert any(c.must_match for c in CASES)
    assert any(not c.must_match for c in CASES)


def test_every_case_actually_changes_the_stored_bytes():
    """A case whose bytes are identical tests nothing."""
    for c in CASES:
        assert c.before != c.after, f"{c.name} is vacuous: before and after bytes are equal"


# --- the headline failures -------------------------------------------------

def test_naive_canonicalizer_false_accepts_at_the_float64_boundary():
    """The security failure: two different schema bounds, one identity.

    This is the whole argument against an undeclared canonicalizer, so it is
    pinned rather than left to the report.
    """
    naive = _fn("naive_canonical")
    c = _case("float64_precision")
    assert naive.digest(c.before) == naive.digest(c.after), \
        "expected the float-coercing canonicalizer to converge these values"
    assert not c.must_match, "this case is material; converging it is a false accept"


def test_evalseal_never_false_accepts_at_the_float64_boundary():
    for name in ("evalseal_strict", "evalseal_eval", "evalseal_policy"):
        fn = _fn(name)
        c = _case("float64_precision")
        assert fn.digest(c.before) != fn.digest(c.after), f"{name} false-accepted"


def test_float64_boundary_is_anchored_in_a_real_published_schema():
    """The constant is not invented: a real server publishes it as a bound."""
    hits = []
    for p in (Path(__file__).resolve().parent.parent / "realdata" / "tools").glob("*.json"):
        if str(MAX_SAFE) in p.read_text(encoding="utf-8"):
            hits.append(p.name)
    if not hits:
        pytest.skip("no harvested realdata/tools present")
    assert hits, f"{MAX_SAFE} should appear in at least one captured tool schema"


def test_raw_bytes_never_false_accepts():
    r = next(x for x in run_bakeoff()[0] if x.fn == "raw_bytes")
    assert not r.false_accepts


def test_every_global_relation_fails_somewhere():
    """The premise of the materiality policy. If this ever passes cleanly for a
    global relation, the policy is unnecessary and should be deleted."""
    results = {r.fn: r for r in run_bakeoff()[0]}
    for name in ("raw_bytes", "naive_canonical", "evalseal_strict", "evalseal_eval"):
        r = results[name]
        assert r.false_blocks or r.false_accepts, \
            f"{name} is correct on every case; the per-field policy may be unnecessary"


def test_declared_policy_is_correct_on_every_case():
    results = {r.fn: r for r in run_bakeoff()[0]}
    r = results["evalseal_policy"]
    assert not r.false_blocks, r.false_blocks
    assert not r.false_accepts, r.false_accepts
    assert not r.errors, r.errors


def test_the_two_numeric_cases_require_opposite_answers():
    """Why no single global relation can be right."""
    cosmetic = _case("inference_param_numeric_form")
    material = _case("schema_bound_numeric_form")
    assert cosmetic.must_match and not material.must_match
    policy = _fn("evalseal_policy")
    assert policy.digest(cosmetic.before) == policy.digest(cosmetic.after)
    assert policy.digest(material.before) != policy.digest(material.after)


def test_cross_implementation_disagreement_is_reported():
    _, disagreements = run_bakeoff()
    assert disagreements, "naive and strict should not agree on every artifact"
    names = {d["case"] for d in disagreements}
    assert "unicode_nfd" in names


# --- materiality policy mechanics -----------------------------------------

def test_excluded_fields_are_dropped_before_addressing():
    p = MaterialityPolicy(rules=[Rule("key:_comment", EXCLUDE, "editorial")])
    a = {"x": 1, "_comment": "first note"}
    b = {"x": 1, "_comment": "completely different note"}
    assert policy_address_of(a, p) == policy_address_of(b, p)
    assert "_comment" not in apply_policy(a, p)


def test_excluded_fields_are_named_in_the_declaration():
    assert DEFAULT_POLICY.excluded(), "exclusions must be visible to an auditor"
    decl = DEFAULT_POLICY.declare()
    assert any(r["relation"] == EXCLUDE for r in decl["rules"])
    for r in decl["rules"]:
        assert r["why"], "every rule must carry its justification"


def test_policy_is_addressable_and_changing_it_changes_the_address():
    a = MaterialityPolicy(rules=[Rule("key:temperature", "eval", "sampling")])
    b = MaterialityPolicy(rules=[Rule("key:temperature", "strict", "sampling")])
    assert a.address() != b.address()


def test_path_rules_beat_key_rules_by_order():
    """First match wins, so ordering is the disambiguation mechanism."""
    p = MaterialityPolicy(rules=[
        Rule("path:/inputSchema", "strict", "contract"),
        Rule("key:maximum", "eval", "would collapse numeric form"),
    ])
    a = {"inputSchema": {"maximum": 100}}
    b = {"inputSchema": {"maximum": 100.0}}
    assert policy_address_of(a, p) != policy_address_of(b, p)


def test_unknown_match_kind_is_rejected():
    p = MaterialityPolicy(rules=[Rule("regex:.*", "eval")])
    with pytest.raises(ValueError):
        policy_address_of({"a": 1}, p)


def test_receipt_carries_the_materiality_declaration(tmp_path):
    from evalseal.manifest import build_manifest, load_config
    from evalseal.receipt import issue

    cfg = load_config(Path(__file__).resolve().parent.parent / "demo")
    r = issue(manifest=build_manifest(cfg, "strict"),
              eval_results={"passed": 18, "failed": 2, "gate": "pass"},
              leakage=None, approver="t@example.com",
              key_path=tmp_path / "k.pem", agent_name="a",
              materiality=DEFAULT_POLICY)
    m = r.payload["materiality"]
    assert m["name"] == DEFAULT_POLICY.name
    assert m["rules"]
    assert "not a" in m["note"] or "declared policy" in m["note"]


def test_receipt_without_a_policy_says_so_explicitly(tmp_path):
    """Silence must not be mistaken for a policy."""
    from evalseal.manifest import build_manifest, load_config
    from evalseal.receipt import issue

    cfg = load_config(Path(__file__).resolve().parent.parent / "demo")
    r = issue(manifest=build_manifest(cfg, "strict"),
              eval_results={"passed": 18, "failed": 2, "gate": "pass"},
              leakage=None, approver="t@example.com",
              key_path=tmp_path / "k.pem", agent_name="a")
    m = r.payload["materiality"]
    assert m["rules"] == []
    assert "applies uniformly" in m["note"]
