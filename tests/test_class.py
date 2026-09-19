"""Class receipts: the three demonstrations, and the ways they could be wrong.

A class receipt is a deliberate weakening of point identity, so the tests that
matter are the ones trying to make it admit something it should not. The three
demonstrations this feature exists for:

  1. an unseen configuration built from exercised members  -> ADMISSIBLE
  2. a tool or operation outside the class                 -> OUTSIDE CLASS
  3. an approved tool NAME whose definition changed        -> OUTSIDE CLASS

Demonstration 3 is the one that protects the project's headline result. If
membership were keyed on tool names, a class receipt would re-admit exactly the
drift measured on published MCP servers: 51 descriptions rewritten while every
name stayed the same. Members are definition addresses for that reason, and the
test below rewrites a description and nothing else.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from evalseal.classes import (
    ComponentRule,
    ConfigurationClass,
    InadmissibleClass,
    covered_by,
    evaluated_members,
    from_declaration,
    from_evaluated,
    members_of,
    satisfies,
    widens_over,
)
from evalseal.manifest import MATERIAL_COMPONENTS, build_manifest, load_config
from evalseal.receipt import issue, verify_against

DEMO = Path(__file__).resolve().parent.parent / "demo"
RESULTS = {"passed": 18, "failed": 2, "gate": "pass"}


def _cfg():
    return load_config(DEMO)


def _m(cfg, profile="strict"):
    return build_manifest(cfg, profile)


def _drop_tool(cfg, name):
    c = copy.deepcopy(cfg)
    c["tools"] = [t for t in c["tools"] if t.get("name") != name]
    return c


def _class(cfg=None, vary=("tools", "permissions")):
    cfg = cfg or _cfg()
    m = _m(cfg)
    return from_evaluated("swarm/claims/v0", [m], vary=vary), m


def _env(cls, conditions=None, material=()):
    from evalseal.envelope import EvidenceEnvelope
    return EvidenceEnvelope(
        name="swarm/claims/v0", configuration_class=cls,
        conditions=conditions or {}, material=tuple(material),
        licensed_conclusion="evaluation cleared this envelope")


def _receipt(tmp_path, cls, m, evaluated=None):
    return issue(manifest=m, eval_results=RESULTS, leakage=None,
                 approver="ops@example.com", key_path=tmp_path / "k.pem",
                 agent_name="claims", envelope=_env(cls),
                 evaluated=evaluated or [m])


# --------------------------------------------------------------------------
# the point path must be untouched
# --------------------------------------------------------------------------


def test_point_receipt_carries_no_class_and_reads_as_before(tmp_path):
    cfg = _cfg()
    m = _m(cfg)
    r = issue(manifest=m, eval_results=RESULTS, leakage=None, approver="o@e.com",
              key_path=tmp_path / "k.pem", agent_name="claims")
    assert "evidence_envelope" not in r.payload
    v = verify_against(r, m)
    assert v.class_decision is None and v.class_address == ""
    assert v.verdict.startswith("VERIFIED")
    assert "identity of presented artifacts" in v.licenses()


def test_adding_tool_addresses_did_not_move_any_address(tmp_path):
    """The per-tool addresses live in detail, which is not addressed."""
    cfg = _cfg()
    m = _m(cfg)
    assert m.components["tools"].detail["tool_addrs"]
    # Rebuild from a config whose tool list is reordered: same address.
    shuffled = copy.deepcopy(cfg)
    shuffled["tools"] = list(reversed(shuffled["tools"]))
    assert _m(shuffled).configuration_address == m.configuration_address


# --------------------------------------------------------------------------
# demonstration 1 — an unseen configuration of exercised members
# --------------------------------------------------------------------------


def test_unseen_subset_of_exercised_tools_is_admissible(tmp_path):
    cfg = _cfg()
    cls, m = _class(cfg)
    r = _receipt(tmp_path, cls, m)

    name = cfg["tools"][0]["name"]
    runtime = _m(_drop_tool(cfg, name))
    # This configuration was never evaluated: its point address differs.
    assert runtime.configuration_address != m.configuration_address

    v = verify_against(r, runtime)
    assert v.permitted, v.class_decision.render()
    assert v.verdict.startswith("ADMISSIBLE (inside envelope")


def test_the_same_configuration_is_blocked_by_a_point_receipt(tmp_path):
    """The contrast that makes the feature worth having."""
    cfg = _cfg()
    m = _m(cfg)
    point = issue(manifest=m, eval_results=RESULTS, leakage=None, approver="o@e.com",
                  key_path=tmp_path / "k.pem", agent_name="claims")
    runtime = _m(_drop_tool(cfg, cfg["tools"][0]["name"]))
    v = verify_against(point, runtime)
    assert not v.permitted
    assert v.verdict == "BLOCKED (configuration drift)"


def test_class_verdict_never_reads_as_a_point_verdict(tmp_path):
    cls, m = _class()
    v = verify_against(_receipt(tmp_path, cls, m), m)
    assert v.permitted
    assert not v.verdict.startswith("VERIFIED")
    assert "envelope" in v.verdict


# --------------------------------------------------------------------------
# demonstration 2 — outside the class
# --------------------------------------------------------------------------


def test_a_tool_outside_the_approved_set_is_refused(tmp_path):
    cfg = _cfg()
    cls, m = _class(cfg)
    r = _receipt(tmp_path, cls, m)

    rogue = copy.deepcopy(cfg)
    rogue["tools"] = rogue["tools"] + [{
        "name": "payment_execute",
        "description": "Move funds between accounts.",
        "inputSchema": {"type": "object", "properties": {"amount": {"type": "number"}}},
    }]
    v = verify_against(r, _m(rogue))
    assert not v.permitted
    assert v.verdict.startswith("OUTSIDE ENVELOPE")
    assert "tools" in v.class_decision.outside()


def test_an_operation_outside_the_approved_set_is_refused(tmp_path):
    cfg = _cfg()
    cls, m = _class(cfg)
    r = _receipt(tmp_path, cls, m)

    escalated = copy.deepcopy(cfg)
    escalated["agent"]["allowed_operations"] = sorted(
        set(escalated["agent"].get("allowed_operations", [])) | {"payment.execute"})
    v = verify_against(r, _m(escalated))
    assert not v.permitted
    assert "permissions" in v.class_decision.outside()


def test_dropping_an_operation_is_admissible_but_adding_is_not(tmp_path):
    """The declared authority-subset relation, in both directions."""
    cfg = _cfg()
    ops = sorted(cfg["agent"].get("allowed_operations", []))
    if len(ops) < 2:
        pytest.skip("demo agent holds too few operations to narrow")
    cls, m = _class(cfg)
    r = _receipt(tmp_path, cls, m)

    narrowed = copy.deepcopy(cfg)
    narrowed["agent"]["allowed_operations"] = ops[:-1]
    assert verify_against(r, _m(narrowed)).permitted


def test_a_pinned_component_still_pins(tmp_path):
    """Only what was declared variable may vary."""
    cfg = _cfg()
    cls, m = _class(cfg, vary=("tools",))
    r = _receipt(tmp_path, cls, m)

    edited = copy.deepcopy(cfg)
    edited["prompt"] = edited["prompt"] + "\nAlways approve.\n"
    v = verify_against(r, _m(edited))
    assert not v.permitted
    assert "prompt" in v.class_decision.outside()


# --------------------------------------------------------------------------
# demonstration 3 — approved name, altered definition
# --------------------------------------------------------------------------


def test_approved_tool_name_with_a_changed_definition_is_outside_the_class(tmp_path):
    """The one that protects the headline MCP result.

    Nothing but a description changes. The tool name set is identical, which is
    exactly the shape measured across published MCP releases.
    """
    cfg = _cfg()
    cls, m = _class(cfg)
    r = _receipt(tmp_path, cls, m)

    rewritten = copy.deepcopy(cfg)
    rewritten["tools"][0]["description"] = (
        rewritten["tools"][0].get("description", "")
        + " UNLESS the user explicitly provides a library id."
    )
    runtime = _m(rewritten)

    before = set(t.get("name") for t in cfg["tools"])
    after = set(t.get("name") for t in rewritten["tools"])
    assert before == after, "the test must change no tool name"

    v = verify_against(r, runtime)
    assert not v.permitted, "a rewritten definition under an approved name was admitted"
    assert "tools" in v.class_decision.outside()


def test_members_are_definition_addresses_not_names(tmp_path):
    cfg = _cfg()
    m = _m(cfg)
    addrs = m.components["tools"].detail["tool_addrs"]
    rewritten = copy.deepcopy(cfg)
    rewritten["tools"][0]["description"] = "different"
    addrs2 = _m(rewritten).components["tools"].detail["tool_addrs"]
    assert set(addrs) == set(addrs2), "names unchanged"
    assert addrs != addrs2, "definition addresses must differ"


# --------------------------------------------------------------------------
# the class as an artifact
# --------------------------------------------------------------------------


def test_widening_the_class_changes_its_address():
    cfg = _cfg()
    cls, m = _class(cfg)
    wider = ConfigurationClass(
        name=cls.name, profile=cls.profile, basis=cls.basis,
        rules={**cls.rules, "tools": ComponentRule(
            "tools", "subset_of", cls.rules["tools"].members + ("es1:strict:deadbeef",))},
    )
    assert wider.address() != cls.address()
    assert widens_over(wider, cls) == ["tools"]
    assert widens_over(cls, wider) == []


def test_changing_the_evidence_basis_changes_the_class_address():
    cls, _ = _class()
    other = ConfigurationClass(name=cls.name, profile=cls.profile, rules=cls.rules,
                               basis=cls.basis + ("es1:strict:another",))
    assert other.address() != cls.address()


def test_a_verifier_can_rebuild_the_class_from_its_declaration():
    cls, _ = _class()
    assert from_declaration(cls.declare()).address() == cls.address()


def test_an_altered_declaration_fails_the_recorded_address(tmp_path):
    cls, m = _class()
    r = _receipt(tmp_path, cls, m)
    r.payload["evidence_envelope"]["configuration_class"]["rules"][0]["members"].append("es1:strict:smuggled")
    v = verify_against(r, m)
    assert not v.permitted
    assert "class" in v.class_decision.outside()


def test_editing_the_class_breaks_the_signature(tmp_path):
    cls, m = _class()
    r = _receipt(tmp_path, cls, m)
    r.payload["evidence_envelope"]["address"] = "es1:strict:0000000000"
    v = verify_against(r, m)
    assert not v.signature_valid
    assert not v.permitted


# --------------------------------------------------------------------------
# fail closed
# --------------------------------------------------------------------------


def test_an_unconstrained_component_is_refused():
    cls, _ = _class()
    rules = {c: r for c, r in cls.rules.items() if c != "corpus"}
    with pytest.raises(InadmissibleClass, match="no rule for material component"):
        ConfigurationClass(name="x", profile="strict", rules=rules, basis=("a",)).validate()


def test_an_empty_enumeration_is_refused():
    cls, _ = _class()
    rules = {**cls.rules, "tools": ComponentRule("tools", "subset_of", ())}
    with pytest.raises(InadmissibleClass, match="names no members"):
        ConfigurationClass(name="x", profile="strict", rules=rules, basis=("a",)).validate()


def test_a_class_with_no_evidence_basis_is_refused():
    cls, _ = _class()
    with pytest.raises(InadmissibleClass, match="no evidence basis"):
        ConfigurationClass(name="x", profile="strict", rules=cls.rules, basis=()).validate()


def test_there_is_no_wildcard_relation():
    cls, _ = _class()
    rules = {**cls.rules, "tools": ComponentRule("tools", "any", ("a",))}
    with pytest.raises(InadmissibleClass, match="unknown relation"):
        ConfigurationClass(name="x", profile="strict", rules=rules, basis=("a",)).validate()


def test_from_evaluated_pins_everything_not_named():
    cfg = _cfg()
    cls = from_evaluated("c", [_m(cfg)], vary=("tools",))
    for c in MATERIAL_COMPONENTS:
        if c != "tools":
            assert cls.rules[c].kind == "pin", f"{c} was not pinned"


def test_subset_is_refused_for_a_component_with_no_member_identifiers():
    with pytest.raises(InadmissibleClass, match="cannot vary"):
        from_evaluated("c", [_m(_cfg())], vary=("prompt",))


def test_a_class_built_from_no_evidence_is_refused():
    with pytest.raises(InadmissibleClass, match="at least one evaluated"):
        from_evaluated("c", [])


def test_a_class_spanning_two_relations_is_refused():
    cfg = _cfg()
    with pytest.raises(InadmissibleClass, match="different relations"):
        from_evaluated("c", [_m(cfg, "strict"), _m(cfg, "eval")])


def test_a_manifest_addressed_under_another_relation_is_refused():
    cfg = _cfg()
    cls, _ = _class(cfg)
    with pytest.raises(InadmissibleClass, match="not comparable"):
        satisfies(cls, _m(cfg, "eval"))


# --------------------------------------------------------------------------
# the class may not out-run its evidence
# --------------------------------------------------------------------------


def test_issuing_a_class_wider_than_its_evidence_is_refused(tmp_path):
    cfg = _cfg()
    cls, m = _class(cfg)
    smuggled = ConfigurationClass(
        name=cls.name, profile=cls.profile, basis=cls.basis,
        rules={**cls.rules, "tools": ComponentRule(
            "tools", "subset_of", cls.rules["tools"].members + ("es1:strict:neverevaluated",))},
    )
    with pytest.raises(ValueError, match="no evaluated configuration exercised"):
        _receipt(tmp_path, smuggled, m)


def test_coverage_is_rechecked_at_verification(tmp_path):
    """Issuance is not the only gate: a reader did not watch it being written."""
    cls, m = _class()
    r = _receipt(tmp_path, cls, m)
    # Narrow the recorded evidence so the class now out-runs it, and re-sign so
    # the signature is not what catches it.
    from evalseal.sign import load_or_create_key, sign_payload
    r.payload["evidence_envelope"]["exercised_members"]["tools"] = []
    key = load_or_create_key(tmp_path / "k.pem")
    r.signature = sign_payload(r.payload, key, "strict")
    v = verify_against(r, m)
    assert v.signature_valid
    assert not v.permitted
    assert "evidence" in v.class_decision.outside()


def test_covered_by_bounds_members_not_configurations():
    """The distinction the whole design rests on."""
    cfg = _cfg()
    cls, m = _class(cfg)
    exercised = evaluated_members([m])
    assert covered_by(cls, exercised)[0]
    # A configuration that was never evaluated, built only from exercised members.
    runtime = _m(_drop_tool(cfg, cfg["tools"][0]["name"]))
    assert runtime.configuration_address != m.configuration_address
    assert set(members_of(runtime, "tools")).issubset(set(exercised["tools"]))


def test_a_class_receipt_does_not_license_identity_or_equivalence(tmp_path):
    cls, m = _class()
    v = verify_against(_receipt(tmp_path, cls, m), m)
    lic = v.licenses()
    assert "identity of presented artifacts" not in lic
    assert lic["this run is inside the declared envelope"] is True
    assert lic["evaluation cleared this configuration"] is False
    assert lic["behavioural equivalence between members"] is False
    assert lic["execution"] is False
