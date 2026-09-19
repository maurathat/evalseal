"""Evidence envelopes: the conditions half of the claim.

The case these exist for, and the one configuration identity cannot see:

    Evaluated with the network unavailable. Run later with the network
    available. Model, prompt, tools, corpus and permissions byte-identical, so
    the configuration address is identical and every class rule is satisfied --
    and the conditions under which the evidence was earned no longer hold.

That is a false accept for any system that checks only configurations. The whole
point of the envelope is that an unchanged agent is not automatically a covered
one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from evalseal.classes import from_evaluated
from evalseal.envelope import (
    NETWORK_ABSENCE_CLAIMS,
    ContradictedCondition,
    EvidenceEnvelope,
    InadmissibleEnvelope,
    refuse_contradicted,
    check,
    envelope_from_declaration,
)
from evalseal.manifest import build_manifest, load_config
from evalseal.receipt import issue, verify_against

DEMO = Path(__file__).resolve().parent.parent / "demo"
RESULTS = {"passed": 18, "failed": 2, "gate": "pass"}

# A HYPOTHETICAL network-isolated evaluation. These fixtures never touch a hosted
# model, so `network: unavailable` is a condition this harness has no evidence
# against -- unattested, which is the project's standing limit, and not
# contradicted. The live integration may not declare it and is refused if it
# tries; see test_contradicted_* below and integration/run_agent.py.
EVALUATED_UNDER = {
    "network": "unavailable",
    "human_intervention": "none",
    "harness": "nanogpt-bench-style/autonomous",
    "wall_clock": "2026-09-19T01:04:00Z",   # recorded, deliberately not material
}
MATERIAL = ("network", "human_intervention", "harness")


def _m(profile="strict"):
    return build_manifest(load_config(DEMO), profile)


def _env(m, conditions=None, material=None, conclusion="evaluation cleared this envelope"):
    return EvidenceEnvelope(
        name="nanogpt-style/v0",
        configuration_class=from_evaluated("cfg/v0", [m], vary=("tools", "permissions")),
        conditions=dict(EVALUATED_UNDER if conditions is None else conditions),
        material=tuple(MATERIAL if material is None else material),
        licensed_conclusion=conclusion,
    )


def _receipt(tmp_path, m, env):
    return issue(manifest=m, eval_results=RESULTS, leakage=None, approver="ops@e.com",
                 key_path=tmp_path / "k.pem", agent_name="claims",
                 envelope=env, evaluated=[m])


# --------------------------------------------------------------------------
# the motivating case
# --------------------------------------------------------------------------


def test_identical_configuration_with_a_changed_material_condition_is_refused(tmp_path):
    m = _m()
    r = _receipt(tmp_path, m, _env(m))

    # Same manifest object: the configuration could not be more identical.
    v = verify_against(r, m, runtime_conditions={**EVALUATED_UNDER, "network": "available"})
    assert not v.permitted, "an unchanged agent inherited evidence earned under other conditions"
    assert v.verdict.startswith("OUTSIDE ENVELOPE")
    assert "network" in v.class_decision.outside()
    # and the configuration half was perfectly happy
    assert v.class_decision.class_decision.ok


def test_the_same_run_passes_when_the_conditions_still_hold(tmp_path):
    m = _m()
    r = _receipt(tmp_path, m, _env(m))
    v = verify_against(r, m, runtime_conditions=dict(EVALUATED_UNDER))
    assert v.permitted
    assert v.verdict.startswith("ADMISSIBLE (inside envelope")


def test_an_unreported_material_condition_fails_closed(tmp_path):
    """An unreported control is not a satisfied one."""
    m = _m()
    r = _receipt(tmp_path, m, _env(m))
    partial = {k: v for k, v in EVALUATED_UNDER.items() if k != "network"}
    v = verify_against(r, m, runtime_conditions=partial)
    assert not v.permitted
    assert "network" in v.class_decision.outside()


def test_no_conditions_reported_at_all_fails_closed(tmp_path):
    m = _m()
    r = _receipt(tmp_path, m, _env(m))
    assert not verify_against(r, m).permitted
    assert not verify_against(r, m, runtime_conditions={}).permitted


def test_a_non_material_condition_may_differ(tmp_path):
    """Recorded is not the same as material; a wall clock is not a control."""
    m = _m()
    r = _receipt(tmp_path, m, _env(m))
    v = verify_against(r, m, runtime_conditions={**EVALUATED_UNDER,
                                                 "wall_clock": "2027-01-01T00:00:00Z"})
    assert v.permitted


def test_both_halves_must_hold(tmp_path):
    """Right conditions, wrong configuration."""
    import copy
    cfg = load_config(DEMO)
    m = _m()
    r = _receipt(tmp_path, m, _env(m))
    rogue = copy.deepcopy(cfg)
    rogue["tools"] = rogue["tools"] + [{"name": "payment_execute", "description": "x",
                                        "inputSchema": {"type": "object"}}]
    v = verify_against(r, build_manifest(rogue, "strict"),
                       runtime_conditions=dict(EVALUATED_UNDER))
    assert not v.permitted
    assert "tools" in v.class_decision.outside()


# --------------------------------------------------------------------------
# the envelope as an artifact
# --------------------------------------------------------------------------


def test_changing_a_condition_changes_the_envelope_address():
    m = _m()
    a = _env(m)
    b = _env(m, conditions={**EVALUATED_UNDER, "network": "available"})
    assert a.address() != b.address()


def test_promoting_a_condition_to_material_changes_the_address():
    m = _m()
    a = _env(m, material=("network",))
    b = _env(m, material=("network", "human_intervention"))
    assert a.address() != b.address()


def test_a_verifier_can_rebuild_the_envelope_from_its_declaration():
    m = _m()
    env = _env(m)
    assert envelope_from_declaration(env.declare()).address() == env.address()


def test_editing_the_envelope_breaks_the_signature(tmp_path):
    m = _m()
    r = _receipt(tmp_path, m, _env(m))
    r.payload["evidence_envelope"]["conditions"]["network"] = "available"
    assert not verify_against(r, m, runtime_conditions={**EVALUATED_UNDER,
                                                        "network": "available"}).signature_valid


def test_a_resigned_widened_envelope_still_fails_its_own_address(tmp_path):
    """Re-signing does not help: the declaration must re-address to what is recorded."""
    from evalseal.sign import load_or_create_key, sign_payload
    m = _m()
    r = _receipt(tmp_path, m, _env(m))
    r.payload["evidence_envelope"]["conditions"]["network"] = "available"
    r.signature = sign_payload(r.payload, load_or_create_key(tmp_path / "k.pem"), "strict")
    v = verify_against(r, m, runtime_conditions={**EVALUATED_UNDER, "network": "available"})
    assert v.signature_valid
    assert not v.permitted
    assert "class" in v.class_decision.outside()


# --------------------------------------------------------------------------
# fail closed
# --------------------------------------------------------------------------


def test_declared_conditions_with_none_material_is_refused():
    m = _m()
    with pytest.raises(InadmissibleEnvelope, match="none is marked material"):
        _env(m, material=()).validate()


def test_a_material_condition_with_no_declared_value_is_refused():
    m = _m()
    with pytest.raises(InadmissibleEnvelope, match="no declared value"):
        _env(m, material=("network", "gpu_count")).validate()


def test_an_envelope_with_no_licensed_conclusion_is_refused():
    m = _m()
    with pytest.raises(InadmissibleEnvelope, match="no licensed conclusion"):
        _env(m, conclusion="   ").validate()


def test_issuing_refuses_a_malformed_envelope(tmp_path):
    m = _m()
    with pytest.raises(InadmissibleEnvelope):
        _receipt(tmp_path, m, _env(m, material=()))


def test_an_envelope_with_no_conditions_is_allowed_but_licenses_less(tmp_path):
    """Declaring nothing is honest; ignoring what you declared is not."""
    m = _m()
    env = _env(m, conditions={}, material=())
    env.validate()
    v = verify_against(_receipt(tmp_path, m, env), m)
    assert v.permitted
    assert v.licenses()["conditions were as declared"] is False


def test_conditions_are_declared_not_attested(tmp_path):
    """The receipt says so in its own signed text."""
    m = _m()
    r = _receipt(tmp_path, m, _env(m))
    assert "not attested" in r.payload["evidence_envelope"]["conditions_are_declared"]
    v = verify_against(r, m, runtime_conditions=dict(EVALUATED_UNDER))
    assert v.licenses()["conditions were as declared"] is False
    assert v.licenses()["execution"] is False


# --- contradicted conditions (B-13) ----------------------------------------
# Regression tests for a real bug: the live integration declared
# `network: unavailable` as a MATERIAL condition while performing the evaluation
# by HTTPS calls to api.anthropic.com. Not an unattested condition -- a false
# one, in a signed payload, with a headline result derived from it. Three states
# have to stay apart: consistent-but-unattested, unobserved, and contradicted by
# evidence the issuer already holds. Only the third is refused.


def test_contradicted_network_absence_is_refused_at_issuance():
    m = _m()
    env = _env(m)  # declares network: unavailable
    with pytest.raises(ContradictedCondition, match="no network reachability"):
        refuse_contradicted(env, {"network_reachable": True})


def test_contradiction_is_refused_even_when_the_condition_is_not_material():
    """An unchecked condition is still signed, and a reader may rely on it."""
    m = _m()
    env = _env(m, material=("human_intervention",))
    with pytest.raises(ContradictedCondition):
        refuse_contradicted(env, {"network_reachable": True})


@pytest.mark.parametrize("key,value", [
    ("network", "unavailable"), ("network", "OFFLINE"), ("network", "none"),
    ("network_access", "disabled"), ("internet", "no"), ("egress", "blocked"),
    ("network_egress", "none"), ("network_isolation", "enforced"),
    ("sandbox_network", "off"),
])
def test_every_spelling_of_network_absence_is_refused(key, value):
    m = _m()
    env = _env(m, conditions={key: value, "human_intervention": "none"},
               material=(key,))
    with pytest.raises(ContradictedCondition):
        refuse_contradicted(env, {"network_reachable": True})


def test_the_condition_the_live_integration_actually_declares_is_allowed():
    """`tool_egress: none` is true of the live run and survives."""
    m = _m()
    env = _env(m, conditions={"tool_egress": "none",
                              "human_intervention": "none"},
               material=("tool_egress",))
    refuse_contradicted(env, {"network_reachable": True})  # no raise


def test_declaring_network_available_is_not_a_contradiction():
    m = _m()
    env = _env(m, conditions={**EVALUATED_UNDER, "network": "available"})
    refuse_contradicted(env, {"network_reachable": True})


def test_an_isolated_harness_may_still_declare_network_absence():
    """Unattested is the standing limit. Only contradiction is inadmissible."""
    m = _m()
    refuse_contradicted(_env(m), {"network_reachable": False})
    refuse_contradicted(_env(m), {})


def test_a_directly_observed_condition_value_must_match():
    m = _m()
    env = _env(m, conditions={"harness": "autonomous", "network": "available"},
               material=("harness",))
    with pytest.raises(ContradictedCondition, match="harness"):
        refuse_contradicted(env, {"harness": "human-assisted"})
    refuse_contradicted(env, {"harness": "autonomous"})


def test_an_observation_the_envelope_does_not_declare_is_not_a_conflict():
    m = _m()
    refuse_contradicted(_env(m, conditions={"human_intervention": "none"},
                             material=("human_intervention",)),
                        {"gpu": "a100", "network_reachable": False})


def test_the_live_integration_envelope_declares_no_network_absence():
    """Guards the adapter itself, not just the primitive."""
    src = (Path(__file__).resolve().parent.parent
           / "integration" / "run_agent.py").read_text(encoding="utf-8")
    assert "refuse_contradicted(env," in src
    for key in NETWORK_ABSENCE_CLAIMS:
        assert f'"{key}":' not in src, f"adapter declares a {key} condition"
