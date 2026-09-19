"""Claim confinement: an executable invariant bounding what a success licenses.

These are not honesty gestures or disclaimers. They are an enforceable
constraint: a cryptographic success is mechanically prevented from being
promoted into an execution claim. That promotion is the failure mode of every
provenance system -- verification succeeds, and somewhere between the verifier
and the slide it becomes proof that the thing actually happened. Here the
promotion fails a test instead.

The governing distinction is DECLARED != EFFECTIVE != EXECUTED. EvalSeal lives
at DECLARED. It binds the configuration artifacts an operator presents and
recomputes their identity at runtime. It never observes the running process.

The central case below is the one worth keeping if every other test is deleted:

    valid declaration syntax
    + valid signature
    + configuration address matches
    + relationship truth is NOT established

A verifier that reported anything stronger than "these artifacts are the ones
that were evaluated" would be wrong, and these tests are what stops that drift.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from evalseal.manifest import build_manifest, load_config
from evalseal.receipt import issue, verify_against

DEMO = Path(__file__).resolve().parent.parent / "demo"


@pytest.fixture
def sealed(tmp_path):
    cfg = load_config(DEMO)
    m = build_manifest(cfg, "strict")
    r = issue(
        manifest=m,
        eval_results={"n_items": 20, "passed": 18, "failed": 2, "score": 0.9,
                      "threshold": 0.75, "gate": "pass"},
        leakage=None,
        approver="test@example.com",
        key_path=tmp_path / "k.pem",
        agent_name="claims-review-agent",
    )
    return cfg, m, r


def test_verified_result_does_not_assert_execution(sealed):
    """The C9 case: everything verifies, and the strong claim is still not made."""
    cfg, m, r = sealed
    v = verify_against(r, m)

    # All three cryptographic/structural conditions hold.
    assert v.signature_valid
    assert v.configuration_match
    assert v.receipt_approved
    assert v.permitted

    # And yet nothing in the verification result asserts execution. The verdict
    # vocabulary is deliberately limited to configuration identity -- and it
    # states plainly when the signer was not anchored, because an unanchored
    # signature establishes integrity, not authority.
    assert v.verdict.startswith("VERIFIED")
    assert not v.trust_anchored
    assert "signer not anchored" in v.verdict
    forbidden = ("executed", "execution", "ran", "inference", "produced", "served", "effective")
    blob = json.dumps(r.payload).lower()
    for word in forbidden:
        # The scope block is allowed to *deny* these; no other field may assert them.
        occurrences_outside_scope = json.dumps(
            {k: val for k, val in r.payload.items() if k != "scope"}
        ).lower()
        assert word not in occurrences_outside_scope, (
            f"receipt asserts {word!r} outside its scope declaration — "
            "that is a promotion of DECLARED into EXECUTED"
        )
    assert "DECLARED" == r.payload["scope"]["layer"]
    assert blob  # sanity


def test_receipt_states_its_own_boundary(sealed):
    """The boundary is inside the signed payload, not only in documentation."""
    _, _, r = sealed
    scope = r.payload["scope"]
    for field in ("layer", "invariant", "declared_vs_executed", "model_identity",
                  "leakage_claim", "signature_meaning", "address_scheme"):
        assert field in scope, f"signed receipt is missing its {field} boundary"
    assert "NOT establish" in scope["declared_vs_executed"]
    assert "NOT proof of" in scope["leakage_claim"]
    assert "does NOT" in scope["signature_meaning"].replace("Does NOT", "does NOT")
    # The invariant must be the enforceable one -- what was *presented* for
    # verification -- not the broader product objective about execution.
    assert "presented deployment configuration" in scope["invariant"]
    assert "outside EvalSeal v0" in scope["invariant"]


def test_signature_validity_is_not_truth(sealed):
    """A correctly signed receipt can still make a false declaration.

    Signing establishes authorship of the declaration, nothing else. Here the
    approver seals a configuration whose model identifier is a bare name -- a
    string whose referent can change without the string changing. The receipt
    verifies, and the declaration is still not evidence about any weights.
    """
    cfg, _, _ = sealed
    loose = copy.deepcopy(cfg)
    loose["agent"]["model"] = {"id": "gemma4-26b-32k:latest", "identity_kind": "mutable-tag"}
    m = build_manifest(loose, "strict")

    import tempfile

    with tempfile.TemporaryDirectory() as td:
        r = issue(
            manifest=m,
            eval_results={"passed": 20, "failed": 0, "gate": "pass"},
            leakage=None,
            approver="test@example.com",
            key_path=Path(td) / "k.pem",
            agent_name="a",
        )
    v = verify_against(r, m)
    assert v.signature_valid and v.configuration_match

    # The manifest records *what kind* of identifier was bound, so a reader can
    # see the claim is weak rather than having to infer it.
    assert m.components["model"].kind == "mutable-tag"


def test_leakage_clean_does_not_assert_uncontaminated_training(tmp_path):
    """A clean integrity check says the corpus we scanned is clean. No more."""
    from evalseal.leakage import scan
    from evalseal.mutate import build_leakage_corpus

    cfg = load_config(DEMO)
    corpus = build_leakage_corpus([], n_unrelated=6,
                                  shape_from=copy.deepcopy(cfg["eval_set"]))
    rep = scan(copy.deepcopy(cfg["eval_set"]), corpus)
    assert rep.scores["structural"].detected == 0

    r = issue(
        manifest=build_manifest(cfg, "strict"),
        eval_results={"passed": 18, "failed": 2, "gate": "pass"},
        leakage=rep,
        approver="t@example.com",
        key_path=tmp_path / "k.pem",
        agent_name="a",
    )
    integrity = r.payload["eval_integrity"]
    assert integrity["clean"] is True
    # "clean" is scoped to the corpus actually scanned, and the receipt says so.
    assert "not proof of training exposure" in r.payload["scope"]["leakage_claim"].lower()
    assert integrity["n_corpus_items"] == len(corpus)


def test_evaluation_result_is_not_part_of_the_configuration_identity(tmp_path):
    """The self-reference trap.

    If an evaluation score were a component of the configuration identity, then
    issuing evidence would change the identity that the evidence is about, and
    no receipt could ever verify against the thing it describes. The exclusion
    is structural rather than incidental, so it is pinned here.
    """
    import copy as _copy

    from evalseal.manifest import MATERIAL_COMPONENTS

    cfg = load_config(DEMO)
    base = build_manifest(cfg, "strict")

    assert "evaluation" not in MATERIAL_COMPONENTS
    assert "eval_results" not in MATERIAL_COMPONENTS

    # Two receipts with wildly different scores must describe the SAME identity.
    r_good = issue(manifest=base, eval_results={"passed": 20, "failed": 0, "gate": "pass"},
                   leakage=None, approver="t@example.com",
                   key_path=tmp_path / "k.pem", agent_name="a")
    r_bad = issue(manifest=base, eval_results={"passed": 1, "failed": 19, "gate": "fail"},
                  leakage=None, approver="t@example.com",
                  key_path=tmp_path / "k.pem", agent_name="a")
    assert r_good.configuration_address == r_bad.configuration_address, (
        "the evaluation result leaked into the configuration identity — "
        "issuing evidence would change what the evidence is about"
    )
    # And the eval SET is bound, while the eval RESULT is not.
    assert "eval_set" in base.components


def test_corpus_scope_is_declared_not_assumed(tmp_path):
    """Dependency scoping changes what counts as the same configuration, so it
    must be visible in the receipt rather than inferred from behaviour."""
    cfg = load_config(DEMO)
    m = build_manifest(cfg, "strict", resolved_dependencies=["policy-form-hw3.md"])
    r = issue(manifest=m, eval_results={"passed": 18, "failed": 2, "gate": "pass"},
              leakage=None, approver="t@example.com",
              key_path=tmp_path / "k.pem", agent_name="a", corpus_scope="resolved")
    assert r.payload["materiality"]["corpus_scope"] == "resolved"
    assert "scope=resolved" in m.components["corpus"].kind


def test_unanchored_signature_does_not_license_authority(sealed):
    """A signature with no trusted-key check is integrity, not authorship.

    Anyone can generate a keypair and mint a receipt that verifies against its
    own embedded key. Reporting that as authorship would be exactly the scope
    promotion this suite exists to prevent, so the licence is withheld.
    """
    _, m, r = sealed
    v = verify_against(r, m)
    lic = v.licenses()
    assert lic["integrity of the declaration"] is True
    assert lic["authority of the approver"] is False, (
        "authority was licensed without anchoring the signing key"
    )
    assert lic["execution"] is False
    assert lic["effective model"] is False


def test_forged_receipt_fails_against_a_trusted_key_set(tmp_path):
    """The attack the anchor exists to stop, pinned.

    An attacker with no access to the approver's key mints a receipt claiming a
    perfect score. It verifies against its own key -- and must fail once the
    verifier knows which keys may approve a release.
    """
    cfg = load_config(DEMO)
    m = build_manifest(cfg, "strict")

    real = issue(manifest=m, eval_results={"passed": 18, "failed": 2, "gate": "pass"},
                 leakage=None, approver="ops@example.com",
                 key_path=tmp_path / "real.pem", agent_name="a")
    forged = issue(manifest=m, eval_results={"passed": 20, "failed": 0, "gate": "pass"},
                   leakage=None, approver="ops@example.com",
                   key_path=tmp_path / "attacker.pem", agent_name="a")
    assert real.public_key != forged.public_key

    trusted = {real.public_key}

    good = verify_against(real, m, trusted_keys=trusted)
    assert good.permitted and good.trust_anchored
    assert good.verdict == "VERIFIED"
    assert good.licenses()["authority of the approver"] is True

    bad = verify_against(forged, m, trusted_keys=trusted)
    assert not bad.permitted, "a forged receipt was accepted against a trusted key set"
    assert not bad.trust_anchored
    assert bad.licenses()["authority of the approver"] is False


def test_forged_receipt_is_accepted_when_no_key_set_is_supplied(tmp_path):
    """The limitation, stated as a test rather than left as a surprise.

    With no trusted-key set the forgery DOES verify. That is a real property of
    this mode, and pinning it means nobody can later mistake the default for a
    trust decision.
    """
    cfg = load_config(DEMO)
    m = build_manifest(cfg, "strict")
    forged = issue(manifest=m, eval_results={"passed": 20, "failed": 0, "gate": "pass"},
                   leakage=None, approver="ops@example.com",
                   key_path=tmp_path / "attacker.pem", agent_name="a")
    v = verify_against(forged, m)
    assert v.permitted
    assert not v.trust_anchored
    assert "signer not anchored" in v.verdict
