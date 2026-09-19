"""Observational equality is weaker than certified substitutability.

Two executions that produce the same answer today have not thereby been shown to
be interchangeable. The answer may have matched by luck — a rounding collision, a
rule that happened not to fire, a document whose change was invisible at this
precision. An evidence gate that reuses on observed output alone is reusing on a
coincidence it cannot see.

This is the same lesson as the 6.44 collision in the external SEC reuse ladder
(docs/REUSE-LADDER.md): at precision 2 two different underlying computations
rounded to the same value, so an output-equality oracle called the substitution
valid; certified substitution refused because the resolved dependency differed;
raising the precision made the apparent equivalence vanish and proved the refusal
right.

EvalSeal's version of that refusal is tested here. The configuration below reads
a document, the document changes in a way that alters no decision, and the
evaluation result is byte-for-byte identical — and the evidence is still revoked.
That is the conservative direction, and it is deliberate.
"""

from __future__ import annotations

import copy
from pathlib import Path

from evalseal.evaluate import run_evaluation
from evalseal.manifest import build_manifest, load_config
from evalseal.receipt import issue, verify_against

DEMO = Path(__file__).resolve().parent.parent / "demo"


def _edit_read_document(cfg: dict) -> dict:
    """Change a consulted document without changing any decision it drives."""
    out = copy.deepcopy(cfg)
    for d in out["corpus"]:
        if d["name"] == "policy-form-hw3.md":
            d["text"] = d["text"] + (
                "\n## Clause 9.9 - Notices\n\nNotices under this form may be delivered "
                "electronically. This clause governs no loss type and drives no decision.\n"
            )
    return out


def test_identical_evaluation_results_do_not_imply_substitutability(tmp_path):
    """Same score, same failures, same everything observable — still revoked."""
    cfg = load_config(DEMO)
    other = _edit_read_document(cfg)

    before = run_evaluation(cfg)
    after = run_evaluation(other)

    # The observable outcome is identical in every respect a score board shows.
    assert before["passed"] == after["passed"]
    assert before["failed"] == after["failed"]
    assert before["score"] == after["score"]
    assert before["gate"] == after["gate"] == "pass"
    assert before["failures"] == after["failures"]
    assert before["resolved_dependencies"] == after["resolved_dependencies"]

    deps = before["resolved_dependencies"]
    approved = build_manifest(cfg, "strict", deps)
    receipt = issue(manifest=approved, eval_results=before, leakage=None,
                    approver="t@example.com", key_path=tmp_path / "k.pem",
                    agent_name="claims-review-agent", corpus_scope="resolved")
    assert receipt.approved

    runtime = build_manifest(other, "strict", deps)
    verdict = verify_against(receipt, runtime)

    assert not verdict.permitted, (
        "a consulted document changed and the evidence was carried forward anyway; "
        "that is reuse on observed output rather than on preserved dependency"
    )
    assert verdict.signature_valid
    assert not verdict.configuration_match


def test_the_refusal_is_scoped_to_documents_actually_read(tmp_path):
    """The conservatism has a limit: an unread document changing is not a change.

    Without this, the previous test would be satisfied by a system that simply
    refuses everything, which would be safe and useless.
    """
    cfg = load_config(DEMO)
    deps = run_evaluation(cfg)["resolved_dependencies"]
    approved = build_manifest(cfg, "strict", deps)
    receipt = issue(manifest=approved, eval_results={"passed": 18, "failed": 2, "gate": "pass"},
                    leakage=None, approver="t@example.com",
                    key_path=tmp_path / "k.pem", agent_name="a", corpus_scope="resolved")

    unread = copy.deepcopy(cfg)
    unread["corpus"].append({"name": "zz-never-read.md", "text": "# Unread\n\nNothing consults this.\n"})
    runtime = build_manifest(unread, "strict", deps)

    assert verify_against(receipt, runtime).permitted, (
        "an unread document changed and the evidence was revoked; the gate is "
        "refusing on environment change rather than on material dependency"
    )


def test_both_directions_are_needed_to_make_the_claim(tmp_path):
    """Neither test alone distinguishes the system from a degenerate one.

    Always-refuse passes the first and fails the second. Always-allow does the
    reverse. Only a dependency-scoped relation passes both, which is what makes
    'certified substitutability' a claim rather than a posture.
    """
    cfg = load_config(DEMO)
    deps = run_evaluation(cfg)["resolved_dependencies"]
    base = build_manifest(cfg, "strict", deps).configuration_address

    read_changed = build_manifest(_edit_read_document(cfg), "strict", deps).configuration_address

    unread = copy.deepcopy(cfg)
    unread["corpus"].append({"name": "zz-never-read.md", "text": "x\n"})
    unread_changed = build_manifest(unread, "strict", deps).configuration_address

    assert read_changed != base
    assert unread_changed == base
