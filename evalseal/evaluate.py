"""A small deterministic agent and its evaluation.

No model inference. That is a feature for a one-day build: the evaluation result
is reproducible, the demo runs on a plane, and nothing in the argument depends on
a sampled output. The agent implements the CR-04 procedure as code, which means
the evaluation gate is real -- editing ``procedure.md``'s payout ceiling and
re-running genuinely changes which items pass.

Swap ``decide`` for a model call when connecting a real agent; the receipt
machinery does not care where the decision came from.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["decide", "decide_with_dependencies", "run_evaluation"]

_CEILING = re.compile(r"capped at USD ([\d,]+) \(([\d,]+) cents\)", re.I)


def payout_ceiling_cents(procedure: str, default: int = 1_000_000) -> int:
    """Read the ceiling out of the procedure text, so the procedure is load-bearing."""
    m = _CEILING.search(procedure)
    if not m:
        return default
    return int(m.group(2).replace(",", ""))


def decide(item: dict[str, Any], policy_terms: str, ceiling_cents: int) -> str:
    """Apply CR-04 to one claim. Kept for callers that do not need dependencies."""
    return decide_with_dependencies(
        item, [{"name": "policy", "text": policy_terms}], ceiling_cents
    )[0]


def decide_with_dependencies(
    item: dict[str, Any],
    docs: list[dict[str, str]],
    ceiling_cents: int,
) -> tuple[str, set[str]]:
    """Apply CR-04, and report which corpus documents were actually consulted.

    The returned dependency set is what makes dependency-scoped addressing
    possible. A document that no decision ever read cannot have changed any
    answer, so an evaluation result should survive its addition -- and should
    not survive a change to a document that was read. Recording the set is the
    only way to tell those two cases apart, and the distinction is measurable:
    see the C_irrelevant_dependency / D_relevant_dependency split in the SEC
    reuse-ladder measurement (docs/REUSE-LADDER.md).
    """
    used: set[str] = set()

    def find(term: str) -> bool:
        """Look a clause up across the corpus, recording every document SEARCHED.

        Recording only the documents where the term was *found* was a false
        accept: a term that is absent is exactly what decides the answer on every
        fall-through path, and the document whose silence decided it would go
        unbound. Editing that document could then change the answer while the
        configuration address stayed put. A miss is a read.
        """
        hit = False
        for d in docs:
            used.add(d["name"])
            if term in d["text"].lower():
                hit = True
        return hit

    amount = item["loss"]["amount_cents"]
    limit = item["policy"]["limit_cents"]
    loss_type = item["loss"]["type"].lower()
    date = item["loss"]["date"]
    period = item["policy"]["period"]

    # These three rules are decided from the claim and the procedure alone; no
    # corpus document is consulted, so none is recorded.
    if not (period["start"] <= date <= period["end"]):
        return "escalate", used
    if amount > limit:
        return "escalate", used
    if amount > ceiling_cents:
        return "escalate", used

    if "vandalism" in loss_type and find("vandalism is excluded"):
        return "deny", used
    for w in ("flood", "earth movement", "wear and tear", "neglect"):
        if w in loss_type and find(w):
            return "deny", used

    covered = any(w in loss_type for w in ("fire", "smoke", "wind", "hail", "water", "frozen pipe"))
    if covered:
        find("covered peril")
        return "approve", used
    if "theft" in loss_type:
        # Bulletin 2026-04 requires a police report number; the eval items do
        # not carry one, so the procedure says escalate rather than guess.
        find("police report")
        return "escalate", used
    return "escalate", used


def run_evaluation(config: dict[str, Any]) -> dict[str, Any]:
    """Run the agent over the held-out set and score it against expected decisions."""
    docs = config["corpus"]
    ceiling = payout_ceiling_cents(config["procedure"])
    resolved: set[str] = set()

    passed, failed, failures = 0, 0, []
    for item in config["eval_set"]:
        got, used = decide_with_dependencies(item, docs, ceiling)
        resolved |= used
        want = item.get("expected_decision")
        if got == want:
            passed += 1
        else:
            failed += 1
            failures.append({"id": item["id"], "expected": want, "got": got})

    total = passed + failed
    return {
        "n_items": total,
        "passed": passed,
        "failed": failed,
        "score": round(passed / total, 4) if total else 0.0,
        # The release gate: a fixed pass threshold, declared here rather than
        # inferred from whatever the run happened to produce.
        "threshold": 0.75,
        "gate": "pass" if total and (passed / total) >= 0.75 else "fail",
        "failures": failures[:5],
        "harness": "deterministic rule agent (evalseal.evaluate); no model inference",
        # The documents the evaluation actually read. Everything else in the
        # corpus was present but never consulted, and therefore cannot have
        # changed any answer.
        "resolved_dependencies": sorted(resolved),
        "corpus_present": sorted(d["name"] for d in docs),
    }
