"""Terminal rendering. The demo is 90 seconds, so the output is the interface.

Two rules held throughout: every number is labelled with the kind of evidence it
came from (deterministic or probabilistic), and nothing prints a claim the
signed receipt does not also contain.
"""

from __future__ import annotations

from typing import Any

from .address import short
from .leakage import LeakageReport
from .manifest import Manifest

__all__ = ["banner", "render_manifest", "render_leakage", "render_verdict", "render_receipt_summary"]

W = 62


def banner(title: str, subtitle: str | None = None) -> str:
    lines = ["=" * W, f" {title}"]
    if subtitle:
        lines.append(f" {subtitle}")
    lines.append("=" * W)
    return "\n".join(lines)


def section(title: str) -> str:
    return f"\n{title}\n{'-' * len(title)}"


def render_manifest(m: Manifest) -> str:
    out = [section(f"Agent configuration  (profile: {m.profile})")]
    out.append(m.render())
    out.append(f"\n  {'CONFIGURATION'.ljust(12)}  {short(m.configuration_address, 12)}")
    return "\n".join(out)


def render_leakage(r: LeakageReport, brief_when_clean: bool = False) -> str:
    """Render the three-detector table.

    ``brief_when_clean`` collapses a clean result to one line. A table of zeros
    in the lead command reads as "the detector does not work" to anyone who has
    not been told what it means, which is the opposite of what a clean eval set
    should convey.
    """
    if r.n_eval == 0 or r.n_corpus == 0:
        # Zero comparisons is not a clean result. Three detectors finding nothing
        # in nothing is the same output as three detectors finding nothing in a
        # real set, and printing CLEAN for it is how an empty eval set gets read
        # as a passing integrity check.
        return (f"{section('Eval set integrity')}\n"
                f"  NOT CHECKED — {r.n_eval} held-out item(s) vs {r.n_corpus} "
                f"candidate item(s); no comparison was possible, so this is the "
                f"absence of a result, not a clean one")
    if brief_when_clean and r.n_true_leaks == 0 and not any(
            s.detected for s in r.scores.values()):
        return (f"{section('Eval set integrity')}\n"
                f"  CLEAN — {r.n_eval} held-out items, 0 matches against "
                f"{r.n_corpus} same-domain candidate items\n"
                f"  (byte, structural and lexical all agree; run `evalseal leakage`\n"
                f"  for the full comparison)")
    out = [section("Eval set integrity")]
    out.append(
        f"  {r.n_eval} held-out items vs {r.n_corpus} candidate corpus items "
        f"({r.n_true_leaks} planted leaks)"
    )
    out.append("")
    head = f"  {'method':<12} {'evidence':<14} {'found':>6} {'missed':>7} {'false+':>7} {'recall':>7}"
    out.append(head)
    out.append("  " + "-" * (len(head) - 2))
    labels = {
        "byte": ("byte", "deterministic"),
        "structural": ("structural", "deterministic"),
        "lexical": ("lexical", "probabilistic"),
    }
    for key in ("byte", "structural", "lexical"):
        s = r.scores[key]
        name, kind = labels[key]
        out.append(
            f"  {name:<12} {kind:<14} {s.detected:>6} {s.missed:>7} "
            f"{s.false_positives:>7} {s.recall * 100:>6.0f}%"
        )
    out.append("")
    out.append(f"  structural adds {r.structural_gain} detection(s) over byte matching")
    out.append(f"  level 2 backend: {r.backend}, threshold tau={r.tau}")
    out.append("  boundary: all three measure corpus overlap, not training exposure.")
    return "\n".join(out)


def render_verdict(v: Any, diff_text: str = "") -> str:
    out = [section("Deployment status")]
    out.append(f"  {v.verdict}")
    out.append("")
    out.append(f"  receipt signature   {'valid' if v.signature_valid else 'INVALID'}")
    out.append(f"  receipt status      {'approved' if v.receipt_approved else 'NOT APPROVED'}")
    out.append(f"  evaluated config    {short(v.approved_address, 12)}")
    out.append(f"  runtime config      {short(v.runtime_address, 12)}")
    if not v.configuration_match and diff_text:
        out.append("")
        out.append("  what changed:")
        out.append(diff_text)
        out.append("")
        out.append("  The evaluation receipt does not apply to this configuration.")
    return "\n".join(out)


def render_receipt_summary(receipt: Any) -> str:
    p = receipt.payload
    out = [section("Receipt")]
    out.append(f"  agent        {p['agent']}")
    out.append(f"  release      {p['release']['label']}")
    out.append(f"  status       {p['release']['status']}")
    for reason in p["release"]["reasons"]:
        out.append(f"               - {reason}")
    out.append(f"  approved by  {p['release']['approved_by']}")
    out.append(f"  signature    ed25519, key {p.get('_pk', receipt.public_key)[:16]}…")
    out.append(f"  address      {short(receipt.address(), 12)}")
    return "\n".join(out)
