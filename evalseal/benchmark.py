"""The benchmark: seven rows -- six attacks and one refusal -- declared first.

Every row states what *should* happen before the run, and the command exits
non-zero if any row diverges. That is the difference between a benchmark and a
screenshot.

    1  cosmetic drift        re-serialize everything        evidence PRESERVED
    2  material drift        edit the system prompt         evidence INVALIDATED
    3  dependency drift      change an MCP tool definition  evidence INVALIDATED
    4  irrelevant dependency add an unread corpus document  evidence PRESERVED
    5  relevant dependency   change a document that was read  evidence INVALIDATED
    6  eval contamination    plant a structural duplicate   NO EVIDENCE ISSUED
    7  overclaim attempt     read VERIFIED as execution     INSUFFICIENT EVIDENCE

Rows 4 and 5 are the pair. Binding the whole corpus gets row 5 right and row 4
wrong; binding nothing gets row 4 right and row 5 wrong. Binding the *resolved*
dependency set is the only option that gets both, which is the finding the SEC
reuse ladder measures independently (docs/REUSE-LADDER.md).

Row 7 is the one most hackathon provenance systems would fail. It checks that a
successful verification is *not* interpretable as proof that the configuration
executed. A system that cannot fail this row does not know what it is claiming.

The vocabulary is deliberate. Evaluation evidence belongs to a configuration, not
to an agent's name: when the configuration changes, the new one does not inherit
the old one's evidence. "Evidence invalidated by drift" says that; "hash
mismatch" does not.
"""

from __future__ import annotations

import textwrap

import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .diff import manifest_diff, render_diff
from .evaluate import run_evaluation
from .leakage import scan
from .manifest import build_manifest, load_config
from .mutate import build_leakage_corpus
from .receipt import issue, verify_against

__all__ = ["Row", "run_benchmark", "render"]

PRESERVED = "evidence preserved"
INVALIDATED = "evidence invalidated by drift"
NOT_ISSUED = "no evidence issued"
INSUFFICIENT = "insufficient evidence"


@dataclass
class Row:
    n: int
    attack: str
    action: str
    expected: str
    actual: str
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.expected == self.actual


def _seal(cfg: dict[str, Any], key_path: Path, contaminate: bool = False):
    """Evaluate a configuration and issue evidence for it, if it qualifies."""
    results = run_evaluation(cfg)
    m = build_manifest(cfg, "strict", results["resolved_dependencies"])
    corpus = build_leakage_corpus(
        copy.deepcopy(cfg["eval_set"]) if contaminate else [], n_unrelated=12,
        shape_from=copy.deepcopy(cfg["eval_set"]),
    )
    leak = scan(copy.deepcopy(cfg["eval_set"]), corpus)
    r = issue(
        manifest=m,
        eval_results=results,
        leakage=leak,
        approver="claims-ops@example.com",
        key_path=key_path,
        agent_name=cfg["agent"].get("name", "agent"),
    )
    return m, r, leak


def run_benchmark(config_dir: str | Path, key_path: Path) -> list[Row]:
    from .cli import _mutate, _reserialize

    cfg = load_config(config_dir)
    approved_m, receipt, _ = _seal(cfg, key_path)
    deps = run_evaluation(cfg)["resolved_dependencies"]

    if not receipt.approved:
        raise SystemExit(
            "baseline configuration did not earn evidence; the benchmark needs a "
            "passing baseline before it can test drift"
        )

    rows: list[Row] = []

    def gate(runtime_cfg: dict[str, Any]) -> tuple[str, str]:
        rm = build_manifest(runtime_cfg, "strict", deps)
        d = manifest_diff(approved_m, rm, cfg, runtime_cfg)
        v = verify_against(receipt, rm, d)
        if v.permitted:
            return PRESERVED, "configuration identity unchanged"
        drifted = [c["component"] for c in d["components"] if not c["match"]]
        first = next((c for c in d["components"] if not c["match"] and c["fields"]), None)
        where = first["fields"][0]["path"] if first else ", ".join(drifted)
        return INVALIDATED, f"drift in {', '.join(drifted)} at {where}"

    # 1 — cosmetic drift: key order, escape form, NFD, CRLF, indentation.
    actual, detail = gate(_reserialize(copy.deepcopy(cfg)))
    rows.append(Row(1, "cosmetic drift", "re-serialize every artifact", PRESERVED, actual, detail))

    # 2 — material drift: the system prompt's disclosure rule is reversed.
    actual, detail = gate(_mutate(cfg, "prompt"))
    rows.append(Row(2, "material drift", "edit the system prompt", INVALIDATED, actual, detail))

    # 3 — dependency drift: an MCP tool description gains an instruction.
    actual, detail = gate(_mutate(cfg, "tool"))
    rows.append(Row(3, "dependency drift", "change an MCP tool definition", INVALIDATED, actual, detail))

    # 3b — irrelevant dependency: a corpus document nothing ever read.
    actual, detail = gate(_mutate(cfg, "irrelevant-corpus"))
    rows.append(Row(4, "irrelevant dependency", "add a corpus doc the evaluation never read",
                    PRESERVED, actual, detail))

    # 3c — relevant dependency: a corpus document the evaluation did read.
    actual, detail = gate(_mutate(cfg, "relevant-corpus"))
    rows.append(Row(5, "relevant dependency", "change a corpus doc the evaluation read",
                    INVALIDATED, actual, detail))

    # 4 — eval contamination: structurally equivalent copies of held-out items
    #     appear in the candidate corpus, so no evidence may be issued at all.
    _, contaminated_receipt, leak = _seal(cfg, key_path, contaminate=True)
    actual4 = NOT_ISSUED if not contaminated_receipt.approved else PRESERVED
    rows.append(
        Row(6, "eval contamination", "plant structural duplicates in the corpus",
            NOT_ISSUED, actual4,
            f"{leak.scores['structural'].detected} structural match(es) "
            f"({leak.scores['byte'].detected} visible to byte matching)")
    )

    # 5 — overclaim: attempt to read a VERIFIED result as evidence of execution.
    rm = build_manifest(cfg, "strict", deps)
    v = verify_against(receipt, rm)
    licensed = _what_verification_licenses(receipt, v)
    actual5 = INSUFFICIENT if not licensed["execution"] else "execution claimed"
    rows.append(
        Row(7, "overclaim attempt", "read VERIFIED as proof of execution",
            INSUFFICIENT, actual5,
            f"licenses: {', '.join(k for k, val in licensed.items() if val)}; "
            f"withholds: {', '.join(k for k, val in licensed.items() if not val)}")
    )

    return rows


def _what_verification_licenses(receipt: Any, v: Any) -> dict[str, bool]:
    """Exactly which conclusions a passing verification supports.

    Read off the verification result and the receipt's own declared layer, so
    that widening the claim anywhere shows up here rather than staying
    invisible. Note that "authority of the approver" is withheld unless the
    verifier anchored the signing key: without that, a signature is integrity
    only, and reporting it as authorship would be the same overclaim the row
    exists to catch.
    """
    layer = receipt.payload["scope"]["layer"]
    licensed = dict(v.licenses())
    licensed["execution"] = layer not in ("DECLARED", "PRESENTED")
    licensed["effective model"] = layer not in ("DECLARED", "PRESENTED", "EVALUATED")
    return licensed


def render(rows: list[Row]) -> str:
    """One row per attack, inside 80 columns.

    The verdict used to sit in a fifth column starting past column 90, and the
    overclaim row's detail ran to 184 characters, so at projector width the whole
    verdict column was off-screen and that row lost its entire `withholds:` half --
    the half the row exists to show. Verdict moved to the front; long details wrap.
    """
    head = f"  {'#':>2}  {'verdict':<12} {'attack':<22} expected -> result"
    out = [head, "  " + "-" * 74]
    for r in rows:
        out.append(f"  {r.n:>2}  {'PASS' if r.ok else '*** FAIL ***':<12} "
                   f"{r.attack:<22} {r.expected}")
        out.append(f"      {'':<12} {'':<22} -> {r.actual}")
        out.append(f"      {r.action}")
        for line in textwrap.wrap(r.detail, width=70):
            out.append(f"        {line}")
    passed = sum(1 for r in rows if r.ok)
    out.append("  " + "-" * 74)
    out.append(f"  {passed}/{len(rows)} as declared")
    out.append("")
    out.append("  Evidence belongs to the configuration that earned it.")
    out.append("    rows 2, 3, 5  a changed configuration fails to inherit it")
    out.append("    rows 1, 4     a change that cannot alter the answer keeps it")
    out.append("    row 6         evidence withheld from a contaminated evaluation")
    out.append("    row 7         the system refusing a conclusion it cannot support")
    return "\n".join(out)
