"""The compact renderer has to fit a projected terminal and drop no claim.

Two properties are worth a test rather than a rehearsal. First, the line and
column budget: at projector font size a terminal shows roughly 30 rows of 80
columns, and a wrapped line costs a whole row, so both dimensions are asserted.
Second, and more important, that compact mode is shorter *prose* and not weaker
*evidence* — every address, every measured number and every changed field path
that the full rendering prints must still be present. A compact mode that
quietly dropped a number would make the demo's shortest path also its least
honest one.
"""

from __future__ import annotations

from pathlib import Path

from evalseal.address import short
from evalseal.graph import build_graph, render_graph

DEMO = Path(__file__).resolve().parent.parent / "demo"

# A projected terminal at a legible font size. The header and the trailing
# "written to" line are printed by the CLI, not the renderer, so the renderer's
# own budget is the terminal minus those four rows.
TERMINAL_ROWS = 30
TERMINAL_COLS = 80
RENDERER_ROWS = TERMINAL_ROWS - 4


def _render(tmp_path, compact, **kw):
    g, drift = build_graph(str(DEMO), tmp_path / "k.pem", **kw)
    return render_graph(g, drift, compact=compact), g, drift


def _numbers(text: str) -> set[str]:
    """Every digit run of two or more characters: addresses, counts, versions."""
    out, cur = set(), ""
    for ch in text:
        if ch.isdigit():
            cur += ch
        else:
            if len(cur) >= 2:
                out.add(cur)
            cur = ""
    if len(cur) >= 2:
        out.add(cur)
    return out


def test_compact_replay_fits_a_projected_terminal(tmp_path):
    text, _, _ = _render(tmp_path, True, replay_real=True)
    lines = text.splitlines()
    assert len(lines) <= RENDERER_ROWS, f"{len(lines)} lines, budget {RENDERER_ROWS}"
    over = [(i + 1, len(l)) for i, l in enumerate(lines) if len(l) > TERMINAL_COLS]
    assert not over, f"lines past {TERMINAL_COLS} columns wrap and cost a row: {over}"


def test_compact_widen_child_fits_a_projected_terminal(tmp_path):
    text, _, _ = _render(tmp_path, True, widen_child=True)
    assert len(text.splitlines()) <= RENDERER_ROWS


def test_compact_keeps_both_configuration_addresses(tmp_path):
    compact, g, _ = _render(tmp_path, True, replay_real=True)
    for n in g.blocked_nodes():
        assert short(n.verdict.approved_address, 12) in compact
        assert short(n.verdict.runtime_address, 12) in compact
        assert short(n.verdict.approved_address, 12) != short(n.verdict.runtime_address, 12)


def test_compact_drops_no_measured_number(tmp_path):
    """Prose may go; evidence may not."""
    full, _, _ = _render(tmp_path, False, replay_real=True)
    compact, _, _ = _render(tmp_path, True, replay_real=True)
    missing = _numbers(full) - _numbers(compact)
    assert not missing, f"compact rendering lost measured values: {sorted(missing)}"


def test_compact_still_names_the_real_package_and_versions(tmp_path):
    compact, _, drift = _render(tmp_path, True, replay_real=True)
    assert drift["package"] in compact
    assert drift["from"] in compact and drift["to"] in compact
    assert "not authored for this demo" in compact


def test_compact_still_reports_the_blocked_verdict(tmp_path):
    compact, g, _ = _render(tmp_path, True, replay_real=True)
    assert "RUN BLOCKED" in compact
    for n in g.blocked_nodes():
        assert n.name in compact


def test_truncated_field_list_declares_how_many_it_hid(tmp_path):
    """Printing 1 of 6 changed fields without saying so understates the drift."""
    for compact in (True, False):
        text, g, _ = _render(tmp_path, compact, replay_real=True)
        shown = text.count("[changed]")
        total = sum(
            len(c["fields"])
            for n in g.blocked_nodes()
            for c in n.diff.get("components", [])
            if not c["match"]
        )
        if total > shown:
            assert f"{total - shown} more field(s) changed" in text


def test_compact_admissible_path_is_one_claim_not_a_summary(tmp_path):
    compact, g, _ = _render(tmp_path, True)
    if not g.blocked_nodes():
        assert "RUN ADMISSIBLE" in compact
        # The claim is scoped to the root deliberately: `check_authority_narrows`
        # compares every node to the root, not to its delegator (KNOWN-ISSUES #4),
        # so the line must not say "every hop narrows".
        assert "every hop narrows" not in compact
        assert "root did not" in compact


def test_an_empty_eval_set_is_not_reported_clean():
    """Zero comparisons is the absence of a result, not a passing one."""
    from evalseal.leakage import LeakageReport, MethodScore
    from evalseal.report import render_leakage

    empty = LeakageReport(
        scores={k: MethodScore(method=k, level=k, detected=0)
                for k in ("byte", "structural", "lexical")},
        detections=[], n_eval=0, n_corpus=12, n_true_leaks=0, tau=0.8, backend="local")
    text = render_leakage(empty, brief_when_clean=True)
    assert "CLEAN" not in text
    assert "NOT CHECKED" in text


# --- the "runs" column is a release check, not a wording preference ---------


def _adapter_src():
    return (Path(__file__).resolve().parent.parent
            / "integration" / "run_agent.py").read_text(encoding="utf-8")


def test_the_runs_column_is_derived_from_provenance_never_hardcoded():
    """An earlier build printed a constant 'yes' in this column.

    The value on screen is a claim that an agent ran. It must be a function of
    the observed provenance and nothing else. This test is deliberately literal:
    if someone rewrites either line, it fires, and the rewrite has to be
    justified rather than slipping through with the prose still saying
    "every agent above ran and answered".
    """
    src = _adapter_src()
    assert 'ran = {"failed": "no", "replay": "replayed"}.get(prov, "yes")' in src
    assert 'print(f"  {label:<36} {pt:<9} {ee:<21} {ran}")' in src
    # and no literal verdict is interpolated into that row
    assert '{ee:<21} yes' not in src


def test_provenance_is_never_silently_live():
    """No key means replay; a failing call means failed, not a quiet pass."""
    import integration.run_agent as ra

    cfg = {"agent": {"name": "x"}}
    answer, prov, trace = ra.run_agent(cfg, "q", "t1", None)
    assert prov == "replay" and trace == {}

    def boom(*a, **k):
        raise ra.ApiError("400 from the provider")

    real, ra.call_model = ra.call_model, boom
    try:
        answer, prov, trace = ra.run_agent(cfg, "q", "t1", "not-a-real-key")
    finally:
        ra.call_model = real
    assert prov == "failed"
    assert "model call failed" in answer
    assert trace == {}
