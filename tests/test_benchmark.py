"""The benchmark and the delegation graph, held to their declared expectations."""

from __future__ import annotations

from pathlib import Path

from evalseal.benchmark import INSUFFICIENT, INVALIDATED, NOT_ISSUED, PRESERVED, run_benchmark
from evalseal.graph import build_graph, find_real_drift

DEMO = Path(__file__).resolve().parent.parent / "demo"


def test_all_five_attacks_behave_as_declared(tmp_path):
    rows = run_benchmark(DEMO, tmp_path / "k.pem")
    bad = [f"{r.n} {r.attack}: expected {r.expected}, got {r.actual}" for r in rows if not r.ok]
    assert not bad, bad


def test_benchmark_covers_every_drift_class_plus_refusal(tmp_path):
    rows = {r.n: r for r in run_benchmark(DEMO, tmp_path / "k.pem")}
    assert rows[1].expected == PRESERVED       # cosmetic
    assert rows[2].expected == INVALIDATED     # material
    assert rows[3].expected == INVALIDATED     # tool dependency
    assert rows[4].expected == PRESERVED       # irrelevant corpus dependency
    assert rows[5].expected == INVALIDATED     # relevant corpus dependency
    assert rows[6].expected == NOT_ISSUED      # contamination
    assert rows[7].expected == INSUFFICIENT    # overclaim


def test_dependency_rows_require_resolved_scope_to_both_pass(tmp_path):
    """Rows 4 and 5 are the pair no global corpus binding can satisfy.

    Binding the whole corpus gets row 5 right and row 4 wrong. This asserts the
    two are genuinely in tension, so the pair cannot quietly degrade into two
    copies of the same test.
    """
    import copy

    from evalseal.cli import _mutate
    from evalseal.manifest import build_manifest, load_config

    cfg = load_config(DEMO)
    full = build_manifest(cfg, "strict")                      # whole-corpus scope
    irrelevant = build_manifest(_mutate(cfg, "irrelevant-corpus"), "strict")
    assert full.configuration_address != irrelevant.configuration_address, (
        "whole-corpus scope should false-block on an unread addition; if it does "
        "not, row 4 proves nothing"
    )


def test_contamination_row_reports_the_byte_baseline_too(tmp_path):
    """The contamination row must show what byte matching would have seen."""
    rows = {r.n: r for r in run_benchmark(DEMO, tmp_path / "k.pem")}
    assert "visible to byte matching" in rows[6].detail


def test_overclaim_row_enumerates_what_is_withheld(tmp_path):
    rows = {r.n: r for r in run_benchmark(DEMO, tmp_path / "k.pem")}
    detail = rows[7].detail
    assert "withholds" in detail
    assert "execution" in detail.split("withholds")[1]


# --- delegation -----------------------------------------------------------

def test_clean_graph_is_admissible(tmp_path):
    g, drift = build_graph(DEMO, tmp_path / "k.pem")
    assert drift is None
    assert g.path_admissible()
    assert len(g.nodes) == 3


def test_each_node_has_its_own_configuration_identity(tmp_path):
    from evalseal.manifest import build_manifest

    g, _ = build_graph(DEMO, tmp_path / "k.pem")
    addrs = {n: build_manifest(node.config, "strict").configuration_address
             for n, node in g.nodes.items()}
    assert len(set(addrs.values())) == 3, "delegated agents must not share an identity"


def test_child_drift_blocks_the_run_but_not_the_parent(tmp_path):
    """Evidence does not aggregate upward: the parent verifying is not enough."""
    g, _ = build_graph(DEMO, tmp_path / "k.pem", mutate_child="tool")
    assert not g.path_admissible()
    blocked = {n.name for n in g.blocked_nodes()}
    assert blocked == {"research-agent"}
    assert g.nodes["claims-review-coordinator"].admissible, \
        "the coordinator's own configuration did not change, so it should still verify"


def test_real_drift_replay_is_a_pure_in_place_redefinition(tmp_path):
    """The replayed pair must not rename or add tools, or the diff misleads."""
    drift = find_real_drift()
    if drift is None:
        import pytest

        pytest.skip("no harvested realdata/tools present")
    before = {t.get("name") for t in drift["tools_before"]}
    after = {t.get("name") for t in drift["tools_after"]}
    assert before == after
    assert drift["all_changed"], "replayed pair must contain a description change"


def test_real_drift_replay_blocks_the_delegated_node(tmp_path):
    g, drift = build_graph(DEMO, tmp_path / "k.pem", replay_real=True)
    if drift is None:
        import pytest

        pytest.skip("no harvested realdata/tools present")
    assert not g.path_admissible()
    assert {n.name for n in g.blocked_nodes()} == {"research-agent"}


# --- authority narrowing (the primer's Layer 7 open problem) ---------------

def test_clean_delegation_narrows_authority(tmp_path):
    """Every child must hold a subset of its delegator's operations.

    A demo that prints ADMISSIBLE over a permission set that WIDENED is the
    inverse of what a delegation chain guarantees, and it is the first thing a
    regulated-industry reviewer reads.
    """
    from evalseal.graph import build_graph

    g, _ = build_graph(DEMO, tmp_path / "k.pem")
    root = g.nodes[g.root]
    parent_ops = set(root.config["agent"]["allowed_operations"])
    for name, node in g.nodes.items():
        if name == g.root:
            continue
        child_ops = set(node.config["agent"]["allowed_operations"])
        assert child_ops <= parent_ops, (
            f"{name} holds {sorted(child_ops - parent_ops)} that its delegator does not"
        )
        assert not node.widened
    assert g.path_admissible()


def test_widened_authority_blocks_even_though_configuration_verifies(tmp_path):
    """Identity and authority are different questions.

    The widened node's configuration verifies perfectly. The run must still be
    inadmissible, or an address is being asked to answer something it cannot.
    """
    from evalseal.graph import build_graph

    g, _ = build_graph(DEMO, tmp_path / "k.pem", widen_child=True)
    assert not g.path_admissible()
    blocked = {n.name for n in g.blocked_nodes()}
    assert blocked == {"research-agent"}

    node = g.nodes["research-agent"]
    assert node.widened == ["payment.execute"]
    # The configuration itself is unchanged and verifies; only authority failed.
    assert node.verdict.permitted, (
        "this test is only meaningful while the configuration still verifies"
    )
    assert not node.admissible


def test_narrowing_is_checked_against_the_delegator_not_a_global_set(tmp_path):
    from evalseal.graph import build_graph, check_authority_narrows

    g, _ = build_graph(DEMO, tmp_path / "k.pem")
    g.nodes[g.root].config["agent"]["allowed_operations"] = ["claim.read"]
    check_authority_narrows(g.nodes, g.root)
    assert g.nodes["policy-agent"].widened, "narrowing must be relative to the delegator"
