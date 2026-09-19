"""Drift detection, and the agreement between a verdict and its explanation."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from evalseal.cli import _mutate, _reserialize
from evalseal.diff import manifest_diff
from evalseal.manifest import build_manifest, load_config

DEMO = Path(__file__).resolve().parent.parent / "demo"
MATERIAL = ["tool", "prompt", "model", "permissions", "procedure", "schema", "homoglyph"]


@pytest.fixture(scope="module")
def base():
    cfg = load_config(DEMO)
    return cfg, build_manifest(cfg, "strict")


@pytest.mark.parametrize("kind", MATERIAL)
def test_material_change_moves_configuration_address(base, kind):
    cfg, m = base
    other = build_manifest(_mutate(cfg, kind), "strict")
    assert m.configuration_address != other.configuration_address, \
        f"{kind} changed nothing in the address — false accept"


def test_reserialization_does_not_move_configuration_address(base):
    cfg, m = base
    other = build_manifest(_reserialize(copy.deepcopy(cfg)), "strict")
    assert m.configuration_address == other.configuration_address, \
        "declared meaning-preserving transformations moved the address — false alarm"


@pytest.mark.parametrize("kind", MATERIAL)
def test_diff_agrees_with_address_verdict(base, kind):
    """A verifier whose explanation contradicts its verdict is not trustworthy."""
    cfg, m = base
    mutated = _mutate(cfg, kind)
    other = build_manifest(mutated, "strict")
    d = manifest_diff(m, other, cfg, mutated)

    assert d["match"] is False
    mismatched = [c for c in d["components"] if not c["match"]]
    assert mismatched, "address moved but the diff found no component"
    for c in mismatched:
        assert c["fields"], f"{c['component']} reported MISMATCH with no field-level cause"


def test_diff_finds_nothing_when_only_serialization_changed(base):
    cfg, m = base
    res = _reserialize(copy.deepcopy(cfg))
    d = manifest_diff(m, build_manifest(res, "strict"), cfg, res)
    assert d["match"] is True
    assert all(c["match"] for c in d["components"])


def test_tool_order_is_not_a_change(base):
    """A server returning its tools in a different order has not changed them."""
    cfg, m = base
    shuffled = copy.deepcopy(cfg)
    shuffled["tools"] = list(reversed(shuffled["tools"]))
    assert build_manifest(shuffled, "strict").configuration_address == m.configuration_address


def test_eval_set_order_is_not_a_change(base):
    cfg, m = base
    shuffled = copy.deepcopy(cfg)
    shuffled["eval_set"] = list(reversed(shuffled["eval_set"]))
    assert build_manifest(shuffled, "strict").configuration_address == m.configuration_address


def test_added_tool_is_a_change(base):
    cfg, m = base
    more = copy.deepcopy(cfg)
    more["tools"].append({"name": "exfiltrate", "description": "added after approval"})
    assert build_manifest(more, "strict").configuration_address != m.configuration_address


def test_a_permissions_mapping_is_refused_not_silently_flattened():
    """A denied operation must not address identically to a granted one.

    `sorted()` of a dict yields keys, so {"payment.transfer": false} used to
    produce the same permissions address as ["payment.transfer"], and the denied
    operation was admitted into configuration classes as an approved member.
    """
    import copy

    import pytest

    cfg = load_config(DEMO)
    granted = copy.deepcopy(cfg)
    granted["agent"]["allowed_operations"] = ["claim.read", "payment.transfer"]
    denied = copy.deepcopy(cfg)
    denied["agent"]["allowed_operations"] = {"claim.read": True, "payment.transfer": False}

    build_manifest(granted, "strict")  # fine
    with pytest.raises(ValueError, match="denied operation"):
        build_manifest(denied, "strict")

    as_string = copy.deepcopy(cfg)
    as_string["agent"]["allowed_operations"] = "claim.read, payment.transfer"
    with pytest.raises(ValueError, match="list of strings"):
        build_manifest(as_string, "strict")

    dupes = copy.deepcopy(cfg)
    dupes["agent"]["allowed_operations"] = ["claim.read", "claim.read"]
    with pytest.raises(ValueError, match="duplicates"):
        build_manifest(dupes, "strict")
