"""Signing: what a signature protects, and what tampering it catches."""

from __future__ import annotations

import copy
from pathlib import Path

from evalseal.manifest import build_manifest, load_config
from evalseal.receipt import issue, verify_against
from evalseal.sign import load_or_create_key, public_key_hex, sign_payload, verify_payload

DEMO = Path(__file__).resolve().parent.parent / "demo"
RESULTS = {"passed": 18, "failed": 2, "gate": "pass"}


def _receipt(tmp_path, cfg=None):
    cfg = cfg or load_config(DEMO)
    m = build_manifest(cfg, "strict")
    return cfg, m, issue(manifest=m, eval_results=RESULTS, leakage=None,
                         approver="t@example.com", key_path=tmp_path / "k.pem",
                         agent_name="claims-review-agent")


def test_roundtrip(tmp_path):
    _, m, r = _receipt(tmp_path)
    assert verify_against(r, m).signature_valid


def test_key_is_persisted_and_reused(tmp_path):
    k1 = load_or_create_key(tmp_path / "k.pem")
    k2 = load_or_create_key(tmp_path / "k.pem")
    assert public_key_hex(k1) == public_key_hex(k2)


def test_edited_payload_fails_verification(tmp_path):
    _, m, r = _receipt(tmp_path)
    tampered = copy.deepcopy(r.payload)
    tampered["evaluation"]["passed"] = 20
    assert not verify_payload(tampered, r.signature, r.public_key, "strict")


def test_promoting_blocked_to_approved_fails(tmp_path):
    """The obvious attack: flip the verdict in the JSON file."""
    cfg = load_config(DEMO)
    m = build_manifest(cfg, "strict")
    r = issue(manifest=m, eval_results={"passed": 3, "failed": 17, "gate": "fail"},
              leakage=None, approver="t@example.com", key_path=tmp_path / "k.pem",
              agent_name="a")
    assert not r.approved
    r.payload["release"]["status"] = "APPROVED"
    assert r.approved                                  # the field says so...
    assert not verify_against(r, m).signature_valid    # ...and the signature does not
    assert not verify_against(r, m).permitted


def test_swapping_the_configuration_address_fails(tmp_path):
    _, m, r = _receipt(tmp_path)
    r.payload["configuration"]["address"] = "es1:strict:sha256:" + "0" * 64
    v = verify_against(r, m)
    assert not v.signature_valid
    assert not v.configuration_match


def test_wrong_public_key_fails(tmp_path):
    _, _, r = _receipt(tmp_path)
    other = load_or_create_key(tmp_path / "other.pem")
    assert not verify_payload(r.payload, r.signature, public_key_hex(other), "strict")


def test_signature_covers_the_profile_declaration(tmp_path):
    """Swapping the relation out from under a receipt must not verify."""
    _, _, r = _receipt(tmp_path)
    tampered = copy.deepcopy(r.payload)
    tampered["profile"]["collapse_numeric_form"] = True
    assert not verify_payload(tampered, r.signature, r.public_key, "strict")


def test_save_and_load_roundtrip(tmp_path):
    _, m, r = _receipt(tmp_path)
    r.save(tmp_path / "receipt.json")
    from evalseal.receipt import load
    again = load(tmp_path / "receipt.json")
    assert again.payload == r.payload
    assert verify_against(again, m).permitted
