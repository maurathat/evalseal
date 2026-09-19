"""Leakage detection: three kinds of evidence, and the boundary between them."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from evalseal.leakage import scan, tau_sweep
from evalseal.manifest import load_config
from evalseal.mutate import build_leakage_corpus

DEMO = Path(__file__).resolve().parent.parent / "demo"


def _fixture():
    cfg = load_config(DEMO)
    ev = cfg["eval_set"]
    return ev, build_leakage_corpus(copy.deepcopy(ev), n_unrelated=12)


def test_byte_matching_catches_only_exact_copies():
    ev, corpus = _fixture()
    r = scan(copy.deepcopy(ev), corpus)
    assert set(r.scores["byte"].by_relation) <= {"exact"}


def test_structural_catches_reformatted_copies_byte_misses():
    ev, corpus = _fixture()
    r = scan(copy.deepcopy(ev), corpus)
    assert r.structural_gain > 0, "structural adds nothing over byte — the claim fails"
    caught = r.scores["structural"].by_relation
    assert caught.get("serialization", 0) > 0
    assert caught.get("structural", 0) > 0


def test_structural_does_not_catch_paraphrases():
    """The boundary: canonicalization is identity, not similarity."""
    ev, corpus = _fixture()
    r = scan(copy.deepcopy(ev), corpus)
    assert "paraphrase" not in r.scores["structural"].by_relation


def test_lexical_catches_paraphrases():
    ev, corpus = _fixture()
    r = scan(copy.deepcopy(ev), corpus, tau=0.70)
    assert r.scores["lexical"].by_relation.get("paraphrase", 0) > 0


def test_deterministic_methods_have_no_false_positives_by_construction():
    ev, corpus = _fixture()
    r = scan(copy.deepcopy(ev), corpus)
    assert r.scores["byte"].false_positives == 0
    assert r.scores["structural"].false_positives == 0


def test_deterministic_rows_do_not_move_with_tau():
    """Only level 2 is threshold-dependent; that is the point of separating them."""
    ev, corpus = _fixture()
    a = scan(copy.deepcopy(ev), copy.deepcopy(corpus), tau=0.50)
    b = scan(copy.deepcopy(ev), copy.deepcopy(corpus), tau=0.95)
    assert a.scores["byte"].detected == b.scores["byte"].detected
    assert a.scores["structural"].detected == b.scores["structural"].detected
    assert a.scores["lexical"].detected != b.scores["lexical"].detected


def test_tau_sweep_is_monotonic_in_detections():
    ev, corpus = _fixture()
    rows = tau_sweep(ev, corpus)
    counts = [r["detected"] for r in rows]
    assert counts == sorted(counts, reverse=True), "detections must not rise with tau"


def test_clean_corpus_yields_no_detections():
    cfg = load_config(DEMO)
    corpus = build_leakage_corpus([], n_unrelated=12,
                                  shape_from=copy.deepcopy(cfg["eval_set"]))
    r = scan(copy.deepcopy(cfg["eval_set"]), corpus)
    assert r.scores["structural"].detected == 0
    assert r.scores["byte"].detected == 0


def test_a_candidate_corpus_of_empty_objects_is_refused():
    """The clean demo path once built 12 copies of {} and reported CLEAN.

    Three detectors finding nothing in nothing produces the same output as three
    detectors finding nothing in a real corpus, and the receipt signed it as a
    passing integrity check. Refuse to build it at all.
    """
    with pytest.raises(ValueError, match="cannot be scanned"):
        build_leakage_corpus([], n_unrelated=12)


def test_the_clean_candidate_corpus_shares_the_eval_shape_but_no_values():
    cfg = load_config(DEMO)
    ev = cfg["eval_set"]
    corpus = build_leakage_corpus([], n_unrelated=12, shape_from=copy.deepcopy(ev))
    assert len({c["_raw"] for c in corpus}) == 12, "filler must not be 12 identical records"
    assert all(len(c["_raw"]) > 40 for c in corpus), "filler must carry the eval field shape"
    eval_raws = {json.dumps({k: v for k, v in e.items() if not k.startswith("_")},
                            ensure_ascii=False) for e in ev}
    assert not ({c["_raw"] for c in corpus} & eval_raws), "no eval value may survive"
