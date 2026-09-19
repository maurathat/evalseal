"""The falsifier, as a test: every declared relation must behave as declared."""

from __future__ import annotations

import json
from pathlib import Path

from evalseal.conformance import run_conformance

DEMO = Path(__file__).resolve().parent.parent / "demo"


def _subject():
    tools = json.loads((DEMO / "tools.json").read_text(encoding="utf-8"))["tools"]
    return sorted(tools, key=lambda t: t["name"])


def test_conformance_passes():
    r = run_conformance(_subject())
    assert r.conformance_ok, [f.mutation for f in r.failures]


# Two rows are known to be vacuous for the relation columns: both re-serialize
# and re-parse, so the canonicalizer is handed the same parsed structure twice
# and its columns would read "stable" even with the canonicalizer removed. They
# still say something true about BYTE hashing, which is why they are kept and
# labelled rather than deleted.
KNOWN_VACUOUS = {"json_whitespace", "escape_form"}


def test_vacuous_rows_are_exactly_the_known_ones():
    """A NEW vacuous row must fail, while the known two stay visible.

    Asserting zero vacuous rows was wrong twice over: it was false, and it would
    have had to be deleted the moment it became false — leaving nothing guarding
    against a genuinely uninformative row being added later.
    """
    r = run_conformance(_subject())
    found = {x.mutation for x in r.vacuous}
    assert found == KNOWN_VACUOUS, (
        f"vacuous rows changed: {sorted(found)} vs known {sorted(KNOWN_VACUOUS)}"
    )


def test_informative_row_count_is_reported_honestly():
    r = run_conformance(_subject())
    assert r.n_informative() == len(r.rows) - len(KNOWN_VACUOUS)


def test_byte_false_alarms_exclude_vacuous_rows():
    """The byte baseline's failure count must not be padded by uninformative rows."""
    r = run_conformance(_subject())
    padded = sum(1 for x in r.rows
                 if x.category == "serialization" and not x.byte_stable
                 and x.profile_expected["strict"])
    assert r.byte_false_alarms() < padded, "vacuous rows are being counted as byte false alarms"


def test_byte_hashing_raises_false_alarms():
    """The baseline's weakness is measured, not asserted."""
    r = run_conformance(_subject())
    assert r.byte_false_alarms() > 0


def test_every_material_mutation_invalidates_under_both_profiles():
    r = run_conformance(_subject())
    for row in r.rows:
        if row.category == "material":
            assert row.profile_stable["strict"] is False
            assert row.profile_stable["eval"] is False
