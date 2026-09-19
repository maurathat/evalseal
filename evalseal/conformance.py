"""The conformance table: does each relation behave exactly as declared?

This is the falsifier from the plan, executable. The project's identity claim
loses if either of these ever happens:

    * a declared serialization-equivalent transformation changes the address
      (false alarm -- the relation is too strict to be useful)
    * a declared material change leaves the address unchanged
      (false accept -- the relation is too loose to be safe)

Both are failures. The table reports each mutation against each profile, and
``conformance_ok`` is a single boolean the CLI exits non-zero on. A hackathon
project with a self-falsifying test that actually runs is a different kind of
artifact from one with a slide that says "rigorous".

The byte column is here for contrast, not as a competitor: byte hashing fails
every row, which is precisely why byte pinning produces false alarms on
re-serialized artifacts. That single column is the argument for the whole
approach, and ``realdata.py`` is what turns it from an argument into a number.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .address import addr_of, raw_byte_addr
from .canonical import canonicalize
from .mutate import ALL_MUTATIONS, Mutation

__all__ = ["ConformanceRow", "ConformanceResult", "run_conformance"]

PROFILES_TESTED = ("strict", "eval")


@dataclass
class ConformanceRow:
    mutation: str
    category: str
    note: str
    byte_stable: bool
    profile_stable: dict[str, bool]     # observed
    profile_expected: dict[str, bool]   # declared
    ok: bool
    # A mutation is vacuous when it could not alter this subject at all -- an
    # NFD test on pure ASCII, a CRLF test on text with no newlines. Such a row
    # "passes" while testing nothing, which is the most flattering kind of green
    # tick and therefore the one worth hunting. Vacuous rows are reported
    # separately and never counted as evidence.
    vacuous: bool = False


@dataclass
class ConformanceResult:
    rows: list[ConformanceRow]
    subject: str

    @property
    def conformance_ok(self) -> bool:
        return all(r.ok for r in self.rows)

    @property
    def failures(self) -> list[ConformanceRow]:
        return [r for r in self.rows if not r.ok]

    @property
    def vacuous(self) -> list[ConformanceRow]:
        return [r for r in self.rows if r.vacuous]

    def byte_false_alarms(self) -> int:
        """Rows where byte hashing invalidates something nothing actually changed.

        Vacuous rows are excluded: a mutation that could not touch this subject
        is not evidence of anything, in either direction.
        """
        return sum(
            1 for r in self.rows
            if r.category == "serialization" and not r.byte_stable
            and r.profile_expected["strict"] and not r.vacuous
        )

    def n_informative(self) -> int:
        return sum(1 for r in self.rows if not r.vacuous)

    def to_json(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "conformance_ok": self.conformance_ok,
            "rows_total": len(self.rows),
            "rows_informative": self.n_informative(),
            "rows_vacuous": [r.mutation for r in self.vacuous],
            "byte_false_alarms_on_declared_equivalents": self.byte_false_alarms(),
            "rows": [
                {
                    "mutation": r.mutation,
                    "category": r.category,
                    "note": r.note,
                    "byte_stable": r.byte_stable,
                    "observed": r.profile_stable,
                    "declared": r.profile_expected,
                    "ok": r.ok,
                    "vacuous": r.vacuous,
                }
                for r in self.rows
            ],
        }


def _row(subject: Any, m: Mutation) -> ConformanceRow:
    mutated = m.apply(subject)

    # The byte baseline hashes the bytes each side would actually be stored as.
    base_bytes = _raw(subject)
    mutated_bytes = m.serialize(mutated)
    byte_stable = raw_byte_addr(base_bytes) == raw_byte_addr(mutated_bytes)

    observed: dict[str, bool] = {}
    for p in PROFILES_TESTED:
        observed[p] = addr_of(subject, p) == addr_of(mutated, p)

    expected = {p: m.expected(p) for p in PROFILES_TESTED}

    # Vacuity has two shapes, and only one was being caught.
    #
    #   * the mutation changed nothing at all; or
    #   * the mutation changed only the SERIALIZATION, so the canonicalizer is
    #     handed the same parsed structure twice and the profile columns are a
    #     tautology -- they would read "stable" even with the canonicalizer
    #     removed entirely.
    #
    # The second kind still says something true about byte hashing, but it
    # exercises nothing in the relation under test, so it must not be counted as
    # evidence for it.
    # The precise test is whether the canonicalizer is handed the SAME INPUT
    # twice, which means comparing serializations in insertion order -- not
    # Python equality, because `{"a":1} == {"b":2,"a":1}`-style ordering
    # differences and `1 == 1.0` both compare equal in Python while being
    # exactly what the relation columns exist to exercise.
    same_input = _raw(subject) == _raw(mutated)
    vacuous = same_input

    return ConformanceRow(
        mutation=m.name,
        category=m.category,
        note=m.note,
        byte_stable=byte_stable,
        profile_stable=observed,
        profile_expected=expected,
        ok=observed == expected,
        vacuous=vacuous,
    )


def _raw(obj: Any) -> bytes:
    """The literal serialization a byte-pinning system would hash."""
    import json

    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


def run_conformance(subject: Any, subject_name: str = "tools.json") -> ConformanceResult:
    """Apply every mutation to ``subject`` and check declared vs observed."""
    return ConformanceResult(
        rows=[_row(subject, m) for m in ALL_MUTATIONS],
        subject=subject_name,
    )


def render(result: ConformanceResult) -> str:
    """Fixed-width table, sized for a slide screenshot."""
    head = f"{'mutation':<26} {'kind':<14} {'byte':>6} {'strict':>8} {'eval':>8}   verdict"
    lines = [head, "-" * len(head)]

    def mark(stable: bool) -> str:
        return "stable" if stable else "changed"

    for r in result.rows:
        if r.vacuous:
            verdict = ("VACUOUS for the relation columns — serialization-only, "
                       "canonicalizer not exercised")
        elif r.ok:
            verdict = "as declared"
        else:
            verdict = "*** CONFORMANCE FAILURE ***"
        lines.append(
            f"{r.mutation:<26} {r.category:<14} {mark(r.byte_stable):>6} "
            f"{mark(r.profile_stable['strict']):>8} {mark(r.profile_stable['eval']):>8}   {verdict}"
        )
    lines.append("-" * len(head))
    lines.append(
        f"{result.n_informative()}/{len(result.rows)} rows informative"
        + (f"; vacuous: {', '.join(r.mutation for r in result.vacuous)}" if result.vacuous else "")
    )
    lines.append(
        f"byte hashing raised {result.byte_false_alarms()} false alarm(s) on transformations "
        f"declared meaning-preserving under strict."
    )
    lines.append(
        "conformance: " + ("PASS — every relation behaved as declared" if result.conformance_ok
                           else f"FAIL — {len(result.failures)} row(s) diverged from declaration")
    )
    return "\n".join(lines)
