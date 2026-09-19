"""Class receipts: licensing a bounded set of configurations, not just one.

A point receipt binds one configuration address, and a runtime configuration is
admissible only if it reproduces that exact address. That is the right primitive
for a release: one agent, evaluated, deployed. It is the wrong primitive for a
swarm, where agents are composed at runtime from a pool of tools and documents
and no exact address was ever evaluated. Under point identity every dynamically
composed agent is BLOCKED -- not a false accept, but mass false blocking, which
in practice means the gate gets switched off. A control everyone disables is
worth less than no control, because it also supplies false comfort.

So a class receipt binds an addressed *membership predicate*:

    model        pin        exactly this model
    prompt       pin        exactly this prompt
    tools        subset_of  any subset of these approved tool DEFINITIONS
    corpus       subset_of  any subset of these approved documents
    permissions  subset_of  no operation outside these approved operations
    ...

The question changes from "did anything change?" to "did anything change outside
the variation the evidence was issued for?"

VOCABULARY, deliberately. This establishes *admissibility under a declared
class*, never behavioural equivalence. Two members of one class are not
interchangeable in behaviour: a toolset of {calculator} and a toolset of
{database_writer} can both satisfy a subset constraint. The words used here are
configuration class, membership predicate, class receipt, and member
admissible / outside class. "Equivalent" is not among them and should not be
used about two members of a class.

A class is a WEAKENING. Four rules keep the weakening bounded and visible,
because a predicate is exactly the kind of object that quietly grows until it
admits everything:

1. **Fail closed by construction.** Every permitted degree of freedom is
   serialized into the class. There is no wildcard, no regex, no callable, and no
   "omitted means unconstrained": a component with no rule is refused outright,
   and ``from_evaluated`` gives every component it was not told to vary an exact
   pin. Unspecified is exact identity, never freedom.

2. **The class names members the evidence exercised.** Enumerated members come
   from evaluated manifests. Note precisely what this bounds: it bounds
   *members*, not *configurations*. A runtime toolset of {A, B} drawn from an
   evaluated {A, B, C} is a configuration that was never evaluated, and it is
   admissible -- that is the whole point. What is refused is a class naming a
   tool definition, document or operation that appears in no evaluated
   configuration, because that is self-approval wearing the costume of a
   predicate.

   The open research question this exposes, and does not answer: *what does
   evaluating one member license about an unseen member?* For some dimensions,
   nothing. For others there may be a defensible monotonic rule -- an agent
   evaluated with {read, write} authority arguably licenses a runtime member
   holding {read}, under an explicitly declared authority-subset relation, while
   `payment.execute` must fail. Every relation here is of that explicitly
   declared kind. None of them extrapolate.

3. **The class is an artifact.** It is canonicalized, addressed, and signed with
   the evidence, and its address covers both the rules and the evidence basis
   they rest on. Widening `tools ⊆ {A,B,C}` to `tools ⊆ {A,B,C,D}` changes the
   class identity. That is the class-level form of the project's thesis: the
   relation under which evidence transfers is part of what earned the evidence.

4. **A class verdict never reads like a point verdict.** ``ADMISSIBLE (member of
   class ...)`` is a weaker statement than ``VERIFIED``, and reporting them
   identically would be the same category of error as reporting an unanchored
   signature as authority.

Members of the tools component are tool *definition* addresses, never names. An
approved name whose definition changed is a different member and falls outside
the class. That is deliberate: name-keyed membership would re-open exactly the
drift this project measures on published MCP servers.

What this does NOT do: it says nothing about whether members compose safely. Two
individually evaluated tools may be dangerous together, and no subset rule sees
that. Combination risk is a real gap, stated here rather than discovered.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .address import addr_of, short
from .manifest import MATERIAL_COMPONENTS, Manifest

__all__ = [
    "ComponentRule",
    "ConfigurationClass",
    "from_declaration",
    "ClassDecision",
    "members_of",
    "evaluated_members",
    "satisfies",
    "covered_by",
    "widens_over",
    "from_evaluated",
    "InadmissibleClass",
    "SUBSETTABLE",
    "RULE_KINDS",
]

# Components whose membership can be checked element by element, because the
# manifest carries the member identifiers. Everything else can only be pinned or
# chosen from an enumerated list of whole-component addresses.
SUBSETTABLE = ("tools", "corpus", "permissions")

# The complete set of relations. Enumerations of addresses, nothing evaluable.
RULE_KINDS = ("pin", "any_of", "subset_of")


class InadmissibleClass(Exception):
    """The class itself is not a well-formed claim, so nothing was verified.

    Raised rather than returned: a malformed class is not a failed check on a
    configuration, it is the absence of a check. Returning "not a member" would
    let a caller log a blocked run and move on, when what actually happened is
    that no predicate was ever evaluated.
    """


@dataclass(frozen=True)
class ComponentRule:
    component: str
    kind: str
    members: tuple[str, ...]

    def declare(self) -> dict[str, Any]:
        return {"component": self.component, "relation": self.kind,
                "members": sorted(self.members)}


@dataclass
class ConfigurationClass:
    name: str
    profile: str
    rules: dict[str, ComponentRule]
    # The evaluated configuration addresses this class rests on. Inside the
    # addressed declaration, so a class backed by different evidence is a
    # different class even when its rules are identical.
    basis: tuple[str, ...] = ()

    def declare(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "profile": self.profile,
            "rules": [self.rules[c].declare() for c in sorted(self.rules)],
            "evidence_basis": sorted(self.basis),
        }

    def address(self) -> str:
        return addr_of(self.declare(), self.profile)

    def render(self) -> str:
        width = max(len(c) for c in self.rules)
        out = []
        for c in MATERIAL_COMPONENTS:
            r = self.rules.get(c)
            if r is None:
                continue
            detail = (short(r.members[0], 12) if r.kind == "pin"
                      else f"{len(r.members)} approved member(s)")
            out.append(f"    {c.ljust(width)}  {r.kind:<10} {detail}")
        return "\n".join(out)

    def validate(self) -> None:
        """A class is well formed, or nothing downstream means anything."""
        unconstrained = [c for c in MATERIAL_COMPONENTS if c not in self.rules]
        if unconstrained:
            raise InadmissibleClass(
                f"no rule for material component(s) {unconstrained}. An omitted component "
                "is not a free one: unspecified must mean exact identity, so state a pin. "
                "Silently admitting every value of a component is how a class stops being "
                "a claim."
            )
        for c, r in self.rules.items():
            if r.kind not in RULE_KINDS:
                raise InadmissibleClass(
                    f"unknown relation {r.kind!r} for {c}; the relations are {list(RULE_KINDS)} "
                    "and there is deliberately no wildcard among them"
                )
            if not r.members:
                raise InadmissibleClass(
                    f"the rule for {c} names no members; an empty enumeration is either a "
                    "class that admits nothing or a mistake, and it must not be guessed"
                )
            if r.kind == "pin" and len(r.members) != 1:
                raise InadmissibleClass(
                    f"pin rule for {c} names {len(r.members)} members; a pin is one address"
                )
            if r.kind == "subset_of" and c not in SUBSETTABLE:
                raise InadmissibleClass(
                    f"subset_of is not available for {c}: the manifest carries no member "
                    f"identifiers for it, only a whole-component address, so membership "
                    f"could only be approximated. Use pin or any_of. Subsettable: "
                    f"{list(SUBSETTABLE)}"
                )
        if not self.basis:
            raise InadmissibleClass(
                "the class declares no evidence basis; a class that does not say which "
                "evaluated configurations back it cannot be checked against them"
            )


@dataclass
class ClassDecision:
    ok: bool
    class_address: str
    findings: list[dict[str, Any]]

    def render(self) -> str:
        return "\n".join(
            f"    {'ok  ' if f['ok'] else 'OUT '} {f['component']:<12} "
            f"{f['relation']:<10} {f['detail']}"
            for f in self.findings
        )

    def outside(self) -> list[str]:
        return [f["component"] for f in self.findings if not f["ok"]]


# --------------------------------------------------------------------------
# member extraction
# --------------------------------------------------------------------------


def members_of(manifest: Manifest, component: str) -> list[str]:
    """The element-level identifiers of a subsettable component.

    Read off the manifest rather than the source configuration, because a
    verifier only ever holds the presented artifacts. If this needed the original
    config directory, class membership could not be checked at a deployment gate,
    which is the only place it is useful.
    """
    c = manifest.components.get(component)
    if c is None:
        return []
    if component == "corpus":
        return sorted(d["addr"] for d in c.detail.get("docs", []))
    if component == "permissions":
        return sorted(c.detail.get("allowed_operations", []))
    if component == "tools":
        addrs = c.detail.get("tool_addrs")
        if addrs is None:
            raise InadmissibleClass(
                "this manifest carries no per-tool definition addresses, so tool membership "
                "cannot be checked element by element. Rebuild the manifest with a version "
                "that records them rather than approximating membership by tool name -- "
                "name-keyed membership is the drift this project exists to catch"
            )
        return sorted(addrs.values())
    raise InadmissibleClass(f"{component} is not subsettable")


def evaluated_members(manifests: Iterable[Manifest]) -> dict[str, list[str]]:
    """The union of everything the evaluations actually exercised.

    This is what bounds the enumerations in a class. A member appearing in no
    evaluated manifest was never exercised, whatever the class says.
    """
    out: dict[str, set[str]] = {c: set() for c in MATERIAL_COMPONENTS}
    for m in manifests:
        for c in MATERIAL_COMPONENTS:
            comp = m.components.get(c)
            if comp is not None:
                out[c].add(comp.address)          # the whole-component address
            if c in SUBSETTABLE:
                try:
                    out[c].update(members_of(m, c))
                except InadmissibleClass:
                    pass
    return {c: sorted(v) for c, v in out.items()}


# --------------------------------------------------------------------------
# the two checks
# --------------------------------------------------------------------------


def covered_by(cls: ConfigurationClass, evaluated: dict[str, list[str]]) -> tuple[bool, list[str]]:
    """Does the evidence exercise every member this class enumerates?

    The load-bearing check. Membership alone would let anyone admit a
    configuration by adding its members to the class. This does not bound which
    *configurations* are admissible -- unseen combinations of exercised members
    are the feature -- only which *members* may be named.
    """
    problems: list[str] = []
    for c in sorted(cls.rules):
        r = cls.rules[c]
        known = set(evaluated.get(c, []))
        unknown = sorted(m for m in r.members if m not in known)
        if unknown:
            problems.append(
                f"{c}: {len(unknown)} member(s) named by the class but exercised by no "
                f"evaluated configuration ({', '.join(short(u, 10) for u in unknown[:3])}"
                f"{'…' if len(unknown) > 3 else ''})"
            )
    return (not problems), problems


def satisfies(cls: ConfigurationClass, runtime: Manifest) -> ClassDecision:
    """Is this runtime configuration a member of the class?

    Every component is reported, satisfied or not, so a blocked run names the
    rule it fell outside rather than only that it did.
    """
    cls.validate()
    if runtime.profile != cls.profile:
        raise InadmissibleClass(
            f"the class was declared under relation {cls.profile!r} and this manifest was "
            f"addressed under {runtime.profile!r}; the addresses are not comparable"
        )
    findings: list[dict[str, Any]] = []
    ok = True
    for c in MATERIAL_COMPONENTS:
        r = cls.rules.get(c)
        comp = runtime.components.get(c)
        if comp is None:
            findings.append({"component": c, "relation": r.kind if r else "-", "ok": False,
                             "detail": "component absent from the runtime manifest"})
            ok = False
            continue
        if r.kind == "pin":
            good = comp.address == r.members[0]
            detail = (f"{short(comp.address, 10)} is the pinned address" if good
                      else f"{short(comp.address, 10)} != pinned {short(r.members[0], 10)}")
        elif r.kind == "any_of":
            good = comp.address in r.members
            detail = (f"{short(comp.address, 10)} is one of {len(r.members)} approved" if good
                      else f"{short(comp.address, 10)} is not among {len(r.members)} approved")
        else:  # subset_of
            present = set(members_of(runtime, c))
            extra = sorted(present - set(r.members))
            good = not extra
            detail = (f"{len(present)} member(s), all approved" if good
                      else f"{len(extra)} outside the approved set: "
                           f"{', '.join(short(e, 10) for e in extra[:3])}"
                           f"{'…' if len(extra) > 3 else ''}")
        findings.append({"component": c, "relation": r.kind, "ok": good, "detail": detail})
        ok = ok and good
    return ClassDecision(ok=ok, class_address=cls.address(), findings=findings)


def widens_over(new: ConfigurationClass, old: ConfigurationClass) -> list[str]:
    """Which components the new class admits more of than the old one.

    Used the way authority narrowing is: a delegated class must not be wider than
    the class its delegator holds. Empty means the new class is no wider.
    """
    widened: list[str] = []
    for c in sorted(set(new.rules) | set(old.rules)):
        n, o = new.rules.get(c), old.rules.get(c)
        if o is None or n is None:
            widened.append(c)
            continue
        if not set(n.members).issubset(set(o.members)):
            widened.append(c)
    return widened


# --------------------------------------------------------------------------
# construction
# --------------------------------------------------------------------------


def from_declaration(decl: dict[str, Any]) -> ConfigurationClass:
    """Rebuild a class from its declaration, as a verifier must.

    A verifier holds the signed declaration, not the object that produced it. If
    the rules could only be applied by the code that wrote them, the class would
    be an informal policy interpreted dynamically rather than an artifact.
    """
    rules = {
        r["component"]: ComponentRule(r["component"], r["relation"], tuple(r["members"]))
        for r in decl.get("rules", [])
    }
    cls = ConfigurationClass(
        name=decl.get("name", ""),
        profile=decl.get("profile", ""),
        rules=rules,
        basis=tuple(decl.get("evidence_basis", ())),
    )
    cls.validate()
    return cls


def from_evaluated(
    name: str,
    evaluated: list[Manifest],
    vary: Iterable[str] = (),
    any_of: Iterable[str] = (),
) -> ConfigurationClass:
    """Build a class from evaluated configurations, pinning everything not named.

    ``vary`` names the components that may vary by subset; ``any_of`` the ones
    that may take any one of the evaluated whole-component addresses. Everything
    else is pinned, because a degree of freedom that was not asked for is not
    granted. Members come from the evaluated manifests, so a class built this way
    satisfies ``covered_by`` by construction; a class assembled any other way has
    to prove it.
    """
    if not evaluated:
        raise InadmissibleClass(
            "a configuration class needs at least one evaluated configuration; a class "
            "built from no evidence would admit whatever it was written to admit"
        )
    profile = evaluated[0].profile
    if any(m.profile != profile for m in evaluated):
        raise InadmissibleClass(
            "the evaluated configurations were addressed under different relations, so "
            "their addresses are not comparable and one class cannot span them"
        )
    vary, any_of = tuple(vary), tuple(any_of)
    overlap = sorted(set(vary) & set(any_of))
    if overlap:
        raise InadmissibleClass(f"components named both vary and any_of: {overlap}")
    bad = sorted(set(vary) - set(SUBSETTABLE))
    if bad:
        raise InadmissibleClass(
            f"cannot vary {bad} by subset: the manifest carries no member identifiers "
            f"for them. Subsettable: {list(SUBSETTABLE)}"
        )
    rules: dict[str, ComponentRule] = {}
    for c in MATERIAL_COMPONENTS:
        if c in vary:
            members = sorted({m for man in evaluated for m in members_of(man, c)})
            if not members:
                # Nothing to enumerate. Pin the whole component rather than emit
                # an empty rule: no degree of freedom is the safe reading.
                rules[c] = ComponentRule(c, "pin", (evaluated[0].components[c].address,))
                continue
            rules[c] = ComponentRule(c, "subset_of", tuple(members))
        elif c in any_of:
            rules[c] = ComponentRule(
                c, "any_of", tuple(sorted({m.components[c].address for m in evaluated}))
            )
        else:
            addrs = sorted({m.components[c].address for m in evaluated})
            rules[c] = (ComponentRule(c, "pin", (addrs[0],)) if len(addrs) == 1
                        else ComponentRule(c, "any_of", tuple(addrs)))
    cls = ConfigurationClass(
        name=name, profile=profile, rules=rules,
        basis=tuple(sorted({m.configuration_address for m in evaluated})),
    )
    cls.validate()
    return cls
