"""Evidence envelopes: the conditions under which evidence may be inherited.

A configuration class answers *which configurations* a result covers. On its own
that is not enough, and the gap is easy to demonstrate:

    An agent is evaluated with network access unavailable. Later the same agent
    runs with network access available. Model, prompt, tools, corpus and
    permissions are byte-identical, so the configuration address is identical and
    every class rule is satisfied -- and the conditions under which the evidence
    was earned no longer hold.

Configuration identity cannot see that, because the difference is not in the
configuration. So the top-level primitive is not the class. It is the envelope:

    what was evaluated          the configuration, or a class of them
    under what conditions       the evaluation environment, declared
    which differences matter    which of those conditions are material
    what it licenses            the conclusion the evidence supports

A run either satisfies the envelope or it does not. A dynamically composed swarm
does not have to be equivalent to the evaluated swarm; it has to stay inside the
envelope for the claim it is trying to inherit.

This is the same rule the project reaches from three directions. Resolved
dependencies: only what could affect the measurement should invalidate it.
Claim confinement: a declaration does not establish an execution. And now
conditions: a score means something only under the controls it was taken under.
The relevant condition is not whatever happens to be true, it is whatever was
capable of affecting the measurement.

THE HONEST LIMIT, and it is the project's usual one. Conditions here are
DECLARED, not attested. A runtime that presents ``network: unavailable`` is
making a claim, exactly as an operator presenting a prompt file is making a
claim. The envelope establishes that the presented conditions match the
evaluated ones; it does not establish that either description was true. Attested
conditions need a sandbox or an enclave that reports them, which is the same
EXECUTED-layer problem the receipt already withholds.

The example above is therefore hypothetical, and stays hypothetical: it is what a
network-isolated evaluation could declare. A harness that reached the network to
perform its evaluation may not declare that condition at all. That is a third
state, distinct from the limit just stated -- a declaration is not only either
consistent-but-unattested or unobserved, it can also be CONTRADICTED by evidence
the issuer already holds -- and the third is inadmissible. See
:func:`refuse_contradicted`.

Two more limits worth stating rather than discovering. A condition nobody
declared is not checked -- an envelope is only as good as the list of things its
author thought to control for. And satisfying an envelope says nothing about
whether the members of a class compose safely: two individually evaluated tools
may be dangerous together, and no rule here sees that.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .address import addr_of, short
from .classes import ClassDecision, ConfigurationClass, from_declaration, satisfies

__all__ = [
    "EvidenceEnvelope",
    "EnvelopeDecision",
    "InadmissibleEnvelope",
    "ContradictedCondition",
    "NETWORK_ABSENCE_CLAIMS",
    "refuse_contradicted",
    "envelope_from_declaration",
]


class InadmissibleEnvelope(Exception):
    """The envelope is not a well-formed claim, so nothing was checked."""


class ContradictedCondition(InadmissibleEnvelope):
    """A declared condition is falsified by evidence the issuer already holds.

    Three states have to be kept apart, and only the third is this error:

      1. consistent but unattested -- the usual, honest case: nothing in the
         harness can confirm or deny the declaration;
      2. unobserved -- the harness has no evidence about the condition at all;
      3. contradicted -- the harness's own execution path establishes that the
         declared value is false.

    The first two are the project's standing DECLARED-not-ATTESTED limit. The
    third is not a limit, it is a signed falsehood, and refusing it does not
    require any new attestation machinery: the issuer is only being stopped from
    declaring something it has already disproved.
    """


@dataclass
class EvidenceEnvelope:
    name: str
    configuration_class: ConfigurationClass
    # The evaluation conditions, as declared by whoever ran the evaluation.
    conditions: dict[str, str] = field(default_factory=dict)
    # Which of those conditions must still hold for the evidence to transfer.
    # Named explicitly rather than defaulting to all, because "the wall clock
    # said 14:02" is a condition and is not material; and rather than defaulting
    # to none, because that is the failure this module exists to prevent.
    material: tuple[str, ...] = ()
    licensed_conclusion: str = ""

    def declare(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "configuration_class": self.configuration_class.declare(),
            "conditions": dict(sorted(self.conditions.items())),
            "material_conditions": sorted(self.material),
            "licensed_conclusion": self.licensed_conclusion,
        }

    def address(self) -> str:
        return addr_of(self.declare(), self.configuration_class.profile)

    def validate(self) -> None:
        self.configuration_class.validate()
        if not self.licensed_conclusion.strip():
            raise InadmissibleEnvelope(
                "the envelope states no licensed conclusion; an envelope that does not say "
                "what the evidence supports cannot be checked against what someone claims "
                "from it"
            )
        undeclared = sorted(set(self.material) - set(self.conditions))
        if undeclared:
            raise InadmissibleEnvelope(
                f"material condition(s) {undeclared} have no declared value; a condition "
                "that must hold but was never recorded cannot be compared with anything"
            )
        if self.conditions and not self.material:
            raise InadmissibleEnvelope(
                "conditions are declared but none is marked material, so none of them would "
                "be checked. Name the ones that must hold, or declare no conditions at all "
                "rather than recording controls the envelope then ignores"
            )

    def render(self) -> str:
        out = [f"    class        {short(self.configuration_class.address(), 12)}"]
        for k in sorted(self.conditions):
            mark = "MATERIAL" if k in self.material else "recorded"
            out.append(f"    {k:<12} {self.conditions[k]:<28} {mark}")
        return "\n".join(out)


@dataclass
class EnvelopeDecision:
    ok: bool
    envelope_address: str
    class_decision: ClassDecision | None
    condition_findings: list[dict[str, Any]]

    def outside(self) -> list[str]:
        out = [f["condition"] for f in self.condition_findings if not f["ok"]]
        if self.class_decision is not None:
            out = self.class_decision.outside() + out
        return out

    def render(self) -> str:
        lines = []
        if self.class_decision is not None:
            lines.append(self.class_decision.render())
        for f in self.condition_findings:
            mark = "ok  " if f["ok"] else "OUT "
            lines.append(f"    {mark} {f['condition']:<12} {f['detail']}")
        return "\n".join(lines)


# Declared condition values that assert the evaluation had no network
# reachability. Keyed by condition name because the assertion lives in the pair:
# ``network: unavailable`` claims absence, ``network: available`` does not, and
# ``network_isolation: enforced`` claims absence with the opposite polarity.
# This table is deliberately a table and not a regex or a callable: a harness
# that wants a condition refused has to name it, exactly as everywhere else in
# this project, and a condition nobody listed is unobserved rather than allowed.
NETWORK_ABSENCE_CLAIMS: dict[str, frozenset[str]] = {
    "network": frozenset({"unavailable", "none", "off", "offline", "disabled",
                          "isolated", "no", "false"}),
    "network_access": frozenset({"unavailable", "none", "off", "offline",
                                 "disabled", "isolated", "no", "false"}),
    "internet": frozenset({"unavailable", "none", "off", "offline", "disabled",
                           "isolated", "no", "false"}),
    "egress": frozenset({"none", "off", "blocked", "denied", "disabled", "no"}),
    "network_egress": frozenset({"none", "off", "blocked", "denied", "disabled",
                                 "no"}),
    "network_isolation": frozenset({"enforced", "yes", "true", "on", "complete"}),
    "sandbox_network": frozenset({"none", "off", "blocked", "disabled", "no"}),
}


def refuse_contradicted(
    env: EvidenceEnvelope,
    observations: dict[str, Any],
) -> None:
    """Refuse issuance when the harness's own evidence falsifies a declaration.

    ``observations`` are facts the *issuing harness* established while running
    the evaluation -- not conditions a runtime reported about itself, which are
    self-description and are checked at gate time instead. Two forms are read:

    ``network_reachable: True``
        the harness reached the network to perform the evaluation. Any declared
        condition in :data:`NETWORK_ABSENCE_CLAIMS` asserting absence is then a
        falsehood, whether or not it was marked material: an unchecked condition
        is still signed, and a reader is entitled to treat it as true.

    any other key
        compared against the declared condition of the same name. A differing
        value is a contradiction; a key the envelope does not declare is ignored,
        because the harness observing something the envelope is silent about is
        not a conflict.

    Raises :class:`ContradictedCondition`; returns ``None`` when there is nothing
    to refuse. This does not create attestation and does not make any surviving
    condition attested. It only prevents EvalSeal from signing a statement its
    own execution path has already disproved.
    """
    if observations.get("network_reachable"):
        for key, absent in NETWORK_ABSENCE_CLAIMS.items():
            if key not in env.conditions:
                continue
            value = str(env.conditions[key]).strip().lower()
            if value in absent:
                raise ContradictedCondition(
                    f"envelope declares {key}={env.conditions[key]!r}, which asserts the "
                    "evaluation had no network reachability, and the harness reached the "
                    "network to perform this evaluation. That is not an unattested "
                    "condition, it is a false one; name the control that actually held "
                    "(which tools may egress, for instance) rather than the environment "
                    "that did not"
                )
    for key, observed in observations.items():
        if key == "network_reachable" or key not in env.conditions:
            continue
        if str(observed) != str(env.conditions[key]):
            raise ContradictedCondition(
                f"envelope declares {key}={env.conditions[key]!r} and the harness observed "
                f"{observed!r} while performing the evaluation"
            )


def envelope_from_declaration(decl: dict[str, Any]) -> EvidenceEnvelope:
    """Rebuild an envelope from its declaration, as a verifier must."""
    env = EvidenceEnvelope(
        name=decl.get("name", ""),
        configuration_class=from_declaration(decl.get("configuration_class", {})),
        conditions=dict(decl.get("conditions", {})),
        material=tuple(decl.get("material_conditions", ())),
        licensed_conclusion=decl.get("licensed_conclusion", ""),
    )
    env.validate()
    return env


def check(
    env: EvidenceEnvelope,
    runtime_manifest: Any,
    runtime_conditions: dict[str, str] | None = None,
) -> EnvelopeDecision:
    """Is this run inside the envelope?

    Both halves must hold: the configuration is a member of the class, and every
    material condition still has the value it had when the evidence was earned.
    A missing runtime condition fails rather than passes -- an unreported control
    is not a satisfied one, and defaulting it to "fine" is how an envelope
    silently becomes a configuration check again.
    """
    env.validate()
    cd = satisfies(env.configuration_class, runtime_manifest)
    observed = runtime_conditions or {}
    findings: list[dict[str, Any]] = []
    ok = cd.ok
    for k in sorted(env.material):
        want = env.conditions[k]
        got = observed.get(k)
        if got is None:
            findings.append({"condition": k, "ok": False,
                             "detail": f"not reported at runtime; declared {want!r}"})
            ok = False
            continue
        good = got == want
        findings.append({
            "condition": k, "ok": good,
            "detail": (f"{got!r} as evaluated" if good
                       else f"{got!r} at runtime; evidence DECLARED as issued "
                            f"under {want!r}"),
        })
        ok = ok and good
    return EnvelopeDecision(ok=ok, envelope_address=env.address(),
                            class_decision=cd, condition_findings=findings)
