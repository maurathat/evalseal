"""Materiality policy: which fields are compared, under which relation.

The bake-off produces a result that no single global relation can fix. Two cases:

    temperature: 1  ->  1.0        cosmetic. Every inference API treats these
                                   as the same value.
    "maximum": 2**53+2 -> 2**53+1  material. A schema bound genuinely moved.

Both are "a number changed lexical form". A relation that collapses numeric form
gets the first right and the second wrong; a relation that preserves it gets the
second right and the first wrong. There is no third global option, so the choice
is not a mathematical fact to be derived -- it is a *policy* about which fields
carry meaning, and it has to be declared, carried with the evidence, and open to
challenge.

That is the honest position, and it is stronger than pretending a universal
canonical form exists. Key order is obviously cosmetic. Is whitespace inside a
system prompt? Are reordered few-shot examples? Reasonable people will disagree,
and a verifier six months from now needs to see which answer this evidence was
issued under rather than guess.

So a policy is a list of rules, first match wins:

    Rule("key:temperature",              relation="eval")     numeric form ignored
    Rule("path:/inputSchema",            relation="strict")   numeric form matters
    Rule("key:_comment",                 relation="exclude")  never compared

A subtree under a non-default relation is replaced, for addressing purposes, by
that subtree's address *under its own relation*. So the configuration address
composes relations rather than picking one, and the policy itself is addressed and
signed alongside -- changing the policy changes the evidence, which is the point.
Excluded fields are removed before addressing, and the policy names them, so an
auditor can see what was deliberately not compared instead of discovering it.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .address import addr_of

__all__ = ["Rule", "MaterialityPolicy", "DEFAULT_POLICY", "apply_policy"]

EXCLUDE = "exclude"


@dataclass(frozen=True)
class Rule:
    """One materiality decision.

    ``match`` is either ``key:<name>`` (that field name at any depth) or
    ``path:<prefix>`` (a path prefix, in the same notation the diff prints).
    ``relation`` is a profile name, or ``exclude`` to drop the field from
    comparison entirely.
    """

    match: str
    relation: str
    why: str = ""

    def matches(self, path: str, key: str | None) -> bool:
        kind, _, target = self.match.partition(":")
        if kind == "key":
            return key == target
        if kind == "path":
            # Segment-aligned: `path:/input` must not govern `/inputSchema` or
            # `/inputFoo`. A bare prefix match let one rule silently capture
            # unrelated sibling keys, including exclusions.
            return path == target or path.startswith(target + "/") or path.startswith(target + "[")
        raise ValueError(f"unknown match kind {kind!r} in rule {self.match!r}")


@dataclass
class MaterialityPolicy:
    name: str = "evalseal/materiality/v1"
    default_relation: str = "strict"
    rules: list[Rule] = field(default_factory=list)

    def rule_for(self, path: str, key: str | None) -> Rule | None:
        for r in self.rules:
            if r.matches(path, key):
                return r
        return None

    def declare(self) -> dict[str, Any]:
        """The machine-readable declaration embedded in the receipt."""
        return {
            "name": self.name,
            "default_relation": self.default_relation,
            "rules": [asdict(r) for r in self.rules],
            "note": "Which fields are compared, and under which equivalence relation. "
                    "This is a declared policy, auditable and open to challenge, not a "
                    "universal canonical form. Changing it changes the evidence.",
        }

    def address(self) -> str:
        return addr_of(self.declare(), "strict")

    def excluded(self) -> list[str]:
        return [r.match for r in self.rules if r.relation == EXCLUDE]


# The demo policy, and a worked argument for each rule.
DEFAULT_POLICY = MaterialityPolicy(
    rules=[
        # Path rules come FIRST: a `key:` rule matches at any depth, so with the
        # old ordering `key:temperature` shadowed `path:/inputSchema` and a
        # temperature *bound inside a tool schema* was compared under the loose
        # relation -- a false accept on the exact case the path rule exists for.
        Rule("path:/inputSchema", "strict",
             "a tool schema is a contract with a typed consumer: integer and float "
             "bounds are different contracts, so numeric form is material"),
        Rule("key:temperature", "eval",
             "an inference sampling parameter: 1 and 1.0 are the same value to every "
             "serving stack, so numeric form is not material"),
        Rule("key:top_p", "eval",
             "same reasoning as temperature"),
        Rule("key:top_k", "eval",
             "same reasoning as temperature"),
        Rule("key:_comment", EXCLUDE,
             "an editorial note that is never placed in the model's context, so it "
             "cannot change behaviour"),
        Rule("key:description_human", EXCLUDE,
             "operator-facing catalogue prose, distinct from the tool description "
             "that reaches the model"),
    ]
)


def apply_policy(obj: Any, policy: MaterialityPolicy, path: str = "") -> Any:
    """Rewrite ``obj`` so that addressing it under the default relation honours ``policy``.

    A subtree governed by a non-default relation is replaced by a marker holding
    that subtree's address under its own relation. Excluded subtrees are dropped.
    The result is addressed once, under the default relation, and composes every
    declared relation exactly.
    """
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            child_path = f"{path}/{k}"
            rule = policy.rule_for(child_path, k)
            if rule is None:
                out[k] = apply_policy(v, policy, child_path)
            elif rule.relation == EXCLUDE:
                continue
            elif rule.relation == policy.default_relation:
                out[k] = apply_policy(v, policy, child_path)
            else:
                out[k] = {
                    "__relation": rule.relation,
                    "__addr": addr_of(v, rule.relation),
                }
        return out
    if isinstance(obj, list):
        # List elements previously skipped rule evaluation entirely, so a
        # `path:` rule could never match inside a list -- and `tools` is always
        # a list, which made the shipped path rule dead in every real config.
        out_list: list[Any] = []
        for i, x in enumerate(obj):
            child_path = f"{path}[{i}]"
            rule = policy.rule_for(child_path, None)
            if rule is None or rule.relation == policy.default_relation:
                out_list.append(apply_policy(x, policy, child_path))
            elif rule.relation == EXCLUDE:
                continue
            else:
                out_list.append({"__relation": rule.relation, "__addr": addr_of(x, rule.relation)})
        return out_list
    return obj


def policy_address_of(obj: Any, policy: MaterialityPolicy) -> str:
    """Address ``obj`` under ``policy``: relations composed, exclusions applied."""
    return addr_of(apply_policy(obj, policy), policy.default_relation)
