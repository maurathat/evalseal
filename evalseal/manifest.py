"""The agent configuration manifest and its address.

A configuration is the whole thing an evaluation result actually refers to:

    model, system prompt, procedure, tool definitions, retrieval corpus,
    permissions, eval set

Each component is addressed with the rule that fits its type, then the manifest
of component addresses is itself addressed. That two-level structure is what
makes a mismatch *diagnosable*: the configuration address tells you something
changed, the component addresses tell you which one, and ``diff.py`` tells you
which field inside it.

Model identity is explicitly an open scope boundary. EvalSeal binds whatever
stable identifier the provider gives you (``provider/model/version``, or a
digest the serving stack reports). It does not attempt to canonicalize weights,
adapters, quantizations or tokenizers. That is a genuine research problem and
pretending otherwise inside a configuration manifest would make the manifest
dishonest. ``model.identity_kind`` records which kind of identifier was bound,
so a reader can see how strong the model half of the claim is.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .address import addr_of, addr_of_text, short

__all__ = ["Component", "Manifest", "load_config", "build_manifest"]

# Components that, by declaration, invalidate an evaluation result when they
# change. Kept explicit so the claim is auditable rather than implied by code.
MATERIAL_COMPONENTS = (
    "model",
    "prompt",
    "procedure",
    "tools",
    "corpus",
    "permissions",
    "eval_set",
)


@dataclass
class Component:
    name: str
    address: str
    kind: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class Manifest:
    components: dict[str, Component]
    configuration_address: str
    profile: str

    def addresses(self) -> dict[str, str]:
        return {n: c.address for n, c in self.components.items()}

    def to_json(self) -> dict[str, Any]:
        return {
            "configuration_address": self.configuration_address,
            "profile": self.profile,
            "components": {
                n: {"address": c.address, "kind": c.kind, **({"detail": c.detail} if c.detail else {})}
                for n, c in self.components.items()
            },
        }

    def render(self) -> str:
        width = max(len(n) for n in self.components)
        lines = []
        for name in MATERIAL_COMPONENTS:
            c = self.components.get(name)
            if c is None:
                continue
            lines.append(f"  {name.ljust(width)}  {short(c.address)}  ({c.kind})")
        return "\n".join(lines)


# --------------------------------------------------------------------------


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[Any]:
    items = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            items.append(json.loads(line))
    return items


def load_config(config_dir: str | Path) -> dict[str, Any]:
    """Read a configuration directory into a plain dict.

    Expected layout (all optional except agent.json)::

        agent.json      model identifier, agent name, permissions
        prompt.txt      system prompt
        procedure.md    operating procedure
        tools.json      MCP tool definitions (list, or {"tools": [...]})
        corpus/         retrieval corpus, one file per document
        eval.jsonl      held-out evaluation items
    """
    d = Path(config_dir)
    agent = _read_json(d / "agent.json")

    tools_raw: list[Any] = []
    tools_document: dict[str, Any] = {}
    if (d / "tools.json").exists():
        t = _read_json(d / "tools.json")
        if isinstance(t, dict) and "tools" in t:
            tools_raw, tools_document = t["tools"], t
        else:
            tools_raw = t
    if not all(isinstance(x, dict) for x in tools_raw):
        raise ValueError("tools.json must contain a list of tool objects")

    corpus: list[dict[str, str]] = []
    corpus_dir = d / "corpus"
    if corpus_dir.is_dir():
        for p in sorted(corpus_dir.iterdir()):
            if p.is_file():
                corpus.append({"name": p.name, "text": p.read_text(encoding="utf-8")})

    return {
        "agent": agent,
        "prompt": (d / "prompt.txt").read_text(encoding="utf-8") if (d / "prompt.txt").exists() else "",
        "procedure": (d / "procedure.md").read_text(encoding="utf-8") if (d / "procedure.md").exists() else "",
        "tools": tools_raw,
        # The whole tools.json document, so keys beside "tools" (server-level
        # instructions, for instance) are addressed rather than discarded.
        "tools_document": tools_document,
        "corpus": corpus,
        "eval_set": _read_jsonl(d / "eval.jsonl") if (d / "eval.jsonl").exists() else [],
    }


def build_manifest(
    config: dict[str, Any],
    profile: str = "strict",
    resolved_dependencies: list[str] | None = None,
) -> Manifest:
    """Address every component, then address the manifest of addresses.

    ``resolved_dependencies`` scopes the corpus component to the documents the
    evaluation actually read. This is the difference between two defensible
    positions, and it is measurable rather than a matter of taste:

      * corpus scope FULL -- address every document present. Safe, but it
        false-blocks when an unread document is added, since the answer cannot
        have changed.
      * corpus scope RESOLVED -- address only the documents consulted. A change
        to one of those still invalidates; an addition elsewhere does not.

    An external reuse-ladder measurement over accession-pinned SEC filings
    separates these two classes explicitly (``C_irrelevant_dependency`` vs
    ``D_relevant_dependency``). On the reported frozen-corpus runs,
    resolved-dependency binding achieved precision 1.0, and recall 1.0 in three of
    the four reported runs (0.93 in the fourth); see
    ``docs/REUSE-LADDER.md`` for the limited transition coverage and the
    resulting scope of that evidence.

    Which scope applies is a declared policy, recorded in the receipt, not a
    default to be inferred.
    """
    agent = config["agent"]
    model = agent.get("model", {})
    if isinstance(model, str):
        model = {"id": model, "identity_kind": "provider-string"}

    comps: dict[str, Component] = {}

    # The WHOLE model object is bound, not a two-field summary of it. Binding
    # only id + identity_kind left adapter, quantization, sampling parameters and
    # any system_prompt_override unaddressed -- model-facing configuration
    # invisible to a system whose purpose is binding model-facing configuration.
    if not str(model.get("id", "")).strip():
        raise ValueError(
            "agent.model has no id; an empty model identifier must not be addressable, "
            "because every empty spelling would collide on one identity"
        )
    comps["model"] = Component(
        "model",
        addr_of(model, profile),
        kind=model.get("identity_kind", "provider-string"),
        detail={"id": model.get("id", ""), "fields": sorted(model)},
    )

    comps["prompt"] = Component("prompt", addr_of_text(config["prompt"], profile), kind="text")
    comps["procedure"] = Component("procedure", addr_of_text(config["procedure"], profile), kind="text")

    # Tools are order-insensitive as a *set* keyed by tool name: an MCP server
    # returning its tools in a different order has not changed the toolset.
    # Duplicate names are refused rather than silently de-duplicated, since a
    # verifier cannot know which of two same-named tools a client would resolve.
    tools_sorted = sorted(config["tools"], key=lambda t: t.get("name", ""))
    names = [t.get("name", "") for t in tools_sorted]
    if len(set(names)) != len(names):
        dupes = sorted({n for n in names if names.count(n) > 1})
        raise ValueError(f"duplicate tool name(s) {dupes}: the toolset has no unambiguous identity")
    # Everything else in tools.json is bound too. Server-level `instructions` sit
    # beside `tools` and are model-facing text; discarding them left them
    # unaddressed.
    tools_payload: dict[str, Any] = {"tools": tools_sorted}
    extra = {k: v for k, v in (config.get("tools_document") or {}).items() if k != "tools"}
    if extra:
        tools_payload["document"] = extra
    # Per-tool definition addresses, so membership in a configuration class can be
    # checked element by element. Keyed by name for reporting, but the *address*
    # is the member: an approved name whose definition changed is a different
    # member. Name-keyed membership would re-open precisely the drift measured in
    # realdata/ -- 51 descriptions rewritten under unchanged names.
    #
    # This lives in detail, which is not part of the addressed payload, so adding
    # it does not move any configuration address. tests/test_class.py pins that.
    tool_addrs = {t.get("name", ""): addr_of(t, profile) for t in tools_sorted}
    comps["tools"] = Component(
        "tools",
        addr_of(tools_payload, profile),
        kind=f"{len(tools_sorted)} tool(s)" + (f" + {len(extra)} doc field(s)" if extra else ""),
        detail={"names": names, "document_fields": sorted(extra), "tool_addrs": tool_addrs},
    )

    # Corpus: address each document, then address the sorted list of document
    # addresses. Reordering the directory listing is never a change. Whether
    # *adding* an unread document is a change depends on the declared scope.
    scoped = config["corpus"]
    if resolved_dependencies is not None:
        wanted = set(resolved_dependencies)
        scoped = [d for d in config["corpus"] if d["name"] in wanted]
    doc_addrs = sorted(
        ({"name": d["name"], "addr": addr_of_text(d["text"], profile)} for d in scoped),
        key=lambda x: (x["name"], x["addr"]),
    )
    scope = "resolved" if resolved_dependencies is not None else "full"
    if resolved_dependencies is not None:
        missing = sorted(wanted - {d["name"] for d in config["corpus"]})
        if missing:
            raise ValueError(
                f"resolved dependencies name documents not present in the corpus: {missing}; "
                "a claimed dependency that cannot be resolved must not be silently dropped"
            )
        if not doc_addrs and config["corpus"]:
            raise ValueError(
                "resolved dependency set is empty while the corpus is not: that would leave "
                "every document unbound. Declare --corpus-scope full instead of binding nothing"
            )
    comps["corpus"] = Component(
        "corpus",
        # The scope is inside the addressed payload, so a full-corpus address and
        # a resolved-dependency address can never be mistaken for each other.
        addr_of({"scope": scope, "docs": doc_addrs}, profile),
        kind=f"{len(doc_addrs)} doc(s), scope={scope}",
        detail={"scope": scope, "docs": doc_addrs,
                "present": sorted(d["name"] for d in config["corpus"])},
    )

    # `sorted()` of a dict yields its KEYS, and of a string its CHARACTERS, so
    # {"claim.read": true, "payment.transfer": false} addressed identically to
    # ["claim.read", "payment.transfer"] -- a configuration that DENIES an operation
    # and one that GRANTS it shared a configuration address, and the denied op was
    # admitted into configuration classes as an approved member. Refuse the shape
    # instead of guessing which reading was meant. Nothing else binds this field.
    ops = agent.get("allowed_operations", [])
    if not isinstance(ops, list) or not all(isinstance(o, str) for o in ops):
        raise ValueError(
            "agent.allowed_operations must be a list of strings; got "
            f"{type(ops).__name__}"
            + (" (a mapping of operation -> bool cannot be addressed: its values "
               "would be dropped, so a denied operation would address identically "
               "to a granted one)" if isinstance(ops, dict) else "")
        )
    if len(set(ops)) != len(ops):
        raise ValueError("agent.allowed_operations contains duplicates; refusing to "
                         "collapse them into one addressed set")
    comps["permissions"] = Component(
        "permissions",
        addr_of(sorted(ops), profile),
        kind=f"{len(ops)} op(s)",
        detail={"allowed_operations": sorted(ops)},
    )

    # Eval set: addressed as a *set* of item addresses, so shuffling the file
    # does not invalidate a release, while editing an item does.
    item_addrs = sorted(addr_of(item, profile) for item in config["eval_set"])
    comps["eval_set"] = Component(
        "eval_set",
        addr_of(item_addrs, profile),
        kind=f"{len(item_addrs)} item(s)",
        detail={"n_items": len(item_addrs)},
    )

    # The whole agent document is bound, minus the sub-objects that already have
    # their own components (binding them twice would be harmless but confusing).
    # Previously only agent.name was bound, leaving description and any custom
    # field unaddressed.
    agent_rest = {k: v for k, v in agent.items()
                  if k not in ("model", "allowed_operations")}
    manifest_body = {
        "agent": agent_rest,
        "components": {n: c.address for n, c in comps.items()},
    }
    return Manifest(
        components=comps,
        configuration_address=addr_of(manifest_body, profile),
        profile=profile,
    )
