"""Evidence propagation across agent delegation.

One agent's evidence is not the system's evidence. When a research agent
delegates to a filing agent and a policy agent, the question "did this run use
evaluated configurations?" has three answers, and the usual architecture loses
two of them: the parent's audit log records *that* it delegated, not *which
configuration* answered.

So the graph node is the unit. Each agent has its own configuration identity and
its own evidence envelope, and the run is admissible only if every node on the
path is. Evidence does not aggregate upward by assertion: a parent cannot vouch
for a child it did not evaluate.

The drift injected here is not invented. ``--replay-real`` advances one delegated
agent's toolset from one *published* version of a real MCP server to the next,
using the definitions captured in ``realdata/tools``. The change that blocks the
run is a change that a real maintainer actually shipped, under an unchanged tool
name. That is a materially stronger demonstration than a mutation written to be
caught, and it is the reason the harvested corpus is in the repository.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .address import short
from .diff import json_diff, render_change
from .manifest import build_manifest, load_config
from .receipt import Receipt, issue, verify_against

REALDATA = Path(__file__).resolve().parent.parent / "realdata" / "tools"

__all__ = ["Node", "AgentGraph", "build_graph", "render_graph"]


@dataclass
class Node:
    name: str
    role: str
    config: dict[str, Any]
    delegates_to: list[str] = field(default_factory=list)
    receipt: Receipt | None = None
    verdict: Any = None
    diff: dict[str, Any] = field(default_factory=dict)
    # Operations this node holds that its delegator does not. Authority must
    # narrow at each hop; anything here is a widening, and a widening makes the
    # run inadmissible regardless of how cleanly the configuration verifies.
    widened: list[str] = field(default_factory=list)

    @property
    def admissible(self) -> bool:
        return (self.verdict is not None and self.verdict.permitted
                and not self.widened)


@dataclass
class AgentGraph:
    nodes: dict[str, Node]
    root: str

    def path_admissible(self) -> bool:
        return all(n.admissible for n in self.nodes.values())

    def blocked_nodes(self) -> list[Node]:
        return [n for n in self.nodes.values() if not n.admissible]

    def to_json(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "run_admissible": self.path_admissible(),
            "nodes": {
                name: {
                    "role": n.role,
                    "delegates_to": n.delegates_to,
                    # The address VERIFICATION used, never a fresh build: rebuilding
                    # without the resolved-dependency scope printed a third, unverified
                    # address beside the verdict.
                    "configuration": (n.verdict.runtime_address if n.verdict
                                      else None),
                    "evaluated_configuration": (n.verdict.approved_address if n.verdict
                                                else None),
                    "evidence": n.receipt.address() if n.receipt else None,
                    "admissible": n.admissible,
                    "verdict": n.verdict.verdict if n.verdict else None,
                }
                for name, n in self.nodes.items()
            },
        }


# --------------------------------------------------------------------------
# real published toolsets
# --------------------------------------------------------------------------

def _load_published(pkg: str, version: str) -> list[dict[str, Any]] | None:
    p = REALDATA / f"{pkg.replace('/', '__')}@{version}.json"
    if not p.exists():
        return None
    rec = json.loads(p.read_text(encoding="utf-8"))
    return rec.get("tools")


def find_real_drift() -> dict[str, Any] | None:
    """Find a published version pair whose tool DESCRIPTION changed under a stable name.

    Two constraints, both load-bearing for the demonstration:

    * the tool NAME SETS must be identical across the pair, so the pair is a
      pure in-place redefinition of already-approved tools. A pair that also
      renames or adds a tool would put a rename in the diff while the narrative
      talked about a description, and a demo whose evidence and story disagree
      is worse than no demo;
    * prefer the largest instruction change, because the claim concerns the
      volume of model-facing text that moves under a stable name.
    """
    from .realdata import _load, description_rewrites

    by_pkg = _load()
    dr = description_rewrites(by_pkg)
    for r in dr.get("largest", []):
        before = _load_published(r["package"], r["from"])
        after = _load_published(r["package"], r["to"])
        if not before or not after:
            continue
        if {t.get("name") for t in before} != {t.get("name") for t in after}:
            continue      # a rename or addition would muddy the diff
        return {
            "package": r["package"],
            "from": r["from"],
            "to": r["to"],
            "tool": r["tool"],
            "chars_before": r["chars_before"],
            "chars_after": r["chars_after"],
            "delta": r["delta"],
            "tools_before": before,
            "tools_after": after,
            "n_tools": len(before),
            "all_changed": _all_description_changes(before, after),
        }
    return None


def _all_description_changes(before: list[dict[str, Any]],
                             after: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every tool in the pair whose description moved, with sizes."""
    a = {t.get("name"): (t.get("description") or "") for t in before}
    b = {t.get("name"): (t.get("description") or "") for t in after}
    out = []
    for name in sorted(set(a) & set(b)):
        if a[name] != b[name]:
            out.append({"tool": name, "before": len(a[name]), "after": len(b[name]),
                        "delta": len(b[name]) - len(a[name])})
    return sorted(out, key=lambda x: -abs(x["delta"]))


# --------------------------------------------------------------------------
# graph construction
# --------------------------------------------------------------------------

def _derive(base: dict[str, Any], name: str, role: str, ops: list[str],
            tools: list[dict[str, Any]] | None = None,
            prompt_suffix: str = "") -> dict[str, Any]:
    """A delegated agent: same house style, its own prompt, tools and permissions."""
    cfg = copy.deepcopy(base)
    cfg["agent"] = dict(cfg["agent"])
    cfg["agent"]["name"] = name
    cfg["agent"]["allowed_operations"] = sorted(ops)
    if tools is not None:
        cfg["tools"] = tools
    if prompt_suffix:
        cfg["prompt"] = cfg["prompt"].rstrip() + "\n\n" + prompt_suffix + "\n"
    return cfg


def check_authority_narrows(nodes: dict[str, "Node"], root: str) -> None:
    """Authority must narrow at each delegation hop.

    A child that holds an operation its delegator does not hold has been granted
    authority the delegation could not have conferred. Configuration identity
    says nothing about this: every node can verify perfectly and the run still be
    inadmissible. Checking it is cheap and NOT checking it means printing
    ADMISSIBLE over a permission set that widened, which is the inverse of what a
    delegation chain is supposed to guarantee.
    """
    parent_ops = set(nodes[root].config["agent"].get("allowed_operations", []))
    for name, node in nodes.items():
        if name == root:
            node.widened = []
            continue
        child_ops = set(node.config["agent"].get("allowed_operations", []))
        node.widened = sorted(child_ops - parent_ops)


def build_graph(
    config_dir: str | Path,
    key_path: Path,
    replay_real: bool = False,
    mutate_child: str | None = None,
    widen_child: bool = False,
) -> tuple[AgentGraph, dict[str, Any] | None]:
    """Three agents: a coordinator delegating to two specialists.

    Each is sealed independently against its own configuration. Then, optionally,
    one child's configuration is advanced -- either by a real published version
    bump (``replay_real``) or by a named synthetic mutation -- and the graph is
    re-verified.
    """
    base = load_config(config_dir)
    drift = find_real_drift() if replay_real else None
    if replay_real and drift is None:
        # Silently falling back to the clean graph printed RUN ADMISSIBLE and
        # exited 0 -- the opposite of the story the flag promises, with nothing
        # saying the data was missing.
        raise SystemExit(
            "--replay-real found no usable published version pair in realdata/tools/.\n"
            "Run: python3 realdata/harvest.py --versions 8   (executes third-party code; "
            "use a container)"
        )

    child_tools = drift["tools_before"] if drift else None

    review = _derive(
        base, "claims-review-coordinator", "coordinator",
        # A delegator can only confer authority it holds, so the coordinator's
        # set is the union of what it delegates plus its own operations.
        ["claim.read", "policy.read", "classification.write", "note.append", "delegate"],
        prompt_suffix=(
            "You coordinate two specialists. Delegate policy interpretation to the "
            "policy agent and precedent search to the research agent. You may not "
            "record a decision that a specialist did not support."),
    )
    policy = _derive(
        base, "policy-agent", "specialist: policy interpretation",
        ["policy.read", "note.append"],
        prompt_suffix="You interpret policy terms only. You never record a claim decision.",
    )
    research_ops = ["claim.read", "policy.read"]
    if widen_child:
        # The violation, on demand: an operation the coordinator never held.
        research_ops = research_ops + ["payment.execute"]
    research = _derive(
        base, "research-agent", "specialist: precedent research",
        research_ops,
        tools=child_tools,
        prompt_suffix="You search decided claims for comparable fact patterns.",
    )

    nodes = {
        "claims-review-coordinator": Node(
            "claims-review-coordinator", "coordinator", review,
            delegates_to=["policy-agent", "research-agent"]),
        "policy-agent": Node("policy-agent", "specialist: policy interpretation", policy),
        "research-agent": Node("research-agent", "specialist: precedent research", research),
    }

    # Seal each node against its own configuration, evaluated on its own terms.
    # Reusing the parent's evaluation result would have every child receipt
    # assert a score for a configuration that was never evaluated -- exactly the
    # inheritance this module exists to refuse, asserted by the demo itself.
    from .evaluate import run_evaluation

    approved: dict[str, Any] = {}
    node_deps: dict[str, list[str]] = {}
    for name, node in nodes.items():
        node_results = run_evaluation(node.config)
        deps = node_results["resolved_dependencies"] or None
        node_deps[name] = deps
        m = build_manifest(node.config, "strict", deps)
        approved[name] = m
        node.receipt = issue(
            manifest=m, eval_results=node_results, leakage=None,
            approver="claims-ops@example.com", key_path=key_path, agent_name=name,
            corpus_scope="resolved" if deps else "full",
        )

    # Now advance one child's configuration, as a deployment would.
    runtime_cfgs = {name: copy.deepcopy(n.config) for name, n in nodes.items()}
    if drift:
        runtime_cfgs["research-agent"]["tools"] = drift["tools_after"]
    elif mutate_child:
        from .cli import _mutate

        runtime_cfgs["research-agent"] = _mutate(runtime_cfgs["research-agent"], mutate_child)

    for name, node in nodes.items():
        # Same scope the evidence was issued under -- recomputing it from the
        # runtime config would let a drifted config pick a friendlier scope.
        rm = build_manifest(runtime_cfgs[name], "strict", node_deps[name])
        node.diff = manifest_diff_safe(approved[name], rm, node.config, runtime_cfgs[name])
        node.verdict = verify_against(node.receipt, rm, node.diff)

    check_authority_narrows(nodes, "claims-review-coordinator")
    return AgentGraph(nodes=nodes, root="claims-review-coordinator"), drift


def manifest_diff_safe(a, b, ca, cb):
    from .diff import manifest_diff

    return manifest_diff(a, b, ca, cb)


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

def _field_rank(path: str, drift: dict[str, Any] | None) -> tuple:
    """Show the biggest real description change first, then other descriptions."""
    lead = ""
    if drift and drift.get("all_changed"):
        lead = drift["all_changed"][0]["tool"]
    is_desc = "description" in path
    return (0 if (lead and lead in path and is_desc) else 1,
            0 if is_desc else 1,
            path)


def _abbrev(path: str, width: int) -> str:
    """Shorten a field path from the middle, keeping the root and the leaf.

    The leaf is the field that changed, so it is the one segment that must never
    be the part dropped.
    """
    if len(path) <= width:
        return path
    parts = path.split("/")
    if len(parts) < 4:
        return path[: width - 1] + "…"
    head, leaf = parts[0], "/".join(parts[-2:])
    out = f"{head}/…/{leaf}"
    while len(out) > width and len(parts) > 3:
        leaf = parts[-1]
        out = f"{head}/…/{leaf}"
        break
    return out if len(out) <= width else out[: width - 1] + "…"


def render_graph(g: AgentGraph, drift: dict[str, Any] | None,
                 compact: bool = False) -> str:
    """Render the delegation graph.

    ``compact`` drops the explanatory prose and keeps every address, field and
    measured number, so the whole result fits a 30-line terminal at projector
    font size. The prose is what a presenter says out loud; the numbers are what
    the room has to be able to read. Nothing is summarised away: if a claim is
    in the full output it is in the compact output too, shorter.
    """
    out: list[str] = []
    root = g.nodes[g.root]

    out.append("  HUMAN")
    out.append("    |")
    out.append(f"    v  {_line(root)}")
    for i, child_name in enumerate(root.delegates_to):
        child = g.nodes[child_name]
        last = i == len(root.delegates_to) - 1
        branch = "    `--delegates-->" if last else "    |--delegates-->"
        out.append(f"{branch} {_line(child)}")
    out.append("")

    root_ops = set(root.config["agent"].get("allowed_operations", []))
    any_widened = any(g.nodes[c].widened for c in root.delegates_to)
    if compact and not any_widened:
        # Every hop narrows, so the table has nothing in it to read; the counts
        # carry the same claim in one line. When a hop *widens*, the table is
        # the finding and stays in full even here.
        counts = ", ".join(
            str(len(g.nodes[c].config["agent"].get("allowed_operations", [])))
            for c in root.delegates_to
        )
        out.append(f"  authority: {len(root_ops)} ops at the root, then {counts} "
                   f"— each narrows vs the ROOT")
    else:
        out.append("  Authority vs the root (must narrow, never widen):")
        # One op per line rather than a Python list repr: at projector width the
        # repr ran to 113 columns and the WIDENS marker -- the only finding on the
        # screen -- wrapped onto a continuation line or off a truncating terminal.
        out.append(f"    {root.name:<28} {len(root_ops)} op(s)")
        if not compact:
            for op in sorted(root_ops):
                out.append(f"      {op}")
        for child_name in root.delegates_to:
            child = g.nodes[child_name]
            ops = sorted(child.config["agent"].get("allowed_operations", []))
            mark = "NARROWS" if not child.widened else f"WIDENS by {child.widened}"
            out.append(f"    {child.name:<28} {len(ops)} op(s)  {mark}")
            # In compact mode only the ops that are the finding are listed; the
            # full list is the non-compact view. Either way the marker is on its
            # own line and cannot wrap off a projected terminal.
            for op in (ops if not compact else child.widened):
                flag = "  <-- not held by the root" if op in child.widened else ""
                out.append(f"      {op}{flag}")
    out.append("")

    blocked = g.blocked_nodes()
    if not blocked:
        if compact:
            out.append("  RUN ADMISSIBLE — every node carries evidence bound to the")
            out.append("  configuration presented for it, and no node holds an operation the")
            out.append("  root did not. (Vs the ROOT, not each delegator: KNOWN-ISSUES #4.)")
            return "\n".join(out)
        out.append("  RUN ADMISSIBLE — every node on the delegation path carries evidence")
        out.append("  bound to the configuration presented for it, and no node holds an")
        out.append("  operation the root did not. (Measured against the root, not against")
        out.append("  each delegator -- at depth that is weaker. KNOWN-ISSUES.md #4.)")
        return "\n".join(out)

    if compact:
        names = ", ".join(n.name for n in blocked)
        out.append(f"  RUN BLOCKED — {names} presents a configuration no evidence covers")
    else:
        out.append("  RUN BLOCKED")
        out.append("")
    for n in blocked:
        if not compact:
            out.append(f"  {n.name}")
        if n.widened:
            out.append(f"    AUTHORITY WIDENED at this hop: {n.widened}")
            # Whether the configuration also drifted is a separate question, and
            # asserting "the configuration verifies" here printed a false line
            # whenever it had not: report what was actually computed.
            cfg_line = ("the configuration verifies" if n.verdict.permitted
                        else f"the configuration ALSO fails: {n.verdict.verdict}")
            if compact:
                out.append("    The delegator never held these operations, so the")
                out.append(f"    delegation could not confer them; {cfg_line};")
                out.append("    the run is inadmissible either way.")
                continue
            out.append("    The delegator does not hold these operations, so the delegation")
            out.append("    could not have conferred them.")
            out.append(f"    Separately, {cfg_line};")
            out.append("    the run is inadmissible either way. Identity and authority are")
            out.append("    different questions, and this one is not answered by an address.")
            if not n.verdict.permitted:
                out.append(f"    evaluated  {short(n.verdict.approved_address, 12)}")
                out.append(f"    presented  {short(n.verdict.runtime_address, 12)}")
            continue
        out.append(f"    evaluated  {short(n.verdict.approved_address, 12)}")
        out.append(f"    presented  {short(n.verdict.runtime_address, 12)}")
        for c in n.diff.get("components", []):
            if c["match"]:
                continue
            fields = sorted(c["fields"], key=lambda f: _field_rank(f["path"], drift))
            shown = fields[:1] if compact else fields[:2]
            for f in shown:
                out.append(f"    {f['path']}  [{f['change']}]")
                for line in render_change(f.get("before"), f.get("after")):
                    out.append(f"      {line}")
            rest = fields[len(shown):]
            if rest:
                # Both modes truncate the field list; only saying so keeps the
                # count honest, since a reader who counts the printed fields
                # would otherwise conclude that two things changed, not six.
                # Named, not just counted: a bare "+N more" hides which field
                # moved. Paths abbreviate from the middle, so the leaf survives.
                out.append(f"    {len(rest)} more field(s) changed, including:")
                for f in rest[:2]:
                    out.append(f"      {_abbrev(f['path'], 68) if compact else f['path']}")
        if not compact:
            out.append("")
    if compact:
        out.append("    A coordinator cannot vouch for a configuration it never evaluated.")
    else:
        out.append("  This execution contains a component that has not earned the evaluation")
        out.append("  evidence the deployment policy requires. The parent's evidence does not")
        out.append("  cover it: a coordinator cannot vouch for a configuration it never")
        out.append("  evaluated, so the run is inadmissible even though the coordinator itself")
        out.append("  verifies.")

    if drift:
        out.append("")
        pkg = drift["package"]
        changed = drift.get("all_changed") or []
        if compact:
            out.append("  REAL DRIFT — not authored for this demo")
            out.append(f"    {pkg}  {drift['from']} -> {drift['to']}  "
                       f"(consecutive published releases)")
            out.append(f"    descriptions rewritten {len(changed)} of {drift.get('n_tools')}; "
                       f"tool name set IDENTICAL")
            for c in changed:
                out.append(f"      {c['tool']:<24} {c['before']:>5} -> {c['after']:<5} chars "
                           f"({c['delta']:+d})")
            out.append("    That text tells the model when and how to call the tool, so a")
            out.append("    name-keyed allowlist sees nothing here.")
            return "\n".join(out)
        out.append("  NOTE — this drift was not authored for the demo.")
        out.append(f"    {pkg}")
        out.append(f"    advanced {drift['from']} -> {drift['to']} (consecutive published releases)")
        out.append(f"    tool name set: IDENTICAL ({drift.get('n_tools')} tools, none added, "
                   f"none removed, none renamed)")
        out.append(f"    descriptions rewritten: {len(changed)} of {drift.get('n_tools')}")
        for c in changed:
            out.append(f"      {c['tool']:<24} {c['before']:>5} -> {c['after']:<5} chars "
                       f"({c['delta']:+d})")
        out.append("    Every tool this server exposes had its description rewritten, and")
        out.append("    not one name changed. That text goes into the model's context to")
        out.append("    tell it when and how to call the tool, so the delegated agent's")
        out.append("    instructions changed while its name stayed the same. A name-keyed")
        out.append("    allowlist sees nothing here.")
    return "\n".join(out)


def _line(n: Node) -> str:
    """One node on the tree.

    The address printed is the one VERIFICATION compared -- the runtime address
    from the node's own verdict. Rebuilding the manifest here without the
    resolved-dependency scope that verification used printed a third address that
    matched neither the evaluated nor the presented one, beside a verdict that was
    about the other two.

    The verdict word is the point-receipt word. ADMISSIBLE is reserved for the
    weaker class verdict elsewhere in this project, so it is not used here: a node
    either verifies against its own evidence or it does not.
    """
    mark = "VERIFIES" if n.admissible else "BLOCKED"
    addr = (short(n.verdict.runtime_address, 10) if n.verdict
            else short(build_manifest(n.config, "strict").configuration_address, 10))
    return f"{n.name:<28} k={addr}  {mark}"
