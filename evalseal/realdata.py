"""Measurement on published MCP servers: how noisy is byte pinning in the wild?

The conformance table (``conformance.py``) shows the identity relation behaves
as declared against transformations we wrote. This module measures artifacts
nobody here authored, and answers a question the conformance table cannot:

    Across consecutive published versions of real MCP servers, how often does
    a tool definition change byte-wise while staying structurally identical?

Each such pair is a false alarm that a byte-pinning deployment gate would have
raised: the approved configuration would have been rejected although no tool
name, description, schema or parameter changed.

Three outcomes were written down before the data was collected:

  * a meaningful count of byte-only changes -> byte pinning is measurably noisy
    on real artifacts, and configuration addressing earns its place;
  * zero byte-only changes -> the distinctive claim is weak on this evidence.
    Say so, and lead with the leakage result, where the gain comes from
    contamination instead;
  * mostly material changes -> expected and uninteresting either way, since
    both methods catch those. Reported for completeness.

The sample is a convenience sample of servers installable and startable without
credentials, which is a real limitation and is printed with the result rather
than buried. Servers that refused to start are counted, not dropped.

OUTCOME (10 packages, 79 versions, 63 consecutive pairs, 2026-09-19)
--------------------------------------------------------------------
The second outcome fired. **Zero** byte-only changes, with the positive control
passing -- so the comparator works and the null is real. Byte pinning is not
measurably noisy at the published-version boundary, and that argument for
canonical addressing is therefore dead on this evidence. It is kept in the
report as a negative result rather than deleted.

What the data did show is sharper than what was being looked for: **51 tool
descriptions were rewritten while the tool name stayed the same**. A tool
description is text placed in the model's context instructing it when and how to
call the tool, so each of those is an already-approved tool whose instructions
changed underneath it. One -- context7's ``resolve-library-id`` -- grew from 523
to 2,006 characters across three releases. Approval keyed only on tool or
server *names* cannot detect these changes at all. Version-based controls do
detect them -- the version string changed, by construction, since these are
consecutive releases -- but only where versions are pinned to an immutable
release and re-approval is actually enforced on every bump. The gap this
measures is therefore name-keyed approval, and version pinning without
re-approval; it is not a claim that version pinning is blind.

That moves the argument off "canonical beats byte", which the data does not
support, and onto "binding the whole configuration beats approving names", which
it does. Canonicalization keeps that binding from false-alarming on transport
re-serialization, which is justified by the conformance suite rather than by any
claim about prevalence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .address import addr_of, raw_byte_addr
from .diff import json_diff

TOOLS_DIR = Path(__file__).resolve().parent.parent / "realdata" / "tools"

__all__ = ["PairResult", "analyse", "main"]


@dataclass
class PairResult:
    package: str
    v_from: str
    v_to: str
    byte_identical: bool
    struct_identical: bool
    n_tools_from: int
    n_tools_to: int
    changed_fields: list[str]          # truncated for display
    same_tool_names: bool = True
    n_changed_fields: int = 0
    # Classification must never read `changed_fields`: it is cut to 8 paths for
    # printing, and 26 of 38 material pairs here have more than 8. Classifying off
    # the truncation misfiled 12 pairs, 8 of them name-set changes reported as
    # schema changes, which then disagreed with the name-set count printed above it.
    kind: str = "other"

    @property
    def classification(self) -> str:
        if self.byte_identical and self.struct_identical:
            return "identical"
        if not self.byte_identical and self.struct_identical:
            return "byte-only"      # the interesting case: a false alarm
        return "material"


def _load() -> dict[str, list[dict[str, Any]]]:
    if not TOOLS_DIR.is_dir():
        return {}
    by_pkg: dict[str, list[dict[str, Any]]] = {}
    for p in sorted(TOOLS_DIR.glob("*.json")):
        rec = json.loads(p.read_text(encoding="utf-8"))
        by_pkg.setdefault(rec["package"], []).append(rec)
    return by_pkg


def _version_key(v: str) -> tuple:
    parts = []
    for chunk in v.split("."):
        parts.append(int(chunk) if chunk.isdigit() else 0)
    return tuple(parts)


def _normalise_toolset(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Tools as a set keyed by name: server-side ordering is not a change."""
    return sorted(tools, key=lambda t: t.get("name", ""))


def _tools_bytes(rec: dict[str, Any]) -> bytes:
    """The bytes a byte-pinning system would hash.

    Prefers the server's own serialization when it was captured. Falls back to
    a re-dump, and the fallback is reported, because a re-dump normalises
    whitespace and escape form and therefore *understates* byte drift.
    """
    if rec.get("raw"):
        try:
            payload = json.loads(rec["raw"])
            tools = payload.get("result", {}).get("tools", [])
            # Slice the tools array out of the raw line to keep the server's
            # own byte-level formatting of exactly the part being compared.
            marker = json.dumps(tools[0], ensure_ascii=False)[:1] if tools else None
            del marker
            start = rec["raw"].find('"tools"')
            if start != -1:
                return rec["raw"][start:].encode("utf-8")
        except Exception:
            pass
        return rec["raw"].encode("utf-8")
    return json.dumps(rec.get("tools") or [], ensure_ascii=False).encode("utf-8")


def positive_control() -> dict[str, Any]:
    """Prove the comparator can detect a byte-only change before trusting a zero.

    A null result from a detector nobody tested is indistinguishable from a
    broken detector. So: take a real captured toolset, apply a transformation
    that changes only serialization, and require the comparator to classify it
    byte-only. If this control fails, the headline number means nothing.
    """
    recs = [r for rs in _load().values() for r in rs if r.get("tools")]
    if not recs:
        return {"ran": False}

    rec = max(recs, key=lambda r: len(r["tools"]))
    tools = _normalise_toolset(rec["tools"])

    # Serialization-only: reversed key order, \u-escaped, indented.
    import copy

    def reorder(o: Any) -> Any:
        if isinstance(o, dict):
            return {k: reorder(o[k]) for k in reversed(list(o))}
        if isinstance(o, list):
            return [reorder(x) for x in o]
        return o

    reordered = reorder(copy.deepcopy(tools))
    bytes_a = json.dumps(tools, ensure_ascii=False).encode("utf-8")
    bytes_b = json.dumps(reordered, ensure_ascii=True, indent=2).encode("utf-8")

    byte_same = raw_byte_addr(bytes_a) == raw_byte_addr(bytes_b)
    struct_same = addr_of(tools, "strict") == addr_of(_normalise_toolset(reordered), "strict")

    detected = (not byte_same) and struct_same
    return {
        "ran": True,
        "subject": f"{rec['package']}@{rec['version']} ({len(tools)} tools)",
        "byte_identical": byte_same,
        "structurally_identical": struct_same,
        "byte_only_detected": detected,
        "verdict": "PASS — comparator detects byte-only change" if detected
                   else "FAIL — comparator cannot detect byte-only change; the headline zero is meaningless",
    }


def description_rewrites(by_pkg: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Tool descriptions rewritten while the tool name stayed the same.

    This is the measurement that survived. A tool description is not
    documentation -- it is text injected into the model's context that tells it
    when and how to call the tool. Rewriting one changes the agent's
    instructions.

    A name-keyed allowlist cannot see any of this. A control keyed to an
    immutable pinned version *can*, because the version changed -- these are
    consecutive releases -- but only if re-approval is enforced on every bump
    rather than the pin being widened or the review skipped. State it that way:
    claiming version controls are blind here is an overclaim the data does not
    support.

    Counted per tool per consecutive version pair, over names present in both
    versions, so additions and removals are excluded: every count here is an
    already-approved tool whose instructions changed underneath it.
    """
    rewrites: list[dict[str, Any]] = []
    total_delta = 0

    for pkg, recs in by_pkg.items():
        ok = sorted(
            (r for r in recs if r.get("tools") is not None and not r.get("error")),
            key=lambda r: _version_key(r["version"]),
        )
        for a, b in zip(ok, ok[1:]):
            ta = {t.get("name", ""): t for t in a["tools"]}
            tb = {t.get("name", ""): t for t in b["tools"]}
            for name in sorted(set(ta) & set(tb)):
                da = ta[name].get("description") or ""
                db = tb[name].get("description") or ""
                if da == db:
                    continue
                total_delta += len(db) - len(da)
                rewrites.append(
                    {
                        "package": pkg,
                        "from": a["version"],
                        "to": b["version"],
                        "tool": name,
                        "chars_before": len(da),
                        "chars_after": len(db),
                        "delta": len(db) - len(da),
                        "before": da[:200],
                        "after": db[:200],
                    }
                )

    rewrites.sort(key=lambda r: -abs(r["delta"]))
    return {
        "n_rewrites": len(rewrites),
        "net_chars_added": total_delta,
        "largest": rewrites[:10],
        "claim": "Tool descriptions are instructions to the model. Each of these is an "
                 "already-approved tool whose instructions changed without its name changing. "
                 "Name-keyed approval cannot detect these; version-keyed approval detects them "
                 "only where versions are pinned to an immutable release and re-approval is "
                 "enforced on every bump.",
    }


def _material_kind(fields: list[str]) -> str:
    """What sort of material change this was, for the rug-pull risk breakdown."""
    if not fields:
        return "unclassified"
    if any(f.endswith("]") and f.count("/") <= 1 for f in fields):
        pass
    has_desc = any("description" in f for f in fields)
    has_schema = any("Schema" in f or "schema" in f or "required" in f or "properties" in f
                     for f in fields)
    has_name = any(f.endswith("/name") for f in fields)
    if has_name:
        return "tool set changed (names added/removed)"
    if has_desc and not has_schema:
        return "description only (same names, same schemas)"
    if has_schema and not has_desc:
        return "schema only"
    if has_desc and has_schema:
        return "description and schema"
    return "other"


def analyse() -> dict[str, Any]:
    by_pkg = _load()
    pairs: list[PairResult] = []
    failures: list[dict[str, str]] = []
    raw_available = 0
    total_records = 0
    packages_used: set[str] = set()

    for pkg, recs in by_pkg.items():
        total_records += len(recs)
        for r in recs:
            if r.get("error"):
                failures.append({"package": pkg, "version": r["version"], "error": r["error"]})
            if r.get("raw"):
                raw_available += 1

        ok = sorted(
            (r for r in recs if r.get("tools") is not None and not r.get("error")),
            key=lambda r: _version_key(r["version"]),
        )
        if len(ok) >= 2:
            packages_used.add(pkg)
        for a, b in zip(ok, ok[1:]):
            ta, tb = _normalise_toolset(a["tools"]), _normalise_toolset(b["tools"])
            byte_same = raw_byte_addr(_tools_bytes(a)) == raw_byte_addr(_tools_bytes(b))
            struct_same = addr_of(ta, "strict") == addr_of(tb, "strict")
            all_fields = [] if struct_same else [
                d["path"] for d in json_diff(ta, tb, "strict", "tools")
            ]
            fields = all_fields[:8]
            names_a = {t.get("name", "") for t in ta}
            names_b = {t.get("name", "") for t in tb}
            same_names = names_a == names_b
            pairs.append(
                PairResult(
                    package=pkg, v_from=a["version"], v_to=b["version"],
                    byte_identical=byte_same, struct_identical=struct_same,
                    n_tools_from=len(ta), n_tools_to=len(tb), changed_fields=fields,
                    same_tool_names=same_names, n_changed_fields=len(all_fields),
                    kind=_material_kind(all_fields),
                )
            )

    counts = {"identical": 0, "byte-only": 0, "material": 0}
    for p in pairs:
        counts[p.classification] += 1

    material = [p for p in pairs if p.classification == "material"]
    silent_redef = [p for p in material if p.same_tool_names]
    breakdown: dict[str, int] = {}
    for p in material:
        breakdown[p.kind] = breakdown.get(p.kind, 0) + 1

    return {
        "n_packages_sampled": len(by_pkg),
        "n_packages_with_pairs": len(packages_used),
        "n_versions_captured": total_records,
        "n_version_pairs": len(pairs),
        "n_startup_failures": len(failures),
        "raw_bytes_available": f"{raw_available}/{total_records}",
        "counts": counts,
        "byte_only_rate": round(counts["byte-only"] / len(pairs), 4) if pairs else None,
        "positive_control": positive_control(),
        "description_rewrites": description_rewrites(by_pkg),
        "material_breakdown": breakdown,
        "silent_redefinition": {
            "n": len(silent_redef),
            "of_material": len(material),
            "note": "consecutive published versions whose tool NAMES are unchanged but whose "
                    "definitions changed: an already-approved tool was silently redefined",
            "examples": [
                {"package": p.package, "from": p.v_from, "to": p.v_to,
                 "n_tools": p.n_tools_from, "fields": p.changed_fields[:4],
                 "n_changed_fields": p.n_changed_fields}
                for p in silent_redef[:8]
            ],
        },
        "pairs": [
            {
                "package": p.package, "from": p.v_from, "to": p.v_to,
                "classification": p.classification,
                "n_tools": [p.n_tools_from, p.n_tools_to],
                "changed_fields": p.changed_fields,
            }
            for p in pairs
        ],
        "failures": failures,
        "limitations": [
            "Convenience sample: only servers installable and startable without credentials.",
            "Consecutive pairs are of sampled versions, not every published release, so "
            "intermediate changes are invisible.",
            "tools/list only; prompts, resources and server instructions are not compared.",
            "A server whose tool list depends on credentials or environment may report a "
            "different set here than in a configured deployment.",
        ],
    }


def render(a: dict[str, Any]) -> str:
    lines = []
    pc = a.get("positive_control", {})
    if pc.get("ran"):
        lines.append(f"  positive control        {pc['verdict']}")
        lines.append(f"                          subject: {pc['subject']}")
        lines.append("")
    lines.append(f"  packages sampled        {a['n_packages_sampled']} "
                 f"({a['n_packages_with_pairs']} yielded comparable pairs)")
    lines.append(f"  versions captured       {a['n_versions_captured']}")
    lines.append(f"  startup failures        {a['n_startup_failures']} (counted, not dropped)")
    lines.append(f"  server-own bytes        {a['raw_bytes_available']} records")
    lines.append(f"  consecutive pairs       {a['n_version_pairs']}")
    lines.append("")
    c = a["counts"]
    lines.append(f"  {'classification':<24} {'pairs':>6}   meaning")
    lines.append("  " + "-" * 62)
    lines.append(f"  {'identical':<24} {c['identical']:>6}   no change either way")
    lines.append(f"  {'byte-only':<24} {c['byte-only']:>6}   byte pin would FALSE ALARM here")
    lines.append(f"  {'material':<24} {c['material']:>6}   both methods invalidate (correctly)")
    lines.append("")

    if a["n_version_pairs"]:
        rate = a["byte_only_rate"] * 100
        if c["byte-only"] > 0:
            lines.append(f"  {c['byte-only']} of {a['n_version_pairs']} consecutive version pairs "
                         f"({rate:.0f}%) changed byte-wise")
            lines.append("  while remaining structurally identical: a byte-pinned deployment gate")
            lines.append("  would have blocked those releases with no tool definition change.")
        else:
            lines.append("  ZERO byte-only changes in this sample. On this evidence byte pinning")
            lines.append("  raises no false alarms across published versions, so configuration")
            lines.append("  addressing cannot be justified by drift noise here. The honest lead")
            lines.append("  is the leakage result, where the structural gain is measured, not")
            lines.append("  the tool-pinning story. Do not present this table as support.")

    dr = a.get("description_rewrites", {})
    if dr.get("n_rewrites"):
        lines.append("")
        lines.append("  THE HEADLINE — instruction drift under a stable name")
        lines.append("  " + "-" * 62)
        lines.append(f"  {dr['n_rewrites']} tool descriptions were rewritten while the tool NAME stayed")
        lines.append(f"  the same, a net {dr['net_chars_added']:+,} characters of model-facing instruction.")
        lines.append("  A tool description is not documentation: it is text placed in the")
        lines.append("  model's context telling it when and how to call the tool.")
        lines.append("  Name-keyed approval cannot see any of this. Version-keyed approval")
        lines.append("  can -- the version changed by construction -- but only where versions")
        lines.append("  are pinned to an immutable release AND re-approval is enforced on")
        lines.append("  every bump. That is the gap being measured.")
        lines.append("")
        for r in dr["largest"][:5]:
            pkg = r["package"].replace("@modelcontextprotocol/", "@mcp/")
            lines.append(f"    {pkg} {r['from']} -> {r['to']}  {r['tool']}")
            lines.append(f"      {r['chars_before']} -> {r['chars_after']} chars ({r['delta']:+d})")

    sr = a.get("silent_redefinition", {})
    if sr.get("of_material"):
        lines.append("")
        lines.append(f"  Of {sr['of_material']} material changes, {sr['n']} kept the tool NAMES "
                     f"identical while")
        lines.append("  changing the definitions — an already-approved tool redefined in place,")
        lines.append("  which is the shape a rug pull takes and the case a name-based allowlist")
        lines.append("  cannot see at all:")
        for e in sr.get("examples", [])[:6]:
            pkg = e["package"].replace("@modelcontextprotocol/", "@mcp/")
            n = e.get("n_changed_fields", len(e["fields"]))
            shown = ", ".join(e["fields"][:2])
            more = f" (+{n - 2} more of {n})" if n > 2 else ""
            lines.append(f"    {pkg} {e['from']} -> {e['to']}  ({e['n_tools']} tools)  "
                         f"{shown}{more}")
        bd = a.get("material_breakdown", {})
        if bd:
            lines.append("")
            lines.append("  Material changes by kind:")
            for k, v in sorted(bd.items(), key=lambda kv: -kv[1]):
                lines.append(f"    {v:>3}  {k}")
    lines.append("")
    lines.append("  Limitations:")
    for lim in a["limitations"]:
        lines.append(f"    - {lim}")
    return "\n".join(lines)


def main(args: Any) -> int:
    from .report import banner

    out_dir = Path(__file__).resolve().parent.parent / "out"
    a = analyse()
    print(banner("REAL-DATA MEASUREMENT", "published MCP servers, not our mutations"))
    print()
    if not a["n_version_pairs"]:
        print("  No harvested data found. Run:")
        print("      python3 realdata/harvest.py --versions 8")
        print("  (installs and starts third-party servers; use a container)")
        return 1
    print(render(a))
    out_dir.mkdir(exist_ok=True)
    (out_dir / "realdata.json").write_text(json.dumps(a, indent=2, ensure_ascii=False), encoding="utf-8")
    print("\n  written to out/realdata.json")
    return 0
