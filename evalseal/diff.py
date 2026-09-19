"""Locating drift, not just detecting it.

A verifier that says MISMATCH is a worse product than one that says
``tools/search/description``. Both halves matter for the demo: the address
comparison is the proof, the diff is the explanation.

The diff runs on the *canonical* forms, so it never reports a difference the
identity relation has already declared insignificant. If a diff path shows up
here, the address changed too, and vice versa. ``tests/test_drift.py`` pins
that agreement, because a verifier whose explanation disagrees with its own
verdict is not trustworthy.
"""

from __future__ import annotations

import json
from typing import Any

from .canonical import canonicalize
from .manifest import MATERIAL_COMPONENTS, Manifest

__all__ = ["json_diff", "manifest_diff", "render_diff"]


def _canon_roundtrip(obj: Any, profile: str) -> Any:
    """Re-parse the canonical bytes, so the diff sees only what the relation keeps."""
    return json.loads(canonicalize(obj, profile).decode("utf-8"))


def json_diff(a: Any, b: Any, profile: str = "strict", path: str = "") -> list[dict[str, Any]]:
    """Field-level differences between two JSON values, under ``profile``."""
    return _diff(_canon_roundtrip(a, profile), _canon_roundtrip(b, profile), path, profile)


def _fmt(v: Any, limit: int = 60) -> str:
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
    s = s.replace("\n", "\\n")
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _val(v: Any) -> Any:
    """Value as stored in a diff entry: strings raw, everything else compact JSON.

    Truncation happens at render time. Storing a truncated string here would
    hide the tail of a long tool description, which is exactly where an
    appended injection sentence lives.
    """
    return v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)


def _script(ch: str) -> str:
    """Coarse Unicode script of a character, from its name.

    Enough to tell a Latin 'a' from a Cyrillic 'а', which is the case that
    matters: a homoglyph substitution in a tool description is invisible to a
    reviewer and must be visible in a diff.
    """
    import unicodedata

    try:
        return unicodedata.name(ch).split()[0]
    except ValueError:
        return "UNKNOWN"


def _codepoint_note(a: str, b: str) -> str | None:
    """If two strings differ only in a few characters, name them by codepoint.

    Returns None when the strings differ substantially, in which case a windowed
    text diff is the better rendering.
    """
    import unicodedata

    if len(a) != len(b):
        return None
    diffs = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
    if not diffs or len(diffs) > 3:
        return None
    parts = []
    for i in diffs:
        x, y = a[i], b[i]

        def desc(ch: str) -> str:
            try:
                return f"{ch!r} U+{ord(ch):04X} {unicodedata.name(ch)}"
            except ValueError:
                return f"{ch!r} U+{ord(ch):04X}"

        note = f"char {i}: {desc(x)} -> {desc(y)}"
        if _script(x) != _script(y):
            note += "  [different script — invisible to a human reviewer]"
        parts.append(note)
    return "; ".join(parts)


def _window(a: str, b: str, width: int = 54) -> tuple[str, str]:
    """Show both strings around their first divergence, not from the start."""
    n = min(len(a), len(b))
    i = 0
    while i < n and a[i] == b[i]:
        i += 1
    start = max(0, i - width // 3)
    lead = "…" if start > 0 else ""

    def cut(s: str) -> str:
        seg = s[start : start + width]
        tail = "…" if start + width < len(s) else ""
        return f"{lead}{seg}{tail}".replace("\n", "\\n")

    return cut(a), cut(b)


def render_change(before: Any, after: Any) -> list[str]:
    """Lines describing one changed value, chosen to make the change visible."""
    if isinstance(before, str) and isinstance(after, str):
        note = _codepoint_note(before, after)
        if note is not None:
            return [f"differs by {note}"]
        x, y = _window(before, after)
        return [f"- {x}", f"+ {y}"]
    out = []
    if before is not None:
        out.append(f"- {_fmt(before)}")
    if after is not None:
        out.append(f"+ {_fmt(after)}")
    return out


def _scalars_differ(a: Any, b: Any, profile: str) -> bool:
    """Compare scalars the way the *relation* compares them, not the way Python does.

    Python says ``1 == 1.0`` and ``True == 1``; the strict relation emits ``1``
    vs ``1.0`` and ``true`` vs ``1``. Comparing with ``!=`` therefore produced a
    MISMATCH verdict with an empty explanation -- the address moved and the diff
    found nothing to show. A verifier whose explanation contradicts its own
    verdict is worse than one that only says MISMATCH, so the comparison is done
    on canonical bytes.
    """
    try:
        return canonicalize(a, profile) != canonicalize(b, profile)
    except Exception:
        return type(a) is not type(b) or a != b


def _diff(a: Any, b: Any, path: str, profile: str = "strict") -> list[dict[str, Any]]:
    if type(a) is not type(b) and not (isinstance(a, (int, float)) and isinstance(b, (int, float))):
        return [{"path": path or "/", "change": "type", "before": _val(a), "after": _val(b)}]

    if isinstance(a, dict):
        out: list[dict[str, Any]] = []
        for k in sorted(set(a) | set(b)):
            p = f"{path}/{k}"
            if k not in b:
                out.append({"path": p, "change": "removed", "before": _val(a[k]), "after": None})
            elif k not in a:
                out.append({"path": p, "change": "added", "before": None, "after": _val(b[k])})
            else:
                out.extend(_diff(a[k], b[k], p, profile))
        return out

    if isinstance(a, list):
        out = []
        for i in range(max(len(a), len(b))):
            p = f"{path}[{i}]"
            if i >= len(b):
                out.append({"path": p, "change": "removed", "before": _val(a[i]), "after": None})
            elif i >= len(a):
                out.append({"path": p, "change": "added", "before": None, "after": _val(b[i])})
            else:
                out.extend(_diff(a[i], b[i], p, profile))
        return out

    if _scalars_differ(a, b, profile):
        # Spell out a difference that is invisible in the rendered value, e.g.
        # 25 vs 25.0, which print identically once formatted.
        before, after = _val(a), _val(b)
        if before == after:
            before = f"{before} ({type(a).__name__})"
            after = f"{after} ({type(b).__name__})"
        return [{"path": path or "/", "change": "changed", "before": before, "after": after}]
    return []


def manifest_diff(
    approved: Manifest,
    runtime: Manifest,
    approved_config: dict[str, Any] | None = None,
    runtime_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compare two manifests component by component.

    When the underlying configs are supplied, drill into the components that
    differ so the report can name the exact field.
    """
    result: dict[str, Any] = {
        "match": approved.configuration_address == runtime.configuration_address,
        "approved_address": approved.configuration_address,
        "runtime_address": runtime.configuration_address,
        "components": [],
    }

    for name in MATERIAL_COMPONENTS:
        ca, cb = approved.components.get(name), runtime.components.get(name)
        if ca is None and cb is None:
            continue
        same = ca is not None and cb is not None and ca.address == cb.address
        entry: dict[str, Any] = {
            "component": name,
            "match": same,
            "approved": ca.address if ca else None,
            "runtime": cb.address if cb else None,
            "fields": [],
        }
        if not same and approved_config is not None and runtime_config is not None:
            entry["fields"] = _component_fields(name, approved_config, runtime_config, approved.profile)
        result["components"].append(entry)

    return result


def _component_fields(
    name: str, a_cfg: dict[str, Any], b_cfg: dict[str, Any], profile: str
) -> list[dict[str, Any]]:
    if name == "tools":
        a = {t.get("name", ""): t for t in a_cfg["tools"]}
        b = {t.get("name", ""): t for t in b_cfg["tools"]}
        if len(a) != len(a_cfg["tools"]) or len(b) != len(b_cfg["tools"]):
            return [{"path": "tools", "change": "ambiguous",
                     "before": f"{len(a_cfg['tools'])} tools, {len(a)} distinct names",
                     "after": f"{len(b_cfg['tools'])} tools, {len(b)} distinct names"}]
        out: list[dict[str, Any]] = []
        for k in sorted(set(a) | set(b)):
            if k not in b:
                out.append({"path": f"tools/{k}", "change": "removed", "before": "<tool>", "after": None})
            elif k not in a:
                out.append({"path": f"tools/{k}", "change": "added", "before": None, "after": "<tool>"})
            else:
                for d in json_diff(a[k], b[k], profile, f"tools/{k}"):
                    out.append(d)
        return out
    if name in ("prompt", "procedure"):
        return _text_diff(a_cfg[name], b_cfg[name], name)
    if name == "permissions":
        # A permission list is a set. Diffing it positionally reports index
        # churn ("policy.read -> payment.execute") and hides the only thing
        # that matters, which is that payment.execute was granted.
        a = set(a_cfg["agent"].get("allowed_operations", []))
        b = set(b_cfg["agent"].get("allowed_operations", []))
        out = []
        for op in sorted(b - a):
            out.append({"path": "permissions", "change": "granted", "before": None, "after": op})
        for op in sorted(a - b):
            out.append({"path": "permissions", "change": "revoked", "before": op, "after": None})
        return out
    if name == "model":
        return json_diff(a_cfg["agent"].get("model"), b_cfg["agent"].get("model"), profile, "model")
    if name == "corpus":
        a = {d["name"]: d["text"] for d in a_cfg["corpus"]}
        b = {d["name"]: d["text"] for d in b_cfg["corpus"]}
        out = []
        for k in sorted(set(a) | set(b)):
            if k not in b:
                out.append({"path": f"corpus/{k}", "change": "removed", "before": "<doc>", "after": None})
            elif k not in a:
                out.append({"path": f"corpus/{k}", "change": "added", "before": None, "after": "<doc>"})
            elif a[k] != b[k]:
                out.extend(_text_diff(a[k], b[k], f"corpus/{k}"))
        return out
    if name == "eval_set":
        na, nb = len(a_cfg["eval_set"]), len(b_cfg["eval_set"])
        if na != nb:
            return [{"path": "eval_set", "change": "changed",
                     "before": f"{na} items", "after": f"{nb} items"}]
        # Same count: say WHICH item moved. "20 items -> 20 items" explains nothing.
        out: list[dict[str, Any]] = []
        for i, (x, y) in enumerate(zip(a_cfg["eval_set"], b_cfg["eval_set"])):
            for d in json_diff(x, y, profile, f"eval_set[{i}]"):
                out.append(d)
            if len(out) >= 4:
                break
        return out or [{"path": "eval_set", "change": "reordered",
                        "before": f"{na} items", "after": f"{nb} items"}]
    return []


def _text_diff(a: str, b: str, label: str) -> list[dict[str, Any]]:
    """First differing line, which is all a 90-second demo has room for."""
    la, lb = a.splitlines(), b.splitlines()
    for i in range(max(len(la), len(lb))):
        x = la[i] if i < len(la) else None
        y = lb[i] if i < len(lb) else None
        if x != y:
            return [
                {
                    "path": f"{label}:line {i + 1}",
                    "change": "changed" if x is not None and y is not None else ("removed" if y is None else "added"),
                    "before": _val(x) if x is not None else None,
                    "after": _val(y) if y is not None else None,
                }
            ]
    return []


def render_diff(d: dict[str, Any], indent: str = "  ") -> str:
    lines: list[str] = []
    for c in d["components"]:
        mark = "MATCH" if c["match"] else "MISMATCH"
        lines.append(f"{indent}{c['component'].ljust(12)} {mark}")
        for f in c["fields"][:6]:
            lines.append(f"{indent}{indent}{f['path']}  [{f['change']}]")
            for line in render_change(f.get("before"), f.get("after")):
                lines.append(f"{indent}{indent}{indent}{line}")
        extra = len(c["fields"]) - 6
        if extra > 0:
            lines.append(f"{indent}{indent}… and {extra} more field(s)")
    return "\n".join(lines)
