#!/usr/bin/env python3
"""Harvest real tool definitions from published MCP servers.

This is the part of the project that is not a conformance test. Every mutation
in ``evalseal/mutate.py`` was written by us, so the conformance table can only
show that the relation behaves as declared -- it cannot show that anyone in the
world ever performs those transformations. The obvious objection to the whole
approach is "why not just pin the bytes?", and the only honest answer is a
measurement on artifacts nobody here authored.

So: install N published versions of real MCP servers from npm, start each one,
speak MCP over stdio, and record the exact ``tools/list`` result. Then compare
adjacent versions under byte identity and under structural identity. The
question being measured is narrow and falsifiable:

    How often does a published MCP server's tool definition change
    byte-wise while remaining structurally identical?

If the answer is zero, byte pinning raises no false alarms in practice, the
distinctive claim for configuration addressing is weak on this evidence, and the
honest move is to say so and lead with the leakage result instead. That outcome
is written down here in advance so it cannot be quietly discarded later.

Running this executes third-party code. Do it in a container.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLS_DIR = HERE / "tools"
REGISTRY = "https://registry.npmjs.org/"

# Per-package launch requirements. Most servers validate credentials only when a
# tool is actually called, so tools/list usually succeeds with placeholders.
# Anything that refuses to start is recorded as a failure rather than dropped,
# because silently dropping the servers that would not cooperate is how a
# measurement turns into a selection effect.
PACKAGES: dict[str, dict] = {
    "@modelcontextprotocol/server-filesystem": {"args": ["{tmpdir}"]},
    "@modelcontextprotocol/server-memory": {"env": {"MEMORY_FILE_PATH": "{tmpdir}/memory.json"}},
    "@modelcontextprotocol/server-everything": {},
    "@modelcontextprotocol/server-sequential-thinking": {},
    "@playwright/mcp": {},
    "@upstash/context7-mcp": {},
    "@notionhq/notion-mcp-server": {"env": {"NOTION_TOKEN": "placeholder", "OPENAPI_MCP_HEADERS": "{}"}},
    "@modelcontextprotocol/server-slack": {"env": {"SLACK_BOT_TOKEN": "xoxb-placeholder", "SLACK_TEAM_ID": "T000"}},
    "@modelcontextprotocol/server-brave-search": {"env": {"BRAVE_API_KEY": "placeholder"}},
    "@modelcontextprotocol/server-google-maps": {"env": {"GOOGLE_MAPS_API_KEY": "placeholder"}},
}


def fetch_versions(pkg: str) -> list[str]:
    url = REGISTRY + pkg.replace("/", "%2f")
    with urllib.request.urlopen(url, timeout=30) as r:
        d = json.load(r)
    # Stable releases only: prereleases are not what an enterprise pins.
    vs = [v for v in d.get("versions", {}) if not any(c in v for c in "-+")]
    order = {v: i for i, v in enumerate(d.get("versions", {}))}
    return sorted(vs, key=lambda v: order.get(v, 0))


def pick_spread(versions: list[str], n: int) -> list[str]:
    """Evenly spaced across publication history, always including the newest."""
    if len(versions) <= n:
        return versions
    step = (len(versions) - 1) / (n - 1)
    idx = sorted({round(i * step) for i in range(n)})
    return [versions[i] for i in idx]


def npm_install(pkg: str, version: str, prefix: Path) -> bool:
    prefix.mkdir(parents=True, exist_ok=True)
    cmd = ["npm", "install", f"{pkg}@{version}", "--prefix", str(prefix),
           "--no-audit", "--no-fund", "--loglevel", "error", "--omit", "dev"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if p.returncode != 0:
        print(f"    npm install failed: {p.stderr.strip()[:200]}", file=sys.stderr)
        return False
    return True


def find_entry(pkg: str, prefix: Path) -> Path | None:
    mod = prefix / "node_modules" / pkg
    pj = mod / "package.json"
    if not pj.exists():
        return None
    meta = json.loads(pj.read_text(encoding="utf-8"))
    b = meta.get("bin")
    rel = None
    if isinstance(b, str):
        rel = b
    elif isinstance(b, dict) and b:
        rel = next(iter(b.values()))
    if rel is None:
        rel = meta.get("main") or "index.js"
    entry = (mod / rel).resolve()
    return entry if entry.exists() else None


def mcp_tools_list(entry: Path, args: list[str], env: dict[str, str], timeout: float = 45.0):
    """Speak MCP over stdio and return the tools/list result.

    Deliberately minimal: initialize, initialized, tools/list. No SDK, so the
    captured bytes are the server's own, not something a client library
    re-serialized on the way in.
    """
    full_env = dict(os.environ)
    full_env.update(env)
    full_env["NODE_NO_WARNINGS"] = "1"

    proc = subprocess.Popen(
        ["node", str(entry), *args],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=full_env, bufsize=1,
    )

    def send(obj: dict) -> None:
        assert proc.stdin
        proc.stdin.write(json.dumps(obj) + "\n")
        proc.stdin.flush()

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                         "clientInfo": {"name": "evalseal-harvest", "version": "0.1.0"}}})

        deadline = time.time() + timeout
        init_ok = False
        while time.time() < deadline:
            line = proc.stdout.readline() if proc.stdout else ""
            if not line:
                if proc.poll() is not None:
                    return None, f"server exited rc={proc.returncode}", None
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue          # servers sometimes log to stdout; skip noise
            if msg.get("id") == 1:
                if "error" in msg:
                    return None, f"initialize error: {msg['error']}", None
                init_ok = True
                break
        if not init_ok:
            return None, "initialize timed out", None

        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})

        deadline = time.time() + timeout
        while time.time() < deadline:
            line = proc.stdout.readline() if proc.stdout else ""
            if not line:
                if proc.poll() is not None:
                    return None, f"server exited rc={proc.returncode}", None
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") == 2:
                if "error" in msg:
                    return None, f"tools/list error: {msg['error']}", None
                # `line` is the server's own serialization. Re-dumping the
                # parsed object would silently normalise its whitespace and
                # escape form -- two of the very transformations under
                # measurement -- so the raw line is kept verbatim.
                return msg.get("result", {}).get("tools", []), None, line.rstrip("\n")
        return None, "tools/list timed out", None
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


def harvest(pkg: str, n_versions: int, workdir: Path) -> list[dict]:
    spec = PACKAGES[pkg]
    try:
        versions = pick_spread(fetch_versions(pkg), n_versions)
    except Exception as e:
        print(f"  cannot list versions: {e}", file=sys.stderr)
        return []

    print(f"  {len(versions)} version(s): {', '.join(versions)}")
    records = []
    for v in versions:
        outpath = TOOLS_DIR / f"{pkg.replace('/', '__')}@{v}.json"
        if outpath.exists():
            cached = json.loads(outpath.read_text(encoding="utf-8"))
            if cached.get("schema") == 2:
                print(f"    {v}: cached")
                records.append(cached)
                continue
            print(f"    {v}: cache predates raw-byte capture, re-harvesting")

        prefix = workdir / f"{pkg.replace('/', '__')}@{v}"
        tmpdir = workdir / "sandbox"
        tmpdir.mkdir(parents=True, exist_ok=True)

        rec = {"schema": 2, "package": pkg, "version": v, "tools": None,
               "error": None, "raw": None}
        if not npm_install(pkg, v, prefix):
            rec["error"] = "npm install failed"
        else:
            entry = find_entry(pkg, prefix)
            if entry is None:
                rec["error"] = "no entry point"
            else:
                # Plain substitution, not str.format: some placeholder env
                # values are themselves JSON (e.g. "{}") and would be parsed as
                # format fields.
                def sub(v: str) -> str:
                    return v.replace("{tmpdir}", str(tmpdir))

                args = [sub(a) for a in spec.get("args", [])]
                env = {k: sub(val) for k, val in spec.get("env", {}).items()}
                tools, err, raw = mcp_tools_list(entry, args, env)
                rec["tools"], rec["error"], rec["raw"] = tools, err, raw

        n = len(rec["tools"]) if rec["tools"] is not None else 0
        print(f"    {v}: " + (f"{n} tool(s)" if rec["error"] is None else f"FAILED — {rec['error']}"))
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        outpath.write_text(json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")
        records.append(rec)
        shutil.rmtree(prefix, ignore_errors=True)

    return records


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--packages", default=None, help="comma-separated subset")
    ap.add_argument("--versions", type=int, default=8)
    args = ap.parse_args()

    names = args.packages.split(",") if args.packages else list(PACKAGES)
    with tempfile.TemporaryDirectory(prefix="evalseal-harvest-") as td:
        workdir = Path(td)
        for pkg in names:
            if pkg not in PACKAGES:
                print(f"skipping unknown package {pkg}", file=sys.stderr)
                continue
            print(f"\n{pkg}")
            harvest(pkg, args.versions, workdir)
    print(f"\ncaptured files in {TOOLS_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
