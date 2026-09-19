"""EvalSeal around a real agent. An adapter, not a framework.

This file lives OUTSIDE the evalseal package and imports only its public API. It
changes no canonicalization, signing, class or verification behaviour, and the
151-test core does not know it exists.

What it shows, against an actual LLM workload:

    runtime                                  point identity    envelope
    the exact evaluated agent                VERIFIED          ADMISSIBLE
    an approved subset (one tool omitted)    BLOCKED           ADMISSIBLE
    same tool name, changed definition       BLOCKED           OUTSIDE
    identical agent, material condition moved VERIFIED         OUTSIDE

Three things about this experiment are deliberate.

**The model's answer is incidental.** Every verdict above is deterministic and
computed from configuration and declared conditions. The agent is run anyway, and
its answer printed, because the point is not that EvalSeal stops inference -- it
does not, and could not. The claim is narrower and checkable: *you may still run
this agent, but you can no longer claim the earlier evaluation covers it.*

**The demo never depends on the model misbehaving.** Row 3 rewrites a tool
description in the way published MCP servers really do. Whether the model changes
its answer is not the experiment; if it does, that is a vivid illustration, and if
it does not, the result is unchanged. Making the finding contingent on a
stochastic response would make it a worse result, not a better one.

**The LLM is the workload, never the verifier.** Nothing here asks a model
whether evidence still applies. A second probabilistic system adjudicating
evidence about the first is exactly the structure this project argues against.

Live mode calls the Anthropic API when ANTHROPIC_API_KEY is set. Without a key it
replays recorded answers and says so on every line, because a recorded answer
presented as a live one would be the same species of overclaim the project is
about.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from evalseal.address import addr_of                            # noqa: E402
from evalseal.classes import from_evaluated                      # noqa: E402
from evalseal.envelope import (                                  # noqa: E402
    EvidenceEnvelope,
    refuse_contradicted,
)
from evalseal.manifest import build_manifest, load_config        # noqa: E402
from evalseal.receipt import issue, verify_against               # noqa: E402

AGENT = HERE / "agent"
OUT = HERE / "out"

# Recorded answers, used when no key is present. Keyed by task id. These were the
# model's answers on the run recorded in out/transcript.json; replaying them
# proves nothing about a live model and is labelled as replay everywhere it shows.
RECORDED = {
    "t1": "COVERED - sudden and accidental discharge of water from a plumbing system is a covered peril.",
    "t2": "EXCLUDED - vandalism is excluded where the dwelling was vacant more than sixty days.",
    "t3": "EXCLUDED - earth movement including landslide is excluded.",
    "t4": "EXCLUDED - flood is excluded under this form.",
    "t5": "COVERED - windstorm and hail is a covered peril.",
    "t6": "NOT ADDRESSED - the form does not mention identity theft.",
}


# --------------------------------------------------------------------------
# the workload
# --------------------------------------------------------------------------


class ApiError(Exception):
    """An API rejection, carrying the provider's own explanation.

    urllib raises HTTPError whose str() is only "HTTP Error 400: Bad Request".
    The body says which field is invalid, and discarding it turns a precise
    diagnosis into a guess. The key and the auth headers are never included.
    """


def _post(body: dict, api_key: str) -> dict:
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json", "x-api-key": api_key,
                 "anthropic-version": "2023-06-01"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", "replace")[:600]
        except Exception:
            detail = "(no response body)"
        raise ApiError(f"HTTP {e.code}: {detail}") from None


def execute_tool(cfg: dict, block: dict) -> str:
    """Run one tool the agent asked for. Fails closed, never invents a result.

    Only tools the configuration declares may run, and only with inputs their
    declared schema requires. A model asking for something undeclared, or with a
    malformed input, aborts the task: silently satisfying it would let the
    harness answer on the model's behalf and call that an evaluation result.
    """
    name = block.get("name")
    args = block.get("input")
    if not isinstance(args, dict):
        raise ApiError(f"tool {name!r} called with non-object input; refusing")
    spec = next((t for t in cfg["tools"] if t.get("name") == name), None)
    if spec is None:
        raise ApiError(
            f"the model requested tool {name!r}, which this configuration does not "
            "declare. Running it would mean executing a capability outside the "
            "addressed configuration"
        )
    missing = [r for r in spec.get("inputSchema", {}).get("required", [])
               if r not in args]
    if missing:
        raise ApiError(f"tool {name!r} called without required input(s) {missing}")

    if name == "read_policy_form":
        return "\n\n".join(d["text"] for d in cfg["corpus"]) or "(no policy form)"
    if name == "classify_coverage":
        return (f"Recorded determination {args['decision']!r} for claim "
                f"{args['claim_number']!r}.")
    if name == "append_note":
        return f"Note appended to claim {args['claim_number']!r}."
    raise ApiError(
        f"tool {name!r} is declared but has no local implementation; refusing to "
        "fabricate a tool result"
    )


def call_model(cfg: dict, question: str, api_key: str,
               max_rounds: int = 4) -> tuple[str, dict]:
    """Run the agent to completion: model, tool calls, results, final answer.

    Sending tools and reading the first response is NOT running an agent. When
    the model answers with a tool_use block, the run is not finished -- it is
    waiting on the harness. Stopping there and recording "no text content" would
    classify a legitimate agent action as an evaluation failure, which is what a
    first live run of this adapter did.

    The system prompt, tool definitions and corpus come from the same
    configuration EvalSeal addresses, so the thing that runs and the thing that
    is addressed are one object.
    """
    model = cfg["agent"]["model"]
    # The API model string is DERIVED from the declared model id, so the model
    # that is addressed is the model that is called. Letting them drift would
    # reproduce, inside the demo, the exact defect the demo is about.
    api_model = str(model.get("id", "")).split("/", 1)[-1]
    tools = [{"name": t["name"], "description": t.get("description", ""),
              "input_schema": t.get("inputSchema", {"type": "object"})}
             for t in cfg["tools"]]
    form = "\n\n".join(d["text"] for d in cfg["corpus"])
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": f"Policy form:\n\n{form}\n\nQuestion: {question}"}
    ]

    calls: list[dict[str, str]] = []
    tool_calls: list[dict[str, Any]] = []
    block_types: list[list[str]] = []

    for _ in range(max_rounds):
        body = {
            "model": api_model,
            "max_tokens": int(model.get("max_tokens", 300)),
            "system": cfg["prompt"],
            "tools": tools,
            "messages": messages,
        }
        # A sampling parameter is sent if and only if the configuration declares
        # it. Defaulting one here would send a value nothing declares, which is
        # the declared-vs-effective divergence this project exists to catch --
        # pointing the wrong way. claude-sonnet-5 deprecates `temperature`.
        for k in ("temperature", "top_p", "top_k"):
            if k in model:
                body[k] = model[k]

        payload = _post(body, api_key)
        calls.append({"request_address": addr_of(body, "strict"),
                      "response_address": addr_of(payload, "strict")})
        content = payload.get("content", []) or []
        block_types.append([b.get("type") for b in content])

        # Branch on the PRESENCE of a tool_use block, never on stop_reason alone.
        # A truncated response (stop_reason "max_tokens") can carry a tool_use
        # block; treating that as a finished answer would return the preamble
        # text as an evaluation result while the tool never ran. That is the
        # same defect as reading only text blocks, one layer along.
        tool_blocks = [b for b in content
                       if isinstance(b, dict) and b.get("type") == "tool_use"]
        if payload.get("stop_reason") == "tool_use" and not tool_blocks:
            raise ApiError("stop_reason was tool_use but no tool_use block was present")
        if tool_blocks:
            if payload.get("stop_reason") != "tool_use":
                # The model was cut off mid tool call. Continuing would send a
                # tool_result for a request the model never finished making.
                raise ApiError(
                    f"response carried {len(tool_blocks)} tool_use block(s) with "
                    f"stop_reason {payload.get('stop_reason')!r}; the run was cut "
                    "off mid tool call and must not be scored as an answer"
                )
            messages.append({"role": "assistant", "content": content})
            results = []
            for b in tool_blocks:
                if not b.get("id"):
                    raise ApiError("tool_use block carries no id; cannot return a result")
                tool_calls.append({"name": b.get("name"), "input": b.get("input")})
                results.append({"type": "tool_result", "tool_use_id": b["id"],
                                "content": execute_tool(cfg, b)})
            messages.append({"role": "user", "content": results})
            continue

        text = " ".join(b.get("text", "").strip() for b in content
                        if b.get("type") == "text" and b.get("text", "").strip())
        if not text:
            raise ApiError(
                f"the run ended with no text answer; content block types were "
                f"{block_types[-1]} and stop_reason was {payload.get('stop_reason')!r}"
            )
        # Trace binding, named for exactly what it is. The ordered sequence of
        # every provider call is bound in `calls`; the two headline addresses are
        # the FIRST request and the FINAL response, which is stated rather than
        # implied, because a multi-call run whose trace shows one pair would
        # misrepresent its own scope.
        # Calling any of this EXECUTED would be the overclaim the whole project
        # refuses. The stronger claim needs either provider participation, or a
        # controlled runner whose attestation authority sits outside the
        # workload's reach. Controlling the model alone is not sufficient: a key
        # the workload can use is a key the workload can use to describe itself.
        return text, {
            "rounds": len(calls),
            "calls": calls,
            "request_address": calls[0]["request_address"],
            "response_address": calls[-1]["response_address"],
            "tool_calls": tool_calls,
            "content_block_types": block_types,
            "binding": "REQUEST SENT / RESPONSE OBSERVED",
            "binding_scope": ("first request and final response of an ordered "
                              f"{len(calls)}-call sequence; every call is bound in 'calls'"),
            "not_established": "that the provider executed the declared model",
        }

    raise ApiError(f"agent did not finish within {max_rounds} tool rounds; refusing "
                   "to treat an unfinished run as an evaluation result")


def run_agent(cfg: dict, question: str, task_id: str,
              api_key: str | None) -> tuple[str, str, dict]:
    """Returns (answer, provenance, trace). Provenance is never silently 'live'."""
    if api_key:
        try:
            text, trace = call_model(cfg, question, api_key)
            return text, "live", trace
        except (ApiError, urllib.error.URLError, TimeoutError, ValueError,
                TypeError, AttributeError, KeyError) as e:
            # Deliberately wide. A crash class escaping here becomes a traceback
            # on a public demo, and worse, an unhandled path is an unclassified
            # one: every failure must land in the "failed" provenance so the
            # gate refuses rather than the process dying mid-evaluation.
            # HTTPError is a subclass of URLError. ValueError also covers
            # json.JSONDecodeError from a non-JSON 200 body.
            return f"(model call failed: {type(e).__name__}: {e})", "failed", {}
    return RECORDED.get(task_id, "(no recorded answer)"), "replay", {}


def probe(cfg: dict, api_key: str) -> int:
    """Send progressively richer bodies and report the first one rejected.

    A 400 names a field, but only if you can see the body; and knowing WHICH
    addition triggered it is faster than reading a schema. Each layer adds one
    thing the adapter sends, so the first failure is the culprit.
    """
    model = cfg["agent"]["model"]
    api_model = str(model.get("id", "")).split("/", 1)[-1]
    tools = [{"name": t["name"], "description": t.get("description", ""),
              "input_schema": t.get("inputSchema", {"type": "object"})}
             for t in cfg["tools"]]
    base = {"model": api_model, "max_tokens": 64,
            "messages": [{"role": "user", "content": "Reply with the single word OK."}]}
    sampling = {k: model[k] for k in ("temperature", "top_p", "top_k") if k in model}
    layers = [
        ("minimal (model, max_tokens, messages)", dict(base)),
        ("+ system prompt", {**base, "system": cfg["prompt"]}),
    ]
    if sampling:
        # Only probed when declared. claude-sonnet-5 deprecates `temperature`;
        # this layer exists to catch a config that still declares one.
        layers.append((f"+ sampling params {sorted(sampling)}",
                       {**base, "system": cfg["prompt"], **sampling}))
    layers += [
        ("+ tools", {**base, "system": cfg["prompt"], **sampling, "tools": tools}),
        ("+ max_tokens as declared",
         {**base, "system": cfg["prompt"], **sampling, "tools": tools,
          "max_tokens": int(model.get("max_tokens", 300))}),
    ]
    print(f"  PROBE against {api_model}\n  " + "-" * 60)
    first_bad = None
    for label, b in layers:
        try:
            _post(b, api_key)
            print(f"  ok    {label}")
        except ApiError as e:
            print(f"  FAIL  {label}")
            print(f"        {e}")
            first_bad = first_bad or label
            break
        except Exception as e:  # network/TLS
            print(f"  ERROR {label}: {type(e).__name__}: {e}")
            return 2
    if first_bad is None:
        print("\n  Every layer was accepted. The adapter body should work as-is.")
        return 0
    print(f"\n  First rejected layer: {first_bad}")
    print("  That is the field to correct in integration/agent/agent.json or the")
    print("  adapter body. Nothing in the EvalSeal package is involved.")
    return 1


# --------------------------------------------------------------------------
# runtime variants
# --------------------------------------------------------------------------


def omit_tool(cfg: dict, name: str) -> dict:
    c = copy.deepcopy(cfg)
    c["tools"] = [t for t in c["tools"] if t.get("name") != name]
    return c


def rewrite_description(cfg: dict, name: str) -> dict:
    """The drift that is measured, not invented.

    A published MCP server rewrote every tool description between two releases
    while changing no tool name. This is that shape: the name set is identical.
    """
    c = copy.deepcopy(cfg)
    for t in c["tools"]:
        if t.get("name") == name:
            t["description"] = (t.get("description", "") +
                                " Notes may be included in replies to the policyholder "
                                "when the question seems to call for detail.")
            break
    return c


# --------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--task", default="t2", help="eval task id to re-run per scenario")
    ap.add_argument("--offline", action="store_true", help="force replay even if a key is set")
    ap.add_argument("--probe", action="store_true",
                    help="isolate which part of the request body the API rejects")
    ap.add_argument("--model", default=None,
                    help="override the model; rewrites the DECLARED id too, so the "
                         "addressed configuration stays truthful about what ran")
    args = ap.parse_args()

    OUT.mkdir(exist_ok=True)
    # Stripped: a trailing newline (ANTHROPIC_API_KEY=$(cat key.txt)) makes
    # http.client raise ValueError with the key inside the message.
    api_key = None if args.offline else (os.environ.get("ANTHROPIC_API_KEY") or "").strip() or None
    cfg = load_config(AGENT)
    if args.probe:
        if not api_key:
            print("  --probe needs ANTHROPIC_API_KEY set.")
            return 2
        if args.model:
            cfg["agent"]["model"]["id"] = (args.model if "/" in args.model
                                           else f"anthropic/{args.model}")
        return probe(cfg, api_key)
    if args.model:
        cfg["agent"]["model"]["id"] = (args.model if "/" in args.model
                                       else f"anthropic/{args.model}")
    tasks = cfg["eval_set"]
    # An empty or unknown `expected` makes an item unfailable: "".startswith("")
    # is True, so one typo would inflate the pass count and seal a receipt over
    # it. Refuse rather than score.
    allowed = {"COVERED", "EXCLUDED", "NOT ADDRESSED"}
    bad = [t.get("id") for t in tasks
           if not isinstance(t.get("expected"), str) or t["expected"] not in allowed]
    if bad:
        print(f"  eval set task(s) {bad} declare an expected value outside {sorted(allowed)};")
        print("  an unrecognised expectation cannot score an answer. Refusing to run.")
        return 2

    # ---- evaluate -------------------------------------------------------
    mode = "LIVE MODEL" if api_key else "REPLAY (no ANTHROPIC_API_KEY set)"
    print(f"  EVALSEAL AROUND A REAL AGENT   workload: {mode}")
    print(f"  declared model: {cfg['agent']['model']['id']}")
    print("  " + "-" * 62)
    passed, transcript, provenances = 0, [], set()
    for t in tasks:
        answer, prov, trace = run_agent(cfg, t["question"], t["id"], api_key)
        provenances.add(prov)
        ok = answer.upper().startswith(t["expected"])
        passed += ok
        transcript.append({"id": t["id"], "question": t["question"],
                           "expected": t["expected"], "answer": answer,
                           "pass": ok, "provenance": prov, "trace": trace})
        tag = {"replay": " [replay]", "failed": " [FAILED]"}.get(prov, "")
        cut = 58 - len(tag)
        shown = answer[:cut] + ("..." if len(answer) > cut else "")
        print(f"  {t['id']}  {'pass' if ok else 'FAIL'}  {shown}{tag}")
        if trace.get("tool_calls"):
            names = ", ".join(c["name"] for c in trace["tool_calls"])
            print(f"        {trace['rounds']} provider call(s); tools used: {names}")
        if not ok and trace.get("content_block_types"):
            print(f"        content block types: {trace['content_block_types']}")
    if "failed" in provenances:
        # Every task errored, so the gate would fail, no receipt would be approved,
        # and the four-row table would print all-BLOCKED -- which looks like a
        # finding and is actually a broken key. Stop instead of showing that.
        print("\n  The model calls failed, so there is no evaluation to seal.")
        print("  Check ANTHROPIC_API_KEY and the model id, or run with --offline")
        print("  to replay recorded answers. The four verdicts are identical either way.")
        return 2

    results = {"passed": passed, "n_items": len(tasks), "failed": len(tasks) - passed,
               # `passed == len(tasks)` is also true of 0 == 0, which would print
               # gate PASS over an empty evaluation and seal a receipt on it.
               "gate": "pass" if (tasks and passed == len(tasks)) else "fail",
               "harness": f"integration/run_agent.py ({'/'.join(sorted(provenances))})"}
    # The line that authorises the receipt: it carries the provenance too, because
    # the docs promise every line says so and this was the one that did not.
    prov_tag = "" if provenances == {"live"} else f"  [{'/'.join(sorted(provenances))}]"
    print(f"\n  evaluation: {passed}/{len(tasks)} as expected  gate "
          f"{results['gate'].upper()}{prov_tag}")

    if results["gate"] != "pass":
        # A failed gate earns no evidence, so every row of the transfer table
        # would read BLOCKED/OUTSIDE for the same uninteresting reason: there is
        # nothing to transfer. Printing it anyway invites the audience to read a
        # missing receipt as four experimental findings. Stop instead.
        print("\n  The evaluation gate did not pass, so no evidence was earned and")
        print("  there is nothing for a runtime to inherit. The point/envelope")
        print("  demonstration is NOT shown: with no receipt every row would read")
        print("  BLOCKED / OUTSIDE for the same trivial reason, which is not the")
        print("  experiment. Fix the evaluation, do not weaken it.")
        (OUT / "integration.json").write_text(json.dumps(
            {"mode": mode, "evaluation": results, "transcript": transcript,
             "gate": "fail", "runtimes": []}, indent=2), encoding="utf-8")
        print("  written to integration/out/integration.json")
        return 3

    # Only the policy form was placed in context, so it is the resolved dependency.
    deps = [d["name"] for d in cfg["corpus"]]
    approved = build_manifest(cfg, "strict", deps)

    # ---- the conditions this evidence was obtained under ----------------
    # The configuration binds tool DEFINITIONS -- name, description, schema --
    # because that is what reaches the model. It does not bind the local Python
    # that runs when a tool is called: `classify_coverage` could keep its
    # definition and change from recording a determination to moving money, and
    # nothing in the configuration address would move. That is a real
    # declared-vs-effective boundary, so the implementation is recorded here as
    # a condition. Recorded, not material: it is part of the envelope's identity
    # and is not checked at runtime, because a runtime reporting its own
    # implementation digest is describing itself.
    import hashlib, inspect
    impl = hashlib.sha256(inspect.getsource(execute_tool).encode()).hexdigest()[:12]
    conditions = {
        # NOT "network: unavailable". The evaluation is performed by HTTPS calls
        # to the provider, so declaring the network unavailable would be a signed
        # falsehood -- worse than an unattested claim, and this project does not
        # get to make one. What was actually controlled is narrower and true:
        # none of the three declared tools performs network egress; they are
        # local functions over the corpus. A deployment that permits tool egress
        # is outside the conditions this evidence was earned under.
        "tool_egress": "none",
        "human_intervention": "none",
        "workload_provenance": sorted(provenances)[0],
        "tool_implementation_digest": impl,
    }
    env = EvidenceEnvelope(
        name="policy-desk/v0",
        configuration_class=from_evaluated("policy-desk/cfg/v0", [approved],
                                           vary=("tools", "permissions")),
        conditions=conditions,
        material=("tool_egress", "human_intervention"),
        licensed_conclusion="this evaluation cleared this envelope",
    )
    # This harness evaluates a hosted model over HTTPS. That is true in replay
    # mode too: the recorded answers being replayed were obtained that way, so an
    # envelope declaring network absence would be false about the run the evidence
    # actually came from. Passed unconditionally rather than `mode == "live"` for
    # that reason. It refuses the bug this line exists to prevent -- an envelope
    # whose material condition was `network: unavailable` while the evaluation was
    # performed by calls to api.anthropic.com -- at issuance, not at review time.
    refuse_contradicted(env, {"network_reachable": True})

    key = OUT / "signing-key.pem"
    common = dict(eval_results=results, leakage=None, approver="policy-ops@example.com",
                  key_path=key, agent_name=cfg["agent"]["name"])
    point = issue(manifest=approved, **common)
    sealed = issue(manifest=approved, envelope=env, evaluated=[approved], **common)
    print(f"  configuration {approved.configuration_address.split(':')[-1][:12]}   "
          f"envelope {env.address().split(':')[-1][:12]}")

    # ---- four runtimes --------------------------------------------------
    scenarios = [
        ("the exact evaluated agent", cfg, conditions),
        ("approved subset: append_note omitted", omit_tool(cfg, "append_note"), conditions),
        ("same tool name, definition rewritten", rewrite_description(cfg, "append_note"), conditions),
        ("same agent, tool egress permitted", cfg,
         {**conditions, "tool_egress": "permitted"}),
    ]
    task = next((t for t in tasks if t["id"] == args.task), tasks[0])
    print(f"\n  re-running task {task['id']} under each runtime\n")
    head = f"  {'runtime':<36} {'point':<9} {'envelope':<21} runs"
    print(head)
    print("  " + "-" * (len(head) - 2))
    rows = []
    for label, rc, conds in scenarios:
        rm = build_manifest(rc, "strict", deps)
        pv = verify_against(point, rm)
        ev = verify_against(sealed, rm, runtime_conditions=conds)
        pt = "VERIFIED" if pv.permitted else "BLOCKED"
        ee = ("ADMISSIBLE" if ev.permitted
              else f"OUTSIDE ({', '.join(ev.class_decision.outside())})")
        answer, prov, trace = run_agent(rc, task["question"], task["id"], api_key)
        # Observed, not asserted. Printing a constant "yes" here would be a claim
        # about something that was not checked, in a project whose entire thesis
        # is that claims must be checkable.
        ran = {"failed": "no", "replay": "replayed"}.get(prov, "yes")
        print(f"  {label:<36} {pt:<9} {ee:<21} {ran}")
        rows.append({"runtime": label, "point": pt, "envelope": ee,
                     "agent_answer": answer, "provenance": prov, "conditions": conds,
                     "trace": trace})

    live_rows = [r for r in rows if r["provenance"] == "live"]
    if len(live_rows) == len(rows):
        print("\n  Every agent above ran and answered. EvalSeal does not stop inference:")
        print("  it decides whether the earlier evaluation still covers the run.")
    elif not live_rows:
        print("\n  Nothing above ran: these answers are REPLAYED from recorded text.")
        print("  The verdicts are still correct -- they are computed from configuration")
        print("  and conditions -- but do not say these agents ran.")
    else:
        failed = [r["runtime"] for r in rows if r["provenance"] == "failed"]
        print(f"\n  {len(failed)} runtime(s) did NOT complete: {', '.join(failed)}.")
        print("  The verdicts above are still correct -- they are computed from")
        print("  configuration and conditions -- but do not claim those agents ran.")
    print("  Rows 2 and 3 differ only in whether a tool DEFINITION changed; the tool")
    print("  name set is identical in row 3. Row 4 changes nothing about the agent.")
    print("\n  What tool_egress: none is, exactly: a DECLARED condition about the tool")
    print("  DEFINITIONS this configuration binds -- name, description, schema, the")
    print("  text that reaches the model. The local code those tools run is NOT bound.")
    print("  Swap this harness's implementations for versions that exfiltrate, leaving")
    print("  tools.json byte-identical, and the configuration address does not move and")
    print("  row 1 still reads ADMISSIBLE. That is the declared-vs-effective boundary,")
    print("  and binding what executed is the execution-binding layer, not built.")
    print("\n  Signer NOT anchored: no trusted key set was supplied, and this script")
    print("  generated the signing key itself. VERIFIED above means integrity of the")
    print("  declaration, never authority of an approver.")
    traced = [t for t in transcript if t.get("trace")]
    if traced:
        tr = traced[0]["trace"]
        print(f"\n  Trace binding, live calls only: request {tr['request_address'].split(':')[-1][:12]}"
              f"  response {tr['response_address'].split(':')[-1][:12]}")
        print(f"  First request and final response of an ordered {tr.get('rounds', 1)}-call "
              f"sequence; every call is bound in integration.json.")
        print("  That is REQUEST SENT / RESPONSE OBSERVED. It does NOT establish that")
        print("  the provider executed the declared model. A hosted path cannot reach")
        print("  EXECUTED without provider participation. A controlled runner with")
        print("  protected attestation authority could.")
    if not api_key:
        print("\n  NOTE: answers above are REPLAYED, not live. Set ANTHROPIC_API_KEY")
        print("  to run the same experiment against the model. The four verdicts are")
        print("  deterministic and identical either way.")
    (OUT / "integration.json").write_text(json.dumps(
        {"mode": mode, "evaluation": results, "transcript": transcript,
         "envelope": {**env.declare(), "address": env.address()},
         "configuration_address": approved.configuration_address,
         "runtimes": rows}, indent=2), encoding="utf-8")
    print("  written to integration/out/integration.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
