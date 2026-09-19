# EvalSeal around a real agent

An adapter, not a framework. It imports only EvalSeal's public API and changes
nothing in the package. Three tests in the core suite do read this file (they
pin the derived `runs` column and the absence of a network-absence condition), so
the dependency runs that way round: the package does not import this directory.

    python3 integration/run_agent.py                 # live if ANTHROPIC_API_KEY is set
    python3 integration/run_agent.py --offline       # replay recorded answers
    python3 integration/run_agent.py --model claude-haiku-4-5-20251001

`agent/` is an ordinary EvalSeal configuration directory — system prompt, three
MCP-shaped tool definitions, permissions, one policy-form document, six
deterministic tasks. The agent answers coverage questions from the form.

## What it demonstrates

| runtime | point identity | envelope |
| --- | --- | --- |
| the exact evaluated agent | VERIFIED | ADMISSIBLE |
| approved subset: one tool omitted | BLOCKED | ADMISSIBLE |
| same tool name, definition rewritten | BLOCKED | OUTSIDE (tools) |
| same agent, tool egress permitted | VERIFIED | OUTSIDE (tool_egress) |

Every one of those agents **runs and answers**. That is the point. EvalSeal does
not stop inference and could not; it decides whether the earlier evaluation still
covers the run. The claim is *you may run this, but you can no longer say the
evaluation covers it.*

## Three deliberate choices

**The model's answer is incidental.** All four verdicts are deterministic,
computed from configuration and declared conditions. They are identical live or
replayed.

**Nothing depends on the model misbehaving.** Row 3 rewrites a tool description
the way published MCP servers really do, with the name set unchanged. Whether the
model's answer changes is not the experiment.

**The LLM is the workload, never the verifier.** No model is asked whether
evidence still applies. A second probabilistic system adjudicating evidence about
the first is the structure this project argues against.

## Honest limits

- The API model string is derived from the declared model id, so what is
  addressed is what is called. That binds the declaration, not the weights.
- Conditions (`tool_egress`, `human_intervention`) are **declared, not
  attested**. Nothing here observes them. The condition says no *declared tool*
  performs network egress; the workload itself reaches the provider over HTTPS
  by construction, which is why it is not called "network unavailable".
- The table prints bare VERIFIED / ADMISSIBLE. No trusted key set is supplied
  and this script generates its own signing key, so that is integrity of the
  declaration, never authority of an approver. The script says so on stdout.
- Live runs address the request package and the response. That is REQUEST SENT /
  RESPONSE OBSERVED, never EXECUTED: it does not establish that the provider ran
  the declared model. A hosted path cannot reach EXECUTED without provider
  participation; a controlled runner with protected attestation authority could.
- Without a key the answers are replayed and every line says so.
