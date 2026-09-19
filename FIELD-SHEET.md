# Field sheet — AGI House, Hillsborough, 19 Sep 2026

Print this or keep it open. The demo is the ticket in; the notes below are what
you actually leave with.

---

## The two questions

Ask these of every person from a regulated industry. Heads of AI, the judges,
anyone who says "we have agents in production."

> **1. When an agent changes in your organization, what determines whether it has
> to be re-evaluated?**

> **2. Could you prove, six months later, exactly which configuration earned the
> approval currently attached to a production agent?**

**Do not pitch after asking. Listen.** The answer is the product research; your
demo is only what earns you the right to ask.

Answers you should expect, and what each one means:

| If they say | It means |
| --- | --- |
| "Any prompt change" | They have a policy. Ask if it's enforced or aspirational. |
| "Only model changes" | The gap is exactly what you measured. Best case. |
| "We don't know" / "No policy" | Real pain, no owner yet. Ask who *would* own it. |
| "Security decides" | Find out whether security can see prompt and tool changes at all. |
| "We rerun everything" | Expensive. Ask what that costs per release. |
| "Depends on the application" | Ask for the application where it matters most. |

---

## Capture matrix

Fill a row per conversation. Names optional; the pattern is the asset.

| Org type | Re-evaluation trigger | Identity unit | Evidence retained | Biggest gap |
| --- | --- | --- | --- | --- |
| Pharma |  |  |  |  |
| Bank / financial services |  |  |  |  |
| Insurance |  |  |  |  |
| Enterprise SaaS |  |  |  |  |
| AI-native vendor |  |  |  |  |
| Healthcare provider |  |  |  |  |

**Identity unit** is the sharpest column: what do they think "the agent" *is*
when they approve it? A name? A model version? A container digest? A git SHA? A
prompt file? Nobody has a good answer, and the distribution of bad answers tells
you where the buyer is.

Witness has no defined first-customer profile. This is how that gets defined.

---

## The four claims, in order

Pitch these in this order. The boundary comes third-to-last on purpose — stated
early it reads as maturity, stated last it reads as backpedalling.

1. **Problem.** Agent approval names components. The model-facing configuration
   underneath those names changes.
2. **Evidence.** 10 published MCP servers, 79 versions, measured: 51 tool
   descriptions rewritten under unchanged tool names. One grew from 523 to 2,006
   characters of model-facing instruction.
3. **Mechanism.** Carry evaluation evidence forward only when the presented
   configuration is equivalent under an explicitly declared materiality relation.
   Evidence belongs to the configuration that earned it — and identity includes
   what was *material* to earning it, not everything that coexisted with it.
4. **Boundary.** Verification establishes the identity of the declared artifacts
   presented to EvalSeal — not what the runtime loaded or executed.
   DECLARED ≠ EFFECTIVE ≠ EXECUTED.

## Twenty seconds

> "Enterprises approve agents by name and version. We measured ten published MCP
> servers: fifty-one tool descriptions were rewritten under unchanged names — one
> grew four-fold into two thousand characters of instruction that goes straight
> into the model's context. Approval keyed on names sees none of it. EvalSeal
> gives the evaluated configuration a deterministic identity, checks the held-out
> set for contamination before issuing evidence, and blocks any deployment whose
> configuration drifted. It does not claim to know what executed — that boundary
> is in the signed receipt and enforced by a test."

---

## Demo running order

Five commands, 90 seconds. Run them in this order.

    python3 -m evalseal demo                  # seal → VERIFIED
    python3 -m evalseal demo --mutate tool    # silent tool change → BLOCKED, field named
    python3 -m evalseal demo --reserialize    # re-serialize everything → still VERIFIED
    python3 -m evalseal benchmark             # 7/7 attacks as declared
    python3 -m evalseal bakeoff               # 9/9 only for the declared policy
    python3 -m evalseal swarm                 # point vs envelope, 4 attempts
    python3 -m evalseal graph --replay-real --compact
                                              # real published drift breaks delegation;
                                              # --compact fits 30 lines x 80 cols for a projector

Benchmark is 7 rows. Rows 4 and 5 are the pair worth narrating: adding a
corpus document nothing read PRESERVES the evidence; changing one that was read
REVOKES it. No global corpus binding gets both.

If you only get one: **`benchmark`**. It's the whole argument in one table.

If the room is technical, **`bakeoff`** is the stronger one. Say "a published MCP
server" and let the output put the name on screen — you're measuring, not
accusing:

> "A published MCP server sets a schema bound at 9007199254740991. Raise it by
> one, and by two — 9007199254740992 and 9007199254740993 — and a float-coercing
> canonicalizer gives both the same identity. That's not a false alarm, it's a
> false accept: a changed configuration inheriting approval it never earned."

**Do not say "one step past that bound."** The published bound (2^53−1) and one
step past it (2^53) are both exactly representable. It's 2^53 and 2^53+1 that
collide. Someone may do the arithmetic while you talk.

`--mutate homoglyph` is command 7 and the pinned fallback: run it for a technical
audience, and run it if anything stalls. Cyrillic `а` U+0430 for Latin `a`
U+0061, flagged as a different script.

Have `realdata` ready but don't lead with it; it contains the negative result and
needs a sentence of setup.

## Two phrasings to use verbatim

**On the SEC reuse result** — say this, not a safety rate:

> "Across this frozen corpus, certified substitution eliminated every false reuse
> observed in the comparison. Relevant-state coverage is still only two filing
> transitions, so we treat this as evidence for the mechanism, not an estimated
> safety rate."

**Speaker note, if you show both the reuse ladder and the bake-off.** They will
look contradictory and they are not:

> L0 asks whether two *requests* have the same visible surface, while external
> resolved state may be omitted from that surface. `raw_bytes` compares the actual
> *configuration material* being bound. Same request text ≠ same configuration
> bytes. So L0 false-reusing and configuration-byte identity never false-accepting
> are consistent.

Always say **"external measurement"** and **"not our measurement"** when the SEC
ladder comes up. Showing that the design changed in response to independent
evidence is stronger than appearing to have produced that evidence yourself.

## Answers to have loaded

**"Isn't this just JCS plus sha256?"**
RFC 8785 is the canonical form; the contribution isn't the digest. It's binding
evaluation evidence to a configuration identity under a *declared* equivalence
relation, and measuring what drifts in the wild. Also note `1` vs `1.0`: JCS
collapses them, which is wrong for a schema contract, so the strict profile
deliberately doesn't.

**"Why not just pin the bytes?"**
Say the honest thing: *we measured that, and byte pinning was fine.* Zero
byte-only changes across 63 published version pairs, positive control passing.
We pre-registered that falsifier and it killed one of our selling points. The
claim that survived is about name-keyed approval, not byte fragility.

**"Why not just use embeddings for leakage?"**
We haven't tested embeddings — level 2 is a lexical char-n-gram baseline, and
calling it semantic would overstate it. Even that lexical baseline out-recalls
structural on our corpus: at tau 0.60 it finds 20/20 with one false positive,
against structural's 16/20 with none. For a release gate we want determinism, not
a tunable: no threshold to defend, no false positives by construction, the same
answer on every machine forever.

**"Your Town work says 1 and 1.0 are the same value. This says they aren't."**
Not an inconsistency — the thesis working. Dataset lineage wants invariance
across numeric spelling; a schema bound wants injectivity, because integer and
float are different contracts to a typed consumer. Declaring the relation per
contract is how you get both.

**"Why not just canonicalize the JSON like everyone else?"**
Because most shipped canonicalizers coerce numbers to float64 and normalize no
Unicode. We measured six identity functions on nine transformations: the
Go-style canonicalizer had **two false accepts**, including two distinct schema
bounds converging at the float64 boundary. It fails in the dangerous direction
while looking rigorous.

**"Isn't 1 vs 1.0 the same number?"**
For `temperature`, yes. For a tool schema bound, no — different contract to a
typed consumer. That's why materiality is declared per field and carried in the
signed receipt, rather than baked into one canonical form. If you disagree with a
specific rule, that's the point: it's visible and contestable.

**"Is 100 the same bound as 100.0?"**
Say it's an open policy question and you declared an answer. `strict` says no
(different contract to a typed consumer); `integral_safe` says yes and refuses
anything it cannot represent exactly. Both are in the bake-off with their costs.
Do not pretend there's a derived right answer — the declared, contestable policy
*is* the contribution.

**"MCP scanners already hash tool definitions."**
Correct, and we don't claim otherwise. Those detect that a tool changed. We bind
the *evaluation result* to the whole configuration, so the question becomes
whether the evidence still applies — and across delegation, whether it applies to
the child a parent handed work to.

**"How do you know the agent actually used that prompt?"**
We don't, and we say so in the signed receipt. That's EFFECTIVE/EXECUTED
attestation and it's outside v0. `test_overclaim.py` fails if any field outside
the scope block asserts execution.

---

## Do not

- Claim canonicalization prevents real-world false alarms. Your own data refuses
  it.
- Present `realdata` as support for the byte argument. It's a negative result.
- Call level 2 "semantic." It's a lexical char-n-gram baseline until a real
  embedding model is behind it.
- Mention UMRP, the Foundation's scope question, or anything from the Buzz
  normative profile. Import the principle, not the lineage.
- Claim byte compatibility with UOR-ADDR digests. The scheme is `es1` and it's
  local to this project.
- Add an embedding model before the room opens.
- ~~Add a live model~~ -- superseded 19 Sep. `integration/run_agent.py` runs a
  real Claude agent and was verified live at 13:51. The rule it replaces was
  about not adding one *during* the build; the verifier stayed deterministic,
  which is the property that mattered.


---

## Late additions (post code review, 01:30)

**The demo prints "VERIFIED (signer not anchored)", not plain VERIFIED.** Deliberate.
A signature proves the payload is unchanged since signing; it does not prove who
signed it, because nothing here knows which keys may approve a release. Pass a
trusted key set and it reads VERIFIED. There is a test proving a forged receipt
fails against a key set, and another pinning that it passes without one.

**Two numbers were corrected downward and the old ones must not be quoted:**

| number | was | is |
| --- | --- | --- |
| leakage precision at tau 0.50 | 83% | **56%** (16 false positives) |
| *always name the tau when quoting precision* | — | main table is tau **0.80**, where false+ = 0 |
| conformance rows informative | 12/12 | **10/12** |
| byte false alarms in conformance | 5 | **3** |

**Benchmark rows 4 and 5** are the pair worth narrating: adding a corpus document
nothing read PRESERVES the evidence; changing one that was read REVOKES it. No
global corpus binding gets both.

**Still advertised beyond what it enforces:** `evalseal relation` prints a
materiality policy that currently governs only the bake-off — `build_manifest`
does not call `apply_policy`, so receipts record `v0-implicit`. Say so in one line
if asked; don't discover it live.

**If asked how you controlled your own claims** (keep in reserve): three
independent reviewers audited the code overnight and found 20+ erased
distinctions, including an end-to-end false accept in our own dependency-scoping
mechanism and two published numbers that were too favourable. All fixed, numbers
corrected downward.

**Keep `evalseal relation` out of the running order.** It prints a materiality
policy that currently governs only the bake-off — `build_manifest` does not call
`apply_policy`, so receipts record `v0-implicit`. If a judge runs it: the policy
is declared and governs the bake-off today; receipts carry it in v0.1.

**Attribution line:** Maura Clark. Kessai work using UOR-style structural
addressing — not a UOR Foundation deliverable, no byte-compatibility claim
against UOR-ADDR digests.
