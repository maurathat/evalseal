# EvalSeal

**Did you deploy the agent you evaluated?**

An enterprise evaluates an agent, approves it, and deploys it. Then the system
prompt gets edited, an MCP server ships a new version, someone widens a
permission — and the dashboard still shows the score from the configuration that
no longer exists. EvalSeal binds an evaluation result to a deterministic identity
for the configuration that earned it, checks the held-out set for contamination
before sealing, and refuses to let a changed configuration inherit the result.

    python3 -m evalseal demo                  # seal a release, verify at runtime
    python3 -m evalseal demo --mutate tool    # silently change a tool → BLOCKED
    python3 -m evalseal demo --reserialize    # re-serialize everything → VERIFIED
    python3 -m evalseal conformance           # declared vs observed, per relation
    python3 -m evalseal leakage               # byte vs structural vs lexical
    python3 -m evalseal relation              # print the declared relation + its address
    python3 -m evalseal bakeoff               # 6 identity functions: blocks / accepts / refusals
    python3 -m evalseal benchmark             # 7 rows: 4 drift classes + contamination + refusal
    python3 -m evalseal graph --replay-real   # real published drift breaks delegation
    python3 -m evalseal graph --widen-child   # authority widens at a hop -> BLOCKED
      ... add --compact to either: same addresses and numbers, 30 lines
    python3 -m evalseal realdata              # measurement on published MCP servers
    python3 -m evalseal swarm                 # evidence envelope: class + conditions

Install: `pip install cryptography scikit-learn` (plus `pytest` to run tests).
The `evalseal` package itself does no model inference: no GPU, no vector store,
and no network anywhere in the package (`realdata` reads a cache; the harvester
that fetches it, `realdata/harvest.py`, is outside the package). That is deliberate -- **the verifier is
deterministic; the workload does not have to be.** `integration/` runs a real
Claude agent through it and needs an API key and network; the package does not
know that directory exists.

---

## The principle

> **Identity should quotient out representation differences, but preserve every
> distinction capable of changing the claim being certified.**

Three separate lines of work converge on that, and each one is a different way of
getting it wrong:

| | the mistake | the correction |
| --- | --- | --- |
| Model-artifact binding | canonicalizing opaque artifact bytes | byte-exact identity; weights have no meaningful normal form |
| EvalSeal | treating serialization as meaningful | quotient out what a formatter or transport can introduce |
| Reuse ladder | canonicalizing away resolved state | preserve dependencies that can change the answer |

Canonicalization is a **mechanism inside** this, not the thesis. Canonicalizing
too little produces false blocks; canonicalizing too much produces false accepts,
and the bake-off shows that the second failure is the dangerous one.

## The four claims

**Problem.** Agent approval names components, while the model-facing
configuration underneath those names can change.

**Evidence.** In a sample of 10 published MCP servers: 51 tool descriptions
rewritten under unchanged tool names, including one that expanded from 523 to
2,006 characters of model-facing instruction.

**Mechanism.** Carry evaluation evidence forward only when the presented
configuration remains equivalent under an explicitly declared materiality
relation. Evidence belongs to the configuration that earned it — and
configuration identity includes what was *material* to earning it, not everything
that happened to coexist with it.

**Boundary.** Verification establishes the identity of the declared artifacts
presented to EvalSeal — not what the runtime actually loaded or executed.
DECLARED ≠ EFFECTIVE ≠ EXECUTED.

## The invariant

The product objective is that an evaluation result should never silently follow a
changed agent configuration. The *enforceable* invariant is narrower, and stating
the difference is the point:

> An evaluation result may be released only when the presented deployment
> configuration resolves to the same declared configuration identity that earned
> the result.

"Presented" is load-bearing. EvalSeal resolves the artifacts handed to it for
verification. Establishing what a process actually loaded and ran is
EFFECTIVE/EXECUTED attestation, and is outside v0.

A configuration is not a model name. It is the model, the system prompt, the
operating procedure, the MCP tool definitions, the retrieval corpus, the
permission set and the eval set. Each component is addressed with the rule that
fits its type; the manifest of component addresses is itself addressed. Two
levels, so a mismatch is diagnosable: the configuration address says something
changed, the component addresses say which, the diff says which field.

    model        bb7f8909  (provider-string)
    prompt       3d61c95c  (text)
    procedure    b83f38f6  (text)
    tools        d8c41de2  (4 tool(s))
    corpus       ac168caf  (2 doc(s), scope=resolved)
    permissions  c7e07b60  (4 op(s))
    eval_set     cda66f55  (20 item(s))
    CONFIGURATION  8cabf76750ae

---

## Evidence inheritance

Evaluation evidence is not a property of an agent's name. It is evidence attached
to an identified configuration:

    evaluation evidence  ->  configuration k1

If the configuration changes, `k1 -> k2`, then **k2 does not inherit k1's
evidence**. That gives one rule, and the whole system is an implementation of it:

> **Evidence inheritance rule.** Evaluation evidence may be reused only when the
> deployment satisfies the equivalence relation under which the evidence was
> issued.

Which immediately forces the question the relation profiles exist to answer:
*what counts as the same configuration?* Re-serialize the artifacts and it is the
same one. Rewrite a tool description and it is not.

## The identity bake-off

    python3 -m evalseal bakeoff

The conformance table asks whether one relation behaves as declared. This asks
the harder question: given the identity functions people actually ship, how often
does each get the wrong answer, and **in which direction**?

    false block    a cosmetic change breaks identity
                   cost: an evaluation suite re-run for nothing
    false accept   a material change preserves identity
                   cost: a changed configuration inherits evidence it did not
                   earn — a security failure, not an inconvenience

Nine transformations, chosen because they break shipped canonicalizers. Key
reordering is deliberately **not** among them: everyone handles it, and a demo
built on it proves nothing.

| identity function | correct | false blocks | false accepts |
| --- | --- | --- | --- |
| `raw_bytes` | 5/9 | 4 | 0 |
| `naive_canonical` (Go-style parse/sort/re-serialize) | 6/9 | 1 | **2** |
| `evalseal_strict` | 8/9 | 1 | 0 |
| `evalseal_eval` | 8/9 | 0 | **1** |
| `evalseal_policy` (declared per-field) | **9/9** | 0 | 0 |
| `evalseal_integral_safe` (integral-safe admission) | 7/9 | 0 | 1 (+1 refused) |

**The headline is the false-accept column.** `naive_canonical` models what a
service written in Go ships when it round-trips JSON through
`map[string]interface{}`: HTML-escaping of `&`, keys sorted by code point rather
than the UTF-16 order RFC 8785 requires, and every number coerced to float64.
That last one is not a style difference. Two distinct schema bounds converge to
one identity:

    "maximum": 9007199254740992   (2^53)    ->  float64  ->  9007199254740992
    "maximum": 9007199254740993   (2^53+1)  ->  float64  ->  9007199254740992
    same digest, different contract

    Note the published bound 9007199254740991 (2^53-1) is itself exactly
    representable, as is 2^53. It is the NEXT pair that collides.

**This is anchored in real data, not constructed.**
`@modelcontextprotocol/server-sequential-thinking@2025.11.25` publishes
`"maximum": 9007199254740991` on four separate integer parameters — exactly
2^53−1, `Number.MAX_SAFE_INTEGER`. The ecosystem's own schemas are written right
up against the precision limit that a float-coercing canonicalizer silently
crosses. A canonicalizer that has not declared its relation is not safer than no
canonicalizer; it is worse, because it fails in the dangerous direction while
looking rigorous.

### Why no global relation is enough

Two cases, same transformation — an integer gains a decimal point:

| | change | verdict |
| --- | --- | --- |
| `temperature: 1 → 1.0` | a sampling parameter | **cosmetic** — identical to every serving stack |
| `"maximum": 100 → 100.0` | a tool schema bound | **material** — a different contract to a typed consumer |

`evalseal_strict` gets the second right and false-blocks the first.
`evalseal_eval` gets the first right and false-accepts the second. Loosening the
relation does not fix the problem, it relocates it — into the dangerous
direction. There is no third global option.

So materiality is a **declared policy**, not a derived fact:

    Rule("key:temperature",   "eval")     numeric form ignored
    Rule("path:/inputSchema", "strict")   numeric form matters
    Rule("key:_comment",      exclude)    never compared

Each rule carries its justification, the policy is addressed and signed with the
evidence, and exclusions are named so an auditor sees what was deliberately not
compared. Key order is obviously cosmetic; whether whitespace in a system prompt
or reordered few-shot examples are is genuinely arguable — and that argument
belongs in a visible, contestable policy rather than buried in a canonicalizer
nobody reads. Changing the policy changes the evidence.

A receipt issued with no policy says so explicitly, so silence is never mistaken
for a decision.

### An open disagreement, measured rather than argued

`evalseal_integral_safe` is a third declared position: any spelling of an
integral value is the same value, and anything outside ±(2^53−1) or non-integral
is **refused** rather than approximated. That refusal is a real third outcome —
safer than answering, and portable to a reimplementation in a language without
arbitrary-precision integers, where `strict` would only be accidentally correct.

It also treats a schema bound of `100` and `100.0` as the same bound, which this
repo's case set classifies as a false accept. Whether that classification is
right turns on whether the JSON *type* of a schema bound is part of the contract.
The bake-off does not settle it; it makes the disagreement visible and costed.
Pick one, declare it, and be able to defend it — that is what the `relation`
command prints.

## Dependency scoping

Benchmark rows 4 and 5 are a pair no global corpus binding can satisfy:

| row | change | correct verdict |
| --- | --- | --- |
| 4 | add a corpus document the evaluation never read | **evidence preserved** |
| 5 | change a corpus document the evaluation read | **evidence invalidated** |

Binding the whole corpus gets row 5 right and row 4 wrong. Binding nothing
inverts both. Binding the *resolved dependency set* — the documents the
evaluation actually consulted — gets both, and is the default
(`--corpus-scope resolved`). The scope is declared in the receipt, because it
changes what "the same configuration" means.

### Observational equality is weaker than certified substitutability

Two executions producing the same answer today have not been shown to be
interchangeable. The match may be luck: a rounding collision, a rule that did not
fire, a document whose change was invisible at this precision. The external
measurement caught exactly this — at precision 2, two different computations
collided at `6.44`, so an output-equality oracle called the reuse valid while
certified substitution refused; raising the precision made the apparent
equivalence vanish and proved the refusal right.

`tests/test_substitutability.py` makes that an executable invariant here: a
consulted document changes in a way that alters no decision, the evaluation result
is identical in every observable respect — score, failures, gate — and the
evidence is still revoked. A companion test asserts the refusal is scoped to
documents actually read, because always-refuse would pass the first test and be
useless. Neither test alone distinguishes this from a degenerate system; that is
why both are pinned.

This came from an **external measurement** — not ours — over accession-pinned SEC
EDGAR filings, which separates exactly these two classes. In that frozen corpus,
resolved-dependency binding achieved precision 1.0 across the reported runs,
and recall 1.0 in three of the four (run d11 records one missed reuse, recall
0.93 — see docs/REUSE-LADDER.md). Across the
reported runs, including when corpus state was hidden from the request surface
(where request-text matching recovered 6 valid reuses and 19 invalid ones).
Coverage of relevant dependency changes spans only **two underlying filing
transitions**, so this supports the mechanism and the paired comparison, not a
general safety rate. See [docs/REUSE-LADDER.md](docs/REUSE-LADDER.md).

## The benchmark

    python3 -m evalseal benchmark        # exits non-zero if any row diverges

Every row declares its expectation before the run.

| # | attack | action | expected | result |
| --- | --- | --- | --- | --- |
| 1 | cosmetic drift | re-serialize every artifact | evidence preserved | PASS |
| 2 | material drift | edit the system prompt | evidence invalidated by drift | PASS |
| 3 | dependency drift | change an MCP tool definition | evidence invalidated by drift | PASS |
| 4 | irrelevant dependency | add a corpus doc the evaluation never read | evidence preserved | PASS |
| 5 | relevant dependency | change a corpus doc the evaluation read | evidence invalidated | PASS |
| 6 | eval contamination | plant structural duplicates | no evidence issued | PASS |
| 7 | overclaim attempt | read VERIFIED as proof of execution | insufficient evidence | PASS |

Row 7 is the one most provenance systems would fail. It reads off the receipt's
own declared layer and reports exactly what a passing verification licenses:

    licenses:  integrity of the declaration, identity of presented artifacts,
               evaluation cleared this configuration
    withholds: execution, effective model, and -- unless a trusted key set was
               supplied -- authority of the approver

For a class receipt the same command licenses less, and says so: membership
inside the declared envelope replaces identity of presented artifacts, and
behavioural equivalence between members and conditions were as declared are both
withheld.

## Delegation: evidence does not aggregate upward

    python3 -m evalseal graph --replay-real

A coordinator delegates to two specialists. Each has its own configuration
identity and its own evidence; the run is admissible only if every node is. A
parent cannot vouch for a child it never evaluated.

**Authority must also narrow at each hop.** A child holding an operation its
delegator does not hold was granted authority the delegation could not have
conferred. Configuration identity says nothing about this — every node can verify
perfectly and the run still be inadmissible — so it is checked separately:

    python3 -m evalseal graph --widen-child

    research-agent
      AUTHORITY WIDENED at this hop: ['payment.execute']
      The delegator does not hold these operations, so the delegation
      could not have conferred them. The configuration verifies; the
      run is inadmissible anyway.

That is the primer's "delegated authority chains that narrow at each hop", and it
is the one place where an address is the wrong instrument.

The drift that breaks it is **not authored for the demo**. It advances one
delegated agent's toolset across two consecutive *published* releases of
`@upstash/context7-mcp`, from the captured definitions in `realdata/tools`:

    HUMAN
      |
        v  claims-review-coordinator    k=82a7b2c686  ADMISSIBLE
        |--delegates--> policy-agent                 k=9a7358c3f3  ADMISSIBLE
        `--delegates--> research-agent               k=79fc0246df  BLOCKED

    tools/resolve-library-id/description  [changed]
      - Resolves a package name to a Context7-compatible libra…
      + Resolves a package/product name to a Context7-compatib…
    tools/get-library-docs/description  [changed]
      - …d to use this tool.
      + …d to use this tool, UNLESS the user explicitly provide…

    NOTE — this drift was not authored for the demo.
      @upstash/context7-mcp  1.0.8 -> 1.0.18 (consecutive published releases)
      tool name set: IDENTICAL (2 tools, none added, removed or renamed)
      descriptions rewritten: 2 of 2
        resolve-library-id    523 -> 1133 chars (+610)
        get-library-docs      166 ->  286 chars (+120)

Both tools this server exposes had their descriptions rewritten; neither name
changed. The second one added a conditional override — `UNLESS the user
explicitly provide…` — to the text that tells the model when to call the tool.
That is an edit to the agent's instructions, shipped by a legitimate maintainer
with no bad intent, and invisible to a name-keyed allowlist.

## What the measurements actually say

Three separate exercises, kept separate on purpose. Two of them produced the
result hoped for. One did not, and is reported anyway.

### 1. Conformance — does the relation behave as declared? (PASS)

Every mutation declares, in code, whether it should preserve the address under
each profile. The suite scores observed against declared. **10/12 rows
informative**: `json_whitespace` and `escape_form` re-serialize and re-parse, so
the canonicalizer is handed the same parsed structure twice and its columns would
read "stable" even with the canonicalizer removed. They still say something true
about byte hashing, so they are kept and labelled rather than deleted — and a row
that became uninformative later would fail the suite.

| mutation | kind | byte | strict | eval |
| --- | --- | --- | --- | --- |
| key_reorder | serialization | changed | **stable** | stable |
| json_whitespace | serialization | changed | **stable** | stable |
| escape_form | serialization | changed | **stable** | stable |
| unicode_nfd | serialization | changed | **stable** | stable |
| crlf_newlines | serialization | changed | **stable** | stable |
| int_to_float | serialization | changed | changed | **stable** |
| string_whitespace_pad | serialization | changed | changed | **stable** |
| text_edited | material | changed | changed | changed |
| homoglyph_substitution | material | changed | changed | changed |
| field_removed | material | changed | changed | changed |
| number_changed | material | changed | changed | changed |
| element_added | material | changed | changed | changed |

The two rows where the profiles disagree are the argument for declaring the
relation rather than assuming one. `1` and `1.0` are the same value written
twice when looking for a leaked eval item, and different contracts when pinning a
tool schema. No single canonical form serves both.

`homoglyph_substitution` is the row that matters for security: NFC is not
confusable folding, so a Cyrillic `а` for a Latin `a` changes the address under
both profiles, and the diff names it by codepoint:

    tools/classify_claim/description  [changed]
      differs by char 59: 'a' U+0061 LATIN SMALL LETTER A -> 'а' U+0430
      CYRILLIC SMALL LETTER A  [different script — invisible to a human reviewer]

### 2. Leakage — three kinds of evidence, scored separately (PASS)

20 held-out items, 32 candidate corpus items, 20 planted leaks with labelled
relations. Planted by us, so this is a controlled measurement, not a prevalence
claim.

| method | evidence | found | missed | false+ | recall |
| --- | --- | --- | --- | --- | --- |
| byte | deterministic | 4 | 16 | 0 | 20% |
| structural | deterministic | 16 | 4 | 0 | 80% |
| lexical | probabilistic | 17 | 3 | 0 | 85% |

Structural matching adds 12 detections over byte matching. The 4 it misses are
paraphrases, which is the boundary, not a bug:

    level 0  byte identity        H(bytes)                deterministic
    level 1  structural identity  H(canonical_eval(x))    deterministic
    level 2  lexical similarity   cos(x, y) >= tau        probabilistic

Identity is not similarity. Levels 0 and 1 answer "are these the same item" and
have no false positives by construction. Level 2 answers "are these plausibly
the same item" and has a threshold you have to defend, which is why the report
prints the whole sweep rather than one number:

| tau | found | false+ | precision |
| --- | --- | --- | --- |
| 0.50 | 20 | 16 | 56% |
| 0.60 | 20 | 1 | 95% |
| 0.70 | 18 | 0 | 100% |
| 0.80 | 17 | 0 | 100% |
| 0.90 | 14 | 0 | 100% |
| 0.95 | 8 | 0 | 100% |

**Read this honestly:** on this corpus the lexical detector at tau=0.60 beats
structural matching outright — 20/20 found, with one false positive (precision
95%), as the table above records. The case for
structural matching is not recall. It is that it needs no threshold, has no
false positives by construction, and gives the same answer on every machine
forever. That is a different kind of evidence, which is the whole point of
separating the levels. Level 2 here is a char n-gram TF-IDF cosine, a *lexical*
baseline, labelled as such everywhere; a sentence-embedding model would widen
the paraphrase class and is a one-function swap.

None of the three proves training exposure. All three measure corpus overlap.

### 3. Real data — the pre-registered null that fired (NEGATIVE RESULT)

10 published MCP server packages from npm, 79 versions installed and started,
`tools/list` captured over stdio from each, 63 consecutive version pairs
compared. 6 versions refused to start and are counted, not dropped.

The question was: how often does a published tool definition change byte-wise
while remaining structurally identical? Each such pair is a false alarm a
byte-pinning gate would have raised.

**Answer: zero, out of 63.** The positive control passes — the comparator does
detect a byte-only change when one is injected — so the null is real and not a
broken detector. Byte pinning is not measurably noisy at the published-version
boundary, and that argument for canonical addressing is dead on this evidence.

What the same data did show:

> **51 tool descriptions were rewritten while the tool name stayed the same**,
> a net +2,401 characters of model-facing instruction across 10 real servers.

| package | versions | tool | chars |
| --- | --- | --- | --- |
| @upstash/context7-mcp | 1.0.28 → 2.1.2 | resolve-library-id | 1214 → 2006 (+792) |
| @upstash/context7-mcp | 1.0.8 → 1.0.18 | resolve-library-id | 523 → 1133 (+610) |
| @mcp/server-filesystem | 2025.3.28 → 2025.7.29 | read_file | 263 → 85 (−178) |
| @mcp/server-filesystem | 2026.1.14 → 2026.8.31 | read_media_file | 114 → 234 (+120) |

`resolve-library-id` went from 523 to 2,006 characters across three releases,
under an unchanged name. `read_file`'s description became
`DEPRECATED: Use read_text_file instead`. A tool description is not
documentation — it is text placed in the model's context telling it when and how
to call the tool. Rewriting one edits the agent's instructions.

Approval keyed only on tool or server **names** cannot detect these definition
changes. Version-based controls *can* detect them — the version string changed by
construction, since these are consecutive releases — but only where versions are
pinned to an immutable release and re-approval is enforced on every bump. The gap
measured here is name-keyed approval, and version pinning without re-approval. It
is not a claim that version pinning is blind.

20 of 38 material changes kept the tool names identical, which is the shape a rug
pull takes and the case a name-based allowlist cannot see.

So the claim is **not** "canonical beats byte" — the data refuses that. It is
**"binding the whole configuration beats approving names"**, which the data
supports. Canonicalization is what stops that binding from false-alarming on
transport re-serialization, and its justification is the conformance suite, not a
prevalence claim.

Limitations, printed with every run: convenience sample of servers startable
without credentials; sampled versions, so intermediate releases are invisible;
`tools/list` only; a server whose tool list depends on environment may differ in
a configured deployment.

---

## What EvalSeal does not claim

The boundary is inside the signed receipt, not just in this README, because a
receipt that overclaims is worse than no receipt.

    DECLARED  ≠  EFFECTIVE  ≠  EXECUTED

EvalSeal operates entirely at **DECLARED**. It binds the configuration artifacts
an operator presents and recomputes their identity at runtime. It does not
observe the running process, so it cannot establish that the loaded prompt, the
served model or the live tool handlers correspond to those artifacts. A
`VERIFIED` result means *these are the artifacts that were evaluated*, and
nothing stronger.

- **Model identity** is a provider-supplied string. Weights, adapters,
  quantizations and tokenizers are not canonicalized. Where serving is dynamic —
  request-level routing, mixture-of-agents committees, models partitioned across
  peers by layer range — the effective artifact set may not be knowable to the
  agent at all, so an agent-side declaration cannot be effective-model
  provenance.
- **A signature** establishes that a holder of the signing key signed the
  declaration. That it was the named approver holds only against a trusted key
  set supplied out of band; without one, `VERIFIED` is integrity, never
  authority, and the demos generate their own key. It never establishes that the
  declaration is true.
- **A declared condition** may be consistent-but-unattested, unobserved, or
  contradicted by evidence the issuer already holds. The third is inadmissible,
  and `envelope.refuse_contradicted` is what refuses it — but read the scope
  exactly: it is **not** inside `issue()`. It is a call a harness makes about
  itself before issuing, over condition names it chose, against a table of
  network-absence spellings that is a table and not a general consistency check.
  `integration/run_agent.py` is the only caller. An issuer that does not call it
  is not stopped, and a spelling outside the table is not caught. The first state
  is the normal case and is not detectable here at all.
- **Leakage** is corpus overlap, not proof of training exposure.
- **The `es1` address scheme** is local to EvalSeal. No byte compatibility with
  any other content-addressing scheme is claimed or implied.

`tests/test_overclaim.py` makes this **claim confinement** testable rather than a
disclaimer. The suite fails if any field outside the scope block asserts
execution, and it pins the case where syntax is valid, the signature is valid,
the digest matches — and relationship truth is still not established. What is
enforced is the receipt's own vocabulary: nothing here can stop a human reading
`VERIFIED` off a screen and telling a room the agent ran. `KNOWN-ISSUES.md`
lists where the enforcement is thinner than this section reads.

---

## Layout

    evalseal/
      canonical.py     declared equivalence profiles (strict, eval)
      address.py       es1:<profile>:sha256:<hex>
      manifest.py      per-component addressing, configuration address
      diff.py          which component, which field, which codepoint
      evaluate.py      deterministic rule agent + eval harness
      leakage.py       three detectors, scored with false positives
      mutate.py        mutations, each declaring its own expectation
      conformance.py   declared vs observed, with a vacuity guard
      sign.py          ed25519 over canonical receipt bytes
      receipt.py       issue / verify, with the boundary in the payload
      bakeoff.py       six identity functions, false blocks vs false accepts
      materiality.py   declared per-field relations and exclusions
      benchmark.py     seven rows: six attacks and one refusal, declared first
      graph.py         delegation, per-node evidence, real published drift replay
      realdata.py      published-MCP-server measurement
      report.py        terminal rendering
    demo/              claims-review agent: prompt, procedure, tools, eval set
    realdata/
      harvest.py       installs and starts real MCP servers (use a container)
      tools/           captured tools/list per package@version
    FIELD-SHEET.md     the two customer questions, capture matrix, demo order
    docs/REUSE-LADDER.md  external SEC reuse measurement and what it changed
    tests/             174 tests, including claim-confinement, substitutability
                       and the projected-terminal budget
    out/               receipts, audit events, JSON results

`realdata/harvest.py` executes third-party code. Run it in a container.

## Tests

    python3 -m pytest tests -q        # 174 passed

The suite includes the project's own falsifiers. It fails if a declared
meaning-preserving transformation moves an address, if a declared material change
does not, if the diff disagrees with the address verdict, if structural matching
adds nothing over byte matching, if a conformance row is vacuous, or if the
receipt claims execution, if a benchmark row diverges from its declaration, if
delegated agents share a configuration identity, or if the replayed real drift
turns out to rename a tool rather than redefine one in place. It also fails if any
global relation becomes correct on every bake-off case — which would mean the
per-field materiality policy is unnecessary and should be deleted.
