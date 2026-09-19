# The reuse ladder (external measurement)

**Not our measurement.** This records a separate harness — `f4_sec_edgar_reuse.py`
— run over a frozen, accession-pinned SEC EDGAR corpus (Apple `CIK0000320193`,
Tesla `CIK0001318605`). It is summarised here because it independently measures
the thing EvalSeal's dependency scoping is for, and because it changed the design:
the `corpus` component used to be addressed over every document present, which
false-blocks on additions nothing ever read.

## What it measures

Five tiers of "may this prior answer be reused for this request?", scored against
an external outcome oracle (`final_output_equality@request_precision`):

| tier | key |
| --- | --- |
| L0 Exact | the request surface text |
| L1 Structural | normalised request fields |
| L2 Semantic | resolved ids rather than labels |
| L3 Canonical operation | the operation, with corpus state dropped |
| L4 Certified substitution | the operation **plus the resolved dependency hash** |

Pairs are classified by what differs: `A_surface`, `B_serialization`,
`C_irrelevant_dependency`, `D_relevant_dependency`, `E_output_contract`,
`F_policy`, `G_different_task`, `H_different_customer`.

## Results, four runs on the same frozen corpus

| run | D pairs | precision | state on surface | L3 | L4 |
| --- | --- | --- | --- | --- | --- |
| ref32 | 4 | 2 | yes | 14v / 4f | 14v / 0f / 0m |
| d11 | 11 | 2 | yes | 15v / 10f | 14v / 0f / 1m |
| d11_p4 | 11 | 4 | yes | 14v / 11f | 14v / 0f / 0m |
| d11_p4_offsurface | 11 | 4 | **no** | 14v / 11f | 14v / 0f / 0m |

`v` valid reuse, `f` false reuse, `m` missed reuse.

**The headline, off-surface:**

> On identical frozen EDGAR data, request-text matching recovers 6 valid reuses
> and **19 invalid** ones; certified substitution recovers 14 valid and **0**
> invalid. Both find the same state-change reuse opportunities — one by not
> looking, the other by binding to resolved evidence.

Three things that make it more than a table:

1. **L4 dominates L3 on identical pairs** — a paired comparison on the same pairs,
   not a rate estimated from different samples. L3's precision degrades as `D`
   expands (0.7778 → 0.6000 → 0.5600); L4 stays at 1.0 across all four reported
   runs. The paired claim is what the evidence supports; a general claim about
   resolved-dependency binding is not.
2. **A predicted collision was reproduced.** In `d11`, a Tesla `share_density`
   pair produced different underlying computations that both rounded to `6.44` at
   precision 2, so the equality oracle counted it reusable while L4 refused. The
   prediction was that raising request precision would dissolve it. At precision
   4 it did: `D` goes from 1 oracle-valid pair to 0. That turns an anomaly into a
   demonstrated mechanism.
3. **Hiding state changes only L0 and L1.** L2 through L4 are invariant, which is
   the control that makes the off-surface result credible.

## The caveat, stated by the note itself

> Zero unsafe certified reuse was observed on this frozen Apple/Tesla corpus, but
> relevant-dependency coverage currently spans only **two** underlying filing
> transitions.

The eleven `D` pairs in `d11` are eleven metrics across those two events, not
eleven independent amendment scenarios. The data supports *mechanism* and *paired
comparison*; it does not yet support a general safety rate. The stated next step
is two more issuers with messy amendment histories, rerunning the same harness
unchanged — testing the thinnest part of the evidence rather than elaborating
what is already shown.

## What EvalSeal took from it

The `C_irrelevant_dependency` / `D_relevant_dependency` split is the design input.
EvalSeal originally addressed the whole corpus, which means:

- `C` (a document nothing read is added) → **blocked**. A false block: the answer
  could not have changed.
- `D` (a document that was read is changed) → blocked. Correct.

Binding nothing would invert both errors. Binding the *resolved* dependency set —
the documents the evaluation actually consulted — gets both right, which is
benchmark rows 4 and 5, and is what `--corpus-scope resolved` now does by default.
The scope is declared in the receipt's `materiality` block, because it changes
what "the same configuration" means and must not be inferred.

## One tension to keep straight

This note's L0 tier false-reuses on almost every decision it makes. EvalSeal's
bake-off says `raw_bytes` never false-*accepts*. Both are true and they are not
the same claim: L0 keys on the **request surface text**, EvalSeal's `raw_bytes`
keys on the **bytes of the configuration**. Surface text omits resolved state;
configuration bytes do not. Do not state both results in the same breath without
that distinction — it is the first thing a careful listener will push on.
