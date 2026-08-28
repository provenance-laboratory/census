# ⛔ This is not a ranking, and the sentence travels with the numbers

`mp-metric` measures **how much of a model release a third party can check.** It does not measure
how good a model is, how safe it is, how open its publisher is, or whether anyone behaved well.

## What a score is, and what it is not

A score is a fraction of a **stated standard** — the 22 axes in `axes.py`, each of which a third
party could in principle decide from published artifacts. It is *reference-relative*: it says how
far a release sits from that standard, in the way `obl-metric` says how far a chain sits from the
January 2009 consensus rules.

```
IT SAYS          this release publishes artifacts sufficient to check N of 22 properties
IT DOES NOT SAY  this release is better · this lab is more honest · this model is safer
```

⚠️ **A low score is not an accusation.** Most of these axes were not standard practice when most
of these releases were made. An instrument that reads as a league table will be answered as one,
and the answer will be about the table rather than the artifacts.

## Subjects are releases, never organisations

`llama-3.1-8B` is a subject. A company is not. A lab may publish one exemplary release and one
opaque one, and an organisation-level score erases exactly that — which is the information worth
having. This is the same discipline as the rest of this workshop: **cite the artifact, never
characterise the actor.**

## The N/A column is load-bearing, and it is a hazard

`N/A` removes an axis from the **denominator**. So a release can hold its as-coded score while
disclosing *less*, provided the axes it withdraws are ones it can call inapplicable. That is
arithmetic, not suspicion — `stress_test.py` demonstrates it:

```
all 22 disclosed at CLAIMED     as-coded 0.500
7 axes withdrawn as N/A         as-coded 0.500      [N/A→0 0.341, N/A→2 0.659]
```

⛔ **Therefore no as-coded figure is reportable alone.** `score()` returns the triple and there is
deliberately no function that returns the first value by itself; `emit_tables()` writes all three
columns. Where the `N/A→0`–`N/A→2` spread is wide, the middle number is carrying weight it has not
earned, and the paper must say so at that cell rather than in a footnote.

## Every non-zero cell is backed by bytes we retrieved

Not by a link, and not by a claim on a page. **url + retrieval date + sha256 of the retrieved
bytes.** A cell with no artifact record is not a `1`; it is a bug, and `validate()` refuses to
score the whole census until it is fixed.

⛔ **An HTTP 200 is not an artifact.** Model cards live behind consent gates and bot challenges
that answer 200 with a body containing nothing of what was asked for. `fetch_artifact.py` hashes
the payload and refuses anything that reads as a wall — deliberately over-refusing, because a
false refusal costs one manual look and a false accept silently corrupts a cell that will then be
cited.

⚠️ **Releases change.** A model card edited after scoring silently invalidates a cell. Every
evidence record is re-fetched and re-hashed before publication, and a digest that moved is a
**finding**, not a maintenance chore.

## What the instrument declines to claim

- That a `2` means the property *holds* — it means the property is **checkable**, and that we ran
  the check named in the cell.
- That the 22 axes are the right 22. They are a stated standard, published so it can be argued
  with. Disagreement about an axis is a contribution, not an objection.
- That a bit-identical reproduction is achievable for large training runs at all. Whether the
  standard is reachable is Paper B's question, not this one's — which is why the census includes
  a release expected to score near the top. **A rubric on which everything fails is
  indistinguishable from a rubric that is simply too strict.**
