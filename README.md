# census — mp-metric

**What a model release lets a third party CHECK, as opposed to being TOLD.**

An instrument, and the census it produces. Twenty-two axes across five groups, each scored
`2 CHECKED · 1 CLAIMED · 0 ABSENT · – N/A`, every non-zero cell backed by bytes we actually
retrieved and hashed.

> ⛔ **Not a ranking.** It measures how much of a release is checkable — not how good, how safe,
> or how honest anyone is. The sentence travels with the numbers: [`NOT-A-RANKING.md`](NOT-A-RANKING.md).

## Why it looks like `obl-metric`

Because it is the same instrument pointed at a different subject. `obl-metric` measures how far a
chain has diverged from the January 2009 Bitcoin consensus rules; this measures how far a model
release sits from a stated provenance standard. Both are **reference-relative and
source-anchored**, and neither ranks.

The mechanism does not transfer — you cannot content-address a training run the way you can
content-address a constant. **The goal does:** *you need not take my word.*

`obl-metric` — replication archive: [`10.5281/zenodo.21964447`](https://doi.org/10.5281/zenodo.21964447)

## Two structural decisions, taken before the first subject

**1 · The engine emits the tables; the paper includes them.**
`obl-metric`'s round-2 referees returned NO-GO with six regressions in a single round, and the root
cause was not carelessness — the manuscript hand-maintained numbers the engine computed, edited by
string surgery every time a cell moved. Here `emit_tables()` writes `tables/`, and nothing in
`tables/` is ever typed into prose.

**2 · The headline cannot be emitted without its sensitivity band.**
`N/A` leaves the denominator, so withdrawing an axis does not lower the as-coded score.
`score()` returns `(as_coded, na_as_0, na_as_2)` and there is deliberately no function returning
the first alone — because a number that *can* be quoted alone eventually is.

## Files

```
axes.py            the 22 axes as data: the question, and what a CHECKED requires
cells.json         the ledger, one record per (subject, axis) -- EMPTY until artifacts exist
mp_metric.py       validate -> score -> emit tables.  Refuses to score a defective census
fetch_artifact.py  retrieve, hash the payload, and refuse a wall that answers 200
stress_test.py     the hostile referee: every case attacks validate()
tables/            EMITTED. Never hand-edited
NOT-A-RANKING.md   the sentence that must accompany any number from here
```

## Run

```bash
python stress_test.py     # 15 attacks; exit 0 means every one was caught
python mp_metric.py       # validate, score, emit
python fetch_artifact.py <url>    # cell-ready evidence, or a refusal with its reason
```

`validate()` fails **closed**. A missing `(subject, axis)` pair is a defect, not a zero — *"nobody
looked"* and *"we looked and found nothing"* are different claims, and a census that writes them
identically is an opinion.

## Scope

This repository is **code and measurement**. Papers are written elsewhere and published as
preprints with a DOI; this holds the instrument, the ledger and the emitted tables that any such
paper includes. The same division as
[`original-bitcoin-laboratory/genesis`](https://github.com/original-bitcoin-laboratory/genesis),
which carries `paper-artifacts/obl-metric/` while the manuscript lives outside it.

The ledger ships **empty on purpose**. Seeding it with plausible-looking scores would be precisely
the defect the instrument exists to detect.

## Licence

MIT. Copyright (c) 2026 Parth Mauria Saxena.
