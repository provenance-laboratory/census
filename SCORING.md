# What the levels mean — rewritten after round-1 review

⛔ **The round-1 reviewers were right about the deepest defect, and it was not any single cell.**
The instrument's wording claimed one thing and its checks established another.

> *"Pythia's seed scores 2 because a README states that seed 1234 was used. That verifies that the
> README contains the statement; it does not independently establish that the released weights were
> produced using that seed."*

That is correct, and it applied broadly: to training code, to hyperparameters, to data order. The
paper spoke of *provenance established*; the checks established *material published*.

There were two ways out and only one of them is honest.

**The strong reading** — score 2 only when the causal provenance of the released weights is
independently established — would require retraining every subject. Nothing in the field would
score above 1, the instrument would stop discriminating, and it would be measuring the state of a
different world.

**The weak reading**, adopted here: the instrument measures **whether checkable provenance material
was published, and whether it survives being checked.** That is narrower than the old wording
implied and it is what the checks actually do.

## The four levels

```
2  VERIFIED   an artifact exists; we retrieved it AT A PINNED REVISION; and a REGISTERED
              MECHANICAL CHECK over its content succeeded. The check, its assertion and its
              observed result are recorded in the cell
1  ASSERTED   the property is stated in a document we retrieved, and no artifact exists whose
              content a third party could check against the claim
0  ABSENT     neither stated nor available, within a search whose bound is written in the cell
–  N/A        the property cannot exist for this release type, justified per cell
```

### Where the line falls, stated precisely

A first draft of this file said *"a README stating `seed: 1234` is a 1, however specific."* That
was wrong, and inconsistent with the axes themselves: axis 8 asks **"are the random seeds
published?"** — a question about publication, which retrieving the document does settle.

The line is not *document versus artifact*. It is **what the axis asks**:

```
PUBLICATION axes    "is X published / specified / released?"   (1, 6, 8, 11, 12, 13, 18)
                    a mechanical check over retrieved content settles these -> 2 is available
COMPLETENESS axes   "are ALL of X given?"  "can Y be DECIDED?"  (5, 7, 19)
                    a retrieved document cannot establish a universal -> these cap at 1
SEARCH axes         "has anyone reported Z?"                    (16, 17)
                    absence is established only within a stated bound -> 0 means not-found
                    a report that IS found caps at 1 -- see below
```

⚠️ **And the caveat that belongs in the paper rather than in a score:** a publication axis scored 2
records that checkable material *exists and survived being checked*. It does **not** record that
the material is true of the released weights. Nobody can establish that without retraining, which
is the second paper's subject. The instrument measures what was published, and says so.

## The positive case on a search axis, which this rule did not define

⛔ **This document said what a `0` means on axes 16 and 17 and never said what a hit scores.**
Nothing had ever been found, so the branch was never taken — a rule exercised on one side only.
Round-1 review's demand for a real negative-search protocol produced the first hit, and the gap
appeared the moment it did.

**A found report scores 1, never 2.** The reason is the same one that caps the completeness axes:

- What a mechanical check can settle is that **a document exists and says so** — `grep_retrieved`
  over bytes fetched at a pinned URL. That is real, and it is not what the axis asks.
- The axis asks whether **an independent party reported a reproduction**, and scoring it 2 would
  claim the census had checked the *reproduction*, which nobody can do without retraining. Awarding
  the top level for a successful grep would make VERIFIED mean "the sentence is present", which is
  precisely the ASSERTED/VERIFIED collapse this instrument exists to prevent.

⇒ So a search axis has three states and only three: **0** not found within a written bound, **1** a
third-party report found and retrievable, and — until somebody retrains a model and the census can
check the result — **2 is unreachable by construction, and is recorded as such rather than left to
look like an absence of effort.**

⚠️ The bar is the axis's own wording. Axis 17 asks for a report *stating what matched and within
what tolerance*. A replication study that re-runs a pretraining recipe while deliberately varying
it, and reports improving on the original, is more than nothing and less than that — which is why
the one hit in this census is a 1 with the shortfall written into the cell.

## What makes a check "registered"

Round-1 review demonstrated the hole directly: the validator required `check` to be a *non-empty
string*, so `check = "read a document"` passed on every cell. A free-text field is not a control.

`check` is now an object, and `method` must name an implemented probe:

```json
"check": {
  "method": "hf_probe.weight_object",
  "asserts": "range request at a pinned revision returns non-pointer bytes",
  "observed": "HTTP 206, 2048 B, is_pointer=false, revision bb1e3e71"
}
```

The registry lives in `axes.py` as `CHECK_METHODS`. A method not in it is a validation failure, so
a cell cannot be promoted to 2 by describing a check more impressively.

⚠️ **This does not make lying impossible.** An author who wants a 2 can still record a method they
did not run. What it does is make the claim *specific enough to be contradicted*: the method names
a program, the assertion names its postcondition, and the observation names what came back. A
reader who reruns the method and sees something else has caught it.

## What a `2` does NOT mean

- **Not** that the property is true of the released weights.
- **Not** that the publisher is truthful.
- **Not** that the artifact is complete — completeness is per-axis. Axis 13 requires a digest for
  *every* shard at a pinned revision, because a digest for one shard of seventy-two is not a digest
  of the weights, and round-1 review found the census doing exactly that.

## Consequences recorded before rescoring

Written down first so the rescore cannot be tuned:

1. Cells on COMPLETENESS axes (5, 7, 19) drop from 2 to 1: a retrieved document cannot
   establish a universal such as "ALL hyperparameters" or "membership is decidable".
2. Axis 12 requires **retrieved weight-object bytes** at a pinned revision, verified not to be a
   Git-LFS pointer. A pointer is what the LFS specification puts in the repository *instead of* the
   blob; retrieving one is not retrieving weights.
3. Axis 13 requires a publisher-committed digest for **every** weight shard at a pinned revision.
4. Every weight cell cites a **pinned revision**, so the evidence cannot drift and a reader fetches
   the bytes we fetched.
5. `gpt-2-1.5b` is rebound to `openai-community/gpt2-xl` — 1,607,942,848 parameters. The prior
   evidence pointed at `openai-community/gpt2`, which is 137,022,720. **Every gate passed on the
   wrong model**, because every gate checked shape and none checked identity.

⇒ Identity is now checked: the probe records `reported_params`, and a subject's cells are bound to
a repository whose parameter count matches the size in its name.
