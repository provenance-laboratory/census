# Amendment 1 to the selection rule — 29 August 2026

⛔ **`SELECTION-RULE.md` IS NOT EDITED AND WILL NEVER BE.** Its bytes are anchored to a Bitcoin
block; changing one character would break the proof and destroy the only thing that makes a
pre-registration worth reading. Corrections are appended as dated amendments, and this is the first.

## What was found

Round-1 internal review asked for the download ranking the open-weights criterion refers to, so
that a third party could re-derive the list. Retrieving it showed something worse than a missing
file.

**The pre-registered criterion does not produce the list that was scored.** The rule says:

> open-weights — the highest-download releases on the Hugging Face Hub as of the census date,
> one per publishing organisation, taken in rank order until the stratum is filled.

Taken literally, against the ranking deposited in `selection/`:

| scored subject | position by downloads |
|---|---|
| `meta-llama/Llama-3.1-8B` | rank 137 of 1,000 |
| `Qwen/Qwen2.5-7B` | rank 156 of 1,000 |
| `google/gemma-2-9b` | rank 719 of 1,000 |
| `mistralai/Mistral-7B-v0.3` | **not in the top 1,000 at all** |

"Rank order until the stratum is filled" would have selected the first four organisations in the
list. Those are `Qwen/Qwen3-0.6B`, `trl-internal-testing/tiny-Qwen2ForCausalLM-2.5`,
`openai-community/gpt2`, and `unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF` — a 0.6B model, a unit-test
fixture, a 2019 release already scored in another stratum, and a third-party quantisation. Of the
top 200, 59 are quantised re-uploads, 52 are instruction-tuned variants, and 12 are test fixtures.

⇒ **The four subjects were chosen by judgement, not by the registered mechanism.** The operative
criteria — first-party publisher, base rather than instruction-tuned, native precision, 7–14B, one
per organisation — were real and consistently applied, but they were never written down, and a rule
that is not written down is not a pre-registration.

## A second defect, which was there from the start

Hugging Face reports downloads over a **rolling 30-day window**. No historical snapshot is
published. So the phrase "as of the census date" describes a quantity that **cannot be recovered by
anyone**, including us, once the date has passed. Even had the rule been followed exactly, it was
never re-derivable, and calling it so was wrong.

## What is claimed now

The honest position, and the one the paper states:

- **Pre-registered and binding**: the 22 axes, the scoring levels, the four strata and their
  definitions, the whole-stratum treatment of fully-open, and the rule that a subject is never
  removed. These were fixed before any cell was scored and they did constrain the work.
- **NOT pre-registered**: which four open-weights releases were scored. That was a judgement made
  after the fact and it carries none of the pre-registration's force.

⚠️ **A reconstructed rule is not a pre-registered one.** The criteria above are recorded here so
the choice is at least inspectable, but writing them down today cannot make them binding
yesterday, and this amendment does not pretend otherwise.

## Which way the error cuts

Stated as an argument, because it is one — no measurement supports it:

The releases the literal rule would have selected are quantisations, chat variants and test
fixtures published by third parties. Such releases document *less* provenance than first-party base
models: no training code, no corpus statement, frequently no paper. Scoring them would very likely
have **lowered** the open-weights stratum and **widened** the gap this paper reports. The judgement
call therefore worked against the headline rather than toward it.

⚠️ That is a reason to think the finding is not an artifact of selection. It is not evidence that
it is not, and the difference matters. Settling it requires scoring those releases, which this
census has not done.

## Deposited with this amendment

| file | what it is |
|---|---|
| `selection/hf-downloads-rank.json` | top 200 text-generation models by downloads, retrieved 29 Aug 2026 |
| `selection/hf-downloads-frame.json` | the same, top 1,000 — the frame the table above is computed against |
| `selection/check_selection.py` | recomputes the table; fails if the ranks change what this says |

Both snapshots are the ranking **as retrieved on 29 August 2026**, which is after scoring. They
cannot show what the ranking was on the census date. They are deposited so that this amendment's
own claims are checkable, not to repair the original defect.
