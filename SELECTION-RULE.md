# The selection rule — written and timestamped BEFORE any cell was scored

⛔ **This document exists to be falsifiable.** The obvious objection to any census is that the
subjects were chosen to produce the result. The only answer that is worth anything is a selection
rule fixed *in advance* and anchored to a time nobody controls — so this file is committed and
OpenTimestamped **before** `cells.json` contains a single score, and the anchor is a Bitcoin block.

If a subject is added later, it is recorded in "Late additions" with its reason and its date. A
subject is never removed.

## What a subject is

**A release, never an organisation.** `pythia-12b` is a subject; the lab that published it is not.
A lab may publish one exemplary release and one opaque one, and an organisation-level score erases
exactly the information worth having — see [`NOT-A-RANKING.md`](NOT-A-RANKING.md).

A *release* means a named, versioned artifact with a public announcement. Where a family ships many
sizes, **one size is scored and named explicitly**, because provenance artifacts are usually
published per family, and scoring five sizes would weight that family five times.

## The four strata, fixed in advance

Chosen because they are the ways a release can differ in *what it publishes*, which is what the
instrument measures — not by expected score.

| stratum | definition | why it is here |
|---|---|---|
| **fully-open** | publishes both a named corpus **and** training code | the instrument's **positive control** |
| **open-weights** | weights retrievable, corpus not published as obtainable bytes | the large majority of "open" releases |
| **API-only** | no weights published in any form | most axes resolve to 0 or N/A, and that is a finding |
| **historical control** | first published before 2020 | tests whether the standard was ever achievable |

⇒ **At least one release must be expected to score near the top.** A rubric on which everything
fails is indistinguishable from a rubric that is simply too strict, and a referee will say so. If
the fully-open stratum does not score materially above the others, **that is a finding about the
instrument**, and it is reported as one rather than repaired.

## The mechanical criterion, per stratum

Applied on a stated date, so a third party can rerun the selection and get the same list:

```
fully-open           every release satisfying the definition that (a) has a paper or technical
                     report, and (b) names its corpus as a retrievable dataset. This stratum is
                     small; it is taken WHOLE rather than sampled, so there is nothing to choose
open-weights         the highest-download releases on the Hugging Face Hub as of the census date,
                     one per publishing organisation, taken in rank order until the stratum is
                     filled. Download rank is public and re-derivable; it is not a quality signal
                     and is not used as one
API-only             frontier text models with a published model or system card, one per
                     publishing organisation
historical control   pre-2020 releases whose weights were published at release time
```

⚠️ **Download rank is a selection device only.** It says a release is widely used, which is why its
provenance matters; it says nothing about the release and enters no score.

## The provisional list

Fixed here before scoring. Sizes are named because the instrument scores one size per family.

```
fully-open            pythia-12b · olmo-2-13b · bloom-176b
open-weights          llama-3.1-8b · mistral-7b-v0.3 · qwen2.5-7b · gemma-2-9b
api-only              gpt-4o · claude-3.5-sonnet · gemini-1.5-pro
historical control    gpt-2-1.5b (2019) · bert-base-uncased (2018)
```

⚠️ **Names here are identifiers, not yet subjects.** A release enters `cells.json` only when its
artifacts have been retrieved and hashed. If a release cannot be scored — because nothing about it
is retrievable — **it is entered with zeros and a note, never dropped.** Dropping it would convert
an unmeasurable release into an absent one, and those are different findings.

## What this census declines to do

- **No adjectives about publishers.** Anywhere. Every cell is a fact about a document, with a
  digest, retrievable by the reader.
- **Absence of a checkable artifact is not evidence of bad faith.** It is, overwhelmingly, evidence
  that nobody asked. Most of these axes were not standard practice when most of these releases were
  made.
- **Copyright status of corpora is out of scope**, deliberately. It is a different argument and it
  would swallow this one.
- **The scored rows go to no one for comment before publication.** That converts a measurement into
  a negotiation. Publish, then correct on evidence.

## ⚠️ Two disclosures owed to the reader, recorded now rather than discovered later

**1 · An API-only subject is published by the organisation whose model assisted this work.**
The instrument and this repository were drafted with AI assistance, and one candidate subject is a
release by that assistant's publisher. The mitigation is not to drop it — **excluding a subject to
avoid an appearance is itself a selection effect**, and a worse one, since it would silently remove
the release most likely to be scrutinised. It is scored by the same rule as every other subject,
from public artifacts, and this paragraph is the disclosure.

**2 · Scoring is not a claim about model quality.** A release scoring 0 on twenty axes may be
excellent. The instrument answers *"is this the artifact you say it is, and can anyone check"* —
narrow, and prior to every other question.

## Late additions

*(none yet — any entry here carries its reason and its date)*

---

**Anchored:** this file's digest is OpenTimestamped in the commit that introduced it, before
`cells.json` held any score. `git log --follow SELECTION-RULE.md` and the accompanying `.ots` are
the record.
