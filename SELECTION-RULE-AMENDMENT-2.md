# Amendment 2 to the selection rule — 14 September 2026, recorded 24 September 2026

**What this amendment is.** A wording change to the disclosure section of `SELECTION-RULE.md`,
and nothing else. It alters no stratum, no criterion, no axis, no scoring level and no subject. It
is dated 14 September 2026 because that is the day the wording was written; it is recorded here on
24 September 2026 because that is the day the wording was moved out of the rule file, where it had
been written in place, and into this amendment, where Amendment 1 says corrections belong.

## What happened

- **28 August 2026.** `SELECTION-RULE.md` was committed (5,998 bytes, SHA-256
  `553cea7951c9dc8aa43f1809174d55f4b9b423e9bc77708f1373922f8f76aa37`) and anchored. The proof
  `SELECTION-RULE.md.ots` commits to exactly those bytes and asserts Bitcoin block 964462.
- **14 September 2026.** The rule file was edited in place: the section headed *"Two disclosures
  owed to the reader, recorded now rather than discovered later"* was rewritten as the section
  quoted below (5,824 bytes, SHA-256
  `0c1ff9e9ef33ff30172b81769cc52c1e4a1040c6d479e6b991c3761475b63a09`). The proof was not touched,
  so from that day the proof and the file disagreed. The control-audit records taken between 14
  and 24 September carry the edited file's digest as an audit input; the records taken after this
  amendment carry the anchored one.
- **24 September 2026.** A cold reader parsed the proof, found that it commits to a digest the
  shipped file did not have, and reported that the paper's statement that the rule "is left
  byte-identical" was false from the archive. The file was restored to the anchored bytes from
  the repository history (commit `26d336f`), the proof was re-parsed against the restored bytes
  and reports them as committed, and the 14 September wording is carried here.

## The wording of 14 September 2026, verbatim

> ## ⚠️ A disclosure owed to the reader, recorded now rather than discovered later
>
> ⚠️ **No subject is excluded to avoid an appearance.** Every candidate is scored by the same rule,
> from public artifacts, whatever the relationship between this laboratory and the publisher of a
> release — because **excluding a subject to avoid an appearance is itself a selection effect**, and a
> worse one, since it would silently remove the release most likely to be scrutinised.
>
> **Scoring is not a claim about model quality.** A release scoring 0 on twenty axes may be
> excellent. The instrument answers *"is this the artifact you say it is, and can anyone check"* —
> narrow, and prior to every other question.

## The anchored wording it replaced, verbatim from the anchored file

> ## ⚠️ Two disclosures owed to the reader, recorded now rather than discovered later
>
> **1 · An API-only subject is published by the organisation whose model assisted this work.**
> The instrument and this repository were drafted with AI assistance, and one candidate subject is a
> release by that assistant's publisher. The mitigation is not to drop it — **excluding a subject to
> avoid an appearance is itself a selection effect**, and a worse one, since it would silently remove
> the release most likely to be scrutinised. It is scored by the same rule as every other subject,
> from public artifacts, and this paragraph is the disclosure.
>
> **2 · Scoring is not a claim about model quality.** A release scoring 0 on twenty axes may be
> excellent. The instrument answers *"is this the artifact you say it is, and can anyone check"* —
> narrow, and prior to every other question.

## What the change is, and what it is not

- **Changed:** the first of the two numbered disclosures, which named the relationship between
  this work and one subject's publisher, became a general statement that no subject is excluded
  to avoid an appearance; the second lost its number and kept its text. The specific disclosure
  the anchored wording makes is still made, by the paper's own disclosure section, and it is
  covered by the anchored proof because the anchored bytes carry it.
- **Not changed:** the four strata and their definitions, the 22 axes, the scoring levels, the
  whole-stratum treatment of the fully-open stratum, the rule that a subject is not removed once
  selected, and the census date. The edit touched no line outside the disclosure section.

## Why the edit was wrong to make in place, and what stands

A pre-registration is worth reading because its bytes were fixed before the work; editing the file
afterwards, for any reason and however small the edit, removes that, and Amendment 1 says so in
its first line. This amendment exists because that rule was not followed for ten days. What stands
now: the anchored bytes are the bytes the archive ships; `build_paper.py` parses every
OpenTimestamps proof in this directory against the bytes of the file beside it, with a
standard-library reader and no network, and refuses to build when a proof commits to different
bytes. An edit of the kind made on 14 September now stops the build instead of shipping.

## Proof

The operator will stamp this amendment with OpenTimestamps as `SELECTION-RULE-AMENDMENT-2.md.ots`.
Until that proof is beside this file, the dates above rest on the repository history alone, and
the paper says so.
