"""The 22 axes, as data.

An axis qualifies ONLY if a third party could, in principle, decide it from published artifacts.
"Is the lab honest" is not an axis. "Is there a manifest whose digest matches the shipped corpus"
is.

Each axis carries the question it asks and, separately, **what would satisfy it at CHECKED** --
because the difference between 2 and 1 is the whole instrument, and leaving that to a scorer's
judgement is how a rubric becomes an opinion. `satisfied_by` is the sentence a reviewer holds the
cell against.

`na_permitted` marks the axes where "not applicable" can ever be honest -- every release was
made from *something*, so axis 1 never can be.

⛔ SETTLED 2026-08-28, WHILE SCORING THE FIRST API-ONLY RELEASE: an absence of published
weights makes axes 13, 14 and 15 score ZERO, not N/A.
The tempting reading is that a release with no public weights has no weights to content-address,
sign or timestamp, so those axes do not apply. That reading is wrong here, and dangerously so:
this instrument measures WHAT A THIRD PARTY CAN CHECK, and a third party can check nothing about
weights that were never published. Marking them N/A would remove them from the DENOMINATOR and
so RAISE the score of a release for publishing less -- the precise hazard the N/A policing
exists to prevent. N/A is for a property that cannot exist, never for one that was not provided.

The flags below therefore stay permissive so that a genuine future case can be argued per cell,
with its reason; they are not a licence to withdraw Group 3 for an API-only release. ⚠️ N/A is the escape hatch that will quietly do all the work if it is not policed --
see NOT-A-RANKING.md and the referee's re-coding test.
"""

GROUPS = {
    1: "Corpus — what the model was made from",
    2: "Procedure — how the artifact was produced",
    3: "Artifact — the thing shipped",
    4: "Verification — has anyone actually checked",
    5: "Post-training — where behaviour is shaped, and visibility is lowest",
}

# id, group, short name, the question, what a CHECKED (2) requires, may this axis ever be N/A
AXES = [
    (1, 1, "corpus enumerated",
     "Does a list of training sources exist at all?",
     "A published list a third party can read, naming sources rather than categories.",
     False),
    (2, 1, "corpus content-addressed",
     "Are per-item or aggregate digests published for the corpus?",
     "Digests that a third party can recompute over obtained bytes and compare.",
     False),
    (3, 1, "corpus committed BEFORE",
     "Is the corpus digest timestamped prior to training?",
     "An OpenTimestamps proof, or a dated signed publication, that predates the training run.",
     False),
    (4, 1, "corpus obtainable",
     "Can a third party actually acquire the same bytes?",
     "A retrieval path that yields bytes matching the published digests.",
     False),
    (5, 1, "membership decidable",
     "For an arbitrary document, can in-or-out be demonstrated?",
     "A published mechanism that answers membership without trusting an assertion.",
     False),

    (6, 2, "training code released",
     "Is the code that produced the weights published?",
     "Source sufficient to run the described procedure, not a description of it.",
     False),
    (7, 2, "hyperparameters fully specified",
     "Are all hyperparameters given, not a subset?",
     "Every value needed to rerun, with no 'and standard settings'.",
     False),
    (8, 2, "seeds published",
     "Are the random seeds published?",
     "The actual seed values used for the released run.",
     False),
    (9, 2, "determinism settings specified",
     "Are kernel flags, TF32/cuDNN modes and reduction order stated?",
     "The settings that decide whether a rerun can be bit-identical at all.",
     False),
    (10, 2, "environment pinned",
     "Is the software environment pinned exactly?",
     "A container digest, or exact library versions, not a requirements range.",
     False),
    (11, 2, "data order reproducible",
     "Are sharding and shuffle derivable from a published seed?",
     "Enough to reconstruct the exact sequence of examples.",
     False),

    (12, 3, "weights released",
     "Are the weights published?",
     "Retrievable weights, not gated access granted case by case.",
     True),
    (13, 3, "weights content-addressed",
     "Does the publisher publish a digest of the weights?",
     "A digest published BY THE PUBLISHER, not computed by a mirror.",
     True),
    (14, 3, "weights signed",
     "Are the weights signed by an identifiable key?",
     "A signature verifiable against a key the publisher has previously bound to itself.",
     True),
    (15, 3, "weights timestamped",
     "Is the weights digest timestamped?",
     "A timestamp a third party can verify without trusting the publisher's clock.",
     True),

    (16, 4, "bit-identical reproduction reported",
     "Has an independent party reported a bit-identical reproduction?",
     "A third-party report with artifacts, not the publisher's own claim.",
     False),
    (17, 4, "approximate reproduction reported",
     "Has an independent party reported an approximate reproduction?",
     "A third-party report stating what matched and within what tolerance.",
     False),
    (18, 4, "eval harness released and versioned",
     "Is the evaluation harness published at a pinned version?",
     "A harness a third party can run, at the version the reported numbers came from.",
     False),
    (19, 4, "eval/train disjointness checkable",
     "Can contamination be TESTED rather than merely denied?",
     "A mechanism that lets a third party check overlap, not a statement that there is none.",
     False),

    (20, 5, "fine-tuning data disclosed",
     "Is the instruction / fine-tuning data disclosed?",
     "The data itself, or digests plus a retrieval path.",
     True),
    (21, 5, "preference or reward data disclosed",
     "Is the preference or reward data disclosed?",
     "The data itself, or digests plus a retrieval path.",
     True),
    (22, 5, "safety-training procedure disclosed",
     "Is the safety-training procedure disclosed?",
     "A procedure specific enough to be reproduced or contested.",
     True),
]

SCORES = {
    2: ("CHECKED", "an artifact exists, was retrieved BY US, and the check is scripted"),
    1: ("CLAIMED", "asserted in a document, with no artifact that would let anyone verify it"),
    0: ("ABSENT", "neither asserted nor available"),
    None: ("N/A", "the axis cannot apply to this release type -- justified per cell, never in bulk"),
}

BY_ID = {a[0]: a for a in AXES}
NA_PERMITTED = {a[0] for a in AXES if a[5]}

assert len(AXES) == 22, "the instrument is defined as 22 axes"
assert {a[0] for a in AXES} == set(range(1, 23)), "axis ids must be 1..22 with no gaps"
