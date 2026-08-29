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
     "A retrieval path that yields the corpus bytes, verified by retrieving some of them. "
     "It does NOT require a published digest -- that is axis 2, which is absent for every "
     "release measured, so requiring it here made this axis unsatisfiable by construction.",
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
     "Weight-object BYTES retrieved at a pinned revision and verified not to be a Git-LFS "
     "pointer. A pointer is what LFS commits INSTEAD of the blob; retrieving one is not "
     "retrieving weights. Gated access granted case by case does not satisfy this.",
     True),
    (13, 3, "weights content-addressed",
     "Does the publisher publish a digest of the weights?",
     "A publisher-committed digest for EVERY weight shard at a pinned revision. A digest for "
     "one shard of seventy-two is not a digest of the weights. Not computed by a mirror.",
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
    2: ("VERIFIED", "an artifact exists, was retrieved AT A PINNED REVISION, and a REGISTERED "
                    "mechanical check over its content succeeded"),
    1: ("ASSERTED", "stated in a document we retrieved, with no artifact whose content a third "
                    "party could check against the claim"),
    0: ("ABSENT", "neither stated nor available, within a search whose bound is in the cell"),
    None: ("N/A", "the property cannot exist for this release type -- justified per cell"),
}

# ⛔ THE REGISTRY THAT CLOSES THE FREE-TEXT HOLE.
# Round-1 review passed every score-2 cell with check="read a document" and the validator
# reported no defect, because it required only a NON-EMPTY STRING. A free-text field is not a
# control. `check.method` must now name something implemented here, so a cell cannot be promoted
# to VERIFIED by describing a check more impressively than it was performed.
#
# ⚠️ This does not make lying impossible. It makes the claim specific enough to be CONTRADICTED:
# the method names a program, `asserts` names its postcondition, `observed` names what came back,
# and a reader who reruns the method and sees something else has caught it.
CHECK_METHODS = {
    "hf_probe.weight_object":   "range-request a weight shard at a pinned revision and verify the "
                                "bytes returned are not a Git-LFS pointer",
    "hf_probe.all_shard_digests": "enumerate every weight shard at a pinned revision and collect a "
                                  "publisher-committed digest for each",
    "http_range":               "range-request a URL and record status, length and first bytes",
    "http_status":              "request a URL and record the status code",
    "api_field":                "query a documented API and read a named field from the response",
    "grep_retrieved":           "search retrieved bytes for a pattern and record the match",
    "count_in_retrieved":       "count occurrences of a pattern in retrieved bytes",
    "hash_compare":             "recompute a digest over retrieved bytes and compare to a published one",
}

# ⚠️ READING A RETRIEVED DOCUMENT IS NOT A METHOD HERE, DELIBERATELY.
# `grep_retrieved` records that a document CONTAINS a statement -- which is evidence that the
# statement was published, not that the statement is true of the weights. An axis whose property
# can only be established by reading prose therefore tops out at ASSERTED, and that is the
# correction round-1 review forced. See SCORING.md.

BY_ID = {a[0]: a for a in AXES}
NA_PERMITTED = {a[0] for a in AXES if a[5]}

assert len(AXES) == 22, "the instrument is defined as 22 axes"
assert {a[0] for a in AXES} == set(range(1, 23)), "axis ids must be 1..22 with no gaps"
