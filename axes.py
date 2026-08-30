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
    "hf_probe.corpus_item_digests": "every file in a pinned dataset subtree carries a Git-LFS sha256 oid",
    "hf_probe.all_shard_digests": "enumerate every weight shard at a pinned revision and collect a "
                                  "publisher-committed digest for each",
    "http_range":               "range-request a URL and record status, length and first bytes",
    "http_status":              "request a URL and record the status code",
    "api_field":                "query a documented API and read a named field from the response",
    "grep_retrieved":           "search retrieved bytes for a pattern and record the match",
    "count_in_retrieved":       "count occurrences of a pattern in retrieved bytes",
    "hash_compare":             "recompute a digest over retrieved bytes and compare to a published one",
    "repo_tree_probe":          "enumerate a source repository's tree at a pinned commit and "
                                "require the named training entrypoints to exist as files, with a "
                                "dependency manifest -- the artifact, not a document about it",
    "hf_probe.signed_commit":   "read the git commit object at a pinned revision and establish "
                                "whether it is signed, by which key, and whether that key is the "
                                "publisher's or the hosting platform's",
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


# ── What it would COST a publisher to satisfy an axis nobody satisfies ───────────────────────
# Section 8.1 of the paper asks what the universally-absent axes have in common. An earlier draft
# answered "they are the machine-checkable ones", which was FALSE -- several satisfied axes are
# verified by range request and digest comparison, and two absent ones are documentary. The real
# common property is what a publisher would have to DO, so it is recorded per axis, here, next to
# the axis definitions rather than in prose the paper maintains separately.
#
# NOT AN ENUMERATION OF THE CURRENTLY-ABSENT AXES. Every axis carries an entry, so an axis that
# becomes constant later is already described; cost_of() fails CLOSED on any that is not.
ABSENT_COST = {
    1:  "name the corpus -- a deliberate act, no tooling required",
    2:  "publish a digest over the corpus: a CRYPTOGRAPHIC COMMITMENT with no established "
        "practice in this field, and no platform emits it",
    3:  "publish that digest BEFORE training: the same commitment, plus a timestamp, plus the "
        "willingness to be bound by it afterwards",
    4:  "host the corpus bytes -- expensive, but ordinary infrastructure",
    5:  "enumerate every filtering step; a completeness claim no one can audit",
    6:  "release the training code -- a deliberate act, ordinary tooling",
    7:  "state every hyperparameter, including the ones that were not tidy",
    8:  "record the seed and the ordering",
    9:  "record the hardware",
    10: "pin the environment -- ordinary tooling, rarely done",
    11: "publish the log",
    12: "host the weights -- the PLATFORM DOES THIS, which is why it is near-universal",
    13: "per-shard digests -- THE PLATFORM EMITS THESE AUTOMATICALLY from Git-LFS; no publisher "
        "decided provenance mattered",
    14: "sign the weights: a key, a published fingerprint, and a signing step in the release "
        "pipeline. A CRYPTOGRAPHIC COMMITMENT the ecosystem supplies no default for",
    15: "timestamp that signature against something outside the publisher's control",
    16: "A SECOND PARTY must retrain and report bit-identity. The publisher cannot do this at all",
    17: "A SECOND PARTY must retrain and report approximate agreement. Same structure, weaker bar",
    18: "state the licence -- near-universal, because a platform field asks for it",
    19: "make the eval/train split checkable rather than asserted",
    20: "disclose the fine-tuning data: a DELIBERATE ACT with commercial and legal cost, and, for "
        "several releases here, data the publisher may not be free to redistribute",
    21: "disclose the preference or reward data: the same, and it is the stage least often "
        "documented anywhere in the field",
    22: "state the evaluation contamination position",
}


def cost_of(axis_id):
    """What a publisher would have to do. Fails CLOSED rather than returning a dash.

    A .get(id, '--') here would let a newly-constant axis appear in the paper's own table with an
    empty explanation, which is exactly how the six-of-eight omission happened the first time.
    """
    if axis_id not in ABSENT_COST:
        raise KeyError("axis %r has no ABSENT_COST entry; section 8.1 would print a blank cell "
                       "for it. Describe the act, do not add a default." % (axis_id,))
    return ABSENT_COST[axis_id]


# ── THE ATTAINABLE MAXIMUM, DECLARED PER AXIS ───────────────────────────────────────────────
# ⛔ CAPS USED TO BE RECORDED PER CELL, and a cap only ever got written where there was a document
# to be incomplete. So a release that published a hyperparameter table had its axis-7 cell capped
# at 1, while a release that published nothing scored 0 against a ceiling of 2. THE RELEASES THAT
# DISCLOSED MORE HAD LOWER CEILINGS. Round-2 review found it. It never threatened a result -- no
# subject was near its ceiling -- but a rubric in which disclosing more lowers your maximum is not
# defensible however little it moves.
#
# SCORING.md already declared these caps by CLASS; only the ledger applied them by cell. Declaring
# them here makes the ceiling a property of the instrument, identical for every subject.
#
#   COMPLETENESS axes  "are ALL of X given?" -- a retrieved document cannot establish a universal
#   SEARCH axes        "has anyone reported Z?" -- the only mechanical check over a report is a
#                      grep, and awarding VERIFIED for a successful grep would make VERIFIED mean
#                      "the sentence is present", which is the collapse this instrument prevents
MAX_SCORE = {5: 1, 7: 1, 19: 1, 16: 1, 17: 1}

# ⛔ AND A SECOND RESTRICTION THAT THE PROSE CLAIMED AND THE CODE DID NOT HAVE. Section 5.2 said the
# ceiling reflects three things -- completeness axes, search axes, AND that an API-only release
# cannot reach the weights axes. Only the first two were implemented, so API-only releases came out
# with a HIGHER ceiling (0.886) than every open release (0.868): the opposite of what the sentence
# describes, printed in the table beside it.
#
# A release that publishes no weights cannot have them retrieved (12), cannot have a third party
# hash them (13), and cannot have them signed or timestamped in any way a third party could check
# (14, 15). Those are facts about the stratum, not about the publisher's diligence, and a ceiling
# that ignores them flatters the stratum it is supposed to bound.
STRATUM_MAX = {
    "api-only": {12: 0, 13: 1, 14: 1, 15: 1},
}


def max_for(axis_id, kind=None):
    """The highest score this axis can attain, for a release of this kind. Defaults to 2."""
    if axis_id not in BY_ID:
        raise KeyError("axis %r is not one of the %d" % (axis_id, len(AXES)))
    base = MAX_SCORE.get(axis_id, 2)
    if kind and kind in STRATUM_MAX and axis_id in STRATUM_MAX[kind]:
        return min(base, STRATUM_MAX[kind][axis_id])
    return base


def attainable(axis_ids, kind=None):
    """The denominator a subject is really scored against, given its stratum and applicable axes."""
    return sum(max_for(a, kind) for a in axis_ids)


# ── WHICH METHOD MAY SETTLE WHICH AXIS ──────────────────────────────────────────────────────
# ⛔ ROUND-3 REVIEW SET A CONFIG-FILE AXIS'S METHOD TO `hf_probe.weight_object` WITH BOTH FIELDS
# READING "nonsense", AND THE LEDGER VALIDATED. The validator confirmed the method string was on an
# allowlist and asked nothing about whether that method could possibly settle that axis.
#
# A weights probe cannot establish that a corpus is enumerated; a grep over a model card cannot
# establish that a shard's bytes are retrievable. Compatibility is declared here, and replay.py
# refuses a pairing that is not.
METHOD_AXES = {
    "grep_retrieved": set(range(1, 23)) - {4, 12, 13},
    "count_in_retrieved": set(range(1, 23)) - {4, 12, 13},
    "http_range": {4, 12},
    "hf_probe.weight_object": {12, 13},
    "hf_probe.all_shard_digests": {12, 13},
    "http_status": {4, 12, 18},
    "api_field": {12, 18},
    "hash_compare": {2, 13, 14, 15},
    # ⛔ AXIS 2 HAD NO STORAGE-LAYER METHOD. Its only registered methods read PROSE --
    # grep, count, and a hash comparison over a document -- so the axis could be settled only by
    # someone writing that a digest exists, and digests published by the HOSTING LAYER were
    # invisible to it by construction. Two round-12 reviewers found the same counter-example
    # independently, and the missing method is why it was there to find: axis 13 credits Git-LFS
    # oids for weights, and nothing could credit the identical mechanism for a corpus.
    "hf_probe.corpus_item_digests": {2},
    # ⛔ AXIS 14 HAD NO METHOD THAT COULD SEE A SIGNATURE. Its registered methods -- grep, count,
    # hash_compare -- all read prose, so "are the weights signed?" could be settled only by someone
    # WRITING that they were. A round-13 reviewer found signed commits on the very revisions axes
    # 12 and 13 already pin and concluded the axis could not be universally zero. The blindness was
    # real; the conclusion was not. See m_signed_commit in replay.py for what the evidence showed.
    "hf_probe.signed_commit": {14},
    # ⛔ AXIS 6 ASKS FOR SOURCE AND COULD ONLY READ PROSE ABOUT SOURCE. Its bar contrasts source
    # with "a description of it", and every score-2 cell was a grep of a README for one literal --
    # 'gpt-neox', 'torchrun', 'Megatron-DeepSpeed'. Two round-14 reviewers found this independently;
    # one demoted the cells and re-scored to show what it cost. A string's presence in a document
    # is compatible with the named repository being absent, empty, or unrelated.
    "repo_tree_probe": {6},
}


def methods_for(axis_id):
    """The methods that may settle this axis. Empty means no method has been declared for it,
    which is a reason to refuse a 2 rather than to allow any method."""
    if axis_id not in BY_ID:
        raise KeyError("axis %r is not one of the %d" % (axis_id, len(AXES)))
    return {m for m, axes in METHOD_AXES.items() if axis_id in axes}


# ── WHAT AN AXIS REQUIRES, not merely what it permits ───────────────────────────────────────
# ⛔ IDENTITY BINDING WAS OPT-IN PER EXECUTOR. `http_range` is registered and declared legal for
# axis 12, so moving a weights cell onto it bypassed every identity check by a route the validator
# and the axis table both approved: mp_metric reported no defects and replay printed
# "24 replayed and passed" with one cell holding another subject's bytes.
#
# A permitted-set says which methods MAY settle an axis. That is not enough where one method binds
# identity and another does not. These axes name the method that MUST be used.
REQUIRED_METHOD = {
    # ⛔ A 2 ON AXIS 6 MUST READ THE SOURCE TREE. Its bar contrasts source with "a description of
    # it", so a grep of a document about the source can support a 1 and never a 2. Registering the
    # method was not enough on its own: axis 2's round-12 repair added a method and left the old
    # prose cells scoring beside it, and this is the same shape.
    6: {"repo_tree_probe"},
    12: {"hf_probe.weight_object"},
    13: {"hf_probe.all_shard_digests"},
}

# Fields an executor cannot run without. Deleting one used to DEMOTE a cell to "unreplayable",
# after which its evidence was unconstrained and the build printed the count into the paper.
# A VERIFIED cell missing what its own method needs is a defect, not a weaker cell.
REQUIRED_FIELDS = {
    "grep_retrieved": ("expect",),
    "count_in_retrieved": ("expect", "expect_count"),
    "hf_probe.weight_object": ("expect_range_bytes", "expect_file",
                              "expect_evidence_sha256"),
    "hf_probe.all_shard_digests": ("expect_shards", "expect_evidence_sha256"),
    "hf_probe.corpus_item_digests": ("expect_files", "expect_repo",
                                     "expect_evidence_sha256"),
    "hf_probe.signed_commit": ("expect_revision", "expect_evidence_sha256"),
    "repo_tree_probe": ("expect_repo", "expect_commit", "expect_paths",
                        "expect_evidence_sha256"),
}


def required_method(axis_id):
    return REQUIRED_METHOD.get(axis_id)


def required_fields(method):
    return REQUIRED_FIELDS.get(method, ())
