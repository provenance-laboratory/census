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

    # ⛔ THE BAR SAID "SUFFICIENT TO RUN" AND NOTHING HERE CAN OBSERVE SUFFICIENCY. Round 14
    # replaced a README grep with `probe_source_trees.py`, which archives each declared repository
    # at a pinned commit and checks that the trainer entrypoints and a dependency manifest are
    # present -- a large improvement, and still not the stated bar. A round-5 reviewer named the
    # gap exactly: the check establishes that a tree is RUNNABLE-SHAPED, not that it runs.
    #
    # ⚠ SO THE BAR IS CORRECTED TO WHAT IS MEASURED, rather than the measurement being described
    # as more than it is. Establishing sufficiency would mean executing a training run for each
    # subject, which this census does not do and does not claim to. A bar the registry cannot
    # observe produces scores guaranteed by the instrument -- the defect this project has now
    # found on axes 2, 3, 14 and 15, and this is the same one stated in the opposite direction:
    # not a zero the method forced, but a two the method could not have earned.
    (6, 2, "training code released",
     "Is the code that produced the weights published?",
     "A declared repository, archived at a pinned commit, containing the trainer entrypoints and "
     "a dependency manifest -- runnable-SHAPED. Sufficiency to run is not established here.",
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
    # ⛔ THE CAP SAID ONE THING AND THE BAR SAID ANOTHER, AND A REVIEWER READ THE BAR. These read
    # "a signature verifiable against a key the publisher has previously bound to itself" and "a
    # timestamp a third party can verify without trusting the publisher's clock" -- neither of
    # which mentions the weights. An api-only publisher can sign and externally timestamp a digest
    # and publish the key, satisfying both sentences in full, so `STRATUM_MAX` capping the stratum
    # at 1 was not justified by the stated bar. **A cap the bar does not entail is a number the
    # instrument cannot defend**, and it is the same defect as a bar the method cannot observe,
    # which this file already records on axes 2, 3, 6, 14 and 15.
    #
    # ⚠ The bars now say what was always meant: a signature over a digest of bytes NOBODY CAN
    # OBTAIN is unfalsifiable. A third party can check that the signature verifies; it cannot check
    # that the signed digest is the digest of the weights, which is the property the axis asks
    # about. That is exactly a 1 -- ASSERTED -- and the cap follows from the bar rather than
    # sitting beside it.
    (14, 3, "weights signed",
     "Are the weights signed by an identifiable key?",
     "A signature verifiable against a key the publisher has previously bound to itself, over a "
     "digest a third party can RECOMPUTE from weight bytes it has obtained. A valid signature over "
     "a digest of unobtainable bytes is an assertion, not a check: it establishes who said it, "
     "never that what was said is true of the weights.",
     True),
    (15, 3, "weights timestamped",
     "Is the weights digest timestamped?",
     "A timestamp a third party can verify without trusting the publisher's clock, over a digest "
     "that same party can RECOMPUTE from weight bytes it has obtained. Timestamping a digest of "
     "unobtainable bytes fixes WHEN a string existed and nothing about the weights.",
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
    "reproduction_search":      "re-run the recorded reproduction search over ARCHIVED query "
                                "responses: every query present, every total recomputed from the "
                                "bytes, and the human adjudication recorded as human",
    "hf_probe.release_artifacts": "enumerate every file published at a pinned revision and count "
                                  "those matching a declared class of artifact -- signatures, "
                                  "timestamp proofs, attestations -- so their ABSENCE is a "
                                  "measurement rather than an assumption",
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
#
# ⛔ AND AXIS 16 WAS MISSING FROM IT WHILE BEING DECLARED UNREACHABLE ONE TABLE BELOW. `MAX_SCORE`
# caps axis 16 at 1 for everyone; `STRUCTURALLY_DETERMINED` says an api-only release cannot reach
# even that, because bit-identity is a comparison against weights no independent party can obtain.
# So the ceiling column priced a point the stratum provably cannot score. The two tables disagreed
# in BOTH directions at once -- axis 12 capped at 0 and undeclared, axis 16 declared and uncapped --
# which is the round-27 contradiction relocated rather than closed.
#
# ⇒ ONE RELATION, TWO SPELLINGS, KEPT IN AGREEMENT BY A CHECK: a pair is declared structurally
# determined IF AND ONLY IF its cap here is 0. `mp_metric.validate` refuses either way round, so
# neither table can drift from the other again, and "no positive is reachable" now means the same
# thing to the ceiling column and to the abstract.
#
# ⚠ THIS MOVES ONLY THE CEILING, NOT THE SCORES. `score()` divides by the uncorrected denominator
# and §5.2 says so; `attainable()` is read at exactly one site, the ceiling column. The correction
# raises the api-only ceiling's accuracy and cuts AGAINST this paper's caution: §5.3's
# non-monotonicity reversal is computed against the uncorrected denominator, so correcting it
# widens the reversal rather than closing it.
STRATUM_MAX = {
    # ⚠ `16: 0` STOOD HERE FOR ONE ROUND, PUT THERE TO MAKE THE CAP AGREE WITH A DECLARATION THAT
    # HAS SINCE BEEN WITHDRAWN. Axis 16 is capped at 1 for everyone by `MAX_SCORE` and is NOT
    # further capped by this stratum: a bit-identical reproduction report about an api-only release
    # is improbable, and this instrument has no ground to call it impossible.
    "api-only": {12: 0, 13: 1, 14: 1, 15: 1},
}

# ⛔ STRUCTURAL DETERMINATION IS A DIFFERENT RELATION FROM A SCORING CAP, AND CONFLATING THEM PUT A
# WRONG NUMBER IN THE ABSTRACT. `STRATUM_MAX` answers "how high can this stratum score". This
# answers "is ANY positive reachable at all, and on what grounds" -- and no table expressed it, so a
# first attempt hardcoded {14, 15, 16} and reported nine determined cells.
#
# ⚠️ THE NINE CAME FROM A REVIEWER'S SENTENCE, NOT FROM THE LEDGER. The derivation's own comment
# claimed the number "follows the ledger instead of being retyped beside it". It followed a literal
# set, and the literal was an assertion nobody had checked against SCORING.md. **The placeholder
# gate refused the typed number and then passed a derivation over a typed set -- the same number
# wearing the envelope.**
#
# ⇒ SCORING.md settles it: level 1 is ASSERTED, "the property is stated in a document we retrieved,
# and no artifact exists whose content a third party could check". An api-only publisher CAN state
# that its weights are signed or its digest timestamped; no artifact exists to check that against,
# which is exactly a 1. So a 0 on axes 14 and 15 is a FINDING -- three publishers, none of whom
# makes the claim -- and calling it structural gives away the result the census exists to produce.
#
# ⚠️ Nor can this be inferred from `max_for`: it returns 1 for axis 16 under api-only, so projecting
# over `== 0` finds nothing and over `> 0` sweeps in 14 and 15. The relation must be DECLARED, with
# the ground stated per entry, or the next round produces a fourth number by a fourth route.
# ⛔ A METHOD CAN SETTLE AN AXIS FROM A DOCUMENT, OR ONLY FROM AN ARTIFACT. Declared, because
# the distinction is what a "no permitted method" ground has to be checked against, and inferring
# it from a method's NAME would be the proxy this project keeps paying for.
#
# ⚠️ `reproduction_search` is DOCUMENT-SETTLED. It searches a corpus for a third party's report,
# and a report is a document. That is why axis 16's withdrawn determination could never have been
# a method-bar ground: a positive was always reachable by the registry's own rules.
# ⇒ THE TEST, STATED SO THE CLASSIFICATION IS NOT A GUESS FROM THE NAME: can this method
# settle the axis WITHOUT THE ARTIFACT EXISTING? If yes it is DOCUMENT -- it reads somebody's
# statement, whether that statement is prose, a third party's report, or a platform's metadata
# record. If no it must touch the artifact's bytes.
SETTLED_FROM_DOCUMENT = {
    "grep_retrieved": "reads literals out of a retrieved document",
    "count_in_retrieved": "counts occurrences in a retrieved document",
    "reproduction_search": "adjudicates third-party reports, which are documents",
    # ⚠️ A PLATFORM RECORD IS STILL A CLAIM. `api_field` reads structured metadata ABOUT a release;
    # metadata can say a file exists that cannot be fetched, so it settles nothing about the bytes.
    "api_field": "reads a hosting platform's metadata, which is an assertion about the artifact",
    "http_status": "a status code is a statement that something answers at a URL, not the bytes",
}
SETTLED_FROM_ARTIFACT = {
    "http_range": "reads bytes of a published object",
    "hf_probe.weight_object": "range-reads a weight file and refuses an LFS pointer",
    "hf_probe.all_shard_digests": "enumerates published shards",
    "hf_probe.corpus_item_digests": "enumerates published corpus files",
    "hf_probe.signed_commit": "reads a commit object",
    "hf_probe.release_artifacts": "enumerates published files at a revision",
    "repo_tree_probe": "reads a source tree at a pinned commit",
    "hash_compare": "recomputes a digest over bytes that were obtained",
}


def method_settlement(method):
    """DOCUMENT, ARTIFACT, or None when the method is not classified.

    ⛔ UNCLASSIFIED IS A REFUSAL, NOT A DEFAULT. A method nobody has classified is a method a
    ground could silently assume anything about.
    """
    if method in SETTLED_FROM_DOCUMENT:
        return "DOCUMENT"
    if method in SETTLED_FROM_ARTIFACT:
        return "ARTIFACT"
    return None


# ⚠️ WHICH STRATA LACK THE ARTIFACT AT ALL. Declared, because a mechanical ground is
# "no permitted method can settle this without an artifact" AND "this stratum has none", and the
# second half is a fact about the stratum rather than about the registry.
STRATA_WITHOUT_ARTIFACT = {
    "api-only": "the release publishes no weight object, so no artifact-settled method can run",
}


# METHODS WHOSE EVIDENCE IS DELIBERATELY NOT THE SUBJECT'S OWN. A reproduction search asks
# whether a THIRD PARTY published a report, so its archived artifacts are search responses from a
# host the subject neither owns nor declares -- and that is precisely what makes them evidence.
# The subject-source rule, which exists to stop a cell resting on somebody else's artifact, is the
# wrong rule here and must not be applied to these; the per-axis DOCUMENT declaration still is,
# and it is the stricter of the two.
SEARCHES_THIRD_PARTIES = {"reproduction_search"}


def searches_third_parties(method):
    return method in SEARCHES_THIRD_PARTIES


def method_bar_holds(axis_id):
    """(holds, why) -- can NO registered method settle this axis from a document?

    ⇒ THIS IS THE ONLY MECHANICALLY CHECKABLE GROUND KIND, and it is checkable by executing it
    rather than by reading a sentence. If every method permitted for an axis needs an artifact,
    then a stratum with no artifact cannot reach even ASSERTED through the registry.
    """
    perm = methods_for(axis_id)
    if not perm:
        return False, "no method is registered for axis %d at all" % axis_id
    unknown = sorted(m for m in perm if method_settlement(m) is None)
    if unknown:
        return False, "unclassified method(s) %s -- classify them before relying on a bar" % unknown
    doc = sorted(m for m in perm if method_settlement(m) == "DOCUMENT")
    if doc:
        return False, "%s can settle axis %d from a document" % (", ".join(doc), axis_id)
    return True, "every permitted method (%s) needs an artifact" % ", ".join(sorted(perm))


# ⛔⛔ THE GROUND UNDER THE ONE SURVIVING DETERMINATION WAS FALSE OF THE CODE IT CITED, AND A
# REVIEWER TESTED IT RATHER THAN READING IT. It said `REQUIRED_METHOD[12]` is
# `hf_probe.weight_object` and `grep_retrieved` is barred, "so no statement in a retrieved document
# can raise this cell even to ASSERTED". Both cited rules are CHECK-BLOCK rules:
#
#     mp_metric.py    if val == 2 and _req and meth not in _req      <- VERIFIED cells only
#     the axis-method rule runs inside `if isinstance(chk, dict)`     <- and 29 of 32 score-1
#                                                                        cells carry no check block
#
# They built the counterexample -- gpt-4o axis 12 at score 1 with a note and a source -- lifted the
# cap alone, and **zero method rules fired**. The only thing making the cell unreachable was the
# cap, which is the same cap the corroboration clause required the declaration to agree with.
# **The declaration was justified by the cap and the cap by the declaration.**
#
# ⇒ THE DEFENSIBLE GROUND IS A SEMANTIC FACT ABOUT THE AXIS, AND IT IS NOT A CLAIM ABOUT THIS
# CODE. It is written below as one, and marked as one.
STRUCTURALLY_DETERMINED = {
    (12, "api-only"): {
        "kind": "semantic",
        "blocks": 1,
        "ground":
            "axis 12 asks whether the weights are RELEASED. Unlike a digest or a signature, that "
            "property cannot be truthfully asserted in the absence of the artifact: an assertion "
            "of it is checkable by trying, and false if there is nothing to obtain. So there is no "
            "ASSERTED level to occupy -- a claim to have released weights that cannot be fetched "
            "is not a weaker form of releasing them, it is a false statement. This is exactly why "
            "axis 13 is capped at 1 and axis 12 at 0: a publisher may state a digest that nobody "
            "can recompute, and the statement is still a statement.",
        "not_machine_checked":
            "This is a claim about what the axis MEANS, not about which methods are registered. "
            "No predicate here executes it. An earlier version claimed a mechanical bar and was "
            "false of the code; stating the kind is what stops that recurring.",
    },
}


def structurally_determined(axis_id, kind):
    """The stated ground on which no positive is reachable, or None. Declared, never inferred."""
    e = STRUCTURALLY_DETERMINED.get((axis_id, kind))
    return e["ground"] if e else None


def determination_entry(axis_id, kind):
    return STRUCTURALLY_DETERMINED.get((axis_id, kind))

# ⚠️ THE RULE THAT DECIDES 0 VERSUS N/A, which the doctrine was missing and which reproduces every
# N/A decision already in the ledger:
#
#     N/A when the impossibility is INDEPENDENT of anything the instrument scores.
#     0   when the impossibility is ENTAILED BY A CHOICE the instrument already scores elsewhere.
#     0 AND DETERMINED when the axis IS the choice -- the cell records the decision itself.
#
# ⛔ THE THIRD CLAUSE WAS MISSING AND A REVIEWER FOUND THE HOLE IT LEFT. The two-clause rule asks
# whether the impossibility is entailed by a choice scored ELSEWHERE; for axis 12 under api-only
# the choice is scored AT axis 12, so the rule returns nothing at all and the cell fell through
# both branches. **A rule with a branch no data has taken is undefined, not settled** -- and this
# one had a case its own headline example landed in.
#
# ⇒ The third clause keeps the 0 (N/A would erase the fact the census exists to record) while
# marking the cell DETERMINED, so the denominator is right and the abstract cannot cite axis 12
# as a scored choice licensing six other cells without that being visible in one table.
#
# Base models on axes 20-22: no post-training stage exists, and nothing here scores the decision to
# release a base model -- independent, so N/A. Api-only on axes 13-16: the impossibility flows from
# publishing no weights, and THAT decision is already scored at axis 12; marking them N/A would
# credit one choice twice, once by capping axis 12 at 0 and again by shrinking the denominator.
# ⇒ Axis 16 is therefore scored 0 and disclosed, not N/A, and the reason generalises rather than
# resting on "every release was made from something", which is a Group 1 rationale that happened to
# reach the right verdict here for the wrong reason.


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
# ⛔⛔ AND THE EXCLUSION OF AXIS 13 MADE ITS *ASSERTED* LEVEL UNREACHABLE BY CONSTRUCTION. The
# reason recorded above -- "a grep over a model card cannot establish that a shard's bytes are
# retrievable" -- is right for axes 4 and 12, whose property IS retrievability. Axis 13 asks
# something else: does the publisher PUBLISH a digest of the weights. A model card stating
# `sha256 = ...` is a published digest, and a grep establishes exactly that it was published --
# which is the definition of ASSERTED, "stated in a document we retrieved, and no artifact exists
# whose content a third party could check".
#
# ★ SO THE EXCLUSION CONFLATED TWO CLAIMS: a grep cannot establish that a digest is CORRECT
# (true, and why `REQUIRED_METHOD[13]` still demands the shard probe for a 2) with a grep cannot
# establish that a digest was PUBLISHED (false). The consequence was that no axis-13 cell could
# ever score 1 -- twelve cells, five 2s and seven 0s -- while section 5.2's cap table said an
# api-only release stops at 1 there **because "a publisher may state a digest; nobody can
# recompute it"**. The paper described a level the instrument did not implement.
#
# ⇒ It changes no score. No publisher in this census states a weights digest in prose, and the
# five 2s rest on the shard probe as before. **What changes is what the seven zeros mean**: they
# were zeros that could not have been ones, and they are now zeros that could have been.
METHOD_AXES = {
    "grep_retrieved": set(range(1, 23)) - {4, 12},
    "count_in_retrieved": set(range(1, 23)) - {4, 12},
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
    # ⛔ THE THIRD AND FOURTH REGISTRY-BLIND AXES, found by both round-14 reviewers
    # independently after round 13 found the second. Axis 3's bar names a file format outright --
    # "An OpenTimestamps proof, or a dated signed publication" -- and permitted only grep and
    # count. An OTS proof is not greppable. Axis 15 asks for "a timestamp a third party can verify
    # without trusting the publisher's clock" and permitted grep, count and hash_compare, of which
    # hash_compare HAD NO EXECUTOR -- so the axis's registry looked richer than it was.
    #
    # ⛔ AND THE SHARPEST FORM OF IT: this census ships SELECTION-RULE.md.ots and
    # SELECTION-RULE-AMENDMENT-1.md.ots, and mp_metric.py names the OpenTimestamps anchor as one
    # of three mechanisms covering this project. It anchored its own pre-registration by exactly
    # the mechanism it had no method to observe in a subject.
    "hf_probe.release_artifacts": {3, 14, 15},
    # ⛔ AXES 16 AND 17 HAD THE ONLY BOUNDED SEARCH IN THE CENSUS AND NO WAY TO EXECUTE IT.
    # negative_search.py recorded every query, its total and its adjudication -- and the cells
    # carried that as PROSE in a note, so section 9.1 could call these the strongest zeros while
    # the first-class accounting counted all 22 among the asserted. A round-14 reviewer found the
    # inconsistency and proposed the fix; this is it.
    "reproduction_search": {16, 17},
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
    "hf_probe.release_artifacts": ("expect_repo", "expect_revision", "expect_patterns",
                                   "expect_matches", "expect_pattern_probe",
                                   "expect_evidence_sha256"),
    "reproduction_search": ("expect_subject_name", "expect_queries", "expect_total_results",
                            "expect_adjudicated_positive", "expect_response_digests"),
}


def required_method(axis_id):
    return REQUIRED_METHOD.get(axis_id)


def required_fields(method):
    return REQUIRED_FIELDS.get(method, ())


def score_name(score):
    """The name and definition of a score. ⚠ SCORES was defined and read by nothing -- the
    rubric the whole census rests on existed as documentation that happened to be Python. Anything
    printing a score name goes through here so the rubric and the code cannot diverge."""
    return SCORES.get(score, ("UNKNOWN", "no definition for this score"))


def group_name(axis_group):
    """The name of an axis group. ⚠ Same as SCORES: defined, never read."""
    return GROUPS.get(axis_group, "ungrouped")
