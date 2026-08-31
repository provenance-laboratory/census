"""mp-metric — what a model release lets a third party CHECK, as opposed to being TOLD.

Deliberately parallel to `obl-metric`, which measures how far a chain has diverged from a
historical reference. Same discipline, different subject: reference-relative, source-anchored,
and NOT A RANKING.

TWO STRUCTURAL DECISIONS, BOTH TAKEN BECAUSE obl-metric PAID FOR THEM

1. THE ENGINE EMITS THE TABLES; THE PAPER INCLUDES THEM.
   obl-metric's round-2 referees returned NO-GO with six regressions in one round, and the root
   cause was not carelessness: the paper hand-maintained numbers the engine computed, edited by
   string surgery every time a cell moved. Numbers here are written by `emit_tables()` into
   `tables/` and are never typed into prose.

2. THE HEADLINE CANNOT BE EMITTED WITHOUT ITS SENSITIVITY BAND.
   `N/A` removes an axis from the DENOMINATOR, so a release with many N/A scores HIGHER. That
   makes N/A the escape hatch that quietly does all the work. `score()` therefore returns a triple
   -- as-coded, N/A re-coded to 0, N/A re-coded to 2 -- and there is no function that returns the
   first alone. A number that can be quoted alone eventually is.

THE EVIDENCE STANDARD, APPLIED WITHOUT EXCEPTION
   Every non-zero cell is backed by a retrievable artifact: url, retrieval date, sha256 of the
   RETRIEVED BYTES. A cell with no artifact record is not a 1 -- it is a bug, and validate()
   refuses to score the whole census until it is fixed.

Run:  python mp_metric.py              validate, score, emit tables
      python mp_metric.py --check      validate only; write nothing
"""
import datetime as dt
import hashlib
import io
import json
import pathlib
import re
import sys

import axes as A

NL = chr(10)
HERE = pathlib.Path(__file__).resolve().parent
LEDGER = HERE / "cells.json"
TABLES = HERE / "tables"
# Methods replay.py actually re-executes against archived bytes. Kept here so the
# volatility exception cannot be claimed for a method nobody replays.
REPLAYABLE = {"grep_retrieved", "count_in_retrieved", "http_range",
              "hf_probe.weight_object", "hf_probe.all_shard_digests"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def load():
    if not LEDGER.exists():
        return {"subjects": [], "cells": []}
    led = json.loads(LEDGER.read_text(encoding="utf-8"))
    # ⛔ THE RATCHET IS ONLY A CONTROL IF IT CANNOT BE DELETED. Its floor lives inside the census
    # so that it travels with the thing it describes -- which means removing the key would disarm
    # it silently, and the census would go back to asserting 182 negatives with nothing watching.
    # Every reader of the real census passes through here, so the requirement is stated once.
    if "zero_bounds_floor" not in led:
        raise SystemExit(
            "⛔ cells.json has no `zero_bounds_floor`. That key is what stops a bounded "
            "negative from being quietly un-bounded; without it the coverage ratchet in "
            "validate() does not run at all. Restore it, do not work around it.")
    return led


def all_cited(led, include_facts=True):
    """Every artifact THE PROJECT CITES -- cells and facts alike -- as (label, evidence_dict).

    ⛔ facts.json SAT OUTSIDE EVERY CONTROL. pin_urls.py, recheck.py and both digest-uniqueness
    rules below walked led["cells"] and nothing else, so the two fact urls were unpinned `/main/`
    branches that were never re-fetched and were free to collide with cell evidence. A fact is
    cited in the manuscript BY NAME and supplies a number no reader can recompute without it;
    there is no principle on which it should be less bound than a cell's evidence.

    ⛔ AND THE FIX IS A PROJECTION, NOT ANOTHER LIST. The recurring defect in this project is
    repairing instance N by enumerating the members of a class. The class here is "everything the
    project cites"; this function IS that class, and every control takes it rather than naming the
    files it happens to know about.
    """
    for c in led.get("cells", []):
        where = "%s/axis%d" % (c.get("subject"), c.get("axis"))
        for e in (c.get("evidence") or []):
            yield where, e
    if not include_facts:
        return
    fp = HERE / "facts.json"
    if not fp.exists():
        return
    for name, f in (json.loads(fp.read_text(encoding="utf-8")).get("facts") or {}).items():
        e = f.get("evidence")
        if isinstance(e, dict):
            yield "fact:" + name, e
        elif isinstance(e, list):
            for one in e:
                yield "fact:" + name, one


def _absent(block, field):
    """Is a required field MISSING, as opposed to legitimately zero or false?

    ⛔ `if not block.get(field)` COULD NOT TELL 0 FROM ABSENT, and 0 is exactly what a negative
    bound carries: `expect_matches: 0` means "we enumerated every published file and none matched",
    which is the whole measurement. Seven axis-15 bounds were reported as missing a field they
    declared. Emptiness still counts as absence for containers -- an empty `expect` list is a
    method name with nothing to replay -- but a number is present when it is there.
    """
    v = block.get(field)
    if v is None:
        return True
    if isinstance(v, (str, bytes, list, tuple, dict, set)) and not v:
        return True
    return False


def validate(led):
    """Return a list of defects. ANY defect means the census is not scoreable.

    Fails CLOSED: a subject-axis pair that is simply missing is a defect, not a zero. An absent
    cell and a cell scored 0 are different claims -- 'nobody looked' is not 'we looked and found
    nothing' -- and writing them identically is how a census becomes an opinion.
    """
    d = []

    # ⛔ `DATE_RE` WAS COMPILED AT MODULE LEVEL AND NEVER APPLIED -- a date validator, inside the
    # validator, checking no dates. Found by the dead-mechanism control written after a round-17
    # reviewer found the same shape in replay.py's `_ENTRY`.
    #
    # ⚠ AND THE FIRST VERSION OF IT RETURNED EARLY, which swallowed an existing control: the
    # bound-rules suite sets `bound.as_of` to "" and expects "bound.as_of is empty", and my check
    # fired first on the same value with a different message, so a passing test started reporting
    # MISSED. A new check that pre-empts an old one has not added coverage, it has moved it. This
    # appends, and leaves the empty case to the control that already owned it.
    _as = led.get("as_of")
    if _as not in (None, "") and not DATE_RE.match(str(_as)):
        d.append("the ledger's as_of is %r, which is not an ISO date" % (_as,))
    for _c in led.get("cells", []):
        _blk = _c.get("bound") or _c.get("check") or {}
        _v = _blk.get("as_of") if isinstance(_blk, dict) else None
        if _v not in (None, "") and not DATE_RE.match(str(_v)):
            d.append("%s/axis%s: as_of is %r, which is not an ISO date"
                     % (_c.get("subject"), _c.get("axis"), _v))
    subjects = [s["id"] for s in led.get("subjects", [])]
    if len(set(subjects)) != len(subjects):
        d.append("duplicate subject ids")

    seen = {}
    for i, c in enumerate(led.get("cells", [])):
        where = f"cell[{i}] {c.get('subject','?')}/axis{c.get('axis','?')}"
        ax, sub, val = c.get("axis"), c.get("subject"), c.get("score", "MISSING")

        if ax not in A.BY_ID:
            d.append(f"{where}: axis {ax} is not one of the 22")
            continue
        if sub not in subjects:
            d.append(f"{where}: subject not declared in subjects[]")
        if (sub, ax) in seen:
            d.append(f"{where}: duplicate of cell[{seen[(sub, ax)]}]")
        seen[(sub, ax)] = i

        if val not in (0, 1, 2, None):
            d.append(f"{where}: score {val!r} is not 2/1/0/null")
            continue

        # N/A is policed: only where the axis permits it, and never without a reason.
        if val is None:
            if ax not in A.NA_PERMITTED:
                d.append(f"{where}: N/A on an axis that can never be N/A "
                         f"({A.BY_ID[ax][2]}) -- every release was made from something")
            if not str(c.get("na_reason", "")).strip():
                d.append(f"{where}: N/A with no na_reason -- bulk N/A is the escape hatch")
            continue

        # THE EVIDENCE STANDARD. A non-zero cell without a retrievable artifact is a bug.
        if val > 0:
            ev = c.get("evidence") or []
            if not ev:
                d.append(f"{where}: score {val} with NO evidence record -- not a {val}, a bug")
            for j, e in enumerate(ev):
                w2 = f"{where} evidence[{j}]"
                if not str(e.get("url", "")).startswith(("http://", "https://")):
                    d.append(f"{w2}: no retrievable url")
                # a regex accepted 2026-99-99; parse it, and refuse the future
                try:
                    got = dt.date.fromisoformat(str(e.get("retrieved", "")))
                    if got > dt.date.today():
                        d.append(f"{w2}: retrieved date {got} is in the future")
                except ValueError:
                    d.append(f"{w2}: retrieved must be a real YYYY-MM-DD date "
                             f"(got {e.get('retrieved')!r}); a regex accepted 2026-99-99")
                # ⛔ A VOLATILE ENDPOINT CANNOT SUPPORT A VERIFIED CELL.
                # Some provenance material exists only behind live APIs whose bodies carry
                # counters -- stars, download totals -- that change independently of the claim.
                # Such a record is admissible as ASSERTED evidence and never as VERIFIED, which
                # is what stops "volatile" from becoming a way to launder an unstable artifact
                # into a 2.
                if e.get("volatile"):
                    # ⛔ THE BAR EXISTS TO STOP A MOVING TARGET LAUNDERING INTO A 2, and it still
                    # does. The narrow exception: a record whose cell is checked by REPLAYING a
                    # registered method against ARCHIVED BYTES is not a moving target, because the
                    # check never touches the live endpoint. The Hugging Face API responses are
                    # pinned to a revision and still carry download counters -- two drifted
                    # between consecutive recheck runs -- but the shard ENUMERATION inside the
                    # archived copy is what the check reads, and replay.py recomputes it there.
                    _replayed = str((c.get("check") or {}).get("method", "")) in REPLAYABLE
                    if val == 2 and not _replayed:
                        d.append(f"{w2}: marked volatile, so it cannot support a VERIFIED cell "
                                 f"unless the cell's check is replayed against ARCHIVED bytes "
                                 f"(method {(c.get('check') or {}).get('method')!r} is not)")
                    if not str(e.get("volatile_reason", "")).strip():
                        d.append(f"{w2}: volatile with no stated reason")
                if not SHA256_RE.match(str(e.get("sha256", ""))):
                    d.append(f"{w2}: sha256 of the RETRIEVED BYTES is required "
                             f"-- an HTTP 200 is not an artifact")
        # The axis cap is a property of the INSTRUMENT, so a cell may not exceed it. This
        # replaces caps that were noted per-cell and therefore applied unevenly.
        _kind = {x["id"]: x.get("kind") for x in led.get("subjects", [])}.get(sub)
        if val is not None and val > A.max_for(ax, _kind):
            d.append(f"{where}: score {val} exceeds this axis's attainable maximum "
                     f"({A.max_for(ax, _kind)}) for a {_kind} release. See axes.MAX_SCORE -- the cap is a property of the "
                     f"axis, not of what this particular release happened to publish.")

        # ⛔ "AT A PINNED REVISION" MUST BE TRUE OF THE URL, NOT JUST OF THE DIGEST. Round-2
        # review found 13 of 25 score-2 cells citing a `main` or `master` branch. The stored
        # digest always established WHICH BYTES were used; it never made the source a pinned
        # revision, and the paper's sentence claimed both.
        if val == 2:
            for j, e in enumerate(c.get("evidence") or []):
                u = str(e.get("url", ""))
                # ⚠️ AN EARLIER VERSION MATCHED ONE HOST. It caught the 13 GitHub urls and
                # missed 4 identical Hugging Face ones -- an enumeration of hosts where a
                # projection over MUTABLE REFS was needed, which is the defect this whole census
                # is arranged against, committed inside the fix for a different defect.
                if re.search(r"/(main|master|HEAD|latest)/", u):
                    d.append(f"{where} evidence[{j}]: VERIFIED cell cites a MUTABLE BRANCH "
                             f"({u[:70]}...). Run pin_urls.py; a branch is a moving pointer and "
                             f"'retrieved at a pinned revision' is false of it.")

        # {D} VERIFIED requires a REGISTERED method, not a sentence. Round-1 review passed every
        # score-2 cell with check="read a document" and this validator reported no defect.
        #
        # {D} AND A CHECK ON A NON-VERIFIED CELL WAS VALIDATED BY NOTHING, which is the same hole
        # `bound` had before round 13. It matters now: round 14 demoted five cells from 2 to 1
        # because their checks did not establish their axis's bar, and those checks STAY on the
        # cells as the record of what was actually tested. Unvalidated, they would be prose again
        # the moment anyone edited them. Every cell carrying a `check` is held to the method rules;
        # only the VERIFIED-specific ones below remain gated on val == 2.
        if isinstance(c.get("check"), dict) or val == 2:
            chk = c.get("check")
            if not isinstance(chk, dict):
                d.append(f"{where}: VERIFIED requires a `check` OBJECT "
                         f"{{method, asserts, observed}}; a free-text string is not a control")
            else:
                meth = str(chk.get("method", ""))
                # ⛔ A METHOD CAN BE REGISTERED AND HAVE NO EXECUTOR, and until round 14
                # three were: api_field, hash_compare and http_status are in CHECK_METHODS and
                # absent from replay.DISPATCH. A cell could be promoted to VERIFIED by naming one,
                # pass this validator, and then be reported by replay as "method has no executor"
                # -- a defect discovered one tool later, in a run nothing forces anyone to make.
                # Worse, hash_compare is the only non-prose method permitted on axis 15, so the
                # axis's registry looked richer than it was. A reviewer found all three.
                import replay as _R
                if meth in A.CHECK_METHODS and meth not in _R.DISPATCH:
                    d.append(f"{where}: check.method {meth!r} is registered in axes.CHECK_METHODS "
                             f"but has NO EXECUTOR in replay.DISPATCH. A registry entry nothing "
                             f"implements is a method name, and it makes an axis look more "
                             f"observable than it is")
                if meth not in A.CHECK_METHODS:
                    d.append(f"{where}: check.method {meth!r} is not registered in "
                             f"axes.CHECK_METHODS -- a cell cannot be promoted to VERIFIED by "
                             f"describing a check that is not implemented")
                # ⛔ METHOD-AXIS COMPATIBILITY. Round-3 review set a config-file axis's method
                # to `hf_probe.weight_object` with both fields reading "nonsense" and this
                # validated: it checked that the name was on an allowlist and asked nothing about
                # whether that method could settle that axis.
                elif meth not in A.methods_for(ax):
                    d.append(f"{where}: method {meth!r} cannot settle this axis "
                             f"({A.BY_ID[ax][2]}). Valid: "
                             f"{sorted(A.methods_for(ax)) or 'NONE DECLARED'}")
                # ⛔ AND WHERE AN AXIS REQUIRES A SPECIFIC METHOD, A LEGAL ALTERNATIVE IS
                # NOT ACCEPTABLE. Round-6 review moved a weights cell to `http_range` -- which is
                # registered, and which axes.py declared legal for that axis -- and every identity
                # check was bypassed with no defect reported anywhere.
                # ⛔ REQUIRED-METHOD IS A RULE ABOUT VERIFIED CELLS ONLY. A score-1 cell may
                # legitimately record a weaker check as the record of what was tested -- bloom's
                # axis 6 greps a README, and that IS the finding: the declared repository holds
                # BLOOM's launch script and chronicles, not the trainer, which lives in an
                # undeclared repository. Demanding the strong method there would delete the
                # distinction this axis now draws.
                _req = A.required_method(ax)
                if val == 2 and _req and meth not in _req:
                    d.append(f"{where}: axis {ax} REQUIRES {sorted(_req)}; {meth!r} is registered "
                             f"and permitted but does not bind this axis's identity")
                # A cell missing what its own method needs is a DEFECT, not a weaker cell. Deleting
                # `expect_range_bytes` used to demote the check to unreplayable and leave the
                # evidence unconstrained.
                for _f in A.required_fields(meth):
                    if _absent(chk, _f):
                        d.append(f"{where}: method {meth!r} requires `{_f}`; without it nothing "
                                 f"can be replayed and the evidence is unconstrained")

                # ⛔ A REPLAYABLE METHOD MUST CARRY SOMETHING TO REPLAY. `grep_retrieved` with no
                # `expect` list is a method NAME, not a check, which is what the paper's phrase
                # "a registered mechanical check over its content succeeded" was resting on.
                if meth in ("grep_retrieved", "count_in_retrieved") and not chk.get("expect"):
                    d.append(f"{where}: method {meth!r} with no `expect` list. Nothing can be "
                             f"replayed, so the method name is a label and the cell cannot be "
                             f"VERIFIED. See replay.py")
                for k in ("asserts", "observed"):
                    if not str(chk.get(k, "")).strip():
                        d.append(f"{where}: check.{k} is empty; the assertion and what came "
                                 f"back must both be recorded or the claim cannot be contradicted")

        # ⛔ A NEGATIVE IS A CLAIM, AND UNTIL ROUND 13 NOTHING VALIDATED ONE. Every rule above
        # is gated on `val == 2`, so a cell scored 0 could carry any `check` it liked, or none, and
        # this validator reported nothing. 182 of 264 cells are zeros; not one recorded what was
        # searched. A reviewer showed that 36 of those notes could simply be DELETED and the build
        # would still pass -- the note was decoration beside a score.
        #
        # A `bound` says what was searched, on what date, with what method, and what came back. It
        # is held to the same standard as a `check`, because it is one.
        if isinstance(c.get("bound"), dict):
            b = c["bound"]
            if val != 0:
                d.append(f"{where}: carries a `bound`, which records a SEARCH THAT FOUND "
                         f"NOTHING, but the cell is scored {val!r}. A bound belongs on a zero.")
            meth = str(b.get("method", ""))
            if meth not in A.CHECK_METHODS:
                d.append(f"{where}: bound.method {meth!r} is not registered in "
                         f"axes.CHECK_METHODS -- a negative cannot rest on a method that is not "
                         f"implemented any more than a positive can")
            elif meth not in A.methods_for(ax):
                d.append(f"{where}: bound.method {meth!r} cannot settle this axis "
                         f"({A.BY_ID[ax][2]}). Valid: {sorted(A.methods_for(ax)) or 'NONE'}")
            for _f in A.required_fields(meth):
                if _absent(b, _f):
                    d.append(f"{where}: bound.method {meth!r} requires `{_f}`; without it the "
                             f"negative cannot be replayed")
            for k in ("asserts", "observed", "as_of"):
                if not str(b.get(k, "")).strip():
                    d.append(f"{where}: bound.{k} is empty. A zero with no {k} is the "
                             f"circular negative this instrument exists to refuse")
            # ⛔ A `searched` LIST WAS PROSE AND NOTHING CHECKED IT. A round-14 reviewer
            # replaced five real search locations with ["nothing-but-a-nonempty-placeholder"] and
            # asserts/observed with "x", and the validator and replay both passed -- so the bounds
            # tested STRUCTURE, not substance, and counting them as replayable proofs of a zero was
            # ceremony. Their word, and it was fair.
            #
            # ⚠ AND THE OBVIOUS FIX WAS WRONG. Requiring every searched url to have an archived
            # response would have forced a keyserver 404 into the evidence store -- and an empty
            # body proves nothing, because every 404 hashes alike. A negative about a live external
            # service CANNOT be made offline-replayable by storing bytes. Pretending otherwise
            # would be the proxy defect one level deeper.
            #
            # ⛔ SO THE TWO KINDS ARE SEPARATED AND BOTH ARE DECLARED. `searched_archived` names
            # locations whose responses are in the evidence store and which replay re-runs
            # offline. `searched_live` names lookups that can only be re-run against the network,
            # each with the date it was made. A bound with nothing archived is not a bound; a bound
            # that hides live lookups among archived ones overstates what it proves.
            _arch = [str(x) for x in (b.get("searched_archived") or [])]
            _live = [str(x) for x in (b.get("searched_live") or [])]
            _byurl = {str(e.get("url")) for e in (c.get("evidence") or [])}
            if not _arch:
                d.append(f"{where}: bound declares no `searched_archived`. Every location is live "
                         f"or prose, so nothing about this negative can be re-run offline -- which "
                         f"is the circular zero this instrument exists to refuse")
            _missing = [u for u in _arch if u not in _byurl]
            if _missing:
                d.append(f"{where}: bound.searched_archived names {len(_missing)} location(s) "
                         f"with no evidence record: {_missing[:2]}. Archived means archived")
            for _u in _live:
                if _u in _byurl:
                    d.append(f"{where}: {_u[:60]} is listed as a LIVE lookup and is also archived. "
                             f"Move it to searched_archived; understating what is verifiable is "
                             f"still a misdescription of the bound")
            if b.get("searched"):
                d.append(f"{where}: bound still carries the old flat `searched` list. Split it "
                         f"into searched_archived and searched_live so the bound's strength is "
                         f"visible rather than averaged")

            if not (c.get("evidence") or []):
                d.append(f"{where}: bound with NO evidence record. The bytes searched must be "
                         f"archived or the negative cannot be re-run against them.")

    # ⛔ THE SAME URL MAY NOT CARRY TWO DIGESTS. Round-1 review showed a census validating with
    # one url recorded under conflicting hashes -- and recheck.py silently used the first, so the
    # contradiction was invisible on both sides.
    seen_url = {}
    for where, e in all_cited(led):
        u, h = e.get("url"), e.get("sha256")
        if u in seen_url and seen_url[u][0] != h:
            d.append(f"{u}: recorded with two different digests "
                     f"({seen_url[u][0][:12]} at {seen_url[u][1]}, {str(h)[:12]} at "
                     f"{where}) -- one of them is wrong")
        elif u not in seen_url:
            seen_url[u] = (h, where)

    # ⛔ AND THE MIRROR OF IT. The rule above refuses one url under two digests. The reverse --
    # one DIGEST under two urls -- is how a cell keeps a truthful-looking url while its bytes are
    # replaced by another artifact's: the url still anchors, and the recorded digest still matches
    # the archived bytes, because BOTH were swapped. Offline, the tell is that the same bytes are
    # now claimed to have come from two different places. Round-6 review demonstrated it on olmo's
    # corpus cell using bert's weight range.
    seen_sha = {}
    for where, e in all_cited(led):
        h, u = e.get("sha256"), e.get("url")
        if h in seen_sha and seen_sha[h][0] != u:
            d.append(f"digest {str(h)[:12]} is cited under TWO different urls "
                     f"({seen_sha[h][0][:58]} at {seen_sha[h][1]}, and {str(u)[:58]} at "
                     f"{where}) -- the same bytes cannot have been retrieved from both")
        elif h not in seen_sha:
            seen_sha[h] = (u, where)

    # ⛔ EVERY NON-ZERO CELL MAY CITE ONLY SOURCES ITS SUBJECT DECLARES. Ownership used to be
    # inferred from the cells being audited, so it could not fire at runtime and a symmetric swap
    # redefined it. subjects[].sources is a DECLARATION on the subject record: it does not travel
    # with evidence, it does not travel with a check block, and exchanging two cells cannot move
    # it. This is the validator's half; replay.gate() applies the same rule per cell.
    import replay as _R                                                    # noqa: PLC0415
    _decl = {s["id"]: set(s.get("sources") or ()) for s in led.get("subjects", [])}
    _ctx_full = _R.subject_context(led)
    for c in led.get("cells", []):
        if not c.get("score"):
            continue
        allowed = _decl.get(c["subject"])
        # ⛔ FAILS CLOSED. `if not allowed: continue` meant DELETING a subject's declaration turned
        # the rule off -- the optional-field failure mode, for the third time in three rounds.
        if not allowed:
            d.append(f"{c['subject']}/axis{c['axis']}: scored, and its subject declares no "
                     f"sources. A missing policy disables nothing; it is a defect.")
            continue
        for e in (c.get("evidence") or []):
            k = _R.source_key(e["url"])
            if k not in allowed:
                owner = sorted(s for s, v in _decl.items() if k in v)
                d.append(f"{c['subject']}/axis{c['axis']}: cites {k}, which this subject does not "
                         f"declare in subjects[].sources"
                         + (f" (it is {', '.join(owner)}'s)" if owner else ""))

    # And the full per-axis policy, so the validator and the gate agree rather than one of them
    # carrying half the rule. A reviewer showed the two disagreeing was itself the defect.
    for c in led.get("cells", []):
        if not c.get("score"):
            continue
        for why in _R.foreign_evidence(c, _ctx_full):
            d.append(f"{c['subject']}/axis{c['axis']}: {why}")

    # PROJECT over subjects x axes: every pair must be present.
    for s in subjects:
        for ax in A.BY_ID:
            if (s, ax) not in seen:
                d.append(f"{s}/axis{ax} ({A.BY_ID[ax][2]}): MISSING -- absent is not zero")
    # ⛔ AND THE COVERAGE MUST NOT FALL. A bounded zero can be un-bounded by deleting a key,
    # and nothing above would notice -- the cell would rejoin the unvalidated majority in silence.
    # This is a PROJECTION over every zero, not a list of the ones we remember bounding.
    #
    # ⚠ THE FLOOR LIVES IN THE CENSUS, NOT BESIDE IT. Its first version read a floor FILE, so
    # the rule fired against stress_test's synthetic fixtures -- small censuses with no zeros at
    # all -- and reported that coverage had "fallen from 6 to 0 of 0". A floor is a fact about one
    # census; a validator runs on whatever ledger it is handed. Carrying it inside the ledger
    # makes it travel with the thing it describes.
    _floor = led.get("zero_bounds_floor")
    if isinstance(_floor, dict):
        _zeros = [c for c in led["cells"] if c.get("score") == 0]
        _bounded = [c for c in _zeros if isinstance(c.get("bound"), dict)]
        if len(_bounded) < _floor.get("bounded_zeros", 0):
            d.append(f"BOUNDED-ZERO COVERAGE FELL from {_floor['bounded_zeros']} to "
                     f"{len(_bounded)} of {len(_zeros)} zeros. A bound was removed. If that was "
                     f"deliberate, say so in the commit and lower zero_bounds_floor in "
                     f"cells.json; otherwise a negative just became unfalsifiable again.")
    return d



def by_subject(led):
    """{subject: {axis: score}} -- the shape every consumer kept rebuilding for itself."""
    out = {}
    for c in led.get("cells", []):
        out.setdefault(c["subject"], {})[c["axis"]] = c.get("score")
    return out


def constant_axes(led):
    """Axes that never vary OVER THE CELLS WHERE THEY APPLY.

    ⛔ FOUR CALL SITES COMPUTED THIS AS `len({(score or 0) for s in subjects}) == 1`, and `or 0`
    coerces N/A to zero. That ran in two directions at once: it put the post-training axes on the
    list on the strength of THREE live cells -- attributing to nine publishers a failure on an axis
    they were never scored against -- and it HID axis 22, which is constant at 1 over every cell it
    applies to, the opposite of absent.
    ⚠️ Round-2 review named two of those call sites. I fixed those two and a third was still
    wrong, which is the recurring lesson: a fix is not finished until the other call sites are
    found. Hence one implementation, here, and callers that import it.

    Returns [(axis, value, applicable_n)], sorted.
    """
    by = by_subject(led)
    subs = sorted(by)
    out = []
    for a in sorted(A.BY_ID):
        live = [by[s].get(a) for s in subs if by[s].get(a) is not None]
        if live and max(live) == min(live):
            out.append((a, live[0], len(live)))
    return out


def dominates(led, lo, hi):
    """Does `lo` weakly dominate `hi` cell by cell? Returns (below, strictly_greater).

    Compares only axes where BOTH have a real score: N/A against a number is not a comparison,
    and coercing it to zero would manufacture dominance where the axis does not apply.
    """
    by = by_subject(led)
    both = [a for a in sorted(A.BY_ID)
            if by[lo].get(a) is not None and by[hi].get(a) is not None]
    below = [a for a in both if by[lo][a] < by[hi][a]]
    strict = [a for a in both if by[lo][a] > by[hi][a]]
    return below, strict, both


def score(led):
    """Per subject: (as_coded, na_as_0, na_as_2), each a fraction of the maximum.

    Returns all three, always. There is deliberately no function returning the first alone.
    """
    out = {}
    kind_of = {x["id"]: x.get("kind") for x in led.get("subjects", [])}
    by_sub = {}
    for c in led.get("cells", []):
        by_sub.setdefault(c["subject"], {})[c["axis"]] = c
    for s, cells in by_sub.items():
        vals = [cells[a].get("score") for a in sorted(cells)]
        real = [v for v in vals if v is not None]
        n_na = sum(1 for v in vals if v is None)
        as_coded = (sum(real) / (2 * len(real))) if real else 0.0
        na0 = sum(real) / (2 * len(vals)) if vals else 0.0
        na2 = (sum(real) + 2 * n_na) / (2 * len(vals)) if vals else 0.0
        # The ceiling this subject could reach, given which axes apply to it and what each axis
        # can attain. Reported because the denominator is NOT the same for every stratum: an
        # API-only release cannot reach axis 12 at all, and no release can reach 2 on a
        # completeness or search axis.
        live = [a for a in sorted(cells) if cells[a].get("score") is not None]
        ceiling = (A.attainable(live, kind_of.get(s)) / (2.0 * len(live))) if live else 0.0
        out[s] = {"as_coded": as_coded, "na_as_0": na0, "na_as_2": na2, "ceiling": ceiling,
                  "n_na": n_na, "n_scored": len(real),
                  "counts": {k: sum(1 for v in vals if v == k) for k in (2, 1, 0)}}
    return out


def policy_keys():
    """The subject-record fields that constitute the POLICY, named ONCE.

    ⛔ sweep.py kept its own copy of this list and it went stale the round two keys were added,
    so the family that claims to "move the policy too" moved four of the six axis-scoped keys and
    left `axis_file` and `axis_evidence_sha256` behind. A reviewer found it: the survivor total
    was unaffected, but 62 cross-subject cases were being rejected by the validator that the
    described mechanism says the executor should see. The paper described one experiment and the
    code ran another.

    ⚠ Two hand-kept copies of the same list is the same defect as one hand-kept list, one file
    further apart. Everything that needs to know what the policy is reads this.
    """
    return ("id", "repo", "kind", "sources", "axis_sources", "axis_documents",
            "axis_method", "axis_literals", "axis_file", "axis_evidence_sha256", "note")


def ledger_fingerprint(led):
    """A digest over every (subject, axis, score) triple, N/A included.

    ⛔ WHY EMITTED TABLES CARRY THIS. Round-2 review found the shipped PDF's results table one
    ledger-revision stale: it said bert scored 0.211 while every other figure in the same document
    said 0.237, because build_paper.py read the table off disk with an existence check while
    recomputing everything else live. The header stamp could not distinguish the two files -- both
    said "as of 2026-08-29".

    The mechanism deserves naming. The gate loop that was supposed to catch this ran
    `mp_metric.py --check`, whose entire purpose is to VALIDATE AND WRITE NOTHING. So the tables
    never regenerated, and a build that refuses to proceed unless a url+digest fingerprint covers
    the drift run then loaded the census's headline result from a filename.
    """
    rows = sorted("%s|%d|%s" % (c["subject"], c["axis"], c.get("score"))
                  for c in led.get("cells", []))
    # ⛔ AND THE POLICY, WHICH NOTHING COVERED. The declarations that judge these cells --
    # sources, axis_sources, axis_documents, axis_method, axis_literals -- live in this same file,
    # beside the cells, written in the same pass. This fingerprint covered (subject, axis, score);
    # the drift fingerprint covers (url, digest); the OpenTimestamps anchor covers the selection
    # rule. NONE covered the policy. So the coverage sweep held one operand of a two-operand
    # comparison fixed by convention rather than by any mechanism: move a cell AND its declaration
    # together and the figure sweep.py computes at run time mutations survive. A round-8 reviewer measured exactly that.
    #
    # ⚠️ WHAT THIS FIXES AND WHAT IT DOES NOT. Hashing the policy here means a policy edit
    # invalidates every emitted table and the build refuses until they are regenerated -- so the
    # edit is loud rather than silent. It does NOT make the policy externally anchored: it is
    # still the same repository, and moving evidence plus its declaration is two edits rather than
    # one. What makes the second visible is review of a diff, not a control in this toolchain.
    # ⛔ `kind` WAS NOT IN THIS TUPLE. It is the field the headline result is stated
    # over -- fully-open versus open-weights -- and it could be flipped without invalidating
    # one emitted table. The two keys added in round 10 were missing for the same reason: a
    # LIST of policy keys omits whatever is added after it is written, so this one fails
    # closed on any subject field it does not name.
    _POLICY_KEYS = policy_keys()
    _unlisted = sorted({k for s in led.get("subjects", []) for k in s} - set(_POLICY_KEYS))
    if _unlisted:
        raise SystemExit("⛔ subject record carries field(s) no policy key covers: %s."
                         " Add them to _POLICY_KEYS or the fingerprint does not cover the"
                         " policy." % _unlisted)
    pol = sorted(json.dumps({k: s.get(k) for k in _POLICY_KEYS}, sort_keys=True)
                 for s in led.get("subjects", []))
    return hashlib.sha256(NL.join(rows + pol).encode("utf-8")).hexdigest()


def emit_tables(led, sc):
    """Write tables/. NOTHING here may ever be typed into the manuscript by hand."""
    TABLES.mkdir(exist_ok=True)
    stamp = led.get("as_of", "undated")
    fp = ledger_fingerprint(led)

    t1 = ["| # | group | axis | may be N/A |", "|---|---|---|---|"]
    for i, g, name, _q, _s, na in A.AXES:
        t1.append(f"| {i} | {g} | {name} | {'yes' if na else 'no'} |")
    (TABLES / "table1_axes.md").write_text(
        f"<!-- EMITTED by mp_metric.py, as of {stamp}. Do not edit. -->" + NL +
        f"<!-- ledger-fingerprint: {fp} -->" + NL +
        NL.join(t1) + NL, encoding="utf-8", newline=NL)

    # Level names abbreviated to their scores: the paper defines 2/1/0 on its first page, and
    # the spelled-out header made this table nine columns wide and pushed it past the margin.
    t2 = ["| release | 2 | 1 | 0 | N/A | as-coded | N/A→0 | N/A→2 | ceiling |",
          "|---|---|---|---|---|---|---|---|---|"]
    for s in sorted(sc, key=lambda k: -sc[k]["as_coded"]):
        v = sc[s]
        t2.append("| %s | %d | %d | %d | %d | %.3f | %.3f | %.3f | %.3f |"
                  % (s, v["counts"][2], v["counts"][1], v["counts"][0], v["n_na"],
                     v["as_coded"], v["na_as_0"], v["na_as_2"], v["ceiling"]))
    (TABLES / "table2_scores.md").write_text(
        f"<!-- EMITTED by mp_metric.py, as of {stamp}. Do not edit. -->" + NL +
        f"<!-- ledger-fingerprint: {fp} -->" + NL +
        NL.join(t2) + NL +
        NL + "The three columns are the same census under three readings of N/A. The spread"
        " between" + NL + "`N/A→0` and `N/A→2` is the weight the escape hatch is carrying; where"
        " it is wide, the" + NL + "as-coded figure is not reportable on its own." + NL + NL +
        "`ceiling` is the highest as-coded score this release COULD reach: completeness and search"
        + NL + "axes cap at 1 for everyone, and an api-only release cannot publish weights at all."
        + NL + "Scores are not comparable across releases whose ceilings differ." + NL,
        encoding="utf-8", newline=NL)
    return [TABLES / "table1_axes.md", TABLES / "table2_scores.md"]


if __name__ == "__main__":
    # only the entry point touches stdout; importing this module must not.
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    led = load()
    print("=" * 78)
    print("  mp-metric — %d axes, %d subject(s), %d cell(s), as of %s"
          % (len(A.AXES), len(led.get("subjects", [])), len(led.get("cells", [])),
             led.get("as_of", "undated")))
    print("=" * 78)

    defects = validate(led)
    if defects:
        print(NL + "  %d DEFECT(S) — the census is NOT scoreable:" % len(defects))
        for x in defects[:40]:
            print("    ! %s" % x)
        if len(defects) > 40:
            print("    ... and %d more" % (len(defects) - 40))
        print(NL + "  Nothing was scored and no table was written. A partially-validated census")
        print("  reported as a score is worse than no census.")
        raise SystemExit(1)
    print(NL + "  validation: no defects")

    sc = score(led)
    if not sc:
        print("  no subjects yet — nothing to score")
        raise SystemExit(0)
    print()
    for s in sorted(sc, key=lambda k: -sc[k]["as_coded"]):
        v = sc[s]
        print("  %-28s as-coded %.3f   [N/A→0 %.3f, N/A→2 %.3f]   %d N/A"
              % (s, v["as_coded"], v["na_as_0"], v["na_as_2"], v["n_na"]))

    if "--check" not in sys.argv:
        for p in emit_tables(led, sc):
            print("  emitted %s" % p.relative_to(HERE).as_posix())
    print()
    print("  " + chr(0x26D4) + " NOT A RANKING. See NOT-A-RANKING.md; the sentence travels with"
          " the numbers.")
