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
    return json.loads(LEDGER.read_text(encoding="utf-8"))


def validate(led):
    """Return a list of defects. ANY defect means the census is not scoreable.

    Fails CLOSED: a subject-axis pair that is simply missing is a defect, not a zero. An absent
    cell and a cell scored 0 are different claims -- 'nobody looked' is not 'we looked and found
    nothing' -- and writing them identically is how a census becomes an opinion.
    """
    d = []
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

        # ⛔ VERIFIED requires a REGISTERED method, not a sentence. Round-1 review passed every
        # score-2 cell with check="read a document" and this validator reported no defect.
        if val == 2:
            chk = c.get("check")
            if not isinstance(chk, dict):
                d.append(f"{where}: VERIFIED requires a `check` OBJECT "
                         f"{{method, asserts, observed}}; a free-text string is not a control")
            else:
                meth = str(chk.get("method", ""))
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
                _req = A.required_method(ax)
                if _req and meth not in _req:
                    d.append(f"{where}: axis {ax} REQUIRES {sorted(_req)}; {meth!r} is registered "
                             f"and permitted but does not bind this axis's identity")
                # A cell missing what its own method needs is a DEFECT, not a weaker cell. Deleting
                # `expect_range_bytes` used to demote the check to unreplayable and leave the
                # evidence unconstrained.
                for _f in A.required_fields(meth):
                    if not chk.get(_f):
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

    # ⛔ THE SAME URL MAY NOT CARRY TWO DIGESTS. Round-1 review showed a census validating with
    # one url recorded under conflicting hashes -- and recheck.py silently used the first, so the
    # contradiction was invisible on both sides.
    seen_url = {}
    for c in led.get("cells", []):
        for e in (c.get("evidence") or []):
            u, h = e.get("url"), e.get("sha256")
            if u in seen_url and seen_url[u][0] != h:
                d.append(f"{u}: recorded with two different digests "
                         f"({seen_url[u][0][:12]} at {seen_url[u][1]}, {str(h)[:12]} at "
                         f"{c.get('subject')}/axis{c.get('axis')}) -- one of them is wrong")
            elif u not in seen_url:
                seen_url[u] = (h, f"{c.get('subject')}/axis{c.get('axis')}")

    # ⛔ AND THE MIRROR OF IT. The rule above refuses one url under two digests. The reverse --
    # one DIGEST under two urls -- is how a cell keeps a truthful-looking url while its bytes are
    # replaced by another artifact's: the url still anchors, and the recorded digest still matches
    # the archived bytes, because BOTH were swapped. Offline, the tell is that the same bytes are
    # now claimed to have come from two different places. Round-6 review demonstrated it on olmo's
    # corpus cell using bert's weight range.
    seen_sha = {}
    for c in led.get("cells", []):
        for e in (c.get("evidence") or []):
            h, u = e.get("sha256"), e.get("url")
            if h in seen_sha and seen_sha[h][0] != u:
                d.append(f"digest {str(h)[:12]} is cited under TWO different urls "
                         f"({seen_sha[h][0][:58]} at {seen_sha[h][1]}, and {str(u)[:58]} at "
                         f"{c.get('subject')}/axis{c.get('axis')}) -- the same bytes cannot have "
                         f"been retrieved from both")
            elif h not in seen_sha:
                seen_sha[h] = (u, f"{c.get('subject')}/axis{c.get('axis')}")

    # PROJECT over subjects x axes: every pair must be present.
    for s in subjects:
        for ax in A.BY_ID:
            if (s, ax) not in seen:
                d.append(f"{s}/axis{ax} ({A.BY_ID[ax][2]}): MISSING -- absent is not zero")
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
    return hashlib.sha256(NL.join(rows).encode("utf-8")).hexdigest()


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
