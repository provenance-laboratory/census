"""Rewrite the axis-16/17 notes to record the search that was ACTUALLY run.

⛔ WHY THE OLD NOTES WERE WRONG. They recorded the search bound as "the release's own model card,
repository README and paper". An INDEPENDENT reproduction report is by definition not in the
publisher's own documents, so that bound could not have found one. The zero followed from the
bound, not from the world -- a negative result guaranteed by its own method.

This script replaces each note with the corpus, the exact queries, the candidate count and the
screening outcome from negative-search.json, so a reader can re-run the queries and contradict the
cell. It NEVER changes a score: a search finding nothing is not a licence to rescore, and a search
finding something is a finding for a human to read, not for a script to act on.

    python apply_negative_search.py --dry-run     show what would change
    python apply_negative_search.py               write cells.json
"""
import io
import json
import re
import pathlib
import sys

NL = chr(10)
HERE = pathlib.Path(__file__).resolve().parent
LEDGER = HERE / "cells.json"
SEARCH = HERE / "negative-search.json"

AXIS_WORD = {16: "bit-identical", 17: "approximate"}


_AFFECTS = re.compile(r"axis\s*(\d+)")


def affected_axes(hit):
    """Which axes a positive adjudication bears on -- READ OUT of the record, never inferred.

    ⛔ THE POSITIVE PATH WROTE ITS OWN OPPOSITE, AND A REVIEWER DEMONSTRATED IT. `note_for` tested
    `if (hit and axis == 17)`, so a hit was a positive for axis 17 BY DEFINITION and a negative for
    axis 16 BY DEFINITION. Handed a synthetic adjudication explicitly reporting a BIT-IDENTICAL
    reproduction, with a reference digest and artifacts, it emitted:

        axis 16: No independent bit-identical reproduction report was identified.
        axis 17: An independent approximate reproduction report WAS found.

    -- the one disposition the census exists to detect, converted into its own absence and filed
    under the wrong axis, in the machinery built to find it. Twelve axis-16 zeros appeared to have
    a positive-capable search behind them and did not.

    ⚠ THE DISPOSITION WAS IN THE DATA THE WHOLE TIME. Every adjudicated hit carries
    `affects`, and both real records say "axis 17 only". The code read the axis number it had been
    handed instead of the field the adjudicator wrote, which is the difference between routing a
    result and assuming one.

    => FAILS CLOSED. A hit whose `affects` names no axis this note covers is a REFUSAL, because the
    alternative is what happened: an unrouted positive silently becomes two negatives, and every
    check downstream passes.
    """
    raw = str(hit.get("affects") or "").strip()
    axes = {int(x) for x in _AFFECTS.findall(raw)} & set(AXIS_WORD)
    if not axes:
        # ⚠ THIS LINE READ `D + " ..."` AND `D` IS NOT DEFINED IN THIS MODULE, so the
        # refusal raised NameError instead of speaking -- a control that crashes rather than
        # reports, found by the first probe that took the branch. Every other message here
        # spells the character inline; this one borrowed a name from a neighbouring file.
        raise SystemExit(
            chr(0x26D4) + " an adjudicated HIT declares affects=%r, which names none of axes %s. A positive "
            "that cannot be routed is written as an absence on every axis, which is how the one "
            "result this search exists to find disappears into the notes it produces."
            % (raw, sorted(AXIS_WORD)))
    return axes


def note_for(sub, rec, axis, run_at):
    """The note states what was RUN, what was FOUND, and what remains undone.

    ⛔ An earlier draft ended '...were screened in and read; none reported reproducing the training
    run itself'. Nothing had been read. That would have been a fabricated adjudication sitting
    inside the control built to stop the zero being circular. The survivors have since been read,
    and the verdict -- including the one hit -- comes from negative-search.json, not from here.
    """
    qs = [q for q in rec["queries"] if "error" not in q]
    totals = ", ".join("%s=%s" % (q["term"], q["total"]) for q in qs)
    n2 = len(rec.get("stage2", []))
    adj = rec.get("adjudication") or {}
    hit = adj.get("hit")

    positive = bool(hit) and axis in affected_axes(hit)
    head = ("An independent %s reproduction report WAS found." % AXIS_WORD[axis]
            if positive else
            "No independent %s reproduction report was identified." % AXIS_WORD[axis])

    body = (
        "SEARCH: arXiv, categories (cat:cs.CL OR cat:cs.LG), abstract queries for %r AND each of "
        "reproduce / reproduction / replicate, run %s (hits %s). %d distinct candidates; %d "
        "survive a second screen requiring the model name and a reproduction verb in the same "
        "sentence, and all %d were read."
        % (rec["name"], run_at[:10], totals, len(rec["candidates"]), n2, n2))

    if positive:
        found = (" FOUND: %s, %s -- %r. %s"
                 % (hit["title"], hit["url"], hit["quote"], adj["rationale"]))
    else:
        found = " " + adj.get("rationale", "No adjudication recorded.")

    tail = ("⚠ NOT-FOUND-WITHIN-A-STATED-BOUND, NOT GLOBAL ABSENCE, and the bound is narrow: arXiv "
            "does not index every venue, and a reproduction report need not use these words. "
            "Queries, candidates and verdicts are in negative-search.json so this can be re-run "
            "and contradicted.")
    return head + " " + body + found + " " + tail


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    if not SEARCH.exists():
        print("  " + chr(0x26D4) + " negative-search.json is missing -- run negative_search.py")
        return 1
    res = json.loads(SEARCH.read_text(encoding="utf-8"))
    led = json.loads(LEDGER.read_text(encoding="utf-8"))

    changed = 0
    unsearched = []
    for c in led["cells"]:
        if c["axis"] not in AXIS_WORD:
            continue
        rec = res["subjects"].get(c["subject"])
        if not rec:
            unsearched.append("%s/axis%d" % (c["subject"], c["axis"]))
            continue
        new = note_for(c["subject"], rec, c["axis"], res["run_at"])
        if c.get("note") != new:
            c["note"] = new
            changed += 1
            print("  %s/axis%d" % (c["subject"], c["axis"]))

    # FAIL CLOSED. A cell scoring 0 for "no reproduction found" with no search behind it is exactly
    # the defect this script exists to remove; it must not be left in place silently.
    if unsearched:
        print()
        print("  " + chr(0x26D4) + " %d cell(s) score 0 with NO search recorded:" % len(unsearched))
        for u in unsearched:
            print("      %s" % u)
        print("  Refusing to write. Add them to negative_search.NAMES and re-run the protocol.")
        return 1

    if "--dry-run" in sys.argv:
        print()
        print("  %d note(s) would change; nothing written (--dry-run)" % changed)
        return 0

    LEDGER.write_text(json.dumps(led, indent=2) + NL, encoding="utf-8", newline=NL)
    print()
    print("  %d note(s) rewritten. NO SCORE WAS CHANGED." % changed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
