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
import pathlib
import sys

NL = chr(10)
HERE = pathlib.Path(__file__).resolve().parent
LEDGER = HERE / "cells.json"
SEARCH = HERE / "negative-search.json"

AXIS_WORD = {16: "bit-identical", 17: "approximate"}


def note_for(sub, rec, axis, run_at):
    """The note states what was RUN and what remains UNDONE.

    ⛔ An earlier draft of this template ended '...were screened in and read; none reported
    reproducing the training run itself'. Nothing had been read. That sentence would have been a
    fabricated adjudication sitting inside the very control built to stop the zero being circular.
    """
    qs = [q for q in rec["queries"] if "error" not in q]
    totals = ", ".join("%s=%s" % (q["term"], q["total"]) for q in qs)
    n2 = len(rec.get("stage2", []))
    return (
        "No independent %s reproduction report was IDENTIFIED. "
        "SEARCH: arXiv, categories (cat:cs.CL OR cat:cs.LG), abstract queries for %r AND each of "
        "reproduce / reproduction / replicate, run %s (hits %s). %d distinct candidates; %d "
        "survive a second screen requiring the model name and a reproduction verb in the same "
        "sentence. "
        "%s "
        "⚠ NOT-FOUND-WITHIN-A-STATED-BOUND, NOT GLOBAL ABSENCE, and the bound is narrow: arXiv "
        "does not index every venue, and a reproduction report need not use these words. "
        "Queries and candidates are in negative-search.json so this can be re-run and "
        "contradicted."
        % (AXIS_WORD[axis], rec["name"], run_at[:10], totals,
           len(rec["candidates"]), n2,
           ("⛔ THE SURVIVORS HAVE NOT BEEN INDIVIDUALLY ADJUDICATED, so this cell is a "
            "NOT-IDENTIFIED, not a verified absence." if n2 else
            "No candidate survived the second screen.")))


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
