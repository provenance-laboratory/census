"""Recompute filter-bound.json from the archived responses. Offline, and from bytes.

⛔ WHY THIS EXISTS. `filter-bound.json` carried the figures section 8 turns on, and it was written
by a scratchpad script that no longer existed. A round-18 reviewer set `distinct_excluded` to 999
in a disposable extraction, ran the documented command, and it exited 0 -- because nothing
recomputed the record, and the tool that reads it simply trusted it. A number the manuscript
depends on, with no producer in the deposit, is an ASSERTED cell by this census's own definition.

⚠️ THE ADJUDICATION IS STILL NOT MECHANICAL. Counting is arithmetic; deciding whether an excluded
paper REPORTS a reproduction of the subject needs reading, and the twelve title-matching
candidates were read by hand. That half is recorded, not computed, and says so.

    python build_filter_bound.py            recompute and write
    python build_filter_bound.py --verify   recompute and refuse if the record disagrees
"""
import io
import json
import pathlib
import re
import sys

NL = chr(10)
D = chr(0x26D4)
W = chr(0x26A0)
HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / "filter-bound.json"
ML = {"cs.CV", "cs.AI", "cs.SE", "cs.IR", "cs.RO", "cs.HC", "cs.NE", "cs.MA", "cs.CR", "cs.DC",
      "cs.DB", "cs.PF", "stat.ML"}
VERB = re.compile(r"reproduc|replicat|reimplement|from scratch", re.I)


def compute():
    fd = json.loads((HERE / "filter-diff.json").read_text(encoding="utf-8"))
    fc = json.loads((HERE / "filter-cats.json").read_text(encoding="utf-8"))
    cats = fc["cats"]
    per, titled = {}, 0
    for subj, hits in sorted(fd.items()):
        tot = adj = t_ = 0
        for url, ti in hits.items():
            m = re.search(r"abs/(.+)$", url)
            tot += 1
            if m and cats.get(m.group(1)) in ML:
                adj += 1
                if VERB.search(ti):
                    t_ += 1
        titled += t_
        per[subj] = {"excluded": tot, "adjacent_cs_ml": adj,
                     "adjacent_with_reproduction_word_in_title": t_}
    distinct = len(cats)
    distinct_adj = sum(1 for c in cats.values() if c in ML)
    return per, distinct, distinct_adj, titled


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace",
                                  line_buffering=True)
    per, distinct, distinct_adj, titled = compute()
    rec = {
        "_readme": ("What the cs.CL/cs.LG category filter removes, recomputed from the archived "
                    "responses by build_filter_bound.py. Every figure here is derived; the "
                    "adjudication below is not."),
        "method": ("For each subject scoring 0 on axis 16 or 17, every distinct probe term was run "
                   "WITH and WITHOUT the category filter, EVERY ARCHIVED PAGE of each is read, and "
                   "each survivor's primary category was fetched and archived."),
        "headline": ("The justification is true for exactly ONE subject. %d of Pythia's %d excluded "
                     "papers are in an adjacent CS/ML category; for the other eleven the exclusions "
                     "are overwhelmingly neighbouring ML literature."
                     % (per["pythia-12b"]["adjacent_cs_ml"], per["pythia-12b"]["excluded"])),
        "does_it_change_any_score": (
            "No. %d adjacent-category exclusions carry a reproduction word in the title; those "
            "were read, and none reports an independent reproduction of the subject model. They "
            "reproduce a paper or system that USES it, or are homonyms of the verb -- 'state "
            "machine REPLICATION', 'assisted REPRODUCTIVE technology'." % titled),
        "limits": (
            W + " The screen is mechanical (a name and a verb in one abstract); the adjudication "
            "is not. A reproduction reported without any of these verbs in its abstract is "
            "invisible to the probe and to the census alike. " + D + " AND THE EARLIER VERSION OF "
            "THIS RECORD DECLARED ONLY THAT BOUND while silently carrying another: the consumer "
            "read page one of a paginated archive, so 'every distinct probe term was run' "
            "described a first-100 window nobody had declared. That is section 7.1's own sentence "
            "about an accidental bound reported as a complete search."),
        "counting": ("Per-subject rows are subject-paper PAIRS; a paper matching two subjects "
                     "appears twice. distinct_excluded and distinct_adjacent_cs_ml are papers."),
        "distinct_excluded": distinct,
        "distinct_adjacent_cs_ml": distinct_adj,
        "per_subject": per,
        "adjudication": {"read": titled, "reproduce_the_subject_model": 0},
    }
    print("  distinct excluded %d, of which adjacent CS/ML %d" % (distinct, distinct_adj))
    print("  pythia %d of %d adjacent; qwen %d of %d"
          % (per["pythia-12b"]["adjacent_cs_ml"], per["pythia-12b"]["excluded"],
             per["qwen2.5-7b"]["adjacent_cs_ml"], per["qwen2.5-7b"]["excluded"]))
    if "--verify" in sys.argv:
        if not OUT.exists():
            print("  " + D + " %s is absent." % OUT.name)
            return 1
        old = json.loads(OUT.read_text(encoding="utf-8"))
        drift = [k for k in ("distinct_excluded", "distinct_adjacent_cs_ml", "per_subject",
                             "adjudication") if old.get(k) != rec[k]]
        if drift:
            print("  " + D + " the record disagrees with the archive on: %s" % ", ".join(drift))
            return 1
        print("  ok  the record matches what the archived responses say.")
        return 0
    OUT.write_text(json.dumps(rec, indent=1) + NL, encoding="utf-8", newline="\n")
    print("  wrote %s" % OUT.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
