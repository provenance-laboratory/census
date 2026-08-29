"""The NEGATIVE SEARCH protocol for axes 16 and 17, made re-runnable and falsifiable.

⛔ THE DEFECT THIS FIXES. Axes 16 and 17 ask whether an INDEPENDENT reproduction of the training
run has been reported. Every cell scored 0, and every note recorded the search bound as "the
release's own model card, repository README and paper". A third party's reproduction report is, by
definition, not in the publisher's own documents -- so the search could not have found one, and the
zero was guaranteed by the bound rather than by the world. Round-1 review asked for the protocol to
be named; naming it exposed that it was not a search.

WHAT THIS DOES INSTEAD. A bounded search of a corpus the publisher does not control, with every
query recorded so anyone can re-run it and contradict the result:

    corpus     arXiv, via the public API
    categories cs.CL or cs.LG -- REQUIRED, see the homonym note below
    terms      7 reproduction verbs, in the abstract (see TERMS)
    paging     every page fetched to exhaustion; an unstated cap is not a stated bound
    subject    the model's name, in the abstract

⚠️ HOMONYMS ARE WHY THE CATEGORY FILTER IS NOT OPTIONAL. abs:"Pythia" AND abs:"reproduce" returns
125 results, most of them particle physics: PYTHIA is a Monte Carlo event generator. Constrained to
cs.CL/cs.LG it returns 18. A protocol without the filter would have reported a large candidate set
of astrophysics papers and found no reproduction in it, which is true and meaningless.

⚠️ AND THE BOOLEAN FORM MATTERS. all:X AND all:Y is NOT honoured by the API -- it returns results
matching neither term. abs:"X" AND abs:"Y" is. This was found by reading the results of a query
whose answer looked plausible, which is the only way it is ever found.

⛔ WHAT A ZERO STILL DOES NOT MEAN. Not that nobody has reproduced these models. It means no such
report was found in this corpus, under these queries, on the date recorded. Reproduction reports
appear in venues arXiv does not index, in blog posts, and in papers whose abstract never says the
word. The bound is narrow; the point is that it is now WRITTEN DOWN AND CHECKABLE rather than
circular.

    python negative_search.py            run the protocol, write negative-search.json
    python negative_search.py --verify   check the stored result covers every subject
"""
import datetime as dt
import io
import json
import pathlib
import re
import sys
import time
import urllib.parse

import fetch_artifact as F
import mp_metric as M

NL = chr(10)
HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / "negative-search.json"
API = "https://export.arxiv.org/api/query?search_query=%s&start=%d&max_results=%d"
# ⚠️ THREE VERBS WAS TOO THIN. Round-2 review pointed out that `replication`,
# `reimplementation` and `from scratch` all name the thing and none were searched.
TERMS = ["reproduce", "reproduction", "replicate", "replication", "reimplementation",
         "from scratch", "independently trained"]
CATS = "(cat:cs.CL OR cat:cs.LG)"
PAGE = 100          # per request
MAX_PAGES = 12      # hard stop, so a runaway query cannot hang the protocol

# The string a paper would use to name each release. NOT derivable from the subject id -- nobody
# writes "llama-3.1-8b" in prose -- so it is a judgement, recorded here rather than improvised.
# ⚠️ PROJECTED, NOT ENUMERATED: names_for() raises on any subject missing an entry, so a subject
# added later cannot silently receive an unsearched zero.
NAMES = {
    "pythia-12b": "Pythia",
    "olmo-2-13b": "OLMo",
    "bloom-176b": "BLOOM",
    "mistral-7b-v0.3": "Mistral",
    "qwen2.5-7b": "Qwen2.5",
    "llama-3.1-8b": "Llama 3.1",
    "gemma-2-9b": "Gemma 2",
    "gpt-4o": "GPT-4o",
    "claude-3.5-sonnet": "Claude 3.5",
    "gemini-1.5-pro": "Gemini 1.5",
    "bert-base-uncased": "BERT",
    "gpt-2-1.5b": "GPT-2",
}

# A candidate is SCREENED IN if its abstract suggests it retrained or reproduced the model itself,
# rather than merely using it. Screening is deliberately GENEROUS: a false positive costs a human
# read, a false negative would silently restore the circular zero.
SIGNALS = [
    "reproduce the training", "reproduction of the training", "retrain", "re-train",
    "from scratch", "replicate the training", "reproduced the pretraining",
    "training run", "reproducibility study", "bit-identical", "bitwise identical",
]


def names_for(subject):
    if subject not in NAMES:
        raise KeyError("no search name for subject %r. Axes 16 and 17 would score 0 for it "
                       "without any search having been run. Add the name." % subject)
    return NAMES[subject]


def query(name, term, start=0):
    q = 'abs:"%s" AND abs:"%s" AND %s' % (name, term, CATS)
    return API % (urllib.parse.quote(q, safe=""), start, PAGE)


def parse(xml):
    total = re.search(r"opensearch:totalResults[^>]*>(\d+)<", xml)
    entries = []
    for blk in re.findall(r"<entry>(.*?)</entry>", xml, re.S):
        t = re.search(r"<title>(.*?)</title>", blk, re.S)
        a = re.search(r"<summary>(.*?)</summary>", blk, re.S)
        i = re.search(r"<id>(.*?)</id>", blk, re.S)
        entries.append({
            "id": (i.group(1).strip() if i else ""),
            "title": " ".join(t.group(1).split()) if t else "",
            "abstract": " ".join(a.group(1).split()) if a else "",
        })
    return (int(total.group(1)) if total else None), entries


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    led = M.load()
    subjects = [s["id"] for s in led.get("subjects", [])]

    if "--verify" in sys.argv:
        if not OUT.exists():
            print("  " + chr(0x26D4) + " negative-search.json is missing -- run the protocol")
            return 1
        res = json.loads(OUT.read_text(encoding="utf-8"))
        missing = [s for s in subjects if s not in res["subjects"]]
        # Round-2 review: the verifier proved only that every subject was searched. It must also
        # refuse an INCOMPLETE retrieval and an UNADJUDICATED candidate set -- the two ways a
        # negative can be produced by the method rather than by the world.
        trunc = ["%s/%s (%s of %s)" % (sid, q["term"], q.get("retrieved"), q.get("total"))
                 for sid, r in res["subjects"].items()
                 for q in r["queries"] if q.get("total") and not q.get("complete")]
        unadj = [sid for sid, r in res["subjects"].items() if not r.get("adjudication")]
        for x in trunc:
            print("  ! TRUNCATED query: %s" % x)
        for x in unadj:
            print("  ! %s has candidates and NO recorded adjudication" % x)
        print("  %d subject(s) in the census, %d covered by the search"
              % (len(subjects), len(res["subjects"])))
        for m in missing:
            print("  ! %s scores 0 on axes 16/17 with NO search recorded" % m)
        print("  " + ("every subject was searched" if not missing
                      else chr(0x26D4) + " %d unsearched" % len(missing)))
        return 1 if (missing or trunc or unadj) else 0

    out = {
        "_readme": "The negative-search protocol behind every 0 on axes 16 and 17. "
                   "See negative_search.py for what a 0 does and does not mean.",
        "protocol": {
            "corpus": "arXiv public API",
            "categories": CATS,
            "terms": TERMS,
            "page_size": PAGE,
            "paginated": True,
            "max_pages": MAX_PAGES,
            "screened_for": SIGNALS,
        },
        "subjects": {},
    }

    for s in subjects:
        name = names_for(s)
        rec = {"name": name, "queries": [], "candidates": [], "screened_in": []}
        for term in TERMS:
            # ⛔ max_results=50 WITH NO PAGINATION WAS AN UNSTATED BOUND. The deposited JSON
            # showed 735 hits reported and 635 retrieved: 100 abstracts, 14% of the pool, never
            # fetched. The worst query was bert + reproduce -- 97 hits, 50 retrieved, 47 unseen --
            # on the one subject whose cell changed. Section 7.1 exists to insist that a bound be
            # STATED; this one was ACCIDENTAL, which is worse than a narrow stated bound.
            start, total, got = 0, None, 0
            for _page in range(MAX_PAGES):
                url = query(name, term, start)
                status, body, err = F.fetch(url)
                if err:
                    print("  %-20s %-20s FETCH FAILED: %s" % (s, term, err))
                    rec["queries"].append({"term": term, "url": url, "error": err})
                    break
                xml = body.decode("utf-8", "replace")
                total, entries = parse(xml)
                have = set(c["id"] for c in rec["candidates"])
                for e in entries:
                    if e["id"] not in have:
                        rec["candidates"].append(e)
                        have.add(e["id"])
                got += len(entries)
                if not entries or total is None or start + PAGE >= total:
                    break
                start += PAGE
                time.sleep(3)
            if total is not None:
                rec["queries"].append({"term": term, "total": total, "retrieved": got,
                                       "complete": got >= total,
                                       "url": query(name, term, 0)})
                print("  %-20s %-20s total=%-5s retrieved=%-4d %s"
                      % (s, term, total, got, "" if got >= total else "⛔ TRUNCATED"))
            time.sleep(3)

        for c in rec["candidates"]:
            hit = [g for g in SIGNALS if g in c["abstract"].lower()]
            if hit:
                rec["screened_in"].append({"id": c["id"], "title": c["title"], "signals": hit})
        out["subjects"][s] = rec
        print("  %-20s %d candidate(s), %d screened in for reading"
              % (s, len(rec["candidates"]), len(rec["screened_in"])))
        print()

    out["run_at"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    OUT.write_text(json.dumps(out, indent=2) + NL, encoding="utf-8", newline=NL)
    tot = sum(len(v["candidates"]) for v in out["subjects"].values())
    sin = sum(len(v["screened_in"]) for v in out["subjects"].values())
    print("=" * 78)
    print("  %d subject(s), %d candidate(s), %d screened in for human reading"
          % (len(out["subjects"]), tot, sin))
    print("  " + chr(0x26A0) + " SCREENED IN IS NOT A FINDING. Each must be read; the abstract")
    print("  signal only says the paper is worth a human's time.")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
