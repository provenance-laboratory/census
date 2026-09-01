"""What does the cs.CL/cs.LG filter EXCLUDE, and is any of it a reproduction report?

Read-only. Writes nothing into the census. This measures a BOUND, to decide whether the bound must
be re-run; it is not evidence for any cell.

⚠️ THE ADJUDICATION IS NOT MECHANICAL. Counting what the filter removes is arithmetic. Deciding
whether any removed paper REPORTS A REPRODUCTION needs reading, and this script does not pretend
otherwise -- it screens for the subject's name and a reproduction verb in the same abstract and
prints the survivors for a human to read.
"""
import json
import pathlib
import re
import sys
import time
import urllib.parse
import urllib.request

D = chr(0x26D4)
W = chr(0x26A0)
# ⛔ THIS WAS AN ABSOLUTE PATH TO THE AUTHOR'S DISK. Run from the deposit it died on
# the first read, so the tool behind the round-17 headline claim could not be executed by
# anyone but the author -- which is the definition of an ASSERTED cell, in a paper whose
# subject is that distinction. Every other tool in this census resolves relative to itself.
C = pathlib.Path(__file__).resolve().parent
UA = "mp-metric-bound-probe (mailto:parthms.id@gmail.com)"
POLITE = 3.1
API = ("https://export.arxiv.org/api/query?search_query=%s&start=0&max_results=100")

# the distinct probes, from the measurement rather than retyped
SE = json.loads((C / "stem-equivalence.json").read_text(encoding="utf-8"))
TERMS = [g["terms"][0] for g in SE["groups"]]

NS = json.loads((C / "negative-search.json").read_text(encoding="utf-8"))
SUBJ = {}
for k, v in (NS["subjects"].items() if isinstance(NS["subjects"], dict)
             else [(s.get("subject"), s) for s in NS["subjects"]]):
    # ⛔ AND  STOPPED AT THE %20 IN A MULTI-WORD LABEL, so "Llama 3.1" and "Claude 3.5"
    # matched nothing at all and the probe fell back to the subject key. Non-greedy to the
    # closing quote instead.
    # the url carries TWO abs:"..." terms and their order is not fixed. Taking the first gave
    # 'reproduce' as the model name for four subjects, which queried abs:"reproduce" AND
    # abs:"reproduce" and returned an identical 203 candidates for all four -- the same
    # identical-numbers tell that exposed the stem collapse, this time in my own probe.
    q = v["queries"][0]["url"]
    found = [urllib.parse.unquote(x) for x in re.findall(r"abs%3A%22(.+?)%22", q)]
    verbs = {e["term"] for e in v["queries"]}
    names = [x for x in found if x not in verbs]
    if len(names) != 1:
        raise SystemExit("cannot identify the subject label for %s from %r" % (k, found))
    SUBJ[k] = names[0]

cells = json.loads((C / "cells.json").read_text(encoding="utf-8"))["cells"]
ZERO = sorted({c["subject"] for c in cells if c["axis"] in (16, 17) and c["score"] == 0})


ARCHIVE = C / "filter-probe-archive.json"
FILTERED = C / "negative-search-archive.json"
STORE = C / "evidence"


def _stored(sha):
    import gzip
    f = STORE / (sha + ".gz")
    return gzip.decompress(f.read_bytes()).decode("utf-8", "replace") if f.exists() else None


def _offline_index():
    """url -> archived body, for both the filtered and unfiltered sweeps.

    ⛔ THE PRODUCER OF THIS PAPER'S NEWEST BOUND NEEDED THE NETWORK AND AN ABSOLUTE PATH INTO ONE
    MACHINE. A round-17 reviewer ran it from the deposit and got FileNotFoundError, which made the
    strongest new claim in the paper an ASSERTED one by the census's own definition. The unfiltered
    responses are archived now, the same way the filtered ones have been since round 3, and this
    reads them.
    """
    idx = {}
    for f, key in ((ARCHIVE, "subjects"), (FILTERED, "subjects")):
        if not f.exists():
            continue
        for _sub, rows in json.loads(f.read_text(encoding="utf-8")).get(key, {}).items():
            for r in rows:
                b = _stored(r.get("sha256", ""))
                if b is not None:
                    idx[r["url"]] = b
    return idx


_IDX = None
_FROM_NET = False
# ⚠ POLITENESS IS FOR THE NETWORK. The delay ran on archive reads too,
# so a fully offline recomputation waited seven minutes for nothing.


def fetch(q, url=None):
    """⚠ OFFLINE FIRST. The network is the fallback, not the source: a reader must be able to
    recompute this from the deposit alone, and an author must not be able to get a different
    answer by being online."""
    global _IDX
    if _IDX is None:
        _IDX = _offline_index()
    u = url or (API % urllib.parse.quote(q, safe=""))
    if u in _IDX:
        global _FROM_NET
        _FROM_NET = False
        return _IDX[u]
    if "--offline" in sys.argv:
        raise SystemExit(D + " %s is not in the archive and --offline was given. Run "
                         "archive_filter_probe.py first." % u[:80])
    _FROM_NET = True
    req = urllib.request.Request(u, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=90) as r:
        return r.read().decode("utf-8", "replace")


def entries(body):
    out = {}
    for m in re.finditer(r"<entry>(.*?)</entry>", body, re.S):
        e = m.group(1)
        i = re.search(r"<id>([^<]+)</id>", e)
        t_ = re.search(r"<title>(.*?)</title>", e, re.S)
        s = re.search(r"<summary>(.*?)</summary>", e, re.S)
        if i:
            out[i.group(1).strip()] = (" ".join((t_.group(1) if t_ else "").split()),
                                       " ".join((s.group(1) if s else "").split()))
    return out


VERB = re.compile(r"\b(reproduc\w+|replicat\w+|reimplement\w+|from scratch|independently trained)\b",
                  re.I)

print("  %d subject(s) score 0 on axis 16 or 17. Probing what the filter removes." % len(ZERO))
print("  %d distinct term(s): %s" % (len(TERMS), ", ".join(TERMS)))
print()

report = {}
for name in ZERO:
    label = SUBJ.get(name, name)
    new_hits = {}
    for term in TERMS:
        base = 'abs:"%s" AND abs:"%s"' % (label, term)
        try:
            filt = entries(fetch(base + " AND (cat:cs.CL OR cat:cs.LG)"))
            if _FROM_NET:
                time.sleep(POLITE)
            unfilt = entries(fetch(base))
            if _FROM_NET:
                time.sleep(POLITE)
        except Exception as e:                                              # noqa: BLE001
            print("  %s %s / %s: %s" % (D, name, term, str(e)[:60]))
            continue
        for k, (ti, ab) in unfilt.items():
            if k in filt:
                continue
            # screen: the subject's name AND a reproduction verb in the same abstract
            if re.search(re.escape(label), ab, re.I) and VERB.search(ab):
                new_hits[k] = ti
    report[name] = new_hits
    print("  %-20s %d excluded paper(s) mention it AND a reproduction verb" % (name, len(new_hits)))
    for k, ti in list(new_hits.items())[:4]:
        print("       %s" % ti[:96])
        print("       %s" % k)

# ⛔ `sys.argv[1]` TOOK THE FLAG AS A FILENAME. The documented command is
# `python filter_diff.py --offline`, and this wrote its report to a file literally named
# `--offline` while leaving `filter-diff.json` -- the input `filter_categories.py` reads, and the
# chain section 8's figures come from -- untouched. So the advertised re-run exited 0 and could
# never refresh the thing it was advertised to refresh; a reviewer set
# `filter-bound.json["distinct_excluded"]` to 999 and the command still went green. The junk file
# was committed, in the commit titled "the filter bound is recomputable, not taken".
_args = [a for a in sys.argv[1:] if not a.startswith("--")]
out = C / (_args[0] if _args else "filter-diff.json")
out.write_text(json.dumps(report, indent=2) + chr(10), encoding="utf-8")
print()
print("  wrote %s" % out)
print("  " + W + " These are CANDIDATES for reading, not findings. The screen is a name and a")
print("  verb in one abstract, which is exactly the mechanical half; whether any of them")
print("  actually REPORTS a reproduction of the subject is the half that needs a person.")
