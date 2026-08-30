"""Archive every arXiv query the reproduction search made, so its zeros replay offline.

⛔ WHY. `negative-search.json` records what each query returned -- totals, candidates,
adjudications -- and the queries themselves are LIVE urls against a growing corpus. A round-14
reviewer proposed binding the 22 axis-16/17 zeros to that protocol, which is right and takes
coverage from 13 of 182 to 35. But under the rule that reviewer's own critique motivated, a bound
whose every search location is live has nothing anybody can re-run offline -- which is the ceremony
they objected to, wearing a different noun.

⇒ So the responses are archived. That does not freeze arXiv, and it is not meant to: the claim a
bound can carry is *"on this date, these queries returned these results"*, and archiving the
responses is exactly what makes that claim checkable a year later without trusting this record.

⭐ AND THE PROTOCOL CARRIES ITS OWN POSITIVE CONTROL. Two cells on axis 17 score 1, not 0, because
this same search FOUND reproduction reports for BERT and GPT-2. A search that has returned
positives in the census it is used on is not a search that could only ever return nothing.

⚠️ POLITE BY DEFAULT. arXiv asks for a delay between requests; this waits 3 seconds and fetches
each query once.

    python archive_negative_search.py
    python archive_negative_search.py --verify    check stored bytes, fetch nothing
"""
import gzip
import hashlib
import io
import json
import pathlib
import sys
import time
import urllib.request

NL = chr(10)
D = chr(0x26D4)
W = chr(0x26A0)
HERE = pathlib.Path(__file__).resolve().parent
STORE = HERE / "evidence"
DELAY = 3.0


def queries():
    """Every (subject, term, url) the protocol recorded. Projected, never retyped."""
    n = json.loads((HERE / "negative-search.json").read_text(encoding="utf-8"))
    out = []
    for sub, rec in sorted(n["subjects"].items()):
        for q in rec.get("queries") or []:
            if q.get("url"):
                out.append((sub, q["term"], q["url"], q))
    return out


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace",
                                  line_buffering=True)
    verify = "--verify" in sys.argv
    man = json.loads((STORE / "MANIFEST.json").read_text(encoding="utf-8"))
    qs = queries()
    print("=" * 78)
    print("  ARXIV QUERY RESPONSES -- %d, from %d subject(s)"
          % (len(qs), len({s for s, _t, _u, _q in qs})))
    print("=" * 78)
    print()

    index, bad, fetched = {}, [], 0
    for i, (sub, term, url, q) in enumerate(qs):
        known = man["artifacts"].get(url)
        blob = STORE / ((known or {}).get("sha256", "") + ".gz") if known else None
        if known and blob.exists():
            raw = gzip.decompress(blob.read_bytes())
            if hashlib.sha256(raw).hexdigest() != known["sha256"]:
                bad.append("%s/%s: stored bytes do not hash to the manifest digest" % (sub, term))
                continue
        elif verify:
            bad.append("%s/%s: not archived, and --verify fetches nothing" % (sub, term))
            continue
        else:
            time.sleep(DELAY if fetched else 0)
            try:
                raw = urllib.request.urlopen(urllib.request.Request(
                    url, headers={"User-Agent": "mp-metric-census/1.0"}), timeout=90).read()
            except Exception as e:                                          # noqa: BLE001
                bad.append("%s/%s: %s" % (sub, term, str(e)[:60]))
                continue
            fetched += 1
            sha = hashlib.sha256(raw).hexdigest()
            (STORE / (sha + ".gz")).write_bytes(gzip.compress(raw, mtime=0))
            man["artifacts"][url] = {
                "bytes": len(raw), "cells": [], "sha256": sha, "stored": True,
                "note": ("one arXiv API query from the reproduction search. Archived so an "
                         "axis-16/17 zero can be re-run offline against what the corpus returned "
                         "ON THE DATE SEARCHED, rather than against a live corpus that has since "
                         "grown."),
            }
        sha = hashlib.sha256(raw).hexdigest()
        # <opensearch:totalResults> is what the protocol recorded as `total`
        import re as _re
        m = _re.search(rb"<opensearch:totalResults[^>]*>(\d+)<", raw)
        total = int(m.group(1)) if m else None
        if total is not None and q.get("total") is not None and total != q["total"]:
            print("  %s %-18s %-22s archived total %s, protocol recorded %s"
                  % (W, sub, term, total, q["total"]))
        index.setdefault(sub, []).append(
            {"term": term, "url": url, "sha256": sha, "bytes": len(raw),
             "total_in_response": total, "total_recorded": q.get("total")})

    for sub, rows in index.items():
        for r in rows:
            key = r["url"]
            cells = set(man["artifacts"][key].get("cells") or [])
            cells |= {"%s/axis16" % sub, "%s/axis17" % sub}
            man["artifacts"][key]["cells"] = sorted(cells)

    if not verify:
        (STORE / "MANIFEST.json").write_text(json.dumps(man, indent=2, sort_keys=True) + NL,
                                             encoding="utf-8", newline=NL)
        (HERE / "negative-search-archive.json").write_text(
            json.dumps({"_readme": __doc__.strip().split(NL + NL)[1],
                        "as_of": "2026-08-31", "queries": len(qs), "subjects": index},
                       indent=2, sort_keys=True) + NL, encoding="utf-8", newline=NL)

    print()
    print("  %d query response(s) covered, %d newly fetched" % (len(qs) - len(bad), fetched))
    if bad:
        print("  " + D + " %d problem(s):" % len(bad))
        for b in bad[:6]:
            print("      %s" % b)
        return 1
    print("  every recorded query has archived bytes that hash to the manifest")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
