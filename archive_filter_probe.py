"""Archive the UNFILTERED responses, so the filter's cost is re-runnable and not merely asserted.

⛔ WHY THIS EXISTS. The paper states what the `cs.CL OR cs.LG` category filter excludes -- 0 of
Pythia's 91 exclusions are adjacent CS/ML, against 42 of 43 for Qwen2.5 -- and those figures came
from live queries whose responses were never stored. Two round-16 reviewers said the same thing
independently: the measurement that SIZES the filter's cost was in exactly the position of the
zeros it was defending, real and stated and not re-runnable from the deposit.

⇒ The filtered responses have been archived since round 3. These are their unfiltered counterparts,
stored the same way, named by digest, so `filter_diff.py --offline` recomputes the difference set
from bytes rather than from the network.

⚠️ PAGINATED TO EXHAUSTION AND CHECKED BY COUNTING, not by reading a header. The sibling archiver
stored one page of a 121-result query for four rounds because it compared a header to the
protocol's copy of the same header and nothing ever counted `<entry>`.

    python archive_filter_probe.py            fetch and archive
    python archive_filter_probe.py --verify   re-hash what is stored; fetch nothing
"""
import gzip
import hashlib
import io
import json
import pathlib
import re
import sys
import time
import urllib.parse
import urllib.request

NL = chr(10)
D = chr(0x26D4)
W = chr(0x26A0)
HERE = pathlib.Path(__file__).resolve().parent
STORE = HERE / "evidence"
OUT = HERE / "filter-probe-archive.json"
PAGE = 100
DELAY = 12.0
UA = "mp-metric-census/1.0 (mailto:parthms.id@gmail.com)"
API = "https://export.arxiv.org/api/query?search_query=%s&start=%d&max_results=%d"


def terms():
    se = json.loads((HERE / "stem-equivalence.json").read_text(encoding="utf-8"))
    return [g["terms"][0] for g in se["groups"]]


def labels():
    ns = json.loads((HERE / "negative-search.json").read_text(encoding="utf-8"))
    out = {}
    for sub, rec in sorted(ns["subjects"].items()):
        q = (rec.get("queries") or [{}])[0]
        found = [urllib.parse.unquote(x)
                 for x in re.findall(r"abs%3A%22(.+?)%22", q.get("url", ""))]
        verbs = {e.get("term") for e in (rec.get("queries") or [])}
        names = [x for x in found if x not in verbs]
        if len(names) != 1:
            raise SystemExit(D + " cannot identify the subject label for %s from %r" % (sub, found))
        out[sub] = names[0]
    return out


def fetch(url, tries=6):
    """Fetch with backoff. ⚠ arXiv answers 429 to a sustained sweep, and a 429 body is
    an ERROR PAGE that would archive cleanly and hash fine -- the same shape as a bot-wall 200.
    Retried, and never stored unless it parsed as a feed.
    """
    wait = DELAY
    for attempt in range(tries):
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                body = r.read()
            if b"<feed" not in body[:4000]:
                raise OSError("response is not an Atom feed (%d bytes)" % len(body))
            return body
        except Exception:                                                    # noqa: BLE001
            if attempt == tries - 1:
                raise
            time.sleep(wait)
            wait = min(wait * 2, 120)
    raise OSError("unreachable")


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace",
                                  line_buffering=True)
    verify = "--verify" in sys.argv
    subs, tms = labels(), terms()
    rec = json.loads(OUT.read_text(encoding="utf-8")) if OUT.exists() else {"subjects": {}}
    print("=" * 78)
    print("  UNFILTERED ARXIV RESPONSES -- %d subject(s) x %d distinct term(s)"
          % (len(subs), len(tms)))
    print("=" * 78)
    print()
    bad, fetched = [], 0
    out = {}
    for sub, label in sorted(subs.items()):
        rows = []
        for term in tms:
            q = 'abs:"%s" AND abs:"%s"' % (label, term)
            start, total, got = 0, None, 0
            while True:
                url = API % (urllib.parse.quote(q, safe=""), start, PAGE)
                prev = next((r for r in (rec.get("subjects", {}).get(sub) or [])
                             if r.get("url") == url), None)
                if verify or (prev and (STORE / (prev["sha256"] + ".gz")).exists()):
                    if not prev:
                        bad.append("%s/%s start=%d is not archived" % (sub, term, start))
                        break
                    raw = gzip.decompress((STORE / (prev["sha256"] + ".gz")).read_bytes())
                    if hashlib.sha256(raw).hexdigest() != prev["sha256"]:
                        bad.append("%s/%s start=%d does not hash to its name" % (sub, term, start))
                        break
                else:
                    try:
                        raw = fetch(url)
                    except Exception as e:                                   # noqa: BLE001
                        bad.append("%s/%s: %s" % (sub, term, str(e)[:50]))
                        break
                    fetched += 1
                    sha = hashlib.sha256(raw).hexdigest()
                    (STORE / (sha + ".gz")).write_bytes(gzip.compress(raw, mtime=0))
                    time.sleep(DELAY)
                sha = hashlib.sha256(raw).hexdigest()
                m = re.search(rb"<opensearch:totalResults[^>]*>(\d+)<", raw)
                total = int(m.group(1)) if m else 0
                ent = raw.count(b"<entry>")
                got += ent
                rows.append({"term": term, "url": url, "sha256": sha, "start": start,
                             "entries": ent, "total": total})
                if ent == 0 or got >= total or start + PAGE >= total:
                    break
                start += PAGE
            if total is not None and got != total:
                bad.append("%s/%s: %d entries archived, header says %d" % (sub, term, got, total))
        out[sub] = rows
        print("  %-20s %2d response(s), %5d entries"
              % (sub, len(rows), sum(r["entries"] for r in rows)))

    if bad:
        print()
        for b in bad[:6]:
            print("  " + D + " " + b)
        print("  " + D + " %d problem(s). Nothing written." % len(bad))
        return 1
    if verify:
        print()
        print("  ok  every archived unfiltered response re-hashes, and each query's pages")
        print("  account for its whole total.")
        return 0
    OUT.write_text(json.dumps({
        "_readme": ("The UNFILTERED counterpart of every reproduction query. The census applies a "
                    "cs.CL/cs.LG filter; these are the same queries without it, archived so the "
                    "filter's cost is recomputable offline rather than asserted."),
        "subjects": out,
    }, indent=1) + NL, encoding="utf-8")
    print()
    print("  wrote %s -- %d response(s), %d newly fetched"
          % (OUT.name, sum(len(v) for v in out.values()), fetched))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
