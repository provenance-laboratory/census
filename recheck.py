"""Test F — retrieval drift. Re-fetch every evidence artifact and compare digests.

⛔ WHY THIS EXISTS AS A REAL TOOL RATHER THAN A SENTENCE. obl-metric shipped a `--at` flag
advertised in three places that silently did nothing: every date produced byte-identical output.
In a paper whose claim is reproducibility, an advertised control that does not work is the worst
available defect. `referee.py` names this script, so this script exists and does the thing.

Releases change. A model card edited after scoring silently invalidates the cell that cites it,
and nothing in the ecosystem announces that. A digest that moved is therefore a FINDING -- it is
reported, dated, and carried into the paper -- not a maintenance chore to be quietly repaired.

A cell whose artifact has drifted is not automatically wrong. It is UNVERIFIED until someone reads
the new bytes and decides whether the property still holds. This script never rescores anything.

    python recheck.py             re-fetch every evidence record
    python recheck.py --subject X only that subject
"""
import io
import json
import pathlib
import sys

import fetch_artifact as F
import mp_metric as M

NL = chr(10)
HERE = pathlib.Path(__file__).resolve().parent


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    only = None
    if "--subject" in sys.argv:
        only = sys.argv[sys.argv.index("--subject") + 1]

    led = M.load()
    records = []
    for c in led.get("cells", []):
        if only and c["subject"] != only:
            continue
        for e in (c.get("evidence") or []):
            records.append((c["subject"], c["axis"], e))

    # De-duplicate by url: the same artifact backs several cells, and fetching it once is both
    # faster and, more importantly, guarantees every cell sees the SAME bytes.
    by_url = {}
    for s, a, e in records:
        by_url.setdefault(e["url"], {"sha256": e["sha256"], "cells": [],
                                     "range": e.get("range"),
                                     "volatile": bool(e.get("volatile"))})["cells"].append((s, a))

    print("=" * 78)
    print("  retrieval drift — %d evidence record(s), %d distinct artifact(s)"
          % (len(records), len(by_url)))
    print("=" * 78)
    print()

    same = drift = gone = volatile_drift = limited = 0
    findings = []
    # ⚠️ 226 ARTIFACTS, MOST FROM ONE HOST. Re-fetching them back to back is what met Hugging
    # Face's limiter and produced the two 429s a reviewer asked about. A short per-host pause
    # costs a few minutes and keeps the sweep COMPLETE, which matters because the paper's sentence
    # is "all N were re-fetched" -- sampling would be a different and weaker claim.
    import time as _time
    _last_host = {}

    def _be_polite(u):
        host = u.split("//", 1)[-1].split("/", 1)[0]
        prev = _last_host.get(host)
        now = _time.time()
        if prev is not None and now - prev < 0.7:
            _time.sleep(0.7 - (now - prev))
        _last_host[host] = _time.time()

    for url in sorted(by_url):
        _be_polite(url)
        want = by_url[url]["sha256"]
        cells = by_url[url]["cells"]
        # ⛔ A CELL MAY CITE A BYTE RANGE OF AN OBJECT TOO LARGE TO HOLD. The OLMo corpus object
        # is 1.74 GB; re-fetching it whole to check a 2 KB range would download 1.74 GB per run.
        # Re-issue the SAME range instead -- which is also the only way the recorded digest, which
        # is a digest of the range, could ever match.
        rng = by_url[url].get("range")
        if rng:
            first, last = (int(x) for x in rng.split("=", 1)[1].split("-"))
            rec, why = F.evidence_range(url, first, last)
        else:
            rec, why = F.evidence(url)
        label = "%-58s" % (url[-58:] if len(url) > 58 else url)
        if rec is None and "RATE-LIMITED" in (why or ""):
            limited += 1
            print("  limit  %s" % label)
            print("         %s" % why)
        elif rec is None:
            gone += 1
            print("  GONE   %s" % label)
            print("         %s" % why)
            findings.append((url, "unretrievable: %s" % why, cells))
        elif rec["sha256"] != want and by_url[url]["volatile"]:
            volatile_drift += 1
            print("  vol    %s" % label)
            print("         digest moved, as a volatile endpoint is expected to. Not a finding "
                  "about the artifact; it is a finding ABOUT THE ENDPOINT, and the cell it backs "
                  "is capped at ASSERTED for exactly this reason.")
        elif rec["sha256"] != want:
            drift += 1
            print("  DRIFT  %s" % label)
            print("         was %s" % want)
            print("         now %s" % rec["sha256"])
            findings.append((url, "digest moved", cells))
        else:
            same += 1
            print("  ok     %s" % label)

    # Leave EVIDENCE that the run happened. The paper says "all N artifacts were re-fetched and
    # none had drifted", which is a claim about a PROCESS: without a record it is unfalsifiable,
    # and an unfalsifiable sentence in a paper about checkability is the wrong kind of sentence.
    import datetime as _dt
    import hashlib as _hl
    log = HERE / "recheck-log.json"
    prev = json.loads(log.read_text(encoding="utf-8")) if log.exists() else {"runs": []}
    # ⛔ A COUNT IS NOT A COVER. The paper says "all N artifacts were re-fetched"; the build used
    # to confirm that by comparing N against the ledger's artifact count. Swap one url for another
    # and the count is identical, so the check would pass for a run that never touched the current
    # evidence. Record a fingerprint over the url+digest SET instead, and let the build compare
    # that. Round-1 review asked for exactly this.
    fp = _hl.sha256(chr(10).join(sorted(
        u + chr(0) + str(by_url[u]["sha256"]) for u in by_url)).encode("utf-8")).hexdigest()
    # ⛔ A COUNT IS NOT A COVER -- AND THAT APPLIES TO THE DRIFT COUNT TOO. This function builds a
    # findings list carrying every drifted url and the cells it backs, prints it, and then
    # persisted the integer 2. Four lines above sat the comment saying a count is not a cover,
    # about the coverage fingerprint. Round-4 review found the same defect in the same dictionary.
    #
    # A drifted cell is UNVERIFIED until someone reads the new bytes -- this docstring says so --
    # and "someone" cannot act on an integer. The findings are persisted.
    prev["runs"].append({
        "at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "artifacts": len(by_url), "unchanged": same, "drifted": drift, "unretrievable": gone,
        "volatile": volatile_drift, "rate_limited": limited,
        "covered": fp,
        "subject_filter": only,
        "findings": [{"url": u, "what": w,
                      "cells": ["%s/axis%d" % c for c in cs],
                      "recorded_sha256": by_url[u]["sha256"]}
                     for u, w, cs in findings],
    })
    prev["runs"] = prev["runs"][-50:]
    log.write_text(json.dumps(prev, indent=2) + NL, encoding="utf-8", newline=NL)

    print()
    print("=" * 78)
    print("  %d unchanged · %d DRIFTED · %d unretrievable · %d volatile · %d rate-limited"
          % (same, drift, gone, volatile_drift, limited))
    print("  recorded in recheck-log.json")
    if findings:
        print()
        print("  " + chr(0x26D4) + " THESE ARE FINDINGS, NOT CHORES. The cells below are now")
        print("  UNVERIFIED: someone must read the new bytes and decide whether the property")
        print("  still holds. Do not rescore from the digest alone, and do not silently")
        print("  refresh the digest -- that would erase the observation that it moved.")
        for url, what, cells in findings:
            print("      %s" % what)
            print("        %s" % url)
            print("        affects: %s" % ", ".join("%s/axis%d" % c for c in cells))
    print("=" * 78)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
