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
        by_url.setdefault(e["url"], {"sha256": e["sha256"], "cells": []})["cells"].append((s, a))

    print("=" * 78)
    print("  retrieval drift — %d evidence record(s), %d distinct artifact(s)"
          % (len(records), len(by_url)))
    print("=" * 78)
    print()

    same = drift = gone = 0
    findings = []
    for url in sorted(by_url):
        want = by_url[url]["sha256"]
        cells = by_url[url]["cells"]
        rec, why = F.evidence(url)
        label = "%-58s" % (url[-58:] if len(url) > 58 else url)
        if rec is None:
            gone += 1
            print("  GONE   %s" % label)
            print("         %s" % why)
            findings.append((url, "unretrievable: %s" % why, cells))
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
    log = HERE / "recheck-log.json"
    prev = json.loads(log.read_text(encoding="utf-8")) if log.exists() else {"runs": []}
    prev["runs"].append({
        "at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "artifacts": len(by_url), "unchanged": same, "drifted": drift, "unretrievable": gone,
        "subject_filter": only,
    })
    prev["runs"] = prev["runs"][-50:]
    log.write_text(json.dumps(prev, indent=2) + NL, encoding="utf-8", newline=NL)

    print()
    print("=" * 78)
    print("  %d unchanged · %d DRIFTED · %d unretrievable" % (same, drift, gone))
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
