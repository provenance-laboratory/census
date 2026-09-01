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
import re
import pathlib
import subprocess
import sys

import fetch_artifact as F
import mp_metric as M

NL = chr(10)
HERE = pathlib.Path(__file__).resolve().parent


# ⛔ A HOST'S POPULARITY COUNTERS ARE NOT THIS CENSUS'S EVIDENCE. A Hugging Face revision
# response carries `downloads` and `spaces`, which change daily, so every archived one drifts
# within a day and the drift check reported ten artifacts moved without saying that not one of
# them had moved in any way a cell reads.
#
# ⚠ AND NORMALISING THEM AWAY WOULD BE WORSE. Silently ignoring fields is how a substitution
# passes a checksum. So nothing is ignored: the drift is still reported, and the DIFFERING KEYS
# ARE NAMED, so a reader sees whether a popularity counter moved or a file list did.
VOLATILE_KEYS = {
    "downloads", "downloadsAllTime", "likes", "spaces", "trendingScore", "usedStorage",
    "lastModified", "createdAt", "inference", "widgetData", "safetensors",
}


def drift_kind(old, new):
    """(kind, differing keys). MATERIAL unless every difference is a known volatile field."""
    import json as _j
    try:
        a, b = _j.loads(old), _j.loads(new)
    except Exception:                                                       # noqa: BLE001
        return "MATERIAL", ["not JSON: the whole body differs"]
    if isinstance(a, list) or isinstance(b, list):
        return ("MATERIAL", ["a list response whose contents differ"]) if a != b else ("NONE", [])
    keys = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
    if not keys:
        return "NONE", []
    return ("METADATA" if set(keys) <= VOLATILE_KEYS else "MATERIAL"), keys


STORE = pathlib.Path(__file__).resolve().parent / "evidence"


def _bytes_for_digest(sha):
    """The archived bytes for a digest, or None."""
    import gzip as _gz
    blob = STORE / (sha + ".gz")
    if not blob.exists():
        return None
    return _gz.decompress(blob.read_bytes())


# these glyphs were used in six places before they were defined anywhere -- the seventh
# undefined-name bug in this project, and it fired inside the lock refusal itself
D = chr(0x26D4)
W = chr(0x26A0)
LOCK = pathlib.Path(__file__).resolve().parent / ".recheck.lock"


def take_lock():
    """Refuse to start if another instance is already re-fetching.

    ⛔ THREE COPIES OF THIS TOOL RAN AT ONCE AGAINST ONE EVIDENCE STORE AND ONE LOG, and nothing
    noticed. Background jobs were stopped, the stop reported success, and the processes kept
    running -- so the reported drift went from 10 to 42 to 74 while the world had not changed at
    all. It was three clients queueing at one host's rate limiter and overwriting each other's
    record.

    ⚠ THE SUCCESS SIGNAL WAS THE ENVELOPE AGAIN. A stop that returns success is not a process
    that has exited, and the only way this was found was reading the process table instead of
    trusting the tool. A lock makes the second instance say so.
    """
    import os
    if LOCK.exists():
        try:
            pid = int(LOCK.read_text(encoding="utf-8").split()[0])
        except Exception:                                                   # noqa: BLE001
            pid = -1
        alive = False
        if pid > 0:
            try:
                r = subprocess.run(["tasklist", "/FI", "PID eq %d" % pid, "/FO", "CSV"],
                                   capture_output=True, text=True)
                alive = str(pid) in (r.stdout or "")
            except Exception:                                               # noqa: BLE001
                alive = True
        if alive:
            raise SystemExit(
                D + " another recheck is already running (pid %d). Two clients against one host's "
                "rate limiter produce drift that is not drift, and they overwrite each other's "
                "log. Wait for it, or stop it and confirm with the process table -- a stop that "
                "returns success is not a process that has exited." % pid)
        print("  " + W + " a stale lock from pid %d was left behind; taking it over." % pid)
    LOCK.write_text("%d" % os.getpid(), encoding="utf-8", newline="\n")


def drop_lock():
    try:
        LOCK.unlink(missing_ok=True)
    except OSError:
        pass


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    take_lock()
    only = None
    if "--subject" in sys.argv:
        only = sys.argv[sys.argv.index("--subject") + 1]

    led = M.load()
    # ⛔ THE RE-FETCH SKIPPED facts.json ENTIRELY. Every fact in the manuscript is a
    # number read out of a retrieved artifact, and no run of this tool had ever confirmed that
    # artifact still serves the recorded bytes.
    records = [(w, e) for w, e in M.all_cited(led)
               if only is None or w.startswith(only)]

    by_url = {}
    for w, e in records:
        by_url.setdefault(e["url"], {"sha256": e["sha256"], "cells": [],
                                     "range": e.get("range"),
                                     # the METHOD the bytes were obtained by. A commit url's HTTP
                                     # body is rendered HTML; the archived bytes are the git
                                     # object, and re-fetching the wrong representation reports
                                     # drift that has not happened.
                                     "retrieval": e.get("retrieval"),
                                     "volatile": bool(e.get("volatile"))})["cells"].append(w)

    print("=" * 78)
    print("  retrieval drift — %d evidence record(s), %d distinct artifact(s)"
          % (len(records), len(by_url)))
    print("=" * 78)
    print()

    same = drift = gone = volatile_drift = limited = 0

    meta_drift = 0
    findings = []
    # ⚠️ 226 ARTIFACTS, MOST FROM ONE HOST. Re-fetching them back to back is what met Hugging
    # Face's limiter and produced the two 429s a reviewer asked about. A short per-host pause
    # costs a few minutes and keeps the sweep COMPLETE, which matters because the paper's sentence
    # is "all N were re-fetched" -- sampling would be a different and weaker claim.
    import time as _time
    _last_host = {}

    # ⛔ ONE DELAY FOR EVERY HOST IS NOT POLITENESS, IT IS AN AVERAGE. 0.7 s suits Hugging
    # Face and is far too fast for arXiv: adding 84 archived query responses to the evidence set
    # produced 44 rate-limited replies in a single uncontended run, and a run that hit a limiter
    # 44 times has not re-fetched anything -- it has measured the limiter. arXiv asks for one
    # request every three seconds and says so in its terms.
    PER_HOST = {"export.arxiv.org": 3.1, "arxiv.org": 3.1, "api.github.com": 1.5}

    def _be_polite(u):
        host = u.split("//", 1)[-1].split("/", 1)[0]
        gap = PER_HOST.get(host, 0.7)
        prev = _last_host.get(host)
        now = _time.time()
        if prev is not None and now - prev < gap:
            _time.sleep(gap - (now - prev))
        _last_host[host] = _time.time()

    for url in sorted(by_url):
        _be_polite(url)
        want = by_url[url]["sha256"]
        cells = by_url[url]["cells"]
        # ⛔ A CELL MAY CITE A BYTE RANGE OF AN OBJECT TOO LARGE TO HOLD. The OLMo corpus object
        # is 1.74 GB; re-fetching it whole to check a 2 KB range would download 1.74 GB per run.
        # Re-issue the SAME range instead -- which is also the only way the recorded digest, which
        # is a digest of the range, could ever match.
        # ⛔ THE URL IS PROVENANCE, NOT A REPRESENTATION. A commit page's HTTP body is rendered
        # HTML; the bytes this census archives are the GIT COMMIT OBJECT at that revision. Hashing
        # the HTTP reply reported "digest moved" for all five axis-14 artifacts on the first run
        # after they were added -- correctly, because the two are different things.
        #
        # ⛔ THE FIX IS TO RE-FETCH BY THE METHOD THE ARTIFACT WAS OBTAINED BY, NOT TO EXEMPT IT.
        # An artifact excused from the drift check is an artifact whose disappearance nobody
        # notices, and this file exists to notice.
        rng = by_url[url].get("range")
        if by_url[url].get("retrieval") == "git-object":
            import hashlib as _hl

            import probe_signatures as _PS
            _m = re.match("^https://huggingface\\.co/([^/]+/[^/]+)/commit/([0-9a-f]{40})$", url)
            try:
                _blob = _PS.commit_object(_m.group(1), _m.group(2))
                rec = {"sha256": _hl.sha256(_blob).hexdigest(), "bytes": len(_blob)}
                why = None
            except BaseException as _e:                                     # noqa: BLE001
                rec, why = None, "git retrieval failed: %s" % str(_e)[:120]
        elif rng:
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
            # ⛔ "digest moved" IS TRUE AND SAYS NOTHING ABOUT WHETHER THE CLAIM MOVED. Ten
            # artifacts drifted on a Hugging Face `downloads` counter, and the report gave a reader
            # no way to tell that from a changed file list. The differing keys are NAMED -- nothing
            # is ignored, because silently normalising a field away is how a substitution passes.
            _old_bytes = _bytes_for_digest(want)
            # the live body is not in the evidence record, so it is fetched once, here, only
            # when a drift has already been detected
            _live = b""
            try:
                _st, _live, _e = F.fetch(url)
            except Exception:                                               # noqa: BLE001
                _live = b""
            if _old_bytes is None or not _live:
                _kind, _keys = "MATERIAL", ["bytes unavailable for comparison"]
            else:
                _kind, _keys = drift_kind(_old_bytes, _live)
            if _kind == "NONE":
                # ⛔ BYTES DIFFER, PARSED CONTENT IS IDENTICAL. A JSON API may reorder keys or
                # change whitespace between responses; the archived claim is unaffected. This was
                # falling through to MATERIAL with an EMPTY differing-key list -- a finding that
                # named nothing, which is how the 403 rate-limit bodies were nearly filed as
                # three changed source trees.
                meta_drift += 1
                print("  ser    %s" % label)
                print("         the bytes differ and the PARSED CONTENT IS IDENTICAL -- key order "
                      "or whitespace. The claim is unaffected.")
                findings.append((url, "serialisation only: parsed content identical", cells))
            elif _kind == "METADATA":
                meta_drift += 1
                print("  meta   %s" % label)
                print("         differs ONLY in %s -- host metadata, not evidence this census "
                      "reads. Reported, never ignored." % ", ".join(_keys))
                findings.append((url, "metadata drift: " + ", ".join(_keys), cells))
            else:
                drift += 1
                print("  DRIFT  %s" % label)
                print("         was %s" % want)
                print("         now %s" % rec["sha256"])
                print("         differing: %s" % (", ".join(_keys) if _keys else "whole body"))
                findings.append((url, "digest moved: " + ", ".join(_keys), cells))
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
        # ⛔ A RUN THAT HIT A LIMITER HAS NOT RE-FETCHED EVERYTHING, whatever its summary says.
        # Eight rate-limited responses were reported in a line beneath a headline claiming 318
        # artifacts checked -- a count that is not a cover, in the tool whose own comment says so.
        "complete": limited == 0,
        # differs only in host metadata a cell never reads -- reported, never ignored
        "metadata_drift": meta_drift,
        "covered": fp,
        "subject_filter": only,
        "findings": [{"url": u, "what": w,
                      "cells": list(cs),
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
            print("        affects: %s" % ", ".join(cells))
    drop_lock()
    if limited:
        print()
        print("  " + chr(0x26D4) + " %d response(s) were RATE-LIMITED, so this run did NOT"
              % limited)
        print("  re-fetch every artifact and is recorded as INCOMPLETE. A drift figure from a")
        print("  throttled run is a fact about the channel, and three copies of this tool once")
        print("  ran at once and turned 10 drifted into 74 without the world changing at all.")
        print("=" * 78)
        return 1
    print("=" * 78)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
