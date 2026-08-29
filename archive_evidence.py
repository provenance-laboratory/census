"""Store the BYTES every cell rests on, not just their digests.

⛔ THE GAP THIS CLOSES. Until now a cell recorded a url and the SHA-256 of what came back. That is
enough to detect drift and not enough to survive it: when a document is edited or a repository goes
private, the digest proves the old bytes existed and nobody can ever read them again. A census whose
evidence can evaporate is a census that will one day be unfalsifiable.

Two facts in `facts.json` were also carried as VALUES with a sentence describing how they were
obtained -- exactly the ASSERTED level this instrument refuses to award a 2. With the bytes stored,
`check_facts.py` recomputes them, and a fact that cannot be recomputed fails the build.

WHAT IS AND IS NOT STORED. Text artifacts are stored gzipped, named by digest. A few artifacts are
too large to belong in a git repository -- one model card is 46 MB -- and those are recorded in the
manifest with `stored: false` and the reason, then archived to OBL-BACKUP instead. The manifest
covers EVERY artifact either way, so what is missing is visible rather than merely absent.

    python archive_evidence.py            fetch and store what is not stored yet
    python archive_evidence.py --verify    check stored bytes against the ledger digests
"""
import gzip
import hashlib
import io
import json
import pathlib
import sys

import fetch_artifact as F
import mp_metric as M

NL = chr(10)
HERE = pathlib.Path(__file__).resolve().parent
STORE = HERE / "evidence"
MANIFEST = STORE / "MANIFEST.json"
CAP = 8 * 1024 * 1024          # 8 MB: large enough for every document, small enough for a repo


def load_manifest():
    if MANIFEST.exists():
        return json.loads(MANIFEST.read_text(encoding="utf-8"))
    return {"_readme": [
        "Every artifact any cell rests on. `stored: true` means the bytes are in evidence/<sha>.gz",
        "and can be re-read offline; `stored: false` names the reason and the bytes live in",
        "OBL-BACKUP. A digest alone proves what WAS there; only the bytes let anyone check it.",
    ], "artifacts": {}}


def wanted():
    """Every artifact ANY claim rests on -- cells AND named facts.

    ⚠️ An earlier version projected over cells alone. facts.json cites its own artifacts, so a
    fact's bytes were never archived and check_facts.py could not recompute it. The archive must
    cover the whole class of things the paper cites, not the subset that happens to live in the
    ledger; the missing one showed up the first time anything asked for it.
    """
    led = M.load()
    out = {}

    def add(url, sha, who, volatile=False, rng=None):
        out.setdefault(url, {"sha256": sha, "volatile": volatile, "range": rng,
                             "cells": []})
        out[url]["cells"].append(who)

    for c in led.get("cells", []):
        for e in (c.get("evidence") or []):
            add(e["url"], e["sha256"], "%s/axis%d" % (c["subject"], c["axis"]),
                bool(e.get("volatile")), e.get("range"))

    fp = HERE / "facts.json"
    if fp.exists():
        for name, f in json.loads(fp.read_text(encoding="utf-8"))["facts"].items():
            ev = f.get("evidence") or {}
            if ev.get("url"):
                add(ev["url"], ev["sha256"], "fact:" + name)
    return out


def verify(man, want):
    """Every stored blob must hash to the digest the ledger records. Fails closed."""
    bad = []
    for url, rec in sorted(want.items()):
        m = man["artifacts"].get(url)
        if not m:
            bad.append("%s: not in the manifest at all" % url)
            continue
        if m["sha256"] != rec["sha256"]:
            bad.append("%s: manifest %s, ledger %s" % (url, m["sha256"][:12], rec["sha256"][:12]))
            continue
        if not m.get("stored"):
            continue
        blob = STORE / (rec["sha256"] + ".gz")
        if not blob.exists():
            bad.append("%s: manifest says stored, %s is missing" % (url, blob.name))
            continue
        got = hashlib.sha256(gzip.decompress(blob.read_bytes())).hexdigest()
        if got != rec["sha256"]:
            bad.append("%s: STORED BYTES HASH TO %s, ledger says %s -- the archive does not "
                       "contain what the cell cites" % (url, got[:12], rec["sha256"][:12]))
    return bad


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    STORE.mkdir(exist_ok=True)
    man, want = load_manifest(), wanted()

    if "--verify" in sys.argv:
        bad = verify(man, want)
        n_stored = sum(1 for u in want if man["artifacts"].get(u, {}).get("stored"))
        print("  %d artifact(s); %d stored offline, %d recorded but not stored"
              % (len(want), n_stored, len(want) - n_stored))
        for b in bad:
            print("  ! %s" % b)
        print("  " + ("archive agrees with the ledger" if not bad
                      else chr(0x26D4) + " %d PROBLEM(S)" % len(bad)))
        return 1 if bad else 0

    added = skipped = 0
    for url, rec in sorted(want.items()):
        blob = STORE / (rec["sha256"] + ".gz")
        if blob.exists():
            man["artifacts"].setdefault(url, {})
            man["artifacts"][url].update({"sha256": rec["sha256"], "stored": True,
                                          "cells": rec["cells"]})
            continue
        # ⛔ THE RANGE BRANCH RUNS FIRST. A cell citing a byte RANGE is not a citation of the
        # whole object, so sizing the object and filing it under "too large" describes the wrong
        # thing -- which is how a 1.7 GB corpus token shard ended up in the manuscript as a
        # "1744 MB model card". And the range bytes are small, so they ARE archived: 2 KB, not
        # 1.7 GB. Section 2.2.1 says the bytes behind every claim are kept; this is the claim that
        # was not covered.
        if rec.get("range"):
            first, last = (int(x) for x in rec["range"].split("=", 1)[1].split("-"))
            got, why = F.evidence_range(url, first, last)
            if got is None or got["sha256"] != rec["sha256"]:
                print("  RANGE  %-52s %s" % (url[-52:], why or "digest moved"))
                man["artifacts"][url] = {
                    "sha256": rec["sha256"], "stored": False, "range": rec["range"],
                    "reason": "range re-request failed or moved: %s" % (why or "digest moved"),
                    "cells": rec["cells"]}
                skipped += 1
                continue
            blob.write_bytes(gzip.compress(got["body"], 9))
            man["artifacts"][url] = {
                "sha256": rec["sha256"], "stored": True, "bytes": got["bytes"],
                "range": rec["range"], "whole_object_bytes": F.content_length(url),
                "note": "the archived bytes are the CITED RANGE, not the whole object, which is "
                        "far too large to hold. The cell's digest is of this range.",
                "cells": rec["cells"]}
            print("  stored %-52s %7d B (range) -> %6d B"
                  % (url[-52:], got["bytes"], blob.stat().st_size))
            added += 1
            continue

        # PRE-FLIGHT. Ask the size before pulling the body: one artifact in this ledger is a
        # corpus token file of unbounded size, and downloading it to discover it is too big would
        # be the whole failure this cap exists to avoid.
        size = F.content_length(url)
        if size is not None and size > CAP:
            print("  large  %-52s %d bytes (HEAD) -- not fetched" % (url[-52:], size))
            man["artifacts"][url] = {
                "sha256": rec["sha256"], "stored": False, "bytes": size,
                "reason": "%d bytes exceeds the %d-byte repository cap, established by a HEAD "
                          "request BEFORE downloading. Where a cell cites a byte RANGE of this "
                          "object, the range digest is the evidence and is re-checkable by "
                          "repeating the same range request." % (size, CAP),
                "cells": rec["cells"]}
            skipped += 1
            continue
        got, why = F.evidence(url)
        if got is None:
            print("  GONE   %-52s %s" % (url[-52:], why))
            man["artifacts"][url] = {"sha256": rec["sha256"], "stored": False,
                                     "reason": "unretrievable at archive time: %s" % why,
                                     "cells": rec["cells"]}
            skipped += 1
            continue
        # ⛔ Never store bytes under a digest they do not have. The cell cites a digest; if what
        # came back differs, that is DRIFT and recheck.py's job, not something to quietly archive.
        if got["sha256"] != rec["sha256"]:
            print("  DRIFT  %-52s ledger %s, now %s"
                  % (url[-52:], rec["sha256"][:12], got["sha256"][:12]))
            man["artifacts"][url] = {
                "sha256": rec["sha256"], "stored": False,
                "reason": ("VOLATILE endpoint: the body carries counters that move independently "
                           "of the claim, so it cannot be archived under a fixed digest. The cell "
                           "it backs is capped at ASSERTED for the same reason."
                           if rec.get("volatile") else
                           "drifted at archive time; see recheck.py"),
                "cells": rec["cells"]}
            skipped += 1
            continue
        body = got.get("body")
        if body is None:
            man["artifacts"][url] = {"sha256": rec["sha256"], "stored": False,
                                     "reason": "fetcher returned no body to store",
                                     "cells": rec["cells"]}
            skipped += 1
            continue
        if len(body) > CAP:
            print("  large  %-52s %d bytes -- OBL-BACKUP, not the repo" % (url[-52:], len(body)))
            man["artifacts"][url] = {"sha256": rec["sha256"], "stored": False, "bytes": len(body),
                                     "reason": "%d bytes exceeds the %d-byte repository cap; "
                                               "archived to OBL-BACKUP" % (len(body), CAP),
                                     "cells": rec["cells"]}
            skipped += 1
            continue
        blob.write_bytes(gzip.compress(body, 9))
        man["artifacts"][url] = {"sha256": rec["sha256"], "stored": True, "bytes": len(body),
                                 "cells": rec["cells"]}
        print("  stored %-52s %7d B -> %6d B" % (url[-52:], len(body), blob.stat().st_size))
        added += 1

    MANIFEST.write_text(json.dumps(man, indent=2, sort_keys=True) + NL,
                        encoding="utf-8", newline=NL)
    total = sum(p.stat().st_size for p in STORE.glob("*.gz"))
    print()
    print("  %d newly stored, %d recorded but not stored, %d artifact(s) total"
          % (added, skipped, len(want)))
    print("  evidence/ holds %d blob(s), %.1f MB on disk" % (len(list(STORE.glob("*.gz"))),
                                                             total / 1e6))
    bad = verify(man, want)
    for b in bad:
        print("  ! %s" % b)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
