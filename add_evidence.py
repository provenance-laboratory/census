"""Attach evidence to a cell by FETCHING it. A digest is never typed.

⛔ WHY THIS EXISTS. Three times now I have written a SHA-256 into this ledger by hand and three
times it was wrong. The mechanism is identical every time: something displays a TRUNCATED digest --
`sha256[:16]` in a probe's output -- and the remaining 48 characters get completed from memory. The
result is well-formed hex, so `validate()` accepts it; it is the right length, the right alphabet,
and the right prefix. Only re-fetching the bytes catches it.

The first fix was "re-fetching is a pre-commit gate", which is a rule, and a rule is a thing a
person remembers or does not. The second fix was a checker. This is the third fix and it is the
only one with the right shape: **there is no code path in which a human supplies a digest.** You
give it a url; it gives the ledger the bytes' hash.

It also double-fetches to detect volatility, because a rendered HTML page with per-request tokens
cannot support a stable digest at all -- and both artifacts behind the llm.c GPT-2 reproduction
turned out to be exactly that.

    python add_evidence.py <subject> <axis> <url> [<url> ...]
    python add_evidence.py --recheck            re-fetch every recorded digest and report
"""
import io
import json
import pathlib
import sys

import fetch_artifact as F

NL = chr(10)
HERE = pathlib.Path(__file__).resolve().parent
LEDGER = HERE / "cells.json"


def fetch_twice(url, rng=None):
    """Returns (record, volatile, why). Volatility is MEASURED, not assumed.

    ⚠️ HONOURS A RECORDED BYTE RANGE. One artifact in this ledger is a 1.74 GB corpus object whose
    evidence is the digest of a 2 KB range; fetching it whole would download 1.74 GB and then
    compare the wrong digest. recheck.py was taught this and this was not -- a fix is not finished
    until the other call sites are found.
    """
    def once():
        if rng:
            first, last = (int(x) for x in rng.split("=", 1)[1].split("-"))
            return F.evidence_range(url, first, last)
        return F.evidence(url)
    a, why = once()
    if a is None:
        return None, None, why
    b, why2 = once()
    if b is None:
        return None, None, why2
    return a, (a["sha256"] != b["sha256"]), None


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    led = json.loads(LEDGER.read_text(encoding="utf-8"))

    if "--recheck" in sys.argv:
        bad = 0
        seen = set()
        for c in led["cells"]:
            for e in (c.get("evidence") or []):
                if e["url"] in seen:
                    continue
                seen.add(e["url"])
                rec, _vol, why = fetch_twice(e["url"], e.get("range"))
                if rec is None:
                    print("  GONE   %s -- %s" % (e["url"][-56:], why))
                    bad += 1
                elif rec["sha256"] != e["sha256"] and not e.get("volatile"):
                    print("  ⛔ MISMATCH %s" % e["url"][-56:])
                    print("       recorded %s" % e["sha256"])
                    print("       actual   %s" % rec["sha256"])
                    bad += 1
        print("  %d recorded digest(s) do not match the bytes" % bad)
        return 1 if bad else 0

    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    subject, axis, urls = sys.argv[1], int(sys.argv[2]), sys.argv[3:]

    target = [c for c in led["cells"] if c["subject"] == subject and c["axis"] == axis]
    if not target:
        print("  no cell %s/axis%d" % (subject, axis))
        return 1
    cell = target[0]

    records = []
    for u in urls:
        rec, volatile, why = fetch_twice(u)
        if rec is None:
            print("  ⛔ %s -- %s" % (u, why))
            print("  Refusing to attach evidence that could not be retrieved.")
            return 1
        e = {"url": u, "retrieved": rec["retrieved"], "sha256": rec["sha256"]}
        if volatile:
            e["volatile"] = True
            e["volatile_reason"] = ("two fetches seconds apart returned different bytes: this is a "
                                    "rendered page carrying per-request state, so no digest of it "
                                    "is stable. Admissible as ASSERTED evidence only.")
            print("  VOLATILE %s" % u[-58:])
            print("           %s  (recorded, capped at ASSERTED)" % rec["sha256"][:32])
        else:
            print("  stable   %s" % u[-58:])
            print("           %s" % rec["sha256"])
        records.append(e)

    cell["evidence"] = records
    LEDGER.write_text(json.dumps(led, indent=2) + NL, encoding="utf-8", newline=NL)
    print("  %s/axis%d now carries %d evidence record(s), none of them typed"
          % (subject, axis, len(records)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
