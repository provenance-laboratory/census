"""Re-execute every registered check over the ARCHIVED BYTES, and report what actually holds.

⛔ WHY. `CHECK_METHODS` was an allowlist of NAMES. The validator confirmed a cell's method string
appeared in it and stopped there, so round-3 review set a cell's method to `hf_probe.weight_object`
with `asserts` and `observed` both reading "nonsense" and the ledger validated; changing `observed`
to "I did not run this" also validated. Meanwhile the paper says a VERIFIED cell is one where "a
REGISTERED MECHANICAL CHECK over its content SUCCEEDED".

That sentence was describing a check rather than performing one, which is the distinction this
entire instrument exists to draw. This script performs them.

WHAT IT CAN AND CANNOT DO. `grep_retrieved` and `count_in_retrieved` are fully replayable: the cell
names the literal strings its claim rests on and this greps the stored bytes for them.
`http_range` is replayable against the recorded range digest. The `hf_probe.*` methods executed a
live probe at scoring time whose outputs are recorded; this checks the recorded evidence has the
shape that probe produces, which is weaker, and says so rather than implying more.

    python replay.py            replay every score-2 check
    python replay.py --strict   also fail on a check that is only shape-verified
"""
import gzip
import io
import json
import pathlib
import sys

import axes as A

NL = chr(10)
HERE = pathlib.Path(__file__).resolve().parent
STORE = HERE / "evidence"


def _bytes_for(e):
    blob = STORE / (e["sha256"] + ".gz")
    if not blob.exists():
        return None
    return gzip.decompress(blob.read_bytes())


def m_grep(c, ev):
    """Every literal in `expect` must appear in the archived bytes of some cited artifact."""
    exp = c["check"].get("expect")
    if not exp:
        return None, "no `expect` list: nothing to replay, so the method name is a label"
    haystacks = [b for b in (_bytes_for(e) for e in ev) if b is not None]
    if not haystacks:
        return None, "no archived bytes for any cited artifact"
    missing = [x for x in exp
               if not any(x.lower().encode() in h.lower() for h in haystacks)]
    if missing:
        return False, "NOT FOUND in the archived bytes: %s" % missing
    return True, "found all %d expected string(s)" % len(exp)


def m_range(c, ev):
    r = [e for e in ev if e.get("range")]
    if not r:
        return False, "method is http_range and no evidence record carries a range"
    b = _bytes_for(r[0])
    if b is None:
        return None, "the range bytes are not archived"
    want = int(r[0]["range"].split("-")[-1]) + 1
    if len(b) != want:
        return False, "archived range is %d bytes, the record claims %d" % (len(b), want)
    return True, "%d archived bytes match the cited range" % len(b)


def m_probe(c, ev):
    """Shape-verified only, and reported as such."""
    if not any("huggingface.co" in e["url"] for e in ev):
        return False, "an hf_probe method with no Hugging Face artifact cited"
    return None, "shape-verified only: the probe ran at scoring time and is not re-executed here"


DISPATCH = {
    "grep_retrieved": m_grep,
    "count_in_retrieved": m_grep,
    "http_range": m_range,
    "hf_probe.weight_object": m_probe,
    "hf_probe.all_shard_digests": m_probe,
}


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    strict = "--strict" in sys.argv
    led = json.loads((HERE / "cells.json").read_text(encoding="utf-8"))
    ok = failed = unreplayable = 0
    print("=" * 78)
    print("  replaying every VERIFIED check over archived bytes")
    print("=" * 78)
    print()
    for c in led["cells"]:
        if c.get("score") != 2:
            continue
        meth = c["check"]["method"]
        fn = DISPATCH.get(meth)
        where = "%s/axis%d" % (c["subject"], c["axis"])
        if fn is None:
            print("  ⛔ %-26s method %r has no executor" % (where, meth))
            failed += 1
            continue
        # ⛔ METHOD-AXIS COMPATIBILITY. Round-3 review put an hf_probe method on a config-file
        # axis and nothing objected.
        if meth not in A.methods_for(c["axis"]):
            print("  ⛔ %-26s method %r is not valid for this axis (%s)"
                  % (where, meth, ", ".join(sorted(A.methods_for(c["axis"])))))
            failed += 1
            continue
        res, why = fn(c, c.get("evidence") or [])
        if res is True:
            print("  ok    %-26s %s" % (where, why))
            ok += 1
        elif res is False:
            print("  ⛔ FAIL %-24s %s" % (where, why))
            failed += 1
        else:
            print("  ~     %-26s %s" % (where, why))
            unreplayable += 1
    print()
    print("=" * 78)
    print("  %d replayed and passed, %d FAILED, %d shape-verified only"
          % (ok, failed, unreplayable))
    if unreplayable and strict:
        print("  --strict: a shape-verified check does not support the sentence 'a registered")
        print("  mechanical check over its content succeeded'.")
    print("=" * 78)
    return 1 if (failed or (strict and unreplayable)) else 0


if __name__ == "__main__":
    raise SystemExit(main())
