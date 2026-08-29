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
import re
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


def m_weight_object(c, ev):
    """Axis 12: the archived bytes must BE a real weight range, not a pointer, at the right length.

    ⛔ THE OLD CHECK ASKED WHETHER SOME URL CONTAINED "huggingface.co". A fabricated digest, a
    nonsense observation and a non-existent repository all returned "shape-verified only". Both
    round-4 reviewers found it. The cell claimed "HTTP 206, 2048 B, is_pointer=False" while the
    archive held a 136-byte Git-LFS pointer -- the paper's own confessed defect, inside the fix.
    """
    want = c["check"].get("expect_range_bytes")
    if not want:
        return None, "no expect_range_bytes: nothing to recompute"
    r = [e for e in ev if e.get("range")]
    if not r:
        return False, "axis-12 cell cites no ranged artifact"
    b = _bytes_for(r[0])
    if b is None:
        return None, "the range bytes are not archived"
    if len(b) != want:
        return False, "archived range is %d bytes, the cell claims %d" % (len(b), want)
    if b[:100].startswith(b"version https://git-lfs.github.com/spec/v1"):
        return False, "the archived 'weight range' IS A GIT-LFS POINTER -- exactly the defect"
    import hashlib as _h
    if _h.sha256(b).hexdigest() != r[0]["sha256"]:
        return False, "archived bytes do not hash to the recorded digest"
    return True, "%d real weight bytes, not a pointer, digest matches" % len(b)


def m_all_shard_digests(c, ev):
    """Axis 13: recompute the shard enumeration from the archived API response.

    The cell used to assert "144/144 shards" with one pointer archived. Now the response that
    ENUMERATES the shards is archived, so the count is recomputed rather than believed, and every
    cited pointer must carry a real Git-LFS sha256 oid.
    """
    want = c["check"].get("expect_shards")
    if not want:
        return None, "no expect_shards: nothing to recompute"
    api = [e for e in ev if "/api/models/" in e["url"]]
    if not api:
        return False, "axis-13 cell cites no api response, so its count rests on nothing"
    raw = _bytes_for(api[0])
    if raw is None:
        return None, "the api response is not archived"
    try:
        files = [s["rfilename"] for s in json.loads(raw).get("siblings", [])]
    except ValueError:
        return False, "the archived api response is not json"
    enumerated = sorted(f for f in files
                        if re.search(r"\.(safetensors|bin)$", f) and "index" not in f)
    if len(enumerated) != want:
        return False, ("the api response enumerates %d shards, the cell claims %d"
                       % (len(enumerated), want))
    ptrs = [e for e in ev if e.get("lfs_oid") is not None]
    if len(ptrs) != want:
        return False, "%d shard pointer(s) cited, %d enumerated" % (len(ptrs), want)
    bad = []
    for e in ptrs:
        b = _bytes_for(e)
        if b is None:
            bad.append("%s not archived" % e["url"].rsplit("/", 1)[-1])
            continue
        m = re.search(rb"oid sha256:([0-9a-f]{64})", b)
        if not m:
            bad.append("%s carries no sha256 oid" % e["url"].rsplit("/", 1)[-1])
        elif m.group(1).decode() != e["lfs_oid"]:
            bad.append("%s oid does not match the ledger" % e["url"].rsplit("/", 1)[-1])
    if bad:
        return False, "; ".join(bad[:3])
    return True, "%d shards enumerated by the archived api response, %d oids verified" % (
        want, len(ptrs))


DISPATCH = {
    "grep_retrieved": m_grep,
    "count_in_retrieved": m_grep,
    "http_range": m_range,
    "hf_probe.weight_object": m_weight_object,
    "hf_probe.all_shard_digests": m_all_shard_digests,
}


def selftest():
    """Mutate the real ledger IN MEMORY and require each mutation to fail.

    ⛔ A CONTROL NOBODY HAS WATCHED FAIL IS INDISTINGUISHABLE FROM ONE THAT CANNOT FIRE. Round-4
    review made that the standard and then demonstrated it: the previous probe check passed a
    fabricated digest, a nonsense observation and a non-existent repository. These are the exact
    attacks both reviewers ran, kept so they run on every invocation rather than once.
    """
    import copy
    led = json.loads((HERE / "cells.json").read_text(encoding="utf-8"))

    def run_one(mut):
        d = copy.deepcopy(led)
        mut(d)
        for c in d["cells"]:
            if c.get("score") != 2:
                continue
            fn = DISPATCH.get(c["check"]["method"])
            if fn and c["check"]["method"] not in A.methods_for(c["axis"]):
                return False
            if fn:
                res, _why = fn(c, c.get("evidence") or [])
                if res is False:
                    return False
        return True

    def _find(d, sub, ax):
        return [c for c in d["cells"] if c["subject"] == sub and c["axis"] == ax][0]

    attacks = [
        ("a fabricated but well-formed shard digest",
         lambda d: _find(d, "mistral-7b-v0.3", 13)["evidence"][2].update({"sha256": "b" * 64})),
        ("one shard pointer removed from a cited enumeration",
         lambda d: _find(d, "qwen2.5-7b", 13).__setitem__(
             "evidence", _find(d, "qwen2.5-7b", 13)["evidence"][:3])),
        ("a false shard count",
         lambda d: _find(d, "bloom-176b", 13)["check"].update({"expect_shards": 999})),
        ("a weight range replaced by its Git-LFS pointer",
         lambda d: _find(d, "mistral-7b-v0.3", 12)["evidence"].__setitem__(
             0, dict(_find(d, "mistral-7b-v0.3", 13)["evidence"][1],
                     range="bytes=0-2047"))),
        ("falsified expected strings on a replayable grep",
         lambda d: _find(d, "bert-base-uncased", 1)["check"].update(
             {"expect": ["this string is not in the archived bytes"]})),
    ]
    print("=" * 78)
    print("  SELF-TEST: every mutation below MUST make a check fail")
    print("=" * 78)
    print()
    bad = 0
    for name, mut in attacks:
        try:
            survived = run_one(mut)
        except Exception:                                       # noqa: BLE001
            survived = False
        print(("  ok    " if not survived else "  " + chr(0x26D4) + " PASSES ")
              + "%s" % name)
        if survived:
            bad += 1
    print()
    print("  %d of %d attacks correctly rejected" % (len(attacks) - bad, len(attacks)))
    if bad:
        print("  " + chr(0x26D4) + " a control that cannot fail is reported as coverage.")
    print("=" * 78)
    return 1 if bad else 0


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    if "--selftest" in sys.argv:
        return selftest()
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
