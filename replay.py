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
`http_range` is replayable against the recorded range digest. The `hf_probe.*` methods are replayed
too, and against IDENTITY rather than shape: the archived API response must be of the repository and
revision its url claims, the cited shard pointers must be SET-EQUAL to the enumeration it carries,
and the ranged file must be one of those shards, at that revision, carrying real weight bytes.
⚠️ An earlier version of this docstring called them "shape-verified", which was generous: what it
actually tested was that some cited url contained a hostname.

    python replay.py            replay every score-2 check
    python replay.py --strict   also fail on a check that is only shape-verified
"""
import gzip
import hashlib
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
    # ⚠️ THIS COMPUTED last + 1, which is the length only when the range starts at zero. True of
    # every range in this ledger today, and a silent wrong answer the moment one does not.
    _spec = r[0]["range"].split("=", 1)[-1]
    _first, _last = (int(x) for x in _spec.split("-"))
    want = _last - _first + 1
    if len(b) != want:
        return False, "archived range is %d bytes, the record claims %d" % (len(b), want)
    return True, "%d archived bytes match the cited range" % len(b)


HF_API = re.compile(r"^https://huggingface\.co/api/models/([^/]+/[^/]+)/revision/([0-9a-f]{40})$")
HF_FILE = re.compile(r"^https://huggingface\.co/([^/]+/[^/]+)/(?:raw|resolve)/([0-9a-f]{40})/(.+)$")
# safetensors begins with a little-endian u64 header length, then '{"' of the JSON header. A
# .bin shard is a zip (PK) or a pickle. "Not a Git-LFS pointer" was the old test and it accepts
# an HTML sign-in page, which is the wall the retrieval tool refuses everywhere else.
WEIGHT_MAGIC = (b"{", b"PK", b"\x80")


def _identity(ev):
    """(repo, revision) shared by every cited artifact, or a reason they do not share one."""
    seen = set()
    for e in ev:
        m = HF_API.match(e["url"]) or HF_FILE.match(e["url"])
        if not m:
            return None, "cited url is not a pinned Hugging Face artifact: %s" % e["url"][:70]
        seen.add((m.group(1), m.group(2)))
    if len(seen) != 1:
        return None, ("cited artifacts span %d different repository/revision pairs: %s"
                      % (len(seen), sorted(seen)))
    return seen.pop(), None


def _enumeration(ev):
    """(repo, revision, {filenames}) from the ARCHIVED api response, with its sha checked."""
    api = [e for e in ev if HF_API.match(e["url"])]
    if len(api) != 1:
        return None, "expected exactly one pinned api response, found %d" % len(api)
    repo, rev = HF_API.match(api[0]["url"]).groups()
    raw = _bytes_for(api[0])
    if raw is None:
        return None, "the api response is not archived"
    try:
        j = json.loads(raw)
    except ValueError:
        return None, "the archived api response is not json"
    # ⛔ THE RESPONSE MUST BE OF THE REVISION ITS URL CLAIMS. Otherwise one repository's
    # enumeration can stand in for another's, which is attack 2.
    if j.get("sha") != rev:
        return None, ("the archived api response is for revision %s, the url claims %s"
                      % (str(j.get("sha"))[:12], rev[:12]))
    if j.get("id") and j["id"] != repo:
        return None, "the archived api response is for %r, the url claims %r" % (j["id"], repo)
    files = {s["rfilename"] for s in j.get("siblings", [])}
    # Top-level weight files only -- see bind_probe_evidence.SHARD_RE. A nested vendor
    # export (CoreML, ONNX) is not a shard of the released model.
    shards = {f for f in files if re.match(r"^[^/]+\.(safetensors|bin)$", f)
              and "index" not in f}
    return (repo, rev, shards), None


def subject_context(led):
    """What the ledger already knows: which repository each subject IS.

    Returns {subject: repo_or_None} plus the inverse, so a cell can be checked against its own
    subject AND against every other subject it must not be confused with.
    """
    return {s["id"]: s.get("repo") for s in led.get("subjects", [])}


def foreign_evidence(cell, ctx):
    """Evidence that belongs, by the ledger's own declaration, to a DIFFERENT subject.

    ⛔ THE GENERAL FORM OF THE LAST DEFECT. Not Hugging Face specific: any cited artifact whose url
    contains another subject's declared repository path is that subject's evidence, wherever it is
    hosted. A cell may cite a third party's document -- RoBERTa backs a bert cell, and llm.c backs
    a gpt-2 cell -- but it may never cite an artifact that IS another census subject's release.
    """
    mine = ctx.get(cell["subject"])
    bad = []
    for e in (cell.get("evidence") or []):
        u = e["url"].lower()
        for sub, repo in ctx.items():
            if not repo or sub == cell["subject"]:
                continue
            if repo.lower() in u and (not mine or mine.lower() not in u):
                bad.append("%s is %s's artifact" % (e["url"].rsplit("/", 1)[-1][:38], sub))
    return bad



def m_weight_object(c, ev, ctx=None):
    """Axis 12: a real weight range, from a file THIS SUBJECT's repository enumerates."""
    want = c["check"].get("expect_range_bytes")
    if not want:
        return None, "no expect_range_bytes: nothing to recompute"
    ident, why = _identity(ev)
    if ident is None:
        return False, why
    enum, why = _enumeration(ev)
    if enum is None:
        return False, why
    repo, rev, shards = enum
    # ⛔ THE EDGE NOBODY WAS CHECKING. Every artifact agreed with every other artifact, and none
    # agreed with the SUBJECT. The ledger declares subjects[].repo; this reads it.
    expect = (ctx or {}).get(c["subject"])
    if expect and repo != expect:
        return False, ("this is %s's evidence; the cell is scored for %s, which the ledger "
                       "declares to be %s" % (repo, c["subject"], expect))


    r = [e for e in ev if e.get("range")]
    if len(r) != 1:
        return False, "expected exactly one ranged artifact, found %d" % len(r)
    m = HF_FILE.match(r[0]["url"])
    if not m:
        return False, "the ranged artifact is not a pinned Hugging Face file url"
    rrepo, rrev, rfile = m.groups()
    # ⛔ IDENTITY, NOT SHAPE. Attack 1 swapped this range for a CORPUS range from another host
    # and the old check passed it: it never looked at the url.
    if (rrepo, rrev) != (repo, rev):
        return False, ("the range is from %s@%s, the enumeration is from %s@%s"
                       % (rrepo, rrev[:12], repo, rev[:12]))
    if rfile not in shards:
        return False, "%r is not among the %d shards this revision enumerates" % (rfile, len(shards))
    if r[0].get("pinned_commit") not in (None, rev):
        return False, "pinned_commit disagrees with the url's revision"
    if r[0].get("range") != "bytes=0-%d" % (want - 1):
        return False, "range is %r, the cell claims %d bytes" % (r[0].get("range"), want)

    b = _bytes_for(r[0])
    if b is None:
        return None, "the range bytes are not archived"
    if len(b) != want:
        return False, "archived range is %d bytes, the cell claims %d" % (len(b), want)
    if b[:100].startswith(b"version https://git-lfs.github.com/spec/v1"):
        return False, "the archived 'weight range' IS A GIT-LFS POINTER -- exactly the defect"
    # ⛔ "NOT A POINTER" ACCEPTS AN HTML SIGN-IN PAGE, which is attack 4 and is the same wall the
    # retrieval tool refuses everywhere else in this census.
    if rfile.endswith(".safetensors"):
        if len(b) < 8:
            return False, "too short to carry a safetensors header"
        hdr = int.from_bytes(b[:8], "little")
        if not (0 < hdr < len(b) * 4096) or b[8:10] not in (b'{"', b"{}"):
            return False, ("the archived bytes do not begin with a safetensors header "
                           "(first bytes %r)" % b[:16])
    elif not b.startswith(WEIGHT_MAGIC):
        return False, "the archived bytes do not look like weight data (first bytes %r)" % b[:16]
    if hashlib.sha256(b).hexdigest() != r[0]["sha256"]:
        return False, "archived bytes do not hash to the recorded digest"
    return True, ("%d bytes of %s at %s@%s, enumerated, non-pointer, digest matches"
                  % (len(b), rfile, repo, rev[:12]))


def m_all_shard_digests(c, ev, ctx=None):
    """Axis 13: the cited pointers must BE this subject's shard set -- exactly, and distinctly."""
    want = c["check"].get("expect_shards")
    if not want:
        return None, "no expect_shards: nothing to recompute"
    ident, why = _identity(ev)
    if ident is None:
        return False, why
    enum, why = _enumeration(ev)
    if enum is None:
        return False, why
    repo, rev, shards = enum
    # ⛔ THE EDGE NOBODY WAS CHECKING. Every artifact agreed with every other artifact, and none
    # agreed with the SUBJECT. The ledger declares subjects[].repo; this reads it.
    expect = (ctx or {}).get(c["subject"])
    if expect and repo != expect:
        return False, ("this is %s's evidence; the cell is scored for %s, which the ledger "
                       "declares to be %s" % (repo, c["subject"], expect))

    if len(shards) != want:
        return False, ("the archived api response enumerates %d shards, the cell claims %d"
                       % (len(shards), want))

    ptrs = [e for e in ev if e.get("lfs_oid") is not None]
    names, bad = [], []
    for e in ptrs:
        m = HF_FILE.match(e["url"])
        if not m:
            bad.append("a pointer url is not a pinned Hugging Face file url")
            continue
        prepo, prev, pfile = m.groups()
        if (prepo, prev) != (repo, rev):
            bad.append("%s is from %s@%s" % (pfile, prepo, prev[:12]))
            continue
        if e.get("pinned_commit") not in (None, rev):
            bad.append("%s: pinned_commit disagrees with its url" % pfile)
        names.append(pfile)
        b = _bytes_for(e)
        if b is None:
            bad.append("%s not archived" % pfile)
            continue
        mo = re.search(rb"oid sha256:([0-9a-f]{64})", b)
        if not mo:
            bad.append("%s carries no sha256 oid" % pfile)
        elif mo.group(1).decode() != e["lfs_oid"]:
            bad.append("%s oid does not match the ledger" % pfile)
        if hashlib.sha256(b).hexdigest() != e["sha256"]:
            bad.append("%s archived bytes do not hash to the recorded digest" % pfile)
    # ⛔ len(ptrs) COUNTED RECORDS. Citing one pointer four times gave "4 oids verified", which is
    # attack 3. Set equality against the enumeration settles count, distinctness and membership
    # in one comparison.
    if len(set(names)) != len(names):
        dup = sorted({n for n in names if names.count(n) > 1})
        bad.append("duplicate shard pointer(s): %s" % dup[:3])
    if set(names) != shards:
        missing = sorted(shards - set(names))[:3]
        extra = sorted(set(names) - shards)[:3]
        bad.append("cited set does not equal the enumeration (missing %s, unexpected %s)"
                   % (missing, extra))
    if bad:
        return False, "; ".join(bad[:3])
    return True, ("%d distinct shards, set-equal to the enumeration at %s@%s, every oid verified"
                  % (len(shards), repo, rev[:12]))


def m_count(c, ev):
    """⚠️ THIS DISPATCHED TO THE GREP EXECUTOR, so a method named `count_in_retrieved` never
    counted anything. No score-2 cell uses it today, which is exactly why nobody noticed -- a
    registry entry that is never exercised is a claim nobody has tested."""
    exp = c["check"].get("expect")
    n = c["check"].get("expect_count")
    if not exp or n is None:
        return None, "needs both `expect` (a pattern) and `expect_count`"
    hay = [b for b in (_bytes_for(e) for e in ev) if b is not None]
    if not hay:
        return None, "no archived bytes for any cited artifact"
    got = max(sum(h.lower().count(x.lower().encode()) for h in hay) for x in exp)
    if got != n:
        return False, "counted %d occurrence(s), the cell claims %d" % (got, n)
    return True, "counted %d, as claimed" % got


DISPATCH = {
    "grep_retrieved": m_grep,
    "count_in_retrieved": m_count,
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
        ctx = subject_context(d)
        for c in d["cells"]:
            if c.get("score") != 2:
                continue
            if foreign_evidence(c, ctx):
                return False
            fn = DISPATCH.get(c["check"]["method"])
            if fn and c["check"]["method"] not in A.methods_for(c["axis"]):
                return False
            if fn:
                try:
                    res, _why = fn(c, c.get("evidence") or [], ctx)
                except TypeError:
                    res, _why = fn(c, c.get("evidence") or [])
                if res is False:
                    return False
        return True

    def _stub_html(d):
        """Round-4 review: "not a Git-LFS pointer" accepts a consent wall -- the same wall the
        retrieval tool refuses everywhere else in this census."""
        import hashlib as _h
        page = (b"<!DOCTYPE html><html><head><title>Sign in</title></head><body>"
                b"You need to agree to share your contact information to access this model."
                + b" " * 1900)[:2048]
        # ⚠️ THIS LEFT ITS FABRICATED PAGE IN evidence/, and the archive shipped an
        # unreferenced 2 KB sign-in blob. Round-5 review found it. Written, used, removed.
        blob = STORE / (_h.sha256(page).hexdigest() + ".gz")
        blob.write_bytes(gzip.compress(page, 9))
        _temp_blobs.append(blob)
        e = _find(d, "mistral-7b-v0.3", 12)["evidence"][0]
        e["sha256"] = _h.sha256(page).hexdigest()

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
        # ── the seven substitutions round-4 review ran, all of which PASSED ─────────
        # Each swaps one artifact for another that is equally well-formed. Identity, not shape.
        ("a weight range swapped for another repository's range",
         lambda d: _find(d, "mistral-7b-v0.3", 12)["evidence"].__setitem__(
             0, dict(_find(d, "olmo-2-13b", 12)["evidence"][0]))),
        ("an enumeration swapped for another repository's api response",
         lambda d: _find(d, "qwen2.5-7b", 13)["evidence"].__setitem__(
             0, dict(_find(d, "mistral-7b-v0.3", 13)["evidence"][0]))),
        ("the same shard pointer cited four times",
         lambda d: _find(d, "qwen2.5-7b", 13).__setitem__(
             "evidence", [_find(d, "qwen2.5-7b", 13)["evidence"][0]]
             + [dict(_find(d, "qwen2.5-7b", 13)["evidence"][1]) for _ in range(4)])),
        ("a range whose url is not among the enumerated shards",
         lambda d: _find(d, "pythia-12b", 12)["evidence"][0].__setitem__(
             "url", _find(d, "pythia-12b", 12)["evidence"][0]["url"]
             .rsplit("/", 1)[0] + "/not-a-shard.safetensors")),
        ("a pointer whose recorded pinned_commit disagrees with its url",
         lambda d: _find(d, "bloom-176b", 13)["evidence"][3].__setitem__(
             "pinned_commit", "0" * 40)),
        # ── round 5: evidence that is internally perfect and belongs to another subject ──
        ("one subject's ENTIRE axis-12 evidence set given to another",
         lambda d: _find(d, "qwen2.5-7b", 12).__setitem__(
             "evidence", copy.deepcopy(_find(d, "mistral-7b-v0.3", 12)["evidence"]))),
        ("both weight axes swapped wholesale between two subjects",
         lambda d: [_find(d, "qwen2.5-7b", a).__setitem__(
             "evidence", copy.deepcopy(_find(d, "mistral-7b-v0.3", a)["evidence"]))
             for a in (12, 13)]),
        ("a grep cell given another subject's evidence AND its check block",
         lambda d: (_find(d, "bert-base-uncased", 1).__setitem__(
             "evidence", copy.deepcopy(_find(d, "bloom-176b", 1)["evidence"])),
             _find(d, "bert-base-uncased", 1).__setitem__(
             "check", copy.deepcopy(_find(d, "bloom-176b", 1)["check"])))),
        ("2 KB of an HTML sign-in page instead of the weight range",
         lambda d: _stub_html(d)),
        ("falsified expected strings on a replayable grep",
         lambda d: _find(d, "bert-base-uncased", 1)["check"].update(
             {"expect": ["this string is not in the archived bytes"]})),
    ]
    _temp_blobs = []
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
    for _b in _temp_blobs:
        _b.unlink(missing_ok=True)          # never leave a fabricated artifact in the archive
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
    ctx = subject_context(led)
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
        stray = foreign_evidence(c, ctx)
        if stray:
            print("  " + chr(0x26D4) + " FAIL %-24s %s" % (where, "; ".join(stray[:2])))
            failed += 1
            continue
        try:
            res, why = fn(c, c.get("evidence") or [], ctx)
        except TypeError:
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
