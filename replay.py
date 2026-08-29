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


MIN_LITERAL = 4


def m_grep(c, ev):
    """Every literal in `expect` must appear in the archived bytes of some cited artifact."""
    exp = c["check"].get("expect")
    if not exp:
        return None, "no `expect` list: nothing to replay, so the method name is a label"
    # ⛔ NOTHING REQUIRED A LITERAL TO DISCRIMINATE. `expect = ["e"]` passed: grep_retrieved is only
    # as strong as its string, and the string was unconstrained.
    weak = [x for x in exp if len(x.strip()) < MIN_LITERAL]
    if weak:
        return False, ("literal(s) too short to discriminate anything: %s (minimum %d characters)"
                       % (weak, MIN_LITERAL))
    # ⛔ AND THE CITED SET WAS A MAXIMUM, NOT A REQUIREMENT: dropping a co-cited artifact passed.
    want_n = c["check"].get("expect_artifacts")
    if want_n is not None and len(ev) != want_n:
        return False, ("the cell cites %d artifact(s); its check requires %d"
                       % (len(ev), want_n))
    docs = [(e, _bytes_for(e)) for e in ev]
    docs = [(e, b) for e, b in docs if b is not None]
    if not docs:
        return None, "no archived bytes for any cited artifact"
    # ⛔ THIS ORed OVER THE UNION, answering "do these strings occur somewhere in this pile" rather
    # than "does one of this subject's documents say this". Every literal must be found in ONE
    # artifact, and that artifact is named in the verdict.
    for e, b in docs:
        low = b.lower()
        if all(x.lower().encode() in low for x in exp):
            return True, ("all %d expected string(s) found in %s"
                          % (len(exp), e["url"].rsplit("/", 1)[-1][:40]))
    missing = [x for x in exp
               if not any(x.lower().encode() in b.lower() for _e, b in docs)]
    return False, ("no single cited artifact contains all %d expected string(s)%s"
                   % (len(exp), ("; never found anywhere: %s" % missing) if missing else ""))


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


def source_key(u):
    """A stable identity for the PUBLISHING SOURCE an artifact comes from."""
    rest = u.split("//", 1)[-1]
    host = rest.split("/", 1)[0]
    tail = rest.split("/", 1)[1] if "/" in rest else ""
    p = [x for x in tail.split("/") if x]
    if host == "huggingface.co":
        if p and p[0] == "api":
            return ("hf:" if len(p) > 1 and p[1] == "models" else "hfds:") + "/".join(p[2:4])
        if p and p[0] == "datasets":
            return "hfds:" + "/".join(p[1:3])
        return "hf:" + "/".join(p[:2])
    if host in ("raw.githubusercontent.com", "github.com"):
        return "gh:" + "/".join(p[:2])
    if host == "api.github.com":
        return "gh:" + "/".join(p[1:3])
    if host == "arxiv.org":
        return "arxiv:" + p[-1]
    return "host:" + host


def cited_by(led):
    """url -> {subjects citing it}. ⛔ THIS IS NOT THE OWNERSHIP ORACLE AND MUST NOT BE USED AS ONE.

    It is derived from the cells being audited, so a cell's own subject is in the set by
    construction and a SYMMETRIC swap redefines every owner. That is precisely how ownership
    failed: `main()` passed this map and the check became unreachable, while `--selftest` passed a
    frozen copy and the same mutation was rejected. Ownership now comes from `subjects[].sources`,
    which a mutation of cells cannot move.

    Kept because it is a useful description of the ledger, and because an external harness may
    still call it -- but nothing in the gate reads it.
    """
    out = {}
    for c in led.get("cells", []):
        for e in (c.get("evidence") or []):
            out.setdefault(e["url"], set()).add(c["subject"])
    return out


def subject_context(led):
    """What the ledger DECLARES about each subject: its repository and its permitted sources.

    ⛔ OWNERSHIP USED TO BE INFERRED FROM THE CELLS BEING AUDITED. `cited_by()` walked the same
    ledger `validate()` was checking, so a cell's own subject was in the owner set by construction
    and the check could not fire at runtime -- and a SYMMETRIC swap simply redefined each
    artifact's owner. Both round-7 reviewers found this, one by reading the conjunct and one by
    exchanging two cells and watching the ledger accept it.

    ⇒ These lists live on the SUBJECT RECORD. They do not travel with evidence, they do not travel
    with a check block, and exchanging two cells cannot move them.
    """
    return {s["id"]: {"repo": s.get("repo"),
                      "sources": set(s.get("sources") or ()),
                      "axis_sources": {int(k): set(v)
                                       for k, v in (s.get("axis_sources") or {}).items()},
                      "axis_documents": {int(k): set(v)
                                         for k, v in (s.get("axis_documents") or {}).items()},
                      "axis_literals": {int(k): sorted(v)
                                        for k, v in (s.get("axis_literals") or {}).items()},
                      "axis_method": {int(k): v
                                      for k, v in (s.get("axis_method") or {}).items()}}
            for s in led.get("subjects", [])}


def foreign_evidence(cell, ctx, _unused=None):
    """Evidence from a source this subject does not declare. POSITIVE, not merely not-another's.

    ⚠️ The previous test was purely negative -- "not some other subject's artifact" -- so a
    document belonging to NOBODY passed, and nothing required a cell to cite something its own
    subject publishes or names. This asks the other question.
    """
    dec = (ctx or {}).get(cell["subject"])
    # ⛔ FAILS CLOSED. This read `if not allowed: return []` -- so DELETING a subject's declaration
    # turned the control off, which is the optional-field failure mode for the third time. A scored
    # cell whose subject declares nothing is a defect, not an unconstrained cell.
    if dec is None:
        return ["%s is not a declared subject" % cell["subject"]]
    allowed = dec.get("sources") or set()
    if not allowed:
        return ["%s declares no sources, so nothing constrains this cell's evidence"
                % cell["subject"]]
    # ⛔ AND THE AXIS, NOT ONLY THE SUBJECT. Exchanging a subject's OWN cells passed every check:
    # pythia's corpus cell scored VERIFIED on its training-code README. The subject was right and
    # the axis was wrong, and the per-axis profile is what the paper asks a reader to read.
    per_axis = (dec.get("axis_sources") or {}).get(cell["axis"])
    if cell.get("score") and per_axis is None:
        return ["%s/axis%d has no declared axis_sources; a scored cell with no policy is a defect"
                % (cell["subject"], cell["axis"])]
    bad = []
    for e in (cell.get("evidence") or []):
        k = source_key(e["url"])
        if k not in allowed:
            owner = sorted(s for s, v in (ctx or {}).items() if k in (v.get("sources") or set()))
            bad.append("%s is from %s, which %s does not declare%s"
                       % (e["url"].rsplit("/", 1)[-1][:34], k, cell["subject"],
                          " (it is %s's)" % ", ".join(owner) if owner else ""))
        elif per_axis is not None and k not in per_axis:
            elsewhere = sorted(a for a, ks in (dec.get("axis_sources") or {}).items() if k in ks)
            bad.append("%s is from %s, which this subject declares for axis %s, not for axis %d"
                       % (e["url"].rsplit("/", 1)[-1][:34], k,
                          ", ".join(str(a) for a in elsewhere) or "no axis", cell["axis"]))
    # ⛔ AND THE DOCUMENT, NOT ONLY THE SOURCE. One repository legitimately serves several axes --
    # pythia's code and hyperparameter cells both rest on gh:EleutherAI/pythia -- so a source-level
    # rule let a swap between them pass. 95 of 396 intra-subject transplants survived on exactly
    # that.
    per_doc = (dec.get("axis_documents") or {}).get(cell["axis"])
    if cell.get("score") and per_doc is None:
        bad.append("%s/axis%d has no declared axis_documents" % (cell["subject"], cell["axis"]))
    elif per_doc is not None:
        cited = {e["url"] for e in (cell.get("evidence") or [])}
        if cited != per_doc:
            extra = sorted(cited - per_doc)[:2]
            missing = sorted(per_doc - cited)[:2]
            bad.append("the cited documents are not those this subject declares for axis %d"
                       % cell["axis"]
                       + (" (unexpected %s)" % [u.rsplit("/", 1)[-1][:30] for u in extra]
                          if extra else "")
                       + (" (missing %s)" % [u.rsplit("/", 1)[-1][:30] for u in missing]
                          if missing else ""))
    # ⛔ AND THE LITERALS, where several axes rest on ONE document. olmo's hyperparameter,
    # environment, data-order and eval cells all rest on the training config, so a swap between
    # them moved only the check block -- the document policy could not see it.
    # And the METHOD, so a check block transplanted between two axes resting on ONE document is
    # visible. An ASSERTED cell names no mechanical check by definition -- but one legitimately
    # carries a block documenting its demotion, so the rule is "the declared one", not "none".
    # ⛔ THE PER-AXIS CHECKS WERE CONDITIONAL ON THE DECLARATION EXISTING, so deleting a key
    # DISABLED the rule instead of failing the cell: removing axis_method for one cell gave zero
    # defects and a passing gate. That is the optional-guard failure mode for the FOURTH round
    # running, and the rule is now explicit -- every scored cell carries a COMPLETE policy, and a
    # missing key is a defect rather than an exemption. An axis with no literals declares [].
    am = dec.get("axis_method") or {}
    al = dec.get("axis_literals") or {}
    if cell.get("score"):
        for _name, _map in (("axis_method", am), ("axis_literals", al)):
            if cell["axis"] not in _map:
                bad.append("axis %d has no declared %s; a missing key is a defect, not an "
                           "exemption (declare [] or null where there is genuinely none)"
                           % (cell["axis"], _name))
    if cell.get("score") and cell["axis"] in am:
        _chk = cell.get("check")
        got_m = _chk.get("method") if isinstance(_chk, dict) else None
        if got_m != am[cell["axis"]]:
            bad.append("axis %d carries method %r; this subject declares %r for it"
                       % (cell["axis"], got_m, am[cell["axis"]]))
    want_lit = al.get(cell["axis"])
    if cell.get("score") and cell["axis"] in al:
        _chk2 = cell.get("check")
        got = sorted((_chk2.get("expect") if isinstance(_chk2, dict) else None) or [])
        if got != want_lit:
            # ⛔ THIS TRUNCATED BOTH LISTS AT [:2], so a mismatch in a later element printed
            # "looks for [A, B]; declares [A, B]" -- a diagnostic identical on both sides of the
            # thing it is diagnosing. Show the DIFFERENCE.
            _extra = [x for x in got if x not in want_lit]
            _absent = [x for x in want_lit if x not in got]
            bad.append("axis %d literals disagree with the declared policy%s%s"
                       % (cell["axis"],
                          "; not declared: %s" % _extra if _extra else "",
                          "; declared but absent: %s" % _absent if _absent else ""))
    return bad


def m_range(c, ev, ctx=None):
    """A ranged artifact, ANCHORED: the url must appear in a co-cited artifact's archived bytes.

    ⛔ THIS EXECUTOR RECEIVED NONE OF THE IDENTITY REPAIR. It compared len(bytes) to the range spec
    and returned True, never reading the url, the context, or the document that names the path. So
    olmo's CORPUS-OBTAINABLE cell accepted 2 KB of BERT's weights with the olmo-data.org url left
    in place, accepted an arbitrary url with GPT-2's bytes, and accepted having the config deleted.
    A reviewer ran the first end to end: every gate in the project exited 0 and the built paper
    still said the token files were retrievable.

    ⇒ The anchor is available OFFLINE and the ledger already holds it: the ranged url occurs
    verbatim in the archived config that enumerates the corpus. So the pair must be co-cited, and
    the url must be FOUND in the other artifact's bytes. That is what makes this range this
    subject's corpus rather than 2 KB of something.
    """
    r = [e for e in ev if e.get("range")]
    if len(r) != 1:
        return False, "expected exactly one ranged artifact, found %d" % len(r)
    others = [e for e in ev if not e.get("range")]
    if not others:
        return False, ("the ranged artifact is cited alone, so nothing in the ledger says this "
                       "url belongs to this subject")
    b = _bytes_for(r[0])
    if b is None:
        return None, "the range bytes are not archived"

    _spec = r[0]["range"].split("=", 1)[-1]
    _first, _last = (int(x) for x in _spec.split("-"))
    want = _last - _first + 1
    if len(b) != want:
        return False, "archived range is %d bytes, the record claims %d" % (len(b), want)
    if hashlib.sha256(b).hexdigest() != r[0]["sha256"]:
        return False, "archived bytes do not hash to the recorded digest"

    # ⛔ THE ANCHOR BOUND THE DOCUMENT, NOT THE PATH. The config enumerates 1,122 data paths, so
    # relabelling the ranged url to ANY of them still anchored: right host, right corpus, right
    # length, wrong object -- the CoreML shape a third time. The bind step records WHICH position
    # in the enumeration the bytes came from, and the url must be the path at that position.
    idx = c["check"].get("enumerated_index")
    anchored = []
    for e in others:
        hay = _bytes_for(e)
        if hay is None or r[0]["url"].encode() not in hay:
            continue
        if idx is not None:
            paths = [l.strip()[2:] for l in hay.decode("utf-8", "replace").split(chr(10))
                     if l.startswith("    - ")]
            if idx >= len(paths):
                return False, ("the cell records enumeration index %d and the co-cited document "
                               "lists %d paths" % (idx, len(paths)))
            if paths[idx] != r[0]["url"]:
                return False, ("the ranged url is not the path at the recorded position: index %d "
                               "of %s is %s" % (idx, e["url"].rsplit("/", 1)[-1][:28],
                                                paths[idx].rsplit("/", 1)[-1][:34]))
        anchored.append(e["url"].rsplit("/", 1)[-1][:34])
    if not anchored:
        return False, ("the ranged url appears in NO co-cited artifact, so nothing connects these "
                       "bytes to this subject's corpus")
    if idx is None:
        return False, ("the cell records no `enumerated_index`, so the url could name any of the "
                       "paths the co-cited document lists")
    # ⚠️ BOTH THE INDEX AND THE URL ARE AUTHOR-WRITTEN, so moving them together relocates the tell
    # rather than removing it. A property OF THE BYTES is what does not move: for a .npy the header
    # carries dtype and shape, recorded at bind time from the fetched bytes.
    hdr = c["check"].get("npy_header")
    if hdr is not None:
        if not b.startswith(b"\x93NUMPY"):
            return False, "the archived range does not begin with the NumPy magic"
        try:
            hlen = int.from_bytes(b[8:10], "little")
            got = b[10:10 + hlen].decode("latin-1").strip().rstrip(chr(0)).strip()
        except Exception:                                            # noqa: BLE001
            return False, "the archived range carries no readable NumPy header"
        if got != hdr:
            return False, ("the archived bytes' NumPy header is %r; the cell records %r"
                           % (got[:60], hdr[:60]))
    return True, ("%d archived bytes, digest matches, and the url is named in %s"
                  % (len(b), anchored[0]))


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
    expect = ((ctx or {}).get(c["subject"]) or {}).get("repo")
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
    expect = ((ctx or {}).get(c["subject"]) or {}).get("repo")
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


def gate(cell, ctx=None, owners=None, led=None):
    """The single admissibility gate for a VERIFIED cell. (ok, why).

    ⛔ THIS LOGIC EXISTED IN THREE PLACES -- main, selftest, and a reviewer's harness -- and only
    one of them had the newest half. Every caller now goes through here, so a gate cannot be
    partially replicated: whatever is added is added everywhere at once.
    """
    if led is None:
        led = json.loads((HERE / "cells.json").read_text(encoding="utf-8"))
    if ctx is None:
        ctx = subject_context(led)
    meth = (cell.get("check") or {}).get("method", "")

    # ⛔ THIS RAN FOR score == 2 ONLY. Thirty of the fifty-four non-zero cells are ASSERTED and
    # received no identity check anywhere in the project -- and they carry points: all 1,381
    # transplants onto them were accepted end to end. Section 6.1's claims-as-checks test, the one
    # that could have killed the paper, is computed entirely from cells nothing was checking.
    stray = foreign_evidence(cell, ctx, owners)
    if stray:
        return False, "; ".join(stray[:2])
    # The same bytes cannot have come from two different urls. This is what catches a swap that
    # leaves the url truthful and replaces the digest AND the archived bytes together.
    _owned = {}
    for _c in led.get("cells", []):
        for _e in (_c.get("evidence") or []):
            _owned.setdefault(_e["sha256"], set()).add(_e["url"])
    for _e in (cell.get("evidence") or []):
        _urls = _owned.get(_e["sha256"], set())
        if len(_urls) > 1:
            return False, ("digest %s is cited under %d different urls; the same bytes cannot "
                           "have been retrieved from all of them"
                           % (_e["sha256"][:12], len(_urls)))
    if cell.get("score") == 1:
        # An ASSERTED cell names no mechanical check by definition. What it must satisfy -- and
        # what nothing checked until now -- is that its evidence comes from a source its subject
        # declares. The method/field requirements below are about REPLAY, which a 1 does not claim.
        return True, "asserted; evidence is from a declared source"
    req = A.required_method(cell["axis"])
    if req and meth not in req:
        return False, ("axis %d REQUIRES %s; %r is registered and permitted but does not bind "
                       "this axis's identity" % (cell["axis"], sorted(req), meth))
    for f in A.required_fields(meth):
        if not (cell.get("check") or {}).get(f):
            return False, ("method %r requires `%s`; without it nothing can be replayed and the "
                           "evidence is unconstrained" % (meth, f))
    if meth not in A.methods_for(cell["axis"]):
        return False, "method %r cannot settle this axis" % meth
    fn = DISPATCH.get(meth)
    if fn is None:
        return False, "method %r has no executor" % meth
    try:
        return fn(cell, cell.get("evidence") or [], ctx)
    except TypeError:
        return fn(cell, cell.get("evidence") or [])


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
        # ⚠️ THE SELF-TEST USED A FROZEN ORACLE and the runtime used the mutated ledger, so a
        # symmetric swap failed here and passed there. Both now read the DECLARATION, which a
        # mutation of cells cannot move -- so this test is runtime-faithful.
        ctx = subject_context(d)
        owners = None
        # ⛔ THIS FILTERED TO score == 2, so the self-test could not see an attack on an
        # ASSERTED cell -- and 30 of the 54 non-zero cells are ASSERTED. The gate now covers
        # every non-zero cell and so must the test that exercises it.
        for c in d["cells"]:
            if not c.get("score"):
                continue
            res, _why = gate(c, ctx, owners, d)
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
        # ── round 6: the seven a reviewer demonstrated still surviving ───────────────
        ("a corpus range backed by another subject's weight bytes, url untouched",
         lambda d: _find(d, "olmo-2-13b", 4)["evidence"][1].__setitem__(
             "sha256", _find(d, "bert-base-uncased", 12)["evidence"][0]["sha256"])),
        ("the document that NAMES the ranged path dropped from the cell",
         lambda d: _find(d, "olmo-2-13b", 4).__setitem__(
             "evidence", [e for e in _find(d, "olmo-2-13b", 4)["evidence"] if e.get("range")])),
        ("a weights cell moved to http_range, which is registered and axis-legal",
         lambda d: (_find(d, "qwen2.5-7b", 12)["check"].__setitem__("method", "http_range"),
                    _find(d, "qwen2.5-7b", 12)["evidence"][0].__setitem__(
                        "sha256", _find(d, "bert-base-uncased", 12)["evidence"][0]["sha256"]))),
        ("a weights cell disarmed by deleting expect_range_bytes",
         lambda d: _find(d, "qwen2.5-7b", 12)["check"].pop("expect_range_bytes", None)),
        ("a seeds cell backed solely by another subject's README containing the literal",
         lambda d: _find(d, "pythia-12b", 8).__setitem__(
             "evidence", copy.deepcopy(_find(d, "bert-base-uncased", 6)["evidence"]))),
        ("a corpus cell backed solely by another subject's arXiv page",
         lambda d: _find(d, "bloom-176b", 1).__setitem__(
             "evidence", copy.deepcopy(_find(d, "gemini-1.5-pro", 1)["evidence"]))),
        # ── round 7: ownership inferred from the audited ledger ──────────────────────
        ("a SYMMETRIC swap, which redefined ownership under the old inferred map",
         lambda d: [_find(d, a, 1).__setitem__("evidence", copy.deepcopy(_find(d, b, 1)["evidence"]))
                    for a, b in (("pythia-12b", "olmo-2-13b"),)] +
                   [_find(d, "olmo-2-13b", 1).__setitem__(
                       "evidence", copy.deepcopy(_find(d, "pythia-12b", 1)["evidence"]))]),
        ("an ASSERTED cell given another subject's evidence (no gate ran for score 1)",
         lambda d: _find(d, "bloom-176b", 7).__setitem__(
             "evidence", copy.deepcopy(_find(d, "llama-3.1-8b", 1)["evidence"]))),
        ("a ranged url relabelled to a different path the same document enumerates",
         lambda d: _find(d, "olmo-2-13b", 4)["check"].__setitem__("enumerated_index", 5)),
        ("a cell backed by a document belonging to nobody",
         lambda d: _find(d, "bert-base-uncased", 1).__setitem__(
             "evidence", [{"url": "https://example.org/bert-history", "retrieved": "2026-08-29",
                           "sha256": "c" * 64}])),
        # ── round 8: the subject is right and the AXIS is wrong ──────────────────────
        ("a subject's OWN corpus and training-code cells exchanged, evidence and check",
         lambda d: (_find(d, "pythia-12b", 1).__setitem__(
             "evidence", copy.deepcopy(_find(d, "pythia-12b", 6)["evidence"])),
             _find(d, "pythia-12b", 1).__setitem__(
                 "check", copy.deepcopy(_find(d, "pythia-12b", 6)["check"])))),
        ("two axes of one subject, their check blocks exchanged",
         lambda d: _find(d, "olmo-2-13b", 6).__setitem__(
             "check", copy.deepcopy(_find(d, "olmo-2-13b", 1)["check"]))),
        ("a subject's axis_method policy DELETED for one axis",
         lambda d: [s["axis_method"].pop("1", None) for s in d["subjects"]
                    if s["id"] == "pythia-12b"]),
        ("a subject's axis_literals policy DELETED, then the literal weakened",
         lambda d: ([s.get("axis_literals", {}).pop("6", None) for s in d["subjects"]
                     if s["id"] == "bert-base-uncased"],
                    _find(d, "bert-base-uncased", 6)["check"].__setitem__("expect", ["data"]))),
        ("a check block copied between two subjects' cells",
         lambda d: _find(d, "olmo-2-13b", 11).__setitem__(
             "check", copy.deepcopy(_find(d, "pythia-12b", 1)["check"]))),
        ("a subject's source declaration DELETED, then foreign evidence transplanted in",
         lambda d: ([s.pop("sources", None) for s in d["subjects"]
                     if s["id"] == "pythia-12b"],
                    _find(d, "pythia-12b", 1).__setitem__(
                        "evidence", copy.deepcopy(_find(d, "olmo-2-13b", 1)["evidence"])))),
        ("a replayable literal weakened to a single character",
         lambda d: _find(d, "bert-base-uncased", 6)["check"].__setitem__("expect", ["e"])),
        ("a co-cited artifact dropped, leaving the cited set smaller than required",
         lambda d: _find(d, "bert-base-uncased", 1).__setitem__(
             "evidence", _find(d, "bert-base-uncased", 1)["evidence"][:1])),
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
        # ⛔ AN ATTACK THAT NEVER RAN WAS REPORTED AS "CORRECTLY REJECTED". This loop caught broad
        # Exception and treated it as a rejection, so a mutation raising KeyError -- because the
        # cell it targeted had no `check` block at all -- came back green. That is a vacuous
        # control INSIDE the mechanism built to prove controls are not vacuous, which is the
        # sharpest form this project's recurring defect has taken. Round-8 review found it.
        #
        # A setup failure is now a HARD FAILURE, and every mutation must PROVE it changed the
        # ledger before the verdict counts for anything.
        before = json.dumps(led, sort_keys=True)
        d0 = copy.deepcopy(led)
        try:
            mut(d0)
        except Exception as exc:                                    # noqa: BLE001
            print("  " + chr(0x26D4) + " BROKEN  %s" % name)
            print("            the mutation itself raised %r -- it never ran, so its green was "
                  "meaningless" % (exc,))
            bad += 1
            continue
        if json.dumps(d0, sort_keys=True) == before:
            print("  " + chr(0x26D4) + " INERT   %s" % name)
            print("            the mutation changed nothing, so rejecting it proves nothing")
            bad += 1
            continue
        try:
            survived = run_one(mut)
        except Exception as exc:                                    # noqa: BLE001
            print("  " + chr(0x26D4) + " BROKEN  %s" % name)
            print("            evaluating it raised %r" % (exc,))
            bad += 1
            continue
        print(("  ok    " if not survived else "  " + chr(0x26D4) + " PASSES ") + "%s" % name)
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
    owners = None
    ok = failed = unreplayable = asserted_ok = 0
    print("=" * 78)
    print("  replaying every VERIFIED check over archived bytes")
    print("=" * 78)
    print()
    for c in led["cells"]:
        if not c.get("score"):
            continue
        if c.get("score") == 1:
            res, why = gate(c, ctx, owners, led)
            where1 = "%s/axis%d" % (c["subject"], c["axis"])
            if res is False:
                print("  " + chr(0x26D4) + " FAIL %-24s %s" % (where1, why))
                failed += 1
            else:
                asserted_ok += 1
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
        res, why = gate(c, ctx, owners, led)
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
    print("  %d ASSERTED cell(s) also pass the ownership gate" % asserted_ok)
    if unreplayable and strict:
        print("  --strict: a shape-verified check does not support the sentence 'a registered")
        print("  mechanical check over its content succeeded'.")
    print("=" * 78)
    return 1 if (failed or (strict and unreplayable)) else 0


if __name__ == "__main__":
    raise SystemExit(main())
