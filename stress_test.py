"""The hostile referee. Every case here TRIES TO GET A BAD CELL PAST validate().

obl-metric's round-2 lesson, recorded before this instrument had a single subject: *a test written
by the artifact's author validates the author's model of the artifact.* Its own suite passed 0/0
while an external `revision_check.py` found nine manuscript-vs-engine mismatches. So this suite is
written adversarially -- each case is an attempt to smuggle something through, and it FAILS if the
validator lets it in.

The last group is the substantive one. It does not test a rule; it demonstrates the arithmetic
that makes N/A dangerous: because N/A leaves the DENOMINATOR, a release can raise its as-coded
score by disclosing LESS, provided the undisclosed axes are ones it can call inapplicable. If that
property ever stops holding, the scoring changed and the paper's warning is stale.

    python stress_test.py       exit 0 = every attack was caught and the honest census passed
"""
import ast
import io
import json
import pathlib
import sys

import axes as A
import mp_metric as M

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

EV = [{"url": "https://example.org/a", "retrieved": "2026-08-01", "sha256": "a" * 64}]
passed, failed = 0, 0


def full_census(subject="s1", score=0, cell_over=None, **over):
    """A complete, valid census: every one of the 22 axes present for one subject.

    ⚠️ `**over` updates the LEDGER. An earlier test passed `check=...` expecting it to reach the
    cells; it became a stray top-level key and the test passed for the wrong reason -- vacuously,
    like the two PDF controls found the same day. `cell_over` is the parameter that reaches cells.

    The default score-2 check now picks a method VALID FOR EACH AXIS, because a fixture that
    violates method-axis compatibility on 20 of 22 axes cannot be used to test anything else.
    """
    cells = []
    for ax in A.BY_ID:
        # A valid census respects the instrument OWN caps: a completeness or search axis
        # cannot be 2 for anyone, so a fixture claiming otherwise is not a valid census.
        c = {"subject": subject, "axis": ax,
             "score": min(score, A.max_for(ax, "open-weights")) if score else score}
        if c["score"] and c["score"] > 0:
            c["evidence"] = list(EV)
            if c["score"] == 2:
                # An axis that REQUIRES a method gets it; otherwise prefer grep. A valid
                # census must satisfy the instrument's own requirements, not merely its
                # permissions -- which is the distinction round-6 review turned into a defect.
                req = A.required_method(ax)
                valid = sorted(A.methods_for(ax))
                meth = (sorted(req)[0] if req else
                        ("grep_retrieved" if "grep_retrieved" in valid else
                         (valid[0] if valid else "grep_retrieved")))
                c["check"] = {"method": meth, "asserts": "the material is present",
                              "observed": "it is present"}
                for f in A.required_fields(meth):
                    c["check"][f] = ["something"] if f == "expect" else 1
            if cell_over:
                c.update({k: dict(v) if isinstance(v, dict) else v
                          for k, v in cell_over.items()})
        cells.append(c)
    # A valid census DECLARES its policy: which sources, documents, methods and literals may
    # settle which axis. The rule fails closed, so a fixture without one is not a valid census --
    # which is the point of failing closed.
    import replay as _R                                                   # noqa: PLC0415
    _urls = sorted({e["url"] for c in cells for e in (c.get("evidence") or [])})
    _srcs = sorted({_R.source_key(u) for u in _urls})
    led = {"as_of": "2026-08-01",
           "subjects": [{"id": subject, "kind": "open-weights", "sources": _srcs,
                         "axis_sources": {str(c["axis"]): _srcs for c in cells if c.get("score")},
                         "axis_documents": {str(c["axis"]):
                                            sorted(e["url"] for e in (c.get("evidence") or []))
                                            for c in cells if c.get("score")},
                         "axis_method": {str(c["axis"]): (c.get("check") or {}).get("method")
                                         for c in cells if c.get("score")},
                         # Every scored axis declares literals EXPLICITLY, [] where there are
                         # none -- a missing key is now a defect, not an exemption.
                         "axis_literals": {str(c["axis"]):
                                           sorted((c.get("check") or {}).get("expect") or [])
                                           for c in cells if c.get("score")}}],
           "cells": cells}
    led.update(over)
    return led


def must_catch(name, led, needle):
    """The validator MUST report a defect mentioning `needle`."""
    global passed, failed
    d = M.validate(led)
    hit = any(needle.lower() in x.lower() for x in d)
    print(("  ok    " if hit else "  FAIL  ") + name)
    if hit:
        passed += 1
    else:
        failed += 1
        print("          validator said: %s" % (d[:2] or "NOTHING — it let this through"))


def must_pass(name, led):
    global passed, failed
    d = M.validate(led)
    print(("  ok    " if not d else "  FAIL  ") + name)
    if not d:
        passed += 1
    else:
        failed += 1
        print("          unexpected defects: %s" % d[:3])


print("=" * 78)
print("  hostile referee — every case below is an ATTACK on validate()")
print("=" * 78)
print()

# ── the evidence standard ─────────────────────────────────────────────────────────────
led = full_census(score=1)
del led["cells"][0]["evidence"]
must_catch("a CLAIMED cell with no evidence record", led, "no evidence")

led = full_census(score=2)
del led["cells"][3]["check"]
must_catch("a VERIFIED cell with no check at all", led, "check` OBJECT")

# ── the three holes round-1 review drove through the validator ─────────────────────────
led = full_census(score=2)
for c in led["cells"]:
    c["check"] = "read a document"
must_catch("VERIFIED on a free-text check -- the round-1 attack", led, "not a control")

led = full_census(score=2)
led["cells"][0]["check"] = {"method": "i_looked_at_it", "asserts": "a", "observed": "b"}
must_catch("a check method that is not implemented", led, "not registered")

led = full_census(score=2)
led["cells"][0]["check"] = {"method": "http_range", "asserts": "", "observed": "y"}
must_catch("a check with no stated assertion", led, "check.asserts is empty")

led = full_census(score=1)
led["cells"][0]["evidence"] = [{"url": "https://x/a", "retrieved": "2026-99-99",
                               "sha256": "b" * 64}]
must_catch("a retrieval date that is not a real date", led, "real yyyy-mm-dd")

led = full_census(score=1)
led["cells"][0]["evidence"] = [{"url": "https://x/a", "retrieved": "2099-01-01",
                               "sha256": "b" * 64}]
must_catch("a retrieval date in the future", led, "future")

led = full_census(score=1)
led["cells"][0]["evidence"] = [{"url": "https://x/same", "retrieved": "2026-08-01",
                               "sha256": "c" * 64}]
led["cells"][1]["evidence"] = [{"url": "https://x/same", "retrieved": "2026-08-01",
                               "sha256": "d" * 64}]
must_catch("one url recorded under two different digests", led, "two different digests")

led = full_census(score=1)
led["cells"][0]["evidence"] = [{"url": "https://x/a", "retrieved": "2026-08-01",
                               "sha256": "not-a-digest"}]
must_catch("evidence whose sha256 is not a digest", led, "sha256")

led = full_census(score=1)
led["cells"][0]["evidence"] = [{"url": "https://x/a", "retrieved": "Sept 2026",
                               "sha256": "b" * 64}]
must_catch("evidence with an unparseable retrieval date", led, "yyyy-mm-dd")

led = full_census(score=1)
led["cells"][0]["evidence"] = [{"url": "ftp://x/a", "retrieved": "2026-08-01",
                               "sha256": "b" * 64}]
must_catch("evidence with no retrievable url", led, "url")

# ── the N/A escape hatch ──────────────────────────────────────────────────────────────
led = full_census(score=0)
led["cells"][0]["score"] = None                    # axis 1 -- can never be N/A
led["cells"][0]["na_reason"] = "we would rather not say"
must_catch("N/A on an axis that can never be N/A", led, "never be n/a")

led = full_census(score=0)
for c in led["cells"]:
    if c["axis"] in A.NA_PERMITTED:
        c["score"] = None                          # permitted axis, but no reason given
must_catch("N/A in bulk with no per-cell reason", led, "no na_reason")

# ── completeness: absent is not zero ──────────────────────────────────────────────────
led = full_census(score=0)
led["cells"] = [c for c in led["cells"] if c["axis"] != 7]
must_catch("a subject-axis pair simply missing", led, "missing")

led = full_census(score=0)
led["cells"].append(dict(led["cells"][0]))
must_catch("the same cell recorded twice", led, "duplicate")

led = full_census(score=0)
led["cells"][0]["axis"] = 99
must_catch("a cell on an axis that does not exist", led, "not one of the 22")

led = full_census(score=0)
led["cells"][0]["subject"] = "ghost"
must_catch("a cell for an undeclared subject", led, "not declared")

led = full_census(score=0)
led["cells"][0]["score"] = 3
must_catch("a score outside 2/1/0/null", led, "not 2/1/0")

# ── the positive control ──────────────────────────────────────────────────────────────
must_pass("an honest, complete census validates", full_census(score=1))

# ── the wall detector: a gate versus a document that describes one ─────────────────────
print()
print("  --- fetch_artifact: is it a gate, or a manual about one? ---")
import fetch_artifact as FA

long_doc = (b"# Downloading the weights" + b" filler." * 2000 +
            b" Visit the website, read and accept the license, then download.")
tiny_gate = b"<html><body>You need to agree to share your contact information</body></html>"
challenge = b"<html>" + b"x" * 9000 + b"checking your browser before accessing</html>"

cases = [
    ("10 KB manual that MENTIONS accepting a licence is NOT a gate", long_doc, None),
    ("a short page that only says 'you need to agree' IS a gate", tiny_gate, "gate"),
    ("a long page containing a browser challenge IS a gate", challenge, "challenge"),
]
for name, body, want in cases:
    got = FA.looks_like_a_wall(body, "200")
    ok = (got is None) if want is None else (got is not None)
    print(("  ok    " if ok else "  FAIL  ") + name)
    passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)
    if not ok:
        print("          got: %r" % got)

# a Git-LFS pointer is ~130 bytes and is exactly the artifact axis 13 needs
lfs = b"version https://git-lfs.github.com/spec/v1" + bytes([10]) + b"oid sha256:" + b"a" * 64
ok = FA.looks_like_a_wall(lfs, "200") is None
print(("  ok    " if ok else "  FAIL  ") + "a 130-byte Git-LFS pointer is accepted, not refused")
passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)

# ── the arithmetic that makes N/A dangerous ───────────────────────────────────────────
print()
print("  --- the N/A property, demonstrated rather than asserted ---")
base = full_census(score=1)                                   # all 22 at CLAIMED
sc_base = M.score(base)["s1"]

hidden = full_census(score=1)
for c in hidden["cells"]:
    if c["axis"] in A.NA_PERMITTED:                           # disclose LESS on 7 axes
        c["score"] = None
        c["na_reason"] = "api-only release"
        c.pop("evidence", None)
sc_hidden = M.score(hidden)["s1"]

print("    all 22 disclosed at CLAIMED      as-coded %.3f" % sc_base["as_coded"])
print("    7 axes withdrawn as N/A          as-coded %.3f   [N/A→0 %.3f, N/A→2 %.3f]"
      % (sc_hidden["as_coded"], sc_hidden["na_as_0"], sc_hidden["na_as_2"]))

inflates = sc_hidden["as_coded"] >= sc_base["as_coded"]
band_catches = sc_hidden["na_as_0"] < sc_base["as_coded"]
print(("  ok    " if inflates else "  FAIL  ") +
      "withdrawing axes does NOT lower the as-coded score (this is the hazard)")
passed, failed = (passed + 1, failed) if inflates else (passed, failed + 1)
print(("  ok    " if band_catches else "  FAIL  ") +
      "the N/A→0 column exposes it (%.3f < %.3f)" % (sc_hidden["na_as_0"], sc_base["as_coded"]))
passed, failed = (passed + 1, failed) if band_catches else (passed, failed + 1)

# ── the attacks round-3 review ran by hand, now run every time ───────────────────────────────
# ⛔ ALL THREE OF THESE VALIDATED CLEAN when a reviewer tried them. The validator confirmed a
# method NAME was on an allowlist and asked nothing further.
must_catch("a method that cannot possibly settle the axis it is on",
           full_census(score=2, cell_over={"check": {
               "method": "hf_probe.weight_object",
               "asserts": "nonsense", "observed": "nonsense"}}),
           "cannot settle this axis")

must_catch("a replayable method carrying nothing to replay",
           full_census(score=2, cell_over={"check": {
               "method": "grep_retrieved",
               "asserts": "something", "observed": "something"}}),
           "no `expect` list")

must_pass("the score-2 fixture itself is valid under the new method rules",
          full_census(score=2))

# ── the two round-6 routes AROUND the identity checks ────────────────────────────────────────
# ⛔ BOTH WERE REGISTERED, AXIS-LEGAL AND SILENT. A weights cell moved to `http_range` bypassed
# every identity check by a route axes.py approved; and deleting the field its method needs demoted
# the cell to "unreplayable", after which its evidence was unconstrained and the count was printed
# into the paper as though nothing were wrong.
must_catch("a weights cell moved to a registered, axis-legal method that does not bind identity",
           full_census(score=2, cell_over={"check": {
               "method": "http_range", "asserts": "a range", "observed": "2048 B"}}),
           "does not bind this axis's identity")

must_catch("a cell whose method is missing the field it cannot run without",
           full_census(score=2, cell_over={"check": {
               "method": "grep_retrieved", "asserts": "x", "observed": "y"}}),
           "requires `expect`")

# ── the drift run must be bound to the evidence SET, not to its size ─────────────────────────
# The paper says every artifact was re-fetched. That was confirmed by comparing a COUNT, which a
# substitution passes: swap one url for another and the count is unchanged. The build now compares
# a fingerprint over url+digest, and this is the POSITIVE CONTROL that the fingerprint moves when
# the set does. A binding nobody has watched fail is not known to bind.
import hashlib as _h


def _fp(pairs):
    return _h.sha256(chr(10).join(sorted(
        u + chr(0) + d for u, d in pairs)).encode("utf-8")).hexdigest()


# NOTE: these were named A, B, C -- and `A` is the axes module, imported at the top
# and used by full_census(). The rebinding shadowed it, so every test written BELOW
# this line died with "'list' object has no attribute BY_ID". Renamed.
_FA = [("https://example.org/a", "aa" * 32), ("https://example.org/b", "bb" * 32)]
_FB = [("https://example.org/a", "aa" * 32), ("https://example.org/DIFFERENT", "bb" * 32)]
_FC = [("https://example.org/a", "aa" * 32), ("https://example.org/b", "cc" * 32)]

print()
print("  " + chr(0x26D4) + " SUBSTITUTION, NOT CORRUPTION: same count, different evidence")
print("      two artifacts either way, so a count check passes all three of these")
for label, other in (("a url replaced", _FB), ("a digest replaced", _FC)):
    moved = _fp(_FA) != _fp(other)
    print(("  ok    " if moved else "  FAIL  ") + "the cover fingerprint changes when %s" % label)
    passed, failed = (passed + 1, failed) if moved else (passed, failed + 1)
same = _fp(_FA) == _fp(list(reversed(_FA)))
print(("  ok    " if same else "  FAIL  ") +
      "and does NOT change when only the ORDER differs (it is a set, not a list)")
passed, failed = (passed + 1, failed) if same else (passed, failed + 1)

print()
print("  ⛔ CONTROLS A MUTATION AUDIT FOUND NOTHING WAS WATCHING")
print("      Each of these validator rules could be DELETED with the whole suite still green.")
print("      They are correct and reachable -- a manual probe fired every one -- but nothing")
print("      automated had ever seen one fail, which is indistinguishable from a comment.")

_l = full_census(score=1)
_l["subjects"].append(dict(_l["subjects"][0]))
must_catch("two subjects sharing one id", _l, "duplicate subject")

# The volatile bar EXEMPTS a cell whose check is replayed against archived bytes, and
# full_census picks a replayable method for every axis -- so the first version of this test
# built a census the rule deliberately permits and reported the rule broken. The branch is
# reachable: hash_compare, http_status and api_field are all axis-legal for a 2 and none is
# replayable. Aim at the branch that exists rather than at the one the fixture happens to build.
_l = full_census(score=2)
for _c in _l["cells"]:
    if _c["axis"] == 4 and _c.get("score") == 2:
        _c["check"] = {"method": "http_status", "asserts": "it resolves", "observed": "200"}
        _c["evidence"] = [dict(EV[0], volatile=True, volatile_reason="an api response")]
must_catch("a VERIFIED cell on a NON-replayed check resting on volatile evidence", _l,
           "cannot support a VERIFIED")

_l = full_census(score=2, cell_over={"evidence": [dict(EV[0], volatile=True)]})
must_catch("volatile with no stated reason", _l, "no stated reason")

_l = full_census(score=1)
for _c in _l["cells"]:
    if _c["axis"] == 16:
        _c["score"] = 2
must_catch("a score above the axis's attainable ceiling", _l, "exceeds")

_l = full_census(score=2, cell_over={"evidence": [dict(
    EV[0], url="https://raw.githubusercontent.com/o/r/main/README.md")]})
must_catch("a VERIFIED cell citing a mutable branch", _l, "mutable branch")

_l = full_census(score=1)
_seen = [c for c in _l["cells"] if c.get("evidence")]
_seen[0]["evidence"] = [dict(EV[0], url="https://example.org/somewhere-else")]
must_catch("one digest cited under two different urls", _l, "two different urls")

_l = full_census(score=1)
_l["subjects"][0].pop("axis_sources", None)
must_catch("a scored cell whose subject declares no axis_sources", _l, "axis_sources")

_l = full_census(score=1)
_l["subjects"][0]["sources"] = ["host:nowhere.invalid"]
must_catch("evidence from a source the subject does not declare", _l, "does not declare")

_l = full_census(score=1)
_l["subjects"][0]["unheard_of_key"] = "x"
_fired = False
try:
    M.ledger_fingerprint(_l)
except SystemExit:
    _fired = True
print(("  ok    " if _fired else "  FAIL  ")
      + "a subject field no policy key covers stops the fingerprint")
passed, failed = (passed + 1, failed) if _fired else (passed, failed + 1)


# ⛔ A MECHANISM THAT IS DEFINED AND NEVER CALLED. `replay.py` compiled `_ENTRY =
# re.compile(rb"<entry>")` and its docstring stated that entries were counted; the regex was never
# used and nothing counted anything. A round-17 reviewer grepped the project, found the single
# occurrence, and named the class: a compiled pattern standing in for the check it looks like.
#
# ⚠ This cannot tell a described check from a real one in general. It catches the specific shape
# that has now occurred: a module-level name that exists to do work and is never loaded. Ad hoc
# when it found _ENTRY; a control now, because a defect found by grepping once is found by
# grepping every time or not at all.
# ⚠ AND THE FIRST VERSION OF THIS CONTROL CRIED WOLF, which is the failure mode this project
# has hit four times in two days. It scanned each file for loads WITHIN that file, and reported
# axes.py's SCORES, GROUPS, NA_PERMITTED and CHECK_METHODS as dead -- names whose entire purpose is
# to be read by other modules as `A.SCORES`. A name unused in its own file may be the whole point
# of the file. Usage is collected across the package, attribute access included.
_files = sorted(pathlib.Path(__file__).resolve().parent.glob("*.py"))
_trees = {}
for _f in _files:
    try:
        _trees[_f] = ast.parse(_f.read_text(encoding="utf-8"))
    except SyntaxError:
        pass
_used_anywhere = set()
for _tr in _trees.values():
    for _n in ast.walk(_tr):
        if isinstance(_n, ast.Name) and isinstance(_n.ctx, ast.Load):
            _used_anywhere.add(_n.id)
        elif isinstance(_n, ast.Attribute):
            _used_anywhere.add(_n.attr)
        elif isinstance(_n, ast.ImportFrom):
            for _a in _n.names:
                _used_anywhere.add(_a.name)
_dead = []
for _f, _tr in _trees.items():
    for _n in ast.walk(_tr):
        if (isinstance(_n, ast.Assign) and len(_n.targets) == 1
                and isinstance(_n.targets[0], ast.Name)):
            _nm = _n.targets[0].id
            if (_nm.isupper() or _nm.startswith("_")) and _nm not in ("NL", "_", "D", "W"):
                if _nm not in _used_anywhere:
                    _dead.append("%s:%d %s" % (_f.name, _n.lineno, _nm))
# ⛔ EVIDENCE FROM ONE ENDPOINT MUST BE CLASSIFIED THE SAME WAY. A second page of an arXiv query
# was bound into the ledger by hand and carried no `volatile` flag, while its seven siblings on the
# identical endpoint all carried volatile=true. recheck.py then reported it as DRIFTED -- a real
# finding about the record, produced by adding evidence outside the tool that sets the properties.
# Two records of the same endpoint disagreeing about their own nature is a substitution vector.
# ⚠ AND THE FIRST GRAIN WAS WRONG. Grouping by HOST flagged api.github.com and
# huggingface.co, whose tree and metadata endpoints are different things -- a host standing in for
# an endpoint, which is the substitution this project keeps finding. Grouping by URL found the
# real defect underneath: SEVEN urls were recorded with volatile=true in one cell and unset in
# another, the SAME artifact classified two ways, so recheck.py would suppress a digest change for
# one citing cell and report it for another.
_vol = []
_led = json.loads((pathlib.Path(__file__).resolve().parent / "cells.json").read_text("utf-8"))
_byurl = {}
for _c in _led.get("cells", []):
    for _e in (_c.get("evidence") or []):
        _byurl.setdefault(_e.get("url", ""), set()).add(str(_e.get("volatile")))
for _u, _flags in sorted(_byurl.items()):
    if len(_flags) > 1:
        _vol.append("%s -> %s" % (_u[-56:], sorted(_flags)))
if _vol:
    print("  " + chr(0x26D4) + " %d url(s) recorded with more than one volatility flag:" % len(_vol))
    for _v in _vol[:4]:
        print("      " + _v)
    print("      One artifact cannot be both volatile and stable. Whichever flag is read last")
    print("      decides whether a real change is reported or suppressed.")
    failed += 1
else:
    passed += 1
    print("  ok    every url carries one volatility classification")

# ⛔ BYTE-REPRODUCIBILITY HELD ONLY ON THE PLATFORM THAT WROTE IT. Six modules wrote JSON with
# `write_text(...)` and no `newline=`, which emits CRLF on Windows and LF everywhere else, so two
# DOCUMENTED commands rewrote deposited records with different bytes and identical content. The
# digest the manuscript cites would not reproduce for a replicator, and nothing in the deposit
# gave them a way to learn that -- the byte-identical check is gated on a zip a distribution
# cannot contain, and is skipped silently rather than counted as not-runnable.
_crlf = sorted(f.name for f in pathlib.Path(__file__).resolve().parent.glob("*.json")
               if b"" + chr(13).encode() + chr(10).encode() in f.read_bytes())
if _crlf:
    print("  " + chr(0x26D4) + " %d record(s) contain CRLF: %s" % (len(_crlf), _crlf[:4]))
    print("      A writer that does not pin its newline produces different BYTES for identical")
    print("      CONTENT on another platform, so the cited digest reproduces only here.")
    failed += 1
else:
    passed += 1
    print("  ok    no census record carries platform-dependent line endings")

# ⛔ AND A TOOL THAT ONLY RUNS ON THE AUTHOR'S DISK. `filter_diff.py` hardcoded an absolute
# path into this workspace, so the producer of the paper's newest bound could not be executed from
# the deposit at all -- a round-17 reviewer ran it and got FileNotFoundError. Every other tool here
# resolves relative to itself; nothing checked that they all did.
_abs = []
for _f in _files:
    _src = _f.read_text(encoding="utf-8")
    for _ln, _line in enumerate(_src.splitlines(), 1):
        _s = _line.strip()
        if _s.startswith("#"):
            continue
        _low = _line.lower()
        # ⚠ BUILT, NOT WRITTEN. The first version spelled these needles as literals and
        # then matched itself -- a detector that reports its own definition is a false positive
        # generator, and this project has now had four of those in two days.
        _needles = ("c:" + "/users", "c:" + chr(92) + "users",
                    chr(47) + "home" + chr(47), chr(47) + "Users".lower() + chr(47))
        if any(_n in _low for _n in _needles):
            _abs.append("%s:%d" % (_f.name, _ln))
if _abs:
    print("  " + chr(0x26D4) + " %d absolute path(s) into one machine: %s"
          % (len(_abs), ", ".join(_abs[:4])))
    print("      A tool that only runs on the author's disk cannot be re-run from the deposit,")
    print("      which is the difference between a bound and an assertion.")
    failed += 1
else:
    passed += 1
    print("  ok    no tool hardcodes a path into one machine")

if _dead:
    print("  " + chr(0x26D4) + " %d module-level name(s) defined and never used anywhere:"
          % len(_dead))
    for _d in sorted(_dead)[:8]:
        print("      " + _d)
    print("      A name that looks like a mechanism and is never called is a promise nothing")
    print("      keeps -- the shape of the _ENTRY regex a reviewer found in round 17.")
    failed += 1
else:
    passed += 1
    print("  ok    no module-level name is defined and left uncalled")

print()
print("=" * 78)
print("  %d passed, %d failed" % (passed, failed))
if failed:
    print("  ** the validator let something through. Fix it before scoring anything real. **")
print("=" * 78)
raise SystemExit(1 if failed else 0)
