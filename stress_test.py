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
import io
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
                         "axis_literals": {str(c["axis"]): sorted((c.get("check") or {})["expect"])
                                           for c in cells
                                           if c.get("score") and (c.get("check") or {}).get("expect")}}],
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


A = [("https://example.org/a", "aa" * 32), ("https://example.org/b", "bb" * 32)]
B = [("https://example.org/a", "aa" * 32), ("https://example.org/DIFFERENT", "bb" * 32)]
C = [("https://example.org/a", "aa" * 32), ("https://example.org/b", "cc" * 32)]

print()
print("  " + chr(0x26D4) + " SUBSTITUTION, NOT CORRUPTION: same count, different evidence")
print("      two artifacts either way, so a count check passes all three of these")
for label, other in (("a url replaced", B), ("a digest replaced", C)):
    moved = _fp(A) != _fp(other)
    print(("  ok    " if moved else "  FAIL  ") + "the cover fingerprint changes when %s" % label)
    passed, failed = (passed + 1, failed) if moved else (passed, failed + 1)
same = _fp(A) == _fp(list(reversed(A)))
print(("  ok    " if same else "  FAIL  ") +
      "and does NOT change when only the ORDER differs (it is a set, not a list)")
passed, failed = (passed + 1, failed) if same else (passed, failed + 1)

print()
print("=" * 78)
print("  %d passed, %d failed" % (passed, failed))
if failed:
    print("  ** the validator let something through. Fix it before scoring anything real. **")
print("=" * 78)
raise SystemExit(1 if failed else 0)
