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


def full_census(subject="s1", score=0, **over):
    """A complete, valid census: every one of the 22 axes present for one subject."""
    cells = []
    for ax in A.BY_ID:
        c = {"subject": subject, "axis": ax, "score": score}
        if score and score > 0:
            c["evidence"] = list(EV)
            if score == 2:
                c["check"] = {"method": "http_range",
                              "asserts": "status is 206",
                              "observed": "HTTP 206, 2048 B"}
        cells.append(c)
    led = {"as_of": "2026-08-01",
           "subjects": [{"id": subject, "kind": "open-weights"}], "cells": cells}
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

print()
print("=" * 78)
print("  %d passed, %d failed" % (passed, failed))
if failed:
    print("  ** the validator let something through. Fix it before scoring anything real. **")
print("=" * 78)
raise SystemExit(1 if failed else 0)
