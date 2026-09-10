#!/usr/bin/env python3
"""Positive controls for the declared-determination table, including the ground that was false.

⛔ THE GROUND UNDER THE ONE SURVIVING DETERMINATION WAS FALSE OF THE CODE IT CITED, and a round-5
reviewer found it by TESTING it rather than reading it. It claimed `REQUIRED_METHOD[12]` and the
`grep_retrieved` bar made ASSERTED unreachable; both are check-block rules, `REQUIRED_METHOD` is
enforced only at `val == 2`, and 29 of 32 score-1 cells carry no check block at all. They built the
counterexample, lifted the cap alone, and **zero method rules fired.**

⛔ AND THE PREDICATE COULD NOT HAVE CAUGHT IT. Its three clauses reduced to the two halves of an
identity -- the table was constrained to equal `{{(a,k) : max_for(a,k) == 0}}` -- so the only
content it did not already have was the ground string, whose only test was non-emptiness.

⇒ The ground is a TYPED claim now. `method-bar` grounds are EXECUTED; `semantic` grounds are
argued and must declare that nothing executes them. The completeness projection runs over GROUNDS,
so the determination table and the cap table can disagree -- which is the only condition under
which their agreement means anything. The last check below demonstrates that: re-bar axis 13's
document methods and the projection discovers a determination the cap table does not know about.

    python test_determination.py
"""
import pathlib
import sys

# ⚠ THIS HELD AN ABSOLUTE PATH INTO ONE MACHINE, which `stress_test.py`
# reported within a minute of the file existing -- the same defect
# `unread_notes.py` carried for four rounds. A suite that only runs in the
# author's tree cannot run in the replication package.
R = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(R))
sys.stdout.reconfigure(encoding="utf-8")
import axes as A  # noqa: E402
import mp_metric as M  # noqa: E402

led = M.load()
saved = dict(A.STRUCTURALLY_DETERMINED)


def defects(table):
    A.STRUCTURALLY_DETERMINED = table
    try:
        return [x for x in M.validate(led)
                if "determin" in x.lower() or "method bar" in x.lower() or "ground" in x.lower()]
    finally:
        A.STRUCTURALLY_DETERMINED = saved


CASES = [
    ("NEGATIVE: the real table validates clean", dict(saved), False),
    ("the FALSE MECHANICAL GROUND the reviewer tested",
     {**saved, (12, "api-only"): {"kind": "method-bar", "blocks": 1,
                                  "ground": "REQUIRED_METHOD[12] bars grep_retrieved"}}, True),
    ("a semantic ground that does not admit it is unexecuted",
     {**saved, (12, "api-only"): {"kind": "semantic", "blocks": 1, "ground": "it just is"}}, True),
    ("round 29's wrong entries, re-injected with grounds",
     {**saved,
      (14, "api-only"): {"kind": "semantic", "blocks": 1, "ground": "injected",
                         "not_machine_checked": "injected"},
      (15, "api-only"): {"kind": "semantic", "blocks": 1, "ground": "injected",
                         "not_machine_checked": "injected"}}, True),
    ("an untyped entry (the old prose-only form)",
     {**saved, (16, "api-only"): "a bare string as the whole ground"}, True),
    ("REMOVE the surviving entry", {}, True),
]

print("=" * 88)
print("  THE RETYPED DETERMINATION TABLE, ATTACKED")
print("=" * 88)
bad = 0
for label, table, want in CASES:
    got = bool(defects(table))
    ok = got == want
    bad += 0 if ok else 1
    print("  %s %-56s %s" % ("ok     " if ok else chr(0x26D4) + " MISSED", label,
                             "" if ok else "got %r want %r" % (got, want)))

# and the clause that can discover a pair the cap table does not know
print()
print("  the grounds projection, on a registry that bars every document method:")
_orig = dict(A.METHOD_AXES)
try:
    A.METHOD_AXES = {m: (s - {13} if m in A.SETTLED_FROM_DOCUMENT else s)
                     for m, s in _orig.items()}
    found = [x for x in M.validate(led) if "no positive is reachable there" in x]
    print("    %s axis 13 re-barred -> %s"
          % ("ok     " if found else chr(0x26D4) + " MISSED",
             (found[0][:88] + "...") if found else "NOT DISCOVERED"))
finally:
    A.METHOD_AXES = _orig
print("=" * 88)
raise SystemExit(1 if bad else 0)
