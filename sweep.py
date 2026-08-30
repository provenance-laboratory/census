"""Transplant every non-zero cell's evidence onto every OTHER non-zero cell, and count survivors.

⚠️ WHAT THIS FIGURE MEASURES, SINCE IT IS EASY TO OVERSTATE. A reviewer replaced `replay.gate()`
with a function accepting everything and re-ran this: the cross-subject figure did not move,
because every cross-subject transplant is refused earlier, by `mp_metric.validate()`'s source rule.
So the cross-subject number measures THE SOURCE DECLARATION, not the gate -- and an earlier draft
of this docstring and of section 2.2 said it "moves when the gate changes", which was false in the
same way section 6.4's asserted-weight sweep was: an outcome fixed before any data arrived.

Its value is real and narrower: it would move if a source were ever declared too broadly. The
intra-subject figure is the one that exercises the axis policy.

⛔ WHY A NUMBER AND NOT A LIST. The question "is there a substitution the checks miss?" has been
asked six times and answered six times by a list of named mutations. A list grows by whatever
somebody thought of; it cannot say what fraction of the space is covered, and it goes green the
moment an attack is added rather than when the gate improves.

A reviewer proposed this and the proposal is right: the space is enumerable. Every non-zero cell's
evidence transplanted onto every non-zero cell of a DIFFERENT subject is a mutation that puts one
release's score on another release's artifacts. Counting how many survive is a coverage figure that
moves when the gate changes -- the same upgrade section 6.2 made when it replaced a depth number
with the dominance result.

⚠️ THE OWNERSHIP MAP MUST BE BUILT THE WAY main() BUILDS IT. An earlier self-test used a frozen
copy of the pristine ledger while the runtime used the mutated one, so a symmetric swap failed in
the test and passed in production. This uses `subject_context`, which reads `subjects[].sources` --
a declaration no mutation of cells can move.

    python sweep.py            the coverage figure
    python sweep.py --list     also name every survivor
"""
import copy
import io
import json
import pathlib
import sys

import mp_metric as M
import replay as R

NL = chr(10)
HERE = pathlib.Path(__file__).resolve().parent


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    show = "--list" in sys.argv
    led = json.loads((HERE / "cells.json").read_text(encoding="utf-8"))
    cells = [c for c in led["cells"] if c.get("score")]

    print("=" * 78)
    print("  COVERAGE: every cross-subject transplant of one non-zero cell's evidence")
    print("=" * 78)
    print()

    tally = {}
    survivors = []
    # ⛔ THREE FAMILIES, NOT ONE. The first version moved evidence and copied the check only when
    # the donor had one, so a CHECK-ONLY substitution -- moving expectations between cells without
    # touching evidence -- was never enumerated. A round-8 reviewer ran it separately and found 55
    # survivors. And the whole enumeration held the POLICY fixed, which is one operand of a
    # two-operand comparison; that family is enumerated too, and reported as what it is.
    MODES = ("evidence only", "check only", "evidence and check", "with the policy moved too")
    for dst in cells:
        for src in cells:
            if src is dst:
                continue
            same = src["subject"] == dst["subject"]
            for mode in MODES:
                band = "%s / %s" % ("intra" if same else "cross", mode)
                tally.setdefault(band, {"n": 0, "validator": 0, "gate": 0, "survived": 0,
                                        "vacuous": 0})
                tally[band]["n"] += 1

                d = copy.deepcopy(led)
                tgt = [c for c in d["cells"]
                       if c["subject"] == dst["subject"] and c["axis"] == dst["axis"]][0]
                if mode in ("evidence only", "evidence and check", "with the policy moved too"):
                    tgt["evidence"] = copy.deepcopy(src.get("evidence") or [])
                if mode in ("check only", "evidence and check", "with the policy moved too"):
                    if src.get("check"):
                        tgt["check"] = copy.deepcopy(src["check"])
                    else:
                        tgt.pop("check", None)
                if mode == "with the policy moved too":
                    ds = [s for s in d["subjects"] if s["id"] == dst["subject"]][0]
                    ss = [s for s in d["subjects"] if s["id"] == src["subject"]][0]
                    a_d, a_s = str(dst["axis"]), str(src["axis"])
                    for key in ("axis_sources", "axis_documents", "axis_method", "axis_literals"):
                        if (ss.get(key) or {}).get(a_s) is not None:
                            ds.setdefault(key, {})[a_d] = copy.deepcopy(ss[key][a_s])
                    ds["sources"] = sorted(set(ds.get("sources") or ())
                                           | set(ss.get("sources") or ()))

                # ⛔ THE VACUITY TEST WAS SKIPPED FOR THE POLICY-MOVED FAMILY, so that
                # family alone counted no-op mutations in its denominator -- and it is the family
                # with the large survivor count, which the asymmetry flatters. The test is the same
                # question for every family: did this mutation change anything at all? For the
                # policy family the answer must consider the SUBJECT RECORD too, because that is
                # the operand this family moves.
                pristine = [c for c in led["cells"] if c["subject"] == dst["subject"]
                            and c["axis"] == dst["axis"]][0]
                unchanged = json.dumps(tgt, sort_keys=True) == json.dumps(pristine, sort_keys=True)
                if unchanged and mode == "with the policy moved too":
                    ds_now = [s for s in d["subjects"] if s["id"] == dst["subject"]][0]
                    ds_was = [s for s in led["subjects"] if s["id"] == dst["subject"]][0]
                    unchanged = json.dumps(ds_now, sort_keys=True) == json.dumps(
                        ds_was, sort_keys=True)
                if unchanged:
                    tally[band]["vacuous"] += 1
                    continue

                if M.validate(d):
                    tally[band]["validator"] += 1
                    continue
                tally[band]["gate"] += 1
                ctx = R.subject_context(d)
                res, _why = R.gate(tgt, ctx, None, d)
                if res is not False:
                    tally[band]["survived"] += 1
                    survivors.append((band, dst["subject"], dst["axis"],
                                      src["subject"], src["axis"]))

    total = surv = 0
    for band in sorted(tally):
        t = tally.get(band)
        if not t:
            continue
        print("  %-38s %5d; %5d refused by the validator, %4d reached gate"
              % (band, t["n"], t["validator"], t["gate"]))
        print("            %5d SURVIVED%s" % (t["survived"],
              ("; %d vacuous -- the mutation changed nothing" % t["vacuous"])
              if t.get("vacuous") else ""))
        total += t["n"]
        surv += t["survived"]

    # ⛔ THIS LINE AGGREGATED THE POLICY-MOVED FAMILY, which the paper deliberately reports
    # separately -- so a reviewer running the tool read a total that appears nowhere in the
    # manuscript and contradicts the figure printed beside it. The families are summed the way
    # they are reported.
    held_n = sum(t2["n"] for b, t2 in tally.items() if "policy" not in b)
    held_s = sum(t2["survived"] for b, t2 in tally.items() if "policy" not in b)
    moved_n = sum(t2["n"] for b, t2 in tally.items() if "policy" in b)
    moved_s = sum(t2["survived"] for b, t2 in tally.items() if "policy" in b)
    print()
    print("  WITH THE POLICY HELD FIXED : %d of %d survive" % (held_s, held_n))
    print("  WITH THE POLICY MOVED TOO  : %d of %d survive  -- reported separately, because"
          % (moved_s, moved_n))
    print("                               moving both operands is outside what a policy inside")
    print("                               the ledger can prevent")
    if show and survivors:
        # ⚠️ THE CAP EMITTED THE POLICY-MOVED SURVIVORS FIRST, so the ones the paper actually
        # reports never appeared in the listing. A count without a cover is the defect section 6.5
        # repairs in recheck.py; the same fault reached this tool's own output.
        print()
        held = [s2 for s2 in survivors if "policy" not in s2[0]]
        for bd, a, b, c2, d2 in held:
            print("      [%s] %s/axis%d carries %s/axis%d's material" % (bd, a, b, c2, d2))
        if moved_s:
            print("      ... and %d more with the policy moved too, not listed" % moved_s)
    print("=" * 78)
    # ⚠️ Reported, and NOT asserted to be zero forever. If a legitimate shared source is ever
    # declared, a transplant between the two subjects sharing it may survive and should -- the
    # figure is a measurement, and a measurement that can only have one value is a constant.
    # ⚠️ NOT ASSERTED TO BE ZERO. The "with the policy moved too" family is EXPECTED to survive:
    # a declaration that can be rewritten is still a declaration, and rewriting it leaves a diff.
    # Reporting it as a survivor count rather than hiding it is the honest form -- it says what the
    # zero in the other families rests on.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
