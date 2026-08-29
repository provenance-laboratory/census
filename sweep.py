"""Transplant every non-zero cell's evidence onto every cross-subject non-zero cell, and count.

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
    for dst in cells:
        for src in cells:
            if src is dst or src["subject"] == dst["subject"]:
                continue
            band = "VERIFIED" if dst.get("score") == 2 else "ASSERTED"
            tally.setdefault(band, {"n": 0, "validator": 0, "gate": 0, "survived": 0})
            tally[band]["n"] += 1

            d = copy.deepcopy(led)
            tgt = [c for c in d["cells"]
                   if c["subject"] == dst["subject"] and c["axis"] == dst["axis"]][0]
            tgt["evidence"] = copy.deepcopy(src.get("evidence") or [])
            if src.get("check"):
                tgt["check"] = copy.deepcopy(src["check"])

            if M.validate(d):
                tally[band]["validator"] += 1
                continue
            tally[band]["gate"] += 1
            ctx = R.subject_context(d)
            res, _why = R.gate(tgt, ctx, None, d)
            if res is not False:
                tally[band]["survived"] += 1
                survivors.append((dst["subject"], dst["axis"], src["subject"], src["axis"]))

    total = surv = 0
    for band in ("VERIFIED", "ASSERTED"):
        t = tally.get(band)
        if not t:
            continue
        print("  %-9s %5d transplant(s); %5d refused by the validator, %4d reached the gate"
              % (band, t["n"], t["validator"], t["gate"]))
        print("            %5d SURVIVED" % t["survived"])
        total += t["n"]
        surv += t["survived"]

    print()
    print("  %d of %d transplants survive end to end." % (surv, total))
    if show and survivors:
        for a, b, c2, d2 in survivors[:40]:
            print("      %s/axis%d <- %s/axis%d" % (a, b, c2, d2))
    print("=" * 78)
    # ⚠️ Reported, and NOT asserted to be zero forever. If a legitimate shared source is ever
    # declared, a transplant between the two subjects sharing it may survive and should -- the
    # figure is a measurement, and a measurement that can only have one value is a constant.
    return 1 if surv else 0


if __name__ == "__main__":
    raise SystemExit(main())
