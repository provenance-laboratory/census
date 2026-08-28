"""The hostile referee's attacks on the RESULT, as distinct from the validator.

`stress_test.py` attacks the code. This attacks the finding. obl-metric's own referee found six
failures and four warnings and drove them to 0/0; the corresponding suite here is written before
there is anything to defend.

    E  CLAIMED-vs-CHECKED COLLAPSE   recompute treating every 1 as a 2. RUN THIS FIRST.
    C  N/A RE-CODING                 already structural in score(); reported here for completeness
    G  SELECTION SENSITIVITY         drop each subject in turn; does one subject carry the result?
    B  ORDERING SENSITIVITY          can an adversarially chosen axis subset reverse the order?
    D  AXIS REDUNDANCY               are several axes measuring one thing? effective-axis count

⛔ E IS THE ONE THAT WOULD KILL THE PAPER. The whole instrument rests on the difference between
an artifact that can be checked and an assertion that cannot. If crediting every claim as a check
leaves the picture unchanged, that distinction is decorative and the paper has no subject.

⚠️ POWER. Several of these tests are meaningless at small n, and this refuses to report a number
it cannot support: with three subjects a correlation is noise, and saying so is the finding.

    python referee.py
"""
import io
import itertools
import json
import pathlib
import sys

import axes as A
import mp_metric as M

NL = chr(10)
HERE = pathlib.Path(__file__).resolve().parent


def per_subject_cells(led):
    d = {}
    for c in led.get("cells", []):
        d.setdefault(c["subject"], {})[c["axis"]] = c.get("score")
    return d


def frac(vals):
    """as-coded: N/A leaves the denominator."""
    real = [v for v in vals if v is not None]
    return (sum(real) / (2 * len(real))) if real else 0.0


def order(d):
    return [s for s, _ in sorted(d.items(), key=lambda kv: -kv[1])]


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    led = M.load()
    defects = M.validate(led)
    if defects:
        print("  the census does not validate; there is nothing to referee.")
        return 1
    cells = per_subject_cells(led)
    n = len(cells)
    if n == 0:
        print("  no subjects yet.")
        return 0

    base = {s: frac(list(v.values())) for s, v in cells.items()}
    print("=" * 78)
    print("  referee — %d subject(s), %d axes" % (n, len(A.AXES)))
    print("=" * 78)

    # ── E ─────────────────────────────────────────────────────────────────────────────
    print()
    print("  E · CLAIMED-vs-CHECKED COLLAPSE   (run first; this one can kill the paper)")
    coll = {s: frac([2 if v == 1 else v for v in c.values()]) for s, c in cells.items()}
    moves = []
    for s in sorted(base, key=lambda k: -base[k]):
        delta = coll[s] - base[s]
        moves.append(delta)
        print("      %-14s %.3f -> %.3f   (+%.3f)" % (s, base[s], coll[s], delta))
    biggest = max(moves) if moves else 0.0
    reordered = order(base) != order(coll)
    print()
    print("      largest movement %.3f; ordering changes: %s" % (biggest, reordered))
    # The verdict is COMPUTED. An earlier version asserted "moves every subject" while its
    # own numbers showed two subjects moving 0.000 -- prose disagreeing with the table it sat
    # under, which is the defect this whole repository is arranged against.
    unmoved = [s for s in base if abs(coll[s] - base[s]) < 1e-9]
    if biggest < 0.05:
        print("      " + chr(0x26D4) + " FATAL: crediting claims as checks barely moves the")
        print("      picture. The instrument is not measuring what it says it measures.")
    else:
        print("      the distinction is LOAD-BEARING WHERE IT APPLIES: largest movement",
              "%.3f," % biggest)
        print("      so the scores are not a proxy for what a release merely documents.")
    if unmoved:
        print()
        print("      " + chr(0x26A0) + " %d subject(s) move 0.000: %s"
              % (len(unmoved), ", ".join(sorted(unmoved))))
        print("      They hold NO cell scored 1. For those releases the CHECKED/CLAIMED")
        print("      distinction does no work: everything published is either checkable or")
        print("      absent, with nothing merely asserted in between. That is a finding")
        print("      about them, not a weakness of the test.")

    # ── C ─────────────────────────────────────────────────────────────────────────────
    print()
    print("  C · N/A RE-CODING")
    sc = M.score(led)
    for s in sorted(sc, key=lambda k: -sc[k]["as_coded"]):
        v = sc[s]
        print("      %-14s as-coded %.3f   [0 -> %.3f, 2 -> %.3f]   spread %.3f"
              % (s, v["as_coded"], v["na_as_0"], v["na_as_2"],
                 v["na_as_2"] - v["na_as_0"]))
    print("      every N/A here is Group 5 on a base model, which is the honest case;")
    print("      the spread is nonetheless reported because a reader cannot see that.")

    # ── G ─────────────────────────────────────────────────────────────────────────────
    print()
    print("  G · SELECTION SENSITIVITY   (drop each subject in turn)")
    if n < 3:
        print("      %d subject(s): not computable. Stated, not skipped silently." % n)
    else:
        full_order = order(base)
        for drop in sorted(base):
            rest = {s: base[s] for s in base if s != drop}
            same = order(rest) == [s for s in full_order if s != drop]
            print("      without %-14s order preserved: %s" % (drop, same))
        print("      spread %.3f across %d subject(s)"
              % (max(base.values()) - min(base.values()), n))

    # ── B ─────────────────────────────────────────────────────────────────────────────
    print()
    print("  B · ORDERING SENSITIVITY   (adversarial axis subsets)")
    axes_ids = sorted(A.BY_ID)
    k = 3
    worst, worst_set = 0, None
    full_order = order(base)
    for drop in itertools.combinations(axes_ids, k):
        sub = {s: frac([v for a, v in c.items() if a not in drop])
               for s, c in cells.items()}
        if order(sub) != full_order:
            worst += 1
            if worst_set is None:
                worst_set = drop
    total = len(list(itertools.combinations(axes_ids, k)))
    print("      dropping every %d-axis subset: %d of %d reverse the order somewhere"
          % (k, worst, total))
    if worst_set:
        print("      first such subset: axes %s (%s)"
              % (list(worst_set), ", ".join(A.BY_ID[a][2] for a in worst_set)))
        print("      " + chr(0x26A0) + " this MUST appear in the paper, not in a footnote.")
    else:
        print("      the ordering is stable under every %d-axis drop." % k)

    # ── D ─────────────────────────────────────────────────────────────────────────────
    print()
    print("  D · AXIS REDUNDANCY")
    if n < 8:
        print("      %d subject(s): a correlation across axes is noise at this n, and an" % n)
        print("      effective-axis count computed from it would be a fabricated number.")
        print("      NOT REPORTED. Re-run when the census is complete.")
    else:
        print("      (implement once n >= 8)")

    # ── F ─────────────────────────────────────────────────────────────────────────────
    print()
    print("  F · RETRIEVAL DRIFT")
    ev = [(c["subject"], c["axis"], e) for c in led["cells"]
          for e in (c.get("evidence") or [])]
    print("      %d evidence record(s) across %d subject(s) carry a retrieval date and digest."
          % (len(ev), n))
    print("      Drift is checked by re-fetching before publication (recheck.py), not here:")
    print("      a referee run must not silently depend on the network being up.")

    print()
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
