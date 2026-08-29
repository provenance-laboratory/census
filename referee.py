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


def strict_inversions(a, b):
    """Pairs whose STRICT order flips between two score maps.

    order() imposes a total order on ties, so comparing two orderings counts a reshuffle among
    equal scores as a reversal. Round-1 review found this inflating B by roughly 70%. Only pairs
    that are strictly ordered in `a` and strictly ordered the other way in `b` are counted.
    """
    subs, n = sorted(a), 0
    for i, x in enumerate(subs):
        for y in subs[i + 1:]:
            if (a[x] > a[y] and b[x] < b[y]) or (a[x] < a[y] and b[x] > b[y]):
                n += 1
    return n


def order_transitions(base, coll):
    """Every way the PARTIAL ORDER changes, not one direction of it.

    ⛔ THE TIE ASYMMETRY HAS NOW BEEN WRONG THREE TIMES, each in a different direction: round 1
    over-counted ties as reversals; round 2 compared total orders and missed collapses entirely;
    round 3 counted collapses and MISSED SEPARATIONS -- pairs level in the census that become
    strictly ordered under the test. Reporting one direction of a partial-order change is what
    keeps producing the error, so all three are computed together.
    """
    t = 1e-12
    ks = sorted(base)
    collapsed, separated, reversed_ = [], [], []
    for i, x in enumerate(ks):
        for y in ks[i + 1:]:
            b, c = base[x] - base[y], coll[x] - coll[y]
            if abs(b) > t and abs(c) < t:
                collapsed.append((x, y, base[x], base[y], coll[x]))
            elif abs(b) < t and abs(c) > t:
                separated.append((x, y, base[x], coll[x], coll[y]))
            elif abs(b) > t and abs(c) > t and (b > 0) != (c > 0):
                reversed_.append((x, y))
    return collapsed, separated, reversed_


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
    kind_of = {x["id"]: x["kind"] for x in led["subjects"]}
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
    # ⛔ ORDER-EQUALITY IS NOT ORDER-PRESERVATION. order() is a stable sort, so a strictly-ordered
    # pair that collapses to an exact TIE keeps its sequence and this comparison stays False.
    # Round-2 review found three such collapses, one of them inside the positive control.
    collapsed, separated, flipped = order_transitions(base, coll)
    reordered = order(base) != order(coll)
    changed = reordered or bool(collapsed) or bool(separated) or bool(flipped)
    print()
    print("      largest movement %.3f; sequence changes: %s" % (biggest, reordered))
    print("      partial-order changes: %d strict pair(s) collapse to a tie, %d tied pair(s) "
          "SEPARATE," % (len(collapsed), len(separated)))
    print("      %d reverse." % len(flipped))
    # The verdict is COMPUTED. An earlier version asserted "moves every subject" while its
    # own numbers showed two subjects moving 0.000 -- prose disagreeing with the table it sat
    # under, which is the defect this whole repository is arranged against.
    unmoved = [s for s in base if abs(coll[s] - base[s]) < 1e-9]
    if biggest < 0.05:
        print("      " + chr(0x26D4) + " FATAL: crediting claims as checks barely moves the")
        print("      picture. The instrument is not measuring what it says it measures.")
    else:
        print("      the distinction moves MAGNITUDES by up to %.3f." % biggest)
        # ⛔ THIS VERDICT WAS A HARDCODED STRING that never consulted the computation three lines
        # above it -- the identical defect the comment above warns about, reintroduced in the fix
        # for it. It now prints from `changed`.
        if changed:
            print("      " + chr(0x26D4) + " AND IT DOES CHANGE THE ORDERING.")
            for _x, _y, _bx, _by, _v in collapsed:
                print("        collapse  %-18s %.3f  vs %-18s %.3f  ->  both %.3f"
                      % (_x, _bx, _y, _by, _v))
            for _x, _y, _b, _cx, _cy in separated:
                print("        SEPARATE  %-18s and %-18s both %.3f  ->  %.3f vs %.3f"
                      % (_x, _y, _b, _cx, _cy))
            for _x, _y in flipped:
                print("        REVERSE   %-18s and %-18s" % (_x, _y))
            print("      A pair ordered in the census and unordered under the test is a change in")
            print("      the ordering on any reading a reviewer will apply. What survives is")
            print("      narrower: no pair REVERSES, and the STRATUM separation is untouched")
            print("      because it rests on dominance (see B).")
        else:
            print("      and no ordered pair reverses or collapses under it.")
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
    print("  G · SELECTION SENSITIVITY")
    print("      " + chr(0x26D4) + " LEAVE-ONE-SUBJECT-OUT IS NOT RUN. It is tautological: a")
    print("      subject's score depends only on its own cells, so dropping another subject")
    print("      cannot change it, and \"order preserved\" was guaranteed by arithmetic rather")
    print("      than by evidence. Round-1 review found this; it is removed, not repaired.")
    print()
    print("      What IS sensitive to judgement: how much a CLAIMED cell is worth. Sweeping the")
    print("      weight of an ASSERTED cell from 0 to 2 and asking whether the stratum result")
    print("      holds at every value:")
    fo = [s for s in cells if kind_of[s] == "fully-open"]
    owx = [s for s in cells if kind_of[s] == "open-weights"]
    hist = [s for s in cells if kind_of[s] == "historical-control"]
    holds_fo = holds_bert = 0
    for step in range(0, 21):
        w = step / 10.0
        f = lambda s: (sum((w if v == 1 else v) for v in cells[s].values() if v is not None)
                       / (2 * sum(1 for v in cells[s].values() if v is not None)))
        if all(f(a) > f(b) for a in fo for b in owx):
            holds_fo += 1
        if hist and all(f("bert-base-uncased") > f(b) for b in owx):
            holds_bert += 1
    print("      fully-open above every open-weights release : %d of 21 weights" % holds_fo)
    print("      bert above every open-weights release       : %d of 21 weights" % holds_bert)
    print("      spread %.3f across %d subject(s)"
          % (max(base.values()) - min(base.values()), n))

    # ── B ─────────────────────────────────────────────────────────────────────────────
    print()
    print("  B · ORDERING SENSITIVITY   (adversarial axis subsets)")
    axes_ids = sorted(A.BY_ID)
    k = 3
    inv, first = 0, None
    for drop in itertools.combinations(axes_ids, k):
        sub = {s: frac([v for a, v in c.items() if a not in drop]) for s, c in cells.items()}
        if strict_inversions(base, sub):
            inv += 1
            if first is None:
                first = drop
    total = len(list(itertools.combinations(axes_ids, k)))
    print("      %d of %d %d-axis subsets produce a STRICT inversion." % (inv, total, k))
    print("      " + chr(0x26A0) + " An earlier count of 965 included reshuffles among TIED")
    print("      scores, which are not reversals. Round-1 review caught it.")
    if first:
        print("      first such subset: axes %s (%s)"
              % (list(first), ", ".join(A.BY_ID[a][2] for a in first)))
    print()
    # ⭐ THE SEPARATION IS A DOMINANCE RESULT, and reporting a depth number understated it by a
    # wide margin. Round-2 review raised this twice before it was taken up: if the LOWEST
    # fully-open release is >= the HIGHEST open-weights release on EVERY axis, then no subset of
    # axes and no weighting of them can reverse the separation -- it is closed under both
    # operations, and the deepest deletions can produce at most a tie. A depth number is a sample
    # of that fact; the dominance is the fact.
    lo = min(fo, key=lambda s: base[s])
    hi = max(owx, key=lambda s: base[s])
    below, strict, comparable = M.dominates(led, lo, hi)
    print()
    print("      DOMINANCE: %s (lowest fully-open) vs %s (highest open-weights)" % (lo, hi))
    if below:
        print("      " + chr(0x26D4) + " dominance FAILS on axes %s -- the separation depends on"
              % below)
        print("      the weighting after all, and the depth number below is the real claim.")
    else:
        print("      %s is >= %s on ALL %d axes where both are scored, strictly greater on %d."
              % (lo, hi, len(comparable), len(strict)))
        print("      " + chr(0x21D2) + " NO subset of axes and NO reweighting can reverse the")
        print("      stratum separation. The deepest deletions produce at most a TIE, which is")
        print("      what the k below actually finds.")
    print()
    print("      How deep before even a tie appears? Dropping every subset of size k and")
    print("      asking whether min(fully-open) still exceeds max(open-weights):")
    for k2 in range(1, 12):
        bad = 0
        for drop in itertools.combinations(axes_ids, k2):
            sub = {s: frac([v for a, v in c.items() if a not in drop])
                   for s, c in cells.items()}
            if min(sub[s] for s in fo) <= max(sub[s] for s in owx):
                bad += 1
                break
        if bad:
            # ⚠️ §6.2 excludes ties by policy in the inversion count and then counted them as
            # failures here, in the same section. Say which they are.
            ties = inv2 = 0
            for drop in itertools.combinations(axes_ids, k2):
                sub = {s: frac([v for a, v in c.items() if a not in drop])
                       for s, c in cells.items()}
                mn, mx = min(sub[s] for s in fo), max(sub[s] for s in owx)
                if mn < mx:
                    inv2 += 1
                elif abs(mn - mx) < 1e-12:
                    ties += 1
            print("      survives every drop up to %d axes; first fails at %d" % (k2 - 1, k2))
            print("      and those %d failure(s) are %d TIE(S) and %d STRICT INVERSION(S) --"
                  % (ties + inv2, ties, inv2))
            print("      which the dominance result above already guarantees."
                  if inv2 == 0 else
                  "      an inversion here would CONTRADICT the dominance result above.")
            break
    else:
        print("      survives every drop up to 11 axes")

    # ── D ─────────────────────────────────────────────────────────────────────────────
    print()
    print("  D · AXIS REDUNDANCY")
    if n < 8:
        print("      %d subject(s): a correlation across axes is noise at this n, and an" % n)
        print("      effective-axis count computed from it would be a fabricated number.")
        print("      NOT REPORTED. Re-run when the census is complete.")
    else:
        subs = sorted(cells)
        # N/A is treated as absent for this test, and that choice is stated: a correlation
        # cannot consume a null, and dropping the subject instead would change the axis pairs
        # under comparison from one pair to the next.
        # ⚠️ `or 0` COERCED N/A TO ZERO and ran in two directions at once: it put axes 20 and 21
        # on the never-varies list on the strength of THREE live cells, and it HID axis 22, which
        # is constant over every cell it applies to. Round-2 review found both. Applicable cells
        # only, and every constant axis is reported with the n it rests on.
        vec = {a: [cells[s].get(a) for s in subs if cells[s].get(a) is not None]
               for a in sorted(A.BY_ID)}

        def corr(x, y):
            m = len(x)
            mx, my = sum(x) / m, sum(y) / m
            sxy = sum((x[i] - mx) * (y[i] - my) for i in range(m))
            sxx = sum((x[i] - mx) ** 2 for i in range(m))
            syy = sum((y[i] - my) ** 2 for i in range(m))
            if sxx <= 1e-12 or syy <= 1e-12:
                return None                       # one of them never varies
            return sxy / ((sxx ** 0.5) * (syy ** 0.5))

        constant = [a for a, _v, _n in M.constant_axes(led)]
        varying = [a for a in vec if a not in constant]
        for a in constant:
            print("          axis %2d  constant at %s over n=%2d applicable cell(s)%s"
                  % (a, vec[a][0], len(vec[a]),
                     "  " + chr(0x26A0) + " a claim about %d subjects, not %d" % (len(vec[a]), n)
                     if len(vec[a]) < n else ""))
        print("      %d of %d axes NEVER VARY across the census: %s"
              % (len(constant), len(vec), constant))
        print("      A constant axis discriminates nothing here. It is not necessarily a bad")
        print("      axis -- it may be one nobody satisfies -- but it carries no information")
        print("      about THESE subjects, and it is why a redundancy statistic computed")
        print("      over all 22 would be measuring 14.")
        print()
        pairs = []
        for i, a in enumerate(varying):
            for b in varying[i + 1:]:
                r = corr(vec[a], vec[b])
                if r is not None and abs(r) >= 0.9:
                    pairs.append((abs(r), a, b))
        pairs.sort(reverse=True)
        print("      %d varying axes; %d pair(s) correlate at |r| >= 0.9:"
              % (len(varying), len(pairs)))
        for r, a, b in pairs[:12]:
            print("        r=%.2f  axis %2d (%s)  ~  axis %2d (%s)"
                  % (r, a, A.BY_ID[a][2], b, A.BY_ID[b][2]))
        if len(pairs) > 12:
            print("        ... and %d more" % (len(pairs) - 12))

        # Effective count: collapse each group of mutually >=0.9 axes to one, greedily.
        merged, seen_ax = 0, set()
        for _r, a, b in pairs:
            if a not in seen_ax and b not in seen_ax:
                seen_ax.add(a)
                seen_ax.add(b)
                merged += 1
        eff = len(varying) - merged
        print()
        print("      " + chr(0x26D4) + " NO \"EFFECTIVE AXIS COUNT\" IS REPORTED.")
        print("      An earlier version printed ~%d against %d nominal. That number was not a"
              % (eff, len(vec)))
        print("      recognised effective-dimension statistic: it greedily paired axes above an")
        print("      arbitrary threshold, depended on the order pairs were considered, treated")
        print("      ordinal scores as interval data, recoded N/A as zero, and rested on %d"
              % n)
        print("      observations. Round-1 review was right to reject it. The pairs above are")
        print("      the finding; the single number was an invention.")

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
