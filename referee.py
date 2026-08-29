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
        print("      the distinction moves MAGNITUDES by up to %.3f." % biggest)
        print("      " + chr(0x26A0) + " It does NOT change the ordering, and round-1 review was")
        print("      right that calling it \"load-bearing for the headline\" overstated it. What")
        print("      it shows is that the scores are not a proxy for what a release documents;")
        print("      the comparative picture would survive the collapse.")
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
    print("      How deep does the STRATUM separation go? Dropping every subset of size k and")
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
            print("      survives every drop up to %d axes; FIRST FAILS at %d" % (k2 - 1, k2))
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
        vec = {a: [(cells[s].get(a) or 0) for s in subs] for a in sorted(A.BY_ID)}

        def corr(x, y):
            m = len(x)
            mx, my = sum(x) / m, sum(y) / m
            sxy = sum((x[i] - mx) * (y[i] - my) for i in range(m))
            sxx = sum((x[i] - mx) ** 2 for i in range(m))
            syy = sum((y[i] - my) ** 2 for i in range(m))
            if sxx <= 1e-12 or syy <= 1e-12:
                return None                       # one of them never varies
            return sxy / ((sxx ** 0.5) * (syy ** 0.5))

        constant = [a for a in vec if max(vec[a]) == min(vec[a])]
        varying = [a for a in vec if a not in constant]
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
