"""mp-metric — what a model release lets a third party CHECK, as opposed to being TOLD.

Deliberately parallel to `obl-metric`, which measures how far a chain has diverged from a
historical reference. Same discipline, different subject: reference-relative, source-anchored,
and NOT A RANKING.

TWO STRUCTURAL DECISIONS, BOTH TAKEN BECAUSE obl-metric PAID FOR THEM

1. THE ENGINE EMITS THE TABLES; THE PAPER INCLUDES THEM.
   obl-metric's round-2 referees returned NO-GO with six regressions in one round, and the root
   cause was not carelessness: the paper hand-maintained numbers the engine computed, edited by
   string surgery every time a cell moved. Numbers here are written by `emit_tables()` into
   `tables/` and are never typed into prose.

2. THE HEADLINE CANNOT BE EMITTED WITHOUT ITS SENSITIVITY BAND.
   `N/A` removes an axis from the DENOMINATOR, so a release with many N/A scores HIGHER. That
   makes N/A the escape hatch that quietly does all the work. `score()` therefore returns a triple
   -- as-coded, N/A re-coded to 0, N/A re-coded to 2 -- and there is no function that returns the
   first alone. A number that can be quoted alone eventually is.

THE EVIDENCE STANDARD, APPLIED WITHOUT EXCEPTION
   Every non-zero cell is backed by a retrievable artifact: url, retrieval date, sha256 of the
   RETRIEVED BYTES. A cell with no artifact record is not a 1 -- it is a bug, and validate()
   refuses to score the whole census until it is fixed.

Run:  python mp_metric.py              validate, score, emit tables
      python mp_metric.py --check      validate only; write nothing
"""
import datetime as dt
import hashlib
import io
import json
import pathlib
import re
import sys

import axes as A

NL = chr(10)
HERE = pathlib.Path(__file__).resolve().parent
LEDGER = HERE / "cells.json"
TABLES = HERE / "tables"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def load():
    if not LEDGER.exists():
        return {"subjects": [], "cells": []}
    return json.loads(LEDGER.read_text(encoding="utf-8"))


def validate(led):
    """Return a list of defects. ANY defect means the census is not scoreable.

    Fails CLOSED: a subject-axis pair that is simply missing is a defect, not a zero. An absent
    cell and a cell scored 0 are different claims -- 'nobody looked' is not 'we looked and found
    nothing' -- and writing them identically is how a census becomes an opinion.
    """
    d = []
    subjects = [s["id"] for s in led.get("subjects", [])]
    if len(set(subjects)) != len(subjects):
        d.append("duplicate subject ids")

    seen = {}
    for i, c in enumerate(led.get("cells", [])):
        where = f"cell[{i}] {c.get('subject','?')}/axis{c.get('axis','?')}"
        ax, sub, val = c.get("axis"), c.get("subject"), c.get("score", "MISSING")

        if ax not in A.BY_ID:
            d.append(f"{where}: axis {ax} is not one of the 22")
            continue
        if sub not in subjects:
            d.append(f"{where}: subject not declared in subjects[]")
        if (sub, ax) in seen:
            d.append(f"{where}: duplicate of cell[{seen[(sub, ax)]}]")
        seen[(sub, ax)] = i

        if val not in (0, 1, 2, None):
            d.append(f"{where}: score {val!r} is not 2/1/0/null")
            continue

        # N/A is policed: only where the axis permits it, and never without a reason.
        if val is None:
            if ax not in A.NA_PERMITTED:
                d.append(f"{where}: N/A on an axis that can never be N/A "
                         f"({A.BY_ID[ax][2]}) -- every release was made from something")
            if not str(c.get("na_reason", "")).strip():
                d.append(f"{where}: N/A with no na_reason -- bulk N/A is the escape hatch")
            continue

        # THE EVIDENCE STANDARD. A non-zero cell without a retrievable artifact is a bug.
        if val > 0:
            ev = c.get("evidence") or []
            if not ev:
                d.append(f"{where}: score {val} with NO evidence record -- not a {val}, a bug")
            for j, e in enumerate(ev):
                w2 = f"{where} evidence[{j}]"
                if not str(e.get("url", "")).startswith(("http://", "https://")):
                    d.append(f"{w2}: no retrievable url")
                # a regex accepted 2026-99-99; parse it, and refuse the future
                try:
                    got = dt.date.fromisoformat(str(e.get("retrieved", "")))
                    if got > dt.date.today():
                        d.append(f"{w2}: retrieved date {got} is in the future")
                except ValueError:
                    d.append(f"{w2}: retrieved must be a real YYYY-MM-DD date "
                             f"(got {e.get('retrieved')!r}); a regex accepted 2026-99-99")
                # ⛔ A VOLATILE ENDPOINT CANNOT SUPPORT A VERIFIED CELL.
                # Some provenance material exists only behind live APIs whose bodies carry
                # counters -- stars, download totals -- that change independently of the claim.
                # Such a record is admissible as ASSERTED evidence and never as VERIFIED, which
                # is what stops "volatile" from becoming a way to launder an unstable artifact
                # into a 2.
                if e.get("volatile"):
                    if val == 2:
                        d.append(f"{w2}: marked volatile, so it cannot support a VERIFIED cell")
                    if not str(e.get("volatile_reason", "")).strip():
                        d.append(f"{w2}: volatile with no stated reason")
                if not SHA256_RE.match(str(e.get("sha256", ""))):
                    d.append(f"{w2}: sha256 of the RETRIEVED BYTES is required "
                             f"-- an HTTP 200 is not an artifact")
        # ⛔ VERIFIED requires a REGISTERED method, not a sentence. Round-1 review passed every
        # score-2 cell with check="read a document" and this validator reported no defect.
        if val == 2:
            chk = c.get("check")
            if not isinstance(chk, dict):
                d.append(f"{where}: VERIFIED requires a `check` OBJECT "
                         f"{{method, asserts, observed}}; a free-text string is not a control")
            else:
                meth = str(chk.get("method", ""))
                if meth not in A.CHECK_METHODS:
                    d.append(f"{where}: check.method {meth!r} is not registered in "
                             f"axes.CHECK_METHODS -- a cell cannot be promoted to VERIFIED by "
                             f"describing a check that is not implemented")
                for k in ("asserts", "observed"):
                    if not str(chk.get(k, "")).strip():
                        d.append(f"{where}: check.{k} is empty; the assertion and what came "
                                 f"back must both be recorded or the claim cannot be contradicted")

    # ⛔ THE SAME URL MAY NOT CARRY TWO DIGESTS. Round-1 review showed a census validating with
    # one url recorded under conflicting hashes -- and recheck.py silently used the first, so the
    # contradiction was invisible on both sides.
    seen_url = {}
    for c in led.get("cells", []):
        for e in (c.get("evidence") or []):
            u, h = e.get("url"), e.get("sha256")
            if u in seen_url and seen_url[u][0] != h:
                d.append(f"{u}: recorded with two different digests "
                         f"({seen_url[u][0][:12]} at {seen_url[u][1]}, {str(h)[:12]} at "
                         f"{c.get('subject')}/axis{c.get('axis')}) -- one of them is wrong")
            elif u not in seen_url:
                seen_url[u] = (h, f"{c.get('subject')}/axis{c.get('axis')}")

    # PROJECT over subjects x axes: every pair must be present.
    for s in subjects:
        for ax in A.BY_ID:
            if (s, ax) not in seen:
                d.append(f"{s}/axis{ax} ({A.BY_ID[ax][2]}): MISSING -- absent is not zero")
    return d


def score(led):
    """Per subject: (as_coded, na_as_0, na_as_2), each a fraction of the maximum.

    Returns all three, always. There is deliberately no function returning the first alone.
    """
    out = {}
    by_sub = {}
    for c in led.get("cells", []):
        by_sub.setdefault(c["subject"], {})[c["axis"]] = c
    for s, cells in by_sub.items():
        vals = [cells[a].get("score") for a in sorted(cells)]
        real = [v for v in vals if v is not None]
        n_na = sum(1 for v in vals if v is None)
        as_coded = (sum(real) / (2 * len(real))) if real else 0.0
        na0 = sum(real) / (2 * len(vals)) if vals else 0.0
        na2 = (sum(real) + 2 * n_na) / (2 * len(vals)) if vals else 0.0
        out[s] = {"as_coded": as_coded, "na_as_0": na0, "na_as_2": na2,
                  "n_na": n_na, "n_scored": len(real),
                  "counts": {k: sum(1 for v in vals if v == k) for k in (2, 1, 0)}}
    return out


def emit_tables(led, sc):
    """Write tables/. NOTHING here may ever be typed into the manuscript by hand."""
    TABLES.mkdir(exist_ok=True)
    stamp = led.get("as_of", "undated")

    t1 = ["| # | group | axis | may be N/A |", "|---|---|---|---|"]
    for i, g, name, _q, _s, na in A.AXES:
        t1.append(f"| {i} | {g} | {name} | {'yes' if na else 'no'} |")
    (TABLES / "table1_axes.md").write_text(
        f"<!-- EMITTED by mp_metric.py, as of {stamp}. Do not edit. -->" + NL +
        NL.join(t1) + NL, encoding="utf-8", newline=NL)

    t2 = ["| release | CHECKED | CLAIMED | ABSENT | N/A | as-coded | N/A→0 | N/A→2 |",
          "|---|---|---|---|---|---|---|---|"]
    for s in sorted(sc, key=lambda k: -sc[k]["as_coded"]):
        v = sc[s]
        t2.append("| %s | %d | %d | %d | %d | %.3f | %.3f | %.3f |"
                  % (s, v["counts"][2], v["counts"][1], v["counts"][0], v["n_na"],
                     v["as_coded"], v["na_as_0"], v["na_as_2"]))
    (TABLES / "table2_scores.md").write_text(
        f"<!-- EMITTED by mp_metric.py, as of {stamp}. Do not edit. -->" + NL +
        NL.join(t2) + NL +
        NL + "The three columns are the same census under three readings of N/A. The spread"
        " between" + NL + "`N/A→0` and `N/A→2` is the weight the escape hatch is carrying; where"
        " it is wide, the" + NL + "as-coded figure is not reportable on its own." + NL,
        encoding="utf-8", newline=NL)
    return [TABLES / "table1_axes.md", TABLES / "table2_scores.md"]


if __name__ == "__main__":
    # only the entry point touches stdout; importing this module must not.
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    led = load()
    print("=" * 78)
    print("  mp-metric — %d axes, %d subject(s), %d cell(s), as of %s"
          % (len(A.AXES), len(led.get("subjects", [])), len(led.get("cells", [])),
             led.get("as_of", "undated")))
    print("=" * 78)

    defects = validate(led)
    if defects:
        print(NL + "  %d DEFECT(S) — the census is NOT scoreable:" % len(defects))
        for x in defects[:40]:
            print("    ! %s" % x)
        if len(defects) > 40:
            print("    ... and %d more" % (len(defects) - 40))
        print(NL + "  Nothing was scored and no table was written. A partially-validated census")
        print("  reported as a score is worse than no census.")
        raise SystemExit(1)
    print(NL + "  validation: no defects")

    sc = score(led)
    if not sc:
        print("  no subjects yet — nothing to score")
        raise SystemExit(0)
    print()
    for s in sorted(sc, key=lambda k: -sc[k]["as_coded"]):
        v = sc[s]
        print("  %-28s as-coded %.3f   [N/A→0 %.3f, N/A→2 %.3f]   %d N/A"
              % (s, v["as_coded"], v["na_as_0"], v["na_as_2"], v["n_na"]))

    if "--check" not in sys.argv:
        for p in emit_tables(led, sc):
            print("  emitted %s" % p.relative_to(HERE).as_posix())
    print()
    print("  " + chr(0x26D4) + " NOT A RANKING. See NOT-A-RANKING.md; the sentence travels with"
          " the numbers.")
