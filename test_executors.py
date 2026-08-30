"""Call each executor DIRECTLY, because the self-test no longer reaches them.

⛔ WHY THIS EXISTS. `replay.py --selftest` mutates the ledger and asks whether the pipeline rejects
it. After round 10 the answer is almost always yes -- and almost always for the WRONG REASON:
`mp_metric.validate()` refuses the mutated ledger before any executor is invoked. The coverage
sweep says the same thing in its own units (0 of 8,586 transplants reach the gate), and a control
audit says it at the source level: 67 of 97 defect-reporting statements can be deleted with the
whole suite still green, most of them inside executors that nothing now reaches.

That is not a validator problem. Rejecting early is better than rejecting late. The problem is what
it does to the EVIDENCE that the executors work:

    an intermediate m_all_shard_digests raised NameError on every call, and `--selftest`
    reported 37 of 37 attacks correctly rejected

It did, too -- the validator rejected all 37 before the broken code ran. The break surfaced only
because `replay.py` runs the executors over the UNMUTATED ledger and printed a traceback. A suite
whose failure mode is "the thing under test was never called" is measuring its own scaffolding.

⇒ So these tests bypass `validate()` entirely and hand crafted inputs straight to the executor.

⚠️ THE MUTATIONS ARE PROJECTIONS, NOT A LIST. The check block is a dictionary of declared
expectations, and the interesting question for every one of them is the same: does the executor
actually READ it? So each key is deleted in turn, and then perturbed in turn, and the executor must
reject in both cases. A key that can be deleted AND corrupted with the executor still returning
True is a declaration nothing consumes -- which is exactly the defect that let 40 transplants
survive on axis 12, where `expect_range_bytes` was the only field read and it was 2048 for every
subject in the census.

    python test_executors.py
"""
import copy
import io
import json
import pathlib
import sys

import replay as R

NL = chr(10)
HERE = pathlib.Path(__file__).resolve().parent


def _blk_name(cell):
    """Which block this cell asserts: a positive carries `check`, a negative carries `bound`."""
    return "bound" if isinstance(cell.get("bound"), dict) else "check"


def _blk_of(cell):
    return cell.get(_blk_name(cell)) or {}


def _call(cell, ctx, led):
    """Invoke the executor for this cell exactly as replay.main does, minus the gate."""
    fn = R.DISPATCH.get(_blk_of(cell).get("method"))
    if fn is None:
        return None, "no executor"
    try:
        return fn(cell, cell.get("evidence") or [], ctx)
    except TypeError:
        return fn(cell, cell.get("evidence") or [])


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    led = json.loads((HERE / "cells.json").read_text(encoding="utf-8"))
    ctx = R.subject_context(led)
    # ⛔ THIS SELECTED VERIFIED CELLS ONLY, so the moment negatives became executable there
    # were six load-bearing check-blocks that no mutation ever touched. The selection projects
    # over BOTH kinds now: whatever an executor can be asked to settle, this file mutates.
    cells = [c for c in led["cells"]
             if (c.get("score") == 2 and c.get("check")) or isinstance(c.get("bound"), dict)]

    print("=" * 78)
    print("  EXECUTORS, CALLED DIRECTLY -- the validator is not consulted")
    print("=" * 78)
    print()

    # ── the baseline: every real cell must PASS its own executor ─────────────────────
    # ⛔ Without this the whole file is vacuous. A suite that only checks rejection passes
    # trivially against an executor that rejects everything -- including the true cases.
    base_bad = []
    for c in cells:
        res, why = _call(c, ctx, led)
        if res is not True:
            base_bad.append("%s/axis%d: %s" % (c["subject"], c["axis"], why))
    print("  baseline  %d VERIFIED cell(s) pass their own executor%s"
          % (len(cells) - len(base_bad),
             ("; " + chr(0x26D4) + " %d DO NOT" % len(base_bad)) if base_bad else ""))
    for b in base_bad:
        print("      " + chr(0x26D4) + " " + b)
    print()

    ok = missed = 0
    unread = []
    for c in cells:
        where = "%s/axis%d" % (c["subject"], c["axis"])
        blk = _blk_name(c)
        # ⛔ THIS WAS AN EXCLUSION LIST AND IT BROKE THE MOMENT A FIELD WAS RENAMED. `searched`
        # became `searched_archived` and `searched_live` in round 14, and the stale list let 59
        # mutations of validator-only fields be reported as executor misses -- noise that would
        # have buried a real one. What an EXECUTOR reads is the expectations; everything else is
        # mp_metric's business and is watched by test_bound_rules.py. Projected, not enumerated.
        keys = [k for k in _blk_of(c) if k.startswith("expect")]

        for k in keys:
            # (a) DELETE the declared expectation. The executor must refuse: a check whose
            #     expectation is absent is a method name, not a check.
            d = copy.deepcopy(c)
            d[blk].pop(k, None)
            res, _why = _call(d, ctx, led)
            if res is False:
                ok += 1
            else:
                missed += 1
                unread.append((where, k, "deleting it", res))

            # (b) PERTURB it. Deleting can be caught by a blanket "required field" test while
            #     the value itself is never compared; changing it cannot.
            d2 = copy.deepcopy(c)
            v = d2[blk][k]
            d2[blk][k] = (v + 1 if isinstance(v, int) and not isinstance(v, bool)
                              else ("zzzz" + str(v))[:64] if isinstance(v, str)
                              else ["zzzz"] if isinstance(v, list) else "zzzz")
            res2, _why2 = _call(d2, ctx, led)
            if res2 is False:
                ok += 1
            else:
                missed += 1
                unread.append((where, k, "corrupting it", res2))

        # (c) the EVIDENCE, not the declaration: repoint the primary artifact's digest.
        d3 = copy.deepcopy(c)
        if d3.get("evidence"):
            d3["evidence"][0]["sha256"] = "0" * 64
            res3, _why3 = _call(d3, ctx, led)
            if res3 is False:
                ok += 1
            else:
                missed += 1
                unread.append((where, "evidence[0].sha256", "repointing it", res3))

        # (c2) ANOTHER SUBJECT'S EVIDENCE, WHOLESALE.
        # ⛔ THIS FILE PROJECTED OVER THE CHECK BLOCK AND NEVER OVER THE EVIDENCE'S OWNER,
        # so the executors' subject-binding checks were unreachable from it. A reviewer deleted
        # `return False, "this is %s's evidence; the cell is scored for %s"` from m_weight_object
        # and this suite still reported 153 of 153 rejected, with the whole workspace green. The
        # identity checks the paper is built on were the ones nothing here could exercise --
        # which is the shape of every defect this project keeps finding, arriving inside the tool
        # written to find it.
        for other in cells:
            if other["subject"] == c["subject"] or other["axis"] != c["axis"]:
                continue
            d5 = copy.deepcopy(c)
            d5["evidence"] = copy.deepcopy(other.get("evidence") or [])
            res5, _why5 = _call(d5, ctx, led)
            if res5 is False:
                ok += 1
            else:
                missed += 1
                unread.append((where, "%s's evidence" % other["subject"],
                               "transplanting it", res5))
            break

        # (d) drop every co-cited artifact, leaving the primary alone.
        d4 = copy.deepcopy(c)
        if len(d4.get("evidence") or []) > 1:
            d4["evidence"] = [d4["evidence"][0]]
            res4, _why4 = _call(d4, ctx, led)
            if res4 is False:
                ok += 1
            else:
                missed += 1
                unread.append((where, "the co-cited artifacts", "dropping them", res4))

    print("  %d mutation(s) correctly rejected by the executor itself" % ok)
    print("  %d NOT rejected" % missed)
    if unread:
        print()
        print("  " + chr(0x26A0) + " A declared field the executor does not read is a field that")
        print("  cannot discriminate anything -- the axis-12 defect, in general form.")
        for where, k, how, res in unread:
            print("      %-26s %-26s survives %-16s (returned %r)" % (where, k, how, res))
    print("=" * 78)
    return 1 if (missed or base_bad) else 0


if __name__ == "__main__":
    raise SystemExit(main())
