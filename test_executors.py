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


def _signature_integrity_controls():
    """A corrupted signature must not report as signed. [(label, got, want)]

    ⛔ IT DID. A reviewer corrupted the payload of a synthetic copy of the OLMo commit signature,
    rederived the object id and the archived-byte digest so every consistency rule stayed satisfied,
    and preserved the issuer fingerprint. The executor returned True and described the commit as
    signed, while GPG rejects the same bytes on the armour checksum. Every real signature in this
    census must still pass, or the repair has broken the evidence it was protecting.
    """
    led = json.loads((HERE / "cells.json").read_text(encoding="utf-8"))
    out = []
    for c in led["cells"]:
        blk = _blk_of(c)
        if blk.get("method") != "hf_probe.signed_commit":
            continue
        ev = [e for e in (c.get("evidence") or [])
              if e.get("sha256") == blk.get("expect_evidence_sha256")]
        raw = R._bytes_for(ev[0]) if ev else None
        if raw is None or b"gpgsig" not in raw:
            continue
        i = raw.index(b"gpgsig") + 200
        bad = raw[:i] + (b"A" if raw[i:i + 1] != b"A" else b"B") + raw[i + 1:]
        out.append(("NEGATIVE: %s's real signature packet is intact" % c["subject"],
                    R.signature_intact(raw)[0], True))
        out.append(("a corrupted payload under %s's intact issuer is REFUSED" % c["subject"],
                    R.signature_intact(bad)[0], False))
    return out or [("no signed commit object in the ledger to attack", True, True)]


def _positive_shape_controls():
    """Can the POSITIVE path be satisfied by something that is not the thing? [(label, got, want)]

    ⛔ IT COULD, AND THE MANUSCRIPT CALLS THESE 2s ITS STRONGEST EVIDENCE. A reviewer replaced one
    Git-LFS identifier in the OLMo axis-2 fixture with the string `not-a-sha256-digest`, rehashed
    the synthetic response and updated every ledger reference to it consistently -- the honest
    version of the attack, leaving no internal inconsistency to trip over. The executor returned
    True, the validator found 0 defects and strict replay passed 23 of 23. The check was
    `if e["lfs"].get("oid")`: a TRUTHINESS TEST standing in for "a digest is published".

    ⚠ These run the executor against MUTATED ARCHIVED BYTES rather than a mutated ledger, because
    that is where the reviewer's counter-example lives: every ledger-side reference was made
    consistent, so no ledger-side rule could have noticed.
    """
    import gzip
    led = R.load_ledger() if hasattr(R, "load_ledger") else json.loads(
        (HERE / "cells.json").read_text(encoding="utf-8"))
    cells = led["cells"] if isinstance(led, dict) else led
    cand = [c for c in cells
            if _blk_of(c).get("method") == "hf_probe.corpus_item_digests"
            and not isinstance(c.get("bound"), dict)]
    if not cand:
        return [("no positive corpus-digest cell to attack (fixture absent)", True, True)]
    cell = cand[0]
    real = R._bytes_for((cell.get("evidence") or [{}])[0])
    if real is None:
        return [("the corpus-digest fixture's bytes are not archived", True, True)]
    entries = json.loads(real.decode("utf-8"))

    def _with(oid):
        out = json.loads(json.dumps(entries))
        for e in out:
            if e.get("type") == "file" and isinstance(e.get("lfs"), dict):
                e["lfs"]["oid"] = oid
                break
        return json.dumps(out).encode("utf-8")

    def _verdict(payload):
        orig = R._bytes_for
        R._bytes_for = lambda e, _p=payload: _p
        try:
            return bool(_call(cell, None, led)[0])
        finally:
            R._bytes_for = orig

    # ⛔ AND THE EXCLUSION IS A DENOMINATOR, SO IT IS ATTACKED. `expect_non_content` lets a cell
    # say a file cannot carry a content digest -- true of `.gitattributes`, which is the Git-LFS
    # configuration that causes the others to be addressed. A declaration that shrinks the set a
    # rule applies to is exactly the kind that must not be trusted: it is policed in both
    # directions, and both directions are tested here.
    def _verdict_decl(payload, decl):
        blk = _blk_of(cell)
        was = blk.get("expect_non_content")
        blk["expect_non_content"] = decl
        try:
            return _verdict(payload)
        finally:
            if was is None:
                blk.pop("expect_non_content", None)
            else:
                blk["expect_non_content"] = was

    _extra = [("NEGATIVE: the declared exclusion is honoured",
               _verdict_decl(real, [".gitattributes"]), True),
              ("declaring a file that is NOT in the enumeration is REFUSED",
               _verdict_decl(real, ["no-such-file"]), False),
              ("declaring a file that DOES carry a digest is REFUSED",
               _verdict_decl(real, [e["path"] for e in entries
                                    if isinstance(e.get("lfs"), dict) and e["lfs"].get("oid")][:1]),
               False)]

    return _extra + [
        ("NEGATIVE: the real corpus-digest fixture still passes", _verdict(real), True),
        ("the reviewer's `not-a-sha256-digest` is REFUSED",
         _verdict(_with("not-a-sha256-digest")), False),
        ("a 63-character near-miss is REFUSED", _verdict(_with("a" * 63)), False),
        ("an UPPERCASE oid is REFUSED (an LFS oid is lowercase hex)",
         _verdict(_with("A" * 64)), False),
        ("a plausible-looking word is REFUSED", _verdict(_with("published")), False),
    ]


def _adjudication_routing():
    """Can the positive path record the positive it exists to find? [(label, got, want)]

    ⛔ IT COULD NOT, AND IT HAD NEVER BEEN ASKED. `note_for` decided a hit's disposition from the
    AXIS NUMBER it was handed -- `if (hit and axis == 17)` -- so a bit-identical reproduction was
    routed to axis 17 and axis 16 was told nothing had been identified. A reviewer built the
    fixture and read the two sentences back. Twelve axis-16 zeros stood behind a search that could
    not have written a positive on that axis had one existed, which makes those zeros a property of
    the code rather than of the world.

    ⚠ The disposition was in the record all along: each adjudicated hit declares `affects`. The
    fixtures below are the reviewer's, kept so the positive path is exercised in every run rather
    than only when a positive finally turns up -- which is the one occasion on which nobody would
    be able to tell the difference.
    """
    import copy
    import apply_negative_search as A
    rec = json.loads((HERE / "negative-search.json").read_text(encoding="utf-8"))
    subs = rec["subjects"]
    base = (subs["bert-base-uncased"] if isinstance(subs, dict)
            else [s for s in subs if s.get("name") == "bert-base-uncased"][0])

    def heads(r):
        out = {}
        for ax in (16, 17):
            try:
                out[ax] = "WAS found" in A.note_for("x", r, ax, rec["run_at"])
            except SystemExit:
                out[ax] = "REFUSED"
        return out

    exact = copy.deepcopy(base)
    exact["adjudication"]["hit"]["affects"] = "axis 16 only"
    unroutable = copy.deepcopy(base)
    unroutable["adjudication"]["hit"]["affects"] = "the paper generally"
    return [
        ("NEGATIVE: the real APPROXIMATE hit still lands on 17 alone", heads(base),
         {16: False, 17: True}),
        ("an EXACT hit lands on 16 and not on 17", heads(exact), {16: True, 17: False}),
        ("a hit with no routable disposition is REFUSED, not written as absence",
         heads(unroutable), {16: "REFUSED", 17: "REFUSED"}),
    ]


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

    print()
    print("  signature integrity -- can a corrupted packet report as signed?")
    for _lab, _got, _want in _signature_integrity_controls():
        _ok = _got == _want
        if not _ok:
            missed += 1
        print("    %s %-58s %s" % ("ok     " if _ok else chr(0x26D4) + " MISSED", _lab,
                                   "" if _ok else "got %r want %r" % (_got, _want)))
    print()
    print("  the positive path -- can a non-digest certify as a digest?")
    for _lab, _got, _want in _positive_shape_controls():
        _ok = _got == _want
        if not _ok:
            missed += 1
        print("    %s %-58s %s" % ("ok     " if _ok else chr(0x26D4) + " MISSED", _lab,
                                   "" if _ok else "got %r want %r" % (_got, _want)))
    print()
    print("  the adjudication routing -- can the positive path record a positive?")
    for _lab, _got, _want in _adjudication_routing():
        _ok = _got == _want
        if not _ok:
            missed += 1
        print("    %s %-58s %s" % ("ok     " if _ok else chr(0x26D4) + " MISSED", _lab,
                                   "" if _ok else "got %r want %r" % (_got, _want)))
    print()
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
