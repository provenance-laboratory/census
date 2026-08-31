"""Can any input reach the checks that have never executed? Measure it, and name what still cannot.

⛔ WHY THIS EXISTS. `control_audit.py` deletes each control and re-runs the suite to see whether
anything notices. It reports 173 controls, 96 watched, and **54 that NO INPUT THE SUITE CAN BUILD
REACHES AT ALL** -- not dead code, but code no test has ever run.

⇒ AND THE REASON IS ONE SENTENCE. Every mutation this project makes attacks the LEDGER: transplant
a cell's evidence onto another cell, blank a bound, rewrite a digest. The validator refuses those
before an executor ever runs. But almost all 54 unreached checks are INSIDE executors, and what
they defend against is the ARCHIVE -- truncated bytes, a JSON body that will not parse, a git-LFS
pointer where weights should be, a tree marked truncated. **Nothing in this project has ever
mutated the evidence store.** The suite attacks the record; the executors defend the bytes; the two
have never met.

⚠️ SO THIS IS NOT A FIXTURE LIBRARY, which would be an enumeration and would go stale the moment a
branch was added. It reads the audit's OWN survivor list, applies archive-level mutations through
the single seam every executor reads bytes through, and traces which lines actually execute. A
branch it cannot reach is REPORTED BY NAME rather than quietly dropped, because the residue is the
finding.

⚠️ REACHING A CHECK IS NOT VALIDATING IT. This establishes that an input exists which runs the line
and that the executor refuses. It does not establish that the refusal is correct, or that the
message is right. That still needs reading.

    python reach_controls.py            measure and rewrite REACH-CONTROLS.json
    python reach_controls.py --verify   measure and refuse if the record disagrees
"""
import copy
import gzip
import hashlib
import inspect
import io
import json
import pathlib
import sys

NL = chr(10)
D = chr(0x26D4)
W = chr(0x26A0)
HERE = pathlib.Path(__file__).resolve().parent
AUDIT = HERE / "CONTROL-AUDIT.json"
OUT = HERE / "REACH-CONTROLS.json"

sys.path.insert(0, str(HERE))
import replay as R                                                          # noqa: E402
import mp_metric as M                                                       # noqa: E402

LFS_POINTER = (b"version https://git-lfs.github.com/spec/v1" + bytes([10])
               + b"oid sha256:" + b"0" * 64 + bytes([10]) + b"size 1234" + bytes([10]))


def mutations():
    """Archive-level corruptions, each named for the claim it attacks.

    {W} These are deliberately NOT tailored to individual branches. A mutation written to reach
    one line would prove only that the line can be reached by a mutation written to reach it.
    """
    return [
        ("absent from the store", lambda b: None),
        ("empty", lambda b: b""),
        ("one byte", lambda b: b[:1]),
        ("truncated to half", lambda b: b[:max(1, len(b) // 2)]),
        ("truncated to 8 bytes", lambda b: b[:8]),
        ("one byte flipped mid-body", _flip),
        ("a git-LFS pointer", lambda b: LFS_POINTER),
        ("not JSON", lambda b: b"{ this is not json"),
        ("JSON empty list", lambda b: b"[]"),
        ("JSON empty object", lambda b: b"{}"),
        ("JSON tree marked TRUNCATED", lambda b: b'{"truncated": true, "tree": []}'),
        ("JSON with no files", lambda b: b'{"siblings": [], "files": []}'),
        ("garbage prepended", lambda b: b"XXXXXXXX" + b),
        ("doubled", lambda b: b + b),

        # ⛔ THE GUARDS ARE SEQUENTIAL, AND A GENERIC MUTATION ONLY EVER REACHES THE FIRST ONE.
        # An LFS pointer never reached "the archived weight range IS A GIT-LFS POINTER", because
        # the length check one line above deflected it. Every later guard needs a mutation that
        # PASSES all of its predecessors -- here, one that keeps the byte count exactly. This is
        # why a mutation library plateaus: coverage is not a function of how many mutations there
        # are, but of how many PREFIXES of each guard sequence they satisfy.
        ("an LFS pointer, same length", lambda b: _fit(LFS_POINTER, len(b))),
        ("zero bytes, same length", lambda b: bytes(len(b))),
        ("high bytes, same length", lambda b: bytes([255]) * len(b)),
        ("same length, header zeroed", lambda b: bytes(8) + b[8:] if len(b) > 8 else b),
        ("same length, an HTML sign-in page",
         lambda b: _fit(b"<!DOCTYPE html><html>sign in</html>", len(b))),
    ]


def _fit(pat, n):
    """Repeat or truncate a pattern to exactly n bytes, so a length guard cannot deflect it."""
    if n <= 0:
        return b""
    return (pat * (n // len(pat) + 1))[:n]


def _flip(b):
    if not b:
        return b
    i = len(b) // 2
    return b[:i] + bytes([b[i] ^ 0xFF]) + b[i + 1:]


def ledger_mutations(block):
    """Perturb each field of the check block, PROJECTING over its own keys.

    ⚠ Not a list of field names. A named list would go stale the moment a check gained a field,
    which is the defect this project has now found fourteen times, so the keys come from the block.
    """
    out = []
    for k, v in sorted(block.items()):
        if isinstance(v, bool) or k == "method":
            continue
        if isinstance(v, int):
            out.append(("%s + 1" % k, k, v + 1))
        elif isinstance(v, str) and v:
            out.append(("%s altered" % k, k, v + "X"))
        elif isinstance(v, list) and v:
            out.append(("%s missing one entry" % k, k, v[1:]))
    return out


def never_executed():
    """The unreached branches, read from the audit rather than listed here."""
    a = json.loads(AUDIT.read_text(encoding="utf-8"))
    out = {}
    for s in a.get("survivors", []):
        if s.get("class") == "NEVER EXECUTES":
            out[(s["file"], int(s["line"]))] = s.get("source", "").strip()
    return out


class Tracer:
    """Record every (file, line) executed. The only honest way to know a branch ran."""

    def __init__(self):
        self.seen = set()

    def __enter__(self):
        sys.settrace(self._t)
        return self

    def __exit__(self, *a):
        sys.settrace(None)

    def _t(self, frame, event, arg):
        name = pathlib.Path(frame.f_code.co_filename).name
        if name in ("replay.py", "mp_metric.py"):
            self.seen.add((name, frame.f_lineno))
            return self._t
        return None


def call_executor(fn, cell, ev, ctx):
    n = len(inspect.signature(fn).parameters)
    return fn(cell, ev, ctx) if n >= 3 else fn(cell, ev)


def _still_says(info, why):
    """Did the control that was recorded here still produce ITS OWN message?

    ⛔ QUICK MODE COMPARED LINE NUMBERS AND NOTHING ELSE, so replacing a control with `pass` at
    the same line left it green. The line still executed; the control was gone. **A line number
    is a proxy for a control** -- the same defect this project has now found in a substring
    standing for a token, a build-config line standing for a BLAS, and a status string standing
    for a verdict. Found by running the positive control: delete the thing and see if the tool
    notices. It did not.

    ⚠ The message is not a perfect identity either -- two controls could share wording. It is
    strictly better than a line number and it is what the control itself emits.
    """
    want = (info or {}).get("says")
    if not want:
        return True
    return str(why)[:90] == want


def quick(led, ctx, cells_by_key):
    """Replay only the mutations a full run recorded as REACHING a branch, and check they still do.

    ⛔ THE FULL SWEEP MADE THE CONTROL AUDIT UNUSABLE. `control_audit.py` re-runs the entire
    suite once per control, 173 times; a sweep of ~8,600 mutations turned a ten-minute audit into
    a multi-hour one, and an audit nobody runs is worse than no audit -- which is the same defect
    class as a control nobody executes, one level up.

    ⚠ THIS IS A REPLAY, NOT A MEASUREMENT, and the distinction matters. The full run is the
    authority and rewrites the record; quick mode only re-executes what that run found and FAILS
    if any recorded branch stops being reached. That is what makes it a watcher: delete a control
    it covers and this notices. It cannot discover a NEW reachable branch, and does not claim to.
    """
    rec = json.loads(OUT.read_text(encoding="utf-8"))
    detail = rec.get("detail") or {}
    if not detail:
        print("  " + D + " %s records no reaching mutation, so quick mode would verify nothing."
              % OUT.name)
        return 1
    by_label = {m[0]: m[1] for m in mutations()}
    real_bytes = R._bytes_for
    lost = []
    for where, info in sorted(detail.items()):
        f, ln = where.rsplit(":", 1)
        key = (f, int(ln))
        cell = cells_by_key.get(info["cell"])
        if cell is None:
            lost.append((where, "the cell %s is gone" % info["cell"]))
            continue
        ev = cell.get("evidence") or []
        fn = R.DISPATCH.get((R._asserted(cell) or {}).get("method"))
        if fn is None:
            lost.append((where, "no executor for this cell any more"))
            continue
        mut = by_label.get(info.get("mutation"))
        hit = False
        variants = []
        if mut is not None:
            idx = info.get("evidence_index", 0)
            sha = ev[idx].get("sha256") if idx < len(ev) else None
            variants.append((ev, mut, sha))
        elif info.get("kind") == "ledger":
            # a LEDGER mutation: rebuild it from the block's own keys and find the label again
            blk = R._asserted(cell) or {}
            for lab, k2, newval in ledger_mutations(blk):
                if lab == info.get("mutation"):
                    m2 = copy.deepcopy(cell)
                    holder = m2.get("bound") or m2.get("check") or {}
                    holder[k2] = newval
                    _w2 = None
                    with Tracer() as tr:
                        try:
                            _o2, _w2 = call_executor(fn, m2, ev, ctx)
                        except Exception:                                    # noqa: BLE001
                            pass
                    if key in tr.seen and _still_says(info, _w2):
                        hit = True
                    break
            if not hit:
                lost.append((where, "ledger mutation %r no longer reaches it"
                             % info.get("mutation")))
            continue
        else:
            # an evidence-shape mutation: re-run the shapes for this cell
            if ev:
                variants += [(list(ev[1:]), None, None), ([ev[0]], None, None),
                             ([ev[0]] + list(ev), None, None), ([ev[-1]], None, None),
                             ([], None, None)]
        for newev, m, sha in variants:
            def patched(e, _m=m, _s=sha):
                b = real_bytes(e)
                if _m is None or e.get("sha256") != _s:
                    return b
                return None if b is None else _m(b)
            R._bytes_for = patched
            _last_why = None
            try:
                with Tracer() as tr:
                    try:
                        _ok2, _last_why = call_executor(fn, copy.deepcopy(cell), newev, ctx)
                    except Exception:                                        # noqa: BLE001
                        pass
            finally:
                R._bytes_for = real_bytes
            if key in tr.seen and _still_says(info, _last_why):
                hit = True
                break
        if not hit:
            lost.append((where, "no longer reached by %r" % info.get("mutation")))

    print("  quick replay of %d recorded branch(es)" % len(detail))
    for where, why in lost:
        print("  " + D + " %-18s %s" % (where, why))
    if lost:
        print()
        print("  " + D + " %d recorded branch(es) are no longer reached. Either a control was "
              % len(lost))
        print("  removed, or an executor changed shape. Re-run the full sweep to re-measure.")
        return 1
    print("  ok  every recorded branch still executes.")
    return 0


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace",
                                  line_buffering=True)
    targets = never_executed()
    led = json.loads((HERE / "cells.json").read_text(encoding="utf-8"))
    ctx = R.subject_context(led)

    if "--quick" in sys.argv:
        if not OUT.exists():
            print("  " + D + " %s is absent. Quick mode REPLAYS a full run and cannot stand in "
                  "for one; run `python reach_controls.py` first." % OUT.name)
            return 1
        by_key = {"%s/axis%d" % (c["subject"], c["axis"]): c for c in led["cells"]}
        return quick(led, ctx, by_key)

    print("=" * 78)
    print("  REACHING THE CHECKS THAT HAVE NEVER EXECUTED")
    print("=" * 78)
    print()
    print("  %d branch(es) the control audit reports as unreachable by the suite." % len(targets))
    print("  " + W + " Every mutation this project makes attacks the LEDGER, and the validator")
    print("  refuses those before an executor runs. These branches defend the ARCHIVE, and")
    print("  nothing here has ever mutated the evidence store.")
    print()

    real_bytes = R._bytes_for
    reached = {}
    refused = attempted = 0

    cells = [c for c in led["cells"] if (R._asserted(c) or {}).get("method") in R.DISPATCH]
    print("  %d cell(s) name an executor. Mutating the bytes each one reads." % len(cells))
    print()

    for cell in cells:
        meth = R._asserted(cell)["method"]
        fn = R.DISPATCH[meth]
        ev = cell.get("evidence") or []
        if not ev:
            continue
        # {D} THE FIRST VERSION OF THIS TOOL CORRUPTED EVERY EVIDENCE ITEM AT ONCE, so an
        # executor reading an API response and a weight range saw BOTH corrupted, the JSON check
        # fired first, and every branch behind it stayed unreached. The tool written to reach
        # unreached branches was itself unable to reach them, for the same reason the suite could
        # not: it attacked at the wrong granularity. One item at a time, and the ledger's claims
        # about that item left standing, is what lets the deeper checks fire.
        for idx in range(len(ev)):
            target_sha = ev[idx].get("sha256")
            for label, mut in mutations():
                def patched(e, _m=mut, _s=target_sha):
                    b = real_bytes(e)
                    if e.get("sha256") != _s:
                        return b
                    return None if b is None else _m(b)
                R._bytes_for = patched
                attempted += 1
                try:
                    with Tracer() as tr:
                        try:
                            ok, _why = call_executor(fn, copy.deepcopy(cell), ev, ctx)
                        except Exception:                                    # noqa: BLE001
                            ok = None
                finally:
                    R._bytes_for = real_bytes
                refused += ok is False
                for key in targets:
                    if key in tr.seen and key not in reached:
                        reached[key] = {"cell": "%s/axis%d" % (cell["subject"], cell["axis"]),
                                        "method": meth, "mutation": label,
                                        "evidence_index": idx,
                                        "refused": ok is False,
                                        "says": str(_why)[:90]}

    # ⛔ A SECOND AXIS, AND THE POINT IS THE DISTINCTION IT DRAWS. Many of these branches check
    # that the LEDGER'S CLAIM disagrees with intact bytes -- a recorded length, a recorded digest,
    # a recorded count. No archive mutation reaches those. But a ledger mutation that the
    # VALIDATOR would refuse does not show the branch is reachable in production; it shows the
    # branch is defence in depth behind a check that fires first. Both are recorded, separately,
    # because calling them the same thing is how a redundant guard gets counted as a tested one.
    for cell in cells:
        meth = R._asserted(cell)["method"]
        fn = R.DISPATCH[meth]
        ev = cell.get("evidence") or []
        block = R._asserted(cell) or {}
        for label, key, newval in ledger_mutations(block):
            mutant = copy.deepcopy(cell)
            tgt = mutant.get("bound") or mutant.get("check") or {}
            tgt[key] = newval
            probe = copy.deepcopy(led)
            for i, c in enumerate(probe["cells"]):
                if c["subject"] == cell["subject"] and c["axis"] == cell["axis"]:
                    probe["cells"][i] = mutant
            try:
                validator_catches = not M.validate(probe)
            except Exception:                                                # noqa: BLE001
                validator_catches = True
            attempted += 1
            try:
                with Tracer() as tr:
                    try:
                        ok, _why = call_executor(fn, mutant, ev, ctx)
                    except Exception:                                        # noqa: BLE001
                        ok = None
            finally:
                pass
            refused += ok is False
            for key2 in targets:
                if key2 in tr.seen and key2 not in reached:
                    reached[key2] = {
                        "cell": "%s/axis%d" % (cell["subject"], cell["axis"]),
                        "method": meth, "mutation": label,
                        "kind": "ledger",
                        "validator_would_catch_it_first": bool(validator_catches)}

    # ⛔ A THIRD AXIS: THE EVIDENCE LIST ITSELF. Several checks ask how MANY artifacts a cell
    # cites -- "expected exactly one pinned enumeration, found %d", "the ranged artifact is cited
    # alone". Corrupting bytes cannot reach those and neither can perturbing a scalar field; the
    # shape of the list is a third thing, and nothing in this project had ever varied it.
    for cell in cells:
        meth = R._asserted(cell)["method"]
        fn = R.DISPATCH[meth]
        ev = cell.get("evidence") or []
        shapes = [("evidence list emptied", [])]
        if ev:
            shapes.append(("first artifact duplicated", [ev[0]] + list(ev)))
            shapes.append(("first artifact dropped", list(ev[1:])))
            shapes.append(("only the first artifact kept", [ev[0]]))
            shapes.append(("only the last artifact kept", [ev[-1]]))
        for label, newev in shapes:
            mutant = copy.deepcopy(cell)
            mutant["evidence"] = copy.deepcopy(newev)
            attempted += 1
            with Tracer() as tr:
                try:
                    ok, _why = call_executor(fn, mutant, mutant["evidence"], ctx)
                except Exception:                                            # noqa: BLE001
                    ok = None
            refused += ok is False
            for key in targets:
                if key in tr.seen and key not in reached:
                    reached[key] = {"cell": "%s/axis%d" % (cell["subject"], cell["axis"]),
                                    "method": meth, "mutation": label, "kind": "evidence-shape",
                                    "refused": ok is False, "says": str(_why)[:90]}

    # ⛔ A FOURTH AXIS: THE VALIDATOR. Four of the unreached branches are in `mp_metric.py` and
    # are complaints the VALIDATOR makes, not refusals an executor returns. Running executors
    # could never have reached them, and a tool that only ran executors would have reported them
    # unreachable while the input that reaches them is two lines away.
    for cell in cells + [c for c in led["cells"] if c not in cells][:40]:
        block = R._asserted(cell) or {}
        muts = list(ledger_mutations(block))
        muts.append(("bound emptied", None, {}))
        muts.append(("bound removed", None, None))
        for label, key, newval in muts:
            mutant = copy.deepcopy(cell)
            if key is None:
                for holder in ("bound", "check"):
                    if holder in mutant:
                        if newval is None:
                            mutant.pop(holder)
                        else:
                            mutant[holder] = {}
            else:
                tgt = mutant.get("bound") or mutant.get("check") or {}
                tgt[key] = newval
            probe = copy.deepcopy(led)
            for i, c in enumerate(probe["cells"]):
                if c["subject"] == cell["subject"] and c["axis"] == cell["axis"]:
                    probe["cells"][i] = mutant
            attempted += 1
            with Tracer() as tr:
                try:
                    M.validate(probe)
                except Exception:                                            # noqa: BLE001
                    pass
            for key2 in targets:
                if key2 in tr.seen and key2 not in reached:
                    reached[key2] = {"cell": "%s/axis%d" % (cell["subject"], cell["axis"]),
                                     "method": (block or {}).get("method"),
                                     "mutation": label, "kind": "validator"}

    # ⛔ A FIFTH AXIS: THE GATE. Three branches live in `gate()` and ask whether a method binds
    # its axis at all -- "method %r has no executor", "method %r cannot settle this axis". No
    # executor call reaches them, because reaching them means never getting to an executor.
    for cell in cells[:12]:
        for label, newmeth in (("method that has no executor", "no_such_executor"),
                               ("method not permitted on this axis", "grep_retrieved"),
                               ("method removed", None)):
            mutant = copy.deepcopy(cell)
            mutant["score"] = 2
            tgt = mutant.get("bound") or mutant.get("check") or {}
            if newmeth is None:
                tgt.pop("method", None)
            else:
                tgt["method"] = newmeth
            probe = copy.deepcopy(led)
            for i, c in enumerate(probe["cells"]):
                if c["subject"] == cell["subject"] and c["axis"] == cell["axis"]:
                    probe["cells"][i] = mutant
            attempted += 1
            with Tracer() as tr:
                try:
                    R.gate(mutant, R.subject_context(probe), None, probe)
                except Exception:                                            # noqa: BLE001
                    pass
            for key2 in targets:
                if key2 in tr.seen and key2 not in reached:
                    reached[key2] = {"cell": "%s/axis%d" % (cell["subject"], cell["axis"]),
                                     "method": newmeth, "mutation": label, "kind": "gate"}

    still = {k: v for k, v in targets.items() if k not in reached}

    for (f, ln), info in sorted(reached.items()):
        print("  ok   %-13s:%-5s reached by %-26s on %s"
              % (f, ln, info["mutation"], info["cell"]))
    if still:
        print()
        for (f, ln), src in sorted(still.items()):
            print("  %s %-13s:%-5s %s" % (W, f, ln, src[:70]))

    print()
    import collections as _c
    _kinds = _c.Counter(v.get("kind", "archive") for v in reached.values())
    print("  reached by axis: %s" % dict(_kinds))
    _arch = sum(1 for v in reached.values() if v.get("kind") in (None, "archive"))
    _ledg = [v for v in reached.values() if v.get("kind") == "ledger"]
    _behind = sum(1 for v in _ledg if v.get("validator_would_catch_it_first"))
    print("  %d of %d unreached branch(es) are now reached." % (len(reached), len(targets)))
    print("    %d by corrupting the ARCHIVE -- reachable in production" % _arch)
    print("    %d by altering the LEDGER, of which %d the validator refuses first"
          % (len(_ledg), _behind))
    if _behind:
        print("  " + W + " A branch behind a validator that refuses first is DEFENCE IN DEPTH,")
        print("  not a tested control. It fires, and no real input can make it fire. Counting")
        print("  those as covered would be the same error as counting a control nobody runs.")
    print("  %d attempt(s), %d refusal(s) from the executors." % (attempted, refused))
    if still:
        print()
        print("  " + W + " %d STILL UNREACHED, and they are named above rather than dropped."
              % len(still))
        print("  A branch this cannot reach is one of three things: it needs a ledger shape no")
        print("  real cell has, it belongs to an executor no cell currently names, or it is")
        print("  unreachable because it is WRONG. Only reading tells them apart.")

    rec = {
        "_readme": ("Which never-executing branches an ARCHIVE mutation can reach. Reaching a "
                    "check is not validating it: this shows an input exists that runs the line "
                    "and that the executor refuses, not that the refusal is correct."),
        "targets": len(targets),
        "reached": len(reached),
        "reached_via_archive": sum(1 for v in reached.values() if v.get("kind") != "ledger"),
        "reached_via_ledger": sum(1 for v in reached.values() if v.get("kind") == "ledger"),
        "behind_the_validator": sum(1 for v in reached.values()
                                    if v.get("validator_would_catch_it_first")),
        "still_unreached": len(still),
        "attempts": attempted,
        "refusals": refused,
        "detail": {"%s:%d" % k: v for k, v in sorted(reached.items())},
        "unreached": {"%s:%d" % k: v for k, v in sorted(still.items())},
    }

    if "--verify" in sys.argv:
        if not OUT.exists():
            print("  " + D + " %s is absent; nothing to verify against." % OUT.name)
            return 1
        old = json.loads(OUT.read_text(encoding="utf-8"))
        drift = [k for k in ("targets", "reached", "still_unreached") if old.get(k) != rec[k]]
        if drift:
            print("  " + D + " the record disagrees on: %s" % ", ".join(drift))
            return 1
        print("  ok  the record matches this run.")
        return 0

    OUT.write_text(json.dumps(rec, indent=2) + NL, encoding="utf-8")
    print("  wrote %s" % OUT.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
