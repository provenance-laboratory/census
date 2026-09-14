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
import control_identity as _CI
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


def source_fingerprint():
    """A digest of the module set this measurement was taken against.

    ⛔ TWO RECORDS WERE INTERSECTED AND THEY HAD BEEN MEASURED AGAINST DIFFERENT TREES.
    CONTROL-AUDIT.json was re-run; REACH-CONTROLS.json was not; the code between them moved. 28 of
    the 70 unreached records then pointed at a line holding different source -- typically the `if`
    one line above -- and that line drift MANUFACTURED a disjointness the paper printed as a
    finding. On the basis that survives an edit the relation is unchanged: the reach set is
    contained in the audit's, exactly as a round-17 reviewer said.

    ⇒ So a figure derived by intersecting two records must refuse when the records disagree about
    the tree. Each carries this fingerprint; the builder compares them.

    ⚠ It fingerprints the MODULE SET AND ITS CONTENTS -- not a timestamp, which would go stale
    for reasons that are not about the code, and not a commit, which a dirty tree makes a lie.
    """
    import hashlib as _h
    parts = []
    for f in sorted(pathlib.Path(__file__).resolve().parent.glob("*.py")):
        parts.append(f.name)
        parts.append(_h.sha256(f.read_bytes()).hexdigest())
    return _h.sha256(("|".join(parts)).encode("utf-8")).hexdigest()[:16]


def never_executed():
    """The unreached branches, read from the audit rather than listed here.

    ⛔ KEYED BY LINE NUMBER, THIS RECORD DIED THE MOMENT replay.py WAS EDITED. Adding a
    control shifted every line below it and 21 of 23 recorded branches silently stopped matching --
    the tool reported them unreached when they were merely renumbered. A LINE NUMBER IS A PROXY
    FOR A CONTROL, which is the defect this same file already fixed once inside quick mode, here
    again one level out in the record it reads. The line is resolved through the SOURCE TEXT the
    audit stored, so an edit above a control no longer invalidates it.
    """
    # ⚠️ AND THE SET THIS CHASES GOT SMALLER, SO THE SET IT DROPS IS PRINTED. A round-9
    # reviewer separated *the suite entered this file and the line did not run* from *the suite
    # never entered the file*, and only the first is a control this tool can build an input for.
    # Narrowing silently would have moved a number in the paper for a reason no reader could see,
    # so the second population is reported here rather than simply not appearing.
    a = json.loads(AUDIT.read_text(encoding="utf-8"))
    _uncollected = [s for s in a.get("survivors", []) if s.get("class") == "NOT COLLECTED"]
    if _uncollected:
        _files = sorted({s["file"] for s in _uncollected})
        print("  %s %d control(s) in %d file(s) are NOT COLLECTED -- this suite never enters "
              "them, so they are not chased here and not counted as unreached either: %s"
              % (chr(0x26A0), len(_uncollected), len(_files),
                 ", ".join(_files[:4]) + ("..." if len(_files) > 4 else "")))
    src_cache = {}
    out = {}
    for s in a.get("survivors", []):
        if s.get("class") != "NEVER EXECUTES":
            continue
        f, want = s["file"], (s.get("source") or "").strip()
        if f not in src_cache:
            fp = HERE / f
            src_cache[f] = fp.read_text(encoding="utf-8").splitlines() if fp.exists() else []
        lines = src_cache[f]
        ln = int(s["line"])
        if not (1 <= ln <= len(lines) and lines[ln - 1].strip() == want):
            hits = [i + 1 for i, L in enumerate(lines) if L.strip() == want]
            ln = hits[0] if len(hits) == 1 else ln
        out[(f, ln)] = want
    return out


class Tracer:
    """Record every (file, line) executed. The only honest way to know a branch ran.

    ⛔⛔ THIS DESTROYED THE AUDIT'S TRACER, AND THAT CHANGED A PUBLISHED NUMBER. `__enter__`
    called `sys.settrace(self._t)` without reading `sys.gettrace()`, and `__exit__` called
    `sys.settrace(None)`. `sys.settrace` admits exactly ONE tracer and has no notion of
    composition, so when `control_audit.py` ran this tool as item 9 of the declared suite:

        the audit installed its tracer once; the FIRST mutation displaced it; the first `__exit__`
        set it to None; and across the remaining 70-odd calls it was never reinstated.

    Measured: an outer tracer saw **0 of the 26 recorded branches** execute during `--quick`,
    while every one of them demonstrably ran. The audit therefore classified 21 of them as
    NEVER EXECUTES -- and the build, unable to reconcile that with the reach record, had its
    convergence criterion weakened from equality to a subset relation to accommodate the gap.
    **The gap was this function.** The alarm was true and the criterion was the thing changed.

    ⚠️ IT IS THE SAME DEFECT AS THE `sys.stdout` REBINDING, in this same file's neighbourhood
    and in the same round: a module reconfiguring a process-global on behalf of whoever called it.
    That one broke a print. This one moved a number in a manuscript.

    ⇒ Keep what we displaced, forward every event to it, and put it back. A tracer that must
    survive being nested inside another either chains, as here, or uses `sys.monitoring`, which
    admits several under distinct tool ids and is the right instrument if this ever needs more
    than one level.
    """

    def __init__(self):
        self.seen = set()
        self._outer = None

    def __enter__(self):
        self._outer = sys.gettrace()
        sys.settrace(self._t)
        return self

    def __exit__(self, *a):
        sys.settrace(self._outer)
        self._outer = None

    # ⛔⛔ ROUND 8 FORWARDED THE EVENT AND THREW AWAY THE ANSWER, AND THAT IS STILL BLINDING.
    # The comment three lines down said it -- *its answer about which frames interest it is its
    # own; filtering on our behalf is how it went blind* -- and the code committed exactly that
    # one line later, with `return None`.
    #
    # `sys.settrace`'s GLOBAL function is called on `call`, and ITS RETURN VALUE BECOMES THAT
    # FRAME'S LOCAL TRACER. Returning None means no line events are delivered for the frame -- to
    # ANYONE, including the tracer we just handed the call event to. So round 8's chain passed the
    # outer tracer every `call` and then silenced every `line` inside it.
    #
    # Measured by a round-9 reviewer over a full 26-record replay:
    #
    #     audit tracer sees, shipped chain : 7969
    #     audit tracer sees, unfiltered    : 8347
    #     HIDDEN by the filtered return    :  378   (0 in the reverse direction)
    #
    # ⚠️ AND THE MEASUREMENT THAT CERTIFIED THE ROUND-8 FIX COULD NOT HAVE CAUGHT IT. "0 of 26
    # before, 26 of 26 after" was taken entirely inside this filter's own whitelist, so it got the
    # answer the filter guarantees. A control that can only look where it is already looking is
    # not a second reader.
    #
    # ⇒ HONOUR THE OUTER TRACER'S ANSWER. It returns the local tracer it wants for this frame;
    # we return one that serves both. We never decide on its behalf which frames matter.
    def _t(self, frame, event, arg):
        outer_local = self._outer(frame, event, arg) if self._outer is not None else None
        name = pathlib.Path(frame.f_code.co_filename).name
        mine = name in ("replay.py", "mp_metric.py")
        if mine:
            self.seen.add((name, frame.f_lineno))
        if outer_local is None and not mine:
            return None                       # neither of us wants this frame; nothing is hidden
        return self._local(outer_local)

    def _local(self, outer_local):
        """A frame-local tracer that records our lines AND keeps feeding the displaced one."""
        def local(frame, event, arg):
            nonlocal outer_local
            if outer_local is not None:
                nxt = outer_local(frame, event, arg)
                # A local tracer may return a different local tracer, or None to stop. Respect it,
                # but keep OUR recording alive either way -- our scope is not its scope.
                outer_local = nxt if nxt is not None else None
            name = pathlib.Path(frame.f_code.co_filename).name
            if name in ("replay.py", "mp_metric.py"):
                self.seen.add((name, frame.f_lineno))
            return local
        return local


def call_executor(fn, cell, ev, ctx):
    n = len(inspect.signature(fn).parameters)
    return fn(cell, ev, ctx) if n >= 3 else fn(cell, ev)


# ⛔ NOTE: quick mode no longer consults the line number at all. It was consulting BOTH the
# line and the message, and the line is the half that dies on any edit above the control -- twice
# in one session it reported live controls as lost. The message is the control's own output and
def apply_ledger_mutation(cell, label, led):
    """Apply ONE named ledger mutation to a cell and return (mutant, probe_ledger).

    ⛔ THE FULL SWEEP AND QUICK MODE EACH BUILT THIS THEMSELVES, and they disagreed: the sweep
    reached replay.py:1018 by 'as_of altered' and the replay of that exact record said it no
    longer did. Two implementations of one mutation is the same defect as the three proof parsers
    in the sibling project -- a repair to one cannot reach the other. One implementation, two
    callers.
    """
    blk = R._asserted(cell) or {}
    for lab, key, newval in ledger_mutations(blk):
        if lab != label:
            continue
        mutant = copy.deepcopy(cell)
        holder = mutant.get("bound") or mutant.get("check") or {}
        holder[key] = newval
        probe = copy.deepcopy(led)
        for i, c in enumerate(probe["cells"]):
            if c["subject"] == cell["subject"] and c["axis"] == cell["axis"]:
                probe["cells"][i] = mutant
        return mutant, probe
    return None, None


def _record(reached, targets, key, cell, method, mutation, kind=None, why=None, **extra):
    """The ONE place a reached branch is recorded.

    ⛔ FIVE CALL SITES BUILT THIS DICT AND ONLY SOME SET `source`, so entries written by the
    other paths could not be identified after an edit moved their line numbers -- and --verify
    reported them as no longer reached when they were reached, at a different line, by the same
    mutation. The fix for one wrong call site is not a sixth correct one.

    ⚠ `source` is the control's own text and is what identifies it across an edit; `says` is
    what it emitted and is what identifies it across a rewrite. A record with neither cannot be
    re-checked at all, and is refused rather than believed.
    """
    if key in reached:
        return
    # ⛔ `source` IS A PROXY FOR AN IDENTITY AND ROUND 6 BROKE IT WITHOUT TRYING. Two recorded
    # entries resolved to `return False, (` -- a bare continuation line occurring twice in the
    # same file -- so the record could not say which control it meant, in a healthy tree. Two
    # more resolved to statements that had been rewritten, and nothing could distinguish a
    # control REMOVED from a control MOVED.
    #
    # ⇒ The identity is an AST fact: module, enclosing qualname, node kind, a hash of the node's
    # shape with positions stripped, and which of the identically-shaped siblings it is. Edits
    # above a branch stop mattering. `source` is kept beside it as a human-readable label and is
    # no longer what resolution depends on.
    rec = {"cell": "%s/axis%d" % (cell["subject"], cell["axis"]) if cell else "-",
           "method": method, "mutation": mutation,
           "source": targets.get(key, ""),
           "identity": _CI.identify(HERE / key[0], key[1])}
    if kind:
        rec["kind"] = kind
    if why is not None:
        rec["says"] = str(why)[:90]
    rec.update(extra)
    reached[key] = rec


# the thing whose disappearance actually means something.


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
        # ⛔ THIS RETURNED TRUE FOR A RECORD WITH NO MESSAGE, so an entry written before
        # messages were recorded verified vacuously -- one of the 23 passed for no reason at all.
        # An unverifiable record is a re-measurement, not a pass.
        return False
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
    lost, unidentifiable, unverifiable, moved, uncomparable = [], [], [], [], []
    for where, info in sorted(detail.items()):
        f, ln = where.rsplit(":", 1)
        key = (f, int(ln))

        # ⛔ THIS REPLAYED A LINE NUMBER AND NEVER ASKED WHETHER IT STILL NAMES THAT STATEMENT.
        # The full sweep re-resolves every recorded branch by its stored SOURCE TEXT before
        # measuring -- it has to, because any edit above a branch moves it -- and quick mode,
        # which is the half that runs inside `control_audit.py`, did not. So after a code change
        # the recorded line named a different statement, the replay could not reach it, and the
        # watcher reported a control lost that was never touched. That failure is FATAL to the
        # audit and therefore to the build, so a false one blocks everything downstream of it.
        #
        # ⇒ Same resolution the sweep uses, and the two categories are kept apart: a branch this
        # cannot IDENTIFY is not a branch that stopped being reached, and saying otherwise sends
        # somebody looking for a control that is sitting where it always was.
        # RESOLUTION IS BY IDENTITY. An older record with no identity gets one computed from its
        # own recorded line, which is exactly as good as the old scheme and no worse -- but every
        # record written from here carries one.
        _ident = info.get("identity") or _CI.identify(HERE / f, key[1])
        if _ident is None:
            unidentifiable.append((where, "no statement at that line and no stored identity"))
            continue
        _line, _status = _CI.resolve(HERE / f, _ident, recorded_line=key[1])
        if _status == _CI.UNCOMPARABLE:
            uncomparable.append(
                (where, "recorded under %s; this interpreter renders %s"
                        % (_ident.get("canon") or "an unrecorded rendering", _CI._canon_tag())))
            continue
        if _status in (_CI.AMBIGUOUS, _CI.GONE):
            unidentifiable.append(
                (where, "%s: %s in %s" % (_status,
                                          "several identically-shaped statements and the sibling "
                                          "count changed" if _status == _CI.AMBIGUOUS
                                          else "no statement of this shape remains",
                                          _ident.get("qualname") or "(module)")))
            continue
        if _status == _CI.MOVED:
            moved.append((where, "%s:%d" % (f, _line)))
        key = (f, _line)

        # ⚠️ AND A BRANCH RECORDED WITH NO OUTPUT CANNOT BE REPLAYED BY MATCHING OUTPUT. Some
        # branches execute and say nothing; the sweep records `says: ""` for them, and
        # `_still_says` then has nothing to compare, so the replay fails every single time no
        # matter what the tree does. A check that can only fail is not a watcher.
        if not (info.get("says") or "").strip():
            unverifiable.append((where, "recorded with no distinguishing output"))
            continue
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
        elif info.get("kind") == "validator":
            # ⛔ QUICK MODE KNEW THREE OF THE FOUR KINDS. A validator-kind branch fell through to
            # the evidence-shape path, which cannot produce a validator complaint, so a branch the
            # full sweep reaches was reported lost every time. The sweep and the replay have to
            # cover the same axes or the replay is measuring a smaller thing and calling it the
            # same name.
            m2, probe = apply_ledger_mutation(cell, info.get("mutation"), led)
            if m2 is not None:
                _cs = []
                with Tracer() as tr:
                    try:
                        _cs = M.validate(probe) or []
                    except Exception:                                        # noqa: BLE001
                        pass
                if _still_says(info, "; ".join(str(x) for x in _cs)):
                    hit = True
            if not hit:
                lost.append((where, "validator mutation %r no longer reaches it"
                             % info.get("mutation")))
            continue
        elif info.get("kind") == "ledger":
            # a LEDGER mutation: rebuild it from the block's own keys and find the label again
            m2, _probe = apply_ledger_mutation(cell, info.get("mutation"), led)
            if m2 is not None:
                _w2 = None
                with Tracer() as tr:
                    try:
                        _o2, _w2 = call_executor(fn, m2, ev, ctx)
                    except Exception:                                        # noqa: BLE001
                        pass
                if _still_says(info, _w2):
                    hit = True
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
            if _still_says(info, _last_why):
                hit = True
                break
        if not hit:
            lost.append((where, "no longer reached by %r" % info.get("mutation")))

    print("  quick replay of %d recorded branch(es): %d replayed, %d unidentifiable, "
          "%d unverifiable" % (len(detail), len(detail) - len(unidentifiable) - len(unverifiable),
                               len(unidentifiable), len(unverifiable)))
    # ⚠️ A MOVE IS NOT A LOSS AND IS NOT SILENCE EITHER. Reporting it is how "the identity moved
    # and was uniquely recoverable" stays distinguishable from "nothing changed".
    for _w, _to in moved:
        print("      %s %-26s rebound to %s" % (W, _w, _to))
    # ⚠ NOT SILENT. Every branch this could not replay is named, because the count of branches a
    # watcher actually watches is the only honest measure of what it covers -- and skipping them
    # quietly is how a suite's coverage falls without its summary line moving.
    for _w, _why in unidentifiable + unverifiable:
        print("      %s %-28s %s" % (W, _w, _why))
    for where, why in uncomparable:
        print("      %s %-28s %s" % (W, where, why))
    for where, why in lost:
        print("  " + D + " %-18s %s" % (where, why))

    # ⛔⛔ DISPOSITION, NOT DETECTION, WAS THE DEFECT. `lost` returned 1; `unidentifiable` and
    # `unverifiable` printed and fell through to `ok  every recorded branch still executes.` A
    # round-7 reviewer ran this project's own test on it -- neuter a recorded control and ask
    # whether the watcher notices -- and got exit 0 four times out of four:
    #
    #     control deleted: return False, "the archived revision response is not JSON"
    #       replay.py:1271   gone: no statement of this shape remains in m_release_artifacts
    #       quick replay of 26 recorded branch(es): 25 replayed, 1 unidentifiable, 0 unverifiable
    #       ok  every recorded branch still executes.                              exit code: 0
    #
    # DELETING A CONTROL ALWAYS CHANGES ITS SHAPE, so deletion always resolves to `gone`, and
    # `gone` was routed to the bucket that prints and passes. The identity scheme was built to
    # stop false `lost` reports after code motion; it did, by converting the true positives into
    # the same disposition. The docstring still promised this mode FAILS if any recorded branch
    # stops being reached -- which is the whole of what makes it a watcher.
    #
    # ⚠️ AND THE VERDICT LINE WAS FALSE ON ITS OWN TERMS: it cannot have established that the
    # branches it skipped still execute. Naming them is not counting them.
    #
    # ⇒ Every disposition that is not a replay now returns 1, with the instruction the `lost`
    # path already carried. A legitimate rewrite costs one full sweep, which is the correct price;
    # an instruction that does not block is an instruction nobody reads.
    _blocking = [("no longer reached", lost), ("unidentifiable", unidentifiable),
                 ("unverifiable", unverifiable), ("not comparable", uncomparable)]
    _n = sum(len(v) for _k, v in _blocking)
    if _n:
        print()
        for _kind, _rows in _blocking:
            if _rows:
                print("  " + D + " %d %s" % (len(_rows), _kind))
        print("  " + D + " %d of %d recorded branch(es) were not replayed against their own "
              "output." % (_n, len(detail)))
        print("  A control was removed, an executor changed shape, an identity could not be "
              "resolved,")
        print("  or the record was rendered by another interpreter. Re-run the full sweep to "
              "re-measure.")
        return 1
    print("  ok  all %d recorded branch(es) were replayed and still execute." % len(detail))
    return 0


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace",
                                  line_buffering=True)
    targets = never_executed()
    _pinned_targets = None
    if OUT.exists():
        try:
            _pinned_targets = json.loads(OUT.read_text(encoding="utf-8")).get("targets_pinned")
        except Exception:                                                    # noqa: BLE001
            _pinned_targets = None
    # ⛔ A SWEEP THAT ONLY TARGETS WHAT IS STILL UNREACHED CANNOT RE-VERIFY WHAT IT
    # ALREADY FIXED. Branches this tool makes reachable leave the audit's never-executing list, so
    # they stopped being targets and their records could never be refreshed -- one of them held no
    # message at all and was passing quick mode vacuously, with nothing able to re-measure it. The
    # sweep targets the residue AND everything it has previously claimed.
    # ⛔ REMEMBERED ENTRIES WERE RE-ADDED BY THEIR OLD NUMERIC LINE, WITHOUT CHECKING THAT THE
    # LINE STILL HELD THAT STATEMENT. A round-22 reviewer compared all 44 entries against the
    # controls the detector actually finds: 22 matched, 3 carried no stored source at all, 2
    # pointed at a DIFFERENT current control, and 17 were not a control line in any sense --
    # `mp_metric.py:112` recorded as reached with source `return True`, `replay.py:386` now
    # reading `if b is None:`. Whatever moved onto the line was rediscovered under the old
    # identity, `--verify` compared the record with itself and reported "the record matches this
    # run", and the convergence gate passed because it compares only the never/unreached COUNTS
    # and never validates the reached set at all. 130 equalled 130 while a third of the reached
    # branches were fictional.
    #
    # ⚠ A LINE NUMBER IS A PROXY FOR A CONTROL -- the same sentence this file already carries
    # twice, once for quick mode and once for the regression set, now a third time one level out
    # in the memory that feeds them both. Each remembered entry must now resolve BY ITS STORED
    # SOURCE TEXT to a line the detector currently calls a control. Anything that cannot is
    # DROPPED and named, never carried forward on a number.
    _lost_identity = []
    if OUT.exists():
        try:
            import control_audit as _CA
            _ctl_cache = {}

            def _is_control(fname, line_no):
                if fname not in _ctl_cache:
                    try:
                        _src = (HERE / fname).read_text(encoding="utf-8")
                        _ctl_cache[fname] = {lo for lo, _k, _s in _CA.controls(_src, fname)}
                    except Exception:                                        # noqa: BLE001
                        _ctl_cache[fname] = set()
                return line_no in _ctl_cache[fname]

            for k, v in (json.loads(OUT.read_text(encoding="utf-8")).get("detail") or {}).items():
                f, _ln = k.rsplit(":", 1)
                ln = int(_ln)
                want = (v.get("source") or "").strip()
                if not want:
                    _lost_identity.append((k, "carries no stored source text, so it cannot be "
                                              "identified in this tree at all"))
                    continue
                try:
                    lines = (HERE / f).read_text(encoding="utf-8").splitlines()
                except OSError:
                    _lost_identity.append((k, "its file is gone"))
                    continue
                if 1 <= ln <= len(lines) and lines[ln - 1].strip() == want:
                    here = ln
                else:
                    hits = [i + 1 for i, L in enumerate(lines) if L.strip() == want]
                    if len(hits) != 1:
                        _lost_identity.append(
                            (k, "its statement is %s in this tree, so the recorded line names "
                                "something else" % ("ambiguous (%d matches)" % len(hits)
                                                    if hits else "gone")))
                        continue
                    here = hits[0]
                if not _is_control(f, here):
                    _lost_identity.append((k, "resolves to %s:%d, which the detector does not "
                                              "classify as a control" % (f, here)))
                    continue
                targets.setdefault((f, here), want)
        except Exception:                                                    # noqa: BLE001
            pass
    if _lost_identity:
        print()
        print("  " + W + " %d remembered entr(ies) DROPPED -- they cannot be identified as "
              "controls in this tree:" % len(_lost_identity))
        for _k, _why in _lost_identity[:8]:
            print("      %-28s %s" % (_k, _why))
        print("  They are not counted as reached. A reached count that includes statements the")
        print("  detector does not call controls is not a measurement of control coverage.")
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
    # ⛔ THIS LABELLED A MIXED POPULATION AS THE AUDIT'S. `targets` is the audit's current
    # never-executing set PLUS every branch this record already claims -- a regression-replay set,
    # constructed so previously-fixed branches keep being re-measured. Calling it "what the audit
    # reports as unreachable" made the paper quote 92, which is neither the pinned baseline (85)
    # nor the audit's current answer (76). Three populations, one name.
    _audit_now = len(never_executed())
    print("  %d branch(es) the control audit currently reports as never executing." % _audit_now)
    print("  %d in the REGRESSION SET: that, plus every branch this record already claims, so a"
          % len(targets))
    print("  branch once made reachable keeps being re-measured instead of dropping out of view.")
    print("  %s is the PINNED BASELINE -- the population first measured against, and the"
          % (_pinned_targets if "_pinned_targets" in dir() else "?"))
    print("  denominator to quote for a before/after.")
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
                        _record(reached, targets, key, cell, meth, label,
                                why=_why, evidence_index=idx, refused=ok is False)

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
                    _record(reached, targets, key2, cell, meth, label, kind="ledger",
                            why=_why,
                            validator_would_catch_it_first=bool(validator_catches))

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
                    _record(reached, targets, key, cell, meth, label,
                            kind="evidence-shape", why=_why, refused=ok is False)

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
            _complaints = []
            with Tracer() as tr:
                try:
                    _complaints = M.validate(probe) or []
                except Exception:                                            # noqa: BLE001
                    pass
            # ⛔ THIS RECORDED THE LITERAL STRING "validator complaint" as the message, so quick
            # mode had nothing to compare and fell back to the line number -- and deleting the
            # control left the line executing as `pass`, so the positive control MISSED. The
            # complaint itself is the control's output and is what identifies it.
            _vsay = "; ".join(str(x) for x in _complaints)[:90]
            for key2 in targets:
                if key2 in tr.seen and key2 not in reached:
                    _record(reached, targets, key2, cell, (block or {}).get("method"), label,
                            kind="validator", why=_vsay)

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
                    _record(reached, targets, key2, cell, newmeth, label, kind="gate",
                            why="gate refusal")

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
    # ⛔ THIS QUANTITY WAS COMPUTED TWICE, ELEVEN LINES APART, WITH TWO DIFFERENT PREDICATES.
    # The console used `kind in (None, "archive")` and printed 15. The record used
    # `kind != "ledger"` and deposited 23, because that predicate sweeps the 7 evidence-shape
    # branches and the 1 validator branch into "archive" on the sole ground that neither is
    # literally labelled "ledger". The manuscript then printed 23 as "reached by corrupting the
    # archive alone ... not only by a hand-built ledger" -- a sentence that was false of eight of
    # the branches it counted, since evidence-shape mutates the CELL'S EVIDENCE LIST in the ledger
    # and never touches the byte seam, and the validator branch is reached by altering `as_of`,
    # a ledger field. `--verify` could not catch it: it re-derives the record from the same
    # function and gets the same 23.
    #
    # ⇒ ONE classification, computed once, consumed by both the console and the record. Two
    # implementations of one number is how they drift apart -- which this file already says about
    # `targets` and says again here because saying it did not prevent it.
    #
    # The axis is named, never inferred from what a kind is NOT. `archive` is the only axis that
    # corrupts bytes, so it is the only one that may be called archive-reachable.
    _kinds = _c.Counter(v.get("kind") or "archive" for v in reached.values())
    print("  reached by axis: %s" % dict(_kinds))
    _arch = _kinds["archive"]
    _ledg = [v for v in reached.values() if (v.get("kind") or "archive") != "archive"]
    _behind = sum(1 for v in _ledg if v.get("validator_would_catch_it_first"))
    print("  %d of %d unreached branch(es) are now reached." % (len(reached), len(targets)))
    print("    %d by corrupting the ARCHIVE -- reachable in production" % _arch)
    print("    %d by altering the RECORD, of which %d the validator refuses first"
          % (len(_ledg), _behind))
    for _k in sorted(k for k in _kinds if k != "archive"):
        print("        %2d %s" % (_kinds[_k], _k))
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

    # ⛔ THE RECORD MUST BE CUMULATIVE OR IT ERASES ITS OWN WORK. A branch this tool
    # reaches leaves the audit's never-executing list on the next audit -- which is the point --
    # and the next full run therefore no longer sees it as a target. Replacing  each run
    # dropped every branch the tool had already made reachable, so quick mode had nothing to
    # replay and those controls became unwatched again. The tool would have undone itself, on a
    # schedule, silently.
    _prev = {}
    if OUT.exists():
        try:
            _prev = (json.loads(OUT.read_text(encoding="utf-8")).get("detail") or {})
        except Exception:                                                    # noqa: BLE001
            _prev = {}
    # ⛔ THE MERGE WAS MADE CUMULATIVE TO STOP THE TOOL ERASING ITS OWN WORK, and that turned
    # the record into one that can only grow. Four branches stopped being reachable this round for
    # a real reason -- the new entry-count guard fires EARLIER in the same guard sequence, so
    # mutations that used to reach "a response carries no totalResults" are now deflected before
    # it -- and a union kept claiming them. **A record that only accumulates cannot be falsified**,
    # which is the property this whole project exists to refuse.
    #
    # ⚠ The reason for the merge is gone anyway: targets now include everything the record
    # claims, so a still-reachable branch is re-measured every run and survives on its own merits.
    # An entry that is targeted and NOT reached is dropped, and named.
    _dropped = sorted(k for k in _prev if k not in {"%s:%d" % kk for kk in reached})
    _merged = {"%s:%d" % k: v for k, v in sorted(reached.items())}
    if _dropped:
        print()
        print("  " + W + " %d branch(es) this record claimed are NO LONGER REACHED and have been"
              % len(_dropped))
        print("  dropped rather than carried forward:")
        for _k in _dropped[:6]:
            print("      %-18s %s" % (_k, (_prev[_k].get("says") or "")[:52]))
        print("  A guard added earlier in the same sequence deflects the mutation that used to")
        print("  reach these. That is a real change in what is reachable, not bookkeeping.")

    # ⛔ THE DENOMINATOR CAME FROM A FILE THIS TOOL'S OWN PRESENCE REWRITES. `targets` was read
    # live from CONTROL-AUDIT.json, and once this tool joined the suite the audit recorded the
    # POST-repair state -- so a reader running the documented command from the deposit got
    # "0 of 23 reached" against a record saying 54 and 23, and --verify refused. The mutation
    # machinery was identical to the recorded run down to the attempt count; only the input had
    # moved. The paper names this hazard in the same section and the code still had it.
    #
    # ⚠ So the ORIGINAL target population is pinned on first write and reused. It is the
    # denominator the measurement was made against, and re-deriving it from a file this tool
    # changes is how a before-figure quietly becomes an after-figure.
    if OUT.exists():
        try:
            _pinned_targets = json.loads(OUT.read_text(encoding="utf-8")).get("targets_pinned")
        except Exception:                                                    # noqa: BLE001
            _pinned_targets = None
    if _pinned_targets is None:
        _pinned_targets = len(targets)

    rec = {
        "_readme": ("Which never-executing branches an ARCHIVE mutation can reach. Reaching a "
                    "check is not validating it: this shows an input exists that runs the line "
                    "and that the executor refuses, not that the refusal is correct."),
        "targets": len(targets),
        "source_fingerprint": source_fingerprint(),
        "targets_pinned": _pinned_targets,
        "_targets_note": (
            "targets_pinned is the population this measurement was FIRST made against. `targets` "
            "is what the audit reports today, which this tool changes by being in the suite -- so "
            "the two differ by design and the pinned one is the denominator to quote."),
        "reached": len(reached),
        # These are the SAME objects the console printed, not a second computation of them.
        "reached_via_archive": _arch,
        "reached_via_ledger": len(_ledg),
        "reached_by_axis": dict(_kinds),
        "_axis_note": (
            "reached_via_archive counts ONLY the `archive` axis -- the one that corrupts bytes. "
            "It was previously computed as `kind != 'ledger'`, which counted the evidence-shape "
            "and validator branches as archive-reachable and published 23 where the honest "
            "figure is %d. evidence-shape rewrites the cell's evidence LIST in the ledger and "
            "never patches the byte seam; the validator branch is reached by altering `as_of`, "
            "a ledger field. reached_by_axis is the full breakdown so no reader has to trust "
            "either total." % _arch),
        "behind_the_validator": sum(1 for v in reached.values()
                                    if v.get("validator_would_catch_it_first")),
        "still_unreached": len(still),
        "attempts": attempted,
        "refusals": refused,
        "detail": _merged,
        "reached_this_run": len(reached),
        "reached_cumulative": len(_merged),
        "unreached": {"%s:%d" % k: v for k, v in sorted(still.items())},
    }

    if "--verify" in sys.argv:
        if not OUT.exists():
            print("  " + D + " %s is absent; nothing to verify against." % OUT.name)
            return 1
        old = json.loads(OUT.read_text(encoding="utf-8"))
        # ⚠ `targets` is EXPECTED to move -- this tool changes it by running. Comparing it
        # made --verify refuse on a healthy tree, which is a control that cries wolf. The pinned
        # denominator and the cumulative reached set are what must not drift.
        # ⛔ THIS COMPARED `reached_cumulative`, AN INTEGER PRODUCED BY MERGING the stored record
        # with the current run -- so its value depends on how the merge behaves, not on whether
        # anything is still true. Run from a clean extraction it disagreed (22 against 23) while
        # every recorded branch was in fact still reached, which is a control failing for a reason
        # unrelated to its claim. A round-17 reviewer predicted this precise shape: "the finding
        # most likely to have a subtle repair that looks right and isn't."
        #
        # ⚠ What must hold is: the population this was measured against has not moved, and every
        # branch the record CLAIMS is reachable still executes and still says what it said. Both
        # are properties of the world, not of an update rule.
        drift = []
        if old.get("targets_pinned") is not None                 and old.get("targets_pinned") != rec.get("targets_pinned"):
            drift.append("targets_pinned (%s -> %s)"
                         % (old.get("targets_pinned"), rec.get("targets_pinned")))
        # ⛔ AND COMPARING THESE BY LINE NUMBER WAS THE SAME DEFECT A THIRD TIME. Editing
        # `replay.py` moved every control below the edit, so five branches that ARE reached --
        # at new line numbers, by the same mutation, emitting the same message -- were reported
        # lost. A line number is a proxy for a control; the control's own source text is not.
        def _ident(entry, key):
            # ⚠ SOURCE FIRST, THEN THE MESSAGE. The control's own text survives a line
            # move; its emitted message survives a line move too and only fails if the message is
            # rewritten. Records written before  existed still carry , so they stay
            # checkable instead of being refused wholesale -- a record that CAN be identified by a
            # weaker key is not the same as one that cannot be identified at all.
            e = entry or {}
            f = key.rsplit(":", 1)[0]
            return (f, e.get("source") or e.get("says") or "")

        _claimed = {_ident(v, k) for k, v in (old.get("detail") or {}).items()}
        _now = {(f, (reached[(f, ln)].get("source") or targets.get((f, ln))
                     or reached[(f, ln)].get("says") or ""))
                for (f, ln) in reached}
        _now |= {(f, reached[(f, ln)].get("says") or "") for (f, ln) in reached}
        _lost = sorted(a for a in _claimed - _now if a[1])
        _unident = sorted(a for a in _claimed - _now if not a[1])
        if _lost:
            drift.append("%d recorded control(s) not reached this run: %s"
                         % (len(_lost), [x[1][:44] for x in _lost[:3]]))
        if _unident:
            drift.append("%d recorded entr(ies) carry no source text and cannot be identified "
                         "across an edit: %s" % (len(_unident), [x[0] for x in _unident[:3]]))
        if drift:
            print("  " + D + " the record disagrees on: %s" % "; ".join(drift))
            return 1
        print("  ok  the record matches this run.")
        return 0

    # ⛔ THE PARTITION MUST BE A PARTITION. The published 23-vs-15 defect was two predicates for
    # one quantity, and it survived because nothing ever asked whether the parts added up. They
    # now come from one Counter, so they cannot drift -- but the next edit can reintroduce a
    # second predicate exactly as the last one did, and this is what would notice.
    _sum_axes = sum(rec["reached_by_axis"].values())
    if _sum_axes != rec["reached"]:
        raise SystemExit(D + " the per-axis counts sum to %d but %d branches were reached. The "
                         "axis breakdown is not a partition of the reached set."
                         % (_sum_axes, rec["reached"]))
    if rec["reached_via_archive"] + rec["reached_via_ledger"] != rec["reached"]:
        raise SystemExit(D + " archive (%d) + record (%d) != reached (%d). Some branch is being "
                         "counted twice or not at all -- which is precisely how 15 was published "
                         "as 23." % (rec["reached_via_archive"], rec["reached_via_ledger"],
                                     rec["reached"]))
    if rec["reached_via_archive"] != rec["reached_by_axis"].get("archive", 0):
        raise SystemExit(D + " reached_via_archive (%d) disagrees with the `archive` axis (%d). "
                         "Only the archive axis corrupts bytes; nothing else may be counted as "
                         "archive-reachable."
                         % (rec["reached_via_archive"], rec["reached_by_axis"].get("archive", 0)))

    OUT.write_text(json.dumps(rec, indent=2) + NL, encoding="utf-8", newline="\n")
    print("  wrote %s" % OUT.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
