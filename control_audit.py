"""Which of this project's controls has anyone ever watched FAIL?

⛔ THE QUESTION THIS ANSWERS. Every round of review has added checks, and each was added because a
specific attack got through. But a check is only evidence of anything if it can fire, and this
project has now shipped three controls that could not:

  * a `--selftest` attack that never ran and reported "correctly rejected" (a broad except),
  * a workflow-block guard that raised NameError on every invocation for a day,
  * a `validate()` truncated by a stray top-level def, which printed "no defects" while missing
    its entire tail.

Each was found by accident. None would have been found by reading, because reading a control tells
you what it INTENDS. So: disable each control in turn and see whether anything notices.

    a control whose removal breaks NO test is a control nobody has watched fail,
    and is indistinguishable from a comment

⚠️ WHAT COUNTS AS A CONTROL. Not every `return False` -- the ones that report a DEFECT: appending
to a defect list, returning a rejection from an executor, or refusing to build. They are found by
walking the AST rather than by grepping for a list of known ones, because a list of controls to
audit has exactly the failure mode the audit is looking for.

⚠️ WHAT A SURVIVOR MEANS. Not necessarily a bug. A control may be unreachable given the current
ledger, may be redundant with an earlier one that fires first, or may guard a state no fixture
produces. Those are three different findings and this tool cannot tell them apart -- it says which
lines nothing is watching, and a human reads them. Reporting it as "N bugs" would be the same
overstatement the census keeps correcting elsewhere.

    python control_audit.py            audit every control
    python control_audit.py --quick    mp_metric.py only
"""
import ast
import re
import datetime
import io
import json
import pathlib
import shutil
import subprocess
import threading
import sys
import time

NL = chr(10)
# ⛔ EVERY WORK TREE WAS A FULL COPY INCLUDING `.git`, AND GIT'S LOOSE OBJECTS ARE READ-ONLY
# (mode 100444), which is why Windows refused to delete them and why 362 of these accumulated.
# The silent `ignore_errors=True` hid it; making the removal report turned an invisible leak into
# a visible one; this is the cure. `.git` is 11.4 MB of an 18.8 MB tree -- 61 per cent -- and no
# mutation harness in this directory reads a single byte of it.
#
# ⚠ IT IS ALSO 61 PER CENT OF THE COPY COST, PAID ONCE PER MUTATION. The audit copies this tree
# for each of its several hundred control sites, so the excluded bytes are the same bytes that
# made the audit slow enough to be worth skipping -- which is the failure mode the paper is about.
_SKIP = __import__("shutil").ignore_patterns(".git", "__pycache__", "*.pyc")

HERE = pathlib.Path(__file__).resolve().parent
# ⛔ D AND W WERE NEVER DEFINED AT MODULE LEVEL, and three error paths in main()
# referenced them -- including the audit's own "the control count fell" warning and both
# --verify refusals. Each would have raised NameError instead of reporting the thing it exists
# to report: a control that crashes on its own failure path, which is precisely the defect a
# round-7 reviewer found in anchor_status.py in the sibling project.
D = chr(0x26D4)
W = chr(0x26A0)
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


def inputs_fingerprint():
    """Every input that can change a control's CLASSIFICATION -- code and data alike.

    ⛔ `source_fingerprint()` HASHES *.py AND THE STALE INPUT WAS JSON. `reach_controls.py
    --quick` is item 8 of this suite: once REACH-CONTROLS.json names a branch, deleting that
    branch's control makes the suite red, so the control is WATCHED. The audit had been measured
    BEFORE the reach record named them, and 17 sites were simultaneously classified NEVER EXECUTES
    here and REACHED there. Both records honestly carried the same fingerprint, both matched the
    tree, and the guard passed -- round 20's defect with DATA in the role code played.

    ⇒ The two records are mutually dependent: the reach tool reads this audit to learn what never
    executes, and this audit runs that tool as part of the suite it measures with. That is a
    FIXPOINT, and running each once in order does not reach it.

    ⚠ The fingerprint covers every .py and every .json except the record being written, so a
    reach record produced after this audit makes this audit's fingerprint stale and the build
    refuses. The loop is forced by the guard rather than remembered by a person.
    """
    import hashlib as _h
    parts = []
    for f in audit_inputs():
        parts.append(f.name)
        parts.append(_h.sha256(f.read_bytes()).hexdigest())
    return _h.sha256(("|".join(parts)).encode("utf-8")).hexdigest()[:16]


# ⛔ THE FINGERPRINT PROJECTED OVER TWO FILE EXTENSIONS AND BOTH REVIEWERS BROKE IT, from
# opposite directions in the same round.
#
#   -- It SWEPT IN a file that is not an input. `COMMIT.json` is written by build_deposit.py
#      AFTER the audit record is copied, so a correctly produced deposit could never satisfy
#      this gate: the archive failed at its own first documented command, and both reviewers
#      hit it in a pristine extraction.
#   -- It MISSED a file that is an input. `AUDIT-ROUND` has no extension, so neither this
#      fingerprint nor the deposit's completeness check could see it; the deposit shipped
#      without it and `control_audit.py --verify` refuses in a clean extraction.
#
# ⚠ THE RULE IS NOW "EVERY FILE IN THE WINDOW IS AN INPUT UNLESS IT IS A DECLARED OUTPUT",
# which fails closed: a new file of any name or extension moves the fingerprint and forces a
# re-run, rather than being silently ignored because nobody added its suffix to a list. That
# is the projection this directory has now had to learn thirteen times, and it is the FIRST
# time the default has been "include" rather than "match one of these shapes".
#
# The two declared exclusions are named with the reason each is not an input:
_AUDIT_OWN_RECORD = ("CONTROL-AUDIT.json",)   # what this run writes; hashing it is circular
# ⛔ THIS NAMED ONE FILE AND THE DEPOSIT GENERATES THREE. `history.bundle` and
# `VERIFY-PREREGISTRATION.md` are created by build_deposit.py and exist only inside an
# extraction, so a clean extraction contained two inputs the audit had never seen and the
# manifest check refused a correct archive. Listing them here would be the enumeration defect
# for the fourteenth time -- a hand-kept list of somebody else's outputs, in the file that
# cannot see them being created.
#
# ⇒ THE GENERATOR DECLARES ITS OWN OUTPUTS. build_deposit.py writes the names it generated
# into DEPOSIT-GENERATED.json beside them, and this reads that when it is present. In the
# author's tree the file does not exist and the tuple below is the whole answer; inside an
# extraction it is the generator's own statement of what it made. Nobody maintains a list of
# another tool's outputs by hand.
_WRITTEN_AFTER_THE_AUDIT = ("COMMIT.json", "DEPOSIT-GENERATED.json")


def _deposit_generated():
    """Names build_deposit.py declares it created, or () in a tree that has no deposit."""
    _f = HERE / "DEPOSIT-GENERATED.json"
    if not _f.exists():
        return ()
    try:
        return tuple(json.loads(_f.read_text(encoding="utf-8")).get("generated") or ())
    except (OSError, ValueError):
        # ⚠ Fails CLOSED: an unreadable declaration excludes nothing, so an unexplained file
        # still refuses rather than being quietly dropped from the measurement.
        return ()
_NEVER_CONTENT = ("__pycache__", ".git", ".pytest_cache")


def inputs_manifest():
    """Every audit input, name to digest. Not one hash over all of them.

    ⛔ A SINGLE FINGERPRINT OVER A DIRECTORY SCAN CANNOT SURVIVE DISTRIBUTION, and a reviewer
    predicted this before it was observed: the deposit is deliberately a SUBSET of the working
    tree -- no `.log` transcripts, no `.git` -- so the scan produces a different value there
    even when nothing is stale and every shipped byte is identical. The archive failed at its
    own first documented command for that reason, and would have kept failing however carefully
    it was rebuilt.

    ⛔ THE DEEPER FAULT IS THAT ONE OPAQUE NUMBER ANSWERS TWO DIFFERENT QUESTIONS. "Did a file
    the audit read change?" and "is this the same collection of files?" are not the same
    question, and a single hash collapses them into one verdict that cannot say which failed.
    Round 22 widened that hash to fix a stale-record defect; widening it made the distribution
    case worse, because the wider the scan the more a subset differs.

    ⇒ A manifest answers both separately. A file present in both and DIFFERING is staleness and
    the build must refuse. A file present here and absent there is a subset, which is what a
    replication package is. A file present there and absent from the record is something the
    audit never saw, which must also refuse.
    """
    import hashlib as _h
    return {f.name: _h.sha256(f.read_bytes()).hexdigest() for f in audit_inputs()}


def audit_inputs():
    """Every file whose bytes can change a control's classification. One declaration.

    ⚠ `build_deposit.py` calls this too, so the set the fingerprint covers and the set the
    archive must contain cannot drift apart. They drifted this round and the archive did not
    build.
    """
    out = []
    for f in sorted(HERE.iterdir()):
        if not f.is_file():
            continue
        if f.name in _AUDIT_OWN_RECORD or f.name in _WRITTEN_AFTER_THE_AUDIT:
            continue
        if f.name in _deposit_generated():
            continue
        if any(part in f.parts for part in _NEVER_CONTENT):
            continue
        if f.suffix in (".pyc", ".pyo"):
            continue
        out.append(f)
    return out


def _targets():
    """Every module in this directory, PROJECTED -- not four names.

    ⛔ THIS WAS A FOUR-NAME TUPLE AND TWO OF THE FOUR CONTRIBUTE NOTHING, so "173 control
    sites" was mp_metric.py plus replay.py and the docstring said "audit every control". A
    round-16 reviewer applied this file's OWN detector to the whole directory and found 206.
    The 33 outside the window included every file involved in that round's two live findings.

    ⚠ The tool warns at the top of this file that a hand-kept list of controls would
    reproduce the enumeration defect it exists to audit. It then kept a hand-kept list of
    FILES, which is the same defect one level out.
    """
    return tuple(sorted(f.name for f in HERE.glob("*.py")))


TARGETS = _targets()

# The suite that must notice. Deliberately the FAST ones: sweep.py takes ten minutes and its
# verdict is already implied by validate() refusing the mutation.
SUITE = (
    (["mp_metric.py"], "validate"),
    (["replay.py"], "replay"),
    (["replay.py", "--selftest"], "selftest"),
    (["stress_test.py"], "stress"),
    (["check_facts.py"], "facts"),
    (["test_executors.py"], "executors"),
    (["test_bound_rules.py"], "bounds"),
    # ⛔ THE SUITE ATTACKED THE LEDGER AND NEVER THE ARCHIVE. 54 controls reported as
    # never-executing were almost all INSIDE executors, defending against corrupted evidence
    # bytes -- and every mutation this project made was to the ledger, which the validator
    # refuses first. reach_controls.py mutates the evidence store through the one seam every
    # executor reads bytes through, and traces which branches actually run.
    (["reach_controls.py", "--quick"], "reach"),
)


# ⛔ FIVE ACCUMULATOR NAMES, HAND-KEPT. `findings.append` in recheck.py -- carrying "digest
# moved" and "unretrievable" -- `failed.append` in pin_urls.py, `lost.append` in reach_controls.py
# and `unread.append` in test_executors.py are all defect reports, and all were outside the list,
# so the registry could not see them. That is the enumeration defect inside the tool that exists
# to audit for it, in the branch beside the one already repaired for the same reason.
#
# ⚠ Still a list, and saying otherwise would be the overclaim: what is fixed is its coverage,
# not its kind. A semantic test -- "an accumulator a control appends a complaint to" -- is the
# right shape and is not what this is.
_ACCUMULATORS = ("d", "bad", "trunc", "unadj", "drift", "findings", "failed", "lost", "unread",
                 "problems", "defects", "missing", "errors", "complaints", "short", "dead",
                 "stale", "wrong", "leftover")


def _can_return_nonzero(value):
    """Could this return expression produce a non-zero exit status?

    ⛔ THE RULE STILL REQUIRED A LITERAL. `return 1` was counted and `return 1 if bad else 0` was
    invisible -- the exact spelling a round-20 reviewer named, and it is live in six modules
    including `test_executors.py`, which is one of the eight tools in the audit's own SUITE. That
    module scored ZERO control sites while being part of the instrument doing the measuring: the
    round-19 finding reproduced inside the suite itself.

    ⚠ 'A refusal is a role, not a shape' was the right idea and the implementation still tested
    shape twice -- once for the role, then again for the literal. A conditional whose branches can
    yield non-zero counts; so does a call, conservatively, because a helper returning a status is
    still a refusal.
    """
    if isinstance(value, ast.Constant):
        return isinstance(value.value, int) and not isinstance(value.value, bool) \
            and value.value != 0
    if isinstance(value, ast.IfExp):
        return _can_return_nonzero(value.body) or _can_return_nonzero(value.orelse)
    if isinstance(value, ast.BoolOp):
        return any(_can_return_nonzero(v) for v in value.values)
    return False


def _exit_status_returns(tree):
    """Returns whose value becomes the PROCESS EXIT STATUS, found semantically.

    ⛔ THE FIRST VERSION OF THIS RULE WAS PURELY SYNTACTIC AND IT COUNTED `return True`. `bool`
    subclasses `int`, so `True not in (0, False)` is true -- five ordinary success predicates were
    registered as refusals, including an "is this field absent?" helper. The converse failed too:
    `return 1 if bad else 0` was invisible while the equivalent `if bad: return 1` was counted, so
    two spellings of one control produced two different registries. A round-20 reviewer named it
    as another registry deciding what the instrument can see.

    ⇒ A status-code refusal is not a shape, it is a ROLE: a non-zero integer returned by a
    function whose result is handed to `SystemExit`. That is discoverable -- find the entry
    functions, then look only inside them -- and it does not care how the return is spelled.

    ⚠ It still cannot see a refusal that exits through a variable computed elsewhere. That is a
    narrower blind spot than the one it replaces, and it is a bound rather than a claim.
    """
    entries = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Raise) and isinstance(n.exc, ast.Call) \
                and isinstance(n.exc.func, ast.Name) and n.exc.func.id == "SystemExit" \
                and n.exc.args and isinstance(n.exc.args[0], ast.Call) \
                and isinstance(n.exc.args[0].func, ast.Name):
            entries.add(n.exc.args[0].func.id)
    def _own_returns(fn):
        """Returns belonging to THIS function, not to helpers defined inside it.

        ⚠ `ast.walk` descends into nested `def`s, so a `return 1` in a helper was credited to
        the entry function that happened to contain it -- a false positive with the same shape as
        the false negative below.
        """
        found = []
        for child in ast.iter_child_nodes(fn):
            stack = [child]
            while stack:
                n = stack.pop()
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda,
                                  ast.ClassDef)):
                    continue
                if isinstance(n, ast.Return):
                    found.append(n)
                stack.extend(ast.iter_child_nodes(n))
        return found

    out = set()
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and fn.name in entries:
            out.update(_own_returns(fn))
    return out


def controls(src, path):
    """Every statement in `src` that REPORTS a defect, with its line number.

    Found structurally: a call to `.append(` on a name whose identifier is a defect accumulator,
    a `return False, ...` inside an executor, or a `raise SystemExit(...)`.
    """
    tree = ast.parse(src)
    _status_returns = _exit_status_returns(tree)
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            f = node.value.func
            if (isinstance(f, ast.Attribute) and f.attr == "append"
                    and isinstance(f.value, ast.Name) and f.value.id in _ACCUMULATORS):
                out.append((node.lineno, node.end_lineno, "reports a defect"))
        elif isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple):
            first = node.value.elts[0] if node.value.elts else None
            if isinstance(first, ast.Constant) and first.value is False:
                out.append((node.lineno, node.end_lineno, "rejects in an executor"))
        elif (isinstance(node, ast.Return) and node in _status_returns
              and _can_return_nonzero(node.value)):
            # ⛔ THE DETECTOR COULD NOT SEE THE CONTROL THAT CATCHES THE FABRICATED FIGURE.
            # `build_filter_bound.py` refuses a tampered record with `print(...); return 1` -- a
            # STATUS-CODE refusal -- and this recognised accumulator appends, `return False, ...`
            # tuples and `raise SystemExit`, so it scored that module at ZERO control sites. The
            # paper's strongest new repair was outside its own audit denominator. A registry that
            # cannot see a refusal reports the wrong denominator, which is this paper's subject.
            out.append((node.lineno, node.end_lineno, "refuses with a status code"))
        elif isinstance(node, ast.Raise):
            e = node.exc
            if isinstance(e, ast.Call) and isinstance(e.func, ast.Name) \
                    and e.func.id == "SystemExit":
                # `raise SystemExit(0)` and `SystemExit(1)` are a main()'s exit paths, not
                # controls: neutering them says nothing about what is watched. ⚠️ An earlier
                # attempt to add this filter was written into a heredoc, which ate the line
                # continuation above, so `str.replace` matched nothing and returned the source
                # unchanged -- and the patch script printed "exit paths excluded" regardless.
                # The tool reported a change it had not made, which is the defect it audits for.
                a = e.args[0] if e.args else None
                if isinstance(a, ast.Constant) and isinstance(a.value, int):
                    continue
                # ⛔ `raise SystemExit(main())` IS AN ENTRYPOINT, NOT A CONTROL. It propagates
                # main()'s status and reports no defect, but it was counted -- so replay.py:1090
                # appeared as REDUNDANT and sweep.py:199 as NEVER EXECUTES, inflating both the
                # denominator and the survivor list the manuscript quotes. Two reviewers found it.
                if (isinstance(a, ast.Call) and isinstance(a.func, ast.Name)
                        and a.func.id == "main"):
                    continue
                out.append((node.lineno, node.end_lineno, "refuses to proceed"))
    return sorted(set(out))


TRACER = r"""
import json, os, runpy, sys
seen = set()
def tr(frame, event, arg):
    if event == "line":
        seen.add((frame.f_code.co_filename, frame.f_lineno))
    return tr
target = sys.argv[1]
out = sys.argv[-1]
# the runner lives elsewhere, so sys.path[0] is NOT the census: without this the traced tool
# dies on `import axes` and the trace records only the import machinery -- which then reads as
# "this control never executes", a false disposition produced by the classifier itself.
sys.path.insert(0, os.path.dirname(target))
sys.argv = [target] + sys.argv[2:-1]
sys.settrace(tr)
try:
    runpy.run_path(target, run_name="__main__")
except SystemExit:
    pass
except Exception:
    pass
finally:
    sys.settrace(None)
open(out + ".trace", "w").write(json.dumps(sorted(seen)))
"""


def executed_lines(scripts):
    """Which lines actually EXECUTE when the suite runs? Traced in a SUBPROCESS.

    ⛔ "MAY BE UNREACHABLE, REDUNDANT, OR UNFIXTURED" IS A MENU, NOT A DISPOSITION. A
    round-12 reviewer said so and was right: this tool reported a count of unwatched controls and
    then offered three possible explanations without choosing between them. The important half of
    that choice is computable.

    A control line that NEVER EXECUTES during the whole suite is not merely untested -- no input
    the suite can build reaches it. A line that executes on every run, and whose deletion changes
    no verdict, is REDUNDANT: something else rejects the same input first. Different findings,
    and only one of them is alarming.

    ⚠ IN A SUBPROCESS, because the traced tools rewrap sys.stdout around the
    real buffer and close it on exit -- tracing them in-process killed this tool's own output
    mid-sentence.
    """
    import json as _j
    import tempfile
    seen = set()
    td = pathlib.Path(tempfile.mkdtemp(prefix="trace-"))
    runner = td / "runner.py"
    runner.write_text(TRACER, encoding="utf-8", newline="\n")
    for argv in scripts:
        out = td / ("t%d" % len(seen))
        r = subprocess.run([sys.executable, "-X", "utf8", str(runner),
                            str(HERE / argv[0])] + list(argv[1:]) + [str(out)],
                           cwd=str(HERE), capture_output=True, text=True)
        f = pathlib.Path(str(out) + ".trace")
        if f.exists():
            seen |= {tuple(x) for x in _j.loads(f.read_text())}
    shutil.rmtree(td, ignore_errors=True)
    return seen


def neutered(src, lo, hi):
    """The same source with lines lo..hi replaced by a `pass` at the same indentation."""
    lines = src.splitlines(True)
    indent = len(lines[lo - 1]) - len(lines[lo - 1].lstrip())
    return "".join(lines[:lo - 1] + [" " * indent + "pass" + NL] + lines[hi:])


_WORK = {"root": None}
_TREES = []
_LOCAL = threading.local()
_TREE_LOCK = threading.Lock()
_MIN_FREE_BYTES = 700 * 1024 * 1024


def _worker_tree():
    """A census copy private to this thread.

    ⛔ EVERY CONTROL MUTATED ONE SHARED TREE, which is the only reason this had to be sequential.

    ⛔ AND THE FIRST VERSION OF THIS CREATED `threading.local()` LAZILY INSIDE THE FUNCTION, so
    racing threads each built their own and none of them ever saw a cached root: a fresh 21 MB
    copy PER CONTROL, 252 controls, and the machine ran out of disk mid-audit. A thread-local that
    is constructed per call is not a thread-local -- it is an expensive way to write a global. It
    is built once, at module scope, where it cannot race.

    ⚠ AND THE RESOURCE IS PRE-FLIGHTED. This project has hit zero free disk twice, and both
    times the failure was silent until something downstream wrote a truncated file. A step that
    can die halfway is checked before it starts, not after.
    """
    import shutil as _sh
    import tempfile as _tf
    root = getattr(_LOCAL, "root", None)
    if root is not None:
        return root
    with _TREE_LOCK:
        free = _sh.disk_usage(_tf.gettempdir()).free
        if free < _MIN_FREE_BYTES:
            raise SystemExit(
                chr(0x26D4) + " %d MB free on the temp volume and this needs a %d MB census copy per "
                "worker. Refusing to start rather than dying halfway through and leaving a "
                "truncated tree behind." % (free // (1024 * 1024), _tree_mb()))
        w = pathlib.Path(_tf.mkdtemp(prefix="control-audit-"))
        _sh.copytree(HERE, w / "census", dirs_exist_ok=True, ignore=_SKIP)
        _TREES.append(w)
    root = w / "census"
    _LOCAL.root = root
    return root


def _tree_mb():
    return sum(f.stat().st_size for f in HERE.rglob("*") if f.is_file()) // (1024 * 1024)


def _cleanup_trees():
    """Remove the worker trees, and SAY SO if any survive.

    ⛔ `ignore_errors=True` IS A CLEANUP THAT REPORTS SUCCESS FOR DOING NOTHING. Nine of eight
    trees survived the first parallel run and the tool said nothing, because a Windows handle can
    keep a directory alive and the flag swallows exactly that. This project has now leaked 2,141
    temp directories -- 13 GB, on a machine that hit zero free disk twice in one day -- through a
    silence of this shape.

    ⚠ A retry, then a count, then a printed number. The leak is allowed to happen; it is not
    allowed to be invisible.
    """
    import shutil as _sh
    import time as _t
    left = []
    for w in _TREES:
        for _attempt in range(3):
            _sh.rmtree(w, ignore_errors=True)
            if not w.exists():
                break
            _t.sleep(0.3)
        if w.exists():
            left.append(w)
    del _TREES[:]
    if left:
        print()
        print("  " + chr(0x26A0) + " %d worker tree(s) could not be removed and are still on disk:"
              % len(left))
        for w in left[:3]:
            print("      %s" % w)
        print("  Something still holds a handle. They are named rather than ignored, because a")
        print("  leak nobody prints is how this directory reached 13 GB.")


def _root_for_baseline():
    """The tree the mutations will run in -- created here so the BASELINE measures IT.

    ⛔ THE BASELINE WAS MEASURED IN THE REAL TREE AND THE MUTATIONS RUN IN A COPY, so a
    copy that could not run the suite at all reported every control as unwatched: 0 watched, 111
    deletable. A baseline is only a baseline for the thing it was taken from.
    """
    import shutil as _sh
    import tempfile as _tf
    if _WORK["root"] is None:
        w = pathlib.Path(_tf.mkdtemp(prefix="control-audit-"))
        _sh.copytree(HERE, w / "census", dirs_exist_ok=True, ignore=_SKIP)
        _WORK["root"] = w / "census"
        # ⛔ THE BASELINE TREE WAS NEVER REGISTERED FOR CLEANUP, so the repair for a leak left
        # one tree per run behind -- a reviewer watched the retained count go 1, 2, 3 across
        # consecutive runs. The fix for the leak had the leak.
        _TREES.append(w)
    return _WORK["root"]


def suite_passes(_cwd=None):
    """True if EVERY tool in the suite still exits 0 in `_cwd` -- i.e. nothing noticed.

    ⛔ `cwd` WAS HARD-CODED TO THE REAL TREE while the mutations were written to a copy,
    so every mutation left the suite green and the audit reported 0 of 111 controls watched. The
    fix for one tree-confusion introduced another: measuring one tree while mutating a different
    one is the same error the copy was meant to prevent, moved inward by a single argument.
    """
    _cwd = _cwd or HERE
    for argv, _name in SUITE:
        r = subprocess.run([sys.executable, "-X", "utf8"] + argv, cwd=str(_cwd),
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        if r.returncode != 0:
            return False, _name
        # ⛔ AN EXIT CODE IS THE ENVELOPE. mp_metric prints defects and still exits 0 in some
        # paths, and a self-test prints its tally rather than returning it. Read the letter.
        out = (r.stdout or "") + (r.stderr or "")
        # ⛔ AND A COUNT IS NOT A VERDICT. The first version of this matched the substring
        # "FAIL", and replay.py's healthy line reads "0 FAILED" -- so the audit declared its own
        # baseline red and measured nothing. The tally has to be READ, not matched.
        if re.search(r"[1-9][0-9]* (?:FAILED|failing|failed|not rejected)", out):
            return False, _name
        # And NOT the project's own defect glyph: mp_metric prints a standing
        # "NOT A RANKING" line carrying it on every healthy run, so matching the glyph would
        # make the baseline permanently red -- the same false positive as "0 FAILED", one
        # layer up. Match what only appears when something is WRONG.
        if "DEFECT" in out or "validation:" in out and "no defects" not in out:
            return False, _name
    return True, None


def _round():
    """Which review round this tree is in, read from a marker the author bumps.

    ⛔ `previous` MEANT "THE LAST RUN WHOSE NUMBERS MOVED" AND THE PAPER SAYS "THE ROUND
    BEFORE". Those are the same sentence only when a round contains exactly one number-moving
    run. Round 22 contained three -- the fixpoint chain, then a --quick repair -- so `previous`
    walked forward to an intermediate state of the SAME round and section 8's comparison read
    "rose by 0" against a figure it had itself produced an hour earlier. The predecessor logic
    already carried forward on UNCHANGED numbers for this exact reason; it could not carry
    forward across changed ones, and a round is where the change belongs.

    ⚠ The round is a human unit and it is written down as one, in a file, bumped
    deliberately. Deriving it would mean inventing a rule for when a round begins, and there
    is no such rule in the code -- there is only a decision a person makes.
    """
    _f = HERE / "AUDIT-ROUND"
    if not _f.exists():
        raise SystemExit(D + " AUDIT-ROUND is missing, so this run cannot say which round it "
                         "belongs to and `previous` would silently mean the last RUN again. "
                         "Write the current round number into it.")
    try:
        return int(_f.read_text(encoding="utf-8").strip())
    except ValueError:
        raise SystemExit(D + " AUDIT-ROUND does not hold an integer.")


def _history(old, rnd, total_now, watched_now, never_now, modules_now, when):
    """Every RUN, append-only, stamped with its round and the tree it measured.

    ⛔ THIS KEPT ONE ENTRY PER ROUND AND THE LAST RUN OF A ROUND OVERWROTE IT. Round 22 was
    deposited at 278 sites / 123 watched -- the tree two reviewers read, where the watched gain
    was 18 against a reconstruction of 17, which is why the "entire gain is bookkeeping" claim
    was withdrawn. Round-23 repairs re-ran the audit while AUDIT-ROUND still said 22, and the
    round-22 entry became 279 / 122. The deposited state was gone from the record, the two
    figures then agreed, and section 8 briefly read as though the withdrawn claim had been
    vindicated by numbers that had simply been overwritten.

    ⇒ THAT IS THE `previous` DEFECT ONE LEVEL OUT. Round 22 fixed "previous means the last RUN"
    by stamping rounds; the history array still meant "the last run stamped with that round".
    Fixing a defect by adding a key does not fix it if the key is not unique. Entries are
    APPEND-ONLY per run now, each carrying the source fingerprint of the tree it measured, so a
    later run inside the same round cannot erase an earlier one and a deposited state stays
    recoverable from the record rather than only from git.

    ⚠ Consecutive runs that measured the SAME tree to the SAME counts are collapsed, because
    that is a repeat rather than a second measurement, and an append-only log that grows on every
    idle re-run is one nobody reads.
    """
    hist = list((old or {}).get("history") or [])
    entry = {"round": rnd, "controls_total": total_now, "watched": watched_now,
             "never_executes": never_now, "modules": modules_now, "when": when,
             "source_fingerprint": source_fingerprint()}
    if hist:
        _last = hist[-1]
        _same = all(_last.get(k) == entry.get(k) for k in
                    ("round", "controls_total", "watched", "never_executes",
                     "source_fingerprint"))
        if _same:
            return hist
    hist.append(entry)
    return hist


def _predecessor(old, total_now, watched_now, rnd=None):
    """The last audit from an EARLIER ROUND, so "the round before" is what it means."""
    if rnd is not None:
        _prior = [h for h in ((old or {}).get("history") or []) if h.get("round", 10 ** 9) < rnd]
        if _prior:
            # ⚠ The LAST run of the previous round, which is that round's final state. With
            # append-only history the earlier runs of that round remain readable beside it.
            return dict(_prior[-1])
        # ⛔ FAILS CLOSED. Returning the last run instead would put the sentence back exactly
        # where it was, and it would look like it was working.
        return None
    if not isinstance(old, dict):
        return None
    if old.get("controls_total") == total_now and old.get("watched") == watched_now:
        return old.get("previous")
    # ⛔  STORED ONLY THE TWO NUMBERS, so nothing in the toolchain could
    # substantiate or refute the paper sentence claiming an earlier ratio came from a SMALLER
    # WINDOW. It did not -- 215 and 218 were measured across an identical 28-module set -- and
    # the excuse suppressed an unflattering real comparison for two rounds. The fact that
    # falsifies it shipped in history.bundle and nothing read it. The window is recorded now.
    return {"controls_total": old.get("controls_total"), "watched": old.get("watched"),
            "modules": len(old.get("targets") or [])}


def _suite_without(name):
    """The suite minus one named item, so "who watches this" can be MEASURED not inferred.

    ⛔ SECTION 8 CLAIMED N SITES ARE "WATCHED ONLY BECAUSE THE REACH RECORD NAMES
    THEM" and computed it as `reached - survivors` -- which proves those sites are not survivors,
    never that reach is their ONLY watcher. A round-22 reviewer measured the real number by
    deleting `reach_controls.py --quick` from the suite and re-running: watched fell 123 to 97,
    so 26 depend on it exclusively, not 44. A set difference stood in for a counterfactual, which
    is the proxy defect at the level of the claim rather than the check.

    ⚠ `--without NAME` makes that counterfactual a command anyone can run, so the
    figure in the manuscript comes from removing the watcher and looking, rather than from
    subtracting two sets that were never about the same question.
    """
    return tuple((args, nm) for args, nm in SUITE if nm != name)


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    # ⛔ `TARGETS[:1]` MEANT mp_metric.py WHEN TARGETS WAS A HAND-WRITTEN TUPLE STARTING WITH IT.
    # Projecting TARGETS over the directory -- the repair that closed the enumeration defect two
    # rounds ago -- re-sorted it, so --quick silently became "add_evidence.py only" while the
    # docstring above still said mp_metric.py. A POSITION STOOD FOR A NAME, which is the same
    # substitution as a line number standing for a control, introduced BY the fix for a different
    # instance of the same class. Named now, and absent means refuse rather than fall back.
    global SUITE
    if "--without" in sys.argv:
        _drop = sys.argv[sys.argv.index("--without") + 1]
        if _drop not in {nm for _a, nm in SUITE}:
            raise SystemExit(D + " --without %r names no suite item; the suite is %s"
                             % (_drop, sorted(nm for _a, nm in SUITE)))
        SUITE = _suite_without(_drop)
        print("  " + W + " MEASURING WITHOUT %r: this run answers 'what does that item watch, "
              "and nothing else' and its record is NOT the tree's record." % _drop)
    if "--quick" in sys.argv:
        _want = "mp_metric.py"
        targets = tuple(x for x in TARGETS if str(x) == _want)
        if not targets:
            raise SystemExit(D + " --quick audits %s and this tree has no such module. "
                             "Falling back to some other file would report a number under a "
                             "name that did not produce it." % _want)
    else:
        targets = TARGETS

    print("=" * 78)
    print("  CONTROL AUDIT: disable each control, ask whether anything notices")
    print("=" * 78)
    print()

    # ⛔ THE PRE-FLIGHT LIVES IN `_worker_tree` AND THIS COPY HAPPENS FIRST, so the copy that
    # runs on a full disk was the unguarded one -- it dies halfway and leaves a truncated tree,
    # the exact failure the pre-flight was added to prevent. Every early return below also skipped
    # the cleanup, so a repeatedly red baseline recreates the disk exhaustion this round claims to
    # have fixed.
    try:
        base_ok, base_why = suite_passes(_root_for_baseline())
    except BaseException:
        _cleanup_trees()
        raise
    if not base_ok:
        print("  " + chr(0x26D4) + " the suite does not pass BEFORE any mutation (%s)." % base_why)
        print("  A mutation audit against a red suite measures nothing. Fix the suite first.")
        _cleanup_trees()
        return 1
    print("  baseline: the suite passes, so a failure below is attributable to the mutation")
    print()

    # trace once, before any mutation, so the classification describes the REAL suite
    print("  tracing which control lines the suite actually executes ...")
    # ⛔ THE TRACER RAN FOUR TOOLS WHILE SUITE DECLARES SIX, so a control exercised only by
    # stress_test.py or check_facts.py was classified "no input the suite can build reaches this
    # line" -- which was false of mp_metric.py:286, built by stress_test.py:370. Both reviewers
    # found the same site. A hand-copied subset of a declared list is the enumeration defect with
    # the list sitting ten lines above it.
    _hit = executed_lines(tuple(tuple(argv) for argv, _n in SUITE))
    print("  %d distinct line(s) executed across the traced tools" % len(_hit))
    print()

    # ⛔ THIS MUTATED THE SOURCE TREE IN PLACE, AND A KILLED RUN LEFT IT NEUTERED. The restore
    # lived in a `finally`, which does not run when the process is killed -- and one was. The
    # neutered mp_metric.py was then COMMITTED (7a4d51d), shipped, and found by a reviewer who
    # recognised the shape as this function's own output: a `d.append(...)` replaced by `pass`
    # with its `owner = ...` left orphaned above it.
    #
    # ⚠ AND THE TOOL COULD NOT SEE ITS OWN DAMAGE. `controls()` walks the AST for `d.append`,
    # so a control reduced to `pass` leaves no signature and drops out of the DENOMINATOR -- the
    # audit that answers "which of our controls does nothing" is blind to one that has been
    # removed entirely. That is why the packet and the paper disagreed by exactly one control.
    #
    # ⇒ The audit now runs against a COPY. The real tree is opened read-only from here on, so an
    # interrupted run can lose work but cannot alter a source file.
    _root = _root_for_baseline()
    print("  auditing a COPY at %s -- the real tree is not written to" % _root)
    print()

    unwatched, watched, t0 = [], 0, time.time()

    # ⛔ FLATTENED, SO THE WORK IS A LIST OF INDEPENDENT ITEMS. The sequential nesting was the
    # only thing making this look serial; nothing about one control's verdict depends on another.
    _work = []
    _srcs = {}
    for name in targets:
        _srcs[name] = (HERE / name).read_text(encoding="utf-8")
        sites = controls(_srcs[name], name)
        print("  %-14s %d control(s)" % (name, len(sites)))
        for lo, hi, kind in sites:
            _work.append((name, lo, hi, kind))
    print()

    def _one(item):
        name, lo, hi, kind = item
        root = _worker_tree()
        p = root / name
        src = _srcs[name]
        p.write_text(neutered(src, lo, hi), encoding="utf-8", newline=NL)
        try:
            still, _n = suite_passes(root)
        finally:
            p.write_text(src, encoding="utf-8", newline=NL)
        return (name, lo, kind, still)

    # ⚠ THREADS, NOT PROCESSES, because every second of this is spent waiting on `subprocess`
    # -- the GIL is released there, and threads avoid pickling the module state. `--jobs 1` runs
    # the identical code path with one worker, so the sequential result stays reproducible.
    import concurrent.futures as _cf
    _jobs = 1
    for _i, _a in enumerate(sys.argv):
        if _a == "--jobs" and _i + 1 < len(sys.argv):
            _jobs = max(1, int(sys.argv[_i + 1]))
    if _jobs == 1 and "--jobs" not in sys.argv:
        _jobs = min(8, (__import__("os").cpu_count() or 2))
    print("  running %d control site(s) across %d worker tree(s)" % (len(_work), _jobs))
    print()

    try:
        if _jobs == 1:
            _results = [_one(w) for w in _work]
        else:
            with _cf.ThreadPoolExecutor(max_workers=_jobs) as _ex:
                _results = list(_ex.map(_one, _work))
    finally:
        _cleanup_trees()

    # ⚠ SORTED, so the record does not depend on which worker finished first. A parallel audit
    # whose output order varies would make every diff unreadable and every digest unstable.
    for name, lo, kind, still in sorted(_results, key=lambda r: (r[0], r[1])):
        if still:
            line = _srcs[name].splitlines()[lo - 1].strip()
            ran = any(f.endswith(name) and n0 == lo for f, n0 in _hit)
            unwatched.append((name, lo, kind, line[:88],
                              "REDUNDANT" if ran else "NEVER EXECUTES"))
            print("      " + chr(0x26D4) + " %-14s line %-4d NOTHING NOTICED  %s"
                  % (name, lo, line[:52]))
        else:
            watched += 1
    print()

    print("=" * 78)
    print("  %d control(s) are watched by at least one test" % watched)
    print("  %d control(s) can be deleted with the whole suite still green" % len(unwatched))
    print("  (%.0f s)" % (time.time() - t0))
    if unwatched:
        print()
        print("  " + chr(0x26A0) + " A survivor is not automatically a bug: it may be unreachable")
        print("  given this ledger, redundant with a control that fires first, or guarding a")
        print("  state no fixture builds. Those are three findings and this tool cannot tell")
        print("  them apart. It says what nothing is watching; a human reads them.")
        _red = [u for u in unwatched if u[4] == "REDUNDANT"]
        _never = [u for u in unwatched if u[4] == "NEVER EXECUTES"]
        print()
        print("      %d REDUNDANT      the line runs, and deleting it changes no verdict --"
              % len(_red))
        print("                       another control rejects the same input first")
        print("      %d NEVER EXECUTES no input the suite can build reaches the line at all."
              % len(_never))
        print("                       This is the half worth reading: either the branch is")
        print("                       unreachable given the ledger, or nothing fixtures it")
        for name, lo, kind, line, cls in unwatched:
            print()
            print("      %-14s %s:%d  (%s)" % (cls, name, lo, kind))
            print("        %s" % line)
    # ⛔ THE RESULT IS RECORDED, because the manuscript must cite it and this takes ten
    # minutes -- and a figure a reader cannot find in the paper is a figure the paper is hiding,
    # whatever the intention. The record carries the digests of the files it audited, so a stale
    # record is detectable rather than merely old.
    import hashlib as _h
    # ⛔ A CONTROL THAT IS DELETED LEAVES NO TRACE IN THIS CENSUS, so the count silently falls
    # and nothing notices. Compare against the previous record: a DROP is either a deliberate
    # removal, which belongs in a commit message, or a neutered file.
    _old = None
    _prev = HERE / "CONTROL-AUDIT.json"
    if _prev.exists():
        try:
            _old = json.loads(_prev.read_text(encoding="utf-8"))
            _was, _now = _old.get("controls_total"), watched + len(unwatched)
            if isinstance(_was, int) and _now < _was:
                print()
                print("  " + D + " THE CONTROL COUNT FELL from %d to %d." % (_was, _now))
                print("  Either a control was deliberately removed -- say so in the commit -- or a")
                print("  file is NEUTERED. A `d.append(...)` replaced by `pass` leaves no AST")
                print("  signature and drops out of this census without appearing anywhere.")
        except Exception:                                                   # noqa: BLE001
            pass

    _RND = _round()
    _WHEN = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rec = {"_what": ("Which of this project's own controls can be deleted with the whole suite "
                     "still green, and what kind of survivor each one is."),
           "targets": {n: _h.sha256((HERE / n).read_bytes()).hexdigest() for n in targets},
           "suite": [list(a) for a, _ in SUITE],
           "source_fingerprint": source_fingerprint(),
           "inputs_fingerprint": inputs_fingerprint(),
           "inputs_manifest": inputs_manifest(),
           # ⛔ THE PAPER COMPARES THIS ROUND'S WATCHED SHARE WITH LAST ROUND'S, and the first
           # version of that resolver TYPED the previous numbers. Reading them from git worked
           # until the audit was committed, after which HEAD held the CURRENT record and the
           # comparison became a figure against itself. The record carries its own predecessor now,
           # so the comparison does not depend on when anything was committed.
           # ⛔ TWO AUDITS IN ONE ROUND MADE THE RECORD ITS OWN PREDECESSOR. The second run
           # recorded 173/96 as the previous of 173/96, so the paper's sentence about the watched
           # SHARE falling would have compared a figure with itself. When the counts are
           # unchanged the predecessor is carried FORWARD, so "previous" means the last time the
           # number actually moved rather than the last time this tool ran.
           "round": _RND,
           "history": _history(_old, _RND, watched + len(unwatched), watched,
                               len([u for u in unwatched if u[4] == "NEVER EXECUTES"]),
                               len(TARGETS), _WHEN),
           "previous": _predecessor(_old, watched + len(unwatched), watched, _RND),
           "controls_total": watched + len(unwatched),
           "watched": watched,
           "unwatched": len(unwatched),
           "redundant": len([u for u in unwatched if u[4] == "REDUNDANT"]),
           "never_executes": len([u for u in unwatched if u[4] == "NEVER EXECUTES"]),
           "survivors": [{"file": n, "line": lo, "kind": k, "source": s, "class": cls}
                         for n, lo, k, s, cls in unwatched],
           "_dispositions": {
               "REDUNDANT": ("the line executes during the suite and deleting it changes no "
                             "verdict: another control rejects the same input first"),
               "NEVER EXECUTES": ("no input the suite can build reaches the line. Either the "
                                  "branch is unreachable given this ledger, or nothing fixtures "
                                  "the state it guards -- and those are still two things")}}
    # ⛔ THE FINGERPRINT BINDS THE INPUTS AND NOTHING BOUND THE CLAIMED OUTPUT. A round-20
    # reviewer ran this from a clean extraction and got a different classification set than the
    # deposited record carried, with the fingerprints agreeing -- because the record had been
    # written by one version of this file and shipped beside another. A record whose inputs are
    # certified says nothing about whether its verdicts are the ones this code produces, and a
    # hand-edited record with a valid fingerprint would pass every check there was.
    #
    # ⚠ `--verify` re-runs the whole audit and compares the COMPLETE per-site set: identity and
    # classification, not counts. It is as expensive as the audit because it IS the audit; that is
    # the honest price of the claim, and it is why the audit was made affordable first.
    if "--verify" in sys.argv:
        old_path = HERE / "CONTROL-AUDIT.json"
        if not old_path.exists():
            print("  " + D + " no record to verify against.")
            return 1
        prev = json.loads(old_path.read_text(encoding="utf-8"))
        def _ident(r):
            # ⛔ THIS DROPPED LINE, KIND AND MULTIPLICITY: 145 survivors collapsed to 125
            # identities, five distinct `bad.append(name)` controls becoming one. A reviewer moved
            # one survivor's recorded line onto another otherwise-identical survivor; the records
            # differed and the verifier's identity sets matched -- a per-site substitution
            # permitted by the control written to forbid exactly that.
            from collections import Counter
            return Counter((s["file"], int(s["line"]), s.get("kind"),
                            (s.get("source") or "").strip(), s["class"])
                           for s in r.get("survivors", []))
        drift = []
        for k in ("controls_total", "watched", "unwatched", "redundant", "never_executes"):
            if prev.get(k) != rec.get(k):
                drift.append("%s: recorded %s, recomputed %s" % (k, prev.get(k), rec.get(k)))
        a, b = _ident(prev), _ident(rec)
        if a != b:
            drift.append("%d survivor record(s) recorded that this run does not "
                         "produce, and %d the other way (multiset over file, line, kind, source "
                         "and class)" % (sum((a - b).values()), sum((b - a).values())))
        if drift:
            print()
            print("  " + D + " THE DEPOSITED RECORD IS NOT WHAT THIS CODE PRODUCES:")
            for _d in drift:
                print("      " + _d)
            for x in sorted(a - b)[:3]:
                print("      only in the record : %s %s" % (x[0], x[1][:44]))
            for x in sorted(b - a)[:3]:
                print("      only in this run   : %s %s" % (x[0], x[1][:44]))
            return 1
        print()
        print("  ok  the record is exactly what this code produces: %d site(s), %d watched,"
              % (rec["controls_total"], rec["watched"]))
        print("  and every survivor identity and classification agrees.")
        return 0

    # ⛔ A COUNTERFACTUAL RUN MUST NOT BECOME THE TREE'S RECORD. `--without` measures
    # a suite that is not this project's suite; writing its numbers to CONTROL-AUDIT.json would
    # put a deliberately weakened measurement under every figure in section 8, and the
    # fingerprints would all agree because the TREE did not change. That is exactly the
    # substitution this file exists to detect, arriving through a flag it was given itself.
    _out_name = ("CONTROL-AUDIT-without-%s.json"
                 % sys.argv[sys.argv.index("--without") + 1].replace(".py", "")
                 if "--without" in sys.argv else "CONTROL-AUDIT.json")
    (HERE / _out_name).write_text(json.dumps(rec, indent=2) + NL,
                                             encoding="utf-8", newline=NL)
    print("  written to %s" % _out_name)
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
