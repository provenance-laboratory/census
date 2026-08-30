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
import io
import json
import pathlib
import shutil
import subprocess
import sys
import time

NL = chr(10)
HERE = pathlib.Path(__file__).resolve().parent
TARGETS = ("mp_metric.py", "replay.py", "axes.py", "sweep.py")

# The suite that must notice. Deliberately the FAST ones: sweep.py takes ten minutes and its
# verdict is already implied by validate() refusing the mutation.
SUITE = (
    (["mp_metric.py"], "validate"),
    (["replay.py"], "replay"),
    (["replay.py", "--selftest"], "selftest"),
    (["stress_test.py"], "stress"),
    (["check_facts.py"], "facts"),
    (["test_executors.py"], "executors"),
)


def controls(src, path):
    """Every statement in `src` that REPORTS a defect, with its line number.

    Found structurally: a call to `.append(` on a name whose identifier is a defect accumulator,
    a `return False, ...` inside an executor, or a `raise SystemExit(...)`.
    """
    tree = ast.parse(src)
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            f = node.value.func
            if (isinstance(f, ast.Attribute) and f.attr == "append"
                    and isinstance(f.value, ast.Name) and f.value.id in ("d", "bad", "trunc",
                                                                        "unadj", "drift")):
                out.append((node.lineno, node.end_lineno, "reports a defect"))
        elif isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple):
            first = node.value.elts[0] if node.value.elts else None
            if isinstance(first, ast.Constant) and first.value is False:
                out.append((node.lineno, node.end_lineno, "rejects in an executor"))
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
    runner.write_text(TRACER, encoding="utf-8")
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


def suite_passes():
    """True if EVERY tool in the suite still exits 0 -- i.e. nothing noticed."""
    for argv, _name in SUITE:
        r = subprocess.run([sys.executable, "-X", "utf8"] + argv, cwd=str(HERE),
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


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    targets = TARGETS[:1] if "--quick" in sys.argv else TARGETS

    print("=" * 78)
    print("  CONTROL AUDIT: disable each control, ask whether anything notices")
    print("=" * 78)
    print()

    base_ok, base_why = suite_passes()
    if not base_ok:
        print("  " + chr(0x26D4) + " the suite does not pass BEFORE any mutation (%s)." % base_why)
        print("  A mutation audit against a red suite measures nothing. Fix the suite first.")
        return 1
    print("  baseline: the suite passes, so a failure below is attributable to the mutation")
    print()

    # trace once, before any mutation, so the classification describes the REAL suite
    print("  tracing which control lines the suite actually executes ...")
    _hit = executed_lines((("replay.py",), ("replay.py", "--selftest"),
                           ("test_executors.py",), ("mp_metric.py",)))
    print("  %d distinct line(s) executed across the traced tools" % len(_hit))
    print()

    unwatched, watched, t0 = [], 0, time.time()
    for name in targets:
        p = HERE / name
        src = p.read_text(encoding="utf-8")
        sites = controls(src, name)
        print("  %-14s %d control(s)" % (name, len(sites)))
        backup = src
        for lo, hi, kind in sites:
            p.write_text(neutered(src, lo, hi), encoding="utf-8", newline=NL)
            try:
                still, _n = suite_passes()
            finally:
                p.write_text(backup, encoding="utf-8", newline=NL)
            if still:
                line = src.splitlines()[lo - 1].strip()
                ran = any(f.endswith(name) and n0 == lo for f, n0 in _hit)
                unwatched.append((name, lo, kind, line[:88],
                                  "REDUNDANT" if ran else "NEVER EXECUTES"))
                print("      " + chr(0x26D4) + " line %-4d NOTHING NOTICED  %s" % (lo, line[:60]))
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
    rec = {"_what": ("Which of this project's own controls can be deleted with the whole suite "
                     "still green, and what kind of survivor each one is."),
           "targets": {n: _h.sha256((HERE / n).read_bytes()).hexdigest() for n in targets},
           "suite": [list(a) for a, _ in SUITE],
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
    (HERE / "CONTROL-AUDIT.json").write_text(json.dumps(rec, indent=2) + NL,
                                             encoding="utf-8", newline=NL)
    print("  written to CONTROL-AUDIT.json")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
