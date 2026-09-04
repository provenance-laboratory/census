"""How much of this census is prose that nothing reads? Measured by deleting it.

⛔ THE FINDING. A round-13 reviewer deleted 36 zero-cell notes and the build stayed green. The
real figure is every unbounded zero in the census: their notes carry the search bound, the reason
and the date, and no tool reads any of it. A note beside a score is a claim; if removing it changes
nothing, it was decoration.

⚠️ AND THIS IS NOT AN ARGUMENT, IT IS AN EXPERIMENT. The number below is obtained by blanking
those notes in a COPY of the census and running the suite. If a future control does read them, the
count falls by itself and this file will say so -- which is the only way a claim like "nothing reads
these" can stay true.

    python unread_notes.py
"""
import io
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

NL = chr(10)
D = chr(0x26D4)
W = chr(0x26A0)   # undefined until round 14; the baseline warning raised NameError instead
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
# ⛔ THIS WAS THREE TOOLS WHILE THE PAPER SAID "the whole suite", AND THE GAP WAS THE ANSWER.
# check_claims.py carries two predicates that READ the notes on every axis-16/17 zero, so 22 of
# the 176 are not unread at all -- the true figure is 154. A round-14 reviewer blanked all 176,
# watched check_claims fail two predicates, blanked only the other 154 and watched it pass.
#
# ⚠ The measurement was a PROXY for the claim: "nothing reads these" was tested against a subset
# chosen for speed, and reported as though it had been tested against everything. That is the
# defect this census scores publishers for, in the tool written to measure it.
#
# ⇒ And the correction cuts in our favour, which is why it went unnoticed: those 22 notes are the
# axes-16/17 zeros that section 9.1 calls the STRONGEST in the census. The mechanism that makes
# them strong is exactly these two predicates, and the paper had not cited it.
SUITE = ("mp_metric.py", "replay.py", "check_facts.py", "check_claims.py")
SUITE_ACTIVE = list(SUITE)


def _rm_reporting(work):
    """Remove a work tree and say so if it survives. See test_bound_rules.py for the count."""
    import time as _t
    for _ in range(2):
        try:
            shutil.rmtree(work)
        except OSError:
            _t.sleep(0.2)
        if not work.exists():
            return
    print("  ⚠ could not remove %s -- still on disk" % work)


def _tool_path(here, name):
    """check_claims.py lives with the PAPER, not the census, and resolves the census beside it.

    ⛔ THIS KNEW ONLY THE AUTHOR'S HALF OF THE TWO-LAYOUT RULE, so in every extraction it returned
    (None, None) for `check_claims.py` -- which lives at `../paper/` there, not at
    `../../journal-submissions/mp-metric/`. `notices()` then did a bare `continue`, the tool was
    never invoked, and it stayed in SUITE_ACTIVE: the record said `suite_that_participated`
    includes check_claims.py and `excluded_red_at_baseline` is empty, while the DEPOSITED record
    says the opposite. A reviewer re-running the documented workflow got a record contradicting
    the deposit and asserting the more flattering of the two, and neither run had executed the
    fourth tool. This is the "control passes while inert" shape, live in the shipped archive, in
    the tool written to measure unread prose.
    """
    if (here / name).exists():
        return here, [name]
    # ⚠ BOTH LAYOUTS, the way every paper-side tool already does it: a sibling `paper/` inside an
    # extraction, and the author's working tree. Listing the author's only is what made this
    # unrunnable everywhere except one machine.
    for cand in (here.parent / "paper",
                 here.parents[1] / "journal-submissions" / "mp-metric"):
        if (cand / name).exists():
            return cand, [name]
    return None, None


def blank(led, axes, only_unbounded=True):
    """A copy of the ledger with the notes on `axes`' unbounded zeros blanked."""
    import copy
    out = copy.deepcopy(led)
    n = 0
    for c in out["cells"]:
        if c.get("score") != 0 or c["axis"] not in axes:
            continue
        if only_unbounded and isinstance(c.get("bound"), dict):
            continue
        if str(c.get("note") or "").strip():
            c["note"] = ""
            n += 1
    return out, n


def notices(root, led, paper_src):
    """Does any tool in SUITE notice this ledger? Returns the list that did."""
    (root / "cells.json").write_text(json.dumps(led, indent=2) + NL, encoding="utf-8", newline=NL)
    hit = []
    for tool in SUITE_ACTIVE:
        cwd, argv = _tool_path(HERE, tool)
        if cwd is None:
            # ⛔ TWO STATES WHERE THERE ARE THREE. A tool can be GREEN at baseline, RED at
            # baseline (excluded, and named as excluded), or UNRESOLVABLE -- and the third folded
            # silently into the first, so a tool that was never invoked was reported as having
            # participated. That is the same anchored-but-unusable shape as the arithmetic
            # control's middle state and `watched_direction` on equal ratios, here in the tool
            # that decides which prose nothing reads.
            #
            # ⇒ Unresolvable is a REFUSAL, not a shrug. A measurement over a suite is a claim
            # about that suite, and a suite this cannot assemble is not a smaller suite -- it is
            # an unknown one.
            raise SystemExit(
                D + " %r is in the suite and cannot be located from %s. A tool that cannot be "
                "run must not be reported as having participated: the record would name a suite "
                "member that never executed, and the figure beneath it would be measured over a "
                "population this tool could not assemble." % (tool, HERE))
        if cwd != HERE:
            cwd = paper_src
        r = subprocess.run([sys.executable, "-X", "utf8"] + argv, cwd=str(cwd),
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        out = (r.stdout or "") + (r.stderr or "")
        if (r.returncode != 0 or "DEFECT" in out
                or ("validation:" in out and "no defects" not in out)):
            hit.append(tool)
    return hit


def read_axes(root, led, axes, paper_src):
    """The minimal set of axes whose notes something reads. Bisection, not inspection.

    ⛔ THE FIRST VERSION OF THIS FILE ASKED ONLY *WHETHER* ANYTHING NOTICED, and answered with a
    single number that was wrong: it reported all 176 unbounded-zero notes as unread, against a
    suite of three tools, while the paper claimed "the whole suite". check_claims.py reads the
    notes on every axis-16/17 zero, so 22 of them are read and the figure is 154.

    ⚠ AND THE OBVIOUS FIX WOULD HAVE BEEN TO READ THE PREDICATES AND SUBTRACT -- which is
    inspection, the thing this file exists to avoid. So the partition is MEASURED: blank a subset,
    ask whether anything notices, and bisect. If a future control starts reading a different axis's
    notes, this finds it without anyone editing a list.
    """
    if not axes:
        return []
    mutated, n = blank(led, set(axes))
    if n == 0 or not notices(root, mutated, paper_src):
        return []
    if len(axes) == 1:
        return list(axes)
    mid = len(axes) // 2
    return (read_axes(root, led, axes[:mid], paper_src)
            + read_axes(root, led, axes[mid:], paper_src))


def main():
    # line_buffering, because this tool runs for twenty minutes and a block-buffered run that is
    # interrupted loses EVERY line -- which happened: a background run exited 0 having written
    # nothing at all, and the absence of output was indistinguishable from the absence of a result.
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace",
                                  line_buffering=True)
    led = json.loads((HERE / "cells.json").read_text(encoding="utf-8"))
    zeros = [c for c in led["cells"] if c.get("score") == 0]
    bounded = [c for c in zeros if isinstance(c.get("bound"), dict)]
    target = [c for c in zeros
              if not isinstance(c.get("bound"), dict) and str(c.get("note") or "").strip()]

    print("=" * 78)
    print("  UNREAD PROSE -- measured by deleting it")
    print("=" * 78)
    print()
    print("  %d zero(s), of which %d carry a replayable bound and %d carry only a note"
          % (len(zeros), len(bounded), len(target)))
    print()

    work = pathlib.Path(tempfile.mkdtemp(prefix="unread-"))
    root = work / "provenance-laboratory" / "census"
    shutil.copytree(HERE, root, dirs_exist_ok=True, ignore=_SKIP)
    paper_src = work / "journal-submissions" / "mp-metric"
    _real_paper = HERE.parents[1] / "journal-submissions" / "mp-metric"
    if _real_paper.exists():
        shutil.copytree(_real_paper, paper_src, dirs_exist_ok=True, ignore=_SKIP)
    # ⛔ THIS HAD NO BASELINE, AND IT COST THIRTY-FIVE MINUTES OF MEASURING NOTHING.
    # check_claims compares the MANUSCRIPT against the ledger, so it is red whenever the paper has
    # been edited and not yet rebuilt -- which is exactly when someone re-runs this tool. Every
    # bisection step then "noticed", the recursion descended to all 19 axes, and the answer would
    # have been "every note is read": a control that always fires, reported as a measurement.
    #
    # ⚠ control_audit.py CARRIES THIS EXACT GUARD, added after being burned twice, and this file
    # was written without it. A tool that is red before any mutation cannot tell you what a
    # mutation did.
    #
    # ⇒ A red tool is EXCLUDED and NAMED, rather than silently treated as a signal. The figure
    # then carries the bound: measured against the tools that could participate.
    print("  baseline: running the suite BEFORE any mutation ...")
    red = notices(root, led, paper_src)
    if red:
        print("  " + W + " %s %s red on the UNMUTATED tree and cannot participate."
              % (", ".join(red), "is" if len(red) == 1 else "are"))
        print("  A tool that fails before any mutation cannot report what a mutation did. The")
        print("  usual cause is an edited manuscript that has not been rebuilt.")
        for _t in red:
            SUITE_ACTIVE.remove(_t)
        if not SUITE_ACTIVE:
            print("  " + D + " nothing is left to measure with.")
            return 1
    else:
        print("  baseline: every tool green, so a failure below is attributable to the mutation")
    print()

    try:
        axes = sorted({c["axis"] for c in target})
        print("  bisecting over %d axes that carry unbounded-zero notes ..." % len(axes))
        read = sorted(read_axes(root, led, axes, paper_src))
        read_cells = [c for c in target if c["axis"] in read]
        unread_cells = [c for c in target if c["axis"] not in read]
        print()
        if read:
            print("  READ   axes %s -- %d note(s). Something in the suite fails when these are"
                  % (read, len(read_cells)))
            print("         blanked, so they are load-bearing rather than decorative.")
        else:
            print("  READ   none")
        print("  UNREAD %d note(s) across the remaining axes." % len(unread_cells))
        # confirm the complement really is green, rather than inferring it
        mutated, n = blank(led, {c["axis"] for c in unread_cells} - set(read))
        still = notices(root, mutated, paper_src)
        print()
        print("  CONTROL: blanking only the %d unread note(s) -> %s"
              % (n, "nothing noticed" if not still else (D + " %s NOTICED" % still)))
    finally:
        # ⛔ a removal that cannot fail out loud is a leak with a clean conscience
        _rm_reporting(work)

    rec = {"_what": ("Which zero-cell notes can be blanked with the whole suite still green, "
                     "measured by blanking them and bisecting -- not by reading the predicates, "
                     "which is the inspection this file exists to avoid."),
           "zeros": len(zeros), "bounded_zeros": len(bounded),
           "notes_examined": len(target),
           "read_axes": read,
           "read_notes": len(read_cells),
           "unread_notes": len(unread_cells),
           "complement_still_green": not still,
           "suite": list(SUITE),
           "suite_that_participated": list(SUITE_ACTIVE),
           "excluded_red_at_baseline": [x for x in SUITE if x not in SUITE_ACTIVE]}
    # ⛔ THE WRITE WAS DELETED BY A PATCH AND THE PRINT SURVIVED IT. For three runs this tool
    # announced "written to UNREAD-NOTES.json" and wrote nothing at all -- the success message
    # without the artifact, in the file whose entire purpose is to find prose that nothing backs.
    # It was caught by reading the record instead of the log: the file's mtime was six hours old
    # and its schema two versions behind, while the run reported success.
    (HERE / "UNREAD-NOTES.json").write_text(json.dumps(rec, indent=2) + NL,
                                            encoding="utf-8", newline=NL)
    _back = json.loads((HERE / "UNREAD-NOTES.json").read_text(encoding="utf-8"))
    if _back.get("unread_notes") != rec["unread_notes"]:
        raise SystemExit(D + " the record on disk does not match what was just computed.")
    print()
    print("  written to UNREAD-NOTES.json and read back")
    print("=" * 78)
    return 1 if still else 0


if __name__ == "__main__":
    raise SystemExit(main())
