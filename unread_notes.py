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
HERE = pathlib.Path(__file__).resolve().parent
SUITE = ("mp_metric.py", "replay.py", "check_facts.py")


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
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
    root = work / "census"
    shutil.copytree(HERE, root, dirs_exist_ok=True)
    try:
        mutated = json.loads(json.dumps(led))
        for c in mutated["cells"]:
            if (c.get("score") == 0 and not isinstance(c.get("bound"), dict)
                    and str(c.get("note") or "").strip()):
                c["note"] = ""
        (root / "cells.json").write_text(json.dumps(mutated, indent=2) + NL,
                                         encoding="utf-8", newline=NL)
        noticed = []
        for tool in SUITE:
            r = subprocess.run([sys.executable, "-X", "utf8", tool], cwd=str(root),
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace")
            out = (r.stdout or "") + (r.stderr or "")
            bad = (r.returncode != 0 or "DEFECT" in out
                   or ("validation:" in out and "no defects" not in out))
            print("  %-16s %s" % (tool, "NOTICED" if bad else "did not notice"))
            if bad:
                noticed.append(tool)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    rec = {"_what": ("The number of zero-cell notes that can be blanked with the whole suite "
                     "still green. It is measured, not asserted: the notes are blanked in a copy "
                     "and the suite is run against it."),
           "zeros": len(zeros), "bounded_zeros": len(bounded),
           "unread_notes": 0 if noticed else len(target),
           "noticed_by": noticed, "suite": list(SUITE)}
    (HERE / "UNREAD-NOTES.json").write_text(json.dumps(rec, indent=2) + NL,
                                            encoding="utf-8", newline=NL)
    print()
    if noticed:
        print("  %d note(s) blanked and %s NOTICED. The prose is load-bearing after all;"
              % (len(target), ", ".join(noticed)))
        print("  update the paper, which currently reports that nothing reads it.")
    else:
        print("  " + D + " %d NOTE(S) BLANKED AND NOTHING NOTICED." % len(target))
        print("  Every one of them states a search bound, a reason and a date for a zero, and no")
        print("  tool in this project reads a character of it. That is the difference between the")
        print("  %d bounded zeros and the rest: a bound is executed, a note is decoration."
              % len(bounded))
    print()
    print("  written to UNREAD-NOTES.json")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
