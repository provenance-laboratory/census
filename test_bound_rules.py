"""Positive controls for the bound rules: watch every one of them fail before trusting any.

A control nobody has watched fail is indistinguishable from a comment, and this project has
shipped several. Each mutation below is applied to a COPY of the census -- never to the tree --
because an interrupted in-place mutation run once left a neutered mp_metric.py that was then
committed and shipped.
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


def run(root, argv):
    r = subprocess.run([sys.executable, "-X", "utf8"] + argv, cwd=str(root),
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def find(led, sub, ax):
    for c in led["cells"]:
        if c["subject"] == sub and c["axis"] == ax:
            return c
    raise SystemExit("no such cell")


MUTATIONS = [
    # ⛔ THE ROUND-14 REVIEWER'S EXACT ATTACK. They replaced pythia axis 14's five-item searched
    # list with ["nothing-but-a-nonempty-placeholder"] and asserts/observed with "x", and BOTH the
    # validator and replay passed -- the bounds tested structure, not substance. It is a control
    # now, so the hole cannot reopen silently.
    ("the reviewer's placeholder attack, verbatim",
     lambda L: (find(L, "pythia-12b", 14)["bound"].__setitem__(
         "searched_archived", ["nothing-but-a-nonempty-placeholder"]),
         find(L, "pythia-12b", 14)["bound"].__setitem__("asserts", "x"),
         find(L, "pythia-12b", 14)["bound"].__setitem__("observed", "x")),
     "mp_metric.py", "Archived means archived"),
    ("delete bound.searched_archived",
     lambda L: find(L, "pythia-12b", 14)["bound"].pop("searched_archived"),
     "mp_metric.py", "declares no `searched_archived`"),
    ("pass off a live lookup as archived",
     lambda L: find(L, "olmo-2-13b", 15)["bound"]["searched_archived"].append(
         "https://keys.openpgp.org/vks/v1/by-fingerprint/DEADBEEF"),
     "mp_metric.py", "no evidence record"),
    ("understate an archived location as live",
     lambda L: find(L, "olmo-2-13b", 15)["bound"]["searched_live"].append(
         find(L, "olmo-2-13b", 15)["bound"]["searched_archived"][0]),
     "mp_metric.py", "is still a misdescription"),
    ("blank bound.observed",
     lambda L: find(L, "pythia-12b", 14)["bound"].__setitem__("observed", "  "),
     "mp_metric.py", "bound.observed is empty"),
    ("drop bound.as_of",
     lambda L: find(L, "olmo-2-13b", 14)["bound"].__setitem__("as_of", ""),
     "mp_metric.py", "bound.as_of is empty"),
    ("bound on a scored cell",
     lambda L: find(L, "pythia-12b", 13).__setitem__("bound", dict(
         find(L, "pythia-12b", 14)["bound"])),
     "mp_metric.py", "A bound belongs on a zero"),
    ("bound method that cannot settle the axis",
     lambda L: find(L, "pythia-12b", 14)["bound"].__setitem__("method", "http_range"),
     "mp_metric.py", "cannot settle this axis"),
    ("unregistered bound method",
     lambda L: find(L, "pythia-12b", 14)["bound"].__setitem__("method", "read_it_carefully"),
     "mp_metric.py", "is not registered"),
    ("strip the bound's evidence",
     lambda L: find(L, "qwen2.5-7b", 14).__setitem__("evidence", []),
     "mp_metric.py", "NO evidence record"),
    ("delete a bound entirely (coverage ratchet)",
     lambda L: find(L, "mistral-7b-v0.3", 14).pop("bound"),
     "mp_metric.py", "COVERAGE FELL"),
    # ⚠ THIS EXPECTED THE SUBSTRING "the cell declares" AND THE MESSAGE NOW SAYS "this cell
    # declares", so the control reported MISSED against a rejection that had happened correctly.
    # A substring is not a token -- the same defect that produced three false verdicts in this
    # project in one day. Matched on the distinctive clause instead.
    ("claim the platform key is the publisher's",
     lambda L: find(L, "pythia-12b", 14)["bound"].__setitem__(
         "expect_signer_fingerprint", "0" * 40),
     "replay.py", "must be rescored"),
    ("claim a README edit was a weight upload",
     lambda L: find(L, "olmo-2-13b", 14)["bound"].__setitem__(
         "expect_commit_subject", "Adding safetensors weights"),
     "replay.py", "the cell declares"),
    ("drop the shared-signer requirement",
     lambda L: find(L, "pythia-12b", 14)["bound"].pop(
         "expect_signer_is_shared_across_publishers"),
     "replay.py", "silently disables"),
    ("claim an unsigned commit is signed",
     lambda L: find(L, "bloom-176b", 14)["bound"].__setitem__("expect_signed", True),
     "replay.py", "carries no a signature"),
    ("transplant another subject's commit object",
     lambda L: find(L, "qwen2.5-7b", 14).__setitem__(
         "evidence", list(find(L, "pythia-12b", 14)["evidence"])),
     "replay.py", "found 0"),
    ("point the bound at a different revision",
     lambda L: find(L, "olmo-2-13b", 14)["bound"].__setitem__("expect_revision", "a" * 40),
     "replay.py", "the cell declares"),
]


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    print("=" * 78)
    print("  POSITIVE CONTROLS for the bound rules -- each must be REJECTED")
    print("=" * 78)
    print()
    base = json.loads((HERE / "cells.json").read_text(encoding="utf-8"))
    caught = missed = 0
    work = pathlib.Path(tempfile.mkdtemp(prefix="bound-controls-"))
    root = work / "census"
    shutil.copytree(HERE, root, dirs_exist_ok=True)
    for name, mutate, tool, expect in MUTATIONS:
        led = json.loads(json.dumps(base))
        try:
            mutate(led)
        except Exception as e:                                              # noqa: BLE001
            print("  %-46s MUTATION FAILED: %s" % (name, e))
            missed += 1
            continue
        (root / "cells.json").write_text(json.dumps(led, indent=2) + NL,
                                         encoding="utf-8", newline=NL)
        rc, out = run(root, [tool])
        hit = expect.lower() in out.lower()
        if hit:
            print("  caught  %-44s (%s)" % (name, tool))
            caught += 1
        else:
            print("  " + D + " MISSED %-44s (%s, rc=%d)" % (name, tool, rc))
            print("      expected to see: %r" % expect)
            missed += 1
    shutil.rmtree(work, ignore_errors=True)
    print()
    print("  %d caught, %d MISSED" % (caught, missed))
    print("=" * 78)
    return 1 if missed else 0


if __name__ == "__main__":
    raise SystemExit(main())
