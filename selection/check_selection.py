"""Recompute the claims Amendment 1 makes about the download ranking.

⛔ WHY THIS IS A SCRIPT AND NOT A PARAGRAPH. Amendment 1 says the pre-registered criterion does not
select the scored subjects. That is the single most damaging sentence about this census, and a
damaging sentence a reader cannot check is worth no more than a flattering one. The ranks below are
read out of the deposited snapshots every time, and the exit code is non-zero if the amendment says
something the snapshots do not support.

The snapshots are FROZEN EVIDENCE, retrieved 2026-08-29. Their digests are pinned here: a snapshot
that is silently refreshed would let this check pass for a claim about different data.
"""
import hashlib
import io
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
NL = chr(10)

PINNED = {
    "hf-downloads-rank.json":
        "316f61e497ce9be13425f3ef17098d191313b9ab297806f7ae9bfcc86fd31d19",
    "hf-downloads-frame.json":
        "4fe478527877b83c5e2f0139bc92d28f920e8bb60ece5b1f4e17e33af3953c53",
}
# The amendment's table. Ranks are ASSERTED here and CHECKED below; a subject absent from the
# frame is recorded as None, which is itself one of the amendment's claims.
CLAIMED = {
    "meta-llama/Llama-3.1-8B": 137,
    "Qwen/Qwen2.5-7B": 156,
    "google/gemma-2-9b": 719,
    "mistralai/Mistral-7B-v0.3": None,
}


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    bad = []

    for fn, want in PINNED.items():
        p = HERE / fn
        if not p.exists():
            bad.append("%s is missing" % fn)
            continue
        got = hashlib.sha256(p.read_bytes()).hexdigest()
        print("  %-28s %s" % (fn, "ok" if got == want else "DIGEST MOVED"))
        if got != want:
            bad.append("%s: pinned %s, found %s -- the snapshot was replaced, so every rank "
                       "below is a claim about different data" % (fn, want[:12], got[:12]))

    if bad:
        for b in bad:
            print("  ! %s" % b)
        return 1

    frame = json.loads((HERE / "hf-downloads-frame.json").read_text(encoding="utf-8"))
    rank = {m["id"]: i for i, m in enumerate(frame, 1)}
    print()
    print("  the four open-weights subjects, in the deposited frame of %d:" % len(frame))
    for sub, want in CLAIMED.items():
        got = rank.get(sub)
        agree = (got == want)
        print("    %-32s %-18s %s"
              % (sub, ("rank %d" % got) if got else "ABSENT",
                 "ok" if agree else "AMENDMENT SAYS %s" % want))
        if not agree:
            bad.append("%s: amendment says %r, frame says %r" % (sub, want, got))

    # The amendment's central claim, recomputed rather than repeated: rank order over distinct
    # organisations does not reach the scored subjects.
    seen, top4 = set(), []
    for m in frame:
        org = m["id"].split("/")[0]
        if org not in seen:
            seen.add(org)
            top4.append(m["id"])
        if len(top4) == 4:
            break
    print()
    print("  'rank order, one per organisation, until the stratum is filled' selects:")
    for i, x in enumerate(top4, 1):
        print("    %d. %s" % (i, x))
    overlap = set(top4) & set(CLAIMED)
    if overlap:
        bad.append("the literal rule DOES select %s -- the amendment's central claim is wrong"
                   % ", ".join(sorted(overlap)))
    else:
        print("  " + chr(0x21D2) + " none of the four scored subjects. This is the amendment's "
              "central claim,")
        print("      and it holds against the deposited frame.")

    print()
    if bad:
        print("  " + chr(0x26D4) + " %d PROBLEM(S):" % len(bad))
        for b in bad:
            print("      %s" % b)
        return 1
    print("  amendment 1 agrees with the deposited snapshots")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
