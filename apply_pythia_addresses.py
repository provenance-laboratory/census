"""The Pythia source correction reached axis 2 and stopped. This applies it to the other cells.

WHAT HAPPENED. Round 30 established, from the publisher's own Reproducing Training instructions,
that pythia-12b's training corpus is `EleutherAI/pile-standard-pythia-preshuffled` and not
`EleutherAI/pile`, which is the loader. Axis 2 was re-settled at the corrected address. Axis 3 was
left bounded at the loader -- three files, none of them the corpus -- while printing one of the
four headline zeros. Axis 4 was left scored 1 from prose at the same disowned address, and section
3.1 built its cleanest contrast on that 1.

A round-31 reviewer put it exactly: this census already carries the general form of the lesson, as
a comment in `test_bound_rules.py` about `mkdtemp` -- "a fix is not finished until the other call
sites have been read" -- and it was not applied to source addresses.

WHAT THIS DOES, and it is not a re-labelling:

  axis 3   re-bounds the search at the corpus repository. 23 files enumerated instead of 3, none
           matching any timestamp-or-signature pattern. The score stays 0 and the BOUND becomes
           true of the thing the axis is about.

  axis 4   PROBES, and the answer changes the score. A byte-range request against a corpus shard
           returns HTTP 206 with real token data, which is the same probe and the same standard
           that earns olmo-2-13b its 2. 1 -> 2, settled by artifact rather than asserted from a
           dataset card.

  the subject declares the superseded address, so nothing can quietly go on using it.

Run with --check to see what it would do without writing.
"""
import hashlib
import json
import pathlib
import struct
import sys

import fetch_artifact as F

sys.stdout.reconfigure(encoding="utf-8")
D, W, OK, AR = chr(0x26D4), chr(0x26A0), "ok ", chr(0x21D2)
NL = chr(10)
HERE = pathlib.Path(__file__).resolve().parent
LEDGER = HERE / "cells.json"

SUBJECT = "pythia-12b"
LOADER = "EleutherAI/pile"
CORPUS = "EleutherAI/pile-standard-pythia-preshuffled"
CORPUS_REV = "bac79b6820adb34e451f9a02cc1dc7cd920febf0"
MODEL_REPO = "EleutherAI/pythia-12b"
MODEL_REV = "bb1e3e710cdf6b524461d543cfb5ba773f0a81b6"

TREE = "https://huggingface.co/api/datasets/%s/tree/%s" % (CORPUS, CORPUS_REV)
BASE = "https://huggingface.co/datasets/%s/resolve/%s/" % (CORPUS, CORPUS_REV)
CONFIG = "https://huggingface.co/%s/raw/%s/config.json" % (MODEL_REPO, MODEL_REV)
SHARD = "document-00000-of-00020.bin"


def fetch(url, rng=None):
    rec, why = (F.evidence_range(url, *rng) if rng else F.evidence(url))
    if rec is None:
        raise SystemExit("%s could not retrieve %s -- %s" % (D, url, why))
    return rec


def main():
    dry = "--check" in sys.argv
    led = json.loads(LEDGER.read_text(encoding="utf-8"))
    cells = {(c["subject"], c["axis"]): c for c in led["cells"]}

    print("=" * 88)
    print("  THE PYTHIA SOURCE CORRECTION, APPLIED TO THE CELLS IT DID NOT REACH")
    print("=" * 88)

    # ---- the enumeration both axes rest on -------------------------------------------------
    tree_rec = fetch(TREE)
    entries = json.loads(tree_rec["body"].decode("utf-8"))
    files = [e["path"] for e in entries if e.get("type") == "file"]
    print("  %s %s@%s enumerates %d file(s)" % (OK, CORPUS, CORPUS_REV[:8], len(files)))
    if SHARD not in files:
        raise SystemExit("%s %s is not in the enumeration; the revision moved" % (D, SHARD))
    index = files.index(SHARD)

    # ---- axis 3: the same question, asked at the corpus -------------------------------------
    old3 = cells[(SUBJECT, 3)]
    patterns = old3["bound"]["expect_patterns"]
    import re as _re
    matches = [f for f in files if any(_re.search(p, f) for p in patterns)]
    print("  %s axis 3: %d of %d file(s) match a timestamp-or-signature pattern"
          % (OK, len(matches), len(files)))

    # ---- axis 4: the probe that was never run ------------------------------------------------
    rng_rec = fetch(BASE + SHARD, rng=(0, 2047))
    body = rng_rec["body"]
    n = len(body) // 2
    vals = struct.unpack("<%dH" % n, body[:n * 2])
    cfg_rec = fetch(CONFIG)
    cfg = json.loads(cfg_rec["body"].decode("utf-8"))
    vocab = int(cfg["vocab_size"])
    over = sum(1 for x in vals if x >= vocab)
    print("  %s axis 4: HTTP %s, %d byte(s); %d uint16 word(s), max %d, %d at or above the "
          "model's declared vocab_size %d"
          % (OK, rng_rec["http_status"], len(body), n, max(vals), over, vocab))
    if over:
        raise SystemExit("%s the retrieved bytes are not a token stream under this vocabulary; "
                         "the score must not move on this evidence" % D)
    wide = len(body) // 4
    wide_ok = all(x < vocab for x in struct.unpack("<%dI" % wide, body[:wide * 4]))
    print("  %s the same bytes read as uint32: %s"
          % (OK, "ALSO a valid token stream -- the width proves nothing" if wide_ok
             else "every word above the bound, so the declared width discriminates"))
    if wide_ok:
        raise SystemExit("%s the width does not discriminate" % D)

    if dry:
        print("  --check: nothing written")
        return 0

    # ---- write ------------------------------------------------------------------------------
    old3["note"] = (
        "No timestamp over the corpus digest: %d files enumerated at %s@%s, none matching any "
        "declared timestamp or signature artifact pattern. %s THIS BOUND WAS PREVIOUSLY TAKEN AT "
        "%s -- the LOADER, three files -- while this cell printed one of the four headline zeros. "
        "The round-30 correction that established the corpus address was applied to axis 2 and "
        "went no further. The zero is unchanged; what changed is that the search now happened at "
        "the corpus. The enumeration is a pinned subtree, and a dated signed publication outside "
        "the repository would not appear in it."
        % (len(files), CORPUS, CORPUS_REV[:8], AR, LOADER))
    old3["bound"].update({
        "observed": (
            "%d file(s) are enumerated at %s@%s (the repository root) and NONE matches any of %d "
            "declared timestamp-or-signature patterns. %s The 22 Git-LFS entries carry sha256 oids "
            "-- which is what axis 2 scores -- and a digest is not a timestamp: nothing here dates "
            "one, and nothing signs one. %s WHAT THE ZERO MEANS AND WHERE IT STOPS: no such FILE "
            "is published in this enumeration. The axis's second limb, a dated signed publication "
            "predating the training run, is not a repository property and is not settled here."
            % (len(files), CORPUS, CORPUS_REV[:8], len(patterns), W, W)),
        "searched_archived": [TREE],
        "as_of": rng_rec["retrieved"],
        "expect_repo": CORPUS,
        "expect_revision": CORPUS_REV,
        "expect_matches": len(matches),
        "expect_evidence_sha256": tree_rec["sha256"],
    })
    old3["evidence"] = [{"url": TREE, "retrieved": tree_rec["retrieved"],
                         "sha256": tree_rec["sha256"]}]

    old4 = cells[(SUBJECT, 4)]
    old4["score"] = 2
    old4.pop("note", None)
    old4["check"] = {
        "method": "http_range",
        "asserts": ("a third party can acquire this model's training bytes: a byte-range request "
                    "against a corpus shard the publisher names for this configuration returns "
                    "real token content"),
        "observed": (
            "Range 0-2047 on %s%s returned HTTP %s with 2048 bytes, which are %d little-endian "
            "uint16 token ids, every one below the model config's declared vocab_size of %d "
            "(maximum %d). Read at the other width this executor knows, every word is above the "
            "bound, so the declared width discriminates. The pinned tree enumerates %d files. "
            "%s THIS CELL WAS A 1, ASSERTED FROM A DATASET CARD AT %s -- the loader repository, "
            "the address section 8 disowns -- with the note 'the original distribution host "
            "returns 000'. That host is still gone; the publisher's Reproducing Training section "
            "names THIS repository for this configuration, and it answers. The probe is the one "
            "that earns olmo-2-13b its 2 on this axis, run at the address the corpus actually "
            "lives at. %s A RESIDUAL BOUND, STATED: the ranged url and its recorded position in "
            "the enumeration are both fields this ledger's author writes, so the token-width "
            "property above is what does not move with them."
            % (BASE, SHARD, rng_rec["http_status"], n, vocab, max(vals), len(files), AR, LOADER,
               W)),
        "enumeration": {"kind": "hf_tree_json", "base": BASE},
        "enumerated_index": index,
        "byte_property": {
            "kind": "uint16_token_stream",
            "count": n,
            "vocab_bound": vocab,
            "max_id": max(vals),
            "_how": ("recomputed from the archived range by m_range. The bound is not typed: it is "
                     "`vocab_size` read from %s, whose bytes hash to %s. The corpus's own "
                     "`document.idx` independently declares the width -- its header is the "
                     "Megatron magic MMIDIDX followed by dtype code 8, which is uint16."
                     % (CONFIG, cfg_rec["sha256"][:32])),
        },
    }
    old4["evidence"] = [
        {"url": TREE, "retrieved": tree_rec["retrieved"], "sha256": tree_rec["sha256"]},
        {"url": BASE + SHARD, "retrieved": rng_rec["retrieved"], "sha256": rng_rec["sha256"],
         "range": rng_rec["range"]},
    ]

    # ---- and the address itself is declared superseded --------------------------------------
    for s in led["subjects"]:
        if s["id"] == SUBJECT:
            s["superseded_sources"] = {
                LOADER: {
                    "superseded_by": CORPUS,
                    "for": "any axis whose question is about the training corpus itself",
                    "why": ("the publisher's Reproducing Training section names the "
                            "standard/preshuffled repository as this configuration's training "
                            "data; %s is the loader, and a statement true of a loader says "
                            "nothing about the corpus" % LOADER),
                    "still_valid_for": [1, 19],
                    "_note": ("axes 1 and 19 ask what the dataset card SAYS about composition and "
                              "licensing, which is a claim about the published record and is "
                              "correctly read at the loader's card."),
                }
            }
    LEDGER.write_text(json.dumps(led, indent=2) + NL, encoding="utf-8", newline=NL)
    print()
    print("  %s axis 3 re-bounded at the corpus; axis 4 probed and rescored 1 -> 2" % OK)
    print("  %s %s is declared superseded on the subject, for corpus questions" % (OK, LOADER))
    print("  %s run archive_evidence.py to store the new artifacts, then replay.py" % W)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
