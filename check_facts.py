"""Recompute every named fact from the ARCHIVED BYTES it cites.

⛔ WHY. `facts.json` carried values with a sentence describing how each was obtained. That is the
ASSERTED level -- stated, with nothing a third party can run against it -- and this instrument
refuses to score a release 2 for exactly that. A paper that will not accept a described check from
its subjects cannot rely on one for its own numbers.

FAILS CLOSED, THREE WAYS. A fact whose method is not registered fails. A fact whose bytes are not
in the archive fails. A fact whose recomputed value differs from the recorded one fails. None of
them degrades to a warning: the alternative to a checked number here is no number, not a trusted
one.

⚠️ NOT AN ENUMERATION OF THE FACTS THAT EXIST. The loop projects over every entry in facts.json;
adding a fact with a method nobody registered breaks the build rather than passing unnoticed.
"""
import gzip
import hashlib
import io
import json
import pathlib
import re
import struct
import sys

NL = chr(10)
HERE = pathlib.Path(__file__).resolve().parent
STORE = HERE / "evidence"


def m_count_lines_matching(body, spec):
    text = body.decode("utf-8", "replace")
    hits = [ln for ln in text.split(NL) if re.match(spec["pattern"], ln)]
    need = spec.get("also_all_contain")
    if need and not all(need in ln for ln in hits):
        n = sum(1 for ln in hits if need not in ln)
        raise ValueError("%d of %d matching lines do not contain %r, so the fact's own "
                         "qualifier is false" % (n, len(hits), need))
    return len(hits)


def m_byte_length(body, _spec):
    return len(body)


def m_count_json_entries(body, spec):
    """Entries of a JSON array matching a field/value pair, recomputed from the archived bytes.

    Added for the pythia corpus enumeration, which is a Hugging Face tree response rather than a
    config listing paths on lines. The first attempt at these facts declared no method at all and
    this file refused them, which is the behaviour: a number the paper may print has to follow
    from bytes somebody can re-read, and prose describing how it was counted is not that.
    """
    rows = json.loads(body.decode("utf-8", "replace"))
    if not isinstance(rows, list):
        raise ValueError("the archived artifact is not a JSON array")
    field, value = spec["field"], spec["value"]
    return sum(1 for r in rows if isinstance(r, dict) and r.get(field) == value)


def m_token_ids_below(body, spec):
    """The count of fixed-width little-endian words in the range, all below a declared bound.

    THE HTTP STATUS WAS THE FIRST VERSION OF THIS FACT AND IT IS NOT RECOMPUTABLE. A 206 is a
    property of the channel at fetch time; it is nowhere in the bytes, so no reader could ever
    check it here. What the archived range does support is what it IS -- token ids of a declared
    width, every one under the model's vocabulary bound -- and that is the claim the paper needs
    anyway, since the point is that real corpus content came back rather than an error page.
    """
    width = {"uint16": ("<%dH", 2), "uint32": ("<%dI", 4)}[spec["width"]]
    n = len(body) // width[1]
    vals = struct.unpack(width[0] % n, body[:n * width[1]])
    over = [v for v in vals if v >= spec["below"]]
    if over:
        raise ValueError("%d of %d words are not below %d, so these bytes are not the token "
                         "stream this fact claims" % (len(over), n, spec["below"]))
    return n


METHODS = {"count_lines_matching": m_count_lines_matching, "byte_length": m_byte_length,
           "count_json_entries": m_count_json_entries, "token_ids_below": m_token_ids_below}


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    facts = json.loads((HERE / "facts.json").read_text(encoding="utf-8"))["facts"]
    bad = []
    print("=" * 78)
    print("  named facts, RECOMPUTED from archived bytes — %d" % len(facts))
    print("=" * 78)
    print()
    for name, f in sorted(facts.items()):
        meth = (f.get("method") or {}).get("name")
        if meth not in METHODS:
            print("  FAIL  %-22s method %r is not registered" % (name, meth))
            bad.append(name)
            continue
        sha = f["evidence"]["sha256"]
        blob = STORE / (sha + ".gz")
        if not blob.exists():
            print("  FAIL  %-22s bytes not archived (%s.gz); run archive_evidence.py"
                  % (name, sha[:12]))
            bad.append(name)
            continue
        body = gzip.decompress(blob.read_bytes())
        got_sha = hashlib.sha256(body).hexdigest()
        if got_sha != sha:
            print("  FAIL  %-22s archived bytes hash to %s, the fact cites %s"
                  % (name, got_sha[:12], sha[:12]))
            bad.append(name)
            continue
        try:
            got = METHODS[meth](body, f["method"])
        except ValueError as e:
            print("  FAIL  %-22s %s" % (name, e))
            bad.append(name)
            continue
        agree = (got == f["value"])
        print(("  ok    " if agree else "  FAIL  ") +
              "%-22s %s = %s" % (name, meth, got) +
              ("" if agree else "   RECORDED %s" % f["value"]))
        if not agree:
            bad.append(name)

    print()
    print("=" * 78)
    print("  %d ok, %d failing" % (len(facts) - len(bad), len(bad)))
    if bad:
        print("  " + chr(0x26D4) + " a number the paper may cite does not follow from the bytes")
        print("  it cites. Fix the fact or fix the method; do not adjust the value to match.")
    print("=" * 78)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
