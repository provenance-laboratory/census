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


METHODS = {"count_lines_matching": m_count_lines_matching, "byte_length": m_byte_length}


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
