"""Do the search's terms retrieve DIFFERENT papers? Two of them never did.

⛔ WHY THIS EXISTS. The negative search issues seven reproduction verbs per subject and the paper
reported *"84 recorded queries using 7 reproduction verbs"*. A round-5 reviewer noticed that
`replicate` and `replication` returned the same totals for every subject, and they were right about
the cause: **arXiv stems the two to one token, so the two queries are one query.** Seven verbs are
six. Eighty-four queries are seventy-two, plus twelve restatements.

⚠️ THIS IS NOT A LARGE ERROR AND THAT IS RATHER THE POINT. The bound was not overstated by much —
it was overstated in the one direction that matters, because the section exists to say exactly how
wide the search was, and a reader counting distinct probes was given a number that counted a probe
twice. A bound is a claim about coverage, so an inflated bound is an inflated negative.

⇒ So the count is MEASURED here rather than asserted anywhere: the archived response body for each
term is decompressed, its arXiv identifiers are parsed, and terms whose identifier SETS coincide
across every subject are reported as one probe.

⛔ AND THE CONTROL IS THE HALF THAT MAKES IT MEAN ANYTHING. `reproduce` and `reproduction` are
compared the same way and DIFFER for every subject. Without that, "the sets are identical" could as
easily be a broken parser as a property of the search — and it nearly was: the first version of this
comparison read the gzipped bodies as text, parsed zero identifiers from both, and reported
`IDENTICAL: True` because two empty sets are equal. Absence is not agreement, in the script written
to check the census for absence defects.

    python stem_equivalence.py            recompute and rewrite stem-equivalence.json
    python stem_equivalence.py --verify   recompute and refuse if it disagrees with the record
"""
import gzip
import io
import json
import pathlib
import re
import sys

NL = chr(10)
D = chr(0x26D4)
W = chr(0x26A0)
HERE = pathlib.Path(__file__).resolve().parent
EVIDENCE = HERE / "evidence"
ARCHIVE = HERE / "negative-search-archive.json"
OUT = HERE / "stem-equivalence.json"

ID_RE = re.compile(r"arxiv\.org/abs/([0-9]+\.[0-9]+)")


def ids_for(sha):
    """The arXiv identifiers in one archived response, or None if none could be parsed.

    ⛔ None IS NOT AN EMPTY SET. A response that legitimately returned no results and a body this
    parser could not read are different facts, and collapsing them is how the first draft of this
    check reported every pair as identical.
    """
    p = EVIDENCE / (sha + ".gz")
    if not p.exists():
        return None
    try:
        body = gzip.decompress(p.read_bytes()).decode("utf-8", "replace")
    except (OSError, EOFError):
        return None
    if "<entry" not in body and "<feed" not in body:
        return None
    return set(ID_RE.findall(body))


def measure():
    arc = json.loads(ARCHIVE.read_text(encoding="utf-8"))
    subs = arc["subjects"]
    items = subs.items() if isinstance(subs, dict) else [(s.get("subject"), s) for s in subs]

    per_subject, terms = {}, []
    for name, entries in items:
        # ⛔ THIS ASSIGNED ONE RESPONSE PER TERM, so a paginated query contributed whichever
        # page came last and the identifier set was silently capped at one page. A round-16
        # reviewer spotted the tell before the archive was even fixed: this file printed
        # "from scratch": 100 beside negative-search.json's 121, two files claiming to measure
        # the same bytes, and nothing compared them. The pages of one query are UNIONED now --
        # the measurement of how wide the search was must not itself read a truncated copy.
        by_term = {}
        for e in entries:
            got = ids_for(e["sha256"])
            if got is None:
                by_term[e["term"]] = None
                continue
            prev = by_term.get(e["term"])
            by_term[e["term"]] = got if prev is None and e["term"] not in by_term else (
                (prev | got) if prev is not None else got)
        terms = terms or list(by_term)
        per_subject[name] = by_term

    # ⇒ group terms that retrieved the SAME identifiers on every subject where both are readable
    groups, seen = [], set()
    for a in terms:
        if a in seen:
            continue
        group, evidence = [a], {}
        for b in terms:
            if b == a or b in seen:
                continue
            comparable = agree = witnessed = 0
            for name, by_term in per_subject.items():
                ia, ib = by_term.get(a), by_term.get(b)
                if ia is None or ib is None:
                    continue
                comparable += 1
                agree += ia == ib
                # ⛔ TWO TERMS THAT BOTH RETURN NOTHING ON EVERY SUBJECT WOULD COMPARE EQUAL
                # EVERY TIME and be declared one probe -- absence as agreement, inside the check
                # written to state a bound honestly. Equivalence needs at least one subject where
                # BOTH terms actually retrieved something.
                witnessed += bool(ia) and bool(ib) and ia == ib
            # ⚠ EQUIVALENCE MUST BE OBSERVED, NOT ASSUMED FROM SILENCE: a pair that could never
            # be compared, or was only ever jointly empty, is NOT equivalent.
            if comparable and agree == comparable and witnessed:
                group.append(b)
                evidence[b] = {"subjects_compared": comparable, "identical": agree,
                               "both_non_empty": witnessed}
        for g in group:
            seen.add(g)
        groups.append({"terms": group, "evidence": evidence})

    issued_terms = len(terms)
    distinct_terms = len(groups)
    issued_queries = sum(len(v) for v in per_subject.values())
    distinct_queries = sum(
        sum(1 for g in groups if any(per_subject[n].get(t) is not None for t in g["terms"]))
        or len(groups)
        for n in per_subject)

    # the control: a pair that MUST differ, or the comparison proves nothing
    ctl_pair = ("reproduce", "reproduction")
    ctl = {"pair": list(ctl_pair), "compared": 0, "differ": 0}
    for name, by_term in per_subject.items():
        ia, ib = by_term.get(ctl_pair[0]), by_term.get(ctl_pair[1])
        if ia is None or ib is None:
            continue
        ctl["compared"] += 1
        ctl["differ"] += ia != ib
    ctl["passes"] = ctl["compared"] > 0 and ctl["differ"] == ctl["compared"]

    return {
        "_readme": ("Measured from the archived response bodies, not asserted. Terms whose arXiv "
                    "identifier sets coincide on every comparable subject are ONE probe. The "
                    "control pair must DIFFER, or an identical result would be indistinguishable "
                    "from a broken parser."),
        "as_of": arc.get("as_of"),
        "terms_issued": issued_terms,
        "terms_distinct": distinct_terms,
        "queries_issued": issued_queries,
        "queries_distinct": distinct_queries,
        "groups": [{"terms": g["terms"], "evidence": g["evidence"]} for g in groups],
        "control": ctl,
        "subjects": {n: {t: (None if v is None else len(v)) for t, v in bt.items()}
                     for n, bt in per_subject.items()},
    }


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    got = measure()

    print("=" * 78)
    print("  STEM EQUIVALENCE — how many of the search's terms are distinct probes?")
    print("=" * 78)
    print()
    for g in got["groups"]:
        if len(g["terms"]) == 1:
            print("  %-22s distinct" % g["terms"][0])
        else:
            ev = g["evidence"]
            print("  " + W + " %s" % " == ".join(g["terms"]))
            for t, d in ev.items():
                print("      identical identifier sets on %d of %d comparable subject(s); "
                      "both non-empty on %d"
                      % (d["identical"], d["subjects_compared"], d["both_non_empty"]))
    print()
    c = got["control"]
    print("  CONTROL %s vs %s: differ on %d of %d comparable subject(s)  %s"
          % (c["pair"][0], c["pair"][1], c["differ"], c["compared"],
             "ok" if c["passes"] else D + " THE COMPARISON PROVES NOTHING"))
    print()
    print("  terms   issued %d, distinct %d" % (got["terms_issued"], got["terms_distinct"]))
    print("  queries issued %d, distinct %d" % (got["queries_issued"], got["queries_distinct"]))
    print()

    if not c["passes"]:
        print("  " + D + " Without a control pair that DIFFERS, an identical result is as likely")
        print("  to be a parser that reads nothing as a property of the search.")
        return 1

    if "--verify" in sys.argv:
        if not OUT.exists():
            print("  " + D + " %s is absent; nothing to verify against." % OUT.name)
            return 1
        rec = json.loads(OUT.read_text(encoding="utf-8"))
        # ⛔ THIS COMPARED FOUR SCALARS AND PRINTED "the record matches what the archived
        # responses say", which is a claim about the whole file. A round-16 reviewer flipped the
        # stored control's `passes` from true to false and --verify still exited 0: `passes` is
        # RECOMPUTED live a few lines above, so the stored value was never read by anything. The
        # groups, the per-subject counts, the evidence and the control were all unchecked.
        #
        # ⚠ `as_of` and `_readme` are excluded BY NAME and for a stated reason -- one is a date
        # and the other is prose, and neither is recomputable from the archive. Everything that
        # IS recomputed is compared, by projecting over the recomputed record's own keys rather
        # than over a list somebody maintains.
        _skip = {"as_of", "_readme"}
        drift = sorted(k for k in set(got) | (set(rec) - _skip)
                       if k not in _skip and rec.get(k) != got.get(k))
        if drift:
            print("  " + D + " the record disagrees with the bytes on: %s" % ", ".join(drift))
            for k in drift:
                a, b = rec.get(k), got.get(k)
                if isinstance(a, (dict, list)) or isinstance(b, (dict, list)):
                    print("      %-18s recorded and recomputed differ in structure" % k)
                else:
                    print("      %-18s recorded %s, recomputed %s" % (k, a, b))
            return 1
        print("  ok  every recomputable field matches what the archived responses say")
        print("      (%d field(s) compared; as_of and _readme are not recomputable)"
              % len(set(got) - _skip))
        return 0

    OUT.write_text(json.dumps(got, indent=2) + NL, encoding="utf-8")
    print("  wrote %s" % OUT.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
