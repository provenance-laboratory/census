"""Which categories does the cs.CL/cs.LG filter actually remove?

A homonym (Pythia the physics generator) and a neighbouring ML category (cs.CV) are excluded by
the same rule for very different reasons. Counting exclusions cannot tell them apart; the primary
category can.
"""
import gzip
import hashlib
import sys
import json, re, time, urllib.parse, urllib.request, collections, pathlib

UA = "mp-metric-bound-probe (mailto:parthms.id@gmail.com)"
HERE = pathlib.Path(__file__).resolve().parent
STORE = HERE / "evidence"
d = json.load(open(HERE / "filter-diff.json", encoding="utf-8"))
ids = {}
for subj, hits in d.items():
    for url in hits:
        m = re.search(r"abs/(.+)$", url)
        if m:
            ids.setdefault(m.group(1), []).append(subj)
print("  %d distinct excluded paper(s) across %d subject(s)" % (len(ids), len(d)))

cats = {}
todo = sorted(ids)
for i in range(0, len(todo), 80):
    chunk = todo[i:i+80]
    u = ("https://export.arxiv.org/api/query?id_list=%s&max_results=100"
         % urllib.parse.quote(",".join(chunk), safe=","))
    # ⛔ THIS FETCHED LIVE AND ARCHIVED NOTHING, so the figures section 8 actually turns on --
    # 0 of Pythia's exclusions adjacent, 42 of Qwen's 43 -- were not reproducible offline even
    # after the round-17 repair made the EXCLUSION SETS reproducible. The offline command borrowed
    # credit from a different control: it recomputed the sets and left the numerators unchecked.
    #
    # ⚠ Archived by digest, exactly like every other response in this census, and read before the
    # network so a reader recomputes from bytes rather than from arXiv's mood today.
    # ⛔ THE BLOB WAS NAMED BY THE REQUEST URL AND NEVER BY ITS CONTENT. A round-19 reviewer
    # changed the bytes of an archived category response without changing the ids or categories it
    # parses to, and every control stayed green -- `--offline` resolved 354, `--verify` said the
    # record matched, `archive_evidence.py --verify` agreed. The derivation was replayable and the
    # SOURCE BYTES were unprotected, in the one census whose subject is that distinction. And the
    # blobs were in no manifest, so archive_evidence counted them among files referenced by
    # nothing.
    #
    # ⚠ URL -> body digest is recorded beside the store, and a body that does not hash to its
    # record is refused rather than parsed.
    _key = hashlib.sha256(u.encode("utf-8")).hexdigest()
    _blob = STORE / ("catprobe-" + _key + ".gz")
    _man = HERE / "filter-cats-archive.json"
    _reg = json.loads(_man.read_text(encoding="utf-8")) if _man.exists() else {"responses": {}}
    if _blob.exists():
        _raw = gzip.decompress(_blob.read_bytes())
        _got = hashlib.sha256(_raw).hexdigest()
        _want = (_reg["responses"].get(u) or {}).get("sha256")
        if _want and _got != _want:
            raise SystemExit(chr(0x26D4) + " an archived category response does not hash to its "
                             "record: %s says %s, the bytes are %s. The derivation would still "
                             "have replayed." % (u[:60], _want[:16], _got[:16]))
        if not _want:
            _reg["responses"][u] = {"sha256": _got, "bytes": len(_raw)}
            _man.write_text(json.dumps(_reg, indent=1, sort_keys=True) + chr(10),
                            encoding="utf-8", newline=chr(10))
        body = _raw.decode("utf-8", "replace")
    elif "--offline" in sys.argv:
        raise SystemExit(chr(0x26D4) + " a category lookup is not archived and --offline was "
                         "given. Run filter_categories.py once with network to archive it.")
    else:
        req = urllib.request.Request(u, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=120) as r:
            body = r.read().decode("utf-8", "replace")
        _raw = body.encode("utf-8")
        _blob.write_bytes(gzip.compress(_raw, mtime=0))
        _reg["responses"][u] = {"sha256": hashlib.sha256(_raw).hexdigest(), "bytes": len(_raw)}
        _man.write_text(json.dumps(_reg, indent=1, sort_keys=True) + chr(10),
                        encoding="utf-8", newline=chr(10))
    for m in re.finditer(r"<entry>(.*?)</entry>", body, re.S):
        e = m.group(1)
        i2 = re.search(r"<id>([^<]+)</id>", e)
        pc = re.search(r'<arxiv:primary_category[^>]*term="([^"]+)"', e)
        if i2 and pc:
            k = re.search(r"abs/(.+)$", i2.group(1).strip())
            if k:
                cats[k.group(1)] = pc.group(1)
    time.sleep(3.1)

print("  resolved %d primary categories" % len(cats))
ML = {"cs.CV", "cs.AI", "cs.SE", "cs.IR", "cs.RO", "cs.HC", "cs.NE", "cs.MA", "cs.CR", "cs.DC", "stat.ML"}
per = collections.Counter()
per_subj = collections.defaultdict(collections.Counter)
for k, c in cats.items():
    per[c] += 1
    for s in ids.get(k, []):
        per_subj[s][c] += 1
print()
print("  most common primary categories among EXCLUDED papers:")
for c, n in per.most_common(14):
    tag = "  <- adjacent ML/CS" if c in ML else ("  <- physics/other" if not c.startswith("cs.") else "")
    print("    %-12s %4d%s" % (c, n, tag))
print()
print("  per subject: how many excluded papers are in an ADJACENT CS/ML category")
for s in sorted(per_subj):
    tot = sum(per_subj[s].values())
    adj = sum(n for c, n in per_subj[s].items() if c in ML)
    print("    %-20s %3d of %3d excluded are adjacent CS/ML  %s"
          % (s, adj, tot, ",".join("%s:%d" % (c, n) for c, n in per_subj[s].most_common(3))))
# ⚠ json.dump(open(...)) DOES NOT PIN THE NEWLINE EITHER. The write_text fix swept
# five modules and missed this one, because it is a different call shape -- the same class of
# defect surviving a sweep aimed at one of its spellings.
(HERE / "filter-cats.json").write_text(
    json.dumps({"cats": cats, "ids": ids}, indent=1) + chr(10),
    encoding="utf-8", newline=chr(10))
print()
print("  wrote filter-cats.json")
