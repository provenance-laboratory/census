"""Which categories does the cs.CL/cs.LG filter actually remove?

A homonym (Pythia the physics generator) and a neighbouring ML category (cs.CV) are excluded by
the same rule for very different reasons. Counting exclusions cannot tell them apart; the primary
category can.
"""
import json, re, time, urllib.parse, urllib.request, collections, pathlib

UA = "mp-metric-bound-probe (mailto:parthms.id@gmail.com)"
HERE = pathlib.Path(__file__).resolve().parent
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
    req = urllib.request.Request(u, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=120) as r:
        body = r.read().decode("utf-8", "replace")
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
json.dump({"cats": cats, "ids": ids}, open(HERE / "filter-cats.json", "w", encoding="utf-8"), indent=1)
print()
print("  wrote filter-cats.json")
