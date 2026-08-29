"""Archive the artifacts the weight probes actually rest on, and bind them to their cells.

⛔ THE DEFECT. Axes 12 and 13 were scored 2 from a probe whose RESULTS were written into the cell
and whose ARTIFACTS were not kept. The ledger said "HTTP 206, 2048 B, is_pointer=False" and
"4/4 shards"; the archive held a single 136-byte Git-LFS pointer. The 2 KB weight range, its digest,
the per-shard pointers and the API response that enumerates them were all absent.

`replay.py`'s probe check then tested whether some cited URL contained `huggingface.co` -- so a
fabricated digest, a nonsense observation and a non-existent repository all came back
"shape-verified only". Both round-4 reviewers found this independently, and it is the paper's own
confessed defect surviving inside the fix for it: the number was reported and the artifact was not.

WHAT THIS STORES, per subject:

    api.json        the pinned /api/models/<repo>/revision/<sha> response, which ENUMERATES the
                    shards -- so a claimed shard count can be recomputed rather than believed
    <shard>.ptr     every shard's raw Git-LFS pointer, each carrying an oid sha256
    range.bin       the first 2 KB of the RESOLVED weight object -- real tensor bytes, not a
                    pointer -- with its own digest

⚠️ These are stored under `evidence/` like every other artifact, so `archive_evidence.py --verify`
covers them and `replay.py` can recompute both axes from bytes on disk.

    python bind_probe_evidence.py --dry-run
    python bind_probe_evidence.py
"""
import gzip
import hashlib
import io
import json
import pathlib
import re
import subprocess
import sys

NL = chr(10)
HERE = pathlib.Path(__file__).resolve().parent
STORE = HERE / "evidence"
LEDGER = HERE / "cells.json"
RANGE_BYTES = 2048


def curl(url, extra=None):
    cmd = ["curl", "-sSL", "--max-time", "180", "-w", "%{http_code}", "-o", "-"]
    if extra:
        cmd[1:1] = extra
    r = subprocess.run(cmd + [url], capture_output=True)
    if r.returncode != 0:
        return None, None, "curl exit %d" % r.returncode
    body = r.stdout
    code = body[-3:].decode("ascii", "replace")
    return code, body[:-3], None


def store(raw):
    """Gzip into evidence/<sha>.gz and return the digest. Never takes a digest from a caller."""
    h = hashlib.sha256(raw).hexdigest()
    (STORE / (h + ".gz")).write_bytes(gzip.compress(raw, 9))
    return h, len(raw)


def is_pointer(raw):
    return raw[:100].startswith(b"version https://git-lfs.github.com/spec/v1")


def gather(repo, rev):
    """Retrieve and store every artifact the two probe axes rest on."""
    out = {"repo": repo, "revision": rev, "shards": []}

    api_url = "https://huggingface.co/api/models/%s/revision/%s" % (repo, rev)
    code, body, err = curl(api_url)
    if err or code != "200" or not body:
        return None, "api %s: %s" % (code, err or "no body")
    sha, n = store(body)
    out["api"] = {"url": api_url, "sha256": sha, "bytes": n}
    try:
        files = [s["rfilename"] for s in json.loads(body).get("siblings", [])]
    except ValueError:
        return None, "api response is not json"
    shards = sorted(f for f in files
                    if re.search(r"\.(safetensors|bin)$", f) and "index" not in f)
    if not shards:
        return None, "no weight shards enumerated in the api response"
    out["shard_names"] = shards

    for f in shards:
        u = "https://huggingface.co/%s/raw/%s/%s" % (repo, rev, f)
        code, body, err = curl(u)
        if err or code != "200" or not body:
            return None, "shard pointer %s: %s" % (f, err or code)
        sha, n = store(body)
        oid = re.search(rb"oid sha256:([0-9a-f]{64})", body)
        out["shards"].append({"file": f, "url": u, "sha256": sha, "bytes": n,
                             "oid": oid.group(1).decode() if oid else None,
                             "is_pointer": is_pointer(body)})

    # ⛔ THE RANGE MUST BE OF THE RESOLVED OBJECT, NOT THE POINTER. /raw/ returns the pointer;
    # /resolve/ redirects to the bytes. The old cell claimed "is_pointer=False" about a range it
    # never kept, and what the archive held was the pointer.
    ru = "https://huggingface.co/%s/resolve/%s/%s" % (repo, rev, shards[0])
    code, body, err = curl(ru, ["-r", "0-%d" % (RANGE_BYTES - 1)])
    if err or not body:
        return None, "range: %s" % (err or "no body")
    if len(body) != RANGE_BYTES:
        return None, "range returned %d bytes, asked for %d" % (len(body), RANGE_BYTES)
    if is_pointer(body):
        return None, "the resolved range is STILL a pointer -- this is the defect, not the fix"
    sha, n = store(body)
    out["range"] = {"url": ru, "sha256": sha, "bytes": n, "http_status": code,
                    "range": "bytes=0-%d" % (RANGE_BYTES - 1), "is_pointer": False}
    return out, None


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    dry = "--dry-run" in sys.argv
    STORE.mkdir(exist_ok=True)
    led = json.loads(LEDGER.read_text(encoding="utf-8"))

    # PROJECTED over whatever holds a probe method, so a cell added later is covered.
    targets = {}
    for c in led["cells"]:
        if c.get("score") == 2 and c.get("check", {}).get("method", "").startswith("hf_probe."):
            m = re.search(r"huggingface\.co/([^/]+/[^/]+)/(?:raw|resolve)/([0-9a-f]{40})/",
                          " ".join(e["url"] for e in (c.get("evidence") or [])))
            if not m:
                print("  ⛔ %s/axis%d: cannot read repo+revision from its evidence"
                      % (c["subject"], c["axis"]))
                return 1
            targets.setdefault(c["subject"], m.groups())

    print("  %d subject(s) carry probe-scored cells" % len(targets))
    print()
    gathered = {}
    for sub, (repo, rev) in sorted(targets.items()):
        got, why = gather(repo, rev)
        if got is None:
            print("  ⛔ %-18s %s -- %s" % (sub, repo, why))
            print("  Refusing to bind partial probe evidence.")
            return 1
        gathered[sub] = got
        print("  %-18s %-34s %d shard(s), range %d B, is_pointer=%s"
              % (sub, repo, len(got["shards"]), got["range"]["bytes"],
                 got["range"]["is_pointer"]))
        missing_oid = [s["file"] for s in got["shards"] if not s["oid"]]
        if missing_oid:
            print("      ⚠ %d shard(s) carry no sha256 oid: %s"
                  % (len(missing_oid), missing_oid[:3]))

    if dry:
        print()
        print("  --dry-run: artifacts retrieved and stored; the ledger was not rewritten")
        return 0

    for c in led["cells"]:
        sub = c["subject"]
        if sub not in gathered or c.get("score") != 2:
            continue
        meth = c.get("check", {}).get("method", "")
        g = gathered[sub]
        if meth == "hf_probe.weight_object":
            c["evidence"] = [
                {"url": g["range"]["url"], "retrieved": _today(), "sha256": g["range"]["sha256"],
                 "range": g["range"]["range"], "pinned_commit": g["revision"],
                 "note": "the first %d bytes of the RESOLVED weight object -- tensor bytes, not a "
                         "Git-LFS pointer. Re-issue the same range to check the digest."
                         % RANGE_BYTES},
                {"url": g["api"]["url"], "retrieved": _today(), "sha256": g["api"]["sha256"],
                 "pinned_commit": g["revision"]},
            ]
            c["check"]["observed"] = (
                "HTTP %s, %d bytes of the resolved object at revision %s, is_pointer=False. "
                "The range bytes are archived and replay.py re-checks their length, their digest "
                "and that they are not a pointer."
                % (g["range"]["http_status"], g["range"]["bytes"], g["revision"][:12]))
            c["check"]["expect_range_bytes"] = RANGE_BYTES
        elif meth == "hf_probe.all_shard_digests":
            c["evidence"] = (
                [{"url": g["api"]["url"], "retrieved": _today(), "sha256": g["api"]["sha256"],
                  "pinned_commit": g["revision"]}] +
                [{"url": s["url"], "retrieved": _today(), "sha256": s["sha256"],
                  "pinned_commit": g["revision"], "lfs_oid": s["oid"]}
                 for s in g["shards"]])
            c["check"]["observed"] = (
                "%d of %d enumerated shards carry a Git-LFS sha256 oid at revision %s. The API "
                "response that ENUMERATES them and every shard pointer are archived; replay.py "
                "recomputes the enumeration from the response rather than trusting this count."
                % (sum(1 for s in g["shards"] if s["oid"]), len(g["shards"]),
                   g["revision"][:12]))
            c["check"]["expect_shards"] = len(g["shards"])

    LEDGER.write_text(json.dumps(led, indent=2) + NL, encoding="utf-8", newline=NL)
    print()
    print("  ledger rewritten: every probe cell now cites the artifacts its claim rests on")
    return 0


def _today():
    import datetime as dt
    return dt.date.today().isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
