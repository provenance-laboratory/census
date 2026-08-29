"""Bind weight evidence to a PINNED revision, and check the weights rather than a pointer to them.

⛔ WHY THIS EXISTS. Round-1 review found three defects in how this census gathered weight evidence,
and all three were mine:

  1. A subject named `gpt-2-1.5b` cited `openai-community/gpt2`, which is the 137M checkpoint. The
     1.6B one is `gpt2-xl`. Every gate passed -- validate, recheck, 35 claim predicates -- because
     every gate checked SHAPE and none checked IDENTITY. That is the exact defect this instrument
     was built to detect, shipped inside it.
  2. Axis 12 requires "retrievable weights". The check retrieved a Git-LFS POINTER, which the LFS
     specification describes as the thing written into git INSTEAD of the blob. The cell note even
     said the weights were not downloaded, and it scored 2 anyway.
  3. Axis 13 requires a digest of "the weights". The check read one pointer out of up to 72 shards.

So this probe does four things the old approach did not:

  * resolves the repository to a COMMIT SHA and uses it in every URL, so the evidence cannot drift
    out from under the cell and a reader fetches the same bytes we did
  * enumerates EVERY weight shard at that revision, plus the index manifest if one exists
  * collects the publisher-committed digest for every shard, not one
  * RANGE-REQUESTS ACTUAL WEIGHT BYTES and verifies they are not a pointer, which is what makes
    "retrievable" a check rather than an assumption

⚠️ It reports; it does not score. Scoring is a judgement against `axes.py`, made per cell with the
probe's output as evidence.

    python hf_probe.py <repo-id> [<repo-id> ...]
    python hf_probe.py --save out.json <repo-id> ...
"""
import io
import json
import pathlib
import re
import subprocess
import sys

NL = chr(10)
API = "https://huggingface.co/api/models/"
WEIGHT = re.compile(r"\.(safetensors|bin|pt|h5|msgpack|gguf)$")
INDEX = re.compile(r"index\.json$")


def curl(url, extra=None, out=None):
    cmd = ["curl", "-sSL", "--max-time", "120", "-w", "%{http_code}"]
    if extra:
        cmd += extra
    cmd += ["-o", str(out) if out else "-", url]
    r = subprocess.run(cmd, capture_output=True, timeout=180)
    b = r.stdout
    if out:
        return b.decode("ascii", "replace").strip()[-3:], None
    if len(b) < 3:
        return "000", b""
    return b[-3:].decode("ascii", "replace"), b[:-3]


def probe(repo):
    out = {"repo": repo}
    code, body = curl(API + repo)
    if code != "200":
        out["error"] = "model API returned HTTP %s (gated or absent)" % code
        out["gated"] = code in ("401", "403")
        return out
    j = json.loads(body.decode("utf-8", "replace"))

    sha = j.get("sha")
    out["revision"] = sha
    out["gated_flag"] = j.get("gated", False)
    st = j.get("safetensors") or {}
    out["reported_params"] = st.get("total")

    files = [s["rfilename"] for s in j.get("siblings", [])]
    shards = sorted(f for f in files if WEIGHT.search(f))
    out["weight_shards"] = shards
    out["shard_count"] = len(shards)
    out["index_files"] = sorted(f for f in files if INDEX.search(f))

    # publisher-committed digests: the LFS pointer committed into the repo, one per shard
    ptr = {}
    for f in shards:
        code, body = curl("https://huggingface.co/%s/raw/%s/%s" % (repo, sha, f))
        if code != "200":
            ptr[f] = {"http": code}
            continue
        t = body.decode("utf-8", "replace")
        m = re.search(r"oid sha256:([0-9a-f]{64})", t)
        n = re.search(r"^size (\d+)", t, re.M)
        ptr[f] = {"http": code,
                  "oid_sha256": m.group(1) if m else None,
                  "size": int(n.group(1)) if n else None,
                  "is_pointer": t.startswith("version https://git-lfs")}
    out["pointers"] = ptr
    out["shards_with_publisher_digest"] = sum(
        1 for v in ptr.values() if v.get("oid_sha256"))

    # THE AXIS-12 CHECK: real weight bytes, not a pointer to them
    if shards:
        tmp = pathlib.Path("__probe_chunk.bin")
        code, _ = curl("https://huggingface.co/%s/resolve/%s/%s" % (repo, sha, shards[0]),
                       extra=["-r", "0-2047"], out=tmp)
        got = tmp.read_bytes() if tmp.exists() else b""
        tmp.unlink(missing_ok=True)
        out["weight_object"] = {
            "shard": shards[0], "http": code, "bytes": len(got),
            "is_pointer": got[:7] == b"version",
            "retrieved_ungated": code in ("200", "206") and len(got) > 0
                                 and got[:7] != b"version",
        }
    return out


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    save = None
    if "--save" in sys.argv:
        save = pathlib.Path(args.pop(0))
    if not args:
        print(__doc__)
        raise SystemExit(2)

    results = []
    for repo in args:
        r = probe(repo)
        results.append(r)
        print("  %s" % repo)
        if "error" in r:
            print("      %s" % r["error"])
            continue
        p = r.get("reported_params")
        print("      revision   %s" % r["revision"])
        print("      params     %s" % ("{:,}".format(p) if p else "not reported"))
        print("      shards     %d, %d with a publisher digest"
              % (r["shard_count"], r["shards_with_publisher_digest"]))
        print("      index      %s" % (r["index_files"] or "none"))
        w = r.get("weight_object", {})
        print("      weights    HTTP %s, %d B, pointer=%s -> retrievable=%s"
              % (w.get("http"), w.get("bytes", 0), w.get("is_pointer"),
                 w.get("retrieved_ungated")))
    if save:
        save.write_text(json.dumps(results, indent=2) + NL, encoding="utf-8", newline=NL)
        print()
        print("  wrote %s" % save)
