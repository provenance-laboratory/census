"""Archive each subject's source tree at a pinned commit, so axis 6 reads the artifact.

⛔ WHY. Axis 6's bar is "source sufficient to run the described procedure, not a description of
it", and every score-2 cell settled it by grepping a README for one literal -- 'gpt-neox',
'torchrun', 'Megatron-DeepSpeed'. Two round-14 reviewers found this independently. A string in a
document is compatible with the named repository being absent, empty, or unrelated.

⚠️ AND THE ANSWER IS NOT UNIFORM, WHICH IS THE POINT. Three subjects publish a real trainer at a
pinned commit. BLOOM's declared repository holds its launch script and chronicles; the trainer is
Megatron-DeepSpeed, a repository the subject does not declare. That cell stays at 1.

    python probe_source_trees.py
"""
import gzip
import hashlib
import io
import json
import pathlib
import sys
import urllib.request

NL = chr(10)
D = chr(0x26D4)
HERE = pathlib.Path(__file__).resolve().parent
STORE = HERE / "evidence"
AS_OF = "2026-08-31"

# subject -> (repo, pinned commit, entrypoints that must exist, dependency manifest)
TREES = {
    "pythia-12b": ("EleutherAI/gpt-neox", "5150809878f0cb6bd36e0e7dc2fc73dde1c3c7bb",
                   # train.py is a 1.4 KB launcher; megatron/training.py is the trainer it
                   # calls. Requiring only the entrypoint would be satisfied by a shim.
                   ["train.py", "megatron/training.py"], "requirements/requirements.txt"),
    "olmo-2-13b": ("allenai/OLMo", "4bf8f90c26dd180095f66d0764636e00d8bae4c1",
                   ["scripts/train.py", "olmo/train.py"], "pyproject.toml"),
    "bert-base-uncased": ("google-research/bert", "8028c0459485299fa1ae6692b2300922a3fa2bad",
                          ["run_pretraining.py", "create_pretraining_data.py"],
                          "requirements.txt"),
}


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    man = json.loads((STORE / "MANIFEST.json").read_text(encoding="utf-8"))
    out = {}
    print("=" * 78)
    print("  AXIS 6 -- archiving each declared source tree at a pinned commit")
    print("=" * 78)
    print()
    for sub, (repo, sha, paths, manifest) in sorted(TREES.items()):
        url = "https://api.github.com/repos/%s/git/trees/%s?recursive=1" % (repo, sha)
        raw = urllib.request.urlopen(urllib.request.Request(
            url, headers={"User-Agent": "census/1.0",
                          "Accept": "application/vnd.github+json"}), timeout=90).read()
        tree = json.loads(raw.decode("utf-8"))
        if tree.get("truncated"):
            raise SystemExit(D + " %s's tree is TRUNCATED; an absent path would prove nothing "
                             "about the repository." % repo)
        blobs = {x["path"]: x for x in tree.get("tree", []) if x.get("type") == "blob"}
        missing = [q for q in paths + [manifest] if q not in blobs]
        if missing:
            raise SystemExit(D + " %s@%s does not contain %s" % (repo, sha[:12], missing))
        sha256 = hashlib.sha256(raw).hexdigest()
        (STORE / (sha256 + ".gz")).write_bytes(gzip.compress(raw, mtime=0))
        man["artifacts"][url] = {
            "bytes": len(raw), "cells": ["%s/axis6" % sub], "sha256": sha256, "stored": True,
            "note": ("the repository's own tree at a pinned commit, from the GitHub API. It is "
                     "archived because axis 6 asks for SOURCE, and a README naming a repository "
                     "is a description of source rather than source."),
        }
        out[sub] = {"repo": repo, "commit": sha, "paths": paths, "manifest": manifest,
                    "sha256": sha256, "url": url, "blobs": len(blobs),
                    "sizes": {q: blobs[q]["size"] for q in paths}}
        print("  %-18s %-32s %4d blobs   %s"
              % (sub, repo, len(blobs),
                 ", ".join("%s %dB" % (q.split("/")[-1], blobs[q]["size"]) for q in paths)))

    (STORE / "MANIFEST.json").write_text(json.dumps(man, indent=2, sort_keys=True) + NL,
                                         encoding="utf-8", newline=NL)
    (HERE / "axis6-source-probe.json").write_text(
        json.dumps({"_readme": ("Each subject's declared source tree at a pinned commit. BLOOM is "
                                "absent deliberately: its declared repository holds the launch "
                                "script and chronicles, not the trainer, which lives in "
                                "Megatron-DeepSpeed -- a repository the subject does not declare. "
                                "That cell scores 1 and the asymmetry is the finding."),
                    "as_of": AS_OF, "subjects": out}, indent=2, sort_keys=True) + NL,
        encoding="utf-8", newline=NL)
    print()
    print("  %d tree(s) archived; bloom-176b deliberately absent (see the readme field)" % len(out))
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
