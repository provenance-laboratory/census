"""Rewrite mutable branch URLs to COMMIT-ADDRESSED ones, and re-fetch to prove they resolve.

⛔ THE CLAIM THAT WAS FALSE. The paper says a VERIFIED cell rests on an artifact retrieved AT A
PINNED REVISION. Round-2 review checked and found 13 of 25 score-2 cells citing
`raw.githubusercontent.com/<owner>/<repo>/main/...` or `/master/...`. A branch is a moving pointer.
The stored SHA-256 establishes WHICH BYTES were used -- that part was always sound -- but it does
not make the source a pinned revision, and "pinned" was doing work in the sentence that the URL
could not support.

WHAT THIS DOES. For each such url it asks the GitHub API which commit last touched that exact path,
rewrites the url to that commit SHA, re-fetches, and REQUIRES the bytes to hash to what the ledger
already records. If they differ, the ledger's digest was describing something else and that is a
finding, not something to overwrite.

⚠️ A commit-addressed url is still not a guarantee: a repository can be deleted or rewritten. That
is why the bytes are archived too (`archive_evidence.py`). The three mechanisms answer different
questions -- WHICH revision, WHICH bytes, and CAN THEY STILL BE READ -- and none substitutes for
another.

    python pin_urls.py --dry-run
    python pin_urls.py
"""
import io
import json
import pathlib
import re
import sys
import time

import fetch_artifact as F

NL = chr(10)
HERE = pathlib.Path(__file__).resolve().parent
LEDGER = HERE / "cells.json"
RAW = re.compile(r"^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/(main|master)/(.+)$")
# Hugging Face spells the same mutable pointer differently. Matching one host and calling the job
# done is how four of these survived the first pass.
HF = re.compile(r"^https://huggingface\.co/(datasets/)?([^/]+/[^/]+)/raw/main/(.+)$")
HF_API = "https://huggingface.co/api/%s/%s"
API = "https://api.github.com/repos/%s/%s/commits?path=%s&per_page=1"


def resolve(owner, repo, path):
    """The commit that last touched this path. None if the API will not say."""
    status, body, err = F.fetch(API % (owner, repo, path))
    if err or not body:
        return None, err or "no body"
    try:
        data = json.loads(body)
    except ValueError:
        return None, "not json"
    if not isinstance(data, list) or not data:
        return None, "no commits returned for that path"
    return data[0].get("sha"), None


def resolve_hf(is_dataset, repo):
    """The repository's current head commit. Hugging Face serves /raw/<sha>/ the same way."""
    status, body, err = F.fetch(HF_API % ("datasets" if is_dataset else "models", repo))
    if err or not body:
        return None, err or "no body"
    try:
        return json.loads(body).get("sha"), None
    except ValueError:
        return None, "not json"


def pinned_for(url):
    """(pinned_url, sha) for any mutable ref this knows how to resolve, else (None, why)."""
    m = RAW.match(url)
    if m:
        owner, repo, _b, path = m.groups()
        sha, err = resolve(owner, repo, path)
        if not sha:
            return None, err
        return "https://raw.githubusercontent.com/%s/%s/%s/%s" % (owner, repo, sha, path), sha
    m = HF.match(url)
    if m:
        ds, repo, path = m.groups()
        sha, err = resolve_hf(bool(ds), repo)
        if not sha:
            return None, err
        return "https://huggingface.co/%s%s/raw/%s/%s" % (ds or "", repo, sha, path), sha
    return None, "not a recognised mutable-ref url"


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    dry = "--dry-run" in sys.argv
    led = json.loads(LEDGER.read_text(encoding="utf-8"))

    targets = {}
    for c in led["cells"]:
        for e in (c.get("evidence") or []):
            if RAW.match(e["url"]) or HF.match(e["url"]):
                targets.setdefault(e["url"], []).append("%s/axis%d" % (c["subject"], c["axis"]))

    print("  %d mutable branch url(s) cited by %d cell reference(s)"
          % (len(targets), sum(len(v) for v in targets.values())))
    print()

    mapping, failed = {}, []
    for url in sorted(targets):
        pinned, sha = pinned_for(url)
        if not pinned:
            print("  ⛔ %s" % url[-64:])
            print("     cannot resolve a commit: %s" % sha)
            failed.append(url)
            continue
        rec, why = F.evidence(pinned)
        if rec is None:
            print("  ⛔ %s" % pinned[-64:])
            print("     pinned url does not resolve: %s" % why)
            failed.append(url)
            continue
        mapping[url] = (pinned, rec["sha256"], sha)
        print("  %s" % url[-64:])
        print("     -> %s  %s" % (sha[:12], rec["sha256"][:16]))
        time.sleep(1)

    if failed:
        print()
        print("  ⛔ %d url(s) could not be pinned. Refusing to rewrite a partial set: a ledger "
              "where some VERIFIED cells are pinned and others are not, with nothing saying "
              "which, is worse than one where none are." % len(failed))
        return 1

    # ⛔ The bytes at the pinned commit MUST hash to what the ledger already records. If they do
    # not, the recorded digest was describing a later state of the branch, and rewriting the url
    # would silently repoint the citation at different content.
    drift = []
    for c in led["cells"]:
        for e in (c.get("evidence") or []):
            if e["url"] in mapping:
                _p, got, _sha = mapping[e["url"]]
                if got != e["sha256"]:
                    drift.append((e["url"], e["sha256"], got))
    if drift:
        print()
        print("  ⛔ %d artifact(s) hash DIFFERENTLY at the pinned commit:" % len(drift))
        for u, was, now in drift:
            print("      %s" % u[-64:])
            print("        ledger %s" % was[:24])
            print("        pinned %s" % now[:24])
        print("  The recorded digest described a later state of the branch. That is a FINDING "
              "about when the evidence was taken, not something to overwrite.")
        return 1

    if dry:
        print()
        print("  %d url(s) would be pinned; every one hashes to the digest already recorded. "
              "Nothing written (--dry-run)." % len(mapping))
        return 0

    n = 0
    for c in led["cells"]:
        for e in (c.get("evidence") or []):
            if e["url"] in mapping:
                pinned, _digest, sha = mapping[e["url"]]
                e["url"] = pinned
                e["pinned_commit"] = sha
                n += 1
    LEDGER.write_text(json.dumps(led, indent=2) + NL, encoding="utf-8", newline=NL)
    print()
    print("  %d evidence reference(s) now cite a commit, not a branch. Digests unchanged." % n)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
