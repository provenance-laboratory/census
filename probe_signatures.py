"""Archive the axis-14 signature evidence and write the bounded negatives.

WHAT THIS SETTLES. Round-13 review reported a counterexample: the Hugging Face revisions already
credited on axes 12 and 13 carry VERIFIED SIGNED COMMITS, so axis 14 -- "are the weights signed by
an identifiable key?" -- could not be universally zero, and the registry had no method able to see
a signature at all. The blindness was real. The conclusion was not.

Fetching the commit objects settles it: four signed repositories, belonging to four unrelated
publishers, are signed by ONE key --

    C8A817860F8BA646BF0612916A528E38E0733467, committer `system <system@huggingface.co>`

-- which is the hosting platform's own key, applied to its own record of an upload. Axis 14 asks
for "a signature verifiable against a key THE PUBLISHER has previously bound to itself". A host
signing its own commit is not the publisher signing the weights, and the key is retrievable
nowhere: not from the publisher's profile, not from any Hugging Face endpoint, and not from the
public keyservers -- a lookup proven live by positive controls that returned 26 KB and 45 KB of
real key material for a known fingerprint.

So the score stays 0, and for the first time it is EARNED rather than inevitable. The distinction
the axis exists to draw is exactly the one the badge blurs: a platform attestation that it recorded
an upload is not a publisher's signature over bytes.

The archived commit objects SELF-AUTHENTICATE: sha1("commit " + len + NUL + bytes) reproduces the
very revision axes 12 and 13 pin, so nobody has to trust this retrieval.

    python _stage_axis14.py
"""
import gzip
import hashlib
import io
import json
import pathlib
import re
import sys

NL = chr(10)
D = chr(0x26D4)
W = chr(0x26A0)   # the FIFTH name used only on an error path; see stress_test.py
HERE = pathlib.Path(__file__).resolve().parent
STORE = HERE / "evidence"
AS_OF = "2026-08-30"
PLATFORM_FPR = "C8A817860F8BA646BF0612916A528E38E0733467"

SUBJECTS = {
    "pythia-12b": "EleutherAI/pythia-12b",
    "olmo-2-13b": "allenai/OLMo-2-1124-13B",
    "mistral-7b-v0.3": "mistralai/Mistral-7B-v0.3",
    "qwen2.5-7b": "Qwen/Qwen2.5-7B",
    "bloom-176b": "bigscience/bloom",
}


def _rm_reporting(work):
    """Remove a work tree and say so if it survives. See test_bound_rules.py for the count.

    ⛔ THIS READ `shutil` FROM MODULE SCOPE AND THIS MODULE IMPORTS IT INSIDE
    commit_object(), so the cleanup written THIS ROUND to fix a silent leak would itself have
    raised NameError -- the eighth instance of the class, introduced by the repair for the
    fifth. It was caught by the control added to stress_test.py an hour earlier, which is the
    first time this defect was found by a check rather than by a crash.
    """
    import shutil
    import time as _t
    for _ in range(2):
        try:
            shutil.rmtree(work)
        except OSError:
            _t.sleep(0.2)
        if not work.exists():
            return
    print("  ⚠ could not remove %s -- still on disk" % work)


def commit_object(repo, rev):
    """The raw git commit object at `rev`, fetched from the host.

    Fetched rather than read from a working directory, so this script depends on nothing outside
    the repository it lives in. The bytes are checked against `rev` by the caller: git's object id
    is computed from them, so a wrong or substituted object cannot pass silently.
    """
    import shutil
    import subprocess
    import tempfile
    work = pathlib.Path(tempfile.mkdtemp(prefix="sig-"))
    try:
        subprocess.run(["git", "init", "-q", str(work)], capture_output=True, check=True)
        subprocess.run(["git", "remote", "add", "origin", "https://huggingface.co/" + repo],
                       cwd=str(work), capture_output=True, check=True)
        r = subprocess.run(["git", "fetch", "-q", "--depth", "1", "origin", rev],
                           cwd=str(work), capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit(D + " could not fetch %s@%s: %s" % (repo, rev[:12], r.stderr[:160]))
        out = subprocess.run(["git", "cat-file", "commit", rev], cwd=str(work),
                             capture_output=True)
        if not out.stdout:
            raise SystemExit(D + " %s@%s produced no commit object" % (repo, rev[:12]))
        return out.stdout
    finally:
        # ⛔ a removal that cannot fail out loud is a leak with a clean conscience
        _rm_reporting(work)


def fingerprint(raw):
    """The issuer fingerprint from the commit's OpenPGP signature, or None if unsigned."""
    import base64
    if b"gpgsig" not in raw:
        return None
    body = raw.split(b"gpgsig ", 1)[1]
    out = []
    for line in body.split(bytes([10])):
        out.append(line[1:] if line.startswith(b" ") else line)
        if line.strip() == b"-----END PGP SIGNATURE-----":
            break
    armour = bytes([10]).join(out)
    b64 = b"".join(armour.split(bytes([10, 10]), 1)[1].split(b"-----END")[0].split())
    pkt = None
    for pad in (b"", b"=", b"=="):
        try:
            pkt = base64.b64decode(b64 + pad)
            break
        except Exception:                                                   # noqa: BLE001
            continue
    if pkt is None:
        return "unparsed"
    hexed = pkt.hex()
    for m in re.finditer(r"2104([0-9a-f]{40})", hexed):
        return m.group(1).upper()
    return "no-issuer-subpacket"


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    led = json.loads((HERE / "cells.json").read_text(encoding="utf-8"))
    man = json.loads((STORE / "MANIFEST.json").read_text(encoding="utf-8"))

    # the revision each subject is pinned at, taken from the axis-13 cell that already cites it
    pinned = {}
    for c in led["cells"]:
        if c["axis"] == 13 and c.get("score") == 2:
            for e in c.get("evidence") or []:
                m = re.search(r"huggingface\.co/api/models/([^/]+/[^/]+)/revision/([0-9a-f]{40})",
                              e["url"])
                if m:
                    pinned[c["subject"]] = (m.group(1), m.group(2))

    print("=" * 78)
    print("  AXIS 14 -- archiving the signature evidence")
    print("=" * 78)
    print()

    facts = {}
    for sub, repo in SUBJECTS.items():
        raw = commit_object(repo, (pinned.get(sub) or (repo, None))[1])
        rev = hashlib.sha1(b"commit " + str(len(raw)).encode() + bytes([0]) + raw).hexdigest()
        want_repo, want_rev = pinned.get(sub, (repo, None))
        if want_rev and rev != want_rev:
            raise SystemExit(D + " %s: object is revision %s, census pins %s"
                             % (sub, rev[:12], want_rev[:12]))
        sha = hashlib.sha256(raw).hexdigest()
        blob = STORE / (sha + ".gz")
        if not blob.exists():
            blob.write_bytes(gzip.compress(raw, mtime=0))
        url = "https://huggingface.co/%s/commit/%s" % (repo, rev)
        man["artifacts"][url] = {
            "bytes": len(raw),
            "cells": ["%s/axis14" % sub],
            "note": ("the archived bytes are the GIT COMMIT OBJECT at this revision, obtained with "
                     "`git cat-file commit`, not the rendered HTML page. They SELF-AUTHENTICATE: "
                     "sha1 of the git object header and these bytes reproduces the revision id "
                     "that axes 12 and 13 pin, so this retrieval need not be trusted."),
            "sha256": sha,
            "stored": True,
        }
        fp = fingerprint(raw)
        cm = re.search(bytes([94]).join([b"", b"committer .+? <(.+?)>"]), raw, re.M)
        committer = cm.group(1).decode() if cm else "?"
        facts[sub] = {"repo": repo, "rev": rev, "sha256": sha, "url": url,
                      "signed": fp is not None, "fpr": fp, "committer": committer,
                      "bytes": len(raw)}
        print("  %-17s %s  signed=%-5s  key=%s" % (sub, rev[:12], fp is not None,
                                                   (fp or "-")[:40]))

    (STORE / "MANIFEST.json").write_text(json.dumps(man, indent=2, sort_keys=True) + NL,
                                         encoding="utf-8", newline=NL)
    (HERE / "axis14-signature-probe.json").write_text(
        json.dumps({"_readme": __doc__.strip().split(NL + NL)[1],
                    "as_of": AS_OF, "platform_fingerprint": PLATFORM_FPR,
                    "keyserver_positive_control": {
                        "fingerprint": "EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796",
                        "keys.openpgp.org": "200, 26351 bytes of PGP PUBLIC KEY BLOCK",
                        "keyserver.ubuntu.com": "200, 45075 bytes of PGP PUBLIC KEY BLOCK",
                        "why": ("the signer's fingerprint returns 404 from both. These controls "
                                "prove the lookup works and the endpoints answer, so that 404 is "
                                "a fact about the key rather than about the query.")},
                    "subjects": facts}, indent=2, sort_keys=True) + NL,
        encoding="utf-8", newline=NL)

    signed = {v["fpr"] for v in facts.values() if v["signed"]}
    print()
    print("  %d signed repositories, %d distinct signing key(s)" % (
        sum(1 for v in facts.values() if v["signed"]), len(signed)))
    print("  written: axis14-signature-probe.json, %d evidence blobs" % len(facts))
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
