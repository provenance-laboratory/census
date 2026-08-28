"""Retrieve an artifact, hash what actually came back, and refuse to call a wall an artifact.

⛔ AN HTTP 200 IS NOT AN ARTIFACT. Model cards live behind consent gates, login walls and bot
challenges that return 200 with a body containing nothing of what was asked for. A cell scored
from such a response is scored from a challenge page.

This encodes three things that have already cost this workshop time:

  * HASH THE PAYLOAD, NOT THE STATUS. The digest recorded in a cell is of the bytes retrieved,
    so a later re-fetch that returns a different document is DETECTED rather than absorbed.
  * A WALL LOOKS LIKE A SUCCESS. Anubis and Software Heritage both answer 200 with a challenge;
    so does every "you must agree to share your contact information" gate. The heuristics below
    are deliberately noisy in the direction of refusing -- a false refusal costs one manual look,
    a false accept silently corrupts a cell.
  * A FAILED FETCH IS NOT A PASS. Every failure path here refuses; none returns a partial record.

curl is used rather than urllib because this machine's bundled CA store has an expired root, and
a LOCAL TLS defect must never be recorded as a fact about a REMOTE artifact.

    python fetch_artifact.py <url> [<url> ...]        print cell-ready evidence records
    python fetch_artifact.py --save out.json <url>    and write them
"""
import datetime as dt
import hashlib
import io
import json
import pathlib
import subprocess
import sys


# Phrases that mean "you did not get the document". Matched case-insensitively on a decoded
# prefix. Deliberately over-broad: refusing wrongly costs a manual look; accepting wrongly
# corrupts a cell that will then be cited.
WALL_MARKERS = [
    "enable javascript", "checking your browser", "verify you are human",
    "just a moment", "cf-browser-verification", "captcha", "anubis",
    "sign in to continue", "log in to continue", "please log in", "access denied",
    "you need to agree", "accept the license", "gated repo", "authorization required",
    "request access", "403 forbidden", "rate limit",
]


def fetch(url, timeout=90):
    r = subprocess.run(
        ["curl", "-sSL", "--max-time", str(timeout), "-w", "%{http_code}", "-o", "-", url],
        capture_output=True, timeout=timeout + 30)
    body = r.stdout
    if len(body) < 3:
        return None, None, "empty response"
    status, body = body[-3:].decode("ascii", "replace"), body[:-3]
    return status, body, None


# Small artifacts that are legitimately small. A Git-LFS pointer is ~130 bytes and is THE
# publisher-committed digest of a weights file -- exactly the evidence axis 13 needs.
SMALL_BUT_REAL = (b"version https://git-lfs.github.com/spec/v1",)


def looks_like_a_wall(body, status):
    if status != "200":
        return f"HTTP {status}"
    if any(body.lstrip().startswith(m) for m in SMALL_BUT_REAL):
        return None                    # small on purpose, and the thing we came for
    if len(body) < 64:
        # 512 was the first threshold and it REFUSED A VALID LFS POINTER on the first real
        # run. A rule that cries wolf sometimes is a rule someone switches off in a hurry,
        # so the floor now catches only genuinely empty replies.
        return f"only {len(body)} bytes -- too small to be any document"
    head = body[:20000].decode("utf-8", "replace").lower()
    for m in WALL_MARKERS:
        if m in head:
            return f"body contains {m!r} -- this is a gate, not the artifact"
    return None


def evidence(url):
    status, body, err = fetch(url)
    if err:
        return None, err
    wall = looks_like_a_wall(body, status)
    if wall:
        return None, wall
    return {
        "url": url,
        "retrieved": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d"),
        "sha256": hashlib.sha256(body).hexdigest(),
        "bytes": len(body),
        "content_head": body[:80].decode("utf-8", "replace").strip()[:60],
    }, None


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    save = None
    if "--save" in sys.argv:
        save = pathlib.Path(args.pop(0))
    if not args:
        print(__doc__)
        raise SystemExit(2)

    out, refused = [], 0
    for u in args:
        rec, why = evidence(u)
        if rec is None:
            refused += 1
            print("  REFUSED  %s" % u)
            print("           %s" % why)
            print("           An artifact that cannot be retrieved is not evidence. The cell"
                  " stays 0.")
            continue
        out.append(rec)
        print("  ok       %s" % u)
        print("           sha256 %s  (%d bytes)" % (rec["sha256"], rec["bytes"]))
        print("           starts: %s" % rec["content_head"])
    if save and out:
        save.write_text(json.dumps(out, indent=2), encoding="utf-8", newline=chr(10))
        print("  wrote %s" % save)
    print()
    print("  %d retrieved, %d refused" % (len(out), refused))
    raise SystemExit(1 if refused else 0)
