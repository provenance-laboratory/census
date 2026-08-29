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
import tempfile
import hashlib
import io
import json
import pathlib
import subprocess
import sys


# ⛔ A RESPONSE THAT *IS* A GATE, VERSUS A DOCUMENT THAT *DESCRIBES* ONE.
# The first version of this list refused meta-llama/llama-models/README.md -- 10 KB of ordinary
# documentation whose download instructions say "read and accept the license". That phrase is
# content there, not a challenge. Refusing it would have systematically under-scored the entire
# open-weights stratum, which is exactly the stratum whose releases are documented that way.
#
# So markers are split by how much they can mean on their own:
HARD_MARKERS = [          # these occur only in challenge pages, at any length
    "checking your browser", "cf-browser-verification", "verify you are human",
    "just a moment...", "anubis", "enable javascript and cookies to continue",
]
SOFT_MARKERS = [          # these occur freely in real documentation ABOUT access
    "sign in to continue", "log in to continue", "please log in", "access denied",
    "you need to agree", "accept the license", "gated repo", "authorization required",
    "request access", "403 forbidden", "rate limit", "captcha",
]
# A soft marker only means a gate in a body too small to be the document itself. A real gate page
# is short and says little else; a manual that mentions a licence is long and says a great deal.
SOFT_MAX_BYTES = 4096

# Small artifacts that are legitimately small. A Git-LFS pointer is ~130 bytes and is THE
# publisher-committed digest of a weights file -- exactly the evidence axis 13 needs.
SMALL_BUT_REAL = (b"version https://git-lfs.github.com/spec/v1",)


def fetch(url, timeout=600):
    """Retrieve a URL, and REFUSE a partial read rather than hashing it.

    ⛔ A TRUNCATED DOWNLOAD IS NOT A CHANGED ARTIFACT. This function used to ignore curl's exit
    code and hash whatever bytes arrived. On a 46 MB model card the 90-second limit expired
    mid-transfer, the partial bytes hashed differently, and recheck.py reported DRIFT on a
    document that had not changed at all -- a false provenance finding in a provenance census.

    So: the exit code is checked, and the body length is compared against the server's own
    Content-Length whenever it offers one. Either mismatch is a refusal, never a digest.
    """
    r = subprocess.run(
        ["curl", "-sSL", "--max-time", str(timeout),
         "-w", "%{http_code} %{size_download} %{size_header}", "-o", "-", url],
        capture_output=True, timeout=timeout + 60)
    raw, err = r.stdout, r.stderr.decode("utf-8", "replace")
    if r.returncode != 0:
        return None, None, ("curl exit %d (%s) -- a partial read must never be hashed"
                            % (r.returncode, err.strip()[:80] or "timeout or transport error"))
    if len(raw) < 3:
        return None, None, "empty response"
    tail = raw.rsplit(b" ", 2)
    try:
        status = tail[0][-3:].decode("ascii", "replace")
        reported = int(tail[1])
        body = raw[:len(raw) - (len(tail[1]) + len(tail[2]) + 5)]
    except (IndexError, ValueError):
        status, body, reported = raw[-3:].decode("ascii", "replace"), raw[:-3], None
    if reported is not None and abs(len(body) - reported) > 2:
        return None, None, ("received %d bytes, curl reports %d transferred -- refusing to hash "
                            "a body whose length does not match the transfer"
                            % (len(body), reported))
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
    for m in HARD_MARKERS:
        if m in head:
            return f"body contains {m!r} -- a challenge page, not the artifact"
    if len(body) <= SOFT_MAX_BYTES:
        for m in SOFT_MARKERS:
            if m in head:
                return (f"body is {len(body)} B and contains {m!r} -- too short to be"
                        f" the document, so this reads as a gate")
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
        # The bytes themselves, so a caller can ARCHIVE them rather than only hash them.
        # Transient and never serialised into cells.json: a digest proves what WAS
        # there, and only the bytes let a later reader check the claim for themselves.
        "body": body,
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


def content_length(url, timeout=60):
    """Ask how big it is BEFORE downloading it. None if the server will not say.

    ⛔ WHY THIS IS A PRE-FLIGHT AND NOT A POST-CHECK. archive_evidence downloaded a whole body and
    then compared its length against the 8 MB cap -- fine for a model card, catastrophic for the
    corpus data object the OLMo axis-4 evidence now cites, which is a token file of unbounded size.
    A step that can die halfway needs a check before it starts, not after.
    """
    r = subprocess.run(["curl", "-sSLI", "--max-time", str(timeout), url],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
    m = None
    for line in r.stdout.splitlines():
        if line.lower().startswith("content-length:"):
            m = line.split(":", 1)[1].strip()
    try:
        return int(m) if m else None
    except ValueError:
        return None


def evidence_range(url, first=0, last=2047):
    """Evidence for an artifact too large to hold: the digest of a FIXED byte range.

    A range digest is a weaker claim than a whole-file digest and it is written down as one. What
    it establishes is that the object is REACHABLE and returns real content -- which is exactly
    what an axis asking "can a third party acquire the same bytes?" needs.
    """
    tmp = pathlib.Path(tempfile.gettempdir()) / ("range-%s.bin" % abs(hash(url)))
    r = subprocess.run(["curl", "-sSL", "--max-time", "180", "-r", "%d-%d" % (first, last),
                        "-o", str(tmp), "-w", "%{http_code}", url],
                       capture_output=True, text=True)
    if r.returncode != 0 or not tmp.exists():
        return None, "range request failed: curl exit %d" % r.returncode
    body = tmp.read_bytes()
    tmp.unlink(missing_ok=True)
    if len(body) != (last - first + 1):
        return None, ("asked for %d bytes, got %d -- a partial range must not be recorded as the "
                      "range" % (last - first + 1, len(body)))
    return {"url": url, "retrieved": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d"),
            "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body),
            "http_status": r.stdout.strip(), "range": "bytes=%d-%d" % (first, last),
            "body": body}, None
