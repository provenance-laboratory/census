"""A control's identity, as an AST fact rather than a line of its own text.

⛔ WHY. `REACH-CONTROLS.json` identified a control by `(file, line)` and, across an edit, by the
line's SOURCE TEXT. Round 6 produced the decisive counterexample without trying: two recorded
entries resolve to `return False, (` -- a bare continuation line that occurs twice in `replay.py`
-- so the record cannot say which control it means, in the current tree, with nothing having gone
wrong. Two more resolved to statements that had been rewritten, and the record could not
distinguish *this control was removed* from *this control moved*.

⇒ A SOURCE LINE IS NOT SEMANTICALLY UNIQUE. It has no stable identity under duplicate statements,
re-wrapping a `return`, inserting an identical guard, rewording a message, or lifting a branch into
a helper. A line number is worse. Both are proxies for the thing that actually has an identity:
a node in a module's syntax tree, inside a named function, with a shape.

    module        the file, relative to the census root
    qualname      the enclosing def/class chain, so a helper and its caller are different places
    kind          the node type -- Return, Raise, If, Assign
    node_hash     sha256 over OUR OWN canonical rendering, positions excluded
    parent_hash   the same over the nearest enclosing statement, so two identical branches under
                  different guards are different controls
    ordinal       which of the identically-shaped siblings in that function this one is
    canon         the rendering's version and the interpreter that produced it

⛔⛔ `node_hash` WAS A SHA-256 OVER `ast.dump`, AND THAT MADE THE IDENTITY A PROPERTY OF THE
LAPTOP. `ast.dump` is a debug pretty-printer with no stability contract; CPython 3.13 changed it to
omit fields holding their default values. A round-7 reviewer ran this tool against a byte-identical
archive whose `source_fingerprint` agreed exactly, on CPython 3.12, and got:

    exact 11, moved 2, gone 13          (recorded: exact 24, moved 2, gone 0)

Thirteen branches reported GONE -- *the old identity is gone, audit the new control* -- for code
that had not changed by one byte. They reproduced 24/2 by substituting the other rendering and
changing nothing else. **The one figure in the round that a reviewer was supposed to be able to
re-derive was the one that could not be.**

⇒ It is the defect this project keeps naming, arriving from the far side. A source line was a
proxy for a control; `ast.dump` is a proxy for a node -- better, and still a proxy, and its failure
is silent, environment-dependent, and points at the wrong conclusion. We render the tree ourselves
now, over `_fields`, which is the grammar rather than a display choice, and we record which
interpreter did it. A hash computed under a different rendering is UNCOMPARABLE, which is a status
of its own and never GONE: **a branch you cannot compare is not a branch that was rewritten.**

⚠️ THE IDENTITY DELIBERATELY DOES NOT SURVIVE A SEMANTIC REWRITE, and that is the point a reviewer
made carefully: if a control was rewritten past recognition, the honest answer is not "still
watched" but **the old identity is gone; audit the new control**. Guessing from text is what
produced the ambiguity in the first place.
"""
import ast
import hashlib
import io
import pathlib
import sys

# ⚠️ ONLY WHEN RUN DIRECTLY. Rebinding stdout at IMPORT time detaches the caller's stream:
# `reach_controls.py` imported this and its next print raised "I/O operation on closed
# file". A module that reconfigures a global on behalf of its importer is a module that
# breaks one.
if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
HERE = pathlib.Path(__file__).resolve().parent

EXACT, MOVED, AMBIGUOUS, GONE = "exact", "moved", "ambiguous", "gone"
# ⚠️ A FIFTH STATUS, AND IT IS NOT A FAILURE OF THE TREE. The record was rendered by some
# interpreter; if ours renders differently, the hashes are not commensurable and nothing about the
# control has been established either way. Reporting that as GONE is what turned a Python version
# into thirteen rewritten controls.
UNCOMPARABLE = "uncomparable"

# ⛔⛔ BOTH HALVES OF THE OLD TAG WERE WRONG, IN OPPOSITE AND EXPENSIVE DIRECTIONS.
#
#   the interpreter half fired when it should not.  A round-9 reviewer recomputed `identify()` on
#   CPython 3.12 for all 26 recorded controls: **26 of 26 identical** -- node_hash, parent_hash,
#   ordinal, siblings, kind, qualname, byte for byte. The rendering had not changed between 3.12
#   and 3.14; only the STRING had. Every record reported `uncomparable`, `--quick` exited 1, and
#   because `--quick` is item 9 of the audit's own suite, `control_audit.py` refused to start. The
#   one figure a reviewer is meant to re-derive was again the one that could not be -- by a new
#   mechanism, in the code written to fix the last one.
#
#   the version half failed to fire when it should.  `CANON_VERSION` was a hand-maintained
#   literal. The reviewer changed `_render`'s join separator from "," to ", " -- pure formatting --
#   and left the integer alone: **five unchanged controls reported `gone`.** Round 7's thirteen,
#   reproduced on one interpreter, with a human remembering an integer as the only guard.
#
# ⇒ DERIVE THE VERSION FROM THE THING IT IS A PROXY FOR. `_render`'s own source is sitting right
# there; its digest is the version. A formatting change bumps it automatically and a reviewer on
# another interpreter is not blocked by a string.
#
# ⇒ AND CARRY THE RENDERING, NOT A LABEL FOR IT. When the tag does differ, the recorded canonical
# text lets `resolve()` decide on EVIDENCE -- re-render the candidate and compare -- instead of
# refusing on a label. `uncomparable` then means *we genuinely cannot compare*, which is rare,
# rather than *the tag is not equal*, which was every record.
# ⛔⛔ THE TAG WAS A HASH OF SOURCE AND THE RENDERING WAS NOT OWNED BY THAT SOURCE. `_render`
# ended in `return repr(n)`, and `repr` is a runtime-resolved builtin -- so a round-10 reviewer
# patched `builtins.repr`, watched the rendering and every node hash change, and watched the tag
# NOT change:
#
#     render changed: YES   node_hash changed: YES   _canon_tag changed: NO
#
# The tag's whole premise is that it identifies the thing that produced the hash, and it could
# claim "same renderer" while the renderer's output differed. The same reviewer noted the mirror
# defect: hashing source is also OVER-sensitive, so a comment or docstring edit inside `_render`
# moved the tag while the output stood still. It was a representation-of-SOURCE hash wearing the
# name of a representation-of-BEHAVIOUR one.
#
# ⇒ A CLOSED SCALAR ENCODER, AND THE TAG VERSIONS THE SPECIFICATION. Every scalar this grammar
# can carry is encoded explicitly here; nothing is delegated to an ambient builtin. `SPEC` is the
# statement of that encoding and the tag is over `SPEC`, so the tag moves when the ENCODING moves
# and stands still when a comment does.
SPEC = (
    "canonical-scalar-encoding/1 "
    "None=None True=True False=False "
    "int=decimal float=repr-of-float-with-explicit-nan-inf str=u:<utf8-escaped> "
    "bytes=b:<lowercase-hex> ellipsis=... complex=c:<real>:<imag> "
    "AST=Name(field=value,...) list=[a,b,c]"
)


def _scalar(n):
    """The canonical text for a leaf. CLOSED: an unsupported type is an error, never a repr()."""
    if n is None:
        return "None"
    if n is True:
        return "True"
    if n is False:
        return "False"
    if isinstance(n, int):
        return "%d" % n
    if isinstance(n, float):
        if n != n:
            return "nan"
        if n == float("inf"):
            return "inf"
        if n == float("-inf"):
            return "-inf"
        # ⚠ float.__repr__, NOT repr(): the builtin is exactly the ambient hook this closes.
        return float.__repr__(float(n))
    if isinstance(n, complex):
        return "c:%s:%s" % (_scalar(n.real), _scalar(n.imag))
    if isinstance(n, str):
        return "u:" + n.encode("unicode_escape").decode("ascii")
    if isinstance(n, bytes):
        return "b:" + n.hex()
    if n is Ellipsis:
        return "..."
    raise TypeError("no canonical encoding is declared for %r; add one to SPEC rather than "
                    "letting an ambient repr() decide" % type(n).__name__)


# the functions whose behaviour an identity depends on -- ALL of them, see _render_source
_IDENTITY_FUNCS = ("_scalar", "_render", "_norm", "_parent_render", "_parent_node",
                   "_parent_hash", "identify")


def _render_source():
    """What the version is a version OF: the ENCODING, plus every function that applies it.

    ⛔⛔ THE TAG VERSIONED `_render` AND THE IDENTITY IS PRODUCED BY SIX FUNCTIONS. Round 10
    switched `_norm` from sha256 to sha512 -- three lines below `_render`, whose source was
    untouched -- and got **26 branches reported `gone` for code that had not changed by one
    byte**, under the tag introduced to stop exactly that. Round 7's thirteen, restored.

    ⇒ THE TAG COVERS THE WHOLE PIPELINE: the stated encoding, and the source of every function
    that turns a node into an identity. `SPEC` closes the ambient-hook hole a source hash cannot
    see (a patched builtin changes behaviour without changing text); the source hashes close the
    hole `SPEC` cannot see (a real code change the spec was not updated for). Neither alone is
    enough and the two fail in opposite directions, which is why both are here.

    ⚠️ IT IS DELIBERATELY OVER-SENSITIVE. A comment or docstring edit inside any of these moves
    the tag while the output stands still. That is conservative rather than unsound -- it can say
    "these renderers differ" when they agree, which costs a re-record, and it cannot say "these
    agree" when they differ, which would cost a false verdict.
    """
    import inspect
    parts = [SPEC]
    for _n in _IDENTITY_FUNCS:
        _f = globals().get(_n)
        try:
            parts.append(inspect.getsource(_f))
        except (OSError, TypeError):
            # ⛔ AND THIS USED TO RETURN "" HERE, so the tag collapsed to sha256(b"") and TWO
            # RENDERERS WITH DIFFERENT OUTPUT TAGGED IDENTICALLY -- `_same_renderer` True, every
            # record resolved down the hash path. It fires on any load with no source on disk:
            # zipapp, frozen interpreter, .pyc-only, exec-from-string. The old handler even
            # carried `# pragma: no cover`: the branch that disarmed the guard was excluded from
            # the thing that would have noticed.
            #
            # ⇒ A TAG THAT CANNOT BE COMPUTED IS NOT A TAG. It is named, so every comparison
            # against it fails and every record is UNCOMPARABLE rather than silently equal.
            parts.append("<source-unavailable:%s>" % _n)
    return chr(10).join(parts)


def _render(n):
    """OUR canonical text for a node. Not `ast.dump` -- see the module docstring.

    It walks `_fields`, which is the abstract grammar and part of the documented API, rather than
    a display function whose output is allowed to change between releases. Positions are excluded
    by construction: `lineno` and friends live in `_attributes`, not `_fields`.
    """
    if isinstance(n, ast.AST):
        return "%s(%s)" % (type(n).__name__,
                           ",".join("%s=%s" % (f, _render(getattr(n, f, None)))
                                    for f in n._fields))
    if isinstance(n, list):
        return "[%s]" % ",".join(_render(x) for x in n)
    return _scalar(n)


def _norm(node):
    """A node's shape, with positions stripped. Two identical guards hash the same; that is why
    `ordinal` and `parent_hash` exist rather than being accidents this has to hide."""
    return hashlib.sha256(_render(node).encode("utf-8")).hexdigest()


def _canon_tag():
    """Which RENDERER produced a hash -- the digest of its own source, not a hand-kept integer.

    ⚠️ THE INTERPRETER IS DELIBERATELY NOT IN THIS TAG. It is not what determines the rendering;
    `_render` is. `_fields` can move when the grammar moves, but that shows up as a node whose
    rendering differs -- which the recorded rendering detects per node -- not as a fact about a
    minor version string. Putting the interpreter here made a per-node property into a whole-record
    gate, and the gate fired on records that were byte-identical.
    """
    return "r" + hashlib.sha256(_render_source().encode("utf-8")).hexdigest()[:12]


def _scopes(tree):
    """(qualname, node) for every def/class, outermost first."""
    out = []

    def walk(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = prefix + ("." if prefix else "") + child.name
                out.append((name, child))
                walk(child, name)
            else:
                walk(child, prefix)

    walk(tree, "")
    return out


def _enclosing(tree, lineno):
    """The innermost def/class containing this line, and its qualname. Module scope is ''."""
    best, best_name = None, ""
    for name, node in _scopes(tree):
        start = getattr(node, "lineno", None)
        end = getattr(node, "end_lineno", None)
        if start is None or end is None or not (start <= lineno <= end):
            continue
        if best is None or (getattr(node, "lineno", 0) >= getattr(best, "lineno", 0)):
            best, best_name = node, name
    return best_name, (best if best is not None else tree)


def _statements(scope):
    """Every statement directly or indirectly inside this scope, excluding nested defs' bodies.

    ⚠️ NESTED DEFS ARE THEIR OWN SCOPE. `ast.walk` descends into them, and crediting a helper's
    `return 1` to its caller is a mistake this project has already made once, in the audit's own
    detector -- the comment recording it is three files over.
    """
    out = []

    def walk(node, top):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) \
                    and not top:
                continue
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and top:
                continue
            if isinstance(child, ast.stmt):
                out.append(child)
            walk(child, False)

    walk(scope, True)
    return out


def _parent_render(scope, node):
    """The canonical text of the nearest enclosing statement; "" when directly in the scope body."""
    best = _parent_node(scope, node)
    return "" if best is None else _render(best)


def _parent_node(scope, node):
    """The nearest enclosing STATEMENT node, or None."""
    best = None
    for cand in _statements(scope):
        if cand is node:
            continue
        s, e = getattr(cand, "lineno", None), getattr(cand, "end_lineno", None)
        ns, ne = getattr(node, "lineno", None), getattr(node, "end_lineno", None)
        if None in (s, e, ns, ne) or not (s <= ns and ne <= e):
            continue
        if best is None or getattr(cand, "lineno", 0) >= getattr(best, "lineno", 0):
            best = cand
    return best


def _parent_hash(scope, node):
    """The nearest enclosing STATEMENT's shape, or "" when the node sits directly in the scope body.

    ⛔ THE ORDINAL ALONE CANNOT SURVIVE A PERMUTATION, and a reviewer built the smallest case:

        def f(x):                       def f(x):
            if x == 1:                      if x == 2:
                return False                    return False
            if x == 2:                      if x == 1:
                return False                    return False

    The two `return False` nodes are identical at every recorded field and their COUNT is
    unchanged, so the sibling-count guard does not fire; the resolver reported `moved` for both and
    bound each old identity to the opposite logical branch. It was confident and wrong.

    ⇒ What differs is the guard above each one. Hashing the enclosing statement makes
    `if x == 1: return False` and `if x == 2: return False` different controls, which is what they
    are. Where the parents are identical too, nothing distinguishes them and the answer is
    AMBIGUOUS -- which is the correct answer and the one the ordinal was papering over.
    """
    best = None
    for cand in _statements(scope):
        if cand is node:
            continue
        s, e = getattr(cand, "lineno", None), getattr(cand, "end_lineno", None)
        ns, ne = getattr(node, "lineno", None), getattr(node, "end_lineno", None)
        if None in (s, e, ns, ne) or not (s <= ns and ne <= e):
            continue
        if best is None or getattr(cand, "lineno", 0) >= getattr(best, "lineno", 0):
            best = cand
    return "" if best is None else _norm(best)


def identify(path, lineno):
    """The identity of the control at (path, lineno), or None if there is no statement there."""
    p = pathlib.Path(path)
    try:
        tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return None
    qualname, scope = _enclosing(tree, lineno)
    stmts = _statements(scope)
    here = [s for s in stmts if getattr(s, "lineno", None) == lineno]
    if not here:
        # a continuation line: the statement STARTS above it. That is exactly the `return False, (`
        # case -- the recorded line was the opening of a multi-line statement.
        here = [s for s in stmts
                if getattr(s, "lineno", 10 ** 9) <= lineno <= getattr(s, "end_lineno", -1)]
        if not here:
            return None
        here = [min(here, key=lambda s: (s.end_lineno - s.lineno))]
    node = here[0]
    h = _norm(node)
    siblings = [s for s in stmts if _norm(s) == h]
    siblings.sort(key=lambda s: s.lineno)
    try:
        ordinal = siblings.index(node)
    except ValueError:                                                   # pragma: no cover
        ordinal = 0
    return {
        "module": p.name,
        "qualname": qualname,
        "kind": type(node).__name__,
        "node_hash": h,
        "parent_hash": _parent_hash(scope, node),
        "ordinal": ordinal,
        "siblings": len(siblings),
        "canon": _canon_tag(),
        # ⇒ THE CANONICAL TEXT ITSELF, so a tag mismatch is diffable rather than terminal. It is
        # what `node_hash` is a hash OF, and carrying it is what lets a reviewer on another
        # interpreter establish that two renderers agree instead of being told they might not.
        "render": _render(node),
        "parent_render": _parent_render(scope, node),
    }


def resolve(path, ident, recorded_line=None):
    """(lineno, status). One of exact / moved / ambiguous / gone / uncomparable."""
    # ⚠️ A DIFFERENT RENDERER IS NOT AUTOMATICALLY AN IMPOSSIBLE COMPARISON. When the tag
    # differs we compare the RECORDED CANONICAL TEXT against what this renderer produces. If they
    # agree on a candidate, the two renderers agree about that node and the record is comparable
    # on evidence. `uncomparable` is reserved for a record that carries no rendering to compare --
    # which, after round 9, means a record written before this change.
    _same_renderer = ident.get("canon") == _canon_tag()
    _recorded_render = ident.get("render")
    if not _same_renderer and not _recorded_render:
        return None, UNCOMPARABLE
    p = pathlib.Path(path)
    try:
        tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return None, GONE

    # ⛔ DUPLICATE QUALNAMES WERE A SILENT REBIND. This took the FIRST `_scopes` match and broke,
    # while `identify()`'s `_enclosing` takes the INNERMOST scope containing the line. They
    # disagree whenever two scopes share a name -- an `if os.name` branch, a `try: import` /
    # `except ImportError` fallback. A round-9 reviewer recorded a control in the second of two
    # same-named functions, deleted that entire function, and got `(5, 'moved')`: deleted outright,
    # reported moved, rebound to a different function's statement -- and `moved` does not block.
    # Item 4's exact shape, one scope level up.
    #
    # ⇒ Every scope with that name is a candidate scope, and the candidates are pooled. If the
    # record matches in more than one, nothing distinguishes them and the answer is AMBIGUOUS.
    wanted = ident.get("qualname", "")
    scopes = [node for name, node in _scopes(tree) if name == wanted] if wanted else [tree]
    if not scopes:
        return None, GONE

    # ⛔⛔ THE FALLBACK WAS AVAILABLE EXACTLY WHERE THE TAG WAS RIGHT AND UNAVAILABLE EXACTLY
    # WHERE IT WAS WRONG. The recorded RENDER -- the text itself, which is what a human would
    # compare -- was consulted only when `_same_renderer` was False. So when the tag wrongly said
    # the renderers agreed (round 10 switched `_norm` to sha512 and the tag did not move), this
    # compared hashes, found none, and answered `gone` for 26 branches whose source had not
    # changed by one byte. **The evidence that would have prevented the wrong verdict was sitting
    # in the record, and the tag's claim of sameness is what stopped it being read.**
    #
    # ⇒ THE RENDER IS ALWAYS CONSULTED. A hash match is accepted when the tag agrees; a render
    # match is accepted either way. The two are tried in that order, so the cheap comparison still
    # decides the common case, and the record's own text is never withheld because a tag said it
    # would not be needed.
    def _matches(scope):
        out = []
        for s in _statements(scope):
            if type(s).__name__ != ident.get("kind"):
                continue
            if _same_renderer and _norm(s) == ident.get("node_hash"):
                out.append(s)
            elif _recorded_render and _render(s) == _recorded_render:
                out.append(s)
        return out

    _per_scope = [(sc, _matches(sc)) for sc in scopes]
    _hit = [(sc, m) for sc, m in _per_scope if m]
    if len(_hit) > 1:
        return None, AMBIGUOUS                    # the same shape in two identically-named scopes
    scope, cands = (_hit[0] if _hit else (scopes[0], []))
    cands.sort(key=lambda s: s.lineno)
    if not cands:
        # ⛔ A RENDERER CHANGE REPORTED `gone`, WHICH IS A CLAIM ABOUT THE TREE, when the true
        # state was *we cannot compare*. Round 10: change `_render`'s separator, every one of 26
        # records fails to match, and each is answered "no statement of this shape remains".
        # UNCOMPARABLE had become reachable only by a record carrying no render at all -- i.e. a
        # pre-round-9 record -- so the status that exists to prevent this verdict could never fire
        # for the records it was added for.
        #
        # ⇒ THE RESIDUAL IS THE FINGERPRINT, and this project's own rule says so: all of them
        # failing is a renderer change, one of them failing is a rewrite. When the tag disagrees
        # AND the recorded text matches nothing, this cannot tell a vanished control from a
        # re-rendered one, and says the second rather than asserting the first.
        if not _same_renderer:
            return None, UNCOMPARABLE
        return None, GONE

    # ⛔ THE SIBLING GUARD RUNS FIRST. It used to sit BELOW a `len(cands) == 1 -> EXACT`
    # shortcut, so it only ever applied when duplicates survived -- and a reviewer showed what that
    # costs: with three identical siblings, deleting the WATCHED control and one other leaves a
    # single candidate, the shortcut fires, and the record binds to a statement that was never the
    # one recorded. It reported `exact`. Delete one and it refuses; delete two and it is confident.
    # More deletion, more certainty, and the error runs toward *still watched*, which is the
    # direction that inflates the coverage claim.
    if ident.get("siblings") is not None and len(cands) != ident["siblings"]:
        return None, AMBIGUOUS

    if len(cands) > 1:
        # ⇒ NARROW BY THE ENCLOSING STATEMENT before falling back to position. A permutation of
        # identically-shaped branches changes which guard each sits under and nothing else.
        want_parent = ident.get("parent_hash")
        if want_parent is not None:
            if _same_renderer:
                same = [c for c in cands if _parent_hash(scope, c) == want_parent]
            else:
                _wp = ident.get("parent_render")
                same = ([c for c in cands if _parent_render(scope, c) == _wp]
                        if _wp is not None else list(cands))
            if len(same) == 1:
                cands = same
            elif len(same) > 1:
                # Identical nodes under identical parents. Nothing here distinguishes them, and
                # the ordinal is an ordering, not evidence.
                return None, AMBIGUOUS
            # len(same) == 0: no candidate sits where this one did -- fall through to the ordinal,
            # which is the pre-parent behaviour and no worse than it was.

    if len(cands) == 1:
        line = cands[0].lineno
    else:
        idx = ident.get("ordinal", 0)
        if not (0 <= idx < len(cands)):
            return None, AMBIGUOUS
        line = cands[idx].lineno

    # ⚠️ MOVED MEANS MOVED. It used to be returned whenever `len(cands) > 1` -- i.e. it meant
    # *disambiguated by ordinal* -- so a control resolving to its own recorded line was reported as
    # having moved. Both of round 7's "2 moved" resolved to their own lines: 746 -> 746 and
    # 837 -> 837. Zero branches moved that round. Spending the word there spends the signal needed
    # on the day one actually does.
    if recorded_line is not None and line != recorded_line:
        return line, MOVED
    return line, EXACT


def main():
    """Report the identity of every line named in REACH-CONTROLS.json, and how it resolves."""
    import json
    rec_path = HERE / "REACH-CONTROLS.json"
    if not rec_path.is_file():
        raise SystemExit("no REACH-CONTROLS.json here")
    rec = json.loads(rec_path.read_text(encoding="utf-8"))
    detail = rec.get("detail") or {}
    counts = {EXACT: 0, MOVED: 0, AMBIGUOUS: 0, GONE: 0, UNCOMPARABLE: 0, "no-identity": 0}
    print("=" * 78)
    print("  EVERY RECORDED BRANCH, RESOLVED BY AST IDENTITY")
    print("=" * 78)
    for where, info in sorted(detail.items()):
        f, ln = where.rsplit(":", 1)
        ident = info.get("identity") or identify(HERE / f, int(ln))
        if ident is None:
            counts["no-identity"] += 1
            print("  %-22s no statement at that line" % where)
            continue
        line, status = resolve(HERE / f, ident, recorded_line=int(ln))
        counts[status] += 1
        print("  %-22s %-10s %s%s" % (where, status,
                                      ident["qualname"] or "(module)",
                                      "" if line is None else "  -> line %d" % line))
    print()
    print("  " + ", ".join("%s %d" % (k, v) for k, v in counts.items() if v))
    print("  rendering: %s" % _canon_tag())
    # ⛔ THIS RETURNED 0 WHILE REPORTING 26 OF 26 UNCOMPARABLE AND ESTABLISHING NOTHING. It is in
    # the declared suite, so a green exit here was a green exit for the suite -- and it disagreed
    # with `reach_controls.py --quick`, which blocked on the identical finding from the identical
    # records. Item 3's defect, disposition-not-detection, alive in a third instrument while the
    # round's own text claimed it fixed.
    #
    # ⇒ A run that resolved nothing reports nothing. Only `exact` and `moved` are resolutions;
    # every other disposition means this tool did not establish what it exists to establish.
    _unsettled = counts[GONE] + counts[AMBIGUOUS] + counts[UNCOMPARABLE] + counts["no-identity"]
    if counts[UNCOMPARABLE]:
        print("  " + chr(0x26A0) + " %d record(s) carry no rendering this renderer can compare "
              "against. Nothing is established about them either way -- re-run "
              "`reach_controls.py` here to re-record, and do NOT read this as a rewrite."
              % counts[UNCOMPARABLE])
    if _unsettled:
        print("  " + chr(0x26D4) + " %d of %d recorded branch(es) did not resolve to a statement "
              "in this tree. This tool establishes an identity or it does not; reporting the "
              "count and exiting 0 is the disposition defect it was written to remove."
              % (_unsettled, sum(counts.values())))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
