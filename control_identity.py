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
# ⛔⛔ AND THE ENCODER AT THE BOTTOM OF THE CHAIN WAS NOT INJECTIVE. `u:<escaped>` escaped
# backslashes and non-ASCII and left alone the six characters `_render` uses as STRUCTURE --
# `, ( ) [ ] =` -- so a string could spell the rest of the rendering:
#
#     source A: ["a", "b"]
#     source B: ["a,kind=None),Constant(value=u:b"]
#         renders identical : True        node_hash identical: True
#
# A two-element list and a one-element list, same bytes, same hash. And it was reachable against
# a watched control: a reviewer deleted `d.append('negative', 'refused')`, put a DIFFERENT
# one-argument call with an injected string in its place, and `resolve` returned **exact** -- the
# branch that was recorded -- while quick mode replayed it and passed. `gone`, `ambiguous` and
# `uncomparable` all block; this reached none of them.
#
# ⚠️ THE EXPOSURE IS TOTAL RATHER THAN THEORETICAL: 26 of 26 recorded renders already carry
# string payloads containing those characters. Every record on disk stands on this.
#
# ⇒ LENGTH-PREFIXED, WHICH IS THE ONE FORM NO PAYLOAD CAN IMITATE. `u:<n>:<text>` says how many
# characters follow before any of them is read, so a string cannot end itself early however it is
# spelled -- the discipline `b:<hex>` already had, applied to the type that needed it. The version
# is bumped: a record written under `/1` is not comparable with one written under `/2`, and the
# tag carries `SPEC`, so every existing record is correctly reported as rendered by a different
# renderer rather than silently re-interpreted.
#
# ⚠️ AND THE NAME IS CORRECTED. `/1` said `utf8-escaped` and the code called
# `unicode_escape`, which is a different codec. A specification that names the wrong codec is a
# specification a reader cannot check the implementation against.
#
# ⛔⛔ AND `/2` STATED A COUNT THE CODE DOES NOT WRITE, IN THE ONE PART OF THE TAG WHOSE JOB IS
# TO LET A READER CHECK THE IMPLEMENTATION. `bytes=b:<byte-count>` against `len(n.hex())`:
#
#     b'abc'    -> b:6:616263     3 bytes, prefix says 6
#     b'\xff'   -> b:2:ff         1 byte,  prefix says 2
#
# Every non-empty bytes payload disagreed with its own specification. The CODE is the consistent
# one: the string encoder counts the ESCAPED characters for a stated reason -- *a reader counts
# what is in front of them rather than reconstructing the codec first* -- and hex characters are
# what is in front of them here too. So the count stays and the words are corrected, and both
# counts now say WHICH characters they count instead of leaving a reader to assume.
SPEC = (
    "canonical-scalar-encoding/5 "
    "None=None True=True False=False "
    "int=decimal float=repr-of-float-with-explicit-nan-inf "
    "str=u:<escaped-char-count>:<python-unicode_escape-of-the-text> "
    "bytes=b:<hex-char-count>:<lowercase-hex> ellipsis=... complex=c:<real>:<imag> "
    "AST=Name(field=value,...) list=[a,b,c] "
    "-- every variable-length payload is length-prefixed by the characters it WRITES, so no "
    "payload can imitate a delimiter and a reader can skip one without decoding it; "
    "the renderer tag covers one value per _scalar branch (the branches read from _scalar's source; "
    "a dispatch form the reader does not recognise is recorded as uncovered, never skipped), one "
    "snippet per SELECTED parser feature parsed in the pipeline's own mode, and the ast.parse "
    "signature; a record is comparable only for the features its own text uses -- node kinds and "
    "the enumerated scalar forms, a sample of the encoding and not the whole of it"
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
        # the count is of the ESCAPED characters -- the ones actually written -- so a reader
        # counts what is in front of them rather than reconstructing the codec first
        _e = n.encode("unicode_escape").decode("ascii")
        return "u:%d:%s" % (len(_e), _e)
    if isinstance(n, bytes):
        _h = n.hex()
        return "b:%d:%s" % (len(_h), _h)
    if n is Ellipsis:
        return "..."
    raise TypeError("no canonical encoding is declared for %r; add one to SPEC rather than "
                    "letting an ambient repr() decide" % type(n).__name__)


# ⛔⛔ AND THIS WAS SEVEN OF TEN, HAND-KEPT, IN A FILE WHOSE HEADER WARNS THAT A HAND-KEPT
# LIST REPRODUCES THE DEFECT IT AUDITS. `inspect.getsource(identify)` returns `identify`'s own
# text and not its callees -- and `identify` calls `_scopes`, `_enclosing` and `_statements`,
# which produce `qualname`, `ordinal` and `siblings`: three fields of the identity dict, all three
# used by `resolve` for scope lookup, the sibling guard and ordinal disambiguation. A round-11
# reviewer changed `_statements` to stop recursing into nested blocks:
#
#     shipped                                          tag=r64792c27eeab  {'exact': 26}
#     _statements: stop recursing into nested blocks    tag=r64792c27eeab  {'gone': 26}
#
# **Twenty-six branches gone for code that has not changed by one byte, tag standing still** --
# round 10's `_norm` result, reproduced against the repair that was made for it. The boundary
# moved; the mechanism did not.
#
# ⇒ THE CLOSURE IS COMPUTED, NOT LISTED. `_identity_closure()` parses this module and takes
# every module-level function reachable by name from the roots below. Adding a helper to the
# pipeline adds it to the tag with no edit here, which is the property a hand-kept list cannot
# have. The roots are the entry points an identity actually comes out of.
_IDENTITY_ROOTS = ("identify", "_norm", "_render", "_scalar", "_canon_tag")


def _identity_closure():
    """Every module-level function reachable by name from `_IDENTITY_ROOTS`, sorted.

    ⚠️ BY NAME, which over-approximates: a local variable shadowing a function name pulls that
    function in, and a call through a dict or an attribute is not followed. Over-approximation is
    the safe direction here -- an extra function in the tag costs a re-record, a missing one costs
    a false `exact` -- and the one direction that would be unsafe, missing a callee, requires the
    pipeline to dispatch dynamically, which it does not and which this would then be wrong about
    loudly rather than quietly. If that ever changes, the failure is a wrong verdict, so it is
    written down here rather than discovered.
    """
    try:
        _tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError):                            # pragma: no cover
        return None
    _defs = {n.name: n for n in _tree.body
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    _seen, _todo = set(), [r for r in _IDENTITY_ROOTS if r in _defs]
    while _todo:
        _n = _todo.pop()
        if _n in _seen:
            continue
        _seen.add(_n)
        for _sub in ast.walk(_defs[_n]):
            _f = getattr(_sub, "func", None) if isinstance(_sub, ast.Call) else None
            _nm = getattr(_f, "id", None) if isinstance(_f, ast.Name) else None
            if _nm in _defs and _nm not in _seen:
                _todo.append(_nm)
    return sorted(_seen)


# ⛔⛔ AND NONE OF THAT SEES THE RUNTIME. A round-11 reviewer changed no file at all:
#
#     ast.Constant.__name__ = "TamperedConstant"
#     render changed: True    hash changed: True    tag changed: False
#
# `_render` reads `type(n).__name__` and `n._fields` from the interpreter's AST classes, and a
# source hash cannot see either. `SPEC` closed the ambient-BUILTIN hole and left the ambient
# GRAMMAR hole beside it.
#
# ⇒ THE TAG FINGERPRINTS THE BEHAVIOUR AS WELL AS THE TEXT. the grammar the renderer reads
# is fingerprinted whole and the encoder is exercised on fixed inputs, so an altered AST class
# name, an altered `_fields`, an altered codec or any other runtime change that moves the
# OUTPUT moves the tag --
# while the interpreter VERSION stays deliberately out of it, because a version string is not a
# rendering. Each probe exercises one thing the encoder reads.
#
# ⛔⛔ AND THE CANARIES WERE A HAND-KEPT LIST OF SIX, IN THE REPAIR THAT REPLACED A HAND-KEPT
# LIST OF SEVEN. They covered the node kinds somebody thought of. `ast.Attribute` was not one:
#
#     ast.Attribute._fields loses 'attr'     node_hash moved: True     tag moved: False
#
# → six branches reported `gone` for code that had not changed by one byte, with the tag standing
# still, under the canaries introduced to stop exactly that. The list could not fall behind the
# CODE, because a code change moves a source hash; it could and did fall behind THE GRAMMAR,
# which is the only thing it was there to watch.
#
# ⇒ PROJECT OVER THE GRAMMAR INSTEAD OF SAMPLING IT. `_render` reads exactly two things out of
# the interpreter's AST classes -- `type(n).__name__` and `n._fields` -- so the fingerprint is
# those two things for EVERY class the module has. It is a comprehension over `ast`; there is no
# list to keep, and a node kind added, renamed or re-fielded by a Python release moves the tag
# whether or not anyone here has heard of it. The binding name is recorded beside `__name__`, so
# renaming the class (`ast.Constant.__name__ = "TamperedConstant"`) moves it too.
def _grammar_fingerprint():
    """{binding: __name__(fields)} for every AST class -- the whole grammar, not a sample of it."""
    _out = []
    for _k in sorted(dir(ast)):
        _c = getattr(ast, _k, None)
        if isinstance(_c, type) and issubclass(_c, ast.AST) and hasattr(_c, "_fields"):
            _out.append("%s=%s(%s)" % (_k, _c.__name__, ",".join(map(str, _c._fields))))
    return ";".join(_out)


# ⚠️ THESE ARE NOT GRAMMAR CANARIES AND THEY ARE NOT HAND-KEPT IN THE SAME SENSE. They probe
# the OTHER runtime surface `_render` stands on -- the builtins `_scalar` calls, which a patched
# codec can move without touching a byte of source. Hand-keeping fails SAFE here and failed
# UNSAFE there, and the difference is worth stating rather than treating the two as one problem:
# every type `_scalar` handles is decided by `_scalar`'s own text, so adding one moves the source
# hash and the tag with it. A probe that falls behind `_scalar` costs sensitivity to a patched
# builtin; a canary list that fell behind `ast` cost a wrong verdict.
# ⛔⛔ ROUND 13: FOUR SNIPPETS EXERCISED FOUR TYPES AND NOT THE BRANCHES BEHIND THEM.
# `float('nan')` is a Call node, not a float constant, so `_scalar` never saw a nan; three of
# its four float branches were unreached by the whole probe set. The string probe contained
# nothing `unicode_escape` changes, so a patched codec that differed only in how it escapes moved
# 222 constants in this corpus and no probe output. A reviewer replaced the module's `float` with
# a proxy that behaved for the probed values and differently for 2.5: tag unchanged, rendering
# changed. Sampling by TYPE where the encoder branches by VALUE is the canary defect with the
# word changed.
#
# ⇒ ONE VALUE PER BRANCH, RENDERED AS A CONSTANT NODE, and the branch list is checked against
# `_scalar`'s own source: every `isinstance(n, T)` and `n is X` test in `_scalar` must have a
# probe value of that type, or the tag records `<probe-uncovered:T>` and every comparison against
# it fails. A value-dependent tamper WITHIN a branch that spares every probed value is not caught
# by a probe and cannot be; that is what the per-record feature proof (`renderer_proven`) is for,
# and the docstring there says so rather than letting the probes claim it.
_ENCODER_PROBES = (
    None, True, False,
    0, -7, 2 ** 70,                                        # int: zero, negative, beyond a word
    1.5, -0.0, 1e300, 5e-324,                               # float.__repr__ on ordinary and edge values
    float("nan"), float("inf"), float("-inf"),              # the three special-value branches
    complex(1, 2), complex(float("nan"), float("-inf")),   # complex, recursing into the float branches
    "", "a,b(c)[d]=e",                                      # empty; the delimiter set
    "quote ' and \" both", "back" + chr(92) + "slash", "new" + chr(10) + "line",
    "caf" + chr(233), chr(0x1F600), chr(0),                 # what unicode_escape actually escapes
    b"", bytes([0xff, 0x00]) + b"x",
    Ellipsis,
)


def _probe_coverage():
    """The types `_scalar` dispatches on that no probe exercises. Empty is the only good answer.

    The scan reads two idioms -- `isinstance(n, T)` with a bare name, and `n is <constant>` (plus
    `n is Ellipsis`) -- and every other dispatch form is reported as `unrecognised-dispatch:...`,
    which no probe can satisfy, so the tag records it as uncovered. What it guarantees is stated
    exactly: every branch of the forms it recognises has a probe, and a branch in any other form
    fails closed rather than passing unseen."""
    import inspect
    try:
        _t = ast.parse(inspect.getsource(_scalar))
    except (OSError, TypeError, SyntaxError):                             # pragma: no cover
        return ["<_scalar source unavailable>"]
    # ⛔ ROUND 14: THE SCAN RECOGNISED TWO IDIOMS AND SILENTLY SKIPPED EVERY OTHER. `isinstance(n, (int,
    # bool))`, `type(n) is bytes`, a dispatch table keyed on `type(n)`, a `match`: each registered no
    # type at all, so the promise "every branch has a probe" evaporated the moment `_scalar` was
    # refactored into the tuple form -- the hand-kept list reproducing the defect it audits, one
    # level down, displaced onto the auditor. ⇒ A DISPATCH THE SCAN CANNOT REDUCE TO A NAME IS
    # RECORDED AS UNCOVERED, which moves the tag and fails every comparison, rather than skipped.
    _want = set()
    for _n in ast.walk(_t):
        if isinstance(_n, ast.Call) and isinstance(_n.func, ast.Name) and _n.func.id == "isinstance":
            if len(_n.args) == 2 and isinstance(_n.args[1], ast.Name):
                _want.add(_n.args[1].id)
            else:
                _want.add("unrecognised-dispatch:isinstance:%s"
                          % (type(_n.args[1]).__name__ if len(_n.args) == 2 else "arity"))
        if isinstance(_n, ast.Compare):
            if not isinstance(_n.left, ast.Name):
                _want.add("unrecognised-dispatch:compare-left:%s" % type(_n.left).__name__)
            for _op, _c in zip(_n.ops, _n.comparators):
                if isinstance(_op, (ast.Is, ast.IsNot)):
                    if isinstance(_c, ast.Constant):
                        _want.add(type(_c.value).__name__)
                    elif isinstance(_c, ast.Name) and _c.id == "Ellipsis":
                        _want.add("ellipsis")
                    else:
                        _want.add("unrecognised-dispatch:is:%s" % type(_c).__name__)
                elif isinstance(_op, (ast.In, ast.NotIn)):
                    _want.add("unrecognised-dispatch:in")
        # ⛔ ROUND 15: a `match n: case int(): ...` dispatches on type through a MatchClass pattern
        # and calls `type()` nowhere, so the round-14 guard -- which fired only on a literal `type(...)`
        # inside the match -- recorded NOTHING for the most natural modern spelling. ⇒ Every case
        # pattern is read: a class pattern with a bare name registers that name as a dispatched type;
        # any other pattern (value, sequence, mapping, attribute class, guard) is unrecognised and
        # recorded as such, so the tag moves and every comparison fails rather than the branch passing
        # unseen.
        if isinstance(_n, ast.Match):
            for _case in _n.cases:
                _pat = _case.pattern
                if isinstance(_pat, ast.MatchClass) and isinstance(_pat.cls, ast.Name) and not _pat.patterns \
                        and not _pat.kwd_patterns and _case.guard is None:
                    _want.add(_pat.cls.id)
                elif isinstance(_pat, ast.MatchAs) and _pat.pattern is None and _case.guard is None:
                    pass                                   # the irrefutable `case _:` catch-all
                else:
                    _want.add("unrecognised-dispatch:match:%s" % type(_pat).__name__)
        if isinstance(_n, ast.Subscript) and any(
                isinstance(_x, ast.Call) and isinstance(_x.func, ast.Name) and _x.func.id == "type"
                for _x in ast.walk(_n)):
            _want.add("unrecognised-dispatch:subscript")
    _have = {type(v).__name__ for v in _ENCODER_PROBES}
    _have |= {"NoneType"} if None in _ENCODER_PROBES else set()
    # `n is Ellipsis` compares against a Name, and `bool` is reached through True/False
    if Ellipsis in _ENCODER_PROBES:
        _have.add("ellipsis")
    _missing = sorted(t for t in _want if t not in _have and t not in ("ellipsis",))
    _floats = [v for v in _ENCODER_PROBES if isinstance(v, float)]
    for _need, _test in (("nan", lambda v: v != v), ("inf", lambda v: v == float("inf")),
                         ("-inf", lambda v: v == float("-inf"))):
        if not any(_test(v) for v in _floats):
            _missing.append("float:" + _need)
    if not any(isinstance(v, str) and v.encode("unicode_escape").decode("ascii") != v
               for v in _ENCODER_PROBES):
        _missing.append("str:escaped")
    return _missing


# ⚠️ ROUND 13, PUSH 3: THE FINGERPRINT COVERS THE GRAMMAR'S CLASSES, AND `_render` DEPENDS ON
# THE GRAMMAR'S INSTANCES. `ast.parse(type_comments=True)` populates a field the default parse
# leaves None -- same classes, same `_fields`, different hash. PEP 701 changed the tree
# f-strings parse to without touching JoinedStr or FormattedValue. The parse can move under a
# fixed grammar, and `ast.parse`'s own signature is the enumeration of how far.
# ⇒ THE TAG CARRIES THAT SIGNATURE AND THE RENDERING OF ONE SNIPPET PER PARSER FEATURE, parsed
# exactly as the pipeline parses -- a parser that populates a field, or builds a different tree
# for the same text, moves the tag. It is a sample of the parser as the probes are a sample of
# the encoder, and it is stated as one.
_PARSER_PROBES = (
    # parsed in the PIPELINE'S mode (the default, which leaves `type_comment` None), so this
    # snippet moves the tag only if a release starts populating the field by default; a parser
    # asked for type comments is a different signature, which the tag also carries (round 14)
    "x = []  # type: list",
    "f'{a!r:>{w}} {b}'",                        # f-strings: PEP 701 reshaped these in 3.12
    "(y := 3)",                                 # walrus
    "def g(a, /, b, *, c): pass",               # positional-only and keyword-only markers
    "async def h():\n    return [i async for i in k]",
    "match m:\n    case [1, *rest]: pass",
)


def _render_source():
    """What the version is a version OF: the ENCODING, what it DOES, and the code that does it.

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
    parts = [SPEC, _grammar_fingerprint()]
    # what the renderer DOES, one value per encoder branch -- see `_ENCODER_PROBES`
    for _v in _ENCODER_PROBES:
        try:
            parts.append(_render(ast.Constant(value=_v)))
        except Exception as _e:                                          # noqa: BLE001
            # a renderer that cannot render its own probe is not this renderer
            parts.append("<probe-failed:%s:%s>" % (type(_e).__name__, _e))
    for _t in _probe_coverage():
        parts.append("<probe-uncovered:%s>" % _t)
    # what the PARSER does, one snippet per feature, and how far its signature lets it move
    try:
        parts.append(str(inspect.signature(ast.parse)))
    except (TypeError, ValueError):                                       # pragma: no cover
        parts.append("<parse-signature-unavailable>")
    for _c in _PARSER_PROBES:
        try:
            parts.append(_render(ast.parse(_c)))
        except Exception as _e:                                          # noqa: BLE001
            parts.append("<parser-probe-failed:%s:%s>" % (type(_e).__name__, _e))
    _names = _identity_closure()
    if _names is None:                                                    # pragma: no cover
        parts.append("<closure-unavailable>")
        _names = list(_IDENTITY_ROOTS)
    for _n in _names:
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


def _render_kinds(text):
    """Every AST class name a recorded rendering contains, read EXACTLY rather than matched.

    This is what the length prefixes are FOR. `u:<n>:` and `b:<n>:` say how many characters
    follow, so a reader skips a payload by counting instead of by looking for a delimiter -- and
    a string literal containing `Attribute(` cannot be mistaken for an Attribute node. A regular
    expression over the same text would have no way to tell the two apart, which is the kind of
    difference that decides a verdict about whether a control still exists.

    ⛔ ROUND 13: THIS ASSUMED FOREIGN TEXT FOLLOWED ITS OWN GRAMMAR. A SPEC/1 record -- an
    unprefixed `u:` payload -- raised `ValueError` out of the first declared command, in the one
    branch reached because the renderer is known to differ. A text this reader cannot parse is
    the answer, not an exception: it returns None, and the caller treats None as uncomparable.
    """
    return None if _render_features(text) is None else {f for f in _render_features(text)
                                                          if not f.startswith("scalar:")}


def _is_float_token(tok):
    """Does this token spell a finite float the way `float.__repr__` spells one? Ints are not floats."""
    if not tok or not ("." in tok or "e" in tok) or tok.lstrip("-")[:1] not in "0123456789":
        return False
    try:
        float(tok)
    except ValueError:
        return False
    return all(c in "0123456789.e+-" for c in tok)


def _render_features(text):
    """The FEATURES a recorded rendering exercises: node kinds AND scalar forms. None if unreadable.

    ⛔⛔ ROUND 13: PROOF BY NODE KIND WAS STILL TOO COARSE, ONE LEVEL DOWN FROM ROUND 12. A
    rendering is kind structure plus scalar encoding, and the second half had no representation
    in the proven set. Change how quotes are escaped inside strings: the one record whose
    constant contains a quote is `gone` -- *no statement of this shape remains* -- while its
    kinds (Expr, Call, Attribute, Name, Load, Constant, Return) are all proven by the other 25.
    The int-encoder version was caught by luck: the four records with int constants were the
    four with Slice and Subscript. Change the correlation and the guard is gone.

    ⇒ THE UNIT OF PROOF IS THE FEATURE SET A RENDERING CAN DIFFER IN: {node kinds} ∪ {scalar
    forms exercised}, both computable from the recorded text. A record that matched proves the
    renderer for exactly the features its own text contains; a record that matches nothing is
    GONE only if every feature in its text was proven by some record that did match. Still a
    sample of the encoding -- a value-dependent change that spares every recorded value is
    invisible to any proof over recorded text -- but a sample of the WHOLE encoding rather than
    half of it, and stated as one.

    Scalar forms: scalar:None/True/False/Ellipsis; scalar:int, scalar:int:neg; scalar:float,
    scalar:float:nan|inf|exp|neg|negzero; scalar:str, scalar:str:empty, scalar:str:escaped (a
    backslash in the escaped payload), scalar:str:quote; scalar:bytes, scalar:bytes:empty;
    scalar:complex.

    ⛔ ROUND 14: `scalar:int:neg` existed and `scalar:float:neg` did not, so a renderer change
    confined to negative floats was condemned-provable by any positive float while the identical
    change for ints needed its own negative witness. Sign is a form for both numeric types now,
    and negative zero -- a value the probe set carries and the reader could not tell from zero --
    is its own form. Still a sample of the encoding, stated as one.
    """
    feats, i, n = set(), 0, len(text)
    try:
        while i < n:
            if text.startswith(("u:", "b:"), i) and (i == 0 or not (text[i - 1].isalnum()
                                                                     or text[i - 1] in "_.")):
                j = text.index(":", i + 2)
                cnt = int(text[i + 2:j])
                payload = text[j + 1:j + 1 + cnt]
                if len(payload) != cnt:
                    return None
                if text[i] == "u":
                    feats.add("scalar:str")
                    if not payload:
                        feats.add("scalar:str:empty")
                    if chr(92) in payload:
                        feats.add("scalar:str:escaped")
                    if "'" in payload or '"' in payload:
                        feats.add("scalar:str:quote")
                else:
                    feats.add("scalar:bytes")
                    if not payload:
                        feats.add("scalar:bytes:empty")
                i = j + 1 + cnt
                continue
            if text.startswith("c:", i) and (i == 0 or text[i - 1] in "=,[("):
                feats.add("scalar:complex")
                i += 2
                continue
            j = i
            while j < n and (text[j].isalnum() or text[j] in "_.+-"):
                j += 1
            if j > i:
                tok = text[i:j]
                if j < n and text[j] == "(" and tok[:1].isupper():
                    feats.add(tok)
                elif tok in ("None", "True", "False", "..."):
                    feats.add("scalar:" + tok if tok != "..." else "scalar:Ellipsis")
                elif tok in ("nan", "inf", "-inf"):
                    feats.add("scalar:float")
                    feats.add("scalar:float:" + tok.lstrip("-"))
                    if tok.startswith("-"):
                        feats.add("scalar:float:neg")
                elif tok.lstrip("-").isdigit():
                    feats.add("scalar:int")
                    if tok.startswith("-"):
                        feats.add("scalar:int:neg")
                # ⛔ ROUND 15: THE CHARACTER PREDICATE STRIPPED ONE `-` AND NO `+`, so `1e+300` -- in the probe
                # set -- was not a float token at all and a record whose only scalar was one carried an
                # EMPTY feature set: proven by any survivor, coverable by anything. ⇒ A float token is
                # whatever the renderer wrote for a float: recognised by parsing it as one, with the
                # forms `float.__repr__` produces (a point, or an exponent with either sign).
                elif _is_float_token(tok):
                    feats.add("scalar:float")
                    if "e" in tok:
                        feats.add("scalar:float:exp")
                    if tok.startswith("-"):
                        feats.add("scalar:float:neg")
                    if tok == "-0.0":
                        feats.add("scalar:float:negzero")
                i = j
            else:
                i += 1
    except (ValueError, IndexError):
        return None
    return feats


def renderer_proven(items):
    """The AST node kinds this renderer is SHOWN to reproduce, as a set. Empty means none.

    ⛔⛔ A ROUTINE DOCSTRING EDIT RELABELLED A DELETION AS AN INTERPRETER DIFFERENCE. Delete a
    watched control with the tag unchanged and the tool is exact:

        quick replay of 26: 25 replayed, 1 unidentifiable
          mp_metric.py:205   its statement is gone in this tree            exit 1

    Edit one docstring line inside `_render` -- output unchanged, the over-sensitivity this design
    accepts -- with the same control still deleted:

        quick replay of 26: 26 replayed, 0 unidentifiable
          ⚠ mp_metric.py:205  recorded under r647...; this interpreter renders ra56...
          ⚠ Nothing is established about them either way -- re-run reach_controls.py to re-record

    **The operator is told the wrong cause and pointed at a remedy that drops the finding.** The
    deletion survives the re-record, because re-recording writes down the tree as it now is.

    ⇒ THE DISCRIMINATOR WAS ALREADY ON THE SCREEN, ONE LINE APART: `exact 25, uncomparable 1`. A
    renderer change fails EVERY record; a deletion fails ONE. This project's own constant-residual
    rule says the shared factor is the explanation only when it explains all of them -- so if any
    record resolves against its recorded text, this renderer is demonstrably able to compare, and
    a record that does not match is GONE rather than uncomparable.

    ⚠️ IT IS EVIDENCE, NOT AN ASSUMPTION. With one record, or with every record failing, the
    set is empty and `uncomparable` stands -- which is the case it was introduced for.

    ⛔⛔ AND IT RETURNED ONE BOOLEAN FOR THE WHOLE SWEEP, WHICH IS ROUND 9'S FINDING INVERTED.
    A renderer change confined to ONE NODE KIND is what a grammar revision actually looks like,
    and against it the sweep answer is wrong in the direction that condemns untouched controls:

        exact 20, gone 6      rendering: rb50c4e392bc7
        gone         : mp_metric.py:205, replay.py:687, 881, 883, 885, 1156
        has Attribute: mp_metric.py:205, replay.py:687, 881, 883, 885, 1156   identical: True

    Twenty records happened not to use the changed node kind, so the renderer was "proven" by
    them, and the six that did use it were reported GONE. Round 9 gated a per-node property
    whole-record; this applied a whole-sweep proof to a per-node difference.

    ⇒ THE DISCRIMINATOR IS ON THE SCREEN AGAIN, AND IT IS THE SAME ONE. A residual of six that
    is exactly the set carrying a node kind the twenty do not carry is a fingerprint, not a
    coincidence -- this project's own constant-residual rule says the shared factor explains the
    residual only when it explains ALL of it. So the evidence is kept at the granularity it was
    collected at: a record that matched proves this renderer for the node kinds ITS OWN rendering
    contains, and nothing beyond them. A record that matches nothing is GONE only if every kind
    in its recorded text was proven by some record that did match; otherwise the honest answer is
    that this renderer has not been shown to render that kind, and the record is uncomparable.

    ⚠ It is computed from the RECORDED renders, which the tool already holds, so it costs no
    new notion of identity and no second route to one -- the same rule at the right granularity.
    """
    _proven, _trees = set(), {}
    for _path, _ident in items:
        _rr = _ident.get("render")
        if not _rr:
            continue
        if _path not in _trees:
            try:
                _trees[_path] = ast.parse(
                    pathlib.Path(_path).read_text(encoding="utf-8", errors="replace"))
            except (OSError, SyntaxError):
                _trees[_path] = None
        _tree = _trees[_path]
        if _tree is None:
            continue
        _want = _ident.get("qualname", "")
        _scopes_ = [n for nm, n in _scopes(_tree) if nm == _want] if _want else [_tree]
        # ⚠ EVERY record is now examined. The old loop returned on the first match, which was
        # sound for a yes/no answer and is not sound for an answer about which kinds were seen.
        for _sc in _scopes_:
            for _s in _statements(_sc):
                if _render(_s) == _rr:
                    _f = _render_features(_rr)
                    if _f:
                        _proven |= _f
                    break
    return _proven


def unproven_kinds(ident, proven):
    """The FEATURES in this record's recorded rendering that `proven` does not cover -- node
    kinds and scalar forms alike (the name is kept for its callers). A rendering this reader
    cannot parse is unproven in its entirety: `["<unreadable rendering>"]`."""
    _f = _render_features(ident.get("render") or "")
    if _f is None:
        return ["<unreadable rendering>"]
    return sorted(_f - set(proven or ()))


def resolve(path, ident, recorded_line=None, comparable=()):
    """(lineno, status). One of exact / moved / ambiguous / gone / uncomparable.

    `comparable` is the set of node kinds `renderer_proven()` found this renderer reproducing
    somewhere in this tree. A record that matches nothing is a statement about the TREE rather
    than about the renderer only for the kinds that set covers -- see `renderer_proven`, and
    `unproven_kinds` for the ones it does not.
    """
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
        #
        # ⇒ AND THE EVIDENCE IS READ AT THE GRANULARITY IT WAS COLLECTED AT. A sweep-wide
        # "the renderer works" let twenty records that never used the changed node kind prove a
        # renderer for six that did, and the six were condemned. The question is not whether ANY
        # record matched; it is whether every kind THIS record's rendering contains was
        # reproduced by a record that did match. A kind nothing proved is a kind about which this
        # renderer has shown nothing, and a record standing on one is uncomparable.
        if not _same_renderer and unproven_kinds(ident, comparable):
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
    # ⇒ ONE PASS TO ASK WHETHER THIS RENDERER CAN COMPARE AT ALL, then the verdicts. See
    # `renderer_proven`: the answer is a property of the SWEEP, not of any single record, and
    # reading it per record is what let one deletion wear a renderer change's clothes.
    _items = []
    for _w, _i in sorted(detail.items()):
        _f, _l = _w.rsplit(":", 1)
        _id = _i.get("identity") or identify(HERE / _f, int(_l))
        if _id is not None:
            _items.append((HERE / _f, _id))
    _comparable = renderer_proven(_items)
    if not _comparable and _items and _items[0][1].get("canon") != _canon_tag():
        print("  %s no record matches its own recorded text under this renderer, so a record that "
              "does not match says nothing about the tree" % chr(0x26A0))
    for where, info in sorted(detail.items()):
        f, ln = where.rsplit(":", 1)
        ident = info.get("identity") or identify(HERE / f, int(ln))
        if ident is None:
            counts["no-identity"] += 1
            print("  %-22s no statement at that line" % where)
            continue
        line, status = resolve(HERE / f, ident, recorded_line=int(ln), comparable=_comparable)
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
