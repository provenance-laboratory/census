"""The hostile referee. Every case here TRIES TO GET A BAD CELL PAST validate().

obl-metric's round-2 lesson, recorded before this instrument had a single subject: *a test written
by the artifact's author validates the author's model of the artifact.* Its own suite passed 0/0
while an external `revision_check.py` found nine manuscript-vs-engine mismatches. So this suite is
written adversarially -- each case is an attempt to smuggle something through, and it FAILS if the
validator lets it in.

The last group is the substantive one. It does not test a rule; it demonstrates the arithmetic
that makes N/A dangerous: because N/A leaves the DENOMINATOR, a release can raise its as-coded
score by disclosing LESS, provided the undisclosed axes are ones it can call inapplicable. If that
property ever stops holding, the scoring changed and the paper's warning is stale.

    python stress_test.py       exit 0 = every attack was caught and the honest census passed
"""
import ast
import io
import json
import pathlib
import sys

import axes as A
import mp_metric as M

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

EV = [{"url": "https://example.org/a", "retrieved": "2026-08-01", "sha256": "a" * 64}]
# ⚠ `HERE` AND `D` WERE READ BY THIS FILE AND DEFINED BY NONE OF IT. The control
# written to report exactly that raised NameError before it could report anything --
# the defect inside its own detector, found by running it rather than by reading it.
HERE = pathlib.Path(__file__).resolve().parent
D = chr(0x26D4)
W = chr(0x26A0)
passed, failed = 0, 0



def _own_nodes(fn):
    """Every node belonging to `fn` itself, not to a function nested inside it.

    ⛔ THE PREVIOUS VERSION WALKED EVERY FunctionDef INDEPENDENTLY and reported 141 findings on
    a clean census -- every closure variable, because a name bound in an enclosing function is
    neither module-scope nor local to the nested one. symtable had handled nesting; rewriting on
    raw AST to get statement ORDER silently dropped it. Two correct requirements, one lost while
    satisfying the other, which is this project's recurring shape.
    """
    out, stack = [], list(ast.iter_child_nodes(fn))
    while stack:
        n = stack.pop()
        out.append(n)
        # ⛔ A NESTED DEF INSIDE AN `if` WAS NEVER BOUND. Skipping these nodes entirely
        # meant a helper defined in a conditional branch -- control_audit.py's `_ident` -- read as
        # undefined in the function that calls it. The node is COLLECTED (so its name binds) and
        # its BODY is not descended into (so its locals stay its own).
        # ⛔ EXCLUDING COMPREHENSION TARGETS FROM THE ENCLOSING BINDINGS WITHOUT ALSO EXCLUDING
        # THE COMPREHENSION'S OWN READS reported 197 findings on a clean tree: `[a for a in xs]`
        # reads `a` legitimately INSIDE the comprehension, and the enclosing scan still saw that
        # read while no longer seeing the binding. Half-modelling a scope is worse than not
        # modelling it. A comprehension is a scope and is walked as one, like a lambda.
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
                      + (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            continue
        stack.extend(ast.iter_child_nodes(n))
    return out


def _module_bindings(tree):
    """Names module scope binds, split by whether the binding is UNCONDITIONAL.

    ⛔ A NAME BOUND ONLY INSIDE `if False:` IS ASSIGNED TO symtable AND ABSENT AT RUNTIME. A
    reviewer defeated an earlier version with exactly that, four lines long, and the suite said
    "ok". Reading the module body as a SEQUENCE separates a binding that always happens from one
    that might not -- which is the one thing symtable cannot tell us.

    ⛔ THIS FUNCTION WAS DEFINED TWICE IN THIS FILE, and Python kept the second. The dead copy
    carried the ten-line argument for the round-12 wildcard/`globals()` repair; the live copy
    carried the repair itself and none of the reasoning. Anyone deleting "the duplicate" had a
    coin-flip chance of deleting the mechanism, and a reviewer showed the live copy could be
    removed with the suite still reporting 47 passed, 0 failed. That is the round-24 duplicated-
    paragraph finding one level out -- a shingle control was built for PROSE paragraphs and the
    three-line AST equivalent was not built for SOURCE, inside the very file that hosts the
    undefined-name control. The two copies are one function now, and `_duplicate_defs()` below
    fails the suite if any module in the tree defines one name twice.

    ⚠ THE ROUND-12 REASONING, kept here because it belongs beside the code it explains: a round-12
    reviewer showed `from math import *; sqrt(4)` and `globals()["DYNAMIC_NAME"] = ...` both
    reported as "reads a name nothing in scope defines". A wildcard import means the module's
    names cannot be enumerated, so findings for that module are SUPPRESSED and the wildcard is
    reported instead -- the undecidability is named rather than converted into a false accusation.
    A literal `globals()["X"] = ...` key IS a binding and is collected.
    """
    always, maybe = set(), set()
    # name -> [(first line, last line)] of each CONDITIONAL body that binds it. An inline scope
    # written inside one of these ranges is evaluated while that body runs; one written outside
    # is deferred. This is what lets the check narrow on containment instead of on scope type.
    spans = {}

    def _targets(node):
        tgts = list(getattr(node, "targets", []) or [])
        if getattr(node, "target", None) is not None:
            tgts.append(node.target)
        for tgt in tgts:
            for n in ast.walk(tgt):
                if isinstance(n, ast.Name):
                    yield n.id

    # ⛔ `match` AND `except*` BIND NAMES AND WERE NOT WALKED, so a module binding a name only in a
    # match case or a TryStar handler was reported as reading an undefined name -- a false
    # positive on code that runs clean. A reviewer wrote both. They do not occur in this tree
    # today, which is exactly why they were missed: a branch no data has taken is UNDEFINED, not
    # settled.
    _COND = (ast.If, ast.While, ast.For, ast.Try, ast.With)
    for _extra in ("Match", "TryStar", "AsyncFor", "AsyncWith"):
        if hasattr(ast, _extra):
            _COND = _COND + (getattr(ast, _extra),)

    def _note(names, span):
        if span is None:
            return
        for _nm in names:
            spans.setdefault(_nm, []).append(span)

    def _walk(body, conditional, span=None):
        sink = maybe if conditional else always
        for st in body:
            if isinstance(st, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                _t = set(_targets(st))
                sink.update(_t)
                if conditional:
                    _note(_t, span)
            elif isinstance(st, (ast.Import, ast.ImportFrom)):
                if any(a.name == "*" for a in st.names):
                    sink.add("*")
                sink.update((a.asname or a.name).split(".")[0]
                            for a in st.names if a.name != "*")
            elif isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                sink.add(st.name)
            elif isinstance(st, ast.Delete):
                # ⚠ `del X` at module scope UNBINDS. Treating the earlier assignment as still
                # standing made a real NameError invisible. A deleted name is demoted to `maybe`
                # rather than dropped, because reporting it as undefined would be a second guess
                # about control flow this pass cannot make.
                for t in st.targets:
                    for n in ast.walk(t):
                        if isinstance(n, ast.Name):
                            always.discard(n.id)
                            maybe.add(n.id)
            elif isinstance(st, _COND):
                _span = (st.lineno, getattr(st, "end_lineno", st.lineno) or st.lineno)
                for attr in ("body", "orelse", "finalbody"):
                    _walk(getattr(st, attr, []) or [], True, _span)
                for h in getattr(st, "handlers", []) or []:
                    _walk(h.body, True, _span)
                for c in getattr(st, "cases", []) or []:
                    # ⚠ AN IRREFUTABLE CASE ALWAYS RUNS IF IT IS REACHED: `case _:` or a bare
                    # capture, with no guard, cannot fail to match. Its bindings are therefore
                    # unconditional, and calling them conditional would cry wolf on the ordinary
                    # exhaustive-match idiom. A case with a PATTERN can fail, so its bindings stay
                    # conditional -- which is a true statement about the name, and is why the
                    # message says "binds only inside a conditional" rather than "nothing defines
                    # it": the earlier version could not see match bindings at all and gave the
                    # wrong diagnosis for the right sentence.
                    _pat = getattr(c, "pattern", None)
                    _irrefutable = (getattr(c, "guard", None) is None
                                    and isinstance(_pat, ast.MatchAs)
                                    and getattr(_pat, "pattern", None) is None)
                    _walk(c.body, not _irrefutable, _span)
                    # The capture names in the PATTERN bind the same way the case body does, so
                    # they follow the same irrefutability. Adding them to `maybe` unconditionally
                    # made `case N:` -- which cannot fail -- look conditional, and the check then
                    # fired on the ordinary exhaustive idiom.
                    _psink = always if _irrefutable else maybe
                    for n in ast.walk(_pat or ast.Pass()):
                        if isinstance(n, ast.MatchAs) and n.name:
                            _psink.add(n.name)
                        elif isinstance(n, ast.MatchStar) and getattr(n, "name", None):
                            _psink.add(n.name)
                        elif isinstance(n, ast.MatchMapping) and getattr(n, "rest", None):
                            _psink.add(n.rest)
                        if _psink is maybe:
                            _note([x for x in (getattr(n, "name", None),
                                               getattr(n, "rest", None)) if x], _span)
    _walk(tree.body, False)
    for n in ast.walk(tree):
        if (isinstance(n, ast.Subscript) and isinstance(n.value, ast.Call)
                and isinstance(n.value.func, ast.Name) and n.value.func.id == "globals"
                and isinstance(n.slice, ast.Constant) and isinstance(n.slice.value, str)):
            always.add(n.slice.value)
        # An `except* E as e:` handler binds `e`; so does `except E as e:`.
        if isinstance(n, ast.ExceptHandler) and n.name:
            maybe.add(n.name)
    return always, maybe - always, spans


def _shadowed_reads(tree):
    """Functions that READ a name above the line they assign it, where an outer scope has it.

    ⚠ This is the one question symtable cannot answer: it knows a name is local to a function,
    not WHERE. `build_paper.py` read `D` at line 709 and assigned it at 1198 -- a defect -- while
    a function that assigns `out` and then reads it is not. Only the ordering separates them, so
    only the ordering is computed here, and everything else is left to symtable.
    """
    # ⛔ THIS EXAMINED FunctionDef AND AsyncFunctionDef ONLY, so a lambda could shadow a name and
    # read it before assigning: `D = 1; f = lambda: (D, (D := 2))` raises UnboundLocalError at
    # runtime and this said nothing. A reviewer wrote it in two lines. A lambda is a function
    # scope with the same local-shadowing rule; the only reason it was excluded is that the walk
    # enumerated node TYPES instead of asking what a scope is.
    out = []
    _SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
    for fn in ast.walk(tree):
        if not isinstance(fn, _SCOPES):
            continue
        first, reads, glob = {}, [], set()
        for n in ast.walk(fn):
            # ⚠ Do not descend into a NESTED scope: its locals are its own, and reading a name
            # there says nothing about the ordering in this one.
            if isinstance(n, _SCOPES) and n is not fn:
                continue
            if isinstance(n, (ast.Global, ast.Nonlocal)):
                glob.update(n.names)
            elif isinstance(n, ast.Name):
                # ⚠ ORDER IS (line, column), NOT LINE. A lambda fits the shadowing read and the
                # assignment on ONE line -- `lambda: (D, (D := 2))` -- so comparing line numbers
                # alone made the read look non-earlier and the check stayed silent on code that
                # raises UnboundLocalError. Within a line, position decides.
                _pos = (n.lineno, n.col_offset)
                if isinstance(n.ctx, (ast.Store, ast.Del)):
                    if n.id not in first or _pos < first[n.id]:
                        first[n.id] = _pos
                elif isinstance(n.ctx, ast.Load):
                    reads.append((n.id, _pos))
        for nm, ln in reads:
            if nm in glob or nm not in first:
                continue
            if ln < first[nm]:
                out.append((getattr(fn, "name", None) or "<lambda>", nm))
    return out


def undefined_module_reads(where=None):
    """Names a function cannot read when its line runs -- in each of the ways that happens.

    ⛔ NINE OF THESE SHIPPED ACROSS THE TWO PROJECTS, every one on an error path, so each raised
    instead of reporting and only once something had already gone wrong. Three shapes: UNDEFINED
    (nothing in scope binds it), SHADOWED (an outer scope binds it and this function assigns it
    later, so reads above that line raise UnboundLocalError), and CONDITIONAL (module scope binds
    it only inside `if`/`try`/`while`).

    ⛔ THIS FUNCTION WAS REWRITTEN ONTO RAW AST TO GET STATEMENT ORDER, AND IN DOING SO
    REIMPLEMENTED PYTHON'S SCOPE RULES BADLY -- eight iterations, and each one traded a fixed
    false negative for a new class of false positive: 141 findings when nested functions were
    dropped, 197 when comprehension targets were half-modelled, 258 when the module walk descended
    into functions, 25 when nested comprehensions were not scopes. A round-25 reviewer then showed
    the version that survived all that was blind to every lambda body -- 87 in this directory, 75
    in the paper toolchain, 69 of them `claim(sentence, predicate)` -- and read comprehensions
    with Python 2 scoping.

    ⇒ symtable IMPLEMENTS PYTHON'S SCOPE RULES AND WAS HERE ALL ALONG. It handles lambdas,
    comprehensions, closures and class bodies correctly and for free. It was abandoned because it
    cannot order a read against an assignment -- which is ONE of the three shapes. So symtable
    answers the two it can and a small AST pass answers the third, instead of a hand-rolled scope
    walker answering all three approximately.

    ⚠ KNOWN BLIND SPOT, DISCLOSED RATHER THAN FIXED: a binding created through
    `globals()[expr] = ...` with a non-literal key is not statically decidable and is not
    detected. A literal key IS collected.
    """
    import builtins as _b
    import symtable as _st
    out = []
    for f in sorted((where or HERE).glob("*.py")):
        try:
            src = f.read_text(encoding="utf-8")
            tree = ast.parse(src)
            top = _st.symtable(src, f.name, "exec")
        except (SyntaxError, UnicodeDecodeError, ValueError):
            continue
        always, maybe, _spans = _module_bindings(tree)
        if "*" in always:
            # ⚠ A wildcard import makes the module's names unenumerable. Reporting every
            # unresolved read would be a false accusation; the wildcard is the finding, once.
            out.append("%s: `from ... import *` makes this module's names unenumerable, so "
                       "undefined-name findings are SUPPRESSED here. Remove the wildcard to get "
                       "the check back." % f.name)
            continue
        known = always | set(dir(_b)) | {"__file__", "__name__", "__doc__", "__package__",
                                         "__spec__", "__loader__", "__builtins__", "__debug__",
                                         "__class__", "__qualname__", "__module__"}
        stack = [top]
        while stack:
            sc = stack.pop()
            stack.extend(sc.get_children())
            if sc is top:
                continue
            for s in sc.get_symbols():
                # a name symtable calls GLOBAL here is one no enclosing scope binds
                if not (s.is_global() and not s.is_assigned()):
                    continue
                n = s.get_name()
                if n in known:
                    continue
                if n in maybe:
                    # ⛔ A CONDITIONAL BINDING READ FROM AN INLINE SCOPE IS NOT A DEFECT. A
                    # comprehension or lambda written inside the same `for`/`if` body that binds
                    # the name is evaluated while that body runs, so the binding has happened.
                    # Reporting those gave two false positives on a clean tree -- `sc` in
                    # mp_metric.py and `_low` in this file -- and a checker that cries wolf gets
                    # switched off, which this project has now written down three times.
                    #
                    # ⚠ The reviewer's evasion was `if False: X = ...` read from a DEF, which is
                    # deferred: the function can be called at any later time, including a time at
                    # which the branch never ran. That case is kept. The narrowing is to scopes
                    # whose execution is deferred, not to scopes that happen to be convenient.
                    #
                    # ⛔ AND THE CODE DID NOT DO WHAT THE COMMENT ABOVE SAYS. It narrowed on the
                    # scope's TYPE, so every lambda and every comprehension was exempted -- which
                    # made lambdas blind to the conditional shape again, through the exact
                    # construct the previous round had been fixing, and restored the round-10
                    # reviewer's `if False: X = ...` evasion. `f = lambda: X` at module level is
                    # deferred in precisely the way a `def` is: it is CALLED later, possibly never
                    # having had the branch run. A reviewer wrote it in four lines and the
                    # detector said nothing while Python raised NameError.
                    #
                    # ⇒ Narrow on LEXICAL CONTAINMENT, which is what the comment always said: an
                    # inline scope written INSIDE the conditional body that binds the name is
                    # evaluated while that body runs, so the binding has happened. One written
                    # outside it is deferred and is reported. `_spans` carries the line range of
                    # each conditional body that binds each name.
                    _inline = (sc.get_type() != "function"
                               or sc.get_name() in ("lambda", "genexpr", "listcomp",
                                                    "setcomp", "dictcomp"))
                    if _inline:
                        _ln = sc.get_lineno()
                        if any(_a <= _ln <= _b for _a, _b in _spans.get(n, ())):
                            continue
                        what = ("which module scope binds only inside a conditional this "
                                "deferred scope is not written inside -- it may not exist when "
                                "this line runs")
                        out.append("%s:%s reads %r, %s" % (f.name, sc.get_name(), n, what))
                        continue
                    what = ("which module scope binds only inside a conditional -- it may not "
                            "exist when this line runs")
                else:
                    # ⛔ THE MESSAGE ASSERTED MORE THAN THE ANALYSIS KNEW. "nothing in scope
                    # defines it" is a claim about the program; what this pass knows is that no
                    # STATICALLY VISIBLE binding exists. A module that binds through
                    # `globals()[expr] = ...` with a computed key is not statically decidable --
                    # the docstring discloses exactly that -- and the finding still read as an
                    # accusation. A reviewer hit it with a dynamic-key probe: a liveness false
                    # positive stated as a defect.
                    #
                    # ⇒ The tolerated edge is NAMED in the finding, so a reader can tell an
                    # undecidable case from a real one without reading this source.
                    _dyn = any(isinstance(_x, ast.Subscript)
                               and isinstance(_x.value, ast.Call)
                               and isinstance(_x.value.func, ast.Name)
                               and _x.value.func.id == "globals"
                               and isinstance(_x.ctx, ast.Store)
                               for _x in ast.walk(tree))
                    what = ("which no statically visible binding defines -- and this module also "
                            "assigns through globals() with a computed key, which is UNDECIDABLE "
                            "here, so treat this as a dynamic-globals edge rather than a defect"
                            if _dyn else "which nothing in scope defines")
                out.append("%s:%s reads %r, %s" % (f.name, sc.get_name(), n, what))
        for fname, nm in _shadowed_reads(tree):
            if nm in known:
                out.append("%s:%s reads %r above the line it assigns it, while an outer scope "
                           "also defines it -- that read raises UnboundLocalError"
                           % (f.name, fname, nm))
    return sorted(set(out))


def full_census(subject="s1", score=0, cell_over=None, **over):
    """A complete, valid census: every one of the 22 axes present for one subject.

    ⚠️ `**over` updates the LEDGER. An earlier test passed `check=...` expecting it to reach the
    cells; it became a stray top-level key and the test passed for the wrong reason -- vacuously,
    like the two PDF controls found the same day. `cell_over` is the parameter that reaches cells.

    The default score-2 check now picks a method VALID FOR EACH AXIS, because a fixture that
    violates method-axis compatibility on 20 of 22 axes cannot be used to test anything else.
    """
    cells = []
    for ax in A.BY_ID:
        # A valid census respects the instrument OWN caps: a completeness or search axis
        # cannot be 2 for anyone, so a fixture claiming otherwise is not a valid census.
        c = {"subject": subject, "axis": ax,
             "score": min(score, A.max_for(ax, "open-weights")) if score else score}
        if c["score"] and c["score"] > 0:
            c["evidence"] = list(EV)
            if c["score"] == 2:
                # An axis that REQUIRES a method gets it; otherwise prefer grep. A valid
                # census must satisfy the instrument's own requirements, not merely its
                # permissions -- which is the distinction round-6 review turned into a defect.
                req = A.required_method(ax)
                valid = sorted(A.methods_for(ax))
                meth = (sorted(req)[0] if req else
                        ("grep_retrieved" if "grep_retrieved" in valid else
                         (valid[0] if valid else "grep_retrieved")))
                c["check"] = {"method": meth, "asserts": "the material is present",
                              "observed": "it is present"}
                for f in A.required_fields(meth):
                    c["check"][f] = ["something"] if f == "expect" else 1
            if cell_over:
                c.update({k: dict(v) if isinstance(v, dict) else v
                          for k, v in cell_over.items()})
        cells.append(c)
    # A valid census DECLARES its policy: which sources, documents, methods and literals may
    # settle which axis. The rule fails closed, so a fixture without one is not a valid census --
    # which is the point of failing closed.
    import replay as _R                                                   # noqa: PLC0415
    _urls = sorted({e["url"] for c in cells for e in (c.get("evidence") or [])})
    _srcs = sorted({_R.source_key(u) for u in _urls})
    led = {"as_of": "2026-08-01",
           "subjects": [{"id": subject, "kind": "open-weights", "sources": _srcs,
                         "axis_sources": {str(c["axis"]): _srcs for c in cells if c.get("score")},
                         "axis_documents": {str(c["axis"]):
                                            sorted(e["url"] for e in (c.get("evidence") or []))
                                            for c in cells if c.get("score")},
                         "axis_method": {str(c["axis"]): (c.get("check") or {}).get("method")
                                         for c in cells if c.get("score")},
                         # Every scored axis declares literals EXPLICITLY, [] where there are
                         # none -- a missing key is now a defect, not an exemption.
                         "axis_literals": {str(c["axis"]):
                                           sorted((c.get("check") or {}).get("expect") or [])
                                           for c in cells if c.get("score")}}],
           "cells": cells}
    led.update(over)
    return led


def must_catch(name, led, needle):
    """The validator MUST report a defect mentioning `needle`."""
    global passed, failed
    d = M.validate(led)
    hit = any(needle.lower() in x.lower() for x in d)
    print(("  ok    " if hit else "  FAIL  ") + name)
    if hit:
        passed += 1
    else:
        failed += 1
        print("          validator said: %s" % (d[:2] or "NOTHING — it let this through"))


def must_pass(name, led):
    global passed, failed
    d = M.validate(led)
    print(("  ok    " if not d else "  FAIL  ") + name)
    if not d:
        passed += 1
    else:
        failed += 1
        print("          unexpected defects: %s" % d[:3])


print("=" * 78)
print("  hostile referee — every case below is an ATTACK on validate()")
print("=" * 78)
print()

# ── the evidence standard ─────────────────────────────────────────────────────────────
led = full_census(score=1)
del led["cells"][0]["evidence"]
must_catch("a CLAIMED cell with no evidence record", led, "no evidence")

led = full_census(score=2)
del led["cells"][3]["check"]
must_catch("a VERIFIED cell with no check at all", led, "check` OBJECT")

# ── the three holes round-1 review drove through the validator ─────────────────────────
led = full_census(score=2)
for c in led["cells"]:
    c["check"] = "read a document"
must_catch("VERIFIED on a free-text check -- the round-1 attack", led, "not a control")

led = full_census(score=2)
led["cells"][0]["check"] = {"method": "i_looked_at_it", "asserts": "a", "observed": "b"}
must_catch("a check method that is not implemented", led, "not registered")

led = full_census(score=2)
led["cells"][0]["check"] = {"method": "http_range", "asserts": "", "observed": "y"}
must_catch("a check with no stated assertion", led, "check.asserts is empty")

led = full_census(score=1)
led["cells"][0]["evidence"] = [{"url": "https://x/a", "retrieved": "2026-99-99",
                               "sha256": "b" * 64}]
must_catch("a retrieval date that is not a real date", led, "real yyyy-mm-dd")

led = full_census(score=1)
led["cells"][0]["evidence"] = [{"url": "https://x/a", "retrieved": "2099-01-01",
                               "sha256": "b" * 64}]
must_catch("a retrieval date in the future", led, "future")

led = full_census(score=1)
led["cells"][0]["evidence"] = [{"url": "https://x/same", "retrieved": "2026-08-01",
                               "sha256": "c" * 64}]
led["cells"][1]["evidence"] = [{"url": "https://x/same", "retrieved": "2026-08-01",
                               "sha256": "d" * 64}]
must_catch("one url recorded under two different digests", led, "two different digests")

led = full_census(score=1)
led["cells"][0]["evidence"] = [{"url": "https://x/a", "retrieved": "2026-08-01",
                               "sha256": "not-a-digest"}]
must_catch("evidence whose sha256 is not a digest", led, "sha256")

led = full_census(score=1)
led["cells"][0]["evidence"] = [{"url": "https://x/a", "retrieved": "Sept 2026",
                               "sha256": "b" * 64}]
must_catch("evidence with an unparseable retrieval date", led, "yyyy-mm-dd")

led = full_census(score=1)
led["cells"][0]["evidence"] = [{"url": "ftp://x/a", "retrieved": "2026-08-01",
                               "sha256": "b" * 64}]
must_catch("evidence with no retrievable url", led, "url")

# ── the N/A escape hatch ──────────────────────────────────────────────────────────────
led = full_census(score=0)
led["cells"][0]["score"] = None                    # axis 1 -- can never be N/A
led["cells"][0]["na_reason"] = "we would rather not say"
must_catch("N/A on an axis that can never be N/A", led, "never be n/a")

led = full_census(score=0)
for c in led["cells"]:
    if c["axis"] in A.NA_PERMITTED:
        c["score"] = None                          # permitted axis, but no reason given
must_catch("N/A in bulk with no per-cell reason", led, "no na_reason")

# ── completeness: absent is not zero ──────────────────────────────────────────────────
led = full_census(score=0)
led["cells"] = [c for c in led["cells"] if c["axis"] != 7]
must_catch("a subject-axis pair simply missing", led, "missing")

led = full_census(score=0)
led["cells"].append(dict(led["cells"][0]))
must_catch("the same cell recorded twice", led, "duplicate")

led = full_census(score=0)
led["cells"][0]["axis"] = 99
must_catch("a cell on an axis that does not exist", led, "not one of the 22")

led = full_census(score=0)
led["cells"][0]["subject"] = "ghost"
must_catch("a cell for an undeclared subject", led, "not declared")

led = full_census(score=0)
led["cells"][0]["score"] = 3
must_catch("a score outside 2/1/0/null", led, "not 2/1/0")

# ── the positive control ──────────────────────────────────────────────────────────────
must_pass("an honest, complete census validates", full_census(score=1))

# ── the wall detector: a gate versus a document that describes one ─────────────────────
print()
print("  --- fetch_artifact: is it a gate, or a manual about one? ---")
import fetch_artifact as FA

long_doc = (b"# Downloading the weights" + b" filler." * 2000 +
            b" Visit the website, read and accept the license, then download.")
tiny_gate = b"<html><body>You need to agree to share your contact information</body></html>"
challenge = b"<html>" + b"x" * 9000 + b"checking your browser before accessing</html>"

cases = [
    ("10 KB manual that MENTIONS accepting a licence is NOT a gate", long_doc, None),
    ("a short page that only says 'you need to agree' IS a gate", tiny_gate, "gate"),
    ("a long page containing a browser challenge IS a gate", challenge, "challenge"),
]
for name, body, want in cases:
    got = FA.looks_like_a_wall(body, "200")
    ok = (got is None) if want is None else (got is not None)
    print(("  ok    " if ok else "  FAIL  ") + name)
    passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)
    if not ok:
        print("          got: %r" % got)

# a Git-LFS pointer is ~130 bytes and is exactly the artifact axis 13 needs
lfs = b"version https://git-lfs.github.com/spec/v1" + bytes([10]) + b"oid sha256:" + b"a" * 64
ok = FA.looks_like_a_wall(lfs, "200") is None
print(("  ok    " if ok else "  FAIL  ") + "a 130-byte Git-LFS pointer is accepted, not refused")
passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)

# ── the arithmetic that makes N/A dangerous ───────────────────────────────────────────
print()
print("  --- the N/A property, demonstrated rather than asserted ---")
base = full_census(score=1)                                   # all 22 at CLAIMED
sc_base = M.score(base)["s1"]

hidden = full_census(score=1)
for c in hidden["cells"]:
    if c["axis"] in A.NA_PERMITTED:                           # disclose LESS on 7 axes
        c["score"] = None
        c["na_reason"] = "api-only release"
        c.pop("evidence", None)
sc_hidden = M.score(hidden)["s1"]

print("    all 22 disclosed at CLAIMED      as-coded %.3f" % sc_base["as_coded"])
print("    7 axes withdrawn as N/A          as-coded %.3f   [N/A→0 %.3f, N/A→2 %.3f]"
      % (sc_hidden["as_coded"], sc_hidden["na_as_0"], sc_hidden["na_as_2"]))

inflates = sc_hidden["as_coded"] >= sc_base["as_coded"]
band_catches = sc_hidden["na_as_0"] < sc_base["as_coded"]
print(("  ok    " if inflates else "  FAIL  ") +
      "withdrawing axes does NOT lower the as-coded score (this is the hazard)")
passed, failed = (passed + 1, failed) if inflates else (passed, failed + 1)
print(("  ok    " if band_catches else "  FAIL  ") +
      "the N/A→0 column exposes it (%.3f < %.3f)" % (sc_hidden["na_as_0"], sc_base["as_coded"]))
passed, failed = (passed + 1, failed) if band_catches else (passed, failed + 1)

# ── the attacks round-3 review ran by hand, now run every time ───────────────────────────────
# ⛔ ALL THREE OF THESE VALIDATED CLEAN when a reviewer tried them. The validator confirmed a
# method NAME was on an allowlist and asked nothing further.
must_catch("a method that cannot possibly settle the axis it is on",
           full_census(score=2, cell_over={"check": {
               "method": "hf_probe.weight_object",
               "asserts": "nonsense", "observed": "nonsense"}}),
           "cannot settle this axis")

must_catch("a replayable method carrying nothing to replay",
           full_census(score=2, cell_over={"check": {
               "method": "grep_retrieved",
               "asserts": "something", "observed": "something"}}),
           "no `expect` list")

must_pass("the score-2 fixture itself is valid under the new method rules",
          full_census(score=2))

# ── the two round-6 routes AROUND the identity checks ────────────────────────────────────────
# ⛔ BOTH WERE REGISTERED, AXIS-LEGAL AND SILENT. A weights cell moved to `http_range` bypassed
# every identity check by a route axes.py approved; and deleting the field its method needs demoted
# the cell to "unreplayable", after which its evidence was unconstrained and the count was printed
# into the paper as though nothing were wrong.
must_catch("a weights cell moved to a registered, axis-legal method that does not bind identity",
           full_census(score=2, cell_over={"check": {
               "method": "http_range", "asserts": "a range", "observed": "2048 B"}}),
           "does not bind this axis's identity")

must_catch("a cell whose method is missing the field it cannot run without",
           full_census(score=2, cell_over={"check": {
               "method": "grep_retrieved", "asserts": "x", "observed": "y"}}),
           "requires `expect`")

# ── the drift run must be bound to the evidence SET, not to its size ─────────────────────────
# The paper says every artifact was re-fetched. That was confirmed by comparing a COUNT, which a
# substitution passes: swap one url for another and the count is unchanged. The build now compares
# a fingerprint over url+digest, and this is the POSITIVE CONTROL that the fingerprint moves when
# the set does. A binding nobody has watched fail is not known to bind.
import hashlib as _h


def _fp(pairs):
    return _h.sha256(chr(10).join(sorted(
        u + chr(0) + d for u, d in pairs)).encode("utf-8")).hexdigest()


# NOTE: these were named A, B, C -- and `A` is the axes module, imported at the top
# and used by full_census(). The rebinding shadowed it, so every test written BELOW
# this line died with "'list' object has no attribute BY_ID". Renamed.
_FA = [("https://example.org/a", "aa" * 32), ("https://example.org/b", "bb" * 32)]
_FB = [("https://example.org/a", "aa" * 32), ("https://example.org/DIFFERENT", "bb" * 32)]
_FC = [("https://example.org/a", "aa" * 32), ("https://example.org/b", "cc" * 32)]

print()
print("  " + chr(0x26D4) + " SUBSTITUTION, NOT CORRUPTION: same count, different evidence")
print("      two artifacts either way, so a count check passes all three of these")
for label, other in (("a url replaced", _FB), ("a digest replaced", _FC)):
    moved = _fp(_FA) != _fp(other)
    print(("  ok    " if moved else "  FAIL  ") + "the cover fingerprint changes when %s" % label)
    passed, failed = (passed + 1, failed) if moved else (passed, failed + 1)
same = _fp(_FA) == _fp(list(reversed(_FA)))
print(("  ok    " if same else "  FAIL  ") +
      "and does NOT change when only the ORDER differs (it is a set, not a list)")
passed, failed = (passed + 1, failed) if same else (passed, failed + 1)

print()
print("  ⛔ CONTROLS A MUTATION AUDIT FOUND NOTHING WAS WATCHING")
print("      Each of these validator rules could be DELETED with the whole suite still green.")
print("      They are correct and reachable -- a manual probe fired every one -- but nothing")
print("      automated had ever seen one fail, which is indistinguishable from a comment.")

_l = full_census(score=1)
_l["subjects"].append(dict(_l["subjects"][0]))
must_catch("two subjects sharing one id", _l, "duplicate subject")

# The volatile bar EXEMPTS a cell whose check is replayed against archived bytes, and
# full_census picks a replayable method for every axis -- so the first version of this test
# built a census the rule deliberately permits and reported the rule broken. The branch is
# reachable: hash_compare, http_status and api_field are all axis-legal for a 2 and none is
# replayable. Aim at the branch that exists rather than at the one the fixture happens to build.
_l = full_census(score=2)
for _c in _l["cells"]:
    if _c["axis"] == 4 and _c.get("score") == 2:
        _c["check"] = {"method": "http_status", "asserts": "it resolves", "observed": "200"}
        _c["evidence"] = [dict(EV[0], volatile=True, volatile_reason="an api response")]
must_catch("a VERIFIED cell on a NON-replayed check resting on volatile evidence", _l,
           "cannot support a VERIFIED")

_l = full_census(score=2, cell_over={"evidence": [dict(EV[0], volatile=True)]})
must_catch("volatile with no stated reason", _l, "no stated reason")

_l = full_census(score=1)
for _c in _l["cells"]:
    if _c["axis"] == 16:
        _c["score"] = 2
must_catch("a score above the axis's attainable ceiling", _l, "exceeds")

_l = full_census(score=2, cell_over={"evidence": [dict(
    EV[0], url="https://raw.githubusercontent.com/o/r/main/README.md")]})
must_catch("a VERIFIED cell citing a mutable branch", _l, "mutable branch")

_l = full_census(score=1)
_seen = [c for c in _l["cells"] if c.get("evidence")]
_seen[0]["evidence"] = [dict(EV[0], url="https://example.org/somewhere-else")]
must_catch("one digest cited under two different urls", _l, "two different urls")

_l = full_census(score=1)
_l["subjects"][0].pop("axis_sources", None)
must_catch("a scored cell whose subject declares no axis_sources", _l, "axis_sources")

_l = full_census(score=1)
_l["subjects"][0]["sources"] = ["host:nowhere.invalid"]
must_catch("evidence from a source the subject does not declare", _l, "does not declare")

_l = full_census(score=1)
_l["subjects"][0]["unheard_of_key"] = "x"
_fired = False
try:
    M.ledger_fingerprint(_l)
except SystemExit:
    _fired = True
print(("  ok    " if _fired else "  FAIL  ")
      + "a subject field no policy key covers stops the fingerprint")
passed, failed = (passed + 1, failed) if _fired else (passed, failed + 1)


# ⛔ A MECHANISM THAT IS DEFINED AND NEVER CALLED. `replay.py` compiled `_ENTRY =
# re.compile(rb"<entry>")` and its docstring stated that entries were counted; the regex was never
# used and nothing counted anything. A round-17 reviewer grepped the project, found the single
# occurrence, and named the class: a compiled pattern standing in for the check it looks like.
#
# ⚠ This cannot tell a described check from a real one in general. It catches the specific shape
# that has now occurred: a module-level name that exists to do work and is never loaded. Ad hoc
# when it found _ENTRY; a control now, because a defect found by grepping once is found by
# grepping every time or not at all.
# ⚠ AND THE FIRST VERSION OF THIS CONTROL CRIED WOLF, which is the failure mode this project
# has hit four times in two days. It scanned each file for loads WITHIN that file, and reported
# axes.py's SCORES, GROUPS, NA_PERMITTED and CHECK_METHODS as dead -- names whose entire purpose is
# to be read by other modules as `A.SCORES`. A name unused in its own file may be the whole point
# of the file. Usage is collected across the package, attribute access included.
_files = sorted(pathlib.Path(__file__).resolve().parent.glob("*.py"))
_trees = {}
for _f in _files:
    try:
        _trees[_f] = ast.parse(_f.read_text(encoding="utf-8"))
    except SyntaxError:
        pass
_used_anywhere = set()
for _tr in _trees.values():
    for _n in ast.walk(_tr):
        if isinstance(_n, ast.Name) and isinstance(_n.ctx, ast.Load):
            _used_anywhere.add(_n.id)
        elif isinstance(_n, ast.Attribute):
            _used_anywhere.add(_n.attr)
        elif isinstance(_n, ast.ImportFrom):
            for _a in _n.names:
                _used_anywhere.add(_a.name)
_dead = []
for _f, _tr in _trees.items():
    for _n in ast.walk(_tr):
        if (isinstance(_n, ast.Assign) and len(_n.targets) == 1
                and isinstance(_n.targets[0], ast.Name)):
            _nm = _n.targets[0].id
            if (_nm.isupper() or _nm.startswith("_")) and _nm not in ("NL", "_", "D", "W"):
                if _nm not in _used_anywhere:
                    _dead.append("%s:%d %s" % (_f.name, _n.lineno, _nm))
# ⛔ EVIDENCE FROM ONE ENDPOINT MUST BE CLASSIFIED THE SAME WAY. A second page of an arXiv query
# was bound into the ledger by hand and carried no `volatile` flag, while its seven siblings on the
# identical endpoint all carried volatile=true. recheck.py then reported it as DRIFTED -- a real
# finding about the record, produced by adding evidence outside the tool that sets the properties.
# Two records of the same endpoint disagreeing about their own nature is a substitution vector.
# ⚠ AND THE FIRST GRAIN WAS WRONG. Grouping by HOST flagged api.github.com and
# huggingface.co, whose tree and metadata endpoints are different things -- a host standing in for
# an endpoint, which is the substitution this project keeps finding. Grouping by URL found the
# real defect underneath: SEVEN urls were recorded with volatile=true in one cell and unset in
# another, the SAME artifact classified two ways, so recheck.py would suppress a digest change for
# one citing cell and report it for another.
_vol = []
_led = json.loads((pathlib.Path(__file__).resolve().parent / "cells.json").read_text("utf-8"))
_byurl = {}
for _c in _led.get("cells", []):
    for _e in (_c.get("evidence") or []):
        _byurl.setdefault(_e.get("url", ""), set()).add(str(_e.get("volatile")))
for _u, _flags in sorted(_byurl.items()):
    if len(_flags) > 1:
        _vol.append("%s -> %s" % (_u[-56:], sorted(_flags)))
if _vol:
    print("  " + chr(0x26D4) + " %d url(s) recorded with more than one volatility flag:" % len(_vol))
    for _v in _vol[:4]:
        print("      " + _v)
    print("      One artifact cannot be both volatile and stable. Whichever flag is read last")
    print("      decides whether a real change is reported or suppressed.")
    failed += 1
else:
    passed += 1
    print("  ok    every url carries one volatility classification")

# ⛔ BYTE-REPRODUCIBILITY HELD ONLY ON THE PLATFORM THAT WROTE IT. Six modules wrote JSON with
# `write_text(...)` and no `newline=`, which emits CRLF on Windows and LF everywhere else, so two
# DOCUMENTED commands rewrote deposited records with different bytes and identical content. The
# digest the manuscript cites would not reproduce for a replicator, and nothing in the deposit
# gave them a way to learn that -- the byte-identical check is gated on a zip a distribution
# cannot contain, and is skipped silently rather than counted as not-runnable.
_crlf = sorted(f.name for f in pathlib.Path(__file__).resolve().parent.glob("*.json")
               if b"" + chr(13).encode() + chr(10).encode() in f.read_bytes())
if _crlf:
    print("  " + chr(0x26D4) + " %d record(s) contain CRLF: %s" % (len(_crlf), _crlf[:4]))
    print("      A writer that does not pin its newline produces different BYTES for identical")
    print("      CONTENT on another platform, so the cited digest reproduces only here.")
    failed += 1
else:
    passed += 1
    print("  ok    no census record carries platform-dependent line endings")

# ⛔ AND A TOOL THAT ONLY RUNS ON THE AUTHOR'S DISK. `filter_diff.py` hardcoded an absolute
# path into this workspace, so the producer of the paper's newest bound could not be executed from
# the deposit at all -- a round-17 reviewer ran it and got FileNotFoundError. Every other tool here
# resolves relative to itself; nothing checked that they all did.
_abs = []
for _f in _files:
    _src = _f.read_text(encoding="utf-8")
    for _ln, _line in enumerate(_src.splitlines(), 1):
        _s = _line.strip()
        if _s.startswith("#"):
            continue
        _low = _line.lower()
        # ⚠ BUILT, NOT WRITTEN. The first version spelled these needles as literals and
        # then matched itself -- a detector that reports its own definition is a false positive
        # generator, and this project has now had four of those in two days.
        _needles = ("c:" + "/users", "c:" + chr(92) + "users",
                    chr(47) + "home" + chr(47), chr(47) + "Users".lower() + chr(47))
        # ⛔ ABSOLUTE PATHS ONLY, IN THE DETECTOR WRITTEN FOR EXACTLY THIS CLASS. `unread_notes.py`
        # reached across with `here.parents[1] / "journal-submissions" / "mp-metric"` -- a
        # RELATIVE path into the author's directory layout, equally unrunnable from a deposit
        # where the paper sits at `../paper`, and invisible here. A round-14 reviewer found the
        # tool inert in every extraction because of it. The needle list asked what a path LOOKS
        # like instead of what makes it unrunnable, which is naming a sibling directory that
        # exists only in the author's tree.
        #
        # ⚠ A tool may still reach across; it must simply know both layouts. So the finding is a
        # reference to an author-tree directory that is NOT accompanied by the extraction
        # sibling, which is what the two-layout rule means in practice.
        _AUTHOR_DIRS = ("journal-submissions", "provenance-laboratory")
        if any(_n in _low for _n in _needles):
            _abs.append("%s:%d" % (_f.name, _ln))
        elif any(_d in _low for _d in _AUTHOR_DIRS) and '"paper"' not in _src:
            _abs.append("%s:%d (author-tree layout with no extraction fallback)"
                        % (_f.name, _ln))
if _abs:
    print("  " + chr(0x26D4) + " %d absolute path(s) into one machine: %s"
          % (len(_abs), ", ".join(_abs[:4])))
    print("      A tool that only runs on the author's disk cannot be re-run from the deposit,")
    print("      which is the difference between a bound and an assertion.")
    failed += 1
else:
    passed += 1
    print("  ok    no tool hardcodes a path into one machine")

if _dead:
    print("  " + chr(0x26D4) + " %d module-level name(s) defined and never used anywhere:"
          % len(_dead))
    for _d in sorted(_dead)[:8]:
        print("      " + _d)
    print("      A name that looks like a mechanism and is never called is a promise nothing")
    print("      keeps -- the shape of the _ENTRY regex a reviewer found in round 17.")
    failed += 1
else:
    passed += 1
    print("  ok    no module-level name is defined and left uncalled")

print()
# ⛔ THE FIXTURES THAT JUSTIFY THIS CONTROL WERE NOT IN THE TREE. Round 13 reported "8 fixtures /
# 0 findings" and a reviewer could not check it, because the fixtures lived beside the repository
# rather than in it -- and they were the first person ever to pass `where=`, a parameter with one
# caller that never used it. Nine iterations of this function each traded one error class for
# another, and every trade was invisible for exactly that reason.
#
# ⇒ The oracle is PYTHON ITSELF. Each fixture below is executed as well as analysed: if the module
# raises NameError/UnboundLocalError at runtime the control must fire, and if it runs clean the
# control must stay silent. A fixture whose runtime behaviour nobody checked is how a detector
# comes to disagree with the language it is modelling.
_NL = chr(10)
_FIX = {
    # name: (source, does Python actually raise?)
    "undef_lambda_cond.py": (
        "if False:" + _NL + "    X = 1" + _NL + "f = lambda: X" + _NL, True),
    "undef_genexpr_cond.py": (
        "if False:" + _NL + "    Y = 1" + _NL + "g = lambda: list(Y for _ in range(1))" + _NL, True),
    "undef_def_cond.py": (
        "if False:" + _NL + "    Z = 1" + _NL + "def h(): return Z" + _NL, True),
    "undef_del.py": (
        "Q = 1" + _NL + "del Q" + _NL + "def use(): return Q" + _NL, True),
    "undef_shadow_lambda.py": (
        "D2 = 1" + _NL + "f = lambda: (D2, (D2 := 2))" + _NL, True),
    "undef_match_refutable.py": (
        "import sys" + _NL + "match sys.argv:" + _NL + "    case [M, *_r]:" + _NL
        + "        pass" + _NL + "def use(): return M" + _NL, True),
    "ok_match_irrefutable.py": (
        "import sys" + _NL + "match sys.argv:" + _NL + "    case N:" + _NL + "        pass" + _NL
        + "def use(): return N" + _NL, False),
    "ok_inline_in_branch.py": (
        "import os" + _NL + "if os.sep:" + _NL + "    A = 1" + _NL
        + "    k = [A for _ in range(1)]" + _NL, False),
    "ok_plain.py": ("B = 1" + _NL + "def use(): return B" + _NL, False),
}
# ⛔ THE FIXTURE SET COULD BE EMPTIED AND EVERY GATE STAYED GREEN. A round-14 reviewer set
# `_FIX = {}` and got "the undefined-name control agrees with Python on 0 fixture(s)" inside a
# 49-passed suite -- the claim "the oracle is Python itself" made vacuous while the whole tree
# reported success. The one incidental failure they hit was the dead-name detector noticing an
# unused variable, not any control over the population. A population is a quantity; nothing
# bound it.
_MIN_FIX = 9
if len(_FIX) < _MIN_FIX:
    raise SystemExit(D + " the undefined-name fixture set holds %d and is specified over at "
                     "least %d. 'agrees with Python on 0 fixtures' is not agreement."
                     % (len(_FIX), _MIN_FIX))
import shutil as _sh2      # noqa: E402
import tempfile as _tf2    # noqa: E402
_work = pathlib.Path(_tf2.mkdtemp(prefix="undef-fix-"))
try:
    for _n, (_src, _) in _FIX.items():
        (_work / _n).write_text(_src, encoding="utf-8")
    _found = {}
    for _line in undefined_module_reads(where=_work):
        _found.setdefault(_line.split(":")[0], []).append(_line)
    _fixbad = []
    for _n, (_src, _raises) in sorted(_FIX.items()):
        _fires = _n in _found
        if _fires != _raises:
            _fixbad.append("%s: python %s, detector %s"
                           % (_n, "raises" if _raises else "runs clean",
                              "fires" if _fires else "is silent"))
    if _fixbad:
        print("  " + D + " %d undefined-name fixture(s) disagree with Python:" % len(_fixbad))
        for _b in _fixbad:
            print("      " + _b)
        print("      The control models the language; where they differ, the control is wrong.")
        failed += 1
    else:
        passed += 1
        print("  ok    the undefined-name control agrees with Python on %d fixture(s)" % len(_FIX))
finally:
    _sh2.rmtree(_work, ignore_errors=True)

print()
_undef = undefined_module_reads()
if _undef:
    print("  " + D + " %d name(s) read from module scope that do not exist:" % len(_undef))
    for _u in _undef[:8]:
        print("      " + _u)
    print("      Each raises NameError the first time its path runs -- and these paths run when")
    print("      something has already gone wrong, which is when a report matters most.")
    failed += 1
else:
    passed += 1
    print("  ok    no function reads a module-scope name that does not exist")

print()
# ⛔ THE PROSE DUPLICATE CONTROL HAD NO SOURCE EQUIVALENT, AND THIS FILE PAID FOR IT. Round 24
# built a shingle-overlap control for repeated PARAGRAPHS over 240 characters; nobody built the
# three-line AST equivalent for repeated DEFINITIONS -- and `_module_bindings` was then defined
# twice in this very file, the dead copy carrying the argument and the live copy carrying the
# mechanism, so deleting "the duplicate" was a coin flip on deleting the repair. Python keeps the
# last definition silently, which is why nothing objected for a round.
#
# ⚠ It is a redefinition, not a name collision: a method on a class and a module-level function
# may share a name legitimately, so only same-scope redefinitions count. A conditional
# `try/except ImportError` redefinition is legitimate too and is not at module top level here.
_dupes = []
for _p in sorted(HERE.glob("*.py")):
    try:
        _t = ast.parse(_p.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        continue
    _seen = {}
    for _st in _t.body:
        if isinstance(_st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if _st.name in _seen:
                _dupes.append("%s:%d %s() shadows the definition at line %d"
                              % (_p.name, _st.lineno, _st.name, _seen[_st.name]))
            _seen[_st.name] = _st.lineno
if _dupes:
    print("  " + D + " %d module-level definition(s) shadowed by a later one:" % len(_dupes))
    for _u in _dupes[:8]:
        print("      " + _u)
    print("      Python keeps the LAST one. The earlier body is dead code that still reads as")
    print("      live, and the two copies drift -- which is how a repair and its rationale ended")
    print("      up in different, mutually shadowing halves of one function.")
    failed += 1
else:
    passed += 1
    print("  ok    no module defines the same top-level name twice")

print()
print("=" * 78)
print("  %d passed, %d failed" % (passed, failed))
if failed:
    print("  ** the validator let something through. Fix it before scoring anything real. **")
print("=" * 78)
raise SystemExit(1 if failed else 0)
