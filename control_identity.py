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
    node_hash     sha256 over `ast.dump` WITHOUT line numbers, so edits above it are irrelevant
    ordinal       which of the identically-shaped siblings in that function this one is

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


def _norm(node):
    """A node's shape, with positions stripped. Two identical guards hash the same; that is why
    `ordinal` exists rather than being an accident this has to hide."""
    return hashlib.sha256(
        ast.dump(node, annotate_fields=True, include_attributes=False).encode("utf-8")
    ).hexdigest()


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
        "ordinal": ordinal,
        "siblings": len(siblings),
    }


def resolve(path, ident):
    """(lineno, status). Status is one of exact / moved / ambiguous / gone."""
    p = pathlib.Path(path)
    try:
        tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return None, GONE
    wanted = ident.get("qualname", "")
    scope = tree
    if wanted:
        for name, node in _scopes(tree):
            if name == wanted:
                scope = node
                break
        else:
            return None, GONE
    cands = [s for s in _statements(scope)
             if type(s).__name__ == ident.get("kind") and _norm(s) == ident.get("node_hash")]
    cands.sort(key=lambda s: s.lineno)
    if not cands:
        return None, GONE
    if len(cands) == 1:
        return cands[0].lineno, EXACT
    # ⚠️ THE ORDINAL IS WHAT MAKES DUPLICATES RESOLVABLE, and it is only trustworthy while the
    # NUMBER of identical siblings is unchanged. If somebody added or removed one, the k-th is no
    # longer the same control, and saying so is the honest answer.
    if ident.get("siblings") is not None and len(cands) != ident["siblings"]:
        return None, AMBIGUOUS
    idx = ident.get("ordinal", 0)
    if 0 <= idx < len(cands):
        return cands[idx].lineno, MOVED if len(cands) > 1 else EXACT
    return None, AMBIGUOUS


def main():
    """Report the identity of every line named in REACH-CONTROLS.json, and how it resolves."""
    import json
    rec_path = HERE / "REACH-CONTROLS.json"
    if not rec_path.is_file():
        raise SystemExit("no REACH-CONTROLS.json here")
    rec = json.loads(rec_path.read_text(encoding="utf-8"))
    detail = rec.get("detail") or {}
    counts = {EXACT: 0, MOVED: 0, AMBIGUOUS: 0, GONE: 0, "no-identity": 0}
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
        line, status = resolve(HERE / f, ident)
        counts[status] += 1
        print("  %-22s %-10s %s%s" % (where, status,
                                      ident["qualname"] or "(module)",
                                      "" if line is None else "  -> line %d" % line))
    print()
    print("  " + ", ".join("%s %d" % (k, v) for k, v in counts.items() if v))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
