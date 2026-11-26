"""Checker: symbolic validation of an evidence path reported by the PerSink agent."""

import re

# Ablations (set by `analyzer.run --ablate`; the defaults are the final design):
# 'strict-checker': exact statement text, no annotation stripping, direct call edges only
STRICT = False
VETO = False  # 'veto-prune': unconfirmed steps are fatal (pruning is in strategies.py)


def resolve_step(program, step):
    """Map a step to (method, index) using the index first, then the exact text."""
    sig, _ = program.find(str(step.get("method", "")))
    if sig is None:
        return None, f"method {step.get('method')!r} does not exist in the application"
    stmts = program.methods[sig]["stmts"]
    text = str(step.get("stmt", ""))
    if not STRICT:
        text = re.sub(
            r"\s+//\s*(branch target|field resolves).*$", "", text
        )  # listing annotations, not Jimple
    text = text.strip().rstrip(";").strip()
    idx = step.get("index")
    if isinstance(idx, int) and 0 <= idx < len(stmts) and (not text or stmts[idx]["text"] == text):
        return (sig, idx), None
    found = program.stmt_index(sig, text) if text else None
    if found is not None:
        return (sig, found), None
    # v1.3.1: tolerate formatting differences only (whitespace, empty "()"), e.g. DeepSeek writes
    # "<C: T m>()" for "<C: T m()>()". The statement must still match uniquely in that method.
    want = _norm(text) if not STRICT else ""
    if want:
        if isinstance(idx, int) and 0 <= idx < len(stmts) and _norm(stmts[idx]["text"]) == want:
            return (sig, idx), None
        hits = [k for k, s in enumerate(stmts) if _norm(s["text"]) == want]
        if len(hits) == 1:
            return (sig, hits[0]), None
    return None, f"statement {text!r} (index {idx}) does not exist in {sig}"


def _norm(t):
    return re.sub(r"\s+|\(\)", "", t)


def _calls_transitively(program, src, dst, limit=6):
    if STRICT:
        limit = 1
    frontier, seen = {src}, {src}
    for _ in range(limit):
        frontier = {t for m in frontier for _, t in program.callees.get(m, [])} - seen
        if dst in frontier:
            return True
        if not frontier:
            return False
        seen |= frontier
    return False


def _connected(program, a, b):
    (ma, ia), (mb, ib) = a, b
    if ma == mb:
        return True
    # Call/return, possibly across several call levels in one step (e.g. returning from a
    # nested constructor).
    if _calls_transitively(program, ma, mb) or _calls_transitively(program, mb, ma):
        return True
    # Class initialisation: a method that triggers K's initialisation (new / static access /
    # static call)
    # transfers control to <K: void <clinit>()>, analogous to a call edge.
    for cls, refs in program.class_refs.items():
        clinit = f"<{cls}: void <clinit>()>"
        if mb == clinit and any(r[0] == ma for r in refs):
            return True
        if ma == clinit and any(r[0] == mb for r in refs):
            return True
    return bool(program.stmt_fields(ma, ia) & program.stmt_fields(mb, ib))


def check(program, reach, sink, sources, answer):
    """Validate an evidence path.

    Returns (fatal, unverified):
      fatal      - claims that are provably false against the symbolic facts (a statement or method
          that does not
                   exist, a path that does not start at a known source or end at the sink). These
                       trigger a repair
                   round and, if they persist, rejection.
      unverified - steps the symbolic model cannot confirm (no call edge / field / clinit link in
          the CHA call
                   graph, method not reachable in the symbolic fixpoint). The call graph does not
                       model reflection
                   or framework-mediated dispatch (AsyncTask, Handler, Executor, ...), so these are
                       reported as a
                   flag on the accepted result, not as errors.
    """
    path = answer.get("path") or []
    if not path:
        return ["leak=true but the path is empty"], []
    fatal, resolved = [], []
    for k, step in enumerate(path):
        if not isinstance(step, dict):
            fatal.append(f"step {k} is not an object")
            continue
        r, err = resolve_step(program, step)
        if err:
            fatal.append(f"step {k}: {err}")
        else:
            resolved.append(r)
    if fatal:
        return fatal, []
    source_keys = {(s["method"], s["index"]) for s in sources}
    if resolved[0] not in source_keys:
        fatal.append(
            f"step 0 ({resolved[0][0]} [{resolved[0][1]}]) is not one of the KNOWN SOURCES"
        )
    if resolved[-1] != (sink["method"], sink["index"]):
        fatal.append("the last step is not the sink statement under analysis")
    unverified = []
    for k in range(len(resolved) - 1):
        if not _connected(program, resolved[k], resolved[k + 1]):
            a, b = resolved[k], resolved[k + 1]
            unverified.append(
                f"steps {k}->{k + 1}: no call edge, shared field or class-init link between "
                f"{a[0]} [{a[1]}] and {b[0]} [{b[1]}] in the symbolic call graph"
            )
    for m in dict.fromkeys(m for m, _ in resolved):
        if m not in reach:
            unverified.append(f"{m} is not reachable in the symbolic call graph")
    if VETO:
        return fatal + unverified, []
    return fatal, unverified
