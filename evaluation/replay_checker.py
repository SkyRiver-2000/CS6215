"""Offline replay of PerSink runs with the final, format-tolerant statement matching (no new LLM
calls).

Some PerSink runs were made with an earlier checker that compared statement texts exactly. The
final checker compares them modulo whitespace, listing annotations and empty parentheses, so that
`<C: T m>()` (as DeepSeek writes it) matches `<C: T m()>()`. For every sink whose analysis received
a fatal checker error, the first leak=true answer in the transcript that passes the tolerant check
decides the sink (the answer the agent would have had accepted); all other decisions stand.

Usage: python -m evaluation.replay_checker <run dir> <facts dir> <out dir> [--spec FILE] [--flows]
"""

import json
import re
import shutil
import sys
from pathlib import Path

from analyzer import checker
from analyzer.frontend.program import Program
from analyzer.llm import parse_json
from analyzer.resultfile import write_tsv
from analyzer.tools import Tools

_strict_resolve = checker.resolve_step


def _norm(text):
    text = re.sub(r"\s+//.*$", "", str(text))
    return re.sub(r"\s+|\(\)", "", text)


def tolerant_resolve(program, step):
    resolved, error = _strict_resolve(program, step)
    if resolved:
        return resolved, error
    sig, _ = program.find(str(step.get("method", "")))
    if sig is None:
        return resolved, error
    stmts = program.methods[sig]["stmts"]
    want, index = _norm(step.get("stmt", "")), step.get("index")
    if isinstance(index, int) and 0 <= index < len(stmts) and _norm(stmts[index]["text"]) == want:
        return (sig, index), None
    hits = [k for k, s in enumerate(stmts) if _norm(s["text"]) == want]
    return ((sig, hits[0]), None) if len(hits) == 1 else (resolved, error)


def accepted_flows(program, reach, record, sources, answer):
    flows = []
    for flow in answer.get("flows") or []:
        path = flow.get("path") if isinstance(flow, dict) else None
        if path and not checker.check(program, reach, record["sink"], sources, {"path": path})[0]:
            method, index = tolerant_resolve(program, path[0])[0]
            flows.append(
                {
                    "source_method": method,
                    "source_index": index,
                    "source_statement": program.methods[method]["stmts"][index]["text"],
                    "unverified": [],
                }
            )
    return flows


def replay_record(program, reach, sources, record, flows):
    """Return True (and update the record) if a leak answer passes the tolerant check."""
    for message in record["transcript"]:
        if message.get("role") != "assistant" or '"leak": true' not in (
            message.get("content") or ""
        ):
            continue
        answer = parse_json(message["content"])
        if not answer:
            continue
        if flows:
            ok = accepted_flows(program, reach, record, sources, answer)
            passed = bool(ok)
        else:
            passed = not checker.check(program, reach, record["sink"], sources, answer)[0]
        if passed:
            record.update(decision=True, status="accepted-relaxed")
            if flows:
                record["flows"] = ok
            return True
    return False


def main():
    run, facts, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    spec = sys.argv[sys.argv.index("--spec") + 1] if "--spec" in sys.argv else None
    flows = "--flows" in sys.argv
    out.mkdir(parents=True, exist_ok=True)
    changes = []
    checker.resolve_step = tolerant_resolve
    try:
        for trace in sorted(run.glob("*.trace.json")):
            case = trace.name[: -len(".trace.json")]
            records = json.loads(trace.read_text())
            program = Program(facts / f"{case}.json", spec_file=spec)
            reach, sources = Tools(program).reach, program.sources()
            for record in records:
                had_error = record.get("rejections") or record.get("status") == "turn-limit"
                if not had_error or not record.get("transcript"):
                    continue
                before = (record["decision"], record["status"])
                if replay_record(program, reach, sources, record, flows) and not before[0]:
                    changes.append((case, record["sink"]["index"], before[1]))
            write_tsv(out / f"{case}.tsv", records)
    finally:
        checker.resolve_step = _strict_resolve
    shutil.copy(run / "run.json", out / "run.json")
    (out / "replay-changes.json").write_text(json.dumps(changes, indent=1))
    print(f"{run.name}: {len(changes)} sink decisions flipped to leak: {changes}")


if __name__ == "__main__":
    main()
