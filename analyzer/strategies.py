"""The two inference strategies.

WholeApp (internally "v0"): one prompt per app with all application code and the numbered
candidates. PerSink (internally "v1"): one tool-using agent per candidate sink whose evidence path
is validated by the checker.
"""

import json
import threading
from pathlib import Path

from . import checker, prompts
from .llm import parse_json
from .tools import TOOL_SCHEMAS, Tools

MAX_TURNS = 16
PRUNE = False  # ablation 'veto-prune': drop sinks outside the symbolic reachability fixpoint


def _fmt_sources(sources):
    if not sources:
        return "(none)"
    return "\n".join(
        f"- [{s['kind']}] {s['method']} [{s['index']}] {s['statement']}" for s in sources
    )


# ---------------------------------------------------------------- PerSink
def _check_flows(program, reach, sink, sources, answer):
    """Validate each flow; return (accepted flows with unverified notes, per-flow fatal errors)."""
    ok, fatal = [], []
    flows = answer.get("flows") or []
    if not isinstance(flows, list) or not flows:
        return [], ["leak=true but no flows are given"]
    for k, flow in enumerate(flows):
        path = flow.get("path") if isinstance(flow, dict) else None
        errs, unv = checker.check(program, reach, sink, sources, {"path": path or []})
        if errs:
            fatal += [f"flow {k}: {e}" for e in errs]
        else:
            first = checker.resolve_step(program, path[0])[0]
            ok.append(
                {
                    "source_method": first[0],
                    "source_index": first[1],
                    "source_statement": program.methods[first[0]]["stmts"][first[1]]["text"],
                    "unverified": unv,
                }
            )
    return ok, fatal


def analyze_sink(program, tools, llm, sink, sources, use_verifier=True, flows=False):
    """Run the agent on one sink; returns a decision record with the transcript.

    flows=True: the agent reports one evidence path per source reaching the sink (flow-level
    scoring).
    """
    reach = tools.reach
    user = prompts.USER_V1.format(
        overview=program.app_overview(focus_class=program.methods[sink["method"]]["class"]),
        sources=_fmt_sources(sources),
        escape_note=prompts.ESCAPE_NOTE if sink["kind"] == "escape" else "",
        method=sink["method"],
        index=sink["index"],
        stmt=sink["statement"],
        spec=sink["spec"],
        reach=reach.get(sink["method"], prompts.UNREACHABLE_NOTE),
        listing=program.listing(sink["method"]),
    )
    system = prompts.SYSTEM_V1_FLOWS if flows else prompts.SYSTEM_V1
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    record = {
        "sink": sink,
        "turns": 0,
        "tool_calls": 0,
        "repairs": 0,
        "rejections": [],
        "symbolically_reachable": sink["method"] in reach,
    }
    repaired = False
    for turn in range(MAX_TURNS + 1):
        record["turns"] += 1
        if turn == MAX_TURNS:  # one last call without tools instead of dropping the sink
            messages.append({"role": "user", "content": prompts.FINAL_ANSWER})
            record["forced_final_answer"] = True
            r = llm.chat(messages)
        else:
            r = llm.chat(messages, tools=TOOL_SCHEMAS)
        msg = r.choices[0].message
        if msg.tool_calls:
            messages.append(
                {
                    "role": "assistant",
                    "content": msg.content or "",
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        }
                        for tc in msg.tool_calls
                    ],
                }
            )
            for tc in msg.tool_calls:
                record["tool_calls"] += 1
                result = tools.call(tc.function.name, tc.function.arguments)
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
            continue
        messages.append({"role": "assistant", "content": msg.content or ""})
        answer = parse_json(msg.content)
        if answer is None or "leak" not in answer:
            messages.append(
                {"role": "user", "content": "Reply with ONLY the required JSON object."}
            )
            continue
        if not answer["leak"]:
            record.update(decision=False, status="llm-no-leak", answer=answer)
            break
        if flows:
            accepted, errors = _check_flows(program, reach, sink, sources, answer)
            # partially valid answers: keep the valid flows unless a repair round is
            # still available
            if accepted and (not errors or repaired):
                record.update(
                    decision=True,
                    answer=answer,
                    flows=accepted,
                    dropped_flow_errors=errors,
                    status=(
                        "accepted-unverified"
                        if any(f["unverified"] for f in accepted)
                        else "accepted"
                    ),
                )
                break
            unverified = []
        else:
            errors, unverified = (
                checker.check(program, reach, sink, sources, answer) if use_verifier else ([], [])
            )
        if not errors:
            record.update(
                decision=True,
                status="accepted-unverified" if unverified else "accepted",
                answer=answer,
                unverified=unverified,
            )
            break
        record["rejections"].append(errors)
        if repaired:
            record.update(decision=False, status="rejected-by-verifier", answer=answer)
            break
        repaired = True
        record["repairs"] += 1
        repair = prompts.REPAIR_FLOWS if flows else prompts.REPAIR
        messages.append({"role": "user", "content": repair.format(errors="\n".join(errors))})
    else:
        record.update(decision=False, status="turn-limit", answer=None)
    record["transcript"] = messages
    return record


def run_persink(
    program, llm, use_verifier=True, workers=None, pool=None, checkpoint=None, flows=False
):
    """Run one agent per candidate sink.

    checkpoint: optional JSONL file; finished sink records are appended to it and reused on resume.
    """
    done = {}
    if checkpoint is not None and Path(checkpoint).exists():
        for line in Path(checkpoint).read_text().splitlines():
            try:
                r = json.loads(line)
            except json.JSONDecodeError:  # torn last line after an interruption
                continue
            done[(r["sink"]["method"], r["sink"]["index"])] = r
    lock = threading.Lock()

    def run_one(s):
        key = (s["method"], s["index"])
        if key in done:
            return done[key]
        try:
            r = analyze_sink(program, tools, llm, s, sources, use_verifier, flows=flows)
        except (
            Exception
        ) as e:  # API failure after retries: report, do not checkpoint (retried on --resume)
            return {
                "sink": s,
                "decision": False,
                "status": "llm-error",
                "error": f"{type(e).__name__}: {e}"[:300],
            }
        if checkpoint is not None:
            with lock, open(checkpoint, "a") as fh:
                fh.write(json.dumps(r, default=str) + "\n")
        return r

    tools = Tools(program)
    sources = program.sources()
    records = []
    pending = []
    for sink in program.candidate_sinks():
        # v1.3: symbolically unreachable sinks are no longer pruned; the agent is told and decides.
        if not sources:
            records.append({"sink": sink, "decision": False, "status": "pruned-no-source"})
        elif PRUNE and sink["method"] not in tools.reach:
            records.append({"sink": sink, "decision": False, "status": "pruned-unreachable"})
        else:
            pending.append(sink)
    if pool is not None:
        futures = [pool.submit(run_one, s) for s in pending]
        records.extend(f.result() for f in futures)
    else:
        records.extend(run_one(s) for s in pending)
    return records


# --------------------------------------------------------------- WholeApp
def run_wholeapp(program, llm, flows=False):
    """WholeApp: the whole app in one prompt, no tools and no checker.

    flows=True: sources are numbered and the model attributes sources to each leaking sink."""
    sinks = program.candidate_sinks()
    sources = program.sources()
    if not sinks:
        return []
    code = "\n\n".join(
        program.listing(sig) for sig in program.methods if program.methods[sig]["stmts"]
    )
    comps = {k: v for k, v in program.components().items()}
    cands = "\n".join(
        f"{k}. {s['method']} [{s['index']}] {s['statement']}"
        + (
            " (framework-mediated escape: leaks if the Intent carries tainted extras)"
            if s["kind"] == "escape"
            else ""
        )
        for k, s in enumerate(sinks, 1)
    )
    src_text = (
        (
            "\n".join(
                f"S{k}. [{s['kind']}] {s['method']} [{s['index']}] {s['statement']}"
                for k, s in enumerate(sources, 1)
            )
            or "(none)"
        )
        if flows
        else _fmt_sources(sources)
    )
    user = prompts.USER_V0.format(
        components=json.dumps(comps),
        code=code,
        sources=src_text,
        layout_callbacks=json.dumps(program.layout_callbacks()),
        candidates=cands,
    )
    system = prompts.SYSTEM_V0_FLOWS if flows else prompts.SYSTEM_V0
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    answer = None
    for _ in range(2):
        try:
            r = llm.chat(messages, stream=True)
        except Exception as e:  # e.g. prompt longer than the model's context window (real apps)
            ctx = any(k in str(e).lower() for k in ("context", "too long", "maximum"))
            return [
                {
                    "sink": s,
                    "decision": False,
                    "status": "v0-context-exceeded" if ctx else "llm-error",
                    "error": str(e)[:300],
                }
                for s in sinks
            ]
        content = r.choices[0].message.content or ""
        finish = getattr(r.choices[0], "finish_reason", None)
        messages.append({"role": "assistant", "content": content, "finish_reason": finish})
        answer = parse_json(content)
        if answer is not None and isinstance(answer.get("leaks"), list):
            break
        messages.append({"role": "user", "content": "Reply with ONLY the required JSON object."})
    ids, src_of = set(), {}
    for item in (answer or {}).get("leaks", []) or []:
        try:
            k = int(item["id"] if isinstance(item, dict) else item)
        except (KeyError, TypeError, ValueError):
            continue
        ids.add(k)
        if flows and isinstance(item, dict):
            for x in item.get("sources") or []:
                try:
                    j = int(str(x).lstrip("Ss"))
                except ValueError:
                    continue
                if 1 <= j <= len(sources):
                    src_of.setdefault(k, []).append(sources[j - 1])
    records = []
    for k, s in enumerate(sinks, 1):
        rec = {"sink": s, "decision": k in ids, "status": "v0"}
        if flows and k in ids:
            rec["flows"] = [
                {
                    "source_method": x["method"],
                    "source_index": x["index"],
                    "source_statement": x["statement"],
                    "unverified": [],
                }
                for x in {(y["method"], y["index"]): y for y in src_of.get(k, [])}.values()
            ]
        records.append(rec)
    if records:
        records[0]["transcript"] = messages
    return records
