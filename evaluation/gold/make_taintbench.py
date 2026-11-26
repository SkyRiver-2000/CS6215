"""Map TaintBench ground truth (<app>_findings.json) onto sink statements in our Jimple.

TaintBench labels source->sink flows with the Java statement, class, method, line, target method
name and the Jimple produced by the TaintBench authors' Soot version. Our Jimple (PLDI-era Soot)
can differ in local names, so a sink is matched by: enclosing class and method name (and arity) ->
invoke statements calling the target method -> the statement with locals normalised ($r3 -> $r),
falling back to the Soot line tag. Unmatched sinks are reported, never guessed.

Unit: sink statement, as in the DroidBench evaluation. Identical statement texts in one method are
distinct sinks (kept by index); scoring matches (method, text) with multiplicity because FlowDroid
exports text only. A sink is positive if at least one non-negative finding ends there, and negative
if only negative findings end there.

Usage: python -m evaluation.gold.make_taintbench   (writes config/taintbench-gold.json)
"""

import json
import re
from pathlib import Path

from analyzer.benchmarks import FACTS_DIR, ROOT, load_config, spec_file
from analyzer.frontend.program import Program

LOCAL = re.compile(r"\$?[a-z]\d+\b")


def norm(stmt):
    return LOCAL.sub("$v", stmt.replace(" ", ""))


# Manual decisions after review (app, finding ID) -> (method signature, statement index). Each is
# documented in
# the generated gold file's notes.
MANUAL = {
    # writeUTF("\\" + imei + "\\"): Java and Jimple escape the backslash literal differently;
    # [59] is the only
    # writeUTF whose argument is built from imei ($r7), [64] writes File.getName().
    ("phospy", 1): ("<com.labado.lulaoshi.myService: void log()>", 59),
    ("phospy", 4): ("<com.labado.lulaoshi.myService: void log()>", 59),
}
# Sources in sms_send_locker_qqmagic: 8 identical getDisplayMessageBody() calls in Fr.onReceive.
# Matched by the call
# applied to the result in the labelled Java statement: append -> [46]/[43]; indexOf("!")/("&")
# in the branch whose
# results feed the substrings -> [78]/[80]; substring(a,b) / substring(0,a) / substring(b) ->
# [82]/[85]/[87].
_FR = "<qqkj.qqmagic.Fr: void onReceive(android.content.Context,android.content.Intent)>"
MANUAL.update(
    {
        ("sms_send_locker_qqmagic", i, "source"): (_FR, j)
        for i, j in [(1, 46), (2, 43), (3, 46), (4, 78), (5, 80), (6, 82), (7, 85), (8, 87)]
    }
)


def java_method_name(sig):
    sig = re.sub(
        r"<[^<>]*>", "", re.sub(r"<[^<>]*>", "", sig)
    )  # drop (nested) generics before counting args
    m = re.search(r"([\w$]+)\s*\(([^)]*)\)", sig)
    if not m:
        return None, None
    args = [a for a in m.group(2).split(",") if a.strip()]
    return m.group(1), len(args)


def resolve_class(p, cls):
    """TaintBench writes inner classes as Outer.Inner; Jimple uses Outer$Inner."""
    parts = cls.split(".")
    for k in range(1, len(parts)):
        cand = ".".join(parts[:-k]) + "$" + "$".join(parts[-k:])
        if cand in p.classes:
            return cand
    return cls


def context_tokens(java_stmt):
    lits = re.findall(r'"((?:[^"\\]|\\.)*)"', java_stmt)
    calls = re.findall(r"([A-Za-z_]\w*)\s*\(", java_stmt)
    return [lit for lit in lits if lit], calls


def token_distances(p, sig, idx, java_stmt, target, window=15, ahead=0):
    """For each literal/call of the Java statement: distance to its nearest occurrence in the
    preceding window or within a few statements after (calls applied to the result, e.g.
    getBody().substring(...), follow it).
    """
    lits, calls = context_tokens(java_stmt)
    toks = [(f"lit:{lit}", re.compile(re.escape(f'"{lit}"'))) for lit in lits] + [
        (f"call:{c}", re.compile(rf"[ .]{re.escape(c)}\(")) for c in calls if c != target
    ]
    stmts = p.methods[sig]["stmts"]
    out = {}
    for name, rx in toks:
        hits = [
            abs(idx - j)
            for j in range(max(0, idx - window), min(len(stmts), idx + ahead + 1))
            if j != idx and rx.search(stmts[j]["text"])
        ]
        if hits:
            out[name] = min(hits)
    return out


def pick_by_context(p, pool, java_stmt, target, ahead=0):
    """Tokens found near every candidate (e.g. getBytes, "GBK") carry no information and are
    ignored. Rank by number of distinctive tokens, then by distance to the nearest distinctive
    token.
    """
    dists = [token_distances(p, c[0], c[1], java_stmt, target, ahead=ahead) for c in pool]
    common = set.intersection(*(set(d) for d in dists)) if dists else set()
    ranked = []
    for c, d in zip(pool, dists):
        dist = {k: v for k, v in d.items() if k not in common}
        ranked.append(((len(dist), -min(dist.values()) if dist else -99), c))
    ranked.sort(key=lambda x: x[0], reverse=True)
    if ranked and ranked[0][0][0] > 0 and (len(ranked) == 1 or ranked[0][0] > ranked[1][0]):
        return ranked[0][1]
    return None


def match_sink(p, sink, ahead=0):
    cls = resolve_class(p, sink["className"])
    name, arity = java_method_name(sink["methodName"])
    if name == p.classes.get(cls, {}).get("name", "").split(".")[-1]:
        name = "<init>"  # constructor written as the class name
    target = sink["targetName"]
    irs = [norm(ir["IRstatement"]) for ir in sink.get("IRs", []) if ir.get("IRstatement")]
    cands = []
    for sig, m in p.methods.items():
        if m["class"] != cls:
            continue
        mname = sig.split(" ")[-1].split("(")[0]
        margs = [a for a in sig.split("(")[1].rstrip(")>").split(",") if a]
        if mname != name or (arity is not None and len(margs) != arity):
            continue
        line = None
        for i, s in enumerate(m["stmts"]):
            line = s.get("line", line)
            inv = s.get("invoke")
            callee_cls = inv["callee"][1:].split(":")[0] if inv else ""
            callee_name = inv["callee"].split(": ")[1].split("(")[0].split(" ")[-1] if inv else ""
            # constructors are labelled with the class name as target (e.g. "File" ->
            # java.io.File.<init>)
            if inv and (
                callee_name == target
                or (callee_name == "<init>" and callee_cls.split(".")[-1].split("$")[-1] == target)
            ):
                cands.append((sig, i, s["text"], line))
    if not cands:
        return None, "no invoke of target in the enclosing method"
    by_ir = [c for c in cands if norm(c[2]) in irs]
    if len(by_ir) == 1:
        return by_ir[0], "ir"
    pool = by_ir or cands
    if len(pool) == 1:
        return pool[0], "unique-target"
    by_line = [c for c in pool if c[3] is not None and abs(c[3] - sink["lineNo"]) <= 1]
    if len(by_line) == 1:
        return by_line[0], "line"
    best = pick_by_context(p, pool, sink["statement"], target, ahead=ahead)
    if best is not None:
        return best, "context (review)"
    return None, f"ambiguous ({len(pool)} candidates)"


def main():
    cfg = load_config("taintbench")
    cases, unmatched = [], []
    for apk in cfg["included_apks"]:
        app = Path(apk).stem
        p = Program(FACTS_DIR / "taintbench" / f"{app}.json", spec_file=spec_file(cfg))
        findings = json.loads(
            (ROOT / f"vendor/TaintBench/findings/{app}_findings.json").read_text()
        )["findings"]
        spec_sinks = {(s["method"], s["statement"]) for s in p.candidate_sinks()}
        pos, neg, notes, sink_of = {}, {}, [], {}
        for f in findings:
            if (app, f["ID"]) in MANUAL:
                sig, i = MANUAL[(app, f["ID"])]
                hit, how = (sig, i, p.methods[sig]["stmts"][i]["text"], None), "manual (reviewed)"
            else:
                hit, how = match_sink(p, f["sink"])
            if hit is None:
                unmatched.append(
                    {
                        "app": app,
                        "ID": f["ID"],
                        "negative": f.get("isNegative", False),
                        "sink": f["sink"]["statement"],
                        "reason": how,
                    }
                )
                continue
            key = (
                hit[0],
                hit[1],
                hit[2],
            )  # index kept: identical statements in one method are distinct sinks
            sink_of[f["ID"]] = key
            if how != "ir" and how != "unique-target":
                notes.append(f"finding {f['ID']}: matched by {how} -> {hit[0]} [{hit[1]}]")
            (neg if f.get("isNegative") else pos).setdefault(key, []).append(f["ID"])
            if (key[0], key[2]) not in spec_sinks:
                notes.append(
                    f"finding {f['ID']}: sink {f['sink']['targetName']} not in TB spec as "
                    f"matched by S1"
                )
        neg = {k: v for k, v in neg.items() if k not in pos}
        # flow level: map each finding's source as well (same matcher; sources are invoke
        # statements too)
        src_keys = {(x["method"], x["index"]) for x in p.sources()}
        exp_flows, neg_flows = [], []
        for f in findings:
            sk = sink_of.get(f["ID"])
            if sk is None:
                continue
            if (app, f["ID"], "source") in MANUAL:
                sig, i = MANUAL[(app, f["ID"], "source")]
                src, how = (sig, i, p.methods[sig]["stmts"][i]["text"], None), "manual (reviewed)"
            else:
                src, how = match_sink(p, f["source"], ahead=6)
            if src is None:
                unmatched.append(
                    {
                        "app": app,
                        "ID": f["ID"],
                        "negative": f.get("isNegative", False),
                        "part": "source",
                        "source": f["source"]["statement"],
                        "reason": how,
                    }
                )
                continue
            if how not in ("ir", "unique-target"):
                notes.append(f"finding {f['ID']}: source matched by {how} -> {src[0]} [{src[1]}]")
            if (src[0], src[1]) not in src_keys:
                notes.append(
                    f"finding {f['ID']}: source {f['source']['targetName']} is not a KNOWN "
                    f"SOURCE of S1"
                )
            flow = {
                "finding_id": f["ID"],
                "source": {"method": src[0], "index": src[1], "statement": src[2]},
                "sink": {"method": sk[0], "index": sk[1], "statement": sk[2]},
            }
            (neg_flows if f.get("isNegative") else exp_flows).append(flow)
        cases.append(
            {
                "case": app,
                "apk": apk,
                "expected_sinks": [
                    {"method": k[0], "index": k[1], "statement": k[2], "finding_ids": v}
                    for k, v in pos.items()
                ],
                "negative_sinks": [
                    {"method": k[0], "index": k[1], "statement": k[2], "finding_ids": v}
                    for k, v in neg.items()
                ],
                "out_of_spec_sinks": [],
                "expected_flows": exp_flows,
                "negative_flows": neg_flows,
                "findings_positive": sum(1 for f in findings if not f.get("isNegative")),
                "findings_negative": sum(1 for f in findings if f.get("isNegative")),
                "notes": notes,
            }
        )
    gold = {
        "provenance": "TaintBench findings mapped to sink statements by "
        "evaluation/gold/make_taintbench.py",
        "unit": "sink statement; positive if any expected finding ends there, negative if only "
        "unexpected ones do",
        "scoring": "TP = reported positive sink, FP = reported negative sink, other reported "
        "sinks are 'unlisted' "
        "(TaintBench protocol: only labelled flows are scored)",
        "cases": cases,
        "unmatched_findings": unmatched,
    }
    (ROOT / "config/taintbench-gold.json").write_text(json.dumps(gold, indent=2) + "\n")
    for c in cases:
        print(
            f"{c['case']:28s} findings +{c['findings_positive']}/-{c['findings_negative']} -> "
            f"sinks +{len(c['expected_sinks'])}/-{len(c['negative_sinks'])} "
            f"flows +{len(c['expected_flows'])}/-{len(c['negative_flows'])} "
            f"notes={len(c['notes'])}"
        )
    print("unmatched findings:", len(unmatched))
    for u in unmatched:
        print("  ", u)


if __name__ == "__main__":
    main()
