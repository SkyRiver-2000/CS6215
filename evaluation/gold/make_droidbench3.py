"""Write config/droidbench3-gold.json from the drafted labels plus the manual review decisions
below.

Usage: python -m evaluation.gold.make_droidbench3
"""

import json

from analyzer.benchmarks import FACTS_DIR, ROOT, case_name
from analyzer.frontend.program import Program

from .draft_droidbench3 import draft_labels

NOTES = {
    "Aliasing_FlowSensitivity1": "Header 0. Inline comment 'sink, leak' is stale: the sink reads "
    "b.b before the alias b = a is created (onCreate runs once per instance).",
    "GeneralJava_Exceptions3": "Header 0. Inline comment 'sink, leak' is stale: arr[32] on "
    "int[42] cannot throw, so the handler is dead.",
    "Reflection_Reflection10": "Annotated leak is the reflective "
    "URLConnection.setRequestProperty call (Method.invoke), outside the PLDI spec -> "
    "out_of_spec_sinks. The unannotated Log.i in doInBackground concatenates the same "
    "tainted getLine1() value and is a genuine leak to a spec sink (same policy as the "
    "Button2 log site in the DroidBench 1.0 gold).",
    "Reflection_Reflection10-NoFlow": "getUncritical() returns a constant; neither Log call "
    "receives tainted data.",
    "GeneralJava_StringToOutputStream1": "ByteArrayOutputStream.write matches the PLDI "
    "OutputStream sink spec but writes to an in-memory buffer; the benchmark counts only the "
    "Log.i leak. Labelled non-leak (debatable).",
    "GeneralJava_VirtualDispatch1": "Only DataLeak.logData leaks; NoDataLeak.logData runs only "
    "on the instance constructed with the constant 'no leak'.",
    "GeneralJava_VirtualDispatch2": "sendTextMessage leaks (test1.method(b)); Log.i is annotated "
    "'sink, no leak'.",
    "GeneralJava_StartProcessWithSecret1": "Leak through ProcessBuilder.command/start, outside "
    "the PLDI spec -> out_of_spec_sinks only.",
    "GeneralJava_StaticInitialization3": "Annotated 'possible leak depending on runtime "
    "execution of Test's clinit'; header 1. Labelled leak.",
    "GeneralJava_StringPatternMatching1": "No inline annotation; header 1 and a single candidate "
    "sink (Log.i of the regex group of the IMEI).",
    "Reflection_Reflection5": "Sink method is only invoked via reflection (not in the CHA call "
    "graph).",
    "Reflection_Reflection8": "Sink method is only invoked via reflection (not in the CHA call "
    "graph).",
    "Reflection_Reflection9": "Sink method is only invoked via reflection (not in the CHA call "
    "graph).",
}


def main():
    draft = {c["case"]: c for c in draft_labels()}

    def pick(case, pred):
        return [
            {"method": s["method"], "statement": s["statement"]}
            for s in draft[case]["sinks"]
            if pred(s)
        ]

    def exact(case, method_part, text):
        p = Program(FACTS_DIR / "droidbench3" / f"{case}.json")
        hits = [
            (sig, s["text"])
            for sig, m in p.methods.items()
            if method_part in sig
            for s in m["stmts"]
            if s["text"] == text
        ]
        assert len(hits) == 1, (case, hits)
        return {"method": hits[0][0], "statement": hits[0][1]}

    cfg = json.loads((ROOT / "config/droidbench3-subset.json").read_text())
    cases = []
    for apk in cfg["included_apks"]:
        case = case_name(apk)
        d, oos = draft[case], []
        n = d["number_of_leaks"]
        if case == "Reflection_Reflection10":
            exp = pick(
                case, lambda s: "doInBackground" in s["method"] and "Log: int i(" in s["statement"]
            )
            oos = [
                exact(
                    case,
                    "doInBackground",
                    "virtualinvoke $r9.<java.lang.reflect.Method: java.lang.Object "
                    "invoke(java.lang.Object,java.lang.Object[])>($r10, $r1)",
                )
            ]
        elif case == "GeneralJava_StringToOutputStream1":
            exp = pick(case, lambda s: "android.util.Log" in s["statement"])
        elif case == "GeneralJava_VirtualDispatch1":
            exp = pick(case, lambda s: s["method"].startswith("<de.ecspride.DataLeak:"))
        elif case == "GeneralJava_VirtualDispatch2":
            exp = pick(case, lambda s: "sendTextMessage" in s["statement"])
        elif case == "GeneralJava_StartProcessWithSecret1":
            exp = []
            oos = [
                exact(
                    case,
                    "onCreate",
                    "virtualinvoke $r3.<java.lang.ProcessBuilder: java.lang.Process start()>()",
                )
            ]
        elif n == 0:
            exp = []
        else:
            assert len(d["sinks"]) == n, (case, len(d["sinks"]), n)
            exp = pick(case, lambda s: True)
        entry = {
            "case": case,
            "apk": apk,
            "number_of_leaks_header": n,
            "expected_sinks": exp,
            "out_of_spec_sinks": oos,
        }
        if case in NOTES:
            entry["note"] = NOTES[case]
        cases.append(entry)
    gold = {
        "provenance": "DroidBench 3.0 subset. Sink-level labels drafted by "
        "evaluation/gold/draft_droidbench3.py from the benchmark's "
        "source annotations and @number_of_leaks, then reviewed manually against the Java source "
        "(evaluation/gold/make_droidbench3.py; note per non-obvious case). Prepared with AI "
        "assistance; "
        "reviewed by the student.",
        "unit": "One sink call statement in the Jimple produced by the PLDI-era Soot (API 17 "
        "stubs), as in "
        "config/pldi2014-gold.json.",
        "scoring": "expected_sinks and out_of_spec_sinks are both true leaks; out_of_spec_sinks "
        "cannot be reported "
        "by an analyzer restricted to the PLDI SourcesAndSinks.txt and are also reported "
        "separately.",
        "cases": cases,
    }
    (ROOT / "config/droidbench3-gold.json").write_text(json.dumps(gold, indent=2) + "\n")
    print(
        "apps",
        len(cases),
        "spec-covered leaks",
        sum(len(c["expected_sinks"]) for c in cases),
        "out-of-spec leaks",
        sum(len(c["out_of_spec_sinks"]) for c in cases),
        "header total",
        sum(c["number_of_leaks_header"] for c in cases),
    )


if __name__ == "__main__":
    main()
