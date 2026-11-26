"""Draft sink-level gold labels for the DroidBench 3.0 subset from the benchmark's own source
annotations.

For every spec sink call (strict PLDI spec plus framework escape calls) found in the front-end
facts, the statement is mapped to its Java source line (Soot line tags, forward-filled within the
method). The draft label is taken from the benchmark comment on that line: "sink, no leak" / "no
leak" / "not tainted" -> false ; any other comment mentioning "sink" or "leak" -> true ; no comment
-> false (flagged). The draft is cross-checked against @number_of_leaks. All flags are reviewed
manually; the reviewed labels are stored in config/droidbench3-gold.json by
evaluation.gold.make_droidbench3, with a note per decision.

Usage: python -m evaluation.gold.draft_droidbench3 > droidbench3-draft.json   (to inspect the
draft)
"""

import json
import re
from pathlib import Path

from analyzer.benchmarks import FACTS_DIR, ROOT, case_name
from analyzer.frontend.program import Program


def source_file(project, cls):
    rel = cls.split("$")[0].replace(".", "/") + ".java"
    hits = list(project.rglob(rel))
    return hits[0] if hits else None


def draft_labels():
    cfg = json.loads((ROOT / "config/droidbench3-subset.json").read_text())
    out = []
    for apk in cfg["included_apks"]:
        case = case_name(apk)
        project = ROOT / cfg["projects_dir"] / str(Path(apk).with_suffix(""))
        p = Program(FACTS_DIR / "droidbench3" / f"{case}.json", extended=True)
        reach = p.reachability()
        texts = {}
        header_leaks = None
        for f in project.rglob("*.java"):
            t = f.read_text(errors="replace")
            m = re.search(r"@number_of_leaks\s+(\d+)", t)
            if m:
                header_leaks = (header_leaks or 0) + int(m.group(1))
        sinks = []
        for s in p.candidate_sinks():
            m = p.methods[s["method"]]
            line = None
            for st in m["stmts"][: s["index"] + 1]:
                line = st.get("line", line)
            src = source_file(project, m["class"])
            code = ""
            if src and line:
                lines = src.read_text(errors="replace").splitlines()
                code = lines[line - 1].strip() if line <= len(lines) else ""
                if src not in texts:
                    texts[src] = True
            comment = code.split("//", 1)[1].strip().lower() if "//" in code else ""
            if re.search(r"no leak|not tainted|no data leak|untainted", comment):
                label, flag = False, None
            elif re.search(r"sink|leak", comment):
                label, flag = True, None
            else:
                label, flag = False, "no annotation on sink line"
            sinks.append(
                {
                    "method": s["method"],
                    "statement": s["statement"],
                    "kind": s["kind"],
                    "reachable_symbolic": s["method"] in reach,
                    "line": line,
                    "source_line": code,
                    "draft_leak": label,
                    "flag": flag,
                }
            )
        drafted = sum(x["draft_leak"] for x in sinks)
        out.append(
            {
                "case": case,
                "apk": apk,
                "number_of_leaks": header_leaks,
                "draft_leaks": drafted,
                "count_mismatch": header_leaks is not None and drafted != header_leaks,
                "sinks": sinks,
            }
        )
    return out


def main():
    print(json.dumps(draft_labels(), indent=1))


if __name__ == "__main__":
    main()
