"""ReportAll reference: report every candidate sink of each TaintBench app, with every source of
the app.

Usage: python -m evaluation.report_all   (writes results/neuro/tb-reportall/ and scores it at sink
and flow level)
"""

import subprocess
import sys

from analyzer.benchmarks import FACTS_DIR, ROOT, RUNS_DIR, case_name, load_config, spec_file
from analyzer.frontend.program import Program
from analyzer.resultfile import write_tsv


def main():
    config = load_config("taintbench")
    out = RUNS_DIR / "tb-reportall"
    out.mkdir(parents=True, exist_ok=True)
    for apk in config["included_apks"]:
        case = case_name(apk)
        program = Program(FACTS_DIR / "taintbench" / f"{case}.json", spec_file=spec_file(config))
        sources = program.sources()
        flows = [
            {"source_method": s["method"], "source_statement": s["statement"]} for s in sources
        ]
        records = [
            {"sink": k, "decision": True, "status": "report-all", "flows": flows}
            for k in program.candidate_sinks()
        ]
        write_tsv(out / f"{case}.tsv", records)
        print(f"{case}: {len(records)} sinks, {len(sources)} sources")
    for extra in ([], ["--flows"]):
        subprocess.run(
            [sys.executable, "-m", "evaluation.score_taintbench", str(out)] + extra,
            cwd=ROOT,
            check=True,
        )


if __name__ == "__main__":
    main()
