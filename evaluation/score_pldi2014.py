"""Score a results folder against the recovered DroidBench 1.0 Table 1 labels (sink level).

Usage: python -m evaluation.score_pldi2014 [results dir]   (default: the FlowDroid run in
results/pldi2014)

Matching uses the exact enclosing method and sink statement; per-app counts are compared with the
paper's Table 1.
"""

import json
import sys
from pathlib import Path

from analyzer.benchmarks import ROOT
from analyzer.resultfile import read_case

from .common import match, write_outputs

PAPER_TOTALS = {"tp": 26, "fp": 4, "fn": 2}


def main():
    gold = json.loads((ROOT / "config/pldi2014-gold.json").read_text())
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "results/pldi2014"
    rows = []
    for case in gold["cases"]:
        tsv = out / f"{Path(case['apk']).stem}.tsv"
        native_count = int(tsv.read_text().split("\n", 1)[0].split("\t")[1])  # COUNT line
        _, sinks, _ = read_case(tsv)
        expected = [(s["method"], s["statement"]) for s in case["expected_sinks"]]
        # without negative labels, every unmatched report is a false positive
        tp, _, fp, missed = match(sinks, expected)
        fn = len(missed)
        rows.append(
            {
                "apk": case["apk"],
                "native_sink_count": native_count,
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "paper_tp": case["paper_tp"],
                "paper_fp": case["paper_fp"],
                "paper_fn": case["paper_fn"],
                "matches_paper_row": (tp, fp, fn)
                == (case["paper_tp"], case["paper_fp"], case["paper_fn"]),
            }
        )
    tp, fp, fn = (sum(r[k] for r in rows) for k in ("tp", "fp", "fn"))
    precision, recall = tp / (tp + fp), tp / (tp + fn)
    summary = {
        "evaluation": "Recovered Table 1 sink-level evaluation",
        "original_scoring_script": False,
        "original_analyzer_and_analysis_helper": True,
        "cases": len(rows),
        "expected_sinks": sum(len(c["expected_sinks"]) for c in gold["cases"]),
        "native_reported_sinks": sum(r["native_sink_count"] for r in rows),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "precision_fraction": f"{tp}/{tp + fp}",
        "recall": recall,
        "recall_fraction": f"{tp}/{tp + fn}",
        "f1": 2 * precision * recall / (precision + recall),
        "paper_counts": PAPER_TOTALS,
        "paper_display": {"precision": "86%", "recall": "93%", "f_measure": "0.89"},
        "matching_paper_rows": sum(r["matches_paper_row"] for r in rows),
        "rounding": "Ratios reported directly; no attempt to reproduce unspecified paper display "
        "rounding.",
    }
    write_outputs(out, summary, rows, table="table-1-comparison.csv")


if __name__ == "__main__":
    main()
