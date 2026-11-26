"""Score a results folder against a sink-level gold file (used for the DroidBench 3.0 subset).

Usage: python -m evaluation.score_sinks <gold.json> <results dir>

A case without a result (crash or timeout) reports nothing: all its leaks count as FN and the case
is listed as missing. Out-of-specification leaks are true leaks and are also tallied separately.
"""

import json
import sys
from pathlib import Path

from analyzer.resultfile import read_case

from .common import match, relative, write_outputs


def main():
    gold_path, out = Path(sys.argv[1]), Path(sys.argv[2])
    gold = json.loads(gold_path.read_text())
    rows, missing = [], []
    for case in gold["cases"]:
        name = case["case"]
        out_of_spec = [(s["method"], s["statement"]) for s in case.get("out_of_spec_sinks", [])]
        expected = [(s["method"], s["statement"]) for s in case["expected_sinks"]] + out_of_spec
        reported, sinks, _ = read_case(out / f"{name}.tsv")
        if not reported:
            missing.append(name)
        # without negative labels, every unmatched report is a false positive
        tp, _, fp, missed = match(sinks, expected)
        rows.append(
            {
                "case": name,
                "tp": tp,
                "fp": fp,
                "fn": len(missed),
                "fn_out_of_spec": sum(1 for s in missed if s in out_of_spec),
                "reported": reported,
            }
        )
    tp, fp, fn, fno = (sum(r[k] for r in rows) for k in ("tp", "fp", "fn", "fn_out_of_spec"))
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    summary = {
        "gold": relative(gold_path),
        "cases": len(rows),
        "missing_or_failed": missing,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "fn_out_of_spec": fno,
        "precision": p,
        "recall": r,
        "f1": 2 * p * r / (p + r) if p + r else 0.0,
        "recall_spec_covered": tp / (tp + fn - fno) if tp + fn - fno else 0.0,
        "precision_fraction": f"{tp}/{tp + fp}",
        "recall_fraction": f"{tp}/{tp + fn}",
    }
    write_outputs(out, summary, rows)


if __name__ == "__main__":
    main()
