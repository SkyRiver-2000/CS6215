"""Score a results folder against the TaintBench labels mapped to our Jimple (config/taintbench-
gold.json).

Usage: python -m evaluation.score_taintbench <results dir> [--flows]

TaintBench protocol: a report is a TP if it matches an expected sink (flow) and an FP if it matches
    a negative one;
any other report is unlisted and not scored. Sinks are matched on (method, statement) with
    multiplicity. With
--flows, a flow is a (source statement, sink statement) pair; labels that collapse to the same pair
    count once,
and negative labels that coincide with expected ones are dropped.
"""

import json
import sys
from pathlib import Path

from analyzer.benchmarks import ROOT
from analyzer.resultfile import read_case

from .common import match, write_outputs

GOLD = "config/taintbench-gold.json"


def _sink(s):
    return s["method"], s["statement"]


def _flow(f):
    return _sink(f["source"]) + _sink(f["sink"])


def labels(case, flows):
    if not flows:
        return [_sink(s) for s in case["expected_sinks"]], [
            _sink(s) for s in case["negative_sinks"]
        ]
    positive = list(dict.fromkeys(_flow(f) for f in case["expected_flows"]))
    negative = [
        k for k in dict.fromkeys(_flow(f) for f in case["negative_flows"]) if k not in positive
    ]
    return positive, negative


def main():
    out = Path(sys.argv[1])
    flows = "--flows" in sys.argv[2:]
    gold = json.loads((ROOT / GOLD).read_text())
    rows, missing = [], []
    for case in gold["cases"]:
        reported, sinks, case_flows = read_case(out / f"{case['case']}.tsv")
        if not reported:
            missing.append(case["case"])
        positive, negative = labels(case, flows)
        items = (
            list(dict.fromkeys(case_flows)) if flows else sinks
        )  # a pair reported twice is one flow
        tp, fp, unlisted, missed = match(items, positive, negative)
        rows.append(
            {
                "case": case["case"],
                "tp": tp,
                "fp": fp,
                "fn": len(missed),
                "unlisted": unlisted,
                "reported": reported,
            }
        )
    tp, fp, fn, unlisted = (sum(r[k] for r in rows) for k in ("tp", "fp", "fn", "unlisted"))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else 0.0
    if flows:
        summary = {
            "unit": "flow (source statement, sink statement)",
            "cases": len(rows),
            "missing_or_failed": missing,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "unlisted": unlisted,
            "precision_labelled": precision,
            "recall": recall,
        }
        write_outputs(
            out, summary, rows, table="per-case-flows.csv", summary_name="summary-flows.json"
        )
    else:
        summary = {
            "gold": GOLD,
            "cases": len(rows),
            "missing_or_failed": missing,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "unlisted": unlisted,
            "precision_labelled": precision,
            "recall": recall,
            "note": "precision over labelled sinks only (TaintBench protocol); unlisted reports "
            "counted separately",
        }
        write_outputs(out, summary, rows)


if __name__ == "__main__":
    main()
