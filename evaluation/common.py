"""Helpers shared by the scorers."""

import csv
import json
from pathlib import Path

from analyzer.benchmarks import ROOT


def relative(path):
    """Path as recorded in summaries: relative to the repository when possible."""
    path = Path(path).resolve()
    try:
        return str(path.relative_to(ROOT.resolve()))
    except ValueError:
        return str(path)


def match(reported, positive, negative=()):
    """Match reports against labels with multiplicity; return (tp, fp, unlisted, missed)."""
    positive, negative = list(positive), list(negative)
    tp = fp = unlisted = 0
    for item in reported:
        if item in positive:
            positive.remove(item)
            tp += 1
        elif item in negative:
            negative.remove(item)
            fp += 1
        else:
            unlisted += 1
    return tp, fp, unlisted, positive


def write_outputs(out, summary, rows, table="per-case.csv", summary_name="summary.json"):
    (out / summary_name).write_text(json.dumps(summary, indent=2) + "\n")
    with (out / table).open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps(summary, indent=2))
