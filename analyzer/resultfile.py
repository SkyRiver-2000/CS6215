"""Per-app result files (<case>.tsv), shared by the analyzer, the FlowDroid exporter and the
scorers.

Format (one entry per line, statements Base64-encoded, same as baseline/OriginalFlowDroid.java):
    COUNT  <number of reported sinks>      (or NULL if the tool produced no result)
    SINK   <method> -1 <statement> <statement>
    SOURCE <method> -1 <statement>         (sources reaching the preceding sink, flow level only)
"""

import base64
import json


def _encode(text):
    return base64.b64encode(text.encode("utf-8")).decode()


def _decode(value):
    return base64.b64decode(value).decode("utf-8")


def write_case(out_dir, case, records):
    """Write <case>.tsv for the reported sinks and <case>.trace.json with every decision record."""
    write_tsv(out_dir / f"{case}.tsv", records)
    (out_dir / f"{case}.trace.json").write_text(json.dumps(records, indent=1, default=str))


def write_tsv(path, records):
    """Write the result file for the records whose decision is a leak."""
    leaks = [r for r in records if r["decision"]]
    lines = [f"COUNT\t{len(leaks)}"]
    for r in leaks:
        sink = r["sink"]  # renamed facts carry the original method and statement for scoring
        method = sink.get("orig_method", sink["method"])
        stmt = sink.get("orig_statement", sink["statement"])
        lines.append("\t".join(["SINK", _encode(method), "-1", _encode(stmt), _encode(stmt)]))
        for f in r.get("flows") or []:
            lines.append(
                "\t".join(
                    ["SOURCE", _encode(f["source_method"]), "-1", _encode(f["source_statement"])]
                )
            )
    path.write_text("\n".join(lines) + "\n")


def read_case(path):
    """Return (has_result, sinks, flows): sinks as (method, statement), flows as (source method,
    source statement, sink method, sink statement). A missing file or NULL means no result."""
    lines = path.read_text().splitlines() if path.exists() else []
    if not lines or lines[0] == "NULL":
        return False, [], []
    sinks, flows, sink = [], [], None
    for line in lines[1:]:
        f = line.split("\t")
        if f[0] == "SINK":
            sink = (_decode(f[1]), _decode(f[4]))
            sinks.append(sink)
        elif f[0] == "SOURCE" and sink is not None:
            flows.append((_decode(f[1]), _decode(f[3])) + sink)
    return True, sinks, flows
