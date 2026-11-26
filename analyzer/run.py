"""Run WholeApp or PerSink on a benchmark, write per-app results and score them.

Examples (from the repository root): python -m analyzer.run --benchmark pldi2014 --mode persink
--run db1-qwen-persink python -m analyzer.run --benchmark taintbench --mode wholeapp --flows --run
tb-qwen-wholeapp-flows

Internally WholeApp is mode "v0" and PerSink "v1"; run.json records these names.
"""

import argparse
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import checker, strategies
from .benchmarks import BENCHMARKS, FACTS_DIR, ROOT, RUNS_DIR, case_name, load_config, spec_file
from .frontend.program import Program
from .llm import DEFAULT_MODEL, LLM
from .resultfile import write_case

ANALYZER_VERSION = "v1.3.1"  # final PerSink checker; recorded in run.json
MODES = {"wholeapp": "v0", "persink": "v1", "persink-nochecker": "v1-noverify"}
ABLATIONS = ["none", "no-annotations", "strict-checker", "veto-prune"]


def parse_args():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--benchmark", choices=sorted(BENCHMARKS), default="pldi2014")
    ap.add_argument(
        "--mode",
        choices=list(MODES) + list(MODES.values()),
        default="persink",
        help="wholeapp: one prompt per app; persink: one checked agent per candidate sink",
    )
    ap.add_argument("--run", required=True, help="output folder under results/neuro/")
    ap.add_argument(
        "--model", default=DEFAULT_MODEL, help="OpenRouter model id (default: %(default)s)"
    )
    ap.add_argument(
        "--sinks",
        choices=["strict", "extended"],
        default="strict",
        help="extended adds setResult as a sink",
    )
    ap.add_argument(
        "--flows",
        action="store_true",
        help="flow level: report every source reaching each leaking sink",
    )
    ap.add_argument(
        "--ablate",
        choices=ABLATIONS,
        default="none",
        help="switch off one PerSink design choice (ablation)",
    )
    ap.add_argument(
        "--max-tokens",
        type=int,
        help="completion budget per call (default: 32768 for wholeapp, "
        "16384 for persink --flows, 4096 otherwise)",
    )
    ap.add_argument("--facts", help="facts folder (default: results/neuro/facts/<benchmark>)")
    ap.add_argument("--only", nargs="*", help="case names to run (the run is then not scored)")
    ap.add_argument("--workers", type=int, default=4, help="parallel PerSink agents")
    ap.add_argument("--resume", action="store_true", help="skip cases that are already finished")
    args = ap.parse_args()
    args.mode = MODES.get(args.mode, args.mode)
    return args


def apply_ablation(name):
    Program.ANNOTATE = name != "no-annotations"
    checker.STRICT = name == "strict-checker"
    checker.VETO = strategies.PRUNE = name == "veto-prune"


def make_llm(args):
    wholeapp = args.mode == "v0"
    budget = args.max_tokens or (32768 if wholeapp else 16384 if args.flows else 4096)
    timeout = (
        3600 if wholeapp else 1800 if budget > 4096 else 180
    )  # long single calls need more time
    return LLM(model=args.model, max_tokens=budget, timeout=timeout)


class RunLog:
    """Bookkeeping for run.json: per-case statistics and token usage across resumed segments."""

    def __init__(self, path, args, llm, resume):
        self.path, self.args, self.llm = path, args, llm
        previous = json.loads(path.read_text()) if resume and path.exists() else {}
        self.per_case = previous.get("per_case", {})
        self.segments = previous.get("segments", [])
        self.without_usage = set(previous.get("cases_without_usage_record", []))
        self.started = time.monotonic()

    def add(self, case, records, seconds=None, usage=None):
        self.per_case[case] = {
            "seconds": seconds,
            "sinks": len(records),
            "reported": sum(r["decision"] for r in records),
            "statuses": [r["status"] for r in records],
            "usage": usage,
        }
        if usage is None:
            self.without_usage.add(case)

    def save(self):
        llm, args = self.llm, self.args
        segment = {
            "wall_seconds": round(time.monotonic() - self.started, 1),
            "usage": dict(llm.usage),
            "provider": llm.provider,
            "model": llm.model,
            "max_tokens": llm.max_tokens,
        }
        segments = self.segments + [segment]
        status_counts = {}
        for info in self.per_case.values():
            for status in info["statuses"]:
                status_counts[status] = status_counts.get(status, 0) + 1
        meta = {
            "analyzer_version": ANALYZER_VERSION,
            "ablate": args.ablate,
            "flows": args.flows,
            "mode": args.mode,
            "sinks": args.sinks,
            "model": args.model,
            "temperature": llm.temperature,
            "max_tokens": llm.max_tokens,
            "request_timeout_s": llm.timeout,
            "provider": llm.provider,
            "wall_seconds": round(sum(s["wall_seconds"] for s in segments), 1),
            "usage": {k: sum(s["usage"][k] for s in segments) for k in llm.usage},
            "segments": segments,
            "cases_without_usage_record": sorted(self.without_usage),
            "status_counts": status_counts,
            "per_case": self.per_case,
        }
        self.path.write_text(json.dumps(meta, indent=2))
        return meta


def run_case(program, args, llm, pool, checkpoint):
    if args.mode == "v0":
        return strategies.run_wholeapp(program, llm, flows=args.flows)
    return strategies.run_persink(
        program,
        llm,
        use_verifier=args.mode == "v1",
        pool=pool,
        checkpoint=checkpoint,
        flows=args.flows,
    )


def score(benchmark, out_dir):
    bench = BENCHMARKS[benchmark]
    gold = [str(ROOT / bench.gold)] if bench.gold else []
    cmd = [sys.executable, "-m", bench.scorer] + gold + [str(out_dir)]
    subprocess.run(cmd, cwd=ROOT, check=True)


def main():
    args = parse_args()
    apply_ablation(args.ablate)
    config = load_config(args.benchmark)
    facts_dir = Path(args.facts) if args.facts else FACTS_DIR / args.benchmark
    out_dir = RUNS_DIR / args.run
    out_dir.mkdir(parents=True, exist_ok=True)
    llm = make_llm(args)
    log = RunLog(out_dir / "run.json", args, llm, args.resume)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for apk in config["included_apks"]:
            case = case_name(apk) if args.benchmark != "pldi2014" else Path(apk).stem
            if args.only and case not in args.only:
                continue
            trace = out_dir / f"{case}.trace.json"
            if args.resume and (out_dir / f"{case}.tsv").exists() and trace.exists():
                if (
                    case not in log.per_case
                ):  # finished by a run that was interrupted before run.json
                    log.add(case, json.loads(trace.read_text()))
                continue
            t0, before = time.monotonic(), dict(llm.usage)
            program = Program(
                facts_dir / f"{case}.json",
                extended=args.sinks == "extended",
                spec_file=spec_file(config),
            )
            checkpoint = out_dir / f"{case}.partial.jsonl"
            records = run_case(program, args, llm, pool, checkpoint)
            failed = [r for r in records if r.get("status") == "llm-error"]
            if failed:  # leave the case unfinished: --resume retries it from the checkpoint
                print(f"{case}: {len(failed)} sink(s) failed: {failed[0]['error']}", flush=True)
                continue
            write_case(out_dir, case, records)
            checkpoint.unlink(missing_ok=True)
            log.add(
                case,
                records,
                round(time.monotonic() - t0, 1),
                {k: round(llm.usage[k] - before[k], 1) for k in llm.usage},
            )
            print(f"{case}: {log.per_case[case]}", flush=True)
            log.save()  # checkpoint after every case
    meta = log.save()
    if not args.only:
        score(args.benchmark, out_dir)
    keys = ("wall_seconds", "usage", "status_counts", "cases_without_usage_record")
    print(json.dumps({k: meta[k] for k in keys}, indent=2))


if __name__ == "__main__":
    main()
