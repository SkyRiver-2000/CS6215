"""Symbolic front end: export facts (Jimple, invokes, manifest, layouts) for every APK of a
benchmark.

Usage: python -m analyzer.frontend.export --benchmark pldi2014|droidbench3|taintbench [--only CASE
...]
"""

import argparse
import json
import os
import subprocess
from pathlib import Path

from ..benchmarks import (
    BENCHMARKS,
    FACTS_DIR,
    FLOWDROID_JAR,
    JAVA_HOME,
    LOG_DIR,
    ROOT,
    case_name,
    load_config,
)
from .axml import read_apk_xml

CLASSES = ROOT / "tools/frontend-classes"
EXPORTER = Path(__file__).with_name("ExportFacts.java")


def compile_exporter():
    CLASSES.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            str(JAVA_HOME / "bin/javac"),
            "-cp",
            str(FLOWDROID_JAR),
            "-d",
            str(CLASSES),
            str(EXPORTER),
        ],
        check=True,
    )


def export(apk, platforms, out):
    """Run the Soot-based exporter on one APK and add the manifest and layouts parsed in Python."""
    out.parent.mkdir(parents=True, exist_ok=True)
    classpath = os.pathsep.join([str(CLASSES), str(FLOWDROID_JAR)])
    proc = subprocess.run(
        [
            str(JAVA_HOME / "bin/java"),
            "-Xmx3g",
            "-cp",
            classpath,
            "ExportFacts",
            str(apk),
            str(platforms),
            str(out),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if proc.returncode != 0:
        log = LOG_DIR / "export" / out.with_suffix(".log").name
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(proc.stdout)
        raise RuntimeError(f"export failed, see {log}")
    facts = json.loads(out.read_text())
    facts["manifest"], facts["layouts"] = read_apk_xml(apk)
    try:  # record the APK relative to the repository, not as a machine-specific path
        facts["apk"] = str(Path(apk).relative_to(ROOT))
    except ValueError:
        pass
    out.write_text(json.dumps(facts, indent=1))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--benchmark", default="pldi2014", choices=sorted(BENCHMARKS))
    parser.add_argument("--out", help="output folder (default: results/neuro/facts/<benchmark>)")
    parser.add_argument("--only", nargs="*", help="case names to export")
    args = parser.parse_args()
    bench = BENCHMARKS[args.benchmark]
    out = Path(args.out) if args.out else FACTS_DIR / args.benchmark
    compile_exporter()
    failed = []
    for apk in load_config(args.benchmark)["included_apks"]:
        case = case_name(apk)
        if args.only and case not in args.only:
            continue
        try:
            export(ROOT / bench.apk_dir / apk, ROOT / bench.platforms, out / f"{case}.json")
            print("exported", case, flush=True)
        except RuntimeError as e:
            failed.append(case)
            print("FAILED", case, e, flush=True)
    if failed:
        print("failed:", failed)


if __name__ == "__main__":
    main()
