"""Run the unchanged original FlowDroid artifact (PLDI 2014) on a benchmark.

Usage: python -m baseline.run pldi2014|droidbench3|taintbench [CASE ...]
Heap size: BASELINE_XMX (default 3g). A crash or timeout is recorded as such; there are no retries.

The artifact's own analysis helper JUnitTests.analyzeAPKFile(apk) is invoked through
OriginalFlowDroid.java, which only exports the native results. Only the APK folder, the Android
platform stubs and (for TaintBench) the source/sink specification differ between benchmarks.
"""

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from analyzer.benchmarks import (
    BENCHMARKS,
    FLOWDROID_DIR,
    FLOWDROID_JAR,
    JAVA_HOME,
    LOG_DIR,
    ROOT,
    case_name,
    load_config,
)

CLASSES = ROOT / "tools/pldi2014-classes"
EXPORTER = Path(__file__).with_name("OriginalFlowDroid.java")
JUNIT = ROOT / "tools/junit-4.11.jar"
TIMEOUT_S = 900
OUTPUT = {
    "pldi2014": "results/pldi2014",
    "droidbench3": "results/droidbench3-baseline",
    "taintbench": "results/taintbench-baseline",
}
# working directory holding SourcesAndSinks.txt, AndroidCallbacks.txt and
# EasyTaintWrapperSource.txt
WORKDIR = {
    "pldi2014": FLOWDROID_DIR,
    "droidbench3": FLOWDROID_DIR,
    "taintbench": ROOT / "tools/flowdroid-taintbench",
}


def compile_exporter(classpath):
    CLASSES.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [str(JAVA_HOME / "bin/javac"), "-cp", classpath, "-d", str(CLASSES), str(EXPORTER)],
        check=True,
    )


def run_app(apk, case, benchmark, classpath, env, heap, out):
    """Analyse one APK; return its status ("ok", "exit N" or "timeout")."""
    log = LOG_DIR / "flowdroid" / benchmark / f"{case}.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(JAVA_HOME / "bin/java"),
        f"-Xmx{heap}",
        "-cp",
        classpath,
        "OriginalFlowDroid",
        apk,
        str(out / f"{case}.tsv"),
    ]
    with log.open("w") as stream:
        try:
            proc = subprocess.run(
                cmd,
                cwd=WORKDIR[benchmark],
                env=env,
                stdout=stream,
                stderr=subprocess.STDOUT,
                timeout=TIMEOUT_S,
            )
        except subprocess.TimeoutExpired:
            return "timeout"
    return "ok" if proc.returncode == 0 else f"exit {proc.returncode}"


def main():
    benchmark = sys.argv[1] if len(sys.argv) > 1 else "pldi2014"
    only = set(sys.argv[2:])
    heap = os.environ.get("BASELINE_XMX", "3g")
    config = load_config(benchmark)
    classpath = os.pathsep.join(str(p) for p in (CLASSES, FLOWDROID_JAR, JUNIT))
    compile_exporter(classpath)
    env = dict(
        os.environ,
        ANDROID_JARS=str(ROOT / BENCHMARKS[benchmark].platforms),
        DROIDBENCH=str(ROOT / BENCHMARKS[benchmark].apk_dir),
    )
    out = ROOT / OUTPUT[benchmark]
    out.mkdir(parents=True, exist_ok=True)
    runtime_path = out / "runtime.json"
    runtime = json.loads(runtime_path.read_text()) if only and runtime_path.exists() else {}
    started = time.monotonic()
    for apk in config["included_apks"]:
        case = case_name(apk) if benchmark != "pldi2014" else Path(apk).stem
        if only and case not in only:
            continue
        t0 = time.monotonic()
        status = run_app(apk, case, benchmark, classpath, env, heap, out)
        seconds = round(time.monotonic() - t0, 1)
        runtime.setdefault("status", {})[case] = status
        runtime.setdefault("heap", {})[case] = heap
        runtime.setdefault("per_case_seconds", {})[case] = seconds
        print(f"{case}: {status} {seconds}s", flush=True)
    java_version = subprocess.run(
        [str(JAVA_HOME / "bin/java"), "-version"], capture_output=True, text=True, check=True
    ).stderr
    inputs = [FLOWDROID_JAR, EXPORTER] + [
        WORKDIR[benchmark] / name
        for name in ("SourcesAndSinks.txt", "AndroidCallbacks.txt", "EasyTaintWrapperSource.txt")
    ]
    runtime.update(
        {
            "wall_seconds_last_invocation": round(time.monotonic() - started, 1),
            "timeout_seconds": TIMEOUT_S,
            "java_version": java_version,
            "analysis": "Original artifact JUnitTests.analyzeAPKFile(apk)",
            "sha256": {
                str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in inputs
            },
        }
    )
    runtime_path.write_text(json.dumps(runtime, indent=2) + "\n")


if __name__ == "__main__":
    main()
