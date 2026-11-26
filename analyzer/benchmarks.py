"""Repository paths and benchmark definitions shared by the analyzer, baseline and evaluation."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
JAVA_HOME = ROOT / "tools/jdk8/Contents/Home"
FLOWDROID_DIR = ROOT / "vendor/FlowDroid-PLDI2014"
FLOWDROID_JAR = FLOWDROID_DIR / "FlowDroid.jar"
FACTS_DIR = ROOT / "results/neuro/facts"
RUNS_DIR = ROOT / "results/neuro"
LOG_DIR = ROOT / "logs"  # tool logs (not part of the results)


@dataclass(frozen=True)
class Benchmark:
    config: str  # APK selection (and specification, for TaintBench)
    apk_dir: str
    platforms: str  # Android platform stubs; newer apps also use the API 17 jar of the artifact
    scorer: str  # evaluation module that scores a results folder
    gold: Optional[str] = None  # gold file passed to the scorer, if it takes one


BENCHMARKS = {
    "pldi2014": Benchmark(
        "config/pldi2014.json",
        "vendor/DroidBench-1.0/apk",
        "tools/android-platforms-pldi2014",
        "evaluation.score_pldi2014",
    ),
    "droidbench3": Benchmark(
        "config/droidbench3-subset.json",
        "vendor/DroidBench/apk",
        "tools/android-platforms-forced17",
        "evaluation.score_sinks",
        "config/droidbench3-gold.json",
    ),
    "taintbench": Benchmark(
        "config/taintbench-subset.json",
        "vendor/TaintBench/apk",
        "tools/android-platforms-forced17",
        "evaluation.score_taintbench",
    ),
}


def load_config(benchmark):
    return json.loads((ROOT / BENCHMARKS[benchmark].config).read_text())


def spec_file(config):
    """Source/sink specification named by a benchmark config (None: FlowDroid's default list)."""
    return ROOT / config["spec"].split(" ")[0] if "spec" in config else None


def case_name(apk):
    """Case name of an APK path in a benchmark (Aliasing/Merge1.apk -> Aliasing_Merge1)."""
    return str(Path(apk).with_suffix("")).replace("/", "_")
