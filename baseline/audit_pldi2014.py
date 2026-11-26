"""Check the recovered PLDI 2014 inputs (FlowDroid artifact and DroidBench 1.0) against their Git
hashes.

Usage: python -m baseline.audit_pldi2014   (run by scripts/setup_pldi2014.sh)
"""

import hashlib
import json
import subprocess
from zipfile import ZipFile

from analyzer.benchmarks import ROOT


def main():
    specification = json.loads((ROOT / "config/pldi2014.json").read_text())
    benchmark = ROOT / "vendor/DroidBench-1.0"
    commit = subprocess.check_output(
        ["git", "-C", str(benchmark), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    assert commit == specification["benchmark_commit"]
    included = set(specification["included_apks"])
    excluded = set(specification["excluded_apks"])
    apks = {path.name for path in (benchmark / "apk").glob("*.apk")}
    assert apks == included | excluded
    assert not included & excluded
    assert len(included) == 35 and len(excluded) == 4

    archive = ROOT / "vendor/FlowDroid.zip"
    data = archive.read_bytes()
    blob = hashlib.sha1(
        b"blob " + str(len(data)).encode() + b"\0" + data,
    ).hexdigest()
    assert blob == "c7d0e5f4940453586ef955d3b56bc82e3b15e5d9"
    with ZipFile(archive) as package:
        archive_files = package.namelist()
        for name in archive_files:
            actual = ROOT / "vendor/FlowDroid-PLDI2014" / name
            assert actual.read_bytes() == package.read(name)

    manifest = []
    for path in sorted((benchmark / "apk").glob("*.apk")):
        apk_data = path.read_bytes()
        expected_blob = subprocess.check_output(
            ["git", "-C", str(benchmark), "rev-parse", f"HEAD:apk/{path.name}"],
            text=True,
        ).strip()
        actual_blob = hashlib.sha1(
            b"blob " + str(len(apk_data)).encode() + b"\0" + apk_data,
        ).hexdigest()
        assert actual_blob == expected_blob
        manifest.append(
            {
                "apk": path.name,
                "included_in_table_1": path.name in included,
                "exclusion_reason": "implicit flow" if path.name in excluded else None,
                "sha256": hashlib.sha256(apk_data).hexdigest(),
                "git_blob": actual_blob,
            }
        )
    report = {
        "benchmark_commit": commit,
        "benchmark_apks": len(apks),
        "table_1_apks": len(included),
        "excluded_implicit_flow_apks": len(excluded),
        "original_distribution_commit": "08077a294c31004863d63c1e7bbaa060399fa4dd",
        "distribution_git_blob": blob,
        "distribution_sha256": hashlib.sha256(data).hexdigest(),
        "distribution_files": archive_files,
        "original_scorer_available": False,
        "scoring_code_identical_to_paper_verified": False,
        "recovered_evaluator": "evaluation/score_pldi2014.py",
        "recovered_gold": "config/pldi2014-gold.json",
        "recovered_evaluation_ready": True,
        "recovered_results": "results/pldi2014/summary.json",
        "reason": specification["scoring_code_status"],
        "apks": manifest,
    }
    destination = ROOT / "vendor/pldi2014-alignment.json"
    destination.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "apks"}, indent=2))


if __name__ == "__main__":
    main()
