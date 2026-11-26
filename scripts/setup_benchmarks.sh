#!/usr/bin/env bash
# Fetch the DroidBench 3.0 and TaintBench inputs and prepare the Android stubs used for both.
# Run after scripts/setup_pldi2014.sh (which installs the original FlowDroid artifact, Java 8 and the API 17 stubs).
set -eu
cd "$(dirname "$0")/.."

# DroidBench 3.0, pinned commit
DB3_COMMIT=a57fa6f42f278591695672f1aa8b37c275139370
if [ ! -d vendor/DroidBench/.git ]; then
  git clone https://github.com/secure-software-engineering/DroidBench.git vendor/DroidBench
fi
git -C vendor/DroidBench checkout --quiet "$DB3_COMMIT"

# TaintBench: APKs from each app repository's "APK" release, ground truth <app>_findings.json, and the
# benchmark's source/sink specification
TB_APPS="proxy_samp roidsec sms_send_locker_qqmagic exprespam godwon_samp phospy death_ring_materialflow fakedaum"
mkdir -p vendor/TaintBench/apk vendor/TaintBench/findings vendor/TaintBench/spec
for a in $TB_APPS; do
  [ -f "vendor/TaintBench/apk/$a.apk" ] || \
    curl -fsSL -o "vendor/TaintBench/apk/$a.apk" "https://github.com/TaintBench/$a/releases/download/APK/$a.apk"
  for br in master main; do
    curl -fsSL -o "vendor/TaintBench/findings/${a}_findings.json" \
      "https://raw.githubusercontent.com/TaintBench/$a/$br/${a}_findings.json" && break
  done
done
for br in master main; do
  curl -fsSL -o vendor/TaintBench/spec/TB_SourcesAndSinks.txt \
    "https://raw.githubusercontent.com/TaintBench/TaintBench/$br/TB_SourcesAndSinks.txt" && break
done

# FlowDroid working directory for TaintBench: the original artifact's configuration files with the TaintBench
# specification as SourcesAndSinks.txt
mkdir -p tools/flowdroid-taintbench
cp vendor/FlowDroid-PLDI2014/EasyTaintWrapperSource.txt vendor/FlowDroid-PLDI2014/AndroidCallbacks.txt \
  tools/flowdroid-taintbench/
cp vendor/TaintBench/spec/TB_SourcesAndSinks.txt tools/flowdroid-taintbench/SourcesAndSinks.txt

# Newer apps target API levels 3-35, but only the API 17 stubs of the original artifact are used, for all tools
for n in $(seq 3 35); do
  mkdir -p "tools/android-platforms-forced17/android-$n"
  ln -sf ../../android-platforms-pldi2014/android-17/android.jar "tools/android-platforms-forced17/android-$n/android.jar"
done
echo "benchmarks ready"
