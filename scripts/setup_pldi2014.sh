#!/usr/bin/env bash
set -eu

cd "$(dirname "$0")/.."
mkdir -p vendor
if [ ! -d vendor/DroidBench-1.0/.git ]; then
  git clone --depth 1 --branch DroidBench_1.0 \
    https://github.com/secure-software-engineering/DroidBench.git \
    vendor/DroidBench-1.0
fi
curl -fL \
  'https://raw.githubusercontent.com/lilicoding/soot-infoflow-android/08077a294c31004863d63c1e7bbaa060399fa4dd/PLDI14%20Distribution/FlowDroid.zip' \
  -o vendor/FlowDroid.zip
python3 - <<'PY'
from zipfile import ZipFile

with ZipFile("vendor/FlowDroid.zip") as archive:
    archive.extractall("vendor/FlowDroid-PLDI2014")
PY
python3 -m baseline.audit_pldi2014

mkdir -p tools/jdk8 tools/android-platforms-pldi2014/android-17
curl -fL \
  https://cdn.azul.com/zulu/bin/zulu8.98.0.201-ca-jdk8.0.514-macosx_aarch64.tar.gz \
  -o tools/jdk8.tar.gz
tar -xzf tools/jdk8.tar.gz -C tools/jdk8 --strip-components=1
rm tools/jdk8.tar.gz
curl -fL \
  https://raw.githubusercontent.com/Sable/android-platforms/1e98db1a199e8f7f85541af26bfc27019501b132/android-17/android.jar \
  -o tools/android-platforms-pldi2014/android-17/android.jar
curl -fL \
  https://repo.maven.apache.org/maven2/junit/junit/4.11/junit-4.11.jar \
  -o tools/junit-4.11.jar
curl -fL \
  https://repo.maven.apache.org/maven2/org/hamcrest/hamcrest-core/1.3/hamcrest-core-1.3.jar \
  -o tools/hamcrest-core-1.3.jar
