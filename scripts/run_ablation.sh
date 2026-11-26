#!/usr/bin/env bash
# RQ3 ablation (Table 6): switch off one design choice of PerSink at a time on the DroidBench 3.0 subset (46 apps),
# plus repeated runs on the three DroidBench 1.0 apps for which the choices were introduced.
#   bash scripts/run_ablation.sh
# Needs OPENROUTER_API_KEY. Resumable (--resume). Results: results/neuro/ablation/.
set -eu
cd "$(dirname "$0")/.."
PY=${PYTHON:-python3}
QWEN="--model qwen/qwen3.8-27b --resume"

for v in final no-checker no-annotations strict-checker veto-prune; do
  case $v in
    final)      args="--mode persink" ;;
    no-checker) args="--mode persink-nochecker" ;;
    *)          args="--mode persink --ablate $v" ;;
  esac
  $PY -m analyzer.run $QWEN --benchmark droidbench3 --workers 3 $args --run ablation/db3-$v &
done
wait

APPS="AndroidNonspecific_Loop2 Lifecycle_ActivityLifecycle2 AndroidSpecific_PrivateDataLeak1"
for i in 1 2 3; do
  for v in final no-annotations strict-checker; do
    args="--mode persink"; [ $v = final ] || args="$args --ablate $v"
    $PY -m analyzer.run $QWEN --benchmark pldi2014 --workers 2 $args --only $APPS --run ablation/db1-repeats/$v-$i &
  done
done
wait
