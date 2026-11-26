#!/usr/bin/env bash
# Re-run every LLM configuration reported in the paper and score it. Each section can also be run on its own;
# runs are resumable (--resume) from per-sink checkpoints.
#   bash scripts/reproduce_llm.sh [db1|db3|tb|all]
# Needs OPENROUTER_API_KEY. Results go to results/neuro/<run>/ (shipped copies are overwritten).
set -eu
cd "$(dirname "$0")/.."
PY=${PYTHON:-python3}
QWEN="--model qwen/qwen3.8-27b"
DS="--model deepseek/deepseek-v4.1-flash-1017"
run() { $PY -m analyzer.run --resume "$@"; }
what=${1:-all}

if [ "$what" = db1 ] || [ "$what" = all ]; then      # Table 2: DroidBench 1.0 (35 apps)
  run $QWEN --benchmark pldi2014 --mode wholeapp --workers 1 --run db1-qwen-wholeapp
  run $QWEN --benchmark pldi2014 --mode persink  --workers 4 --run db1-qwen-persink
  run $QWEN --benchmark pldi2014 --mode persink  --workers 4 --run db1-qwen-persink-setresult --sinks extended
  # renaming experiment: facts with all app identifiers renamed (python -m analyzer.frontend.rename)
  run $QWEN --benchmark pldi2014 --mode wholeapp --workers 1 --run db1-qwen-wholeapp-renamed --facts results/neuro/facts/pldi2014-renamed
  run $QWEN --benchmark pldi2014 --mode persink  --workers 4 --run db1-qwen-persink-renamed  --facts results/neuro/facts/pldi2014-renamed
fi

if [ "$what" = db3 ] || [ "$what" = all ]; then      # Table 3: DroidBench 3.0 subset (46 apps)
  run $QWEN --benchmark droidbench3 --mode wholeapp --workers 1 --run db3-qwen-wholeapp
  run $QWEN --benchmark droidbench3 --mode persink  --workers 4 --run db3-qwen-persink
fi

if [ "$what" = tb ] || [ "$what" = all ]; then       # Tables 4-5, Fig. 2: TaintBench (8 apps), sink and flow level
  run $QWEN --benchmark taintbench --mode wholeapp --workers 1 --run tb-qwen-wholeapp
  run $QWEN --benchmark taintbench --mode persink  --workers 6 --run tb-qwen-persink
  run $DS   --benchmark taintbench --mode wholeapp --workers 1 --run tb-deepseek-wholeapp --max-tokens 131072
  run $DS   --benchmark taintbench --mode persink  --workers 6 --run tb-deepseek-persink  --max-tokens 32768
  run $QWEN --benchmark taintbench --mode wholeapp --workers 1 --run tb-qwen-wholeapp-flows     --flows
  run $QWEN --benchmark taintbench --mode persink  --workers 6 --run tb-qwen-persink-flows      --flows --max-tokens 32768
  run $DS   --benchmark taintbench --mode wholeapp --workers 1 --run tb-deepseek-wholeapp-flows --flows --max-tokens 131072
  run $DS   --benchmark taintbench --mode persink  --workers 6 --run tb-deepseek-persink-flows  --flows --max-tokens 32768
  for r in tb-qwen-wholeapp-flows tb-qwen-persink-flows tb-deepseek-wholeapp-flows tb-deepseek-persink-flows; do
    $PY -m evaluation.score_taintbench results/neuro/$r --flows
  done
fi
