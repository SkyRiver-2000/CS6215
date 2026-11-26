# Where Do Symbolic Constraints Help an LLM Taint Analyzer?

Code, data and raw results for the CS6215 (NUS, Fall 2026) project report *"Where Do Symbolic Constraints Help an LLM
Taint Analyzer? A Comparative Study against FlowDroid"*.

The project has two parts:

1. **Baseline.** An exact reproduction of FlowDroid's DroidBench 1.0 evaluation (PLDI 2014, Table 1) with the
   *original* 2014 artifact: all 35 per-app TP/FP/FN rows match the paper.
2. **Neuro-symbolic analyzer.** A symbolic front end, built on the Soot version inside that artifact, exports the
   app's Jimple, enumerates candidate sources and sinks with FlowDroid's own specification, and builds symbolic indices.
   An LLM then decides which candidate sinks leak. There are two inference strategies:
   - **WholeApp**: one prompt per app containing all application code and the numbered candidates.
   - **PerSink**: one tool-using agent per candidate sink. The agent explores the program backwards over the
     front-end indices, and every reported leak comes with an evidence path that a symbolic checker validates.

All tools report the same unit as FlowDroid's native output (enclosing method + exact Jimple sink statement, and
source–sink pairs at flow level) and are scored by the same scripts.

## Main results

| Benchmark | Metric | FlowDroid | WholeApp | PerSink |
|---|---|---|---|---|
| DroidBench 1.0 (35 apps, 28 leaks) | TP/FP/FN | 26/4/2 | 27/0/1 | 27/0/1 |
| DroidBench 3.0 subset (39 apps FlowDroid completes) | TP/FP/FN | 13/8/19 | 31/3/1 | 31/5/1 |
| TaintBench (8 apps), sink level, Qwen | TP/FP/FN/unlisted | 3/0/16/27 | 19/2/0/63 | 19/2/0/58 |
| TaintBench, flow level, Qwen | recall | 10.8% | 89.2% | 67.6% |
| TaintBench, flow level, DeepSeek | recall | 10.8% | 97.3% | 81.1% |

The LLM is Qwen3.8-27B unless stated; DeepSeek v4.1 Flash is used as a stronger model on TaintBench. On TaintBench,
PerSink finds the same expected sinks as WholeApp at 10–19× the input tokens and recovers fewer expected flows; see
the report for the full analysis, cost and ablation.

## Repository layout

```
analyzer/                 the neuro-symbolic analyzer (Python package)
  frontend/               symbolic front end
    ExportFacts.java        Soot exporter (Jimple, invokes, fields, line tags) built on the original artifact
    axml.py                 binary AndroidManifest/layout parser
    export.py               front-end driver: facts for every APK of a benchmark
    program.py              facts model: candidates, sources, call graph, field index, reachability
    rename.py               identifier renaming for the memorisation experiment
  prompts.py              system prompts, including the semantic rules
  tools.py                the five agent tools (get_method, find_callers, field_accesses, ...)
  checker.py              PerSink's evidence-path checker
  strategies.py           WholeApp and PerSink
  llm.py                  OpenRouter client with token accounting
  resultfile.py           per-app result files (<case>.tsv) shared with the baseline and scorers
  benchmarks.py           repository paths and benchmark definitions
  run.py                  command line: run a strategy on a benchmark and score it
baseline/                 the original FlowDroid artifact (PLDI 2014)
  OriginalFlowDroid.java    calls the artifact's own analysis helper and exports its native results
  run.py                    run FlowDroid on a benchmark
  audit_pldi2014.py         check the artifact and DroidBench 1.0 against their Git hashes
evaluation/               scoring and ground truth
  score_pldi2014.py         DroidBench 1.0 (recovered Table 1 labels)
  score_sinks.py            DroidBench 3.0 subset
  score_taintbench.py       TaintBench, sink or flow level
  report_all.py             ReportAll reference
  replay_checker.py         offline replay with the final checker (no LLM calls)
  gold/                     construction of the DroidBench 3.0 and TaintBench labels
config/                   benchmark selections and gold labels
scripts/                  setup and experiment drivers (shell)
results.tar.gz            outputs of every run reported in the paper (extract to results/)
```

All Python entry points are modules run from the repository root (`python -m analyzer.run ...`). Internally,
WholeApp is called `v0` and PerSink `v1`; these names appear in `run.json` files and in the prompts. The code
follows PEP 8 (99-character lines, `black`/`isort`/`flake8` settings in `pyproject.toml` and `setup.cfg`).

## Setup

Requirements: Python 3.9+, Git, curl. The setup scripts download a pinned **macOS Apple Silicon** Java 8 (Zulu
8.0.514); on other platforms, install a Java 8 JDK at `tools/jdk8/Contents/Home` or adjust the path in the scripts.

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
bash scripts/setup_pldi2014.sh      # DroidBench 1.0, original FlowDroid artifact (PLDI 2014), Java 8, API 17 stubs
bash scripts/setup_benchmarks.sh    # DroidBench 3.0 (pinned commit), 8 TaintBench apps + findings + spec
```

### LLM access

All LLM calls go through [OpenRouter](https://openrouter.ai) (OpenAI-compatible API, `analyzer/llm.py`). Create an API
key at <https://openrouter.ai/keys> and export it before any LLM run:

```bash
export OPENROUTER_API_KEY=sk-or-...
```

Models are selected with `--model` and an OpenRouter model id. The paper uses:

| Model | OpenRouter id | Used for |
|---|---|---|
| Qwen3.8-27B | `qwen/qwen3.8-27b` (default) | all benchmarks |
| DeepSeek v4.1 Flash | `deepseek/deepseek-v4.1-flash-1017` (pinned snapshot) | TaintBench |

All runs use temperature 0. Rescoring the published results needs no key. Some DroidBench and TaintBench runs
were made with the same Qwen3.8-27B model served by a course endpoint; their `run.json` records the provider.

## Reproducing the results

### Experiment outputs

The outputs of every run reported in the paper (per-app result files, full model transcripts, `run.json`
with token usage, scores, and the front-end facts) are included as `results.tar.gz` in the repository root
(13 MB, 1,691 files). Extract it to obtain `results/`:

```bash
tar xzf results.tar.gz        # creates results/
```

With `results/` in place, the scorers recompute every table without network access or API key (see "Scoring an
existing results folder" below). The commands below also write their outputs to `results/`.

**FlowDroid baseline**

```bash
python3 -m baseline.run pldi2014 && python3 -m evaluation.score_pldi2014   # DroidBench 1.0 (paper's Table 1)
python3 -m baseline.run droidbench3                                        # DroidBench 3.0 subset
python3 -m baseline.run taintbench                                         # TaintBench
BASELINE_XMX=10g python3 -m baseline.run taintbench proxy_samp             # memory retry (fails again)
```

FlowDroid's console output goes to `logs/` (not part of the results).

**Symbolic front end** (facts are included in the results archive, `results/neuro/facts/`)

```bash
python3 -m analyzer.frontend.export --benchmark pldi2014      # also: droidbench3, taintbench
python3 -m analyzer.frontend.rename results/neuro/facts/pldi2014 results/neuro/facts/pldi2014-renamed
```

**LLM runs** (each run scores itself when it finishes)

```bash
bash scripts/reproduce_llm.sh            # all paper configurations; or: db1 | db3 | tb
bash scripts/run_ablation.sh             # ablation (Table 6)
python3 -m evaluation.report_all         # ReportAll reference rows on TaintBench
```

A single run, e.g. PerSink on DroidBench 1.0:

```bash
.venv/bin/python -m analyzer.run --benchmark pldi2014 --mode persink --model qwen/qwen3.8-27b --run my-run
```

Options: `--mode wholeapp|persink|persink-nochecker`, `--flows` (flow-level output), `--sinks extended` (adds
`setResult` as a sink), `--ablate no-annotations|strict-checker|veto-prune`, `--only <case>...`, `--resume`.

**Scoring an existing results folder**

```bash
python3 -m evaluation.score_pldi2014 results/neuro/db1-qwen-persink                   # DroidBench 1.0
python3 -m evaluation.score_sinks config/droidbench3-gold.json results/neuro/db3-qwen-persink
python3 -m evaluation.score_taintbench results/neuro/tb-qwen-persink                  # sink level
python3 -m evaluation.score_taintbench results/neuro/tb-qwen-persink-flows --flows    # flow level
```

**Ground truth** (shipped in `config/`): `python3 -m evaluation.gold.make_droidbench3` and
`python3 -m evaluation.gold.make_taintbench` rebuild the label files from the facts and the benchmark sources.

## Contents of the results archive

| Paper | Folder(s) |
|---|---|
| Table 1 (FlowDroid errors), Table 2 FlowDroid | `results/pldi2014/` |
| Table 2 (DroidBench 1.0) | `results/neuro/db1-qwen-{wholeapp,persink}`, `-renamed`, `db1-qwen-persink-setresult` |
| Table 3 (DroidBench 3.0) | `results/droidbench3-baseline/`, `results/neuro/db3-qwen-{wholeapp,persink}` |
| Table 4, sink level | `results/taintbench-baseline/`, `results/neuro/tb-reportall`, `tb-{qwen,deepseek}-{wholeapp,persink}` |
| Table 4, flow level | the same with `--flows` for the baseline and ReportAll; `tb-*-flows` for the LLM runs |
| Table 5, Fig. 2 (cost) | `run.json` of the TaintBench runs (`usage`) |
| RQ2, 262k-token context | `results/neuro/tb-qwen-wholeapp-262k` |
| Table 6 (ablation) | `results/neuro/ablation/db3-*`, repeated DroidBench 1.0 runs in `ablation/db1-repeats/` |

Each LLM run folder contains, per app, `<case>.tsv` (scorer input; statements Base64-encoded) and
`<case>.trace.json` (the full transcripts: prompts, tool calls, answers, checker results and final decisions), plus
`run.json` (model, provider, token usage, timings) and the scorer outputs (`summary.json` and a per-app table).

Notes:
- Table 3 restricts the 46-app subset to the 39 apps for which FlowDroid produces a result (the 7 failures are listed
  in `results/droidbench3-baseline/runtime.json`); `per-case.csv` in each folder gives the per-app counts.
- Six PerSink runs were made with an earlier checker that matched statements exactly. Their decisions under the final
  checker (which tolerates whitespace and empty `()`) were obtained by an offline replay without new LLM calls
  (`evaluation/replay_checker.py`) and are stored in `replay-v1.3.1/` inside those folders. The replay changes no Qwen
  decision; for DeepSeek it recovers one expected sink (`tb-deepseek-persink/replay-v1.3.1` is the reported result).
- Flow-level TaintBench scoring counts each distinct (source statement, sink statement) pair once: several TaintBench
  labels collapse to the same pair, which leaves 37 expected and 5 negative flows.

## Baseline and benchmarks (upstream sources)

- FlowDroid PLDI 2014 paper: <https://www.rasthofer.info/publications/paper/PLDI2014-FlowDroid.pdf>
- Original FlowDroid artifact (`PLDI14 Distribution/FlowDroid.zip`, commit `08077a2`), recovered from a fork that
  preserves the old repository history:
  <https://github.com/lilicoding/soot-infoflow-android/commit/08077a294c31004863d63c1e7bbaa060399fa4dd>
- DroidBench 1.0 (tag `DroidBench_1.0`) and DroidBench 3.0 (commit `a57fa6f`):
  <https://github.com/secure-software-engineering/DroidBench>
- TaintBench: <https://github.com/TaintBench/TaintBench> (one repository per app, APK in its `APK` release,
  ground truth in `<app>_findings.json`)

`scripts/setup_pldi2014.sh` and `scripts/setup_benchmarks.sh` fetch exactly these versions; `baseline/audit_pldi2014.py`
checks the artifact and DroidBench 1.0 against their Git hashes.

## Third-party components

DroidBench, TaintBench and the FlowDroid PLDI 2014 artifact are downloaded by the setup scripts and are not part of
this repository; they keep their own licenses (FlowDroid: LGPL-2.1).
