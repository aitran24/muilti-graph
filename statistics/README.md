# Statistics Pipeline

This folder contains an independent and modular statistics pipeline.

## Single Entrypoint

- `run_statistics_pipeline.py` is the only file you need to run.

## Internal Structure

- `runner.py`: CLI parsing and mode orchestration (`--neo4j-only`, `--new`, `--from-trees`, `--history`).
- `collectors.py`: data collection logic — `CurrentPipelineStatsCollector` (raw logs), `CleanAttackTreeStatsCollector` (pre-built trees), `Neo4jV1StatsCollector` (Neo4j query).
- `reports.py`: markdown rendering and history comparison report generation.
- `common.py`: shared utilities (versioning, table rendering, file IO helpers).

## Modes

### 1) From Pre-Built Trees (`--from-trees`) ⚡ Recommended

Reads pre-built `clean_attack_tree/*.json` files directly — **no log re-parsing, no Neo4j needed**.
Outputs include `core_effect_stats` (coverage, patterns per technique).

```powershell
python statistics/run_statistics_pipeline.py --from-trees `
  --tree-folder "D:\NCKH_new\muilti-graph\inspect_log_gui\clean_attack_tree" `
  --name "trees_run"
```

### 2) New Versioned Statistics from Raw Logs (`--new`)

Re-parses all Sysmon log files (slow — ~2.9M log entries). Use `--skip-neo4j` to skip Neo4j queries.

```powershell
python statistics/run_statistics_pipeline.py --new `
  --dataset-folder "D:\NCKH_new\attack_data_full\datasets\attack_techniques" `
  --skip-neo4j `
  --name "run3"
```

### 3) Neo4j-Only Baseline (`--neo4j-only`)

Create Neo4j snapshot report only. Requires a running Neo4j instance.

```powershell
python statistics/run_statistics_pipeline.py --neo4j-only --name "baseline" `
  --neo4j-password "<password>" --neo4j-database "multigraph"
```

### 4) History Report (`--history`)

Build a history markdown report from all existing `stat_v*.json` files.

```powershell
python statistics/run_statistics_pipeline.py --history
```

Output: `history_from_v1_v<latest_version>.md`

## Output Files (in `statistics/output/`)

- `stat_v<version>[_name].json` — machine-readable stats payload
- `stat_v<version>[_name].md` — human-readable markdown report
- `history_from_v1_v<N>.md` — version comparison history

## Notes

- `--from-trees` is the fastest mode and does **not** require Neo4j or raw log files.
- `--new` requires `--skip-neo4j` if Neo4j is not running.
- `--new` no longer requires a v1 Neo4j baseline to exist first.
- `core_effect_stats` block is present in `--from-trees` output only.
- JSON is saved as sidecar for robust version comparison across runs.
