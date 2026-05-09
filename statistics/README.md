# Statistics Pipeline

This folder contains an independent and modular statistics pipeline.

## Single Entrypoint

- `run_statistics_pipeline.py` is the only file you need to run.

## Internal Structure

- `runner.py`: CLI parsing and mode orchestration (`--neo4j-only`, `--new`, `--history`).
- `collectors.py`: data collection logic from current pipeline and Neo4j v1.
- `reports.py`: markdown rendering and history comparison report generation.
- `common.py`: shared utilities (versioning, table rendering, file IO helpers).

## Modes

### 1) Neo4j-Only Baseline (`--neo4j-only`)

Create Neo4j snapshot report only. By rule, version `v1` is reserved for this baseline.

```powershell
python statistics/run_statistics_pipeline.py --neo4j-only --name "baseline" --neo4j-password "<password>" --neo4j-database "multigraph"
```

### 2) New Versioned Statistics (`--new`)

Run full extraction (`read log -> parse entity -> create triplet`) and generate versioned outputs.

```powershell
python statistics/run_statistics_pipeline.py --new --dataset-folder "D:\Capstone Project & NCKH\attack_data\datasets\attack_techniques" --name "run2" --neo4j-password "<password>" --neo4j-database "multigraph"
```

Outputs are saved in `statistics/output`:

- `stat_v<version>[_name].md`
- `stat_v<version>[_name].json`

### 3) History Report (`--history`)

Build a history markdown report from all existing `stat_v*.json` files.

```powershell
python statistics/run_statistics_pipeline.py --history
```

Output:

- `history_from_v1_v<latest_version>.md`

The history filename is deterministic by version range and will be overwritten on re-run if no new version is added.

## Notes

- Markdown is the main report format for rendering.
- JSON is saved as sidecar for robust version comparison.
- Neo4j v1 snapshot is queried by default in `--new`. Use `--skip-neo4j` to disable.
- `--new` requires that `v1` already exists from `--neo4j-only`.
