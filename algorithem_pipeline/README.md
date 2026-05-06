# algorithem_pipeline

A standalone matching pipeline for Sysmon graph structures with multiple graph/tree matching algorithms, benchmark comparison, and visualization UI.

## What this folder contains

- `algorithem_pipeline/algorithms/`
  - `baseline_exact.py`: exact subtree matching baseline.
  - `core_approximate.py`: edit-distance style approximate matching.
  - `scale_multipattern.py`: multi-pattern hash matching in one pass.
  - `structure_adaptive.py`: adaptive strategy for sparse/dense graphs.
  - `behavioral_anchor_fusion.py`: hybrid behavioral/graph matcher using malicious-pattern anchors.
- `algorithem_pipeline/io/`: graph loading and graph-to-forest adaptation.
- `algorithem_pipeline/evaluation/`: runtime and top-1 accuracy benchmarking.
- `algorithem_pipeline/service/matcher_service.py`: orchestration service.
- `algorithem_pipeline/http_server.py`: built-in HTTP API server.
- `frontend/`: independent UI for list/highlight/prune behavior.
- `docs/algorithms.md`: algorithm details.
- `docs/algorithm_design_report.md`: detailed algorithm design, behavior, and tuning notes.

## Data sources

By default the service reads:

- Pattern attack trees: `inspect_log_gui/clean_attack_tree/*.json`
- Offline raw Sysmon dataset: `../attack_data/datasets/attack_techniques/<technique>/**/*.log|txt|xml`

Offline processing path is now:

- select a technique in the UI,
- parse its original raw Sysmon log files,
- map entities and create triplets with the same parser/triplet flow used by the existing pipeline,
- build the graph in stream/raw-compatible shape,
- run matching against `clean_attack_tree` patterns.

Resulting graph schema is aligned to existing stream/raw style:

- `nodes`: list of node objects with `id`, `label`, `type`, `group`, `properties`
- `edges`: list of edge objects with `source|from`, `target|to`, `label|type`

## Run

From repository root:

```powershell
.\venv\Scripts\python.exe algorithem_pipeline\run.py
```

Open:

- `http://127.0.0.1:9095/`

## API quick reference

- `GET /api/targets`: list available offline techniques from the raw dataset.
- `GET /api/graph?technique=<Txxxx>`: build and fetch raw target graph payload for that technique.
- `POST /api/match`: run selected algorithms.

Example request body:

```json
{
  "technique": "T1003",
  "algorithms": [
    "baseline_exact",
    "core_approximate",
    "scale_multipattern",
    "structure_adaptive"
  ],
  "top_k": 15
}
```

## Notes

- This mode is offline and does not require realtime stream polling.
- Input is no longer a prebuilt graph file from `test_log`; graph is built on demand from the original raw logs of the selected technique.
- Each algorithm is isolated in a separate file for independent tuning and comparison.
