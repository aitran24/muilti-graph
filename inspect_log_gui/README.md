# Inspect Log GUI

A lightweight web app for inspecting per-technique attack graphs with client-side malicious pattern filtering.

## Features

- List techniques from dataset subfolders in `D:\Capstone Project & NCKH\attack_data\datasets\attack_techniques`
- Discover only Sysmon logs using the original pipeline rule: filename contains `sysmon` and extension is `.log`, `.txt`, or `.xml`
- Build graph from existing pipeline (parse -> merge -> triplet), without writing Neo4j
- Render interactive graph (zoom/pan + node click inspect)
- Add/remove suspicious patterns in UI
- Client-side filtering: remove matched node and all descendants in technique subtree
- Persist patterns to `inspect_log_gui/data/<technique>_malcious_config.json`

## Project Layout

- `inspect_log_gui/backend/`
  - Flask API and graph processing pipeline
- `inspect_log_gui/frontend/`
  - Static HTML/CSS/JS UI with vis-network
- `D:\Capstone Project & NCKH\attack_data\datasets\attack_techniques`
  - Dataset root used by backend
  - Each technique is a subfolder name
  - Backend recursively reads only Sysmon logs inside each technique folder
- `inspect_log_gui/data/`
  - Auto-created by backend to store pattern config files

## Requirements

- Python 3.10+
- pip packages:
  - `flask`
  - `flask-cors`

Install dependencies:

```bash
pip install flask flask-cors
```

## Run

From the repository root:

```bash
python inspect_log_gui/backend/app.py
```

Then open:

- `http://127.0.0.1:5000`

## API Summary

- `GET /api/techniques`
- `GET /api/graph?technique=<name>`
- `GET /api/patterns?technique=<name>`
- `POST /api/patterns` body: `{ "technique": "...", "patterns": ["..."] }`
- `POST /api/patterns/append` body: `{ "technique": "...", "new_pattern": "..." }`

## Notes

- Filtering is done only in frontend JavaScript.
- Backend does not filter graph content and does not connect/write to Neo4j.
- To add a technique, create a subfolder in the dataset path and place Sysmon logs whose filenames contain `sysmon`.
