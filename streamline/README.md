# Streamline Realtime Sysmon Pipeline

`streamline` is a new realtime pipeline that:

- Streams Sysmon events from Windows Event Log (`Microsoft-Windows-Sysmon/Operational`)
- Reuses existing parser/triplet logic from the codebase
- Updates graph nodes/edges live through WebSocket and serves built-in UIs over HTTP
- Can install/update Sysmon and apply a full config profile

## Reused Components

- `log_parsers.sysmon_parser.SysmonLogParser`
- `triplet_creator.triplet_creator.SysmonTripletCreator`
- `inspect_log_gui.backend.pipeline.TechniqueGraphPipeline` static helpers:
  - `_entity_to_node`
  - `_triplet_to_edge`
  - `_upsert_node`
  - `_build_technique_node`
  - `_build_root_edge`

## Folder Structure

- `streamline/backend`: realtime pipeline, event source, websocket server, installer
- `streamline/frontend`: modular UI (`main.js`, `graphView.js`, `store.js`, `wsClient.js`)
- `streamline/assets/sysmon-full.xml`: full Sysmon configuration profile
- `streamline/assets/sysmon-bin`: local Sysmon package and binaries (`Sysmon64.exe`, `Sysmon.exe`)

## Run

From repository root:

```powershell
.\venv\Scripts\python.exe -m pip install -r streamline\requirements.txt
.\streamline\start_streamline.ps1
```

If you need to install/update Sysmon during startup (Administrator shell):

```powershell
.\streamline\start_streamline.ps1 -InstallSysmon
```

Equivalent direct Python command (defaults already applied):

```powershell
.\venv\Scripts\python.exe streamline\run_streamline.py
```

Or run the bundled PowerShell installer (Admin required):

```powershell
powershell -ExecutionPolicy Bypass -File streamline\install_sysmon_full.ps1
```

Notes:

- `--install-sysmon` requires **Administrator** privileges.
- Startup logs print all default URLs directly in CMD:
  - `ws://127.0.0.1:8877`
  - `http://127.0.0.1:8080/index.html`
  - `http://127.0.0.1:8080/match/index.html`
  - `http://127.0.0.1:8081/index.html`
- If you do not want auto-open UI:

```powershell
.\venv\Scripts\python.exe streamline\run_streamline.py --no-open-ui
```

## Optional Arguments

```text
--host 127.0.0.1
--port 8877
--channel Microsoft-Windows-Sysmon/Operational
--poll-interval 1.0
--batch-size 128
--bootstrap-count 200
--technique LIVE_SYSMON
--sysmon-binary <custom path to Sysmon64.exe>
--sysmon-config <custom path to xml config>
```

## UI Behavior

- Auto-adds newly observed nodes and edges in realtime.
- Uses delta updates (`added_nodes`, `updated_nodes`, `added_edges`, `removed_edge_ids`) for fast rendering.
- Keeps HAS_ROOT links from synthetic technique node to every current root process/component.

## Sysmon Profile

- Bundled config is intentionally non-strict and full-open: each rule type is set to `onmatch="include"` with no child filters.
- You can use bundled binaries directly from `streamline/assets/sysmon-bin`.

## Troubleshooting

If UI shows only one node (`LIVE_SYSMON`) and no other nodes:

1. Sysmon channel is missing or inaccessible.
2. Sysmon service is not installed/running with admin privileges.
3. Channel currently has only non-mappable events (for example EventID 4/16 right after setup).

Runtime status now prints top EventIDs per poll when events are received but no graph updates are created.
If you see mostly `4`/`16`, this is expected right after install/config update.

Check channel:

```powershell
wevtutil gli Microsoft-Windows-Sysmon/Operational
```

Fix quickly (run as Administrator):

```powershell
powershell -ExecutionPolicy Bypass -File streamline\install_sysmon_full.ps1
```

Then restart backend:

```powershell
.\venv\Scripts\python.exe streamline\run_streamline.py --no-open-ui
```

Generate a few events to populate graph nodes (EventID 1/3/11 are commonly mapped):

```powershell
Start-Process notepad
ipconfig /all
dir $env:TEMP
```

Inspect live data compatibility quickly (run in Administrator shell):

```powershell
.\venv\Scripts\python.exe streamline\debug_live_probe.py --count 200 --top 10
```

This prints: `records`, `parsed`, `mapped`, `triplets`, and top EventID buckets.

If installer previously failed with `installExit=1242` (service already registered):

- This is handled now: installer updates config with `-c` when service exists.
- Re-run the same installer command from an Administrator PowerShell window.

If backend shows `Access is denied` when reading Sysmon channel:

- Start backend in an Administrator shell.
- Or keep backend in current shell and use an account that has access to
  `Microsoft-Windows-Sysmon/Operational`.

If UI does not open after run command:

- Do not use `--no-open-ui` when you expect auto-open behavior.
- With `--no-open-ui`, open `streamline/frontend/index.html` manually.

If startup fails with `ws://127.0.0.1:8877 is already in use`:

- Another backend process is already running on that port.
- Stop old process or run with a different port, for example:

```powershell
.\venv\Scripts\python.exe streamline\run_streamline.py --no-open-ui --port 8877
```

If you run backend on a custom port, frontend can follow it without code change:

- `index.html?port=9001` to use `ws://127.0.0.1:9001`
- `index.html?host=192.168.1.10&port=9001`
- `index.html?ws=ws://127.0.0.1:9001` for full explicit URL
