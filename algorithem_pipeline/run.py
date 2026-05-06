from __future__ import annotations

from pathlib import Path

from algorithem_pipeline.http_server import run_http_server


if __name__ == "__main__":
    repo_root = Path(__file__).resolve().parents[1]
    run_http_server(repo_root=repo_root, host="127.0.0.1", port=9095)
