from __future__ import annotations

from pathlib import Path

from ..http_server import run_http_server


def create_app(repo_root: Path | None = None):
    root = repo_root or Path(__file__).resolve().parents[3]

    class _CompatApp:
        def run(self, host: str = "127.0.0.1", port: int = 9095, debug: bool = False) -> None:
            _ = debug
            run_http_server(repo_root=root, host=host, port=port)

    return _CompatApp()
