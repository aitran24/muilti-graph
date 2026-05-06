from __future__ import annotations

import json
from dataclasses import asdict
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .service.matcher_service import MatcherService


class PipelineHttpHandler(SimpleHTTPRequestHandler):
    service: MatcherService
    frontend_dir: Path

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(self.frontend_dir), **kwargs)

    def log_message(self, format: str, *args):  # noqa: A003
        return

    def _json_response(self, payload: dict, status: int = HTTPStatus.OK) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/api/health":
            return self._json_response({"status": "ok"})

        if path == "/api/targets":
            return self._json_response({"targets": self.service.list_targets()})

        if path == "/api/techniques":
            return self._json_response({"techniques": self.service.list_techniques()})

        if path == "/api/graph":
            technique = (query.get("technique", [""])[0] or "").strip()
            if not technique:
                return self._json_response(
                    {"error": "Query parameter 'technique' is required."},
                    status=HTTPStatus.BAD_REQUEST,
                )
            try:
                graph = self.service.load_target_graph(technique)
            except FileNotFoundError:
                return self._json_response(
                    {"error": f"Technique dataset not found: {technique}"},
                    status=HTTPStatus.NOT_FOUND,
                )
            except Exception as exc:  # noqa: BLE001
                return self._json_response({"error": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return self._json_response(graph.raw_payload)

        if path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/api/match":
            return self._json_response({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)

        try:
            content_len = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(content_len) if content_len > 0 else b"{}"
            payload = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            return self._json_response({"error": "Invalid JSON payload."}, status=HTTPStatus.BAD_REQUEST)

        target_name = str(payload.get("technique", "")).strip()
        algorithm_names = payload.get("algorithms") or None
        top_k = int(payload.get("top_k") or 20)

        if not target_name:
            return self._json_response({"error": "Field 'technique' is required."}, status=HTTPStatus.BAD_REQUEST)

        if algorithm_names is not None and not isinstance(algorithm_names, list):
            return self._json_response(
                {"error": "Field 'algorithms' must be a list of names."},
                status=HTTPStatus.BAD_REQUEST,
            )

        try:
            result = self.service.run(target_name=target_name, algorithm_names=algorithm_names, top_k=top_k)
        except FileNotFoundError:
            return self._json_response(
                {"error": f"Technique dataset not found: {target_name}"},
                status=HTTPStatus.NOT_FOUND,
            )
        except Exception as exc:  # noqa: BLE001
            return self._json_response({"error": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

        return self._json_response(asdict(result))


def run_http_server(repo_root: Path, host: str = "127.0.0.1", port: int = 9095) -> None:
    frontend_dir = repo_root / "algorithem_pipeline" / "frontend"
    service = MatcherService(repo_root=repo_root)

    PipelineHttpHandler.frontend_dir = frontend_dir
    PipelineHttpHandler.service = service

    server = ThreadingHTTPServer((host, port), PipelineHttpHandler)
    print(f"Algorithm pipeline server running at http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
