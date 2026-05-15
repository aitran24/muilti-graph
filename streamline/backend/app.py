from __future__ import annotations

import argparse
import asyncio
import contextlib
from copy import deepcopy
import functools
import http.server
import json
import mimetypes
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from streamline.backend.config import StreamlineConfig
from streamline.backend.live_matcher import LiveMatchEngine
from streamline.backend.snapshot_archive import SnapshotArchive
from streamline.backend.streamer import LiveStreamPipeline
from streamline.backend.sysmon_installer import SysmonInstaller
from streamline.backend.ws_server import WebSocketHub
from globals.logger_manager import LoggerManager

try:
    from algorithem_pipeline.algorithem_pipeline.service.matcher_service import MatcherService
except Exception:  # noqa: BLE001
    MatcherService = None


class StreamlineService:
    def __init__(self, config: StreamlineConfig) -> None:
        self.config = config
        self.pipeline = LiveStreamPipeline(config)
        self.match_engine = LiveMatchEngine(
            repo_root=config.repo_root,
            algorithm_names=config.match_algorithms,
            top_k=config.match_top_k,
        )
        self.installer = SysmonInstaller(config.sysmon_assets_dir)
        self.snapshot_archive = SnapshotArchive(config.snapshot_storage_dir)
        self.hub = WebSocketHub(
            host=config.host,
            port=config.port,
            snapshot_provider=self.pipeline.snapshot,
            message_handler=self._handle_client_message,
        )
        self._ui_http_server: http.server.ThreadingHTTPServer | None = None
        self._ui_http_thread: threading.Thread | None = None
        self._snapshot_http_server: http.server.ThreadingHTTPServer | None = None
        self._snapshot_http_thread: threading.Thread | None = None
        self._ui_url: str = ""
        self._match_ui_url: str = ""
        self._snapshot_ui_url: str = ""

        self._match_event: asyncio.Event | None = None
        self._match_task: asyncio.Task[None] | None = None
        self._pending_match_snapshot: dict[str, Any] | None = None
        self._pending_match_revision = 0

        self._offline_lock = threading.Lock()
        self._offline_match_service = None
        self._offline_match_engine: LiveMatchEngine | None = None
        self._offline_public_payload: dict[str, Any] | None = None
        self._offline_pruned_graph: dict[str, Any] | None = None
        self._offline_target = ""
        self._offline_graph_revision = 0

        if MatcherService is not None:
            try:
                self._offline_match_service = MatcherService(repo_root=config.repo_root)
            except Exception as exc:  # noqa: BLE001
                self._offline_match_service = None
                self._log_console(
                    f"Offline matcher initialization failed: {exc}",
                    level="warn",
                )

    class _FrontendRequestHandler(http.server.SimpleHTTPRequestHandler):
        service: "StreamlineService | None" = None

        def log_message(self, format: str, *args: object) -> None:  # noqa: A003
            return

        def end_headers(self) -> None:  # noqa: D401
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            super().end_headers()

        def _send_json(self, payload: dict[str, Any], status_code: int = 200) -> None:
            raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()
            self.wfile.write(raw)

        def _read_json_body(self) -> tuple[dict[str, Any] | None, str | None]:
            try:
                content_len = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return None, "Invalid Content-Length header."

            raw = self.rfile.read(content_len) if content_len > 0 else b"{}"
            if not raw.strip():
                return {}, None

            try:
                payload = json.loads(raw.decode("utf-8"))
            except Exception as exc:  # noqa: BLE001
                return None, f"Invalid JSON payload: {exc}"

            if not isinstance(payload, dict):
                return None, "JSON payload must be an object."

            return payload, None

        def _require_service(self) -> "StreamlineService | None":
            service = self.service
            if service is None:
                self._send_json({"error": "Streamline service is unavailable."}, status_code=503)
                return None
            return service

        def do_OPTIONS(self) -> None:  # noqa: N802
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path
            service = self._require_service()
            if service is None:
                return

            if path == "/api/health":
                available, reason = service._offline_match_is_available()
                return self._send_json(
                    {
                        "status": "ok",
                        "offline_available": available,
                        "offline_reason": reason,
                    }
                )

            if path == "/api/offline/targets":
                try:
                    targets = service._offline_list_targets()
                except Exception as exc:  # noqa: BLE001
                    return self._send_json({"error": str(exc)}, status_code=503)
                return self._send_json({"targets": targets})

            if path == "/api/offline/state":
                payload = service._offline_get_state()
                if payload is None:
                    return self._send_json(
                        {"error": "Offline matching state is not ready yet."},
                        status_code=404,
                    )
                return self._send_json(payload)

            if path == "/api/offline/context":
                query = parse_qs(parsed.query)
                key = str((query.get("key") or [""])[0]).strip()
                if not key:
                    return self._send_json({"error": "Query parameter 'key' is required."}, status_code=400)

                try:
                    payload = service._offline_get_context(key)
                except Exception as exc:  # noqa: BLE001
                    return self._send_json({"error": str(exc)}, status_code=500)

                if payload is None:
                    return self._send_json(
                        {"error": f"Offline match context not found for key: {key}"},
                        status_code=404,
                    )
                return self._send_json(payload)

            if path in {"", "/"}:
                self.path = "/index.html"

            return super().do_GET()

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path
            service = self._require_service()
            if service is None:
                return

            if path == "/api/offline/run":
                body, error = self._read_json_body()
                if error:
                    return self._send_json({"error": error}, status_code=400)

                technique = str((body or {}).get("technique") or "").strip()
                if not technique:
                    return self._send_json({"error": "Field 'technique' is required."}, status_code=400)

                try:
                    payload = service._offline_run_match(technique)
                except FileNotFoundError:
                    return self._send_json(
                        {"error": f"Technique dataset not found: {technique}"},
                        status_code=404,
                    )
                except Exception as exc:  # noqa: BLE001
                    return self._send_json({"error": str(exc)}, status_code=500)

                return self._send_json(payload)

            if path == "/api/offline/snapshot":
                body, error = self._read_json_body()
                if error:
                    return self._send_json({"error": error}, status_code=400)

                key = str((body or {}).get("key") or "").strip()
                if not key:
                    return self._send_json({"error": "Field 'key' is required."}, status_code=400)

                try:
                    payload = service._offline_create_snapshot_for_match(key)
                except Exception as exc:  # noqa: BLE001
                    return self._send_json({"error": str(exc)}, status_code=500)

                if payload is None:
                    return self._send_json(
                        {"error": f"Cannot create offline snapshot: unknown match key {key}"},
                        status_code=404,
                    )

                return self._send_json(payload)

            return self._send_json({"error": "Not found"}, status_code=404)

    class _SnapshotRequestHandler(http.server.SimpleHTTPRequestHandler):
        archive: SnapshotArchive | None = None
        match_engine: LiveMatchEngine | None = None
        snapshot_provider: Any | None = None

        def log_message(self, format: str, *args: object) -> None:  # noqa: A003
            return

        def end_headers(self) -> None:  # noqa: D401
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            super().end_headers()

        def _send_json(self, payload: dict[str, Any], status_code: int = 200) -> None:
            raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET,OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()
            self.wfile.write(raw)

        def _send_static_file(self, file_path: Path) -> None:
            if not file_path.exists() or not file_path.is_file():
                return self._send_json({"error": "Static asset not found."}, status_code=404)

            raw = file_path.read_bytes()
            content_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_OPTIONS(self) -> None:  # noqa: N802
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET,OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path

            if path.startswith("/streamline-frontend/"):
                engine = self.match_engine
                if engine is None:
                    return self._send_json({"error": "Shared frontend assets unavailable."}, status_code=503)

                shared_root = (engine.repo_root / "streamline" / "frontend").resolve()
                relative_path = path.removeprefix("/streamline-frontend/").lstrip("/")
                file_path = (shared_root / relative_path).resolve()
                try:
                    file_path.relative_to(shared_root)
                except ValueError:
                    return self._send_json({"error": "Invalid static asset path."}, status_code=400)

                return self._send_static_file(file_path)

            if path == "/api/health":
                return self._send_json({"status": "ok"})

            if path == "/api/snapshots":
                archive = self.archive
                if archive is None:
                    return self._send_json({"error": "Snapshot archive unavailable."}, status_code=503)

                query = parse_qs(parsed.query)
                try:
                    limit = max(1, int((query.get("limit") or ["200"])[0]))
                except ValueError:
                    limit = 200

                return self._send_json({"snapshots": archive.list_snapshots(limit=limit)})

            if path.startswith("/api/snapshots/"):
                archive = self.archive
                if archive is None:
                    return self._send_json({"error": "Snapshot archive unavailable."}, status_code=503)

                snapshot_id = path.split("/", 3)[-1].strip()
                if not snapshot_id:
                    return self._send_json({"error": "Snapshot id is required."}, status_code=400)

                payload = archive.load_snapshot(snapshot_id)
                if payload is None:
                    return self._send_json({"error": f"Snapshot not found: {snapshot_id}"}, status_code=404)

                return self._send_json(payload)

            if path == "/api/live/raw":
                provider = self.snapshot_provider
                if provider is None:
                    return self._send_json({"error": "Live graph provider unavailable."}, status_code=503)

                return self._send_json({"graph": provider()})

            if path == "/api/live/pruned":
                engine = self.match_engine
                if engine is None:
                    return self._send_json({"error": "Live matcher unavailable."}, status_code=503)

                payload = engine.get_pruned_graph_state()
                if payload is None:
                    return self._send_json({"error": "Pruned graph is not ready yet."}, status_code=404)

                return self._send_json(payload)

            if path == "/api/live/matches":
                engine = self.match_engine
                if engine is None:
                    return self._send_json({"error": "Live matcher unavailable."}, status_code=503)

                payload = engine.get_public_state()
                if payload is None:
                    return self._send_json({"error": "Matching state is not ready yet."}, status_code=404)

                return self._send_json(payload)

            if path == "/api/live/context":
                engine = self.match_engine
                if engine is None:
                    return self._send_json({"error": "Live matcher unavailable."}, status_code=503)

                query = parse_qs(parsed.query)
                key = str((query.get("key") or [""])[0]).strip()
                if not key:
                    return self._send_json({"error": "Query parameter 'key' is required."}, status_code=400)

                payload = engine.get_context_for_key(key)
                if payload is None:
                    return self._send_json({"error": f"Match context not found for key: {key}"}, status_code=404)

                return self._send_json(payload)

            if path in {"", "/"}:
                self.path = "/index.html"

            return super().do_GET()

    def _log_console(self, message: str, level: str = "info") -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level.upper()}] {message}", flush=True)

    async def _send_status(
        self,
        message: str,
        level: str = "info",
        websocket: Any | None = None,
        log_console: bool = True,
    ) -> None:
        if log_console:
            self._log_console(message=message, level=level)

        payload = {
            "type": "status",
            "level": level,
            "message": message,
        }
        if websocket is None:
            await self.hub.broadcast_json(payload)
            return
        await self.hub.send_json(websocket, payload)

    def _schedule_match_job(self, snapshot: dict[str, Any] | None = None) -> None:
        if self._match_event is None:
            return

        graph_snapshot = snapshot or self.pipeline.snapshot()
        self._pending_match_snapshot = graph_snapshot
        self._pending_match_revision += 1
        self._match_event.set()

    async def _run_match_loop(self) -> None:
        match_event = self._match_event
        if match_event is None:
            return

        last_run_started = 0.0

        while True:
            await match_event.wait()
            match_event.clear()

            snapshot = self._pending_match_snapshot
            if snapshot is None:
                continue

            elapsed = time.monotonic() - last_run_started
            delay = self.config.match_min_interval_seconds - elapsed
            if delay > 0:
                await asyncio.sleep(delay)

            snapshot = self._pending_match_snapshot
            revision = self._pending_match_revision
            self._pending_match_snapshot = None

            try:
                payload = await asyncio.to_thread(self.match_engine.run, snapshot, revision)
            except Exception as exc:  # noqa: BLE001
                await self._send_status(
                    f"Live matching failed: {exc}",
                    level="error",
                )
                continue

            payload["snapshot_ui_url"] = self._snapshot_ui_url
            await self.hub.broadcast_json({"type": "match_update", "payload": payload})
            last_run_started = time.monotonic()

    async def _send_match_state(self, websocket: Any | None = None) -> None:
        payload = self.match_engine.get_public_state()
        if payload is None:
            await self._send_status(
                "Matching state is not ready yet.",
                level="warn",
                websocket=websocket,
                log_console=False,
            )
            return

        payload["snapshot_ui_url"] = self._snapshot_ui_url
        message = {"type": "match_update", "payload": payload}
        if websocket is None:
            await self.hub.broadcast_json(message)
            return
        await self.hub.send_json(websocket, message)

    async def _send_match_context(self, websocket: Any, key: str) -> None:
        context = self.match_engine.get_context_for_key(key)
        if context is None:
            await self._send_status(
                f"Match context not found for key: {key}",
                level="error",
                websocket=websocket,
            )
            return

        await self.hub.send_json(
            websocket,
            {
                "type": "match_context",
                "payload": context,
            },
        )

    async def _create_snapshot_for_match(self, websocket: Any, key: str) -> None:
        snapshot_id = self.snapshot_archive.create_snapshot_id()
        payload = self.match_engine.build_snapshot_payload(key=key, snapshot_id=snapshot_id)
        if payload is None:
            await self._send_status(
                f"Cannot create snapshot: unknown match key {key}",
                level="error",
                websocket=websocket,
            )
            return

        metadata = await asyncio.to_thread(self.snapshot_archive.enqueue_snapshot, payload, True)

        viewer_url = ""
        if self._snapshot_ui_url:
            viewer_url = f"{self._snapshot_ui_url}?snapshot_id={metadata['snapshot_id']}"

        await self.hub.send_json(
            websocket,
            {
                "type": "snapshot_created",
                "payload": {
                    **metadata,
                    "viewer_url": viewer_url,
                },
            },
        )

    def _offline_match_is_available(self) -> tuple[bool, str]:
        if self._offline_match_service is None:
            return False, (
                "Offline matcher is unavailable. "
                "Verify algorithem_pipeline dependencies and raw dataset location."
            )
        return True, ""

    def _offline_list_targets(self) -> list[str]:
        available, reason = self._offline_match_is_available()
        if not available:
            raise RuntimeError(reason)

        assert self._offline_match_service is not None
        targets = self._offline_match_service.list_targets()
        normalized = sorted(
            {
                str(target).strip()
                for target in targets
                if str(target).strip()
            }
        )
        return normalized

    def _offline_run_match(self, technique: str) -> dict[str, Any]:
        available, reason = self._offline_match_is_available()
        if not available:
            raise RuntimeError(reason)

        technique_name = str(technique or "").strip()
        if not technique_name:
            raise ValueError("Field 'technique' is required.")

        assert self._offline_match_service is not None
        target_graph = self._offline_match_service.load_target_graph(technique_name)

        with self._offline_lock:
            self._offline_graph_revision += 1
            graph_revision = self._offline_graph_revision

            engine = LiveMatchEngine(
                repo_root=self.config.repo_root,
                algorithm_names=self.config.match_algorithms,
                top_k=self.config.match_top_k,
            )
            payload = engine.run(deepcopy(target_graph.raw_payload), graph_revision)
            payload["snapshot_ui_url"] = self._snapshot_ui_url
            payload["mode"] = "offline"
            payload["target_name"] = str(target_graph.name or "")
            payload["target_technique"] = str(target_graph.technique or technique_name)

            pruned_state = engine.get_pruned_graph_state() or {}
            pruned_graph = deepcopy(pruned_state.get("graph") or {})
            pruned_graph.setdefault("nodes", [])
            pruned_graph.setdefault("edges", [])
            pruned_graph.setdefault("stats", {})

            self._offline_match_engine = engine
            self._offline_public_payload = deepcopy(payload)
            self._offline_pruned_graph = deepcopy(pruned_graph)
            self._offline_target = str(target_graph.technique or technique_name)

            return {
                "mode": "offline",
                "target_technique": self._offline_target,
                "graph_revision": graph_revision,
                "graph": pruned_graph,
                "payload": payload,
            }

    def _offline_get_state(self) -> dict[str, Any] | None:
        with self._offline_lock:
            if self._offline_public_payload is None or self._offline_pruned_graph is None:
                return None

            return {
                "mode": "offline",
                "target_technique": self._offline_target,
                "graph_revision": int(self._offline_public_payload.get("graph_revision") or 0),
                "graph": deepcopy(self._offline_pruned_graph),
                "payload": deepcopy(self._offline_public_payload),
            }

    def _offline_get_context(self, key: str) -> dict[str, Any] | None:
        key_text = str(key or "").strip()
        if not key_text:
            raise ValueError("Field 'key' is required.")

        engine = self._offline_match_engine
        if engine is None:
            return None

        payload = engine.get_context_for_key(key_text)
        if payload is None:
            return None
        return payload

    def _offline_create_snapshot_for_match(self, key: str) -> dict[str, Any] | None:
        key_text = str(key or "").strip()
        if not key_text:
            raise ValueError("Field 'key' is required.")

        engine = self._offline_match_engine
        if engine is None:
            return None

        snapshot_id = self.snapshot_archive.create_snapshot_id()
        payload = engine.build_snapshot_payload(key=key_text, snapshot_id=snapshot_id)
        if payload is None:
            return None

        metadata = self.snapshot_archive.enqueue_snapshot(payload, True)
        viewer_url = ""
        if self._snapshot_ui_url:
            viewer_url = f"{self._snapshot_ui_url}?snapshot_id={metadata['snapshot_id']}"

        return {
            **metadata,
            "viewer_url": viewer_url,
        }

    async def _handle_client_message(self, websocket: Any, payload: dict[str, Any]) -> None:
        message_type = str(payload.get("type", "")).strip().lower()

        if message_type == "request_snapshot":
            await self.hub.send_json(
                websocket,
                {
                    "type": "snapshot",
                    "graph": self.pipeline.snapshot(),
                },
            )
            return

        if message_type == "request_match_state":
            await self._send_match_state(websocket=websocket)
            return

        if message_type == "request_match_context":
            key = str(payload.get("key") or "").strip()
            if not key:
                await self._send_status(
                    "Field 'key' is required for request_match_context.",
                    level="error",
                    websocket=websocket,
                )
                return
            await self._send_match_context(websocket=websocket, key=key)
            return

        if message_type == "create_match_snapshot":
            key = str(payload.get("key") or "").strip()
            if not key:
                await self._send_status(
                    "Field 'key' is required for create_match_snapshot.",
                    level="error",
                    websocket=websocket,
                )
                return
            await self._create_snapshot_for_match(websocket=websocket, key=key)
            return

        if message_type == "install_sysmon":
            await self._install_or_update_sysmon(websocket=websocket)
            return

        if message_type == "ping":
            await self.hub.send_json(websocket, {"type": "pong"})
            return

        await self._send_status(
            message=f"Unknown command type: {message_type or '(empty)'}",
            level="error",
            websocket=websocket,
        )

    async def _install_or_update_sysmon(self, websocket: Any | None = None) -> None:
        await self._send_status(
            "Installing/updating Sysmon with full configuration...",
            websocket=websocket,
        )

        try:
            result = await asyncio.to_thread(
                self.installer.install_or_update_full,
                self.config.sysmon_binary_path,
                self.config.sysmon_config_path,
            )
        except Exception as exc:  # noqa: BLE001
            await self._send_status(
                f"Sysmon setup failed: {exc}",
                level="error",
                websocket=websocket,
            )
            return

        summary = (
            f"Sysmon {result.mode} successfully. "
            f"binary={result.binary_path.name} config={result.config_path.name}"
        )
        await self._send_status(summary, websocket=websocket)

    def _announce_ui_url(self) -> None:
        if not self._ui_url:
            self._log_console("UI server is unavailable, cannot provide browser URL.", level="error")
            return

        if self.config.offline_mode:
            if self._match_ui_url:
                self._log_console(f"Open offline matching UI: {self._match_ui_url}")
            if self._snapshot_ui_url:
                self._log_console(f"Open snapshot detail UI: {self._snapshot_ui_url}")
            return

        self._log_console(f"Open stream UI: {self._ui_url}")
        if self._match_ui_url:
            self._log_console(f"Open prune+matching UI: {self._match_ui_url}")
        if self._snapshot_ui_url:
            self._log_console(f"Open snapshot detail UI: {self._snapshot_ui_url}")

    def _start_ui_http_server(self) -> None:
        frontend_dir = self.config.frontend_file.parent
        if not frontend_dir.exists():
            self._log_console(f"Frontend directory not found: {frontend_dir}", level="error")
            return

        self._FrontendRequestHandler.service = self
        handler = functools.partial(self._FrontendRequestHandler, directory=str(frontend_dir))
        try:
            server = http.server.ThreadingHTTPServer(
                (self.config.ui_host, self.config.ui_port),
                handler,
            )
        except OSError as exc:
            self._log_console(
                f"Failed to start UI HTTP server on {self.config.ui_host}:{self.config.ui_port}: {exc}",
                level="error",
            )
            return

        server.daemon_threads = True
        self._ui_http_server = server

        thread = threading.Thread(
            target=server.serve_forever,
            name="streamline-ui-http",
            daemon=True,
        )
        thread.start()
        self._ui_http_thread = thread

        url_host = self.config.ui_host
        if url_host in {"0.0.0.0", "::"}:
            url_host = "127.0.0.1"

        self._ui_url = f"http://{url_host}:{server.server_port}/index.html"
        match_suffix = "/match/index.html?mode=offline" if self.config.offline_mode else "/match/index.html"
        self._match_ui_url = f"http://{url_host}:{server.server_port}{match_suffix}"
        self._log_console(
            f"UI static server started at http://{url_host}:{server.server_port}",
        )
        self._log_console(f"WS endpoint: ws://{self.config.host}:{self.config.port}")
        self._log_console(f"Stream UI URL: {self._ui_url}")
        if self.config.offline_mode:
            self._log_console(f"Offline matching UI URL: {self._match_ui_url}")
        else:
            self._log_console(f"Prune+matching UI URL: {self._match_ui_url}")

    def _start_snapshot_http_server(self) -> None:
        frontend_dir = self.config.snapshot_frontend_file.parent
        if not frontend_dir.exists():
            self._log_console(f"Snapshot frontend directory not found: {frontend_dir}", level="error")
            return

        self._SnapshotRequestHandler.archive = self.snapshot_archive
        self._SnapshotRequestHandler.match_engine = self.match_engine
        self._SnapshotRequestHandler.snapshot_provider = self.pipeline.snapshot
        handler = functools.partial(self._SnapshotRequestHandler, directory=str(frontend_dir))
        try:
            server = http.server.ThreadingHTTPServer(
                (self.config.ui_host, self.config.snapshot_ui_port),
                handler,
            )
        except OSError as exc:
            self._log_console(
                "Failed to start snapshot HTTP server on "
                f"{self.config.ui_host}:{self.config.snapshot_ui_port}: {exc}",
                level="error",
            )
            return

        server.daemon_threads = True
        self._snapshot_http_server = server

        thread = threading.Thread(
            target=server.serve_forever,
            name="streamline-snapshot-http",
            daemon=True,
        )
        thread.start()
        self._snapshot_http_thread = thread

        url_host = self.config.ui_host
        if url_host in {"0.0.0.0", "::"}:
            url_host = "127.0.0.1"

        self._snapshot_ui_url = f"http://{url_host}:{server.server_port}/index.html"
        self._log_console(
            f"Snapshot UI server started at http://{url_host}:{server.server_port}",
        )

    def _stop_snapshot_http_server(self) -> None:
        server = self._snapshot_http_server
        if server is None:
            return

        self._snapshot_http_server = None
        self._snapshot_http_thread = None
        try:
            server.shutdown()
            server.server_close()
        finally:
            self._log_console("Snapshot UI server stopped.")

    def _stop_ui_http_server(self) -> None:
        server = self._ui_http_server
        if server is None:
            return

        self._ui_http_server = None
        self._ui_http_thread = None
        try:
            server.shutdown()
            server.server_close()
        finally:
            self._log_console("UI static server stopped.")

    async def run(self) -> None:
        await self.hub.start()
        await self._send_status(
            f"Streamline WebSocket server started at ws://{self.config.host}:{self.config.port}",
        )

        self._start_ui_http_server()
        self.snapshot_archive.start()
        self._start_snapshot_http_server()
        if not self.config.offline_mode:
            self._match_event = asyncio.Event()
            self._match_task = asyncio.create_task(self._run_match_loop(), name="streamline-live-matcher")

        if self.config.clear_event_log_on_startup and not self.config.offline_mode:
            try:
                await self._send_status(
                    f"Clearing Sysmon event log channel: {self.config.channel}",
                )
                await asyncio.to_thread(self.pipeline.clear_event_log)
                await self._send_status("Sysmon event log cleared.")
            except Exception as exc:  # noqa: BLE001
                await self._send_status(
                    f"Failed to clear Sysmon event log: {exc}",
                    level="error",
                )

        self._log_console(
            "Press Ctrl+C to stop Streamline service.",
            level="info",
        )

        self._announce_ui_url()

        if self.config.install_sysmon_on_startup and not self.config.offline_mode:
            await self._install_or_update_sysmon()

        try:
            if self.config.offline_mode:
                await self._send_status(
                    "Offline mode enabled (--offline): live Sysmon polling is disabled.",
                )
                while True:
                    await asyncio.sleep(3600)

            last_poll_error = ""
            idle_polls = 0

            try:
                bootstrap_result = await asyncio.to_thread(self.pipeline.bootstrap)
                await self.hub.broadcast_json(
                    {
                        "type": "snapshot",
                        "graph": self.pipeline.snapshot(),
                    }
                )
                self._schedule_match_job(self.pipeline.snapshot())
                await self._send_status(
                    "Bootstrap completed: "
                    f"{bootstrap_result.to_status()} last_record_id={bootstrap_result.last_record_id}",
                )
                if bootstrap_result.events_seen == 0 and bootstrap_result.last_record_id is None:
                    await self._send_status(
                        "No Sysmon records were returned at bootstrap (last_record_id=None). "
                        "If Sysmon is running, start terminal as Administrator and verify channel "
                        "'Microsoft-Windows-Sysmon/Operational' is readable.",
                        level="error",
                    )
                if bootstrap_result.events_seen > 0 and bootstrap_result.triplets_created == 0:
                    await self._send_status(
                        "Bootstrap only saw non-mappable Sysmon events (commonly EventID 4/16). "
                        "Graph stays at LIVE_SYSMON until activity creates events like 1/3/11.",
                    )
            except Exception as exc:  # noqa: BLE001
                last_poll_error = str(exc)
                await self.hub.broadcast_json(
                    {
                        "type": "snapshot",
                        "graph": self.pipeline.snapshot(),
                    }
                )
                self._schedule_match_job(self.pipeline.snapshot())
                await self._send_status(
                    "Bootstrap failed, waiting for channel to become available: "
                    f"{exc}",
                    level="error",
                )

            while True:
                try:
                    poll_result = await asyncio.to_thread(self.pipeline.poll_once)
                except Exception as exc:  # noqa: BLE001
                    trace = traceback.format_exc(limit=1)
                    error_message = f"Polling failed: {exc}"
                    if error_message != last_poll_error:
                        await self._send_status(
                            f"{error_message} | {trace.strip()}",
                            level="error",
                        )
                        last_poll_error = error_message
                    await asyncio.sleep(max(1.0, self.config.poll_interval_seconds))
                    continue

                if last_poll_error:
                    await self._send_status("Polling recovered.")
                    last_poll_error = ""

                if poll_result.events_seen <= 0:
                    idle_polls += 1
                    if idle_polls % 15 == 0:
                        await self._send_status(
                            "No new Sysmon events in latest polls. "
                            f"last_record_id={poll_result.last_record_id}",
                            log_console=False,
                        )
                else:
                    idle_polls = 0

                if not poll_result.delta.is_empty():
                    await self.hub.broadcast_json(
                        {
                            "type": "delta",
                            "payload": poll_result.delta.to_payload(),
                        }
                    )
                    self._schedule_match_job(self.pipeline.snapshot())

                if poll_result.events_seen > 0:
                    await self._send_status(
                        "Realtime update: "
                        f"{poll_result.to_status()} last_record_id={poll_result.last_record_id}",
                        log_console=False,
                    )
                    if poll_result.triplets_created == 0:
                        top_codes = sorted(
                            poll_result.event_code_counts.items(),
                            key=lambda item: item[1],
                            reverse=True,
                        )[:5]
                        top_codes_text = ", ".join(
                            f"{code}={count}" for code, count in top_codes if code
                        ) or "(unknown)"
                        await self._send_status(
                            "Realtime events received but no graph changes from current event types. "
                            f"Top EventIDs: {top_codes_text}",
                            log_console=False,
                        )

                await asyncio.sleep(self.config.poll_interval_seconds)
        finally:
            match_task = self._match_task
            self._match_task = None
            if match_task is not None:
                match_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await match_task

            self.snapshot_archive.stop()
            self._stop_snapshot_http_server()
            self._match_event = None
            await self.hub.stop()
            self._stop_ui_http_server()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Streamline Sysmon graph service (live realtime mode or offline mode) "
            "with WebSocket backend + HTTP frontend."
        )
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Run offline mode (disable live Sysmon polling).",
    )
    parser.add_argument("--host", default="127.0.0.1", help="WebSocket host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8877, help="WebSocket port (default: 8877)")
    parser.add_argument(
        "--ui-host",
        default="127.0.0.1",
        help="HTTP host for serving frontend UI (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--ui-port",
        type=int,
        default=8080,
        help="HTTP port for serving frontend UI (default: 8080)",
    )
    parser.add_argument(
        "--snapshot-ui-port",
        type=int,
        default=8081,
        help="HTTP port for snapshot detail UI + snapshot APIs (default: 8081)",
    )
    parser.add_argument(
        "--channel",
        default="Microsoft-Windows-Sysmon/Operational",
        help="Windows Event Log channel to poll",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=1.0,
        help="Polling interval in seconds",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=2048,
        help="Maximum event records fetched per Sysmon query batch",
    )
    parser.add_argument(
        "--poll-max-batches",
        type=int,
        default=8,
        help="Maximum ordered Sysmon query batches drained during one poll tick",
    )
    parser.add_argument(
        "--bootstrap-count",
        type=int,
        default=200,
        help="How many latest records to ingest on startup",
    )
    parser.add_argument(
        "--no-clear-event-log-on-startup",
        dest="clear_event_log_on_startup",
        action="store_false",
        help="Do not clear the Sysmon event log before bootstrap",
    )
    parser.set_defaults(clear_event_log_on_startup=True)
    parser.add_argument(
        "--match-top-k",
        type=int,
        default=12,
        help="Top-k matches per algorithm to publish in realtime matching payload",
    )
    parser.add_argument(
        "--match-min-interval",
        type=float,
        default=0.8,
        help="Minimum interval in seconds between two live matching runs",
    )
    parser.add_argument(
        "--match-algorithms",
        default="behavioral_anchor_fusion",
        help=(
            "Comma-separated algorithm names for live matching. "
            "Available: baseline_exact,core_approximate,scale_multipattern,"
            "structure_adaptive,behavioral_anchor_fusion. "
            "In --offline mode, behavioral_anchor_fusion is enforced."
        ),
    )
    parser.add_argument(
        "--technique",
        default="LIVE_SYSMON",
        help="Technique label used for the synthetic root technique node",
    )
    parser.add_argument(
        "--install-sysmon",
        action="store_true",
        help="Install/update Sysmon and apply full config on startup",
    )
    parser.add_argument(
        "--sysmon-binary",
        default="",
        help="Optional custom path to Sysmon executable",
    )
    parser.add_argument(
        "--sysmon-config",
        default="",
        help="Optional custom path to Sysmon XML config",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    config = StreamlineConfig.from_args(args)
    LoggerManager.configure(level="INFO")

    service = StreamlineService(config)
    try:
        asyncio.run(service.run())
    except KeyboardInterrupt:
        print("Streamline stopped by user.", flush=True)
    except OSError as exc:
        winerror = getattr(exc, "winerror", None)
        if exc.errno == 10048 or winerror == 10048:
            print(
                "Streamline startup failed: ws://"
                f"{config.host}:{config.port} is already in use. "
                "Stop the existing process or run with --port <other_port>.",
                flush=True,
            )
            return 1
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
