from __future__ import annotations

import argparse
import asyncio
import functools
import http.server
import threading
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any

from streamline.backend.config import StreamlineConfig
from streamline.backend.streamer import LiveStreamPipeline
from streamline.backend.sysmon_installer import SysmonInstaller
from streamline.backend.ws_server import WebSocketHub
from globals.logger_manager import LoggerManager


class StreamlineService:
    def __init__(self, config: StreamlineConfig) -> None:
        self.config = config
        self.pipeline = LiveStreamPipeline(config)
        self.installer = SysmonInstaller(config.sysmon_assets_dir)
        self.hub = WebSocketHub(
            host=config.host,
            port=config.port,
            snapshot_provider=self.pipeline.snapshot,
            message_handler=self._handle_client_message,
        )
        self._ui_http_server: http.server.ThreadingHTTPServer | None = None
        self._ui_http_thread: threading.Thread | None = None
        self._ui_url: str = ""

    class _FrontendRequestHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:  # noqa: A003
            return

    def _log_console(self, message: str, level: str = "info") -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level.upper()}] {message}", flush=True)

    async def _send_status(
        self,
        message: str,
        level: str = "info",
        websocket: Any | None = None,
    ) -> None:
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

        self._log_console(f"Open UI manually: {self._ui_url}")

    def _start_ui_http_server(self) -> None:
        frontend_dir = self.config.frontend_file.parent
        if not frontend_dir.exists():
            self._log_console(f"Frontend directory not found: {frontend_dir}", level="error")
            return

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
        self._log_console(
            f"UI static server started at http://{url_host}:{server.server_port}",
        )
        self._log_console(f"WS endpoint: ws://{self.config.host}:{self.config.port}")
        self._log_console(f"UI URL: {self._ui_url}")

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

        if self.config.install_sysmon_on_startup:
            await self._install_or_update_sysmon()

        try:
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

                if poll_result.events_seen > 0:
                    await self._send_status(
                        "Realtime update: "
                        f"{poll_result.to_status()} last_record_id={poll_result.last_record_id}",
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
                        )

                await asyncio.sleep(self.config.poll_interval_seconds)
        finally:
            await self.hub.stop()
            self._stop_ui_http_server()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Streamline realtime Sysmon graph streamer (WebSocket backend + HTTP frontend)."
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
        default=128,
        help="Maximum event records fetched per poll",
    )
    parser.add_argument(
        "--bootstrap-count",
        type=int,
        default=200,
        help="How many latest records to ingest on startup",
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
