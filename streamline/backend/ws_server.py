from __future__ import annotations

import asyncio
import json
from typing import Any, Awaitable, Callable

import websockets


MessageHandler = Callable[[Any, dict[str, Any]], Awaitable[None]]
SnapshotProvider = Callable[[], dict[str, Any]]


class WebSocketHub:
    """Thin websocket hub for broadcasting graph updates to connected UI clients."""

    def __init__(
        self,
        host: str,
        port: int,
        snapshot_provider: SnapshotProvider,
        message_handler: MessageHandler,
    ) -> None:
        self.host = host
        self.port = port
        self._snapshot_provider = snapshot_provider
        self._message_handler = message_handler
        self._clients: set[Any] = set()
        self._server: Any = None
        self._lock = asyncio.Lock()

    @property
    def client_count(self) -> int:
        return len(self._clients)

    async def start(self) -> None:
        self._server = await websockets.serve(
            self._handle_client,
            self.host,
            self.port,
            max_size=16 * 1024 * 1024,
            ping_interval=20,
            ping_timeout=20,
        )

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    async def send_json(self, websocket: Any, payload: dict[str, Any]) -> None:
        await websocket.send(json.dumps(payload, ensure_ascii=False))

    async def broadcast_json(self, payload: dict[str, Any]) -> None:
        if not self._clients:
            return

        message = json.dumps(payload, ensure_ascii=False)
        dead_clients: list[Any] = []

        async with self._lock:
            for client in list(self._clients):
                try:
                    await client.send(message)
                except Exception:
                    dead_clients.append(client)

            for dead in dead_clients:
                self._clients.discard(dead)

    async def _handle_client(self, websocket: Any) -> None:
        self._clients.add(websocket)
        try:
            snapshot = self._snapshot_provider()
            await self.send_json(websocket, {"type": "snapshot", "graph": snapshot})
            await self.send_json(
                websocket,
                {
                    "type": "status",
                    "level": "info",
                    "message": f"Connected to streamline backend ({self.client_count} clients).",
                },
            )

            async for raw_message in websocket:
                try:
                    payload = json.loads(raw_message)
                except json.JSONDecodeError:
                    await self.send_json(
                        websocket,
                        {
                            "type": "status",
                            "level": "error",
                            "message": "Invalid JSON command.",
                        },
                    )
                    continue

                if not isinstance(payload, dict):
                    await self.send_json(
                        websocket,
                        {
                            "type": "status",
                            "level": "error",
                            "message": "Command payload must be a JSON object.",
                        },
                    )
                    continue

                await self._message_handler(websocket, payload)
        finally:
            self._clients.discard(websocket)
