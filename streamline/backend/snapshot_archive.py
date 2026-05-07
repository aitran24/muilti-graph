from __future__ import annotations

import json
import queue
import threading
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


class SnapshotArchive:
    """Persist static match snapshots via a low-resource writer thread."""

    def __init__(self, storage_dir: Path, max_entries: int = 800) -> None:
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.max_entries = max(10, int(max_entries or 10))

        self._index_file = self.storage_dir / "index.json"
        self._lock = threading.Lock()
        self._queue: queue.Queue[tuple[str, dict[str, Any], dict[str, Any], threading.Event | None]] = queue.Queue()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        self._items: list[dict[str, Any]] = []
        self._by_id: dict[str, dict[str, Any]] = {}
        self._load_index()

    def _load_index(self) -> None:
        if not self._index_file.exists():
            return

        try:
            payload = json.loads(self._index_file.read_text(encoding="utf-8"))
        except Exception:
            return

        items = payload.get("items") if isinstance(payload, dict) else []
        if not isinstance(items, list):
            return

        normalized: list[dict[str, Any]] = []
        by_id: dict[str, dict[str, Any]] = {}

        for item in items:
            if not isinstance(item, dict):
                continue
            snapshot_id = str(item.get("snapshot_id") or "").strip()
            file_name = str(item.get("file_name") or "").strip()
            if not snapshot_id or not file_name:
                continue
            snapshot_path = self.storage_dir / file_name
            if not snapshot_path.exists():
                continue
            metadata = {
                "snapshot_id": snapshot_id,
                "created_at": str(item.get("created_at") or ""),
                "technique": str(item.get("technique") or ""),
                "algorithm": str(item.get("algorithm") or ""),
                "score": float(item.get("score") or 0.0),
                "graph_revision": int(item.get("graph_revision") or 0),
                "file_name": file_name,
            }
            normalized.append(metadata)
            by_id[snapshot_id] = metadata

        self._items = normalized[: self.max_entries]
        self._by_id = by_id

    def _save_index(self) -> None:
        payload = {
            "items": self._items,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        self._index_file.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._writer_loop,
            name="streamline-snapshot-writer",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)

    def create_snapshot_id(self) -> str:
        now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        return f"snap-{now}-{uuid4().hex[:10]}"

    def enqueue_snapshot(self, payload: dict[str, Any], wait_for_write: bool = True) -> dict[str, Any]:
        snapshot_id = str(payload.get("snapshot_id") or "").strip() or self.create_snapshot_id()
        payload = {
            **payload,
            "snapshot_id": snapshot_id,
            "created_at": str(payload.get("created_at") or datetime.now(timezone.utc).isoformat()),
        }

        match_info = payload.get("match") if isinstance(payload.get("match"), dict) else {}
        metadata = {
            "snapshot_id": snapshot_id,
            "created_at": payload["created_at"],
            "technique": str(match_info.get("technique") or ""),
            "algorithm": str(match_info.get("algorithm") or ""),
            "score": float(match_info.get("score") or 0.0),
            "graph_revision": int(payload.get("graph_revision") or 0),
            "file_name": f"{snapshot_id}.json",
        }

        done_event = threading.Event() if wait_for_write else None
        self._queue.put((snapshot_id, payload, metadata, done_event))

        if done_event is not None:
            done_event.wait(timeout=3.0)

        return metadata

    def list_snapshots(self, limit: int = 200) -> list[dict[str, Any]]:
        max_limit = max(1, int(limit or 1))
        with self._lock:
            return deepcopy(self._items[:max_limit])

    def load_snapshot(self, snapshot_id: str) -> dict[str, Any] | None:
        normalized_id = str(snapshot_id or "").strip()
        if not normalized_id:
            return None

        with self._lock:
            metadata = self._by_id.get(normalized_id)
            if metadata is None:
                return None
            file_name = str(metadata.get("file_name") or "").strip()

        if not file_name:
            return None

        file_path = self.storage_dir / file_name
        if not file_path.exists():
            return None

        try:
            return json.loads(file_path.read_text(encoding="utf-8"))
        except Exception:
            return None

    def _writer_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                snapshot_id, payload, metadata, done_event = self._queue.get(timeout=0.25)
            except queue.Empty:
                continue

            try:
                self._write_snapshot(snapshot_id=snapshot_id, payload=payload, metadata=metadata)
            except Exception:
                # Keep background writer alive even if a single snapshot write fails.
                pass
            finally:
                if done_event is not None:
                    done_event.set()
                self._queue.task_done()

    def _write_snapshot(
        self,
        snapshot_id: str,
        payload: dict[str, Any],
        metadata: dict[str, Any],
    ) -> None:
        file_name = str(metadata.get("file_name") or f"{snapshot_id}.json")
        file_path = self.storage_dir / file_name

        file_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        with self._lock:
            existing = self._by_id.get(snapshot_id)
            if existing is not None:
                try:
                    old_file_name = str(existing.get("file_name") or "").strip()
                    if old_file_name and old_file_name != file_name:
                        old_path = self.storage_dir / old_file_name
                        if old_path.exists():
                            old_path.unlink(missing_ok=True)
                except Exception:
                    pass
                self._items = [item for item in self._items if item.get("snapshot_id") != snapshot_id]

            self._items.insert(0, metadata)
            self._by_id[snapshot_id] = metadata

            if len(self._items) > self.max_entries:
                overflow = self._items[self.max_entries :]
                self._items = self._items[: self.max_entries]
                for stale in overflow:
                    stale_id = str(stale.get("snapshot_id") or "").strip()
                    stale_name = str(stale.get("file_name") or "").strip()
                    if stale_id:
                        self._by_id.pop(stale_id, None)
                    if stale_name:
                        stale_path = self.storage_dir / stale_name
                        try:
                            if stale_path.exists():
                                stale_path.unlink(missing_ok=True)
                        except Exception:
                            pass

            self._save_index()
