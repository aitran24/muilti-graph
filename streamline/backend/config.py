from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class StreamlineConfig:
    repo_root: Path
    offline_mode: bool
    host: str
    port: int
    ui_host: str
    ui_port: int
    snapshot_ui_port: int
    channel: str
    poll_interval_seconds: float
    batch_size: int
    poll_max_batches: int
    bootstrap_count: int
    technique_name: str
    clear_event_log_on_startup: bool
    install_sysmon_on_startup: bool
    frontend_file: Path
    match_frontend_file: Path
    snapshot_frontend_file: Path
    snapshot_storage_dir: Path
    match_top_k: int
    match_min_interval_seconds: float
    match_algorithms: tuple[str, ...]
    sysmon_assets_dir: Path
    sysmon_binary_path: Path | None = None
    sysmon_config_path: Path | None = None

    @classmethod
    def from_args(cls, args: Any) -> "StreamlineConfig":
        base_dir = Path(__file__).resolve().parents[1]
        repo_root = base_dir.parent
        frontend_file = base_dir / "frontend" / "index.html"
        match_frontend_file = base_dir / "frontend" / "match" / "index.html"
        snapshot_frontend_file = base_dir / "snapshot_frontend" / "index.html"
        snapshot_storage_dir = base_dir / "snapshots"
        assets_dir = base_dir / "assets"
        offline_mode = bool(getattr(args, "offline", False))

        binary_path = str(getattr(args, "sysmon_binary", "") or "").strip()
        config_path = str(getattr(args, "sysmon_config", "") or "").strip()
        raw_algorithms = str(
            getattr(
                args,
                "match_algorithms",
                "behavioral_anchor_fusion",
            )
            or ""
        )
        normalized_algorithms = tuple(
            algorithm
            for algorithm in (part.strip() for part in raw_algorithms.split(","))
            if algorithm
        )
        if offline_mode:
            normalized_algorithms = ("behavioral_anchor_fusion",)
        elif not normalized_algorithms:
            normalized_algorithms = ("behavioral_anchor_fusion",)
        ui_port = max(1, int(getattr(args, "ui_port", 8080) or 8080))
        snapshot_ui_port = max(1, int(getattr(args, "snapshot_ui_port", 8081) or 8081))
        if snapshot_ui_port == ui_port:
            snapshot_ui_port = ui_port + 1

        return cls(
            repo_root=repo_root,
            offline_mode=offline_mode,
            host=str(getattr(args, "host", "127.0.0.1") or "127.0.0.1"),
            port=int(getattr(args, "port", 8877) or 8877),
            ui_host=str(getattr(args, "ui_host", "127.0.0.1") or "127.0.0.1"),
            ui_port=ui_port,
            snapshot_ui_port=snapshot_ui_port,
            channel=str(
                getattr(args, "channel", "Microsoft-Windows-Sysmon/Operational")
                or "Microsoft-Windows-Sysmon/Operational"
            ),
            poll_interval_seconds=max(0.2, float(getattr(args, "poll_interval", 1.0) or 1.0)),
            batch_size=max(1, int(getattr(args, "batch_size", 2048) or 2048)),
            poll_max_batches=max(1, int(getattr(args, "poll_max_batches", 8) or 8)),
            bootstrap_count=max(0, int(getattr(args, "bootstrap_count", 200) or 200)),
            technique_name=str(getattr(args, "technique", "LIVE_SYSMON") or "LIVE_SYSMON"),
            clear_event_log_on_startup=bool(getattr(args, "clear_event_log_on_startup", True)),
            install_sysmon_on_startup=bool(getattr(args, "install_sysmon", False)),
            frontend_file=frontend_file,
            match_frontend_file=match_frontend_file,
            snapshot_frontend_file=snapshot_frontend_file,
            snapshot_storage_dir=snapshot_storage_dir,
            match_top_k=max(1, int(getattr(args, "match_top_k", 12) or 12)),
            match_min_interval_seconds=max(
                0.2,
                float(getattr(args, "match_min_interval", 0.8) or 0.8),
            ),
            match_algorithms=normalized_algorithms,
            sysmon_assets_dir=assets_dir,
            sysmon_binary_path=Path(binary_path).expanduser().resolve() if binary_path else None,
            sysmon_config_path=Path(config_path).expanduser().resolve() if config_path else None,
        )
