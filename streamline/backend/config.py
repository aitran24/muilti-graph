from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class StreamlineConfig:
    host: str
    port: int
    ui_host: str
    ui_port: int
    channel: str
    poll_interval_seconds: float
    batch_size: int
    bootstrap_count: int
    technique_name: str
    install_sysmon_on_startup: bool
    frontend_file: Path
    sysmon_assets_dir: Path
    sysmon_binary_path: Path | None = None
    sysmon_config_path: Path | None = None

    @classmethod
    def from_args(cls, args: Any) -> "StreamlineConfig":
        base_dir = Path(__file__).resolve().parents[1]
        frontend_file = base_dir / "frontend" / "index.html"
        assets_dir = base_dir / "assets"

        binary_path = str(getattr(args, "sysmon_binary", "") or "").strip()
        config_path = str(getattr(args, "sysmon_config", "") or "").strip()

        return cls(
            host=str(getattr(args, "host", "127.0.0.1") or "127.0.0.1"),
            port=int(getattr(args, "port", 8877) or 8877),
            ui_host=str(getattr(args, "ui_host", "127.0.0.1") or "127.0.0.1"),
            ui_port=max(1, int(getattr(args, "ui_port", 8080) or 8080)),
            channel=str(
                getattr(args, "channel", "Microsoft-Windows-Sysmon/Operational")
                or "Microsoft-Windows-Sysmon/Operational"
            ),
            poll_interval_seconds=max(0.2, float(getattr(args, "poll_interval", 1.0) or 1.0)),
            batch_size=max(1, int(getattr(args, "batch_size", 128) or 128)),
            bootstrap_count=max(0, int(getattr(args, "bootstrap_count", 200) or 200)),
            technique_name=str(getattr(args, "technique", "LIVE_SYSMON") or "LIVE_SYSMON"),
            install_sysmon_on_startup=bool(getattr(args, "install_sysmon", False)),
            frontend_file=frontend_file,
            sysmon_assets_dir=assets_dir,
            sysmon_binary_path=Path(binary_path).expanduser().resolve() if binary_path else None,
            sysmon_config_path=Path(config_path).expanduser().resolve() if config_path else None,
        )
