from __future__ import annotations

import ctypes
import io
import subprocess
import sys
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class SysmonInstallResult:
    binary_path: Path
    config_path: Path
    mode: str
    command: list[str]
    stdout: str = ""
    stderr: str = ""
    return_code: int = 0
    actions: list[str] = field(default_factory=list)


class SysmonInstaller:
    SYSMON_ZIP_URL = "https://download.sysinternals.com/files/Sysmon.zip"

    def __init__(self, assets_dir: Path) -> None:
        self.assets_dir = assets_dir
        self.assets_dir.mkdir(parents=True, exist_ok=True)
        self.binary_dir = self.assets_dir / "sysmon-bin"
        self.binary_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _is_windows() -> bool:
        return sys.platform.startswith("win")

    @staticmethod
    def is_admin() -> bool:
        if not sys.platform.startswith("win"):
            return False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _download_sysmon_zip(self) -> bytes:
        with urllib.request.urlopen(self.SYSMON_ZIP_URL, timeout=60) as response:
            return response.read()

    def ensure_sysmon_binary(self, custom_binary: Path | None = None) -> Path:
        if custom_binary:
            binary = custom_binary.expanduser().resolve()
            if not binary.exists():
                raise FileNotFoundError(f"Sysmon binary does not exist: {binary}")
            return binary

        preferred_name = "Sysmon64.exe" if sys.maxsize > 2**32 else "Sysmon.exe"
        preferred_path = self.binary_dir / preferred_name
        fallback_path = self.binary_dir / "Sysmon.exe"

        if preferred_path.exists():
            return preferred_path
        if fallback_path.exists() and preferred_name != "Sysmon.exe":
            return fallback_path

        archive_bytes = self._download_sysmon_zip()
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            extracted = False
            for member_name in archive.namelist():
                simple_name = Path(member_name).name
                if simple_name.lower() not in {"sysmon.exe", "sysmon64.exe"}:
                    continue
                target_path = self.binary_dir / simple_name
                target_path.write_bytes(archive.read(member_name))
                extracted = True

        if not extracted:
            raise RuntimeError("Downloaded Sysmon package did not contain Sysmon executables.")

        if preferred_path.exists():
            return preferred_path
        if fallback_path.exists():
            return fallback_path
        raise RuntimeError("Failed to prepare Sysmon executable after download.")

    def ensure_config_path(self, custom_config: Path | None = None) -> Path:
        if custom_config:
            path = custom_config.expanduser().resolve()
            if not path.exists():
                raise FileNotFoundError(f"Sysmon config file does not exist: {path}")
            return path

        default_config = self.assets_dir / "sysmon-full.xml"
        if not default_config.exists():
            raise FileNotFoundError(
                f"Default full config not found: {default_config}. Please create it first."
            )
        return default_config

    @staticmethod
    def _run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
        )

    def install_or_update_full(
        self,
        custom_binary: Path | None = None,
        custom_config: Path | None = None,
    ) -> SysmonInstallResult:
        if not self._is_windows():
            raise RuntimeError("Sysmon installation is only supported on Windows.")
        if not self.is_admin():
            raise PermissionError("Admin privileges are required to install or update Sysmon.")

        binary = self.ensure_sysmon_binary(custom_binary)
        config = self.ensure_config_path(custom_config)

        actions: list[str] = []
        update_cmd = [str(binary), "-accepteula", "-c", str(config)]
        update_run = self._run_command(update_cmd)
        actions.append("tried_update_config")

        if update_run.returncode == 0:
            return SysmonInstallResult(
                binary_path=binary,
                config_path=config,
                mode="updated",
                command=update_cmd,
                stdout=update_run.stdout,
                stderr=update_run.stderr,
                return_code=update_run.returncode,
                actions=actions,
            )

        install_cmd = [str(binary), "-accepteula", "-i", str(config)]
        install_run = self._run_command(install_cmd)
        actions.append("tried_install")

        if install_run.returncode != 0:
            raise RuntimeError(
                "Failed to apply Sysmon full config. "
                f"Update stderr: {update_run.stderr.strip()} | Install stderr: {install_run.stderr.strip()}"
            )

        return SysmonInstallResult(
            binary_path=binary,
            config_path=config,
            mode="installed",
            command=install_cmd,
            stdout=install_run.stdout,
            stderr=install_run.stderr,
            return_code=install_run.returncode,
            actions=actions,
        )
