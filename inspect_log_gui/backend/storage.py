from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


class PatternStore:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _sanitize_technique_name(technique: str) -> str:
        token = re.sub(r"[^A-Za-z0-9_.-]", "_", (technique or "").strip())
        return token or "technique"

    def _pattern_file_path(self, technique: str) -> Path:
        safe_name = self._sanitize_technique_name(technique)
        return self.data_dir / f"{safe_name}_malcious_config.json"

    @staticmethod
    def _normalize_patterns(patterns: Any) -> list[str]:
        if not isinstance(patterns, list):
            return []

        normalized: list[str] = []
        for item in patterns:
            text = str(item).strip()
            if text and text not in normalized:
                normalized.append(text)
        return normalized

    def get_patterns(self, technique: str) -> list[str]:
        file_path = self._pattern_file_path(technique)
        if not file_path.exists():
            return []

        try:
            payload = json.loads(file_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []

        if isinstance(payload, list):
            return self._normalize_patterns(payload)

        if isinstance(payload, dict):
            return self._normalize_patterns(payload.get("patterns", []))

        return []

    def save_patterns(self, technique: str, patterns: list[str]) -> list[str]:
        normalized = self._normalize_patterns(patterns)
        payload = {
            "technique": technique,
            "patterns": normalized,
        }

        file_path = self._pattern_file_path(technique)
        file_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return normalized

    def append_pattern(self, technique: str, new_pattern: str) -> list[str]:
        patterns = self.get_patterns(technique)
        text = (new_pattern or "").strip()
        if text and text not in patterns:
            patterns.append(text)

        return self.save_patterns(technique, patterns)
