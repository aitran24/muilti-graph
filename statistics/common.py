from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SUPPORTED_LOG_SUFFIXES = {".log", ".txt", ".xml"}
OUTPUT_DIRNAME = "output"
STAT_JSON_PATTERN = re.compile(r"^stat_v(?P<version>\d+)(?:_[A-Za-z0-9_-]+)?\.json$")
STAT_FILE_PATTERN = re.compile(r"^stat_v(?P<version>\d+)(?:_[A-Za-z0-9_-]+)?\.(?:json|md)$")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def slugify(text: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", text.strip())
    slug = re.sub(r"-+", "-", slug).strip("-")
    return slug.lower()


def safe_pct_change(prev: int | float, curr: int | float) -> str:
    if prev == 0:
        if curr == 0:
            return "0.00%"
        return "N/A"

    pct = ((curr - prev) / prev) * 100.0
    return f"{pct:+.2f}%"


def sort_counter(counter: Counter[str]) -> dict[str, int]:
    return {k: int(v) for k, v in sorted(counter.items(), key=lambda item: (-item[1], item[0]))}


def extract_version_from_name(file_name: str) -> int | None:
    match = STAT_FILE_PATTERN.match(file_name)
    if not match:
        return None
    return int(match.group("version"))


def next_version(stats_dir: Path) -> int:
    versions: list[int] = []
    for file_path in stats_dir.iterdir():
        if not file_path.is_file():
            continue
        version = extract_version_from_name(file_path.name)
        if version is not None:
            versions.append(version)

    return max(versions, default=0) + 1


def discover_run_json_files(stats_dir: Path) -> list[Path]:
    run_files: list[Path] = []
    for file_path in sorted(stats_dir.glob("stat_v*.json")):
        if STAT_JSON_PATTERN.match(file_path.name):
            run_files.append(file_path)
    return run_files


def render_table(headers: list[str], rows: Iterable[list[Any]]) -> str:
    def to_cell(value: Any) -> str:
        text = "" if value is None else str(value)
        return text.replace("|", "\\|")

    header_line = "| " + " | ".join(to_cell(h) for h in headers) + " |"
    divider_line = "| " + " | ".join("---" for _ in headers) + " |"
    body_lines = [
        "| " + " | ".join(to_cell(cell) for cell in row) + " |"
        for row in rows
    ]

    return "\n".join([header_line, divider_line, *body_lines])


def render_technique_relation_matrix(
    technique_relation_matrix: dict[str, dict[str, int]],
) -> str:
    relation_types = sorted(
        {
            relation_type
            for per_technique in technique_relation_matrix.values()
            for relation_type in per_technique.keys()
        }
    )

    headers = ["Technique", *relation_types, "Total"]
    rows: list[list[Any]] = []

    for technique_name in sorted(technique_relation_matrix.keys()):
        per_technique = technique_relation_matrix[technique_name]
        counts = [int(per_technique.get(relation_type, 0)) for relation_type in relation_types]
        rows.append([technique_name, *counts, int(sum(counts))])

    if not rows:
        rows.append(["(no data)", *([0] * len(relation_types)), 0])

    return render_table(headers, rows)


def write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
