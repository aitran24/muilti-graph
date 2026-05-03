from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable

from class_define.data_normalizer import DataNormalizer


_WHITELIST_PATH = Path(__file__).resolve().parent / "global_whitelist.json"
try:
    _WHITELIST = json.loads(_WHITELIST_PATH.read_text(encoding="utf-8"))
except FileNotFoundError:
    _WHITELIST = {"ignore_processes": []}


def _pick(data: Dict, *keys: str) -> str:
    for key in keys:
        value = data.get(key)
        if value is not None and value != "":
            return str(value)
    return ""


def _normalize_guid(guid: str) -> str:
    return (guid or "").strip().lower()


def _is_whitelisted_process_image(image_path: str) -> bool:
    return any(
        whitelist_entry in (image_path or "")
        for whitelist_entry in _WHITELIST.get("ignore_processes", [])
    )


def collect_pruned_process_guids(parsed_logs: Iterable[Dict]) -> set[str]:
    normalizer = DataNormalizer()
    process_graph: dict[str, set[str]] = {}
    seed_ignored_guids: set[str] = set()

    for log_entry in parsed_logs:
        event_data = (log_entry or {}).get("EventData") or {}

        process_guid = _normalize_guid(
            _pick(event_data, "ProcessGuid", "TargetProcessGuid", "TargetProcessGUID")
        )
        parent_guid = _normalize_guid(
            _pick(event_data, "ParentProcessGuid", "SourceProcessGuid", "SourceProcessGUID")
        )

        if process_guid and parent_guid and process_guid != parent_guid:
            process_graph.setdefault(parent_guid, set()).add(process_guid)

        process_image = normalizer.normalize(
            ["file_path"],
            _pick(event_data, "Image", "TargetImage"),
        )
        if process_guid and _is_whitelisted_process_image(process_image):
            seed_ignored_guids.add(process_guid)

        parent_image = normalizer.normalize(
            ["file_path"],
            _pick(event_data, "ParentImage", "SourceImage"),
        )
        if parent_guid and _is_whitelisted_process_image(parent_image):
            seed_ignored_guids.add(parent_guid)

    if not seed_ignored_guids:
        return set()

    ignored_guids = set(seed_ignored_guids)
    stack = list(seed_ignored_guids)
    while stack:
        current_guid = stack.pop()
        for child_guid in process_graph.get(current_guid, set()):
            if child_guid in ignored_guids:
                continue
            ignored_guids.add(child_guid)
            stack.append(child_guid)

    return ignored_guids
