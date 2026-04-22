from __future__ import annotations

import copy
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# The original parser expects paths like "analyzing/global_whitelist.json".
_ORIGINAL_CWD = Path.cwd()
os.chdir(REPO_ROOT)
try:
    from class_define.object_definition import BaseEntity  # noqa: E402
    from globals.global_object import clear_all_globals  # noqa: E402
    from graph_db.neo4j_manager import Neo4jGraphManager  # noqa: E402
    from log_parsers.sysmon_parser import SysmonLogParser  # noqa: E402
    from triplet_creator.triplet_creator import SysmonTripletCreator, Triplet  # noqa: E402
finally:
    os.chdir(_ORIGINAL_CWD)


SUPPORTED_SUFFIXES = {".log", ".txt", ".xml"}


@dataclass
class GraphCacheEntry:
    mtime_ns: int
    graph: dict[str, Any]


class TechniqueGraphPipeline:
    def __init__(self, dataset_folder: Path):
        self.dataset_folder = dataset_folder
        self._cache: dict[str, GraphCacheEntry] = {}

    @staticmethod
    def _find_sysmon_logs(folder: Path) -> list[Path]:
        return sorted(
            file_path
            for file_path in folder.rglob("*")
            if file_path.is_file()
            and "sysmon" in file_path.name.lower()
            and file_path.suffix.lower() in SUPPORTED_SUFFIXES
        )

    def _discover_technique_folders(self) -> dict[str, Path]:
        technique_files: dict[str, Path] = {}
        if not self.dataset_folder.exists() or not self.dataset_folder.is_dir():
            return technique_files

        for folder_path in sorted(path for path in self.dataset_folder.iterdir() if path.is_dir()):
            sysmon_logs = self._find_sysmon_logs(folder_path)
            if not sysmon_logs:
                continue

            technique_name = folder_path.name
            technique_files[technique_name] = folder_path

        return technique_files

    def list_techniques(self) -> list[str]:
        return list(self._discover_technique_folders().keys())

    def _resolve_technique_logs(self, technique: str) -> list[Path]:
        files = self._discover_technique_folders()
        if technique not in files:
            raise FileNotFoundError(
                f"Technique '{technique}' does not have Sysmon logs in dataset folder '{self.dataset_folder}'."
            )

        return self._find_sysmon_logs(files[technique])

    @staticmethod
    def _entity_to_node(entity: BaseEntity) -> dict[str, Any]:
        payload = Neo4jGraphManager._build_entity_payload(entity)
        props = payload["properties"]
        return {
            "id": payload["id"],
            "label": props.get("display_name", payload["id"]),
            "type": str(payload["label"]).lower(),
            "group": payload["label"],
            "properties": props,
        }

    @staticmethod
    def _triplet_to_edge(edge_id: str, triplet: Triplet) -> dict[str, Any]:
        relation = (triplet.action or "RELATED_TO").strip() or "RELATED_TO"
        return {
            "id": edge_id,
            "source": triplet.subject.get_id(),
            "target": triplet.object.get_id(),
            "from": triplet.subject.get_id(),
            "to": triplet.object.get_id(),
            "label": relation,
            "type": relation,
            "properties": {
                "action": relation,
                "event_id": str(triplet.event_id or ""),
                "timestamp": str(triplet.timestamp or ""),
            },
        }

    @staticmethod
    def _build_technique_node(technique: str) -> dict[str, Any]:
        token = Neo4jGraphManager._sanitize_cypher_token(technique, "technique")
        technique_id = f"Technique:{token}"
        props = {
            "id": technique_id,
            "name": technique,
            "display_name": technique,
            "type": "Technique",
            "entity_class": "Technique",
        }
        return {
            "id": technique_id,
            "label": technique,
            "type": "technique",
            "group": "Technique",
            "properties": props,
        }

    @staticmethod
    def _build_root_edge(edge_id: str, technique_id: str, root_id: str) -> dict[str, Any]:
        return {
            "id": edge_id,
            "source": technique_id,
            "target": root_id,
            "from": technique_id,
            "to": root_id,
            "label": "HAS_ROOT",
            "type": "HAS_ROOT",
            "properties": {
                "action": "HAS_ROOT",
                "event_id": "",
                "timestamp": "",
            },
        }

    def build_graph(self, technique: str) -> dict[str, Any]:
        log_files = self._resolve_technique_logs(technique)
        cache_fingerprint = sum(
            file_path.stat().st_mtime_ns + file_path.stat().st_size
            for file_path in log_files
        )

        cached = self._cache.get(technique)
        if cached and cached.mtime_ns == cache_fingerprint:
            return copy.deepcopy(cached.graph)

        parser = SysmonLogParser()
        triplet_creator = SysmonTripletCreator(graph_manager=None)

        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []

        subject_ids: set[str] = set()
        object_ids: set[str] = set()
        triplet_count = 0

        clear_all_globals()
        try:
            raw_events_total = 0
            source_files: list[str] = []

            for log_file in log_files:
                source_files.append(str(log_file))
                parsed_logs = parser.parse_from_file(str(log_file)) or []
                raw_events_total += len(parsed_logs)

                for log_entry in parsed_logs:
                    entity = parser.map_entity(log_entry)
                    if not entity:
                        continue

                    triplet = triplet_creator.create_triplet(entity)
                    if not triplet or not triplet.subject or not triplet.object:
                        continue

                    subject_node = self._entity_to_node(triplet.subject)
                    object_node = self._entity_to_node(triplet.object)
                    nodes[subject_node["id"]] = subject_node
                    nodes[object_node["id"]] = object_node

                    edge_id = f"edge:{technique}:{len(edges) + 1}"
                    edges.append(self._triplet_to_edge(edge_id, triplet))
                    triplet_count += 1

                    subject_ids.add(subject_node["id"])
                    object_ids.add(object_node["id"])

            technique_node = self._build_technique_node(technique)
            nodes[technique_node["id"]] = technique_node

            root_ids = sorted(subject_ids - object_ids)
            for root_id in root_ids:
                if root_id not in nodes:
                    continue
                edge_id = f"edge:{technique}:root:{root_id}"
                edges.append(self._build_root_edge(edge_id, technique_node["id"], root_id))

            graph = {
                "technique": technique,
                "source_file": source_files[0] if source_files else "",
                "source_files": source_files,
                "whitelist": {
                    "enabled": True,
                    "config_path": str(REPO_ROOT / "analyzing" / "global_whitelist.json"),
                },
                "nodes": list(nodes.values()),
                "edges": edges,
                "stats": {
                    "raw_events": raw_events_total,
                    "triplets": triplet_count,
                    "roots": len(root_ids),
                },
            }
        finally:
            clear_all_globals()

        self._cache[technique] = GraphCacheEntry(mtime_ns=cache_fingerprint, graph=graph)
        return copy.deepcopy(graph)
