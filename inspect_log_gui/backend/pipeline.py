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
    from analyzing.prune_utils import collect_pruned_process_guids  # noqa: E402
    from globals.global_object import (  # noqa: E402
        add_returned_node_id,
        add_ignored_process_guid,
        clear_all_globals,
        get_all_files,
        get_all_networks,
        get_all_processes,
        get_all_registries,
        get_all_users,
        get_all_wmis,
        get_file,
        get_file_id_redirects,
        get_process,
    )
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


@dataclass
class ProjectionState:
    nodes: dict[str, dict[str, Any]]
    edges: list[dict[str, Any]]
    subject_ids: set[str]
    object_ids: set[str]
    triplet_count: int = 0


class TechniqueGraphPipeline:
    def __init__(self, dataset_folder: Path):
        self.dataset_folder = dataset_folder
        self._cache: dict[str, GraphCacheEntry] = {}

    @staticmethod
    def _has_meaningful_value(value: Any) -> bool:
        if value is None:
            return False
        if isinstance(value, str):
            return value.strip() != ""
        if isinstance(value, (list, tuple, set, dict)):
            return len(value) > 0
        return True

    @classmethod
    def _merge_properties(cls, current: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
        merged = dict(current)

        for key, incoming_value in incoming.items():
            if key not in merged:
                merged[key] = incoming_value
                continue

            current_value = merged[key]
            if cls._has_meaningful_value(incoming_value) and not cls._has_meaningful_value(current_value):
                merged[key] = incoming_value

        # Prefer flattened relation ids over raw relation placeholders (None/object).
        for key in list(merged.keys()):
            if key.endswith("_id"):
                relation_key = key[:-3]
                relation_value = merged.get(relation_key)
                if relation_key in merged and isinstance(relation_value, (dict, type(None))):
                    merged.pop(relation_key, None)

        return merged

    @classmethod
    def _upsert_node(cls, nodes: dict[str, dict[str, Any]], node: dict[str, Any]) -> None:
        node_id = str(node.get("id", ""))
        if not node_id:
            return

        existing = nodes.get(node_id)
        if not existing:
            nodes[node_id] = node
            return

        merged_props = cls._merge_properties(
            existing.get("properties", {}),
            node.get("properties", {}),
        )
        nodes[node_id] = {
            "id": node_id,
            "label": merged_props.get("display_name") or existing.get("label") or node.get("label") or node_id,
            "type": existing.get("type") or node.get("type", ""),
            "group": existing.get("group") or node.get("group", ""),
            "properties": merged_props,
        }

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

    def _apply_file_id_redirects(
        self,
        nodes: dict[str, dict[str, Any]],
        edges: list[dict[str, Any]],
        subject_ids: set[str],
        object_ids: set[str],
    ) -> None:
        redirects = get_file_id_redirects()
        if not redirects:
            return

        def resolve_id(entity_id: str) -> str:
            current = entity_id
            visited: set[str] = set()
            while current in redirects and current not in visited:
                visited.add(current)
                current = redirects[current]
            return current

        rewritten_nodes: dict[str, dict[str, Any]] = {}
        for node in nodes.values():
            original_id = str(node.get("id", ""))
            resolved_id = resolve_id(original_id)

            if resolved_id != original_id:
                file_entity = get_file(resolved_id)
                if file_entity:
                    rewritten_nodes[resolved_id] = self._entity_to_node(file_entity)
                else:
                    rewritten_node = dict(node)
                    rewritten_node["id"] = resolved_id
                    rewritten_nodes[resolved_id] = rewritten_node
            else:
                rewritten_nodes[original_id] = node

        nodes.clear()
        nodes.update(rewritten_nodes)

        for edge in edges:
            source_id = resolve_id(str(edge.get("source", "")))
            target_id = resolve_id(str(edge.get("target", "")))
            edge["source"] = source_id
            edge["from"] = source_id
            edge["target"] = target_id
            edge["to"] = target_id

        remapped_subject_ids = {resolve_id(entity_id) for entity_id in subject_ids}
        remapped_object_ids = {resolve_id(entity_id) for entity_id in object_ids}
        subject_ids.clear()
        subject_ids.update(remapped_subject_ids)
        object_ids.clear()
        object_ids.update(remapped_object_ids)

    def _refresh_nodes_from_globals(self, nodes: dict[str, dict[str, Any]]) -> None:
        entity_maps = (
            get_all_processes(),
            get_all_files(),
            get_all_networks(),
            get_all_registries(),
            get_all_wmis(),
            get_all_users(),
        )

        for entity_map in entity_maps:
            for entity_id, entity in entity_map.items():
                if entity_id in nodes:
                    self._upsert_node(nodes, self._entity_to_node(entity))

    def _project_relation_triplet(self, technique: str, state: ProjectionState, triplet: Triplet) -> None:
        subject_node = self._entity_to_node(triplet.subject)
        object_node = self._entity_to_node(triplet.object)
        self._upsert_node(state.nodes, subject_node)
        self._upsert_node(state.nodes, object_node)

        edge_id = f"edge:{technique}:{len(state.edges) + 1}"
        state.edges.append(self._triplet_to_edge(edge_id, triplet))
        state.triplet_count += 1

        state.subject_ids.add(subject_node["id"])
        state.object_ids.add(object_node["id"])
        add_returned_node_id(object_node["id"])

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

        state = ProjectionState(nodes={}, edges=[], subject_ids=set(), object_ids=set())

        clear_all_globals()
        try:
            raw_events_total = 0
            source_files: list[str] = []
            parsed_logs_by_file: list[tuple[Path, list[dict[str, Any]]]] = []
            all_parsed_logs: list[dict[str, Any]] = []

            for log_file in log_files:
                source_files.append(str(log_file))
                parsed_logs = parser.parse_from_file(str(log_file)) or []
                raw_events_total += len(parsed_logs)
                parsed_logs_by_file.append((log_file, parsed_logs))
                all_parsed_logs.extend(parsed_logs)

            pruned_guids = collect_pruned_process_guids(all_parsed_logs)
            for guid in pruned_guids:
                add_ignored_process_guid(guid)

            for _, parsed_logs in parsed_logs_by_file:
                for log_entry in parsed_logs:
                    entity = parser.map_entity(log_entry)

                    if not entity:
                        continue

                    triplet = triplet_creator.create_triplet(entity)
                    if not triplet or not triplet.subject or not triplet.object:
                        continue

                    self._project_relation_triplet(technique, state, triplet)

                # Run enrichment/redirect once per source file to avoid O(events * nodes)
                # behavior while still applying merged updates before graph finalization.
                # self._refresh_nodes_from_globals(state.nodes)
                # self._apply_file_id_redirects(state.nodes, state.edges, state.subject_ids, state.object_ids)

            # Final pass keeps the graph consistent when the last parsed events only merge
            # existing entities and do not emit new triplets.
            self._refresh_nodes_from_globals(state.nodes)
            self._apply_file_id_redirects(state.nodes, state.edges, state.subject_ids, state.object_ids)

            technique_node = self._build_technique_node(technique)
            state.nodes[technique_node["id"]] = technique_node

            root_ids = sorted(state.subject_ids - state.object_ids)
            for root_id in root_ids:
                if root_id not in state.nodes:
                    continue
                edge_id = f"edge:{technique}:root:{root_id}"
                state.edges.append(self._build_root_edge(edge_id, technique_node["id"], root_id))

            graph = {
                "technique": technique,
                "source_file": source_files[0] if source_files else "",
                "source_files": source_files,
                "whitelist": {
                    "enabled": True,
                    "config_path": str(REPO_ROOT / "analyzing" / "global_whitelist.json"),
                },
                "nodes": list(state.nodes.values()),
                "edges": state.edges,
                "stats": {
                    "raw_events": raw_events_total,
                    "triplets": state.triplet_count,
                    "roots": len(root_ids),
                },
            }
        finally:
            clear_all_globals()

        self._cache[technique] = GraphCacheEntry(mtime_ns=cache_fingerprint, graph=graph)
        return copy.deepcopy(graph)
